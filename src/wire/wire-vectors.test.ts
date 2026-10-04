// @vitest-environment node
/**
 * The cross-language pins.
 *
 * `libs/smart-rollup-messages/testdata/wire-vectors.json` is written by an
 * independent Python Borsh writer and asserted by the Rust wire crate, the
 * Rust sequencer core and this file. Three implementations, one set of bytes:
 * if any two of them drift, the third fails here rather than on chain.
 *
 * What is pinned:
 *   - the twelve-entry action-tag table (value ↔ kebab-case string),
 *   - the three `SequencerMessage` tags,
 *   - the client-seed rule: blake2b-256 of the player's UTF-8 text,
 *   - the server-seed commitment rule: blake2b-256 of the 64 ASCII HEX
 *     characters, and — the point of the third field — the DIFFERENT digest
 *     you get by hashing the 32 raw bytes those characters spell,
 *   - every `RoundTranscript` encoding, decoded field by field,
 *   - the really-signed frame per `SequencerMessage` variant (#954): decoded,
 *     and its signature VERIFIED under the fixture's key and signing domain
 *     with `@noble/ed25519` — the fourth implementation of
 *     `ed25519(blake2b-256(chain_id ‖ rollup_address ‖ envelope))` held to the
 *     same bytes as the generator's RFC 8032 signer, the injector and the
 *     kernel.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { blake2b } from '@noble/hashes/blake2.js';
import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes, serverSeedCommitment } from '../verify/seed';
import {
    ACTION_TAGS,
    GAME_VOCABULARIES,
    GAME_VOCABULARY_START,
    actionTypeOf,
    allowedIn,
    isSystem,
    tagOf,
} from './action-tags';
import { decodeExternalMessage } from './messages';
import { decodeChainId, decodeSr1, sequencerSigningPreimage, verifyInboxSignature } from './signature';
import { wireVectorsUrl } from './wire-vectors-path';

interface WireVectors {
    envelope_header_max_bytes: number;
    signing_domain: {
        chain_id: string;
        chain_id_hex: string;
        rollup_address: string;
        rollup_address_hex: string;
        preimage_prefix_hex: string;
    };
    size_budget: Record<string, number>;
    message_tags: { seed_batch: number; round_transcript: number; end_session: number };
    action_tags: { tag: number; action_type: string }[];
    client_seed_hashing: { text: string; blake2b256_hex: string; effective_seed_hex: string }[];
    server_seed_commitment: {
        seed_hex: string;
        commitment_hex: string;
        wrong_hash_of_raw_bytes_hex: string;
    }[];
    round_transcript: {
        description: string;
        source: string;
        tenant_id: string;
        pool_id: string;
        fields: {
            round_id_hex: string;
            session_id_hex: string;
            game_type: string;
            /** See the BigInt note on the parse below: may arrive as a string. */
            stake: string | number;
            client_seed_hex: string;
            server_seed_hex: string;
            server_seed_index: string | number;
            claimed_payout: string | number;
            player_commitment_hex: string;
            actions: { index: number; tag: number; action_type: string; payload_hex: string }[];
        };
        encoded_bytes: number;
        borsh_hex: string;
        signed_frame_hex: string;
        signing_digest_hex: string;
    }[];
    end_reasons: { tag: number; reason: string }[];
    signed_messages: {
        description: string;
        message_type: 'seed_batch' | 'round_transcript' | 'end_session';
        message_tag: number;
        source: string;
        tenant_id: string;
        pool_id: string;
        signer: { seed_hex: string; public_key_hex: string };
        fields: Record<string, unknown>;
        round_transcript_index?: number;
        encoded_bytes: number;
        borsh_hex: string;
        signing_digest_hex: string;
        signature_hex: string;
        signed_frame_hex: string;
    }[];
}

/**
 * JSON numbers are IEEE-754 doubles, and the worst-case vector carries
 * `u64::MAX` (18446744073709551615) as its stake — `JSON.parse` silently
 * rounds that to …616 and the assertion below would then compare a rounded
 * value against a rounded value. Quote every integer literal too long to be
 * exact and convert it with `BigInt`, so the comparison is over the bytes the
 * decoder actually produced.
 */
const vectors: WireVectors = JSON.parse(
    readFileSync(fileURLToPath(wireVectorsUrl()), 'utf8').replace(/:\s*(\d{16,})(?=\s*[,}\]])/g, ': "$1"'),
);

/** Hyphenate 32 hex characters into the canonical UUID form the decoder emits. */
function hyphenate(hex: string): string {
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

describe('action-tag table', () => {
    it('matches the shared vector entry for entry', () => {
        expect(ACTION_TAGS.length).toBe(vectors.action_tags.length);

        for (const { tag, action_type } of vectors.action_tags) {
            expect(actionTypeOf(tag)).toBe(action_type);
            expect(tagOf(action_type)).toBe(tag);
        }
    });

    it('has exactly twelve tags and rejects anything outside them', () => {
        expect(ACTION_TAGS).toHaveLength(12);
        // The gap between the protocol block and the game vocabulary resolves
        // to nothing: eleven protocol bytes are reserved, not assigned.
        for (let tag = 0x05; tag < GAME_VOCABULARY_START; tag += 1) {
            expect(actionTypeOf(tag)).toBeNull();
        }
        expect(actionTypeOf(0x17)).toBeNull();
        expect(actionTypeOf(0xff)).toBeNull();
        // `fight` survives in the steps.action_type CHECK constraint but no
        // engine emits it, so it deliberately gets no tag.
        expect(tagOf('fight')).toBeNull();
    });

    it('splits the protocol block from the game vocabulary', () => {
        const protocolBlock = ['place-bet', 'cashout', 'partial-cashout', 'abandon', 'expire'];

        for (const entry of ACTION_TAGS) {
            expect(entry.tag < GAME_VOCABULARY_START).toBe(
                protocolBlock.includes(entry.actionType),
            );
        }
    });

    it('classifies the three system-originated actions and nothing else', () => {
        const system = vectors.action_tags.filter((a) => isSystem(a.action_type));

        expect(system.map((a) => a.action_type)).toEqual([
            'partial-cashout',
            'abandon',
            'expire',
        ]);
    });

    it('gives every tag at least one game and refuses an unknown game type', () => {
        const games = Object.keys(GAME_VOCABULARIES);

        for (const { actionType } of ACTION_TAGS) {
            expect(games.some((game) => allowedIn(actionType, game))).toBe(true);
            expect(allowedIn(actionType, 'labours:v1')).toBe(false);
        }
    });

    it('lets every game open, settle and be abandoned', () => {
        for (const game of Object.keys(GAME_VOCABULARIES)) {
            for (const actionType of ['place-bet', 'cashout', 'abandon']) {
                expect(allowedIn(actionType, game)).toBe(true);
            }
        }
    });

    it('holds every vocabulary entry to a real tag', () => {
        for (const [game, actionTypes] of Object.entries(GAME_VOCABULARIES)) {
            for (const actionType of actionTypes) {
                expect(tagOf(actionType), `${game} / ${actionType}`).not.toBeNull();
            }
        }
    });
});

describe('client-seed hashing rule', () => {
    it('reproduces every shared vector', () => {
        expect(vectors.client_seed_hashing.length).toBeGreaterThan(0);

        for (const entry of vectors.client_seed_hashing) {
            const hashed = blake2b(new TextEncoder().encode(entry.text), { dkLen: 32 });

            expect(bytesToHex(hashed)).toBe(entry.blake2b256_hex);
            // The effective seed the engine consumes is the lowercase hex of
            // those same bytes — one rule, applied once, at bet time.
            expect(entry.effective_seed_hex).toBe(entry.blake2b256_hex);
            expect(entry.effective_seed_hex).toMatch(/^[0-9a-f]{64}$/);
        }
    });
});

describe('server-seed commitment rule', () => {
    it('reproduces every shared vector from the ASCII hex', () => {
        expect(vectors.server_seed_commitment.length).toBeGreaterThan(0);

        for (const entry of vectors.server_seed_commitment) {
            expect(bytesToHex(serverSeedCommitment(entry.seed_hex))).toBe(entry.commitment_hex);
        }
    });

    it('hashing the raw bytes gives the WRONG digest, and the vector pins it', () => {
        for (const entry of vectors.server_seed_commitment) {
            const overRawBytes = blake2b(hexToBytes(entry.seed_hex), { dkLen: 32 });

            expect(bytesToHex(overRawBytes)).toBe(entry.wrong_hash_of_raw_bytes_hex);
            expect(entry.wrong_hash_of_raw_bytes_hex).not.toBe(entry.commitment_hex);
        }
    });
});

describe('round transcript encodings', () => {
    it('covers the shapes the plan requires', () => {
        expect(vectors.round_transcript.length).toBeGreaterThanOrEqual(5);
        expect(vectors.message_tags).toEqual({ seed_batch: 0, round_transcript: 1, end_session: 2 });
    });

    for (const entry of vectors.round_transcript) {
        it(`decodes: ${entry.description}`, () => {
            // Every entry declares whether it is a synthetic fixture or a real
            // capture. Synthetic vectors are placeholders until a shadownet
            // round is captured under the new kernel; a capture must never be
            // silently mistaken for a fixture, or the reverse.
            expect(['synthetic', 'captured']).toContain(entry.source);
            expect(entry.borsh_hex.length / 2).toBe(entry.encoded_bytes);

            const decoded = decodeExternalMessage(hexToBytes(entry.signed_frame_hex));

            expect(decoded).not.toBeNull();
            expect(decoded!.tenantId).toBe(entry.tenant_id);
            expect(decoded!.poolId).toBe(entry.pool_id);
            expect(decoded!.signature).toHaveLength(64);
            // The signature covers the whole borsh blob, version byte included.
            expect(bytesToHex(decoded!.signedPayload)).toBe(entry.borsh_hex);

            const message = decoded!.message;

            expect(message.kind).toBe('round-transcript');

            if (message.kind !== 'round-transcript') {
                throw new Error('unreachable');
            }

            const f = entry.fields;

            expect(message.roundId).toBe(hyphenate(f.round_id_hex));
            expect(message.sessionId).toBe(hyphenate(f.session_id_hex));
            expect(message.gameType).toBe(f.game_type);
            expect(message.stake).toBe(BigInt(f.stake));
            expect(bytesToHex(message.clientSeed)).toBe(f.client_seed_hex);
            expect(bytesToHex(message.serverSeed)).toBe(f.server_seed_hex);
            expect(message.serverSeedIndex).toBe(BigInt(f.server_seed_index));
            expect(message.claimedPayout).toBe(BigInt(f.claimed_payout));
            expect(bytesToHex(message.playerCommitment)).toBe(f.player_commitment_hex);
            expect(message.actions).toHaveLength(f.actions.length);

            for (const [index, action] of f.actions.entries()) {
                // The action's index IS its position — nothing on the wire
                // carries it, so a decoder that reorders silently changes the
                // seed derivation.
                expect(action.index).toBe(index);
                expect(message.actions[index].tag).toBe(action.tag);
                expect(message.actions[index].actionType).toBe(action.action_type);
                expect(bytesToHex(message.actions[index].payload)).toBe(action.payload_hex);
            }
        });
    }

    it('reproduces the signing digest of every vector under the shared signing domain (#952)', () => {
        // The one cross-language pin of the signing rule: blake2b-256 over
        // `chain_id ‖ rollup_address ‖ envelope`, where the two prefix fields
        // are the raw base58check payloads the generator decoded
        // independently. A verifier that hashed the bare envelope, or
        // decoded the domain to the wrong width, disagrees here and nowhere
        // else — the kernel pins the same digests from the Rust side.
        const domain = { chainId: vectors.signing_domain.chain_id, rollupAddress: vectors.signing_domain.rollup_address };

        expect(vectors.size_budget.chain_id_bytes).toBe(4);
        expect(vectors.size_budget.rollup_address_bytes).toBe(20);
        expect(vectors.size_budget.signing_domain_bytes).toBe(24);
        expect(bytesToHex(decodeChainId(domain.chainId))).toBe(vectors.signing_domain.chain_id_hex);
        expect(bytesToHex(decodeSr1(domain.rollupAddress))).toBe(vectors.signing_domain.rollup_address_hex);
        expect(bytesToHex(sequencerSigningPreimage(domain, new Uint8Array()))).toBe(
            vectors.signing_domain.preimage_prefix_hex,
        );

        for (const entry of vectors.round_transcript) {
            const preimage = sequencerSigningPreimage(domain, hexToBytes(entry.borsh_hex));

            expect(bytesToHex(blake2b(preimage, { dkLen: 32 })), entry.description).toBe(entry.signing_digest_hex);
        }
    });

    it('keeps the worst case inside the size budget it was derived from', () => {
        const worst = vectors.round_transcript.find(
            (e) => e.fields.actions.length === vectors.size_budget.max_transcript_actions,
        );

        expect(worst, 'a MAX_TRANSCRIPT_ACTIONS-action vector must exist').toBeDefined();
        expect(worst!.encoded_bytes).toBeLessThanOrEqual(vectors.size_budget.max_transcript_encoded_bytes);
        expect(worst!.signed_frame_hex.length / 2).toBeLessThanOrEqual(
            vectors.size_budget.effective_message_size_limit,
        );
    });
});

describe('really-signed frames (#954)', () => {
    const domain = { chainId: vectors.signing_domain.chain_id, rollupAddress: vectors.signing_domain.rollup_address };
    const kinds = { seed_batch: 'seed-batch', round_transcript: 'round-transcript', end_session: 'end-session' } as const;

    it('carries one signed frame per SequencerMessage variant, under the fixed test seed', () => {
        expect(vectors.signed_messages.map((e) => e.message_tag).sort()).toEqual([0, 1, 2]);
        expect(vectors.signed_messages.map((e) => e.message_type).sort()).toEqual([
            'end_session',
            'round_transcript',
            'seed_batch',
        ]);

        for (const entry of vectors.signed_messages) {
            // A real key signed real bytes, but no tenant ever held the key
            // and nothing was captured from a chain — distinct from both the
            // placeholder-signed `synthetic` vectors and a future `captured`.
            expect(entry.source).toBe('synthetic-signed');
            expect(entry.signer.seed_hex).toBe('42'.repeat(32));
            expect(entry.signer.public_key_hex).toHaveLength(64);
            expect(entry.signature_hex).toHaveLength(128);
            expect(entry.signature_hex).not.toBe('00'.repeat(64));
        }
    });

    for (const entry of vectors.signed_messages) {
        it(`decodes and verifies: ${entry.description}`, () => {
            const decoded = decodeExternalMessage(hexToBytes(entry.signed_frame_hex));

            expect(decoded).not.toBeNull();
            expect(decoded!.tenantId).toBe(entry.tenant_id);
            expect(decoded!.poolId).toBe(entry.pool_id);
            expect(decoded!.message.kind).toBe(kinds[entry.message_type]);
            expect(bytesToHex(decoded!.signedPayload)).toBe(entry.borsh_hex);
            expect(bytesToHex(decoded!.signature)).toBe(entry.signature_hex);

            // The digest the generator signed is the one this verifier hashes.
            const preimage = sequencerSigningPreimage(domain, decoded!.signedPayload);

            expect(bytesToHex(blake2b(preimage, { dkLen: 32 }))).toBe(entry.signing_digest_hex);

            // The signature verifies under the fixture's key and domain…
            const publicKey = hexToBytes(entry.signer.public_key_hex);

            expect(verifyInboxSignature(decoded!.signature, decoded!.signedPayload, domain, publicKey)).toBe(true);

            // …and not with one payload byte flipped, one signature byte
            // flipped, or under another rollup's domain — a frame signed for
            // one instance is a plain signature failure everywhere else (#952).
            const flippedPayload = Uint8Array.from(decoded!.signedPayload);

            flippedPayload[flippedPayload.length - 1] ^= 0x01;
            expect(verifyInboxSignature(decoded!.signature, flippedPayload, domain, publicKey)).toBe(false);

            const flippedSignature = Uint8Array.from(decoded!.signature);

            flippedSignature[0] ^= 0x01;
            expect(verifyInboxSignature(flippedSignature, decoded!.signedPayload, domain, publicKey)).toBe(false);

            const otherRollup = { ...domain, rollupAddress: 'sr1V6huFSUBUujzubUCg9nNXqpzfG9t4XD1h' };

            expect(verifyInboxSignature(decoded!.signature, decoded!.signedPayload, otherRollup, publicKey)).toBe(
                false,
            );
        });
    }

    it('signs round_transcript[0] — the same envelope as the placeholder-signed vector', () => {
        const signed = vectors.signed_messages.find((e) => e.message_type === 'round_transcript')!;
        const twin = vectors.round_transcript[signed.round_transcript_index!];

        expect(signed.borsh_hex).toBe(twin.borsh_hex);
        expect(signed.signing_digest_hex).toBe(twin.signing_digest_hex);
        expect(signed.signed_frame_hex).not.toBe(twin.signed_frame_hex);
    });

    it('commits, in the SeedBatch, to exactly the server-seed commitment vectors', () => {
        const batch = vectors.signed_messages.find((e) => e.message_type === 'seed_batch')!;
        const decoded = decodeExternalMessage(hexToBytes(batch.signed_frame_hex))!;

        if (decoded.message.kind !== 'seed-batch') {
            throw new Error('unreachable');
        }

        const onWire = decoded.message.hashes.map(bytesToHex);

        expect(onWire).toEqual(batch.fields.hashes_hex);

        for (const { seed_hex, commitment_hex } of vectors.server_seed_commitment) {
            expect(onWire).toContain(commitment_hex);
            expect(bytesToHex(serverSeedCommitment(seed_hex))).toBe(commitment_hex);
        }
    });

    it('reads the EndReason table from the shared file', () => {
        expect(vectors.end_reasons).toEqual([
            { tag: 0, reason: 'UserRequested' },
            { tag: 1, reason: 'Expired' },
            { tag: 2, reason: 'IdleSwept' },
        ]);
    });
});
