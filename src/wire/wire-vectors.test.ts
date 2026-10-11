// @vitest-environment node
/**
 * The cross-language pins of the signing rule.
 *
 * `libs/smart-rollup-messages/testdata/wire-vectors.json` is written by an
 * independent Python Borsh writer and asserted by the Rust wire crate, the
 * Rust sequencer core, the replay library and this file. The action-tag
 * table, the seed hashing rules and the `RoundTranscript` encodings are
 * pinned by `@99dot5/round-replay`, which owns the decoder.
 *
 * What is pinned here:
 *   - the signing digest of every `RoundTranscript` vector under the shared
 *     signing domain,
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
import { bytesToHex, decodeExternalMessage, hexToBytes, serverSeedCommitment } from '@99dot5/round-replay';
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

describe('round transcript encodings', () => {
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
        // The chain hash rides as 32 raw bytes, never as its hex text.
        expect(decoded.message.drandChainHash).toHaveLength(32);
        expect(bytesToHex(decoded.message.drandChainHash)).toBe(batch.fields.drand_chain_hash_hex);

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
