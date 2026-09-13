// @vitest-environment node
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes, serverSeedCommitment } from '../verify/seed';
import { decodeExternalMessage, uuidFromBytes } from './messages';
import { decodeEdpk } from './signature';
import { wireVectorsUrl } from './wire-vectors-path';

/**
 * The golden frame, taken from the shared cross-language vector file so this
 * decoder, the Rust wire crate and `tools/operator-cli/src/decode.rs` all pin
 * the same bytes.
 *
 * It is currently `source: "synthetic"` — a fixture, deliberately labelled as
 * one. A synthetic golden cannot catch a decoder drifting away from what the
 * sequencer actually emits, because the fixture is written by the same
 * understanding it is meant to check. Replacing it with a real shadownet
 * capture (`tools/capture-inbox-vector.sh`, `source: "captured"`) is a release
 * gate on the first round settled under the transcript kernel, not an
 * optional follow-up.
 */
interface GoldenTranscript {
    source: string;
    tenant_id: string;
    pool_id: string;
    fields: {
        round_id_hex: string;
        game_type: string;
        actions: { tag: number; action_type: string }[];
    };
    signed_frame_hex: string;
}

const golden: GoldenTranscript = JSON.parse(readFileSync(fileURLToPath(wireVectorsUrl()), 'utf8'))
    .round_transcript[0];
const GOLDEN = golden.signed_frame_hex;

describe('external message decoder', () => {
    it('decodes the shared golden transcript frame', () => {
        expect(golden.source).toBe('synthetic'); // flip to "captured" at the P6 gate

        const decoded = decodeExternalMessage(hexToBytes(GOLDEN));

        expect(decoded).not.toBeNull();
        expect(decoded!.tenantId).toBe(golden.tenant_id);
        expect(decoded!.poolId).toBe(golden.pool_id);
        expect(decoded!.signature).toHaveLength(64);

        const message = decoded!.message;

        expect(message.kind).toBe('round-transcript');

        if (message.kind !== 'round-transcript') {
            throw new Error('unreachable');
        }

        expect(message.gameType).toBe(golden.fields.game_type);
        expect(message.clientSeed).toHaveLength(32);
        expect(message.serverSeed).toHaveLength(32);
        expect(message.playerCommitment).toHaveLength(32);
        expect(message.actions.map((a) => a.actionType)).toEqual(
            golden.fields.actions.map((a) => a.action_type),
        );
        // Index 0 is always the place-bet: the action's index is its position,
        // and nothing on the wire restates it.
        expect(message.actions[0].tag).toBe(0x00);
    });

    /**
     * Pins `EndSession` at tag 0x02.
     *
     * It was 0x04 until `RoundCreated` / `PlayerAction` / `RoundSettled` were
     * deleted in favour of one `RoundTranscript` — the schema's second and
     * final pre-mainnet renumber. Nothing else here exercises `EndSession`, so
     * without this the decoder could silently disagree with the kernel about
     * every session-end message on the public inbox and the suite would still
     * pass.
     *
     * Built from the golden frame's own envelope (same prefix, signature,
     * tenant and pool) with an `EndSession` payload substituted, so only the
     * message tag and payload differ.
     */
    it('decodes EndSession at tag 0x02', () => {
        const envelopePrefixHex = GOLDEN.slice(0, 2 * (2 + 64)); // 0x0995 + signature
        const versionAndScopeHex = (() => {
            const decoded = decodeExternalMessage(hexToBytes(GOLDEN))!;
            // version byte + borsh(tenant_id) + borsh(pool_id), i.e. everything
            // before the message tag.
            const scopeLength = 1 + 4 + decoded.tenantId.length + 4 + decoded.poolId.length;

            return bytesToHex(decoded.signedPayload.slice(0, scopeLength));
        })();
        const END_SESSION =
            envelopePrefixHex +
            versionAndScopeHex +
            '02' + // SequencerMessage::EndSession
            'e2b6419aec4b4eefbdfa802b6f338fc2' + // session_id
            '01'; // EndReason::Expired

        const decoded = decodeExternalMessage(hexToBytes(END_SESSION));

        expect(decoded).not.toBeNull();

        const message = decoded!.message;

        expect(message.kind).toBe('end-session');

        if (message.kind !== 'end-session') {
            throw new Error('unreachable');
        }

        expect(message.sessionId).toBe('e2b6419a-ec4b-4eef-bdfa-802b6f338fc2');
        expect(message.reason).toBe('expired');
    });

    it('rejects a message tag outside the three the schema defines', () => {
        const decoded = decodeExternalMessage(hexToBytes(GOLDEN))!;
        const scopeLength = 1 + 4 + decoded.tenantId.length + 4 + decoded.poolId.length;
        const head = GOLDEN.slice(0, 2 * (2 + 64 + scopeLength));

        // 0x03 was RoundSettled before the renumber; it must now be rejected
        // outright rather than decoded as something else.
        expect(() => decodeExternalMessage(hexToBytes(`${head}03`))).toThrow(/unknown SequencerMessage tag/);
        expect(() => decodeExternalMessage(hexToBytes(`${head}ff`))).toThrow(/unknown SequencerMessage tag/);
    });

    it('returns null for non-sequencer frames and rejects trailing bytes', () => {
        expect(decodeExternalMessage(hexToBytes('0000'))).toBeNull();
        expect(decodeExternalMessage(hexToBytes('0995'))).toBeNull();
        expect(() => decodeExternalMessage(hexToBytes(GOLDEN + 'ff'))).toThrow(/trailing/);
    });

    it('renders uuids in canonical hyphenated form', () => {
        expect(uuidFromBytes(hexToBytes('550e8400e29b41d4a716446655440000'))).toBe(
            '550e8400-e29b-41d4-a716-446655440000',
        );
    });
});

describe('edpk decoding', () => {
    it('decodes a known edpk to 32 raw bytes (round-trips through the checksum)', () => {
        // The all-zeros Ed25519 public key in Tezos base58check form.
        const raw = decodeEdpk('edpkteDwHwoNPB18tKToFKeSCykvr1ExnoMV5nawTJy9Y9nLTfQ541');

        expect(raw).toHaveLength(32);
        expect(bytesToHex(raw)).toBe('0'.repeat(64));
    });

    it('rejects a corrupted key', () => {
        expect(() => decodeEdpk('edpkteDwHwoNPB18tKToFKeSCykvr1ExnoMV5nawTJy9Y9nLTfQ542')).toThrow();
    });
});

describe('seed commitment hash', () => {
    it('hashes the ASCII hex string, not the raw bytes it spells', () => {
        // blake2b-256 of the 64 ASCII characters of the seed string. Distinct
        // from blake2b-256 of the 32 decoded bytes — the commitment is over
        // the string, mirroring seed_provisioner/seeds.rs::hash_seed. The
        // transcript wire carries the RAW bytes, which makes this the exact
        // mistake the new format invites; wire-vectors.test.ts pins both
        // digests against the shared vector.
        const seed = 'a'.repeat(64);
        const overString = bytesToHex(serverSeedCommitment(seed));
        const overBytes = bytesToHex(serverSeedCommitment(String.fromCharCode(0xaa).repeat(32)));

        expect(overString).not.toBe(overBytes);
        expect(overString).toHaveLength(64);
    });
});
