// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes, serverSeedCommitment } from '../verify/seed';
import { decodeExternalMessage, uuidFromBytes } from './messages';
import { decodeEdpk } from './signature';

/**
 * Golden vector from a REAL shadownet injection (a tzkt operation) — the same
 * bytes `tools/operator-cli/src/decode.rs` pins its Rust decoder against. Any
 * divergence between this decoder and the kernel's fails here.
 */
const GOLDEN =
    '099585ad17b7d4b08ee5737d6ed4eb7011373df5499ce0749610d408418aae14e82f03c3f10606593e' +
    'bfb4fe925332d5aa6891815edc56c26aca571371bc8128db0800100000003939646f74352d73686164' +
    '6f776e6574080000007374616e64617264029a256790c7c047b09a5b6ed2905d2df1e2b6419aec4b4e' +
    'efbdfa802b6f338fc2000000000000000009000000706c6163652d6265740100000000';

describe('external message decoder', () => {
    it('decodes the real shadownet golden vector', () => {
        const decoded = decodeExternalMessage(hexToBytes(GOLDEN));

        expect(decoded).not.toBeNull();
        expect(decoded!.tenantId).toBe('99dot5-shadownet');
        expect(decoded!.poolId).toBe('standard');
        expect(decoded!.signature).toHaveLength(64);

        const message = decoded!.message;

        expect(message.kind).toBe('player-action');

        if (message.kind !== 'player-action') {
            throw new Error('unreachable');
        }

        expect(message.roundId).toBe('9a256790-c7c0-47b0-9a5b-6ed2905d2df1');
        expect(message.sessionId).toBe('e2b6419a-ec4b-4eef-bdfa-802b6f338fc2');
        expect(message.actionIndex).toBe(0n);
        expect(message.actionType).toBe('place-bet');
        expect(bytesToHex(message.actionPayload)).toBe('00');
    });

    /**
     * Pins `EndSession` at tag 0x04.
     *
     * It was 0x05 until the never-implemented `SeedBatchReveal` was removed
     * from the schema, freeing 0x04. Nothing else here exercises `EndSession`
     * — the golden vector is a `PlayerAction` — so without this the decoder
     * could silently disagree with the kernel about every session-end message
     * on the public inbox and the suite would still pass.
     *
     * Built from the golden vector's own envelope (same prefix, signature,
     * tenant and pool) with an `EndSession` payload substituted, so only the
     * tag and payload differ.
     */
    it('decodes EndSession at tag 0x04', () => {
        const END_SESSION =
            '099585ad17b7d4b08ee5737d6ed4eb7011373df5499ce0749610d408418aae14e82f03c3f10606593e' +
            'bfb4fe925332d5aa6891815edc56c26aca571371bc8128db0800100000003939646f74352d73686164' +
            '6f776e6574080000007374616e6461726404e2b6419aec4b4eefbdfa802b6f338fc201';

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
        // the string, mirroring seed_provisioner/seeds.rs::hash_seed.
        const seed = 'a'.repeat(64);
        const overString = bytesToHex(serverSeedCommitment(seed));
        const overBytes = bytesToHex(serverSeedCommitment(String.fromCharCode(0xaa).repeat(32)));

        expect(overString).not.toBe(overBytes);
        expect(overString).toHaveLength(64);
    });
});
