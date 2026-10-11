import { describe, expect, it } from 'vitest';
import { bytesToHex } from '@99dot5/round-replay';
import { decodeEdpk } from './signature';

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
