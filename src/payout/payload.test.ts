// @vitest-environment node
/**
 * The PACK payload port, pinned to the shared fast-payout vectors: every
 * payload the fixture carries (the right one, and one wrong in each of the
 * chain, the vault, the session and the amount) reproduces byte for byte.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { fastPayoutVectorsUrl } from './fast-payout-vectors-path';
import { bytesToHex } from './micheline';
import { fastPayoutPayload, forgedVaultAddress, zarithNat } from './payload';

interface Vectors {
    chain_id: string;
    chain_id_bytes: string;
    vault: string;
    payloads: Record<
        string,
        { domain: string; chain_id: string; vault: string; session_id: string; amount_mutez: number; bytes: string }
    >;
}

const vectors = JSON.parse(readFileSync(fastPayoutVectorsUrl(), 'utf8')) as Vectors;

function hexToBytes(hex: string): Uint8Array {
    return new Uint8Array((hex.match(/.{2}/g) ?? []).map((byte) => Number.parseInt(byte, 16)));
}

describe('fast-payout payload', () => {
    const fastPayloads = Object.entries(vectors.payloads).filter(([name]) => name.startsWith('fast_payout'));

    it('has every fast-payout payload of the fixture to pin against', () => {
        expect(fastPayloads.map(([name]) => name).sort()).toEqual([
            'fast_payout',
            'fast_payout_other_amount',
            'fast_payout_other_chain',
            'fast_payout_other_session',
            'fast_payout_other_vault',
        ]);
    });

    it.each(fastPayloads)('reproduces the fixture bytes of %s', (_name, payload) => {
        expect(payload.domain).toBe('fast-payout:v1');

        const packed = fastPayoutPayload(
            payload.chain_id,
            payload.vault,
            hexToBytes(payload.session_id),
            BigInt(payload.amount_mutez),
        );

        expect(bytesToHex(packed)).toBe(payload.bytes);
    });

    it('is a domain-tagged five-tuple with the forged vault address and a zarith amount', () => {
        const session = new Uint8Array(16).fill(0xaa);
        const packed = fastPayoutPayload(vectors.chain_id, vectors.vault, session, 3_000_000n);
        const vault = forgedVaultAddress(vectors.vault);
        const expected = [
            0x05,
            0x07,
            0x07,
            0x01,
            0,
            0,
            0,
            14,
            ...new TextEncoder().encode('fast-payout:v1'),
            0x07,
            0x07,
            0x0a,
            0,
            0,
            0,
            4,
            ...hexToBytes(vectors.chain_id_bytes),
            0x07,
            0x07,
            0x0a,
            0,
            0,
            0,
            22,
            ...vault,
            0x07,
            0x07,
            0x0a,
            0,
            0,
            0,
            16,
            ...session,
            // zarith of 3_000_000: `80 9b ee 02`
            0x00,
            0x80,
            0x9b,
            0xee,
            0x02,
        ];

        expect([...packed]).toEqual(expected);
        expect(vault[0]).toBe(0x01);
        expect(vault[21]).toBe(0x00);
        expect(vault.length).toBe(22);
    });

    it('encodes the signed zarith Michelson uses for mutez', () => {
        expect(zarithNat(0n)).toEqual([0x00]);
        expect(zarithNat(63n)).toEqual([0x3f]);
        expect(zarithNat(64n)).toEqual([0x80, 0x01]);
        expect(zarithNat(1_500_000n)).toEqual([0xa0, 0x8d, 0xb7, 0x01]);
        expect(() => zarithNat(-1n)).toThrow(RangeError);
    });

    it('refuses a vault that is not a KT1 and a session id that is not 16 bytes', () => {
        expect(() =>
            fastPayoutPayload(vectors.chain_id, 'tz1UyQDepgtUBnWjyzzonqeDwaiWoQzRKSP5', new Uint8Array(16), 1n),
        ).toThrow(RangeError);
        expect(() =>
            fastPayoutPayload(vectors.chain_id, 'sr1TMxAUtDA4sDL7C4r39L18iQjhRcBRzd8a', new Uint8Array(16), 1n),
        ).toThrow(RangeError);
        expect(() => fastPayoutPayload(vectors.chain_id, vectors.vault, new Uint8Array(15), 1n)).toThrow(RangeError);
        expect(() => fastPayoutPayload(vectors.vault, vectors.vault, new Uint8Array(16), 1n)).toThrow(RangeError);
    });
});
