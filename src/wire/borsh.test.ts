import { describe, expect, it } from 'vitest';

import { BorshError, BorshReader } from './borsh';

/**
 * `u128` is the width every amount on the wire uses — `RoundTranscript.stake`
 * and `claimedPayout` — so the reader has to be exact across the whole range,
 * not just where a JavaScript number would still be safe. Everything here is
 * `bigint`; `Number` loses exactness above 2^53 and would make the assertions
 * agree for the wrong reason.
 */
function leBytes(value: bigint, width: number): Uint8Array {
    const out = new Uint8Array(width);
    let rest = value;

    for (let i = 0; i < width; i++) {
        out[i] = Number(rest & 0xffn);
        rest >>= 8n;
    }

    expect(rest, 'value does not fit the requested width').toBe(0n);

    return out;
}

describe('BorshReader.u128', () => {
    const cases: [string, bigint][] = [
        ['zero', 0n],
        ['one', 1n],
        ['u64::MAX - 1', 2n ** 64n - 2n],
        ['u64::MAX', 2n ** 64n - 1n],
        ['2^64 — the first value a u64 reader cannot hold', 2n ** 64n],
        ['100 tokens of an 18-decimal asset', 100n * 10n ** 18n],
        ['u128::MAX', 2n ** 128n - 1n],
    ];

    for (const [label, value] of cases) {
        it(`round-trips ${label}`, () => {
            const reader = new BorshReader(leBytes(value, 16));

            expect(reader.u128()).toBe(value);
            expect(reader.remaining).toBe(0);
        });
    }

    it('reads sixteen bytes, not eight — the high half is not discarded', () => {
        // Low half 1, high half 1: an eight-byte read would return 1n.
        const bytes = leBytes(2n ** 64n + 1n, 16);

        expect(new BorshReader(bytes).u128()).toBe(2n ** 64n + 1n);
    });

    it('rejects an input shorter than sixteen bytes', () => {
        const reader = new BorshReader(leBytes(1n, 15));

        expect(() => reader.u128()).toThrow(BorshError);
    });

    it('leaves a seventeenth byte unconsumed, and expectEnd rejects it', () => {
        const bytes = new Uint8Array(17);

        bytes.set(leBytes(2n ** 128n - 1n, 16));
        bytes[16] = 0xff;

        const reader = new BorshReader(bytes);

        expect(reader.u128()).toBe(2n ** 128n - 1n);
        expect(reader.remaining).toBe(1);
        expect(() => reader.expectEnd()).toThrow(BorshError);
    });
});
