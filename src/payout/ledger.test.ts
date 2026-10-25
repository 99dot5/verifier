// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { checkCemented, checkFast, expectedCemented, expectedFast } from './ledger';

const mv = (paidNow: bigint, paidTotal: bigint) => ({ paidNow, paidTotal });

describe('the paid ledger', () => {
    it('follows the rule’s table', () => {
        // Fast first (a), cemented later (c > a): pays c − a, records c.
        expect(expectedFast(0n, 3n)).toEqual(mv(3n, 3n));
        expect(expectedCemented(3n, 5n)).toEqual(mv(2n, 5n));
        // Cemented first: pays c, records c; a later fast payout is refused.
        expect(expectedCemented(0n, 5n)).toEqual(mv(5n, 5n));
        expect(expectedFast(5n, 5n)).toBeNull();
        // Fast short (a < c): the cemented tops up to the kernel's number.
        expect(expectedCemented(1n, 5n)).toEqual(mv(4n, 5n));
        // Fast over (a > c): nothing moves, the overpayment stands.
        expect(expectedCemented(7n, 5n)).toEqual(mv(0n, 7n));
        // Already paid in full: no-op.
        expect(expectedCemented(5n, 5n)).toEqual(mv(0n, 5n));
        // Zero amount: no-op.
        expect(expectedCemented(0n, 0n)).toEqual(mv(0n, 0n));
    });

    it('reports a move that differs as a mismatch', () => {
        expect(checkFast(0n, 3n, mv(3n, 3n))).toBeNull();
        expect(checkCemented(3n, 5n, mv(2n, 5n))).toBeNull();
        // The vault paid the cemented amount in full over a fast payout: paid twice.
        expect(checkCemented(3n, 5n, mv(5n, 8n))).toEqual({ previous: 3n, expected: mv(2n, 5n), reported: mv(5n, 8n) });
        // A fast payout over a non-zero ledger has no right answer.
        expect(checkFast(3n, 2n, mv(2n, 2n))).toEqual({ previous: 3n, expected: null, reported: mv(2n, 2n) });
        // A fast payout reporting less paid than it asked for.
        expect(checkFast(0n, 3n, mv(2n, 2n))).not.toBeNull();
    });

    it('holds at the u128 edges', () => {
        const max = (1n << 128n) - 1n;

        expect(expectedCemented(max, 0n)).toEqual(mv(0n, max));
        expect(expectedCemented(0n, max)).toEqual(mv(max, max));
    });
});
