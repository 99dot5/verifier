// @vitest-environment node
import { describe, expect, it } from 'vitest';
import {
    ZERO_BANKED,
    addBanked,
    bankedAmountString,
    decodePartialCashout,
} from './partial-cashout';
import { TRANSCRIPT_DECIMALS } from './assets';
import { hiloStep, replay } from './hilo';
import { ReplayError, type TranscriptAction } from './types';

/**
 * Borsh-encode `Payload { amount: u128 LE }`. Built on an explicit
 * `ArrayBuffer` so the produced view is assignable whether the ambient TS lib
 * types `Uint8Array` generically or not.
 */
function encodePartialCashout(amount: bigint): Uint8Array {
    const buffer = new ArrayBuffer(16);
    const bytes = new Uint8Array(buffer);
    let units = amount;

    for (let i = 0; i < 16; i++) {
        bytes[i] = Number(units & 0xffn);
        units >>= 8n;
    }

    return bytes;
}

/** The pre-`u128`-units encoding: the same amount plus a trailing `u32` scale. */
function encodeLegacyPartialCashout(amount: bigint, scale: number): Uint8Array {
    const buffer = new ArrayBuffer(20);
    const bytes = new Uint8Array(buffer);

    bytes.set(encodePartialCashout(amount));
    new DataView(buffer).setUint32(16, scale, true);

    return bytes;
}

function action(actionIndex: number, actionType: string, payload: Uint8Array = new Uint8Array()): TranscriptAction {
    return { actionIndex, actionType, payload };
}

describe('decodePartialCashout', () => {
    it('round-trips units at the asset grain', () => {
        const decoded = decodePartialCashout(encodePartialCashout(12_500_000n));

        expect(decoded.amount).toBe(12_500_000n);
        expect(decoded.scale).toBe(TRANSCRIPT_DECIMALS);
        expect(bankedAmountString(decoded)).toBe('12.5');
    });

    it('reads the full u128 range', () => {
        // Both sides of the u64 boundary: an eight-byte reader would fail here.
        for (const units of [1n << 64n, 2n ** 128n - 1n]) {
            expect(decodePartialCashout(encodePartialCashout(units)).amount).toBe(units);
        }
    });

    it('rejects wrong-length payloads', () => {
        expect(() => decodePartialCashout(new Uint8Array(4))).toThrow(ReplayError);
    });

    it('rejects the legacy 20-byte payload', () => {
        // No compatibility path: the trailing scale is a decode failure, not
        // four bytes to skip.
        expect(() => decodePartialCashout(encodeLegacyPartialCashout(12_500_000n, 6))).toThrow(
            ReplayError,
        );
    });

    it('renders whole and sub-unit amounts', () => {
        expect(bankedAmountString({ amount: 5n, scale: 0 })).toBe('5');
        expect(bankedAmountString({ amount: 42n, scale: 6 })).toBe('0.000042');
    });

    it('sums across scales exactly', () => {
        const total = addBanked({ amount: 15n, scale: 1 }, { amount: 250_000n, scale: 6 });

        expect(bankedAmountString(total)).toBe('1.75');
        expect(bankedAmountString(addBanked(ZERO_BANKED, { amount: 3n, scale: 0 }))).toBe('3');
    });
});

describe('hilo replay with a partial cashout', () => {
    const SERVER = 'server-seed';
    const CLIENT = 'client-seed';

    it('keeps the multiplier chain across the bank and derives the guess at the shifted index', () => {
        // Direction that wins at action_index 2 (the post-insertion index) for
        // these seeds, derived from the same step math the replay uses.
        const first = hiloStep(SERVER, CLIENT, 0);
        const drawn = hiloStep(SERVER, CLIENT, 2);
        const winning = drawn.rankNumeric >= first.rankNumeric ? 'higher' : 'lower';
        const quoted = winning === 'higher' ? first.higherMultiplierPpm : first.lowerMultiplierPpm;

        const result = replay(SERVER, CLIENT, [
            action(0, 'place-bet'),
            action(1, 'partial-cashout', encodePartialCashout(30_000_000n)),
            action(2, winning),
            action(3, 'cashout'),
        ]);

        expect(result.settled).toBe(true);
        expect(result.outcome).toBe('cashout');
        expect(result.cumulativePpm).toBe(quoted);

        const bankStep = result.steps[1];

        expect(bankStep.actionType).toBe('partial-cashout');
        expect(bankStep.cumulativePpm).toBe(1_000_000n);
        expect(bankStep.title).toContain('30 banked');
    });

    it('abandonment reports the banked total', () => {
        const result = replay(SERVER, CLIENT, [
            action(0, 'place-bet'),
            action(1, 'partial-cashout', encodePartialCashout(12_500_000n)),
            action(2, 'abandon'),
        ]);

        expect(result.outcome).toBe('lose');
        expect(result.steps[2].title).toContain('pays the banked total 12.5');
    });

    it('rejects a malformed partial-cashout payload', () => {
        expect(() =>
            replay(SERVER, CLIENT, [
                action(0, 'place-bet'),
                action(1, 'partial-cashout', new Uint8Array(3)),
            ]),
        ).toThrow(ReplayError);
    });
});
