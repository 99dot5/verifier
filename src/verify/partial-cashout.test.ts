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

/** The seed rule every listed deployment selects today. */

/** 100 TEZ in mutez: the stake every replay below is folded from. */
const STAKE_UNITS = 100_000_000n;

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

    it('keeps the multiplier chain across the bank, and the bank does not move the next card', () => {
        // The system partial-cashout takes action index 1 but draws nothing,
        // so the guess after it is decision 1 — the card it would have been
        // with no bank at all. The winning direction is derived from that
        // card, so the case holds for any seed pair.
        const first = hiloStep(SERVER, CLIENT, 0);
        const drawn = hiloStep(SERVER, CLIENT, 1);
        const winning = drawn.rankNumeric >= first.rankNumeric ? 'higher' : 'lower';
        const quoted = winning === 'higher' ? first.higherMultiplierPpm : first.lowerMultiplierPpm;

        const result = replay(SERVER, CLIENT, [
            action(0, 'place-bet'),
            action(1, 'partial-cashout', encodePartialCashout(30_000_000n)),
            action(2, winning),
            action(3, 'cashout'),
        ], STAKE_UNITS);

        // Discriminating for every seed: the guess step states the decision it
        // drew under and the card it drew, and both are decision 1's — never
        // the action index 2 the old rule keyed on.
        const guess = result.steps[2];

        expect(guess.details).toContainEqual(['decision', '1']);
        expect(guess.title).toContain(`drew ${drawn.rank} of ${drawn.suit}`);

        expect(result.settled).toBe(true);
        expect(result.outcome).toBe('cashed-out');
        expect(result.cumulativePpm).toBe(quoted);

        const bankStep = result.steps[1];

        expect(bankStep.actionType).toBe('partial-cashout');
        expect(bankStep.cumulativePpm).toBe(1_000_000n);
        expect(bankStep.title).toContain('30 banked');
    });

    it('abandonment settles at the current position — banked plus live (sec-28)', () => {
        // 12.5 banked out of a 100 stake leaves 87.5 live; the abandon pays
        // both, exactly what a cashout here would, so a forged one gains
        // nothing. The ending is `abandoned` — no decision of the player's ended it.
        const result = replay(SERVER, CLIENT, [
            action(0, 'place-bet'),
            action(1, 'partial-cashout', encodePartialCashout(12_500_000n)),
            action(2, 'abandon'),
        ], STAKE_UNITS);

        expect(result.outcome).toBe('abandoned');
        expect(result.settled).toBe(true);
        expect(result.bankedUnits).toBe(12_500_000n);
        expect(result.payoutUnits).toBe(STAKE_UNITS);
        expect(result.steps[2].title).toContain("settles at the position's current value: banked 12.5 + live 87.5 = 100");
        // The chain is left where the bank left it, as a cashout would leave it.
        expect(result.steps[2].cumulativePpm).toBe(1_000_000n);
    });

    it('rejects a partial-cashout larger than the live position', () => {
        // Mirrors `apply_bank`: banking more than is live would mint value, and
        // the kernel rejects the transcript rather than replaying it.
        expect(() =>
            replay(SERVER, CLIENT, [
                action(0, 'place-bet'),
                action(1, 'partial-cashout', encodePartialCashout(STAKE_UNITS + 1n)),
            ], STAKE_UNITS),
        ).toThrow(ReplayError);
    });

    it('rejects a malformed partial-cashout payload', () => {
        expect(() =>
            replay(SERVER, CLIENT, [
                action(0, 'place-bet'),
                action(1, 'partial-cashout', new Uint8Array(3)),
            ], STAKE_UNITS),
        ).toThrow(ReplayError);
    });
});
