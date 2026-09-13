/**
 * The system `partial-cashout` transcript step (max-win forced de-lever —
 * docs/specs/max-win-cap.md, slice 2): the sequencer banks part of the live
 * position to the session balance before an action whose winning outcome
 * would breach the pool's max-win cap. The multiplier chain is untouched;
 * the banked amount is the step's whole payload.
 */
import { BorshReader } from '../wire/borsh';
import { TRANSCRIPT_DECIMALS } from './assets';
import { ReplayError, type StepWorking } from './types';

/**
 * A decoded banked amount: integer units at `scale` decimal places.
 *
 * `scale` is a rendering property, not a wire field. The payload carries the
 * amount alone, in the atomic units of the session's asset, and the decoder
 * stamps the grain from the asset table.
 */
export interface BankedAmount {
    amount: bigint;
    scale: number;
}

/**
 * Borsh `Payload { amount: u128 (16 bytes LE) }` — mirrors
 * `libs/games/src/partial_cashout.rs`.
 *
 * There is no `scale` on the wire: one banked amount has exactly one
 * encoding, and the grain comes from the session's asset (see `./assets`).
 * The length check is exact, so the pre-`u128`-units 20-byte encoding is
 * rejected rather than silently read as a truncated amount.
 */
export function decodePartialCashout(payload: Uint8Array): BankedAmount {
    if (payload.length !== 16) {
        throw new ReplayError(`partial-cashout payload must be 16 bytes, got ${payload.length}`);
    }

    return { amount: new BorshReader(payload).u128(), scale: TRANSCRIPT_DECIMALS };
}

/** Render a banked amount as a plain decimal string (e.g. `12.5`). */
export function bankedAmountString(banked: BankedAmount): string {
    if (banked.scale === 0) {
        return banked.amount.toString();
    }

    const raw = banked.amount.toString().padStart(banked.scale + 1, '0');
    const whole = raw.slice(0, raw.length - banked.scale);
    const frac = raw.slice(raw.length - banked.scale).replace(/0+$/, '');

    return frac.length > 0 ? `${whole}.${frac}` : whole;
}

/** Sum two banked amounts exactly (rescaling to the larger scale). */
export function addBanked(a: BankedAmount, b: BankedAmount): BankedAmount {
    const scale = Math.max(a.scale, b.scale);
    const rescale = (x: BankedAmount): bigint => x.amount * 10n ** BigInt(scale - x.scale);

    return { amount: rescale(a) + rescale(b), scale };
}

export const ZERO_BANKED: BankedAmount = { amount: 0n, scale: 0 };

/** The display row for one `partial-cashout` step. */
export function partialCashoutStep(
    actionIndex: number,
    banked: BankedAmount,
    bankedTotal: BankedAmount,
    cumulativePpm: bigint,
): StepWorking {
    return {
        actionIndex,
        actionType: 'partial-cashout',
        title: `partial-cashout (system) — ${bankedAmountString(banked)} banked to the session balance`,
        details: [
            ['rule', 'max-win de-lever: value moves from the live position to the balance; the multiplier chain is untouched'],
            ['banked this step', bankedAmountString(banked)],
            ['banked so far', bankedAmountString(bankedTotal)],
        ],
        cumulativePpm,
    };
}
