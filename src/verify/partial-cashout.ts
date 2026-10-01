/**
 * The system `partial-cashout` transcript step (max-win forced de-lever —
 * docs/specs/max-win-cap.md, slice 2): the sequencer banks part of the live
 * position to the session balance before an action whose winning outcome
 * would breach the pool's max-win cap. The multiplier chain is untouched;
 * the banked amount is the step's whole payload.
 */
import { BorshReader } from '../wire/borsh';
import { TRANSCRIPT_DECIMALS } from './assets';
import { SCALE_PPM, divHalfUp, unitsToDecimalString } from './ints';
import { ReplayError, type StepWorking } from './types';

/**
 * The compounding games' value model (`libs/games/src/partial_cashout.rs`),
 * in integer atomic units: the position splits into `banked` (already the
 * player's) and `live` (still at risk). Every winning step folds `live`;
 * a `partial-cashout` moves value from `live` to `banked`; a loss zeroes
 * `live`; a cashout — and, since sec-28, an `abandon` — pays `banked + live`.
 */
export interface Position {
    bankedUnits: bigint;
    liveUnits: bigint;
}

/** A fresh round: nothing banked, the whole stake live at 1.00×. */
export function openPosition(stakeUnits: bigint): Position {
    return { bankedUnits: 0n, liveUnits: stakeUnits };
}

/**
 * Mirrors `partial_cashout::multiply_live`: `live' = half_up(live × step / 1e6)`,
 * rounded AT THE ASSET GRAIN on every step. Because the units are already the
 * grain, half-up division is the whole rule. This per-step rounding is why
 * `floor(stake × cumulative)` is NOT the payout for a multi-step round.
 */
export function foldLive(position: Position, stepPpm: bigint): Position {
    return { ...position, liveUnits: divHalfUp(position.liveUnits * stepPpm, SCALE_PPM) };
}

/** A lost decision forfeits the live part; the banked part stays the player's. */
export function loseLive(position: Position): Position {
    return { ...position, liveUnits: 0n };
}

/**
 * Mirrors `partial_cashout::apply_bank`: the de-lever may bank any positive
 * amount up to the live position, never more (that would mint value), never
 * zero. The kernel rejects the transcript on either, so this throws.
 */
export function bankFromLive(position: Position, amountUnits: bigint): Position {
    if (amountUnits <= 0n || amountUnits > position.liveUnits) {
        throw new ReplayError(
            `partial-cashout of ${amountUnits} units is not within the live position ${position.liveUnits}`,
        );
    }

    return {
        bankedUnits: position.bankedUnits + amountUnits,
        liveUnits: position.liveUnits - amountUnits,
    };
}

/** `banked + live` — what a cashout (or an abandon) pays. */
export function positionValue(position: Position): bigint {
    return position.bankedUnits + position.liveUnits;
}

/** Render a position as `banked X + live Y = Z` in whole-asset decimals. */
export function positionString(position: Position): string {
    const units = (value: bigint): string => unitsToDecimalString(value, TRANSCRIPT_DECIMALS);

    return `banked ${units(position.bankedUnits)} + live ${units(position.liveUnits)} = ${units(positionValue(position))}`;
}

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
