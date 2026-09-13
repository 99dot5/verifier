/**
 * Integer fixed-point primitives mirroring `libs/game-engine-core/src/fixed_point.rs`.
 *
 * Everything is `bigint`; there is deliberately not a single floating-point
 * operation in this directory. The engines are integer-only (the rollup is
 * `no_std` and its CI forbids float instructions), which is what lets this
 * TypeScript reimplementation reproduce the on-chain results EXACTLY — every
 * function here is pinned against the golden vectors in
 * `libs/games/src/<game>/v1/testdata/vectors.json`.
 */

export const SCALE_PPM = 1_000_000n;

/**
 * Round-half-up (midpoint away from zero) division for non-negative operands
 * — the only domain the game math touches. Mirrors
 * `fixed_point.rs::div_round(HalfUp)`.
 */
export function divHalfUp(numerator: bigint, denominator: bigint): bigint {
    if (numerator < 0n || denominator <= 0n) {
        throw new RangeError('divHalfUp is defined for non-negative / positive operands only');
    }

    const quotient = numerator / denominator;
    const remainder = numerator % denominator;

    return 2n * remainder >= denominator ? quotient + 1n : quotient;
}

/** `half_up(numerator * 1e6 / denominator)` — mirrors `to_ppm_ratio`. */
export function toPpmRatio(numerator: bigint, denominator: bigint): bigint {
    return divHalfUp(numerator * SCALE_PPM, denominator);
}

/** `half_up(a * b / 1e6)` — mirrors `mul_ppm`. */
export function mulPpm(aPpm: bigint, bPpm: bigint): bigint {
    return divHalfUp(aPpm * bPpm, SCALE_PPM);
}

/**
 * The payout rule at the trust boundary, in the rollup's own units.
 *
 * The kernel replays the round, computes `amount_won = stake ×
 * cumulative_multiplier_ppm / 1e6` as a decimal (half-up, ≤18 dp — exact for
 * any stake with ≤6 dp, i.e. every mutez-denominated stake), then converts to
 * `u128` atomic units by truncating TOWARD ZERO at the asset's scale
 * (`libs/smart-rollup/src/games.rs`: `decimal_to_units(truncate_to_decimals(
 * amount_won, decimals), decimals)`, where `decimals` comes from the session's
 * bound asset via `money::decimals_for` — the table this app mirrors in
 * `./assets`). For a stake in integer base units (mutez, scale 6) that
 * collapses to a single floor division:
 *
 *     payout_units = floor(stake_units × cumulative_ppm / 1e6)
 */
export function payoutUnits(stakeUnits: bigint, cumulativePpm: bigint): bigint {
    if (stakeUnits < 0n || cumulativePpm < 0n) {
        throw new RangeError('payoutUnits is defined for non-negative operands only');
    }

    return (stakeUnits * cumulativePpm) / SCALE_PPM;
}

/**
 * Render an integer amount of base units at the given scale as an exact
 * decimal string ("721.4038"), trailing zeros trimmed. Used for display and
 * for comparing against the golden vectors' decimal payout strings.
 */
export function unitsToDecimalString(units: bigint, scale: number): string {
    const factor = 10n ** BigInt(scale);
    const whole = units / factor;
    const frac = units % factor;

    if (frac === 0n) {
        return whole.toString();
    }

    return `${whole}.${frac.toString().padStart(scale, '0').replace(/0+$/, '')}`;
}

/**
 * Parse an exact decimal string ("100", "721.4038") into base units at the
 * given scale. Throws if the value needs more fractional digits than `scale`.
 */
export function decimalStringToUnits(value: string, scale: number): bigint {
    const match = /^(\d+)(?:\.(\d+))?$/.exec(value.trim());

    if (!match) {
        throw new RangeError(`not a non-negative decimal: ${JSON.stringify(value)}`);
    }

    const [, whole, frac = ''] = match;

    if (frac.length > scale) {
        throw new RangeError(`${value} has more than ${scale} fractional digits`);
    }

    return BigInt(whole) * 10n ** BigInt(scale) + BigInt(frac.padEnd(scale, '0') || '0');
}

/** Render a ppm multiplier as a human "×" string: 1_036_458 → "1.036458×". */
export function ppmToMultiplierString(ppm: bigint): string {
    return `${unitsToDecimalString(ppm, 6)}×`;
}
