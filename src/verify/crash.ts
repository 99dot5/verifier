/**
 * crash:v1 — integer reimplementation of `libs/games/src/crash/v1/math.rs` and
 * `engine.rs`, pinned against `libs/games/src/crash/v1/testdata/vectors.json`.
 *
 * A multiplier rises from 1.00× and the round busts at a seed-determined
 * `crash_tick`. Everything a player can win on is fixed by the seed at
 * `action_index = 0`: `raw_u64` → `crash_point_ppm` → `crash_tick`. The later
 * actions decide only WHEN the round stops, never what the curve is.
 *
 * The curve is the constant-hazard exponential `m(N) = 2^(N / 100)`, evaluated
 * with no transcendental and no rounding at call time: `N = 100·q + r` splits
 * it into an exact shift `2^q` times the pinned 100-entry `2^(r/100)` table, so
 * a second runtime reproduces every multiplier from those constants alone.
 *
 * The house edge is charged once, on the single decision this game has (the
 * cashout), so crash's round RTP is a flat 99.5% — the per-decision schedule
 * and the per-round one coincide at depth 1. It rides in the crash point
 * rather than in the payout: `crash_point = (1 − η) / (1 − U)`, which makes
 * instant bust (`crash_tick == 0`) happen with probability exactly η = 0.5%.
 *
 * **Why this port is total where the Rust is fallible.** `math::crash_point_ppm`
 * returns `Result<i64, MathError>` because `fixed_point::div_round` is fallible
 * in general (division by zero, `i128` overflow of the rounding step). Neither
 * is reachable here and neither is representable in this port: the denominator
 * `2^64 − raw_u64` lies in `[1, 2^64]` for every `u64` input, so it is never
 * zero, and `bigint` has no width to overflow. The port therefore returns the
 * value directly instead of mirroring a `Result` that can only ever be `Ok` —
 * the input-range guard below is what keeps that reasoning true.
 */
import { HOUSE_EDGE_PPM, SCALE_PPM } from './constants';
import { divHalfUp, ppmToMultiplierString } from './ints';
import { bytesToHex, deriveSeed, rawU64 } from './seed';
import { ReplayError, type Outcome, type ReplayResult, type StepWorking, type TranscriptAction } from './types';
import { BorshError, BorshReader } from '../wire/borsh';

export const GAME_TYPE = 'crash:v1';

/** Ticks per doubling: `m(N) = 2^(N / DOUBLING_TICKS)`. REPLAY-CRITICAL. */
export const DOUBLING_TICKS = 100n;

/** House exposure cap on the crash point: 1000× = 1e9 ppm. REPLAY-CRITICAL. */
export const MAX_MULTIPLIER_CAP_PPM = 1_000_000_000n;

/**
 * The largest tick the curve reaches, derived from the multiplier cap:
 * `m(996) = 995_998_720 ≤ 1e9 < m(997) = 1_002_926_592`. REPLAY-CRITICAL.
 */
export const MAX_ROUND_TICK_CAP = 996n;

/** Tick quantum in milliseconds — 50 ms ⇒ 20 ticks/s. Rendered, never replayed:
 *  the rollup adjudicates in integer ticks and never sees a wall clock. */
export const TICK_QUANTUM_MS = 50n;

const TWO_POW_64 = 1n << 64n;

/**
 * `round_half_up(2^(r/100) · 10^6)` for `r = 0..=99` — the fractional half of
 * the curve, copied verbatim from `FRACTIONAL_POW2_PPM` in
 * `libs/games/src/crash/v1/math.rs` and asserted equal to `vectors.json`'s
 * `fractional_pow2_ppm` by the test rather than trusted. These 100 constants
 * ARE the canonical curve.
 */
export const FRACTIONAL_POW2_PPM: readonly bigint[] = [
    1_000_000n, 1_006_956n, 1_013_959n, 1_021_012n, 1_028_114n, 1_035_265n, 1_042_466n, 1_049_717n,
    1_057_018n, 1_064_370n, 1_071_773n, 1_079_228n, 1_086_735n, 1_094_294n, 1_101_905n, 1_109_569n,
    1_117_287n, 1_125_058n, 1_132_884n, 1_140_764n, 1_148_698n, 1_156_688n, 1_164_734n, 1_172_835n,
    1_180_993n, 1_189_207n, 1_197_479n, 1_205_808n, 1_214_195n, 1_222_640n, 1_231_144n, 1_239_708n,
    1_248_331n, 1_257_013n, 1_265_757n, 1_274_561n, 1_283_426n, 1_292_353n, 1_301_342n, 1_310_393n,
    1_319_508n, 1_328_686n, 1_337_928n, 1_347_234n, 1_356_604n, 1_366_040n, 1_375_542n, 1_385_109n,
    1_394_744n, 1_404_445n, 1_414_214n, 1_424_050n, 1_433_955n, 1_443_929n, 1_453_973n, 1_464_086n,
    1_474_269n, 1_484_524n, 1_494_849n, 1_505_247n, 1_515_717n, 1_526_259n, 1_536_875n, 1_547_565n,
    1_558_329n, 1_569_168n, 1_580_083n, 1_591_073n, 1_602_140n, 1_613_284n, 1_624_505n, 1_635_804n,
    1_647_182n, 1_658_639n, 1_670_176n, 1_681_793n, 1_693_491n, 1_705_270n, 1_717_131n, 1_729_074n,
    1_741_101n, 1_753_211n, 1_765_406n, 1_777_685n, 1_790_050n, 1_802_501n, 1_815_038n, 1_827_663n,
    1_840_375n, 1_853_176n, 1_866_066n, 1_879_045n, 1_892_115n, 1_905_276n, 1_918_528n, 1_931_873n,
    1_945_310n, 1_958_841n, 1_972_465n, 1_986_185n,] as const;

/**
 * `m(N)` in ppm: `(1 << (N / 100)) * FRACTIONAL_POW2_PPM[N % 100]`, with `N`
 * clamped to `MAX_ROUND_TICK_CAP` first. Exact — a shift and a table lookup,
 * no division and no rounding at call time.
 */
export function multiplierPpm(n: bigint): bigint {
    if (n < 0n) {
        throw new ReplayError(`crash tick must be non-negative, got ${n}`);
    }

    const clamped = n > MAX_ROUND_TICK_CAP ? MAX_ROUND_TICK_CAP : n;

    return (1n << (clamped / DOUBLING_TICKS)) * FRACTIONAL_POW2_PPM[Number(clamped % DOUBLING_TICKS)];
}

/**
 * The seed-determined crash point in ppm:
 * `clamp(half_up(HOUSE_EDGE_PPM · 2^64 / (2^64 − raw_u64)), 1e6, 1e9)`.
 *
 * The floor at 1.00× is the instant-bust clamp (`U < η`); the ceiling at 1000×
 * is the house exposure cap. Total by construction — see the module doc.
 */
export function crashPointPpm(raw: bigint): bigint {
    if (raw < 0n || raw >= TWO_POW_64) {
        throw new ReplayError(`raw_u64 out of range: ${raw}`);
    }

    // Denominator in [1, 2^64]: never zero, so the Rust's fallible div_round
    // cannot fail on this input and this port needs no error arm.
    const value = divHalfUp(HOUSE_EDGE_PPM * TWO_POW_64, TWO_POW_64 - raw);

    if (value < SCALE_PPM) {
        return SCALE_PPM;
    }

    return value > MAX_MULTIPLIER_CAP_PPM ? MAX_MULTIPLIER_CAP_PPM : value;
}

/**
 * The curve inverse: the smallest `N ≥ 0` with `m(N) ≥ crashPoint`, clamped to
 * `MAX_ROUND_TICK_CAP`. Monotone binary search, mirroring `math::crash_tick`.
 * `0` means instant bust — every cashout on that round loses.
 */
export function crashTick(crashPoint: bigint): bigint {
    if (multiplierPpm(0n) >= crashPoint) {
        return 0n;
    }

    let lo = 0n;
    let hi = MAX_ROUND_TICK_CAP;

    while (lo < hi) {
        const mid = lo + (hi - lo) / 2n;

        if (multiplierPpm(mid) >= crashPoint) {
            hi = mid;
        } else {
            lo = mid + 1n;
        }
    }

    return lo;
}

/** Everything the seed fixes at `place-bet`, before any player decision. */
export interface CrashRound {
    seedHex: string;
    rawU64: bigint;
    crashPointPpm: bigint;
    crashTick: bigint;
    /** The best multiplier a cashout could have taken: `m(crash_tick − 1)`, or 0 on an instant bust. */
    maxWinMultiplierPpm: bigint;
}

/**
 * Derive the round's crash point and tick. The derivation input is exactly
 * `(game_type, server_seed, client_seed, action_index = 0)`; `raw_u64` is the
 * little-endian u64 of the first 8 seed bytes.
 */
export function crashRound(serverSeed: string, clientSeed: string): CrashRound {
    const seed = deriveSeed(GAME_TYPE, serverSeed, clientSeed, 0);
    const raw = rawU64(seed);
    const point = crashPointPpm(raw);
    const tick = crashTick(point);

    return {
        seedHex: bytesToHex(seed),
        rawU64: raw,
        crashPointPpm: point,
        crashTick: tick,
        maxWinMultiplierPpm: tick === 0n ? 0n : multiplierPpm(tick - 1n),
    };
}

/** A decoded `place-bet` payload: `borsh(Config { auto_cashout_tick: Option<u32> })`. */
export interface CrashConfig {
    /** The pre-committed auto-cashout tick, or null for a manual round. */
    autoCashoutTick: bigint | null;
}

/**
 * Borsh-decode `Config { auto_cashout_tick: Option<u32> }` — a 1-byte `0x00`
 * for manual, or `0x01` followed by 4 little-endian bytes for auto. Strict:
 * trailing bytes are a malformed transcript, exactly as the kernel treats them.
 */
export function decodeConfig(payload: Uint8Array): CrashConfig {
    try {
        const reader = new BorshReader(payload);
        const tag = reader.u8();

        if (tag !== 0 && tag !== 1) {
            throw new ReplayError(`crash place-bet Option tag must be 0x00 or 0x01, got 0x${tag.toString(16)}`);
        }

        const autoCashoutTick = tag === 1 ? BigInt(reader.u32()) : null;

        reader.expectEnd();

        return { autoCashoutTick };
    } catch (error) {
        if (error instanceof BorshError) {
            throw new ReplayError(`crash place-bet payload is not a borsh Option<u32>: ${error.message}`);
        }

        throw error;
    }
}

/** Borsh-decode a `cashout` payload: the player's signed claimed tick as a u32. */
export function decodeCashoutTick(payload: Uint8Array): bigint {
    try {
        const reader = new BorshReader(payload);
        const tick = BigInt(reader.u32());

        reader.expectEnd();

        return tick;
    } catch (error) {
        if (error instanceof BorshError) {
            throw new ReplayError(`crash cashout payload is not a borsh u32: ${error.message}`);
        }

        throw error;
    }
}

function roundDetails(round: CrashRound): [string, string][] {
    return [
        ['derived seed', round.seedHex],
        ['raw u64 (LE of seed[0..8])', round.rawU64.toString()],
        ['crash point (half_up(995000 × 2^64 / (2^64 − raw)), clamped to [1×, 1000×])', ppmToMultiplierString(round.crashPointPpm)],
        ['crash tick (smallest N with m(N) ≥ crash point, capped at 996)', round.crashTick.toString()],
        ['best cashout available', round.crashTick === 0n
            ? 'none — instant bust, every cashout loses'
            : `tick ${round.crashTick - 1n} paying ${ppmToMultiplierString(round.maxWinMultiplierPpm)}`],
    ];
}

/**
 * Replay a full crash transcript exactly the way the rollup kernel does.
 *
 * The vocabulary is small and closed: `place-bet` at index 0, then at most one
 * of `cashout` (the player-claimed tick), `expire` (the crashed or
 * never-collected round) or `abandon` (termination from outside the round).
 * The kernel's per-game `AbandonPolicy` overrides crash to lose/0 rather than
 * parsing the abandon through the engine, which is what this reproduces.
 */
export function replay(serverSeed: string, clientSeed: string, actions: TranscriptAction[]): ReplayResult {
    if (actions.length === 0 || actions[0].actionType !== 'place-bet') {
        throw new ReplayError('crash transcript must start with place-bet');
    }

    const config = decodeConfig(actions[0].payload);
    const round = crashRound(serverSeed, clientSeed);
    const mode = config.autoCashoutTick === null
        ? 'manual'
        : `auto at tick ${config.autoCashoutTick}`;
    const steps: StepWorking[] = [
        {
            actionIndex: 0,
            actionType: 'place-bet',
            title: `place-bet (${mode}) — crashes at tick ${round.crashTick} (${ppmToMultiplierString(round.crashPointPpm)})`,
            details: [
                ...roundDetails(round),
                ['mode', config.autoCashoutTick === null
                    ? 'manual — settles on a player cashout or the deadline sweep'
                    : `auto — the pre-committed target tick ${config.autoCashoutTick} settles at the deadline sweep`],
                ['sealed at bet time', 'the curve and the crash tick are fixed here; later actions choose only when the round stops'],
            ],
            // Both modes start in progress at 1.00× — neither settles at place-bet.
            cumulativePpm: SCALE_PPM,
        },
    ];
    let cumulative = SCALE_PPM;
    let outcome: Outcome = 'lose';
    let settled = false;

    for (const action of actions.slice(1)) {
        if (settled) {
            throw new ReplayError(`action after settlement: ${action.actionType}`);
        }

        switch (action.actionType) {
            case 'cashout': {
                const tick = decodeCashoutTick(action.payload);
                // The comparison is on the UNCLAMPED tick (engine.rs settle_at_tick):
                // a tick at or past the crash loses, however far past it is. The
                // MAX_ROUND_TICK_CAP clamp inside multiplierPpm is therefore
                // unreachable on a winning cashout — a win implies tick < crash_tick ≤ 996.
                const win = tick < round.crashTick;

                cumulative = win ? multiplierPpm(tick) : 0n;
                steps.push({
                    actionIndex: action.actionIndex,
                    actionType: 'cashout',
                    title: win
                        ? `cashout at tick ${tick} — WIN, pays ${ppmToMultiplierString(cumulative)}`
                        : `cashout at tick ${tick} — LOSE, the round had already crashed at tick ${round.crashTick}`,
                    details: [
                        ['player-claimed cashout tick (signed in crash.v1.CashOut, borsh u32)', tick.toString()],
                        ['crash tick', round.crashTick.toString()],
                        ['rule', 'a cashout pays stake × m(tick) iff tick < crash_tick, else 0 — compared unclamped'],
                        ['multiplier', ppmToMultiplierString(cumulative)],
                    ],
                    cumulativePpm: cumulative,
                });
                outcome = win ? 'cashout' : 'lose';
                settled = true;
                break;
            }
            case 'expire':
                cumulative = 0n;
                steps.push({
                    actionIndex: action.actionIndex,
                    actionType: 'expire',
                    title: 'expire (system) — the round crashed with no cashout, pays 0',
                    details: [
                        ['crash tick', round.crashTick.toString()],
                        ['rule', 'expire is always a loss with payout 0 — no crash-tick comparison'],
                    ],
                    cumulativePpm: 0n,
                });
                outcome = 'lose';
                settled = true;
                break;
            case 'abandon':
                cumulative = 0n;
                steps.push({
                    actionIndex: action.actionIndex,
                    actionType: 'abandon',
                    title: 'abandon (system) — round forfeited, pays 0',
                    details: [['rule', "the rollup's crash AbandonPolicy overrides an abandoned round to lose / 0"]],
                    cumulativePpm: 0n,
                });
                outcome = 'lose';
                settled = true;
                break;
            default:
                throw new ReplayError(`unknown crash action: ${action.actionType}`);
        }
    }

    return { gameType: GAME_TYPE, steps, cumulativePpm: cumulative, outcome, settled };
}
