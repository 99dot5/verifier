/**
 * mines:v1 — integer reimplementation of `libs/games/src/mines/v1/engine.rs` +
 * `math.rs`, pinned against `libs/games/src/mines/v1/testdata/vectors.json`.
 *
 * The mine layout is fixed at bet time by a partial Fisher–Yates shuffle
 * driven by the seed stream; gameplay actions derive nothing. Each safe
 * reveal multiplies the cumulative by a step priced at fair odds times the
 * house edge — charged on every reveal, so RTP is 99.5% per reveal and
 * `0.995^k` over the round. Revealing the last safe tile auto-settles as a win.
 *
 * Two SYSTEM-ONLY transcript steps back the max-win cap
 * (docs/specs/max-win-cap.md): `partial-cashout` (banks part of the position
 * to the session balance — chain untouched; the layout and step pricing are
 * index-insensitive in mines) and `abandon`, which settles at the position's
 * current value, `banked + live` — what a cashout would pay — with outcome
 * `lose` (sec-28; it used to forfeit the live part, and before any reveal
 * that is the stake). A mine hit pays the banked total (0 when nothing was
 * banked).
 *
 * The payout follows the banked/live fold of `partial_cashout.rs` — the live
 * part rounds at the asset grain on every safe reveal — not
 * `floor(stake × cumulative)`.
 */
import { HOUSE_EDGE_PPM, SCALE_PPM } from './constants';
import { divHalfUp, mulPpm, ppmToMultiplierString } from './ints';
import { SeedStream } from './seed';
import { ReplayError, type Outcome, type ReplayResult, type StepWorking, type TranscriptAction } from './types';
import { abandonStep } from './hilo';
import {
    ZERO_BANKED,
    addBanked,
    bankFromLive,
    bankedAmountString,
    decodePartialCashout,
    foldLive,
    loseLive,
    openPosition,
    partialCashoutStep,
    positionValue,
    type Position,
} from './partial-cashout';

export const GAME_TYPE = 'mines:v1';
export const TOTAL_TILES = 25;

export interface LayoutDraw {
    draw: number;
    rawU32: number;
    swapIndex: number;
}

export interface Layout {
    minePositions: number[];
    draws: LayoutDraw[];
}

/**
 * Partial Fisher–Yates over tiles [0..25): draw `i` consumes the next 4 bytes
 * of decision 0's stream (the bet) as a little-endian u32; `swap_index = i +
 * ((raw × (25 − i)) >> 32)` (Lemire wide-reduction, unbiased). 24 mines read
 * 96 bytes, inside the stream's 128-byte budget. Reveals draw nothing. Mines =
 * sorted first `mine_count` entries.
 */
export function deriveLayout(serverSeed: string, clientSeed: string, mineCount: number): Layout {
    if (!Number.isInteger(mineCount) || mineCount < 1 || mineCount > TOTAL_TILES - 1) {
        throw new ReplayError(`mine_count must be 1..=24, got ${mineCount}`);
    }

    const tiles = Array.from({ length: TOTAL_TILES }, (_, i) => i);
    const stream = new SeedStream(GAME_TYPE, serverSeed, clientSeed, 0);
    const draws: LayoutDraw[] = [];

    for (let i = 0; i < mineCount; i++) {
        const bytes = stream.take(4);
        const raw = (bytes[0] | (bytes[1] << 8) | (bytes[2] << 16)) + bytes[3] * 0x1000000;

        const remaining = TOTAL_TILES - i;
        const swapIndex = i + Number((BigInt(raw) * BigInt(remaining)) >> 32n);

        draws.push({ draw: i, rawU32: raw, swapIndex });
        [tiles[i], tiles[swapIndex]] = [tiles[swapIndex], tiles[i]];
    }

    return { minePositions: tiles.slice(0, mineCount).sort((a, b) => a - b), draws };
}

/**
 * Multiplier for revealing the k-th safe tile (k 0-indexed):
 * `fair = half_up((25 − k) × 1e6 / (safe − k))` with `safe = 25 − mine_count`.
 * The house edge is charged on every reveal: each k pays
 * `half_up(fair × 995000 / 1e6)` — every reveal, not just the first — so the
 * cumulative is `0.995^k × fair(k)` and round RTP compounds with depth. See
 * `docs/specs/per-decision-house-edge.md`.
 */
export function stepMultiplierPpm(mineCount: number, revealedCount: number): bigint {
    const safe = TOTAL_TILES - mineCount;

    if (revealedCount >= safe) {
        throw new ReplayError(`no safe tiles left: mines=${mineCount} revealed=${revealedCount}`);
    }

    const fairStepPpm = divHalfUp(BigInt(TOTAL_TILES - revealedCount) * SCALE_PPM, BigInt(safe - revealedCount));

    return mulPpm(fairStepPpm, HOUSE_EDGE_PPM);
}

/** Borsh-decode a place-bet `Config { mine_count: u32 LE }`. */
export function decodeConfig(payload: Uint8Array): number {
    if (payload.length !== 4) {
        throw new ReplayError(`mines place-bet payload must be 4 bytes, got ${payload.length}`);
    }

    return new DataView(payload.buffer, payload.byteOffset).getUint32(0, true);
}

/** Borsh-decode a reveal payload (`tile_index: u32 LE`). */
export function decodeReveal(payload: Uint8Array): number {
    if (payload.length !== 4) {
        throw new ReplayError(`mines reveal payload must be 4 bytes, got ${payload.length}`);
    }

    return new DataView(payload.buffer, payload.byteOffset).getUint32(0, true);
}

/** Replay a full mines transcript exactly the way the rollup kernel does. */
export function replay(
    serverSeed: string,
    clientSeed: string,
    actions: TranscriptAction[],
    stakeUnits: bigint,
): ReplayResult {
    if (actions.length === 0 || actions[0].actionType !== 'place-bet') {
        throw new ReplayError('mines transcript must start with place-bet');
    }

    const mineCount = decodeConfig(actions[0].payload);
    const layout = deriveLayout(serverSeed, clientSeed, mineCount);
    const mineSet = new Set(layout.minePositions);
    const revealed = new Set<number>();
    const steps: StepWorking[] = [
        {
            actionIndex: 0,
            actionType: 'place-bet',
            title: `place-bet — ${mineCount} mines hidden in 25 tiles`,
            details: [
                ['mine positions (derived from seed, hidden until reveal)', layout.minePositions.join(', ')],
                [
                    'layout draws (raw u32 → swap index)',
                    layout.draws.map((d) => `#${d.draw}: ${d.rawU32} → ${d.swapIndex}`).join('; '),
                ],
            ],
            cumulativePpm: SCALE_PPM,
        },
    ];
    let cumulative = SCALE_PPM;
    let outcome: Outcome = 'lose';
    let settled = false;
    let bankedTotal = ZERO_BANKED;
    let position: Position = openPosition(stakeUnits);

    for (const action of actions.slice(1)) {
        if (settled) {
            // The kernel stops at the first settle and never reads what follows
            // (libs/smart-rollup/src/games.rs); the verifier's
            // actions-after-settle check reports any such entries.
            break;
        }

        switch (action.actionType) {
            case 'reveal': {
                const tile = decodeReveal(action.payload);

                if (tile >= TOTAL_TILES || revealed.has(tile)) {
                    throw new ReplayError(`invalid reveal: tile ${tile}`);
                }

                if (mineSet.has(tile)) {
                    cumulative = 0n;
                    position = loseLive(position);
                    outcome = 'lose';
                    settled = true;
                    steps.push({
                        actionIndex: action.actionIndex,
                        actionType: 'reveal',
                        title: `reveal tile ${tile} — MINE, round lost`,
                        details: [
                            ['tile', `${tile} is in the derived mine set`],
                            ...(bankedTotal.amount > 0n
                                ? ([
                                      [
                                          'payout',
                                          `the banked total ${bankedAmountString(bankedTotal)} (already the player's)`,
                                      ],
                                  ] as [string, string][])
                                : []),
                        ],
                        cumulativePpm: 0n,
                    });
                    revealed.add(tile);
                    break;
                }

                const step = stepMultiplierPpm(mineCount, revealed.size);

                cumulative = mulPpm(cumulative, step);
                position = foldLive(position, step);
                revealed.add(tile);

                const allSafeRevealed = revealed.size >= TOTAL_TILES - mineCount;

                steps.push({
                    actionIndex: action.actionIndex,
                    actionType: 'reveal',
                    title: `reveal tile ${tile} — safe (${revealed.size}/${TOTAL_TILES - mineCount})`,
                    details: [
                        ['step multiplier', ppmToMultiplierString(step)],
                        ['cumulative', ppmToMultiplierString(cumulative)],
                        ...(allSafeRevealed
                            ? ([['auto-settle', 'all safe tiles revealed — round won']] as [string, string][])
                            : []),
                    ],
                    cumulativePpm: cumulative,
                });

                if (allSafeRevealed) {
                    outcome = 'win';
                    settled = true;
                }
                break;
            }
            case 'cashout':
                if (revealed.size === 0) {
                    throw new ReplayError('mines cashout requires at least one reveal');
                }

                steps.push({
                    actionIndex: action.actionIndex,
                    actionType: 'cashout',
                    title: `cashout at ${ppmToMultiplierString(cumulative)}`,
                    details: [
                        ['cumulative', ppmToMultiplierString(cumulative)],
                        ...(bankedTotal.amount > 0n
                            ? ([
                                  [
                                      'payout',
                                      `banked total ${bankedAmountString(bankedTotal)} + the live position`,
                                  ],
                              ] as [string, string][])
                            : []),
                    ],
                    cumulativePpm: cumulative,
                });
                outcome = 'cashout';
                settled = true;
                break;
            case 'partial-cashout': {
                const banked = decodePartialCashout(action.payload);

                bankedTotal = addBanked(bankedTotal, banked);
                position = bankFromLive(position, banked.amount);
                steps.push(partialCashoutStep(action.actionIndex, banked, bankedTotal, cumulative));
                break;
            }
            case 'abandon':
                // Admissible before any reveal (unlike a cashout): the sweep's
                // only settling action for an untouched round, worth the stake.
                outcome = 'lose';
                steps.push(abandonStep(action.actionIndex, position, cumulative));
                settled = true;
                break;
            default:
                throw new ReplayError(`unknown mines action: ${action.actionType}`);
        }
    }

    return {
        gameType: GAME_TYPE,
        steps,
        cumulativePpm: cumulative,
        outcome,
        settled,
        // Every settling path pushes its step last, so the final step is the
        // settling action.
        settledAtIndex: settled ? steps[steps.length - 1].actionIndex : null,
        payoutUnits: positionValue(position),
        bankedUnits: position.bankedUnits,
    };
}
