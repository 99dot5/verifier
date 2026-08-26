/**
 * mines:v1 — integer reimplementation of `libs/games/src/mines/v1/engine.rs` +
 * `math.rs`, pinned against `libs/games/src/mines/v1/testdata/vectors.json`.
 *
 * The mine layout is fixed at bet time by a partial Fisher–Yates shuffle
 * driven by the seed stream; gameplay actions derive nothing. Each safe
 * reveal multiplies the cumulative by a fair step — the house edge is
 * charged once per round, on the first reveal, so RTP is 99.5% at every
 * stopping depth. A mine hit settles at 0; revealing the last safe tile
 * auto-settles as a win.
 */
import { HOUSE_EDGE_PPM, SCALE_PPM } from './constants';
import { divHalfUp, mulPpm, ppmToMultiplierString } from './ints';
import { deriveSeed } from './seed';
import { ReplayError, type Outcome, type ReplayResult, type StepWorking, type TranscriptAction } from './types';
import { abandonStep } from './hilo';

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
 * Partial Fisher–Yates over tiles [0..25): draw `i` consumes 4 stream bytes
 * as a little-endian u32; `swap_index = i + ((raw × (25 − i)) >> 32)` (Lemire
 * wide-reduction, unbiased). The stream starts as the seed at action_index 0
 * and extends with the derivation at `action_index = stream_length / 32`
 * whenever a draw would run past the end. Mines = sorted first `mine_count`
 * entries.
 */
export function deriveLayout(serverSeed: string, clientSeed: string, mineCount: number): Layout {
    if (!Number.isInteger(mineCount) || mineCount < 1 || mineCount > TOTAL_TILES - 1) {
        throw new ReplayError(`mine_count must be 1..=24, got ${mineCount}`);
    }

    const tiles = Array.from({ length: TOTAL_TILES }, (_, i) => i);
    let stream = Array.from(deriveSeed(GAME_TYPE, serverSeed, clientSeed, 0));
    let offset = 0;
    const draws: LayoutDraw[] = [];

    for (let i = 0; i < mineCount; i++) {
        if (offset + 4 > stream.length) {
            const extensionIndex = Math.floor(stream.length / 32);

            stream = stream.concat(Array.from(deriveSeed(GAME_TYPE, serverSeed, clientSeed, extensionIndex)));
        }

        const raw =
            (stream[offset] | (stream[offset + 1] << 8) | (stream[offset + 2] << 16)) +
            stream[offset + 3] * 0x1000000;

        offset += 4;

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
 * The house edge is charged once per round, on the first reveal: k = 0 pays
 * `half_up(fair × 995000 / 1e6)`, every later reveal pays exact fair odds —
 * so the cumulative is `0.995 × fair(k)` at every stopping depth.
 */
export function stepMultiplierPpm(mineCount: number, revealedCount: number): bigint {
    const safe = TOTAL_TILES - mineCount;

    if (revealedCount >= safe) {
        throw new ReplayError(`no safe tiles left: mines=${mineCount} revealed=${revealedCount}`);
    }

    const fairStepPpm = divHalfUp(BigInt(TOTAL_TILES - revealedCount) * SCALE_PPM, BigInt(safe - revealedCount));

    return revealedCount === 0 ? mulPpm(fairStepPpm, HOUSE_EDGE_PPM) : fairStepPpm;
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
export function replay(serverSeed: string, clientSeed: string, actions: TranscriptAction[]): ReplayResult {
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

    for (const action of actions.slice(1)) {
        if (settled) {
            throw new ReplayError(`action after settlement: ${action.actionType}`);
        }

        switch (action.actionType) {
            case 'reveal': {
                const tile = decodeReveal(action.payload);

                if (tile >= TOTAL_TILES || revealed.has(tile)) {
                    throw new ReplayError(`invalid reveal: tile ${tile}`);
                }

                if (mineSet.has(tile)) {
                    cumulative = 0n;
                    outcome = 'lose';
                    settled = true;
                    steps.push({
                        actionIndex: action.actionIndex,
                        actionType: 'reveal',
                        title: `reveal tile ${tile} — MINE, round lost`,
                        details: [['tile', `${tile} is in the derived mine set`]],
                        cumulativePpm: 0n,
                    });
                    revealed.add(tile);
                    break;
                }

                const step = stepMultiplierPpm(mineCount, revealed.size);

                cumulative = mulPpm(cumulative, step);
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
                    details: [['cumulative', ppmToMultiplierString(cumulative)]],
                    cumulativePpm: cumulative,
                });
                outcome = 'cashout';
                settled = true;
                break;
            case 'abandon':
                cumulative = 0n;
                outcome = 'lose';
                steps.push(abandonStep(action.actionIndex));
                settled = true;
                break;
            default:
                throw new ReplayError(`unknown mines action: ${action.actionType}`);
        }
    }

    return { gameType: GAME_TYPE, steps, cumulativePpm: cumulative, outcome, settled };
}
