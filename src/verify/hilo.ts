/**
 * hilo:v1 — integer reimplementation of `libs/games/src/hilo/v1/engine.rs`,
 * pinned against `libs/games/src/hilo/v1/testdata/vectors.json`.
 *
 * Each step derives one card from the seed at that step's `action_index`.
 * Both directional multipliers are quoted on the CURRENT card; a guess pays
 * the multiplier quoted on the card it was made against. An equal rank wins
 * BOTH directions.
 *
 * The house edge is charged on every guess, so RTP is
 * 99.5% per guess, so round RTP is `0.995^n` — see
 * `docs/specs/per-decision-house-edge.md`.
 *
 * Two SYSTEM-ONLY transcript steps back the max-win cap
 * (docs/specs/max-win-cap.md): `partial-cashout` (banks part of the position
 * to the session balance — chain untouched; note it consumes an action
 * index, shifting every later card draw) and `abandon`, which forfeits the
 * live position and pays the banked total.
 */
import { HOUSE_EDGE_PPM, SCALE_PPM } from './constants';
import { mulPpm, ppmToMultiplierString, toPpmRatio } from './ints';
import { bytesToHex, deriveSeed, rawU64 } from './seed';
import { ReplayError, type Outcome, type ReplayResult, type StepWorking, type TranscriptAction } from './types';
import {
    ZERO_BANKED,
    addBanked,
    bankedAmountString,
    decodePartialCashout,
    partialCashoutStep,
} from './partial-cashout';

export const GAME_TYPE = 'hilo:v1';

export const RANKS = [
    'ace', 'two', 'three', 'four', 'five', 'six', 'seven',
    'eight', 'nine', 'ten', 'jack', 'queen', 'king',
] as const;
export const SUITS = ['clubs', 'diamonds', 'hearts', 'spades'] as const;

const TOTAL_RANKS = 13n;
const DECK_SIZE = 52n;

export interface HiloStep {
    actionIndex: number;
    seedHex: string;
    rawU64: bigint;
    deckIndex: number;
    rank: (typeof RANKS)[number];
    suit: (typeof SUITS)[number];
    /** Ace=1 … King=13. */
    rankNumeric: number;
    lowerProbabilityPpm: bigint;
    lowerMultiplierPpm: bigint;
    higherProbabilityPpm: bigint;
    higherMultiplierPpm: bigint;
}

/**
 * Price one direction: fair odds times the house edge. Every guess is its own
 * bet and carries the edge, so the round's retention compounds as `0.995^n`.
 * Mirrors `games::hilo::v1::math::step_multiplier_ppm` — the depth argument it
 * used to need is gone, because the price no longer varies with depth.
 */
function quote(fairPpm: bigint): bigint {
    return mulPpm(fairPpm, HOUSE_EDGE_PPM);
}

/** Derive the card and both directional quotes at one action index. */
export function hiloStep(serverSeed: string, clientSeed: string, actionIndex: number): HiloStep {
    const seed = deriveSeed(GAME_TYPE, serverSeed, clientSeed, actionIndex);
    const raw = rawU64(seed);
    // Lemire wide-reduction: (raw * 52) >> 64 — uniform in 0..=51, no modulo bias.
    const deckIndex = Number((raw * DECK_SIZE) >> 64n);
    const rankNumeric = (deckIndex % 13) + 1;
    const higherCount = BigInt(13 - rankNumeric + 1);
    const lowerCount = BigInt(rankNumeric);
    const higherProbabilityPpm = toPpmRatio(higherCount, TOTAL_RANKS);
    const lowerProbabilityPpm = toPpmRatio(lowerCount, TOTAL_RANKS);

    return {
        actionIndex,
        seedHex: bytesToHex(seed),
        rawU64: raw,
        deckIndex,
        rank: RANKS[deckIndex % 13],
        suit: SUITS[Math.floor(deckIndex / 13)],
        rankNumeric,
        lowerProbabilityPpm,
        lowerMultiplierPpm: quote(toPpmRatio(SCALE_PPM, lowerProbabilityPpm)),
        higherProbabilityPpm,
        higherMultiplierPpm: quote(toPpmRatio(SCALE_PPM, higherProbabilityPpm)),
    };
}

function cardName(step: HiloStep): string {
    return `${step.rank} of ${step.suit}`;
}

function stepDetails(step: HiloStep): [string, string][] {
    return [
        ['derived seed', step.seedHex],
        ['raw u64 (LE of seed[0..8])', step.rawU64.toString()],
        ['deck index ((raw × 52) >> 64)', String(step.deckIndex)],
        ['card', `${cardName(step)} (rank ${step.rankNumeric})`],
        ['P(lower or equal)', `${step.lowerProbabilityPpm} ppm`],
        ['lower pays', ppmToMultiplierString(step.lowerMultiplierPpm)],
        ['P(higher or equal)', `${step.higherProbabilityPpm} ppm`],
        ['higher pays', ppmToMultiplierString(step.higherMultiplierPpm)],
    ];
}

/** Replay a full hilo transcript exactly the way the rollup kernel does. */
export function replay(
    serverSeed: string,
    clientSeed: string,
    actions: TranscriptAction[],
): ReplayResult {
    if (actions.length === 0 || actions[0].actionType !== 'place-bet') {
        throw new ReplayError('hilo transcript must start with place-bet');
    }

    const steps: StepWorking[] = [];
    let current = hiloStep(serverSeed, clientSeed, 0);
    let cumulative = SCALE_PPM;
    let outcome: Outcome = 'lose';
    let settled = false;
    let bankedTotal = ZERO_BANKED;

    steps.push({
        actionIndex: 0,
        actionType: 'place-bet',
        title: `place-bet — first card: ${cardName(current)}`,
        details: stepDetails(current),
        cumulativePpm: cumulative,
    });

    for (const action of actions.slice(1)) {
        if (settled) {
            throw new ReplayError(`action after settlement: ${action.actionType}`);
        }

        switch (action.actionType) {
            case 'higher':
            case 'lower': {
                const next = hiloStep(serverSeed, clientSeed, action.actionIndex);
                const win =
                    action.actionType === 'higher'
                        ? next.rankNumeric >= current.rankNumeric
                        : next.rankNumeric <= current.rankNumeric;
                const quoted =
                    action.actionType === 'higher' ? current.higherMultiplierPpm : current.lowerMultiplierPpm;

                cumulative = win ? mulPpm(cumulative, quoted) : 0n;

                steps.push({
                    actionIndex: action.actionIndex,
                    actionType: action.actionType,
                    title: `${action.actionType} — drew ${cardName(next)}: ${win ? 'WIN' : 'LOSE'}`,
                    details: [
                        ...stepDetails(next),
                        ['guess', `${action.actionType} vs rank ${current.rankNumeric} (ties win both ways)`],
                        ['quoted multiplier', ppmToMultiplierString(quoted)],
                        ['cumulative', ppmToMultiplierString(cumulative)],
                    ],
                    cumulativePpm: cumulative,
                });

                if (!win) {
                    outcome = 'lose';
                    settled = true;
                }

                current = next;
                break;
            }
            case 'cashout':
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
                steps.push(partialCashoutStep(action.actionIndex, banked, bankedTotal, cumulative));
                break;
            }
            case 'abandon':
                cumulative = 0n;
                steps.push(abandonStep(action.actionIndex, bankedAmountString(bankedTotal)));
                outcome = 'lose';
                settled = true;
                break;
            default:
                throw new ReplayError(`unknown hilo action: ${action.actionType}`);
        }
    }

    return { gameType: GAME_TYPE, steps, cumulativePpm: cumulative, outcome, settled };
}

/** Abandonment is a real engine action: the live position is forfeited but
 *  the banked total (already the player's) is the round's payout. */
export function abandonStep(actionIndex: number, bankedTotal: string): StepWorking {
    return {
        actionIndex,
        actionType: 'abandon',
        title: `abandon (system) — live position forfeited, pays the banked total ${bankedTotal}`,
        details: [['rule', 'abandonment settles as a loss paying the banked total']],
        cumulativePpm: 0n,
    };
}
