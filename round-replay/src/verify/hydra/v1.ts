/**
 * hydra:v1 — integer reimplementation of `libs/games/src/hydra/v1/engine.rs` +
 * `math.rs`, pinned against `libs/games/src/hydra/v1/testdata/vectors.json`.
 *
 * The player picks a party of 0–8 companions at the bet and then rolls a d20
 * against twelve beasts of rising difficulty class. A roll beats a beast when
 * the face is a natural 20, or when it is not a natural 1 and
 * `face + companions ≥ dc`. Each roll is priced at fair odds for the
 * faces that win, times the house edge — charged on every roll, so RTP is
 * 99.5% per roll and `0.995^k` over the round. Slaying the twelfth beast
 * settles the round as completed, and so does a win after which the next
 * win would carry the cumulative multiplier past 1,000× (the ceiling); a miss
 * is a bust that pays the banked total.
 *
 * Randomness: the bet draws nothing (the player picks the party), so the
 * k-th roll is decision k−1. A roll reads the first 4 bytes of its stream as
 * a little-endian u32 and maps it onto a face by Lemire: `((raw × 20) >> 32)
 * + 1`. Cashout, partial-cashout and abandon draw nothing.
 *
 * `partial-cashout` (the max-win de-lever) and `abandon` are SYSTEM-ONLY;
 * `abandon` pays `banked + live`, what a cashout would pay.
 */
import { HOUSE_EDGE_PPM, SCALE_PPM } from '../constants';
import { divHalfUp, mulPpm, ppmToMultiplierString } from '../ints';
import { SeedStream, bytesToHex } from '../seed';
import { ReplayError, type Ending, type ReplayResult, type StepWorking, type TranscriptAction } from '../types';
import { abandonStep } from '../hilo/v1';
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
} from '../partial-cashout';

export const GAME_TYPE = 'hydra:v1';
export const DIE_FACES = 20;
export const MAX_COMPANIONS = 8;
export const BONUS_PER_COMPANION = 1;
/** The twelve beasts' difficulty classes; 19 is skipped so the last is a DC 20. */
export const DIFFICULTY_CLASSES: readonly number[] = [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 20];
export const STAGES = DIFFICULTY_CLASSES.length;
/**
 * The twelve beasts' names, in the order they are fought: the names the game
 * shows. Display only (a beast is priced by its DC alone), pinned to the
 * vectors' `algorithm.beast_names`, which the game client pins to as well.
 */
export const BEAST_NAMES: readonly string[] = [
    'Lion',
    'Hydra',
    'Boar',
    'Chimera',
    'Harpy',
    'Cyclops',
    'Minotaur',
    'Griffin',
    'Medusa',
    'Siren',
    'Typhon',
    'Cerberus',
];
/** The ceiling on a run's cumulative multiplier, 1,000× in ppm. */
export const MAX_CUMULATIVE_MULTIPLIER_PPM = 1_000_000_000n;

/** Whether `face` beats `dc` with the party's `bonus`. */
export function wins(face: number, dc: number, bonus: number): boolean {
    return face === DIE_FACES || (face !== 1 && face + bonus >= dc);
}

/** How many of the twenty faces beat `dc` with `bonus` (always 1..=19). */
export function winningFaces(dc: number, bonus: number): number {
    let count = 0;

    for (let face = 1; face <= DIE_FACES; face++) {
        if (wins(face, dc, bonus)) {
            count++;
        }
    }

    return count;
}

/** `half_up(half_up(20e6 / faces) × 995000 / 1e6)`. */
export function stepMultiplierPpm(faces: number): bigint {
    if (!Number.isInteger(faces) || faces < 1 || faces > DIE_FACES) {
        throw new ReplayError(`winning faces must be 1..=20, got ${faces}`);
    }

    return mulPpm(divHalfUp(BigInt(DIE_FACES) * SCALE_PPM, BigInt(faces)), HOUSE_EDGE_PPM);
}

export interface Roll {
    decision: number;
    chunk0Hex: string;
    rawU32: number;
    face: number;
}

/** The roll drawn at `decision`: the stream's first 4 bytes, little-endian, onto 1..=20. */
export function hydraRoll(serverSeed: string, clientSeed: string, decision: number): Roll {
    const stream = new SeedStream(GAME_TYPE, serverSeed, clientSeed, decision);
    const bytes = stream.take(4);
    const raw = (bytes[0] | (bytes[1] << 8) | (bytes[2] << 16)) + bytes[3] * 0x1000000;
    const face = Number((BigInt(raw) * BigInt(DIE_FACES)) >> 32n) + 1;

    return { decision, chunk0Hex: bytesToHex(stream.derivedChunks()[0]), rawU32: raw, face };
}

export interface HydraConfig {
    companions: number;
    /** The 0-based beast the run starts at (0 is the first). */
    startStage: number;
}

/** Borsh-decode a place-bet `Config { companions: u8, start_stage: u8 }`. */
export function decodeConfig(payload: Uint8Array): HydraConfig {
    if (payload.length !== 2) {
        throw new ReplayError(`hydra:v1 place-bet payload must be 2 bytes, got ${payload.length}`);
    }

    const companions = payload[0];
    const startStage = payload[1];

    if (companions > MAX_COMPANIONS) {
        throw new ReplayError(`hydra:v1 companions must be 0..=${MAX_COMPANIONS}, got ${companions}`);
    }

    if (startStage >= STAGES) {
        throw new ReplayError(`hydra:v1 start_stage must be 0..${STAGES}, got ${startStage}`);
    }

    return { companions, startStage };
}

function ensureEmpty(action: TranscriptAction): void {
    if (action.payload.length !== 0) {
        throw new ReplayError(
            `hydra:v1 ${action.actionType} carries a ${action.payload.length}-byte payload; it takes none`,
        );
    }
}

/** A beast as the game names it, from its 0-based `stage`: "the Cyclops". */
function beastName(stage: number): string {
    return `the ${BEAST_NAMES[stage]}`;
}

/**
 * The detail row for a beast: "the Cyclops, 6 of 12, health 13". The game
 * shows a beast's difficulty class as its health, so the replay says so too.
 */
function beastDetail(stage: number): string {
    return `${beastName(stage)}, ${stage + 1} of ${STAGES}, health ${DIFFICULTY_CLASSES[stage]}`;
}

function partyLabel(companions: number): string {
    return companions === 0 ? 'solo' : `${companions} companion${companions === 1 ? '' : 's'}`;
}

/** Replay a full hydra:v1 transcript exactly the way the rollup kernel does. */
export function replay(
    serverSeed: string,
    clientSeed: string,
    actions: TranscriptAction[],
    stakeUnits: bigint,
): ReplayResult {
    if (actions.length === 0 || actions[0].actionType !== 'place-bet') {
        throw new ReplayError('hydra:v1 transcript must start with place-bet');
    }

    const { companions, startStage } = decodeConfig(actions[0].payload);
    const bonus = companions * BONUS_PER_COMPANION;
    const steps: StepWorking[] = [
        {
            actionIndex: 0,
            actionType: 'place-bet',
            title: `place-bet — ${partyLabel(companions)}, party power +${bonus}${
                startStage > 0 ? `, from ${beastName(startStage)}` : ''
            }`,
            details: [
                ['first beast', `${beastDetail(startStage)}, at 1×`],
                [
                    'rule',
                    `a roll wins on a natural 20, or when it is not a natural 1 and face + party power ${bonus} ≥ the beast's health`,
                ],
                ['beast health', DIFFICULTY_CLASSES.join(', ')],
            ],
            cumulativePpm: SCALE_PPM,
        },
    ];
    let cumulative = SCALE_PPM;
    let outcome: Ending = 'bust';
    let settled = false;
    // The ladder position: the beast the run started at plus those slain.
    let slain = startStage;
    let decision = 0;
    let bankedTotal = ZERO_BANKED;
    let position: Position = openPosition(stakeUnits);

    for (const action of actions.slice(1)) {
        if (settled) {
            // The kernel stops at the first settle and never reads what follows.
            break;
        }

        switch (action.actionType) {
            case 'roll': {
                ensureEmpty(action);

                const dc = DIFFICULTY_CLASSES[slain];
                const faces = winningFaces(dc, bonus);
                const step = stepMultiplierPpm(faces);
                const roll = hydraRoll(serverSeed, clientSeed, decision);
                const won = wins(roll.face, dc, bonus);
                const details: [string, string][] = [
                    ['decision', String(roll.decision)],
                    ['roll (bytes [0..4))', `${roll.rawU32} → face ${roll.face}`],
                    ['beast', beastDetail(slain)],
                    ['winning faces', `${faces} of 20 (${faces * 5}%)`],
                    ['step multiplier', ppmToMultiplierString(step)],
                ];

                decision++;

                if (!won) {
                    cumulative = 0n;
                    position = loseLive(position);
                    outcome = 'bust';
                    settled = true;
                    steps.push({
                        actionIndex: action.actionIndex,
                        actionType: 'roll',
                        title: `roll ${roll.face} against ${beastName(slain)} (health ${dc}) — missed, round lost`,
                        details: [
                            ...details,
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
                    break;
                }

                cumulative = mulPpm(cumulative, step);
                position = foldLive(position, step);
                slain++;

                const allSlain = slain >= STAGES;
                const capped =
                    !allSlain &&
                    mulPpm(cumulative, stepMultiplierPpm(winningFaces(DIFFICULTY_CLASSES[slain], bonus))) >
                        MAX_CUMULATIVE_MULTIPLIER_PPM;
                const cleared = allSlain || capped;

                steps.push({
                    actionIndex: action.actionIndex,
                    actionType: 'roll',
                    title: `roll ${roll.face} against ${beastName(slain - 1)} (health ${dc}) — slain`,
                    details: [
                        ...details,
                        ['cumulative', ppmToMultiplierString(cumulative)],
                        ...(allSlain
                            ? ([['auto-settle', 'all twelve beasts slain — round completed']] as [string, string][])
                            : capped
                              ? ([['auto-settle', 'the next win would pass 1,000× — round completed']] as [
                                    string,
                                    string,
                                ][])
                              : []),
                    ],
                    cumulativePpm: cumulative,
                });

                if (cleared) {
                    outcome = 'completed';
                    settled = true;
                }
                break;
            }
            case 'cashout':
                ensureEmpty(action);
                steps.push({
                    actionIndex: action.actionIndex,
                    actionType: 'cashout',
                    title: `cashout at ${ppmToMultiplierString(cumulative)}`,
                    details: [
                        ['cumulative', ppmToMultiplierString(cumulative)],
                        ...(bankedTotal.amount > 0n
                            ? ([['payout', `banked total ${bankedAmountString(bankedTotal)} + the live position`]] as [
                                  string,
                                  string,
                              ][])
                            : []),
                    ],
                    cumulativePpm: cumulative,
                });
                outcome = 'cashed-out';
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
                ensureEmpty(action);
                outcome = 'abandoned';
                steps.push(abandonStep(action.actionIndex, position, cumulative));
                settled = true;
                break;
            default:
                throw new ReplayError(`unknown hydra:v1 action: ${action.actionType}`);
        }
    }

    return {
        gameType: GAME_TYPE,
        steps,
        cumulativePpm: cumulative,
        outcome,
        settled,
        settledAtIndex: settled ? steps[steps.length - 1].actionIndex : null,
        payoutUnits: positionValue(position),
        bankedUnits: position.bankedUnits,
    };
}
