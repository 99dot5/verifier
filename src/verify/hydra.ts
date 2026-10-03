/**
 * hydra:v1 — integer reimplementation of `libs/games/src/hydra/v1/engine.rs` +
 * `math.rs`, pinned against `libs/games/src/hydra/v1/testdata/vectors.json`.
 *
 * The player picks a hero (the place-bet payload, `borsh(Config { hero: u8 })`),
 * and the bet — decision 0 — draws weapon, armour and sprite as three
 * little-endian `u64` rolls (24 bytes). Each attack, physical or magic, is the
 * next decision and draws the fight roll from bytes [0..8) and the damage roll
 * from [8..16) — both, even when the fight is fatal. A roll is the raw `u64`
 * reduced onto [0, 1e6) by Lemire's wide multiply, `(raw × 1e6) >> 64`.
 *
 * `drink-potion`, `drink-mana`, `cashout`, `partial-cashout` and `abandon`
 * draw nothing and do not advance the decision, so a system step the
 * sequencer inserts cannot move a later roll.
 *
 * Every surviving attack is its own bet, priced at `0.995 / P(survive)`, so
 * RTP is 99.5% per attack and `0.995^n` over the round. The payout follows the
 * banked/live fold of `partial_cashout.rs`: the live part rounds at the asset
 * grain on every surviving attack, a death pays the banked total, cashout and
 * a full clear pay `banked + live`, and the system `abandon` pays
 * `banked + live` too (sec-28) with outcome `lose`.
 */
import { HOUSE_EDGE_PPM, SCALE_PPM } from './constants';
import { divHalfUp, mulPpm, ppmToMultiplierString } from './ints';
import { SeedStream, rawU64 } from './seed';
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

export const GAME_TYPE = 'hydra:v1';

/** The twelve labours. */
export const TOTAL_STAGES = 12;

const MIN_DEATH_PPM = 10_000n;
const MAX_DEATH_PPM = 900_000n;
const ATK_REDUCTION_PER_POINT = 8_000n;
const MATK_REDUCTION_PER_POINT = 10_000n;
const DEF_REDUCTION_PER_POINT = 8_000n;
const BASE_DEATH_START_PPM = 200_000n;
const BASE_DEATH_STEP_PPM = 63_636n;
const MISS_THRESHOLD_PPM = 100_000n;
const CRIT_THRESHOLD_PPM = 850_000n;
/** Equipment draw: < 600 000 → tier 0, < 900 000 → tier 1, else tier 2 (all three slots). */
const TIER_THRESHOLDS_PPM = [600_000n, 900_000n] as const;

export type AttackType = 'physical' | 'magic';

interface HeroStats {
    name: string;
    atk: number;
    def: number;
    matk: number;
    mdef: number;
    hp: number;
    mp: number;
}

/** Index = hero id (`math::Hero`). */
export const HEROES: readonly HeroStats[] = [
    { name: 'hercules', atk: 5, def: 2, matk: 0, mdef: 1, hp: 3, mp: 1 },
    { name: 'knight', atk: 2, def: 5, matk: 0, mdef: 3, hp: 4, mp: 1 },
    { name: 'magician-boy', atk: 0, def: 1, matk: 5, mdef: 2, hp: 2, mp: 5 },
    { name: 'magician-girl', atk: 1, def: 1, matk: 4, mdef: 4, hp: 2, mp: 4 },
    { name: 'amazonian', atk: 4, def: 2, matk: 2, mdef: 1, hp: 3, mp: 2 },
    { name: 'dev', atk: 1, def: 1, matk: 1, mdef: 1, hp: 1, mp: 1 },
];

/** (name, atk, matk) per weapon tier. */
export const WEAPONS = [
    { name: 'common', atk: 1, matk: 0 },
    { name: 'rare', atk: 2, matk: 1 },
    { name: 'legendary', atk: 2, matk: 3 },
] as const;
/** (name, def, mdef) per armour tier. */
export const ARMOURS = [
    { name: 'cloth', def: 0, mdef: 1 },
    { name: 'chain', def: 2, mdef: 1 },
    { name: 'plate', def: 4, mdef: 0 },
] as const;
/** (name, atk, def, matk, mdef) per sprite tier. */
export const SPRITES = [
    { name: 'common', atk: 0, def: 0, matk: 1, mdef: 1 },
    { name: 'rare', atk: 1, def: 1, matk: 1, mdef: 1 },
    { name: 'legendary', atk: 2, def: 1, matk: 2, mdef: 2 },
] as const;

/** (physical, magic) bonus per stage, ppm. Positive = harder with that type. */
const MONSTER_BONUSES: readonly (readonly [bigint, bigint])[] = [
    [0n, 0n],
    [20_000n, -20_000n],
    [-20_000n, 20_000n],
    [0n, 0n],
    [-30_000n, 30_000n],
    [30_000n, -30_000n],
    [0n, 0n],
    [-20_000n, 20_000n],
    [20_000n, -20_000n],
    [10_000n, -10_000n],
    [30_000n, -30_000n],
    [0n, 0n],
];

/** Hits each monster takes. */
export const MONSTER_HP = [1, 2, 1, 2, 1, 2, 2, 2, 3, 3, 3, 4] as const;

export const MONSTER_NAMES = [
    'Lion', 'Hydra', 'Hind', 'Boar', 'Stables', 'Birds',
    'Bull', 'Mares', 'Belt', 'Cattle', 'Apples', 'Cerberus',
] as const;

export interface Roll {
    raw: bigint;
    /** `(raw × 1e6) >> 64`, in [0, 1e6). */
    ppm: bigint;
}

/** `count` rolls of one decision: 8 stream bytes each, little-endian `u64`. */
export function hydraRolls(serverSeed: string, clientSeed: string, decision: number, count: number): Roll[] {
    const stream = new SeedStream(GAME_TYPE, serverSeed, clientSeed, decision);

    return Array.from({ length: count }, () => {
        const raw = rawU64(stream.take(8));

        return { raw, ppm: (raw * SCALE_PPM) >> 64n };
    });
}

/** Map a gear roll to tier 0/1/2. */
export function tierFromRoll(rollPpm: bigint): number {
    if (rollPpm < TIER_THRESHOLDS_PPM[0]) {
        return 0;
    }

    return rollPpm < TIER_THRESHOLDS_PPM[1] ? 1 : 2;
}

/** 0 (miss), 1 (hit) or 2 (crit). */
export function damageFromRoll(rollPpm: bigint): number {
    if (rollPpm < MISS_THRESHOLD_PPM) {
        return 0;
    }

    return rollPpm >= CRIT_THRESHOLD_PPM ? 2 : 1;
}

export interface EffectiveStats {
    atk: bigint;
    def: bigint;
    matk: bigint;
    mdef: bigint;
}

/** Hero base + weapon + armour + sprite. */
export function effectiveStats(hero: number, weapon: number, armour: number, sprite: number): EffectiveStats {
    const h = HEROES[hero];
    const w = WEAPONS[weapon];
    const a = ARMOURS[armour];
    const s = SPRITES[sprite];

    return {
        atk: BigInt(h.atk + w.atk + s.atk),
        def: BigInt(h.def + a.def + s.def),
        matk: BigInt(h.matk + w.matk + s.matk),
        mdef: BigInt(h.mdef + a.mdef + s.mdef),
    };
}

function clamp(value: bigint, min: bigint, max: bigint): bigint {
    return value < min ? min : value > max ? max : value;
}

/** The pre-health-shielding death chance, `math.rs`'s `single_hit_death`. */
function singleHitDeathPpm(attack: AttackType, offensive: bigint, stage: number): bigint {
    const base = BASE_DEATH_START_PPM + BigInt(stage) * BASE_DEATH_STEP_PPM;
    const [physicalBonus, magicBonus] = MONSTER_BONUSES[stage];
    const adjusted = base + (attack === 'physical' ? physicalBonus : magicBonus);
    const perPoint = attack === 'physical' ? ATK_REDUCTION_PER_POINT : MATK_REDUCTION_PER_POINT;

    return clamp(adjusted - offensive * perPoint, MIN_DEATH_PPM, MAX_DEATH_PPM);
}

/** `single^health` folded with `mul_ppm`, clamped to [1, 999 999]. Dies iff fight roll < this. */
export function deathProbabilityPpm(attack: AttackType, offensive: bigint, stage: number, health: number): bigint {
    if (stage >= TOTAL_STAGES || health === 0) {
        throw new ReplayError(`no death probability at stage ${stage} with ${health} HP`);
    }

    const single = singleHitDeathPpm(attack, offensive, stage);
    let effective = single;

    for (let i = 1; i < health; i++) {
        effective = mulPpm(effective, single);
    }

    return clamp(effective, 1n, SCALE_PPM - 1n);
}

/** A surviving attack wounds iff `health > 1 && death <= roll < this`. */
export function woundThresholdPpm(attack: AttackType, offensive: bigint, defensive: bigint, stage: number): bigint {
    const wound = singleHitDeathPpm(attack, offensive, stage) - defensive * DEF_REDUCTION_PER_POINT;

    return wound > 0n ? wound : 0n;
}

/** `half_up(half_up(1e12 / survival) × 995 000 / 1e6)` — the edge on every attack. */
export function stepMultiplierPpm(attack: AttackType, offensive: bigint, stage: number, health: number): bigint {
    const survival = SCALE_PPM - deathProbabilityPpm(attack, offensive, stage, health);

    return mulPpm(divHalfUp(SCALE_PPM * SCALE_PPM, survival), HOUSE_EDGE_PPM);
}

/** Borsh `Config { hero: u8 }`: exactly one byte, a known hero. */
export function decodeConfig(payload: Uint8Array): number {
    if (payload.length !== 1) {
        throw new ReplayError(`hydra place-bet payload must be 1 byte, got ${payload.length}`);
    }

    const hero = payload[0];

    if (hero >= HEROES.length) {
        throw new ReplayError(`invalid hydra hero ${hero}`);
    }

    return hero;
}

function ensureEmpty(action: TranscriptAction): void {
    if (action.payload.length !== 0) {
        throw new ReplayError(`hydra ${action.actionType} carries a ${action.payload.length}-byte payload; it takes none`);
    }
}

interface HydraState {
    hero: number;
    weapon: number;
    armour: number;
    sprite: number;
    maxHealth: number;
    health: number;
    maxMana: number;
    mana: number;
    monster: number;
    monsterHp: number;
    totalAttacks: number;
    /** The decision the next attack draws under: 1 after the bet, +1 per attack. */
    decision: number;
}

/** Replay a full hydra transcript exactly the way the rollup kernel does. */
export function replay(
    serverSeed: string,
    clientSeed: string,
    actions: TranscriptAction[],
    stakeUnits: bigint,
): ReplayResult {
    if (actions.length === 0 || actions[0].actionType !== 'place-bet') {
        throw new ReplayError('hydra transcript must start with place-bet');
    }

    const hero = decodeConfig(actions[0].payload);
    const gear = hydraRolls(serverSeed, clientSeed, 0, 3);
    const heroStats = HEROES[hero];
    const s: HydraState = {
        hero,
        weapon: tierFromRoll(gear[0].ppm),
        armour: tierFromRoll(gear[1].ppm),
        sprite: tierFromRoll(gear[2].ppm),
        maxHealth: heroStats.hp,
        health: heroStats.hp,
        maxMana: heroStats.mp,
        mana: heroStats.mp,
        monster: 0,
        monsterHp: MONSTER_HP[0],
        totalAttacks: 0,
        decision: 1,
    };
    const stats = effectiveStats(s.hero, s.weapon, s.armour, s.sprite);
    const steps: StepWorking[] = [
        {
            actionIndex: 0,
            actionType: 'place-bet',
            title: `place-bet — ${heroStats.name} with ${WEAPONS[s.weapon].name} weapon, ${ARMOURS[s.armour].name} armour, ${SPRITES[s.sprite].name} sprite`,
            details: [
                ['decision', '0'],
                ...gear.map(
                    (roll, i): [string, string] => [
                        `${['weapon', 'armour', 'sprite'][i]} roll (bytes [${i * 8}..${i * 8 + 8}), (raw × 1e6) >> 64)`,
                        `${roll.raw} → ${roll.ppm} ppm → tier ${tierFromRoll(roll.ppm)}`,
                    ],
                ),
                ['effective stats', `ATK ${stats.atk}, DEF ${stats.def}, MATK ${stats.matk}, MDEF ${stats.mdef}`],
                ['HP / MP', `${s.health} / ${s.mana}`],
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
            case 'physical-attack':
            case 'magic-attack': {
                ensureEmpty(action);

                const attack: AttackType = action.actionType === 'physical-attack' ? 'physical' : 'magic';

                if (s.monster >= TOTAL_STAGES) {
                    throw new ReplayError('hydra attack after all twelve stages were cleared');
                }

                if (attack === 'magic' && s.mana === 0) {
                    throw new ReplayError('hydra magic-attack with no mana');
                }

                const offensive = attack === 'physical' ? stats.atk : stats.matk;
                const defensive = attack === 'physical' ? stats.def : stats.mdef;
                const stage = s.monster;
                const decision = s.decision;
                const healthBefore = s.health;
                const monsterHpBefore = s.monsterHp;
                // Both rolls, always: the fight roll, then the damage roll.
                const [fight, damageRoll] = hydraRolls(serverSeed, clientSeed, decision, 2);
                const death = deathProbabilityPpm(attack, offensive, stage, healthBefore);
                const head: [string, string][] = [
                    ['decision', String(decision)],
                    ['monster', `${MONSTER_NAMES[stage]} (stage ${stage}), HP ${monsterHpBefore}`],
                    ['fight roll (bytes [0..8))', `${fight.raw} → ${fight.ppm} ppm`],
                    ['damage roll (bytes [8..16))', `${damageRoll.raw} → ${damageRoll.ppm} ppm`],
                    ['death probability', `${death} ppm at ${healthBefore} HP (dies iff fight roll < it)`],
                ];

                if (attack === 'magic') {
                    s.mana -= 1;
                }

                s.totalAttacks += 1;
                s.decision += 1;

                if (fight.ppm < death) {
                    s.health = 0;
                    cumulative = 0n;
                    position = loseLive(position);
                    outcome = 'lose';
                    settled = true;
                    steps.push({
                        actionIndex: action.actionIndex,
                        actionType: action.actionType,
                        title: `${action.actionType} vs ${MONSTER_NAMES[stage]} — DIED, round lost`,
                        details: [
                            ...head,
                            ...(bankedTotal.amount > 0n
                                ? ([
                                      ['payout', `the banked total ${bankedAmountString(bankedTotal)} (already the player's)`],
                                  ] as [string, string][])
                                : []),
                        ],
                        cumulativePpm: 0n,
                    });
                    break;
                }

                const step = stepMultiplierPpm(attack, offensive, stage, healthBefore);
                const woundThreshold = woundThresholdPpm(attack, offensive, defensive, stage);
                const wounded = healthBefore > 1 && fight.ppm >= death && fight.ppm < woundThreshold;

                if (wounded) {
                    s.health = Math.max(healthBefore - 1, 1);
                }

                const damage = damageFromRoll(damageRoll.ppm);
                const monsterHpAfter = Math.max(0, monsterHpBefore - damage);
                let cleared = false;

                if (monsterHpAfter === 0) {
                    s.monster = stage + 1;

                    if (s.monster >= TOTAL_STAGES) {
                        s.monsterHp = 0;
                        cleared = true;
                    } else {
                        s.monsterHp = MONSTER_HP[s.monster];
                    }
                } else {
                    s.monsterHp = monsterHpAfter;
                }

                cumulative = mulPpm(cumulative, step);
                position = foldLive(position, step);
                steps.push({
                    actionIndex: action.actionIndex,
                    actionType: action.actionType,
                    title: `${action.actionType} vs ${MONSTER_NAMES[stage]} — survived${wounded ? ' wounded' : ''}, ${['miss', 'hit', 'crit'][damage]}${cleared ? ' — all twelve stages cleared, round won' : ''}`,
                    details: [
                        ...head,
                        ['wound threshold', `${woundThreshold} ppm${wounded ? ` — wounded, HP ${healthBefore} → ${s.health}` : ''}`],
                        ['damage', `${damage} (monster HP ${monsterHpBefore} → ${monsterHpAfter})`],
                        ['step multiplier', ppmToMultiplierString(step)],
                        ['cumulative', ppmToMultiplierString(cumulative)],
                    ],
                    cumulativePpm: cumulative,
                });

                if (cleared) {
                    outcome = 'win';
                    settled = true;
                }
                break;
            }
            case 'drink-potion':
            case 'drink-mana': {
                ensureEmpty(action);

                const potion = action.actionType === 'drink-potion';

                if (s.totalAttacks === 0) {
                    throw new ReplayError(`hydra ${action.actionType} before the first attack`);
                }

                if (potion ? s.health >= s.maxHealth : s.mana >= s.maxMana) {
                    throw new ReplayError(`hydra ${action.actionType} at full ${potion ? 'HP' : 'MP'}`);
                }

                if (potion) {
                    s.health += 1;
                } else {
                    s.mana += 1;
                }

                steps.push({
                    actionIndex: action.actionIndex,
                    actionType: action.actionType,
                    title: `${action.actionType} — ${potion ? `HP ${s.health}/${s.maxHealth}` : `MP ${s.mana}/${s.maxMana}`}`,
                    details: [['rule', 'free: draws nothing and does not advance the decision']],
                    cumulativePpm: cumulative,
                });
                break;
            }
            case 'cashout':
                ensureEmpty(action);

                if (s.totalAttacks === 0) {
                    throw new ReplayError('hydra cashout requires at least one attack');
                }

                steps.push({
                    actionIndex: action.actionIndex,
                    actionType: 'cashout',
                    title: `cashout at ${ppmToMultiplierString(cumulative)}`,
                    details: [
                        ['cumulative', ppmToMultiplierString(cumulative)],
                        ...(bankedTotal.amount > 0n
                            ? ([
                                  ['payout', `banked total ${bankedAmountString(bankedTotal)} + the live position`],
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
                ensureEmpty(action);
                // Admissible before the first attack (unlike a cashout): the
                // sweep's only settling action for an untouched round.
                outcome = 'lose';
                steps.push(abandonStep(action.actionIndex, position, cumulative));
                settled = true;
                break;
            default:
                throw new ReplayError(`unknown hydra action: ${action.actionType}`);
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
