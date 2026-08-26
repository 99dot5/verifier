/**
 * plinko:v1 — integer reimplementation of `libs/games/src/plinko/v1/engine.rs`,
 * pinned against `libs/games/src/plinko/v1/testdata/vectors.json`.
 *
 * The outcome is sealed by the seed at `place-bet` (action_index 0): `rows`
 * uniform bits from the seed choose left/right at each peg, the bin is the
 * popcount, and the multiplier is a frozen table lookup. The later `cashout`
 * is a settle trigger only — it cannot change the payout, which is why a
 * deadline-swept round pays identically to a player-collected one.
 */
import { SCALE_PPM } from './constants';
import { ppmToMultiplierString } from './ints';
import { bytesToHex, deriveSeed } from './seed';
import { ReplayError, type Outcome, type ReplayResult, type StepWorking, type TranscriptAction } from './types';
import { abandonStep } from './hilo';

export const GAME_TYPE = 'plinko:v1';

export type Risk = 'low' | 'medium' | 'high';

export const SUPPORTED_ROWS = [8, 10, 12, 14, 16] as const;
export const SUPPORTED_RISKS: Risk[] = ['low', 'medium', 'high'];

/** Borsh enum tags for `Config.risk` (declaration order in engine.rs). */
export const RISK_BORSH_TAG: Record<Risk, number> = { low: 0, medium: 1, high: 2 };

/**
 * The frozen multiplier tables, stated as their symmetric half from edge to
 * centre in hundredths of 1× — the exact `M_<rows>_<risk>` constants in
 * `engine.rs` (full table = mirror expansion × 10_000). Every table's exact
 * binomial-weighted RTP lands in [995_000, 995_500] ppm; see `exactRtp`.
 */
const HALF_TABLES: Record<string, number[]> = {
    '8:low': [560, 210, 110, 100, 52],
    '8:medium': [1_300, 310, 130, 70, 40],
    '8:high': [2_900, 400, 150, 31, 20],
    '10:low': [800, 260, 130, 120, 100, 50],
    '10:medium': [1_900, 540, 220, 130, 60, 44],
    '10:high': [7_600, 900, 310, 100, 28, 20],
    '12:low': [1_000, 300, 160, 145, 110, 100, 50],
    '12:medium': [3_300, 1_100, 400, 205, 110, 60, 30],
    '12:high': [17_000, 2_400, 810, 200, 70, 21, 20],
    '14:low': [710, 400, 195, 150, 130, 110, 100, 50],
    '14:medium': [5_800, 1_500, 520, 260, 150, 100, 70, 50],
    '14:high': [42_000, 5_520, 1_600, 510, 190, 40, 20, 20],
    '16:low': [1_600, 900, 200, 170, 140, 120, 110, 100, 50],
    '16:medium': [11_000, 4_100, 1_000, 530, 300, 150, 100, 50, 30],
    '16:high': [100_000, 13_030, 2_600, 930, 400, 200, 20, 20, 20],
};

export function isSupported(rows: number, risk: string): risk is Risk {
    return (SUPPORTED_ROWS as readonly number[]).includes(rows) && SUPPORTED_RISKS.includes(risk as Risk);
}

/** Full multiplier table in ppm for a supported `(rows, risk)`. */
export function multipliers(rows: number, risk: Risk): bigint[] {
    const half = HALF_TABLES[`${rows}:${risk}`];

    if (!half) {
        throw new ReplayError(`unsupported plinko config: rows=${rows} risk=${risk}`);
    }

    return Array.from({ length: rows + 1 }, (_, k) => BigInt(half[Math.min(k, rows - k)]) * 10_000n);
}

/** `path[i] = bit (i % 8) of seed byte (i / 8)`; 0 = left, 1 = right. */
export function derivePath(seed: Uint8Array, rows: number): number[] {
    return Array.from({ length: rows }, (_, i) => (seed[Math.floor(i / 8)] >> i % 8) & 1);
}

export function binIndex(path: number[]): number {
    return path.reduce((sum, bit) => sum + bit, 0);
}

/** Borsh-decode a place-bet `Config { rows: u32 LE, risk: u8 enum }`. */
export function decodeConfig(payload: Uint8Array): { rows: number; risk: Risk } {
    if (payload.length !== 5) {
        throw new ReplayError(`plinko place-bet payload must be 5 bytes, got ${payload.length}`);
    }

    const rows = new DataView(payload.buffer, payload.byteOffset).getUint32(0, true);
    const risk = SUPPORTED_RISKS[payload[4]];

    if (risk === undefined) {
        throw new ReplayError(`unknown plinko risk tag: ${payload[4]}`);
    }

    return { rows, risk };
}

function binomial(n: number, k: number): bigint {
    let result = 1n;

    for (let i = 0; i < Math.min(k, n - k); i++) {
        result = (result * BigInt(n - i)) / BigInt(i + 1);
    }

    return result;
}

/**
 * Exact RTP of one table under the binomial bin distribution, as the exact
 * fraction `weightedSum / 2^rows` (in ppm) plus a display string.
 */
export function exactRtp(rows: number, risk: Risk): { weightedSum: bigint; denominator: bigint; display: string } {
    const table = multipliers(rows, risk);
    const weightedSum = table.reduce((sum, m, k) => sum + m * binomial(rows, k), 0n);
    const denominator = 1n << BigInt(rows);
    // Render the exact decimal: weightedSum / 2^rows terminates in binary.
    const whole = weightedSum / denominator;
    let rem = weightedSum % denominator;
    let frac = '';

    while (rem > 0n) {
        rem *= 10n;
        frac += (rem / denominator).toString();
        rem %= denominator;
    }

    return { weightedSum, denominator, display: `${whole}${frac ? '.' + frac : ''} ppm` };
}

export function outcomeFromMultiplier(multiplierPpm: bigint): Outcome {
    if (multiplierPpm > SCALE_PPM) {
        return 'win';
    }

    return multiplierPpm === SCALE_PPM ? 'push' : 'lose';
}

/** Replay a full plinko transcript exactly the way the rollup kernel does. */
export function replay(serverSeed: string, clientSeed: string, actions: TranscriptAction[]): ReplayResult {
    if (actions.length === 0 || actions[0].actionType !== 'place-bet') {
        throw new ReplayError('plinko transcript must start with place-bet');
    }

    const { rows, risk } = decodeConfig(actions[0].payload);

    if (!isSupported(rows, risk)) {
        throw new ReplayError(`unsupported plinko config: rows=${rows} risk=${risk}`);
    }

    const seed = deriveSeed(GAME_TYPE, serverSeed, clientSeed, 0);
    const path = derivePath(seed, rows);
    const bin = binIndex(path);
    const multiplierPpm = multipliers(rows, risk)[bin];
    const rtp = exactRtp(rows, risk);
    const steps: StepWorking[] = [
        {
            actionIndex: 0,
            actionType: 'place-bet',
            title: `place-bet — rows=${rows} risk=${risk}: bin ${bin} pays ${ppmToMultiplierString(multiplierPpm)}`,
            details: [
                ['derived seed', bytesToHex(seed)],
                ['path (0=left, 1=right; bit i%8 of seed byte i/8)', path.join('')],
                ['bin index (popcount)', String(bin)],
                ['table multiplier', ppmToMultiplierString(multiplierPpm)],
                ['table exact RTP', rtp.display],
                ['sealed at bet time', 'the settle action cannot change this payout'],
            ],
            cumulativePpm: multiplierPpm,
        },
    ];
    let outcome: Outcome = outcomeFromMultiplier(multiplierPpm);
    let cumulative = multiplierPpm;
    let settled = false;

    for (const action of actions.slice(1)) {
        if (settled) {
            throw new ReplayError(`action after settlement: ${action.actionType}`);
        }

        switch (action.actionType) {
            case 'cashout':
                steps.push({
                    actionIndex: action.actionIndex,
                    actionType: 'cashout',
                    title: `cashout (settle trigger) at ${ppmToMultiplierString(multiplierPpm)}`,
                    details: [
                        ['rule', 'pays the multiplier sealed at place-bet — player cashout and deadline-sweep pay identically'],
                    ],
                    cumulativePpm: multiplierPpm,
                });
                settled = true;
                break;
            case 'abandon':
                cumulative = 0n;
                outcome = 'lose';
                steps.push(abandonStep(action.actionIndex));
                settled = true;
                break;
            default:
                throw new ReplayError(`unknown plinko action: ${action.actionType}`);
        }
    }

    return { gameType: GAME_TYPE, steps, cumulativePpm: cumulative, outcome, settled };
}
