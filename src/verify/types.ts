/**
 * Shared shapes for game replay. A `Transcript` is the decoded action list a
 * round left in the public L1 inbox: the step-0 `place-bet` plus every
 * in-round action, exactly as the rollup kernel replays them.
 */

export interface TranscriptAction {
    actionIndex: number;
    /** Kebab-case wire vocabulary: `place-bet`, `higher`, `reveal`, `cashout`, `abandon`, … */
    actionType: string;
    /** Raw Borsh action payload (empty for payload-free actions). */
    payload: Uint8Array;
}

/** One display row of "the working" — a label plus fully-derived intermediates. */
export interface StepWorking {
    actionIndex: number;
    actionType: string;
    title: string;
    /** Ordered key → value detail lines, all values pre-rendered as strings. */
    details: [string, string][];
    cumulativePpm: bigint;
}

export type Outcome = 'win' | 'lose' | 'cashout' | 'push';

export interface ReplayResult {
    gameType: string;
    steps: StepWorking[];
    cumulativePpm: bigint;
    outcome: Outcome;
    /** False when the transcript ends without a settling action. */
    settled: boolean;
    /**
     * The kernel's `u128` payout in the asset's atomic units: `banked + live`
     * after the fold, truncated to the grain. This — not `cumulativePpm` — is
     * what the chain compares against `claimed_payout`.
     */
    payoutUnits: bigint;
    /** The banked part of `payoutUnits` (0 for the single-decision games). */
    bankedUnits: bigint;
}

/** Every replayer's shape; `stakeUnits` is the transcript's stake in atomic units. */
export type Replayer = (
    serverSeed: string,
    clientSeed: string,
    actions: TranscriptAction[],
    stakeUnits: bigint,
) => ReplayResult;

/** Thrown when a transcript is malformed — mirrors the kernel's replay rejections. */
export class ReplayError extends Error {}
