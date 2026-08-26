/**
 * Round verification orchestrator. Proves TWO independent things about a
 * round, from public L1 inbox data alone:
 *
 *   1. THE PAYOUT WAS CORRECT — replay the action transcript with the
 *      revealed `server_seed` + the player's `client_seed` through the same
 *      integer-only algorithm the rollup kernel runs (pinned by the golden
 *      vectors), and compare the recomputed payout with the claimed one.
 *
 *   2. THE SEED WAS PRE-COMMITTED — the `server_seed`'s hash was published
 *      on-chain in a `SeedBatch` message at an L1 level STRICTLY BEFORE the
 *      round existed. This half lives entirely outside the game engine, and
 *      it is what makes the result provably fair rather than just arithmetic:
 *      without it, a correct payout could still be a payout from a seed
 *      chosen after seeing the player's actions.
 *
 * Every check is reported individually with its inputs, so a reader can
 * reproduce each one by hand. A tool that prints only PASS/FAIL asks for the
 * same trust it exists to remove.
 */
import type { InboxMessage } from './chain/inbox';
import { payoutUnits, unitsToDecimalString } from './verify/ints';
import { bytesEqual, bytesToHex, serverSeedCommitment } from './verify/seed';
import * as hilo from './verify/hilo';
import * as mines from './verify/mines';
import * as plinko from './verify/plinko';
import { ReplayError, type ReplayResult, type TranscriptAction } from './verify/types';
import { decodeEdpk, verifyInboxSignature } from './wire/signature';

export type CheckStatus = 'pass' | 'fail' | 'unavailable';

export interface Check {
    id: string;
    title: string;
    status: CheckStatus;
    /** What was computed, from what, and what it was compared against. */
    detail: string;
}

export interface MessageRef {
    level: number;
    operationHash: string;
    summary: string;
}

export interface VerificationReport {
    roundId: string;
    gameType: string | null;
    checks: Check[];
    replay: ReplayResult | null;
    references: MessageRef[];
    /** Overall: pass iff every non-unavailable check passed AND both halves ran. */
    verdict: 'verified' | 'failed' | 'incomplete';
}

const REPLAYERS: Record<string, (s: string, c: string, a: TranscriptAction[]) => ReplayResult> = {
    [hilo.GAME_TYPE]: hilo.replay,
    [plinko.GAME_TYPE]: plinko.replay,
    [mines.GAME_TYPE]: mines.replay,
};

export function supportedGameTypes(): string[] {
    return Object.keys(REPLAYERS);
}

export interface VerifyInput {
    roundId: string;
    tenantId: string;
    /** Every decoded inbox message the caller gathered (any order, any kinds). */
    messages: InboxMessage[];
    /** Tenant sequencer public key (`edpk…`) for signature checks; null skips them. */
    sequencerPublicKey: string | null;
}

export function verifyRound(input: VerifyInput): VerificationReport {
    const checks: Check[] = [];
    const references: MessageRef[] = [];
    const roundId = input.roundId.trim().toLowerCase();
    const inTenant = input.messages.filter((m) => m.envelope.tenantId === input.tenantId);

    const ref = (m: InboxMessage, summary: string): void => {
        references.push({ level: m.level, operationHash: m.operationHash, summary });
    };

    // ── Collect the round's own messages ────────────────────────────────
    // At-least-once injection means duplicates are normal; the kernel applies
    // the FIRST occurrence and no-ops the rest, so always pick the earliest
    // level (this matters for the commitment-ordering check, which compares
    // the RoundCreated's level).
    const earliest = (predicate: (m: InboxMessage) => boolean): InboxMessage | undefined =>
        inTenant
            .filter(predicate)
            .sort((a, b) => a.level - b.level || a.messageIndex - b.messageIndex)[0];

    const created = earliest(
        (m) => m.envelope.message.kind === 'round-created' && m.envelope.message.roundId === roundId,
    );
    const settled = earliest(
        (m) => m.envelope.message.kind === 'round-settled' && m.envelope.message.roundId === roundId,
    );
    // Injection is AT-LEAST-ONCE: the same frame can appear in the inbox at
    // more than one level (observed live on shadownet — a whole round's
    // frames duplicated across two consecutive blocks). The kernel dedups on
    // durable storage; mirror that here by keeping the FIRST occurrence per
    // action_index (ordered by level, then intra-block position).
    const actionsByIndex = new Map<bigint, InboxMessage>();

    for (const m of inTenant
        .filter((msg) => msg.envelope.message.kind === 'player-action' && msg.envelope.message.roundId === roundId)
        .sort((a, b) => a.level - b.level || a.messageIndex - b.messageIndex)) {
        if (m.envelope.message.kind !== 'player-action') {
            continue;
        }

        if (!actionsByIndex.has(m.envelope.message.actionIndex)) {
            actionsByIndex.set(m.envelope.message.actionIndex, m);
        }
    }

    const actionMessages = [...actionsByIndex.entries()]
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([, m]) => m);

    if (!created || created.envelope.message.kind !== 'round-created') {
        checks.push({
            id: 'round-created',
            title: 'RoundCreated found in inbox',
            status: 'fail',
            detail: `no RoundCreated for round ${roundId} in the scanned messages — widen the level range?`,
        });

        return { roundId, gameType: null, checks, replay: null, references, verdict: 'incomplete' };
    }

    const createdMsg = created.envelope.message;

    ref(created, `RoundCreated — game ${createdMsg.gameType}, stake ${unitsToDecimalString(createdMsg.stake.units, createdMsg.stake.scale)} ${createdMsg.asset}, seed index ${createdMsg.serverSeedIndex}`);
    checks.push({
        id: 'round-created',
        title: 'RoundCreated found in inbox',
        status: 'pass',
        detail: `level ${created.level}, op ${created.operationHash}`,
    });

    // ── Signatures ──────────────────────────────────────────────────────
    if (input.sequencerPublicKey) {
        let publicKey: Uint8Array | null = null;
        let keyError = '';

        try {
            publicKey = decodeEdpk(input.sequencerPublicKey);
        } catch (error) {
            keyError = error instanceof Error ? error.message : String(error);
        }

        if (!publicKey) {
            checks.push({
                id: 'signatures',
                title: 'Ed25519 signatures verify against the sequencer key',
                status: 'unavailable',
                detail: `could not decode the configured public key: ${keyError}`,
            });
        } else {
            const toCheck = [created, ...actionMessages, ...(settled ? [settled] : [])];
            const bad = toCheck.filter(
                (m) => !verifyInboxSignature(m.envelope.signature, m.envelope.signedPayload, publicKey),
            );

            checks.push({
                id: 'signatures',
                title: 'Ed25519 signatures verify against the sequencer key',
                status: bad.length === 0 ? 'pass' : 'fail',
                detail:
                    bad.length === 0
                        ? `${toCheck.length} message(s): sig = ed25519(blake2b-256(payload)) under ${input.sequencerPublicKey}. The key itself is set on-chain by the administrator contract's RegisterTenant, so this chain of trust needs no operator input. Note: after a RotateSequencerKey, messages near the rotation may verify under the previous key instead.`
                        : `${bad.length}/${toCheck.length} message(s) failed under ${input.sequencerPublicKey} — wrong key for this tenant, or a rotation happened (check RegisterTenant / RotateSequencerKey history)`,
            });
        }
    } else {
        checks.push({
            id: 'signatures',
            title: 'Ed25519 signatures verify against the sequencer key',
            status: 'unavailable',
            detail: 'no sequencer public key configured for this network',
        });
    }

    // ── Half 2: seed pre-commitment ─────────────────────────────────────
    const seedIndex = createdMsg.serverSeedIndex;
    const batch = earliest(
        (m) =>
            m.envelope.message.kind === 'seed-batch' &&
            m.envelope.poolId === created.envelope.poolId &&
            m.envelope.message.startIndex <= seedIndex &&
            seedIndex < m.envelope.message.startIndex + BigInt(m.envelope.message.hashes.length),
    );

    if (batch && batch.envelope.message.kind === 'seed-batch') {
        const batchMsg = batch.envelope.message;
        const offset = Number(seedIndex - batchMsg.startIndex);
        const committedHash = batchMsg.hashes[offset];
        const hashMatches = bytesEqual(committedHash, createdMsg.serverSeedHash);

        ref(batch, `SeedBatch — indices ${batchMsg.startIndex}..${batchMsg.startIndex + BigInt(batchMsg.hashes.length) - 1n}, drand round ${batchMsg.drandRound}`);
        checks.push({
            id: 'commitment-hash',
            title: 'Seed commitment found at the round’s seed index',
            status: hashMatches ? 'pass' : 'fail',
            detail: hashMatches
                ? `SeedBatch at level ${batch.level} carries hash[${offset}] = ${bytesToHex(committedHash)} — equal to RoundCreated.server_seed_hash`
                : `SeedBatch hash[${offset}] = ${bytesToHex(committedHash)} ≠ RoundCreated.server_seed_hash = ${bytesToHex(createdMsg.serverSeedHash)}`,
        });
        checks.push({
            id: 'commitment-order',
            title: 'Commitment strictly precedes the round on L1',
            status: batch.level < created.level ? 'pass' : 'fail',
            detail: `SeedBatch level ${batch.level} vs RoundCreated level ${created.level} — the kernel enforces commitment_level < round_level (same level rejects)`,
        });
    } else {
        checks.push({
            id: 'commitment-hash',
            title: 'Seed commitment found at the round’s seed index',
            status: 'unavailable',
            detail: `no SeedBatch covering index ${seedIndex} in the scanned messages — seed batches are committed ahead of play, so scan further back`,
        });
    }

    // ── The reveal ──────────────────────────────────────────────────────
    let replayResult: ReplayResult | null = null;

    if (settled && settled.envelope.message.kind === 'round-settled') {
        const settledMsg = settled.envelope.message;

        ref(settled, `RoundSettled — claimed ${settledMsg.claimedOutcome}, payout ${unitsToDecimalString(settledMsg.claimedPayout.units, settledMsg.claimedPayout.scale)} ${settledMsg.asset}`);

        const revealedCommitment = serverSeedCommitment(settledMsg.serverSeed);
        const revealMatches = bytesEqual(revealedCommitment, createdMsg.serverSeedHash);

        checks.push({
            id: 'reveal-hash',
            title: 'Revealed server_seed matches the pre-committed hash',
            status: revealMatches ? 'pass' : 'fail',
            detail: `blake2b-256(ascii("${settledMsg.serverSeed.slice(0, 16)}…")) = ${bytesToHex(revealedCommitment)} ${revealMatches ? '=' : '≠'} RoundCreated.server_seed_hash`,
        });

        // ── Half 1: replay the game and recompute the payout ────────────
        const replayer = REPLAYERS[createdMsg.gameType];

        if (!replayer) {
            checks.push({
                id: 'replay',
                title: 'Round replays to the claimed payout',
                status: 'unavailable',
                detail: `game ${createdMsg.gameType} is not implemented in this verifier yet (supported: ${supportedGameTypes().join(', ')})`,
            });
        } else {
            const transcript: TranscriptAction[] = actionMessages.map((m) => {
                const a = m.envelope.message;

                if (a.kind !== 'player-action') {
                    throw new Error('unreachable');
                }

                ref(m, `PlayerAction #${a.actionIndex} — ${a.actionType}`);

                return { actionIndex: Number(a.actionIndex), actionType: a.actionType, payload: a.actionPayload };
            });

            try {
                replayResult = replayer(settledMsg.serverSeed, createdMsg.clientSeed, transcript);

                const computedPayout = payoutUnits(createdMsg.stake.units, replayResult.cumulativePpm);
                const payoutMatches = computedPayout === settledMsg.claimedPayout.units;
                const outcomeMatches = replayResult.outcome === settledMsg.claimedOutcome;

                checks.push({
                    id: 'replay-payout',
                    title: 'Recomputed payout equals the claimed payout',
                    status: payoutMatches ? 'pass' : 'fail',
                    detail: `floor(stake ${createdMsg.stake.units} × cumulative ${replayResult.cumulativePpm} ppm / 1e6) = ${computedPayout} base units (${unitsToDecimalString(computedPayout, createdMsg.stake.scale)} ${createdMsg.asset}) vs claimed ${settledMsg.claimedPayout.units}. Derivation inputs are exactly (game_type, server_seed, client_seed, action_index) — there is no operator-controlled nonce.`,
                });
                checks.push({
                    id: 'replay-outcome',
                    title: 'Recomputed outcome equals the claimed outcome',
                    status: outcomeMatches ? 'pass' : 'fail',
                    detail: `replayed → ${replayResult.outcome}, claimed → ${settledMsg.claimedOutcome}`,
                });
            } catch (error) {
                checks.push({
                    id: 'replay',
                    title: 'Round replays to the claimed payout',
                    status: 'fail',
                    detail: error instanceof ReplayError ? `transcript rejected: ${error.message}` : String(error),
                });
            }
        }
    } else {
        checks.push({
            id: 'reveal-hash',
            title: 'Revealed server_seed matches the pre-committed hash',
            status: 'unavailable',
            detail: 'no RoundSettled in the scanned messages — the round may still be open, or the range too narrow',
        });
    }

    const anyFail = checks.some((c) => c.status === 'fail');
    // "verified" requires every proof to have actually run and passed. The
    // payout and commitment halves are the substance, but the SIGNATURE check
    // is load-bearing too: the rollup inbox is permissionless, so without
    // authenticating the frames against the sequencer key, a third party
    // could inject a fabricated RoundCreated/SeedBatch/RoundSettled set that
    // "verifies". Anything less than all five is "incomplete", never
    // "verified".
    const allProofsRan = (['replay-payout', 'reveal-hash', 'commitment-hash', 'commitment-order', 'signatures'] as const).every(
        (id) => checks.find((c) => c.id === id)?.status === 'pass',
    );

    return {
        roundId,
        gameType: createdMsg.gameType,
        checks,
        replay: replayResult,
        references,
        verdict: anyFail ? 'failed' : allProofsRan ? 'verified' : 'incomplete',
    };
}
