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
 *      round landed. This half lives entirely outside the game engine, and
 *      it is what makes the result provably fair rather than just arithmetic:
 *      without it, a correct payout could still be a payout from a seed
 *      chosen after seeing the player's actions.
 *
 * A whole round now arrives as ONE signed `RoundTranscript` message rather
 * than a `RoundCreated` + N `PlayerAction` + `RoundSettled` sequence, so the
 * transcript's own L1 level is the round's level and one signature covers
 * every action. Two consequences worth stating:
 *
 *   - `commitment-order` compares the batch against the SETTLE level rather
 *     than a create level. Strictly more lenient, and correct, because the
 *     kernel makes exactly the same comparison.
 *   - There is no separate `reveal-hash` proof any more. The transcript
 *     carries no claimed hash to check the reveal against, so the reveal and
 *     the commitment collapse into one check: the hash of the revealed seed
 *     equals the hash published on-chain at that seed index.
 *
 * Every check is reported individually with its inputs, so a reader can
 * reproduce each one by hand. A tool that prints only PASS/FAIL asks for the
 * same trust it exists to remove.
 */
import { blake2b } from '@noble/hashes/blake2.js';
import type { InboxMessage } from './chain/inbox';
import type { AdminLineage, LineageKey } from './chain/admin-lineage';
import type { ImportedReceipts } from './receipts/import';
import {
    decodeReceiptFrame,
    decodeReceiptFrames,
    labelFindings,
    recomputeRoundCommitment,
    type ReceiptFrame,
} from './receipts/recompute';
import { splitSignedFrame, verifyServerFrameSignature, CLIENT_FRAME_TAG } from './wire/signature';
import { TRANSCRIPT_DECIMALS } from './verify/assets';
import { payoutUnits, unitsToDecimalString } from './verify/ints';
import { bytesEqual, bytesToHex, serverSeedCommitment } from './verify/seed';
import * as hilo from './verify/hilo';
import * as mines from './verify/mines';
import * as plinko from './verify/plinko';
import { ReplayError, type ReplayResult, type TranscriptAction } from './verify/types';
import type { RoundTranscriptMessage } from './wire/messages';
import { decodeEdpk, verifyInboxSignature } from './wire/signature';
import { decodeClientEnvelope } from './wire/proto-reader';

export type CheckStatus = 'pass' | 'fail' | 'unavailable';

export interface Check {
    id: string;
    title: string;
    status: CheckStatus;
    /** What was computed, from what, and what it was compared against. */
    detail: string;
}

/**
 * One admissible signing key, with the provenance that makes it admissible.
 *
 * `registration` is null for the UI's manual OVERRIDE — a key the reader typed
 * in rather than one the lineage walk derived. The override exists so a reader
 * can test a key they suspect (or verify against a network whose anchor is not
 * pinned yet), and the report always says which of the two a match came from:
 * a match under a typed key proves the bytes were signed by THAT key, not that
 * the key legitimately belongs to the tenant.
 */
export interface VerifierKey {
    edpk: string;
    registration: { level: number; operationHash: string; source: string; administrator: string } | null;
}

/**
 * The tenant's signing keys, or the reason there are none.
 *
 * A key set is HISTORICAL (ADR 0022 D7): every key any administrator in the
 * lineage ever registered for the tenant, because a receipt signed under a key
 * that was valid at delivery stays valid evidence. Deriving it needs the
 * network, so the failure mode is explicit — a lineage that could not be
 * fetched makes the signature check `unavailable` with the reason stated, and
 * never a pass.
 */
export type KeySet = { status: 'available'; keys: VerifierKey[] } | { status: 'unavailable'; reason: string };

/**
 * Lift the lineage walk's output into the key set `verifyRound` consumes.
 *
 * An AMBIGUOUS lineage yields `unavailable`, not a shorter key set: the walk
 * had to guess which successor the kernel accepted, so a key it did not collect
 * may be the honest one — and a missing key turns an honest frame into a
 * `fail`. Degrading here rather than in the caller is what keeps that rule out
 * of reach of a caller that forgets it.
 */
export function keySetFromLineage(lineage: AdminLineage, tenantKeys: LineageKey[]): KeySet {
    if (lineage.ambiguities.length > 0) {
        return {
            status: 'unavailable',
            reason: `the administrator lineage is ambiguous, so the key set may be incomplete: ${lineage.ambiguities.join('; ')}`,
        };
    }

    return {
        status: 'available',
        keys: tenantKeys.map((key) => ({
            edpk: key.edpk,
            registration: {
                level: key.level,
                operationHash: key.operationHash,
                source: key.source,
                administrator: key.administrator,
            },
        })),
    };
}

export interface MessageRef {
    level: number;
    operationHash: string;
    summary: string;
}

/**
 * What the scan looked at, and the L1 facts that make "no transcript on chain"
 * decidable. Without these the tool cannot tell a suppressed round from one it
 * simply did not look far enough to find, and §8.3 exists because guessing
 * between the two manufactures an accusation out of ordinary latency.
 */
export interface ScanContext {
    fromLevel: number;
    toLevel: number;
    /** L1 head when the scan ran; null = unknown, which makes the range undecidable. */
    headLevel: number | null;
    /**
     * The session's own deposit operation — the bracket's LOWER bound, because
     * a session is not `active` until its deposit is processed, so no round of
     * it can precede that level. `confirmed` is false when the level could not
     * be checked against L1: an unconfirmed hint is not a bound. The UI shell
     * derives the level from L1 itself, so it only ever passes `true`; the flag
     * is for a caller that has a level from somewhere else.
     */
    deposit: { level: number; confirmed: boolean } | null;
}

/** The player's receipts, or why there are none. */
export type ReceiptsInput =
    | { status: 'absent' }
    | { status: 'error'; message: string }
    | { status: 'ok'; receipts: ImportedReceipts };

/**
 * Seven verdicts, and they are NOT interchangeable (§8.3(f)): each says
 * something different about why the tool is or is not alleging anything, and
 * collapsing any two would either hide a real finding or manufacture one.
 *
 *   `verified`     every proof ran and passed.
 *   `attested`     checked, but weakly — the reconstruction was unavailable,
 *                  so only the server's own signed statement was compared.
 *   `inconclusive` you did not look far enough: the scanned range does not
 *                  bracket the round, and widening it may change the answer.
 *   `undetermined` cannot tell yet: no transcript on chain and no evidence the
 *                  injector ever drained past this round's outbox row.
 *   `suppressed`   the round is missing from L1 and the injector demonstrably
 *                  moved past it. The ONE accusatory verdict.
 *   `incomplete`   a proof had no inputs.
 *   `failed`       a proof ran and did not hold.
 */
export type Verdict =
    | 'verified'
    | 'attested'
    | 'inconclusive'
    | 'undetermined'
    | 'suppressed'
    | 'incomplete'
    | 'failed';

export interface VerificationReport {
    roundId: string;
    gameType: string | null;
    checks: Check[];
    replay: ReplayResult | null;
    references: MessageRef[];
    /**
     * Observations that are not proofs: an exporter's labels disagreeing with
     * the bytes they label, most of all. Reported rather than folded into a
     * check, because none of them changes what the signatures say.
     */
    findings: string[];
    /** What was scanned, echoed so a reader can judge the ladder's inputs. */
    scan: ScanContext | null;
    verdict: Verdict;
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
    /**
     * The tenant's admissible signing keys. Derived from L1 by the caller
     * (`chain/admin-lineage.ts`) and passed in, because `verifyRound` is pure:
     * every network call belongs to the shell, so the whole verification is
     * reproducible from a fixture.
     */
    keys: KeySet;
    /**
     * The player's ORIGINAL client-seed text, if they still have it. Optional:
     * the transcript carries only its blake2b-256 hash, and every other proof
     * works from those 32 bytes alone. Supplying the text proves the round was
     * played under the seed the player chose.
     */
    clientSeedText?: string;
    /** The player's exported receipts (§12.3), if they supplied any. */
    receipts?: ReceiptsInput;
    /** What the caller scanned; required for the suppression ladder to resolve. */
    scan?: ScanContext | null;
}

export function verifyRound(input: VerifyInput): VerificationReport {
    const checks: Check[] = [];
    const references: MessageRef[] = [];
    const findings: string[] = [];
    const roundId = input.roundId.trim().toLowerCase();
    const inTenant = input.messages.filter((m) => m.envelope.tenantId === input.tenantId);

    const ref = (m: InboxMessage, summary: string): void => {
        references.push({ level: m.level, operationHash: m.operationHash, summary });
    };

    // ── The round's one message ─────────────────────────────────────────
    // Injection is AT-LEAST-ONCE, so the same frame can appear in the inbox
    // at more than one level (observed live on shadownet). The kernel dedups
    // on durable storage and applies the FIRST occurrence, no-oping the rest;
    // mirror that by keeping the earliest level, then the earliest position
    // within the block. It matters: the commitment-ordering check compares
    // against this message's level.
    //
    // "Earliest" means earliest AUTHENTICATED. The inbox is shared by every
    // rollup on the network and writable by anyone, and slugs are not unique
    // across deployments, so frames under this tenant's slug that no lineage
    // key signed are real traffic — another deployment's, or a forgery. The
    // kernel drops those before touching state, so a verifier that picked one
    // would compare against a seed batch the kernel never saw (observed live
    // on shadownet: a foreign-signed SeedBatch covering the same indices
    // landed ~1000 levels ahead of the tenant's own). Only when NO candidate
    // authenticates does the earliest unauthenticated one stand in, so the
    // signature check still reports the failure instead of hiding the round.
    const authenticates = (m: InboxMessage): boolean =>
        input.keys.status === 'available' && matchSigningKey(m, input.keys.keys) !== null;

    const earliest = (predicate: (m: InboxMessage) => boolean, what: string): InboxMessage | undefined => {
        const candidates = inTenant
            .filter(predicate)
            .sort((a, b) => a.level - b.level || a.messageIndex - b.messageIndex);

        if (input.keys.status !== 'available' || input.keys.keys.length === 0) {
            return candidates[0];
        }

        const chosen = candidates.find(authenticates);
        const skipped = candidates.filter((m) => m !== chosen && !authenticates(m));

        if (chosen && skipped.length > 0) {
            findings.push(
                `Skipped ${skipped.length} ${what} frame(s) under this tenant's slug that verify under no key the ` +
                    `tenant registered (${skipped.map((m) => `level ${m.level}, op ${m.operationHash}`).join('; ')}). ` +
                    'The rollup inbox is shared and permissionless, and the kernel drops unauthenticated frames, ' +
                    `so the authenticated ${what} at level ${chosen.level} is the one it applied.`,
            );
        }

        return chosen ?? candidates[0];
    };

    const transcriptMessage = earliest(
        (m) => m.envelope.message.kind === 'round-transcript' && m.envelope.message.roundId === roundId,
        'RoundTranscript',
    );

    if (!transcriptMessage || transcriptMessage.envelope.message.kind !== 'round-transcript') {
        // NOT a `fail`. A missing transcript is an absence, and an absence is
        // what the §8.3 ladder exists to classify — calling it a failed check
        // here would let "I did not look far enough" read as "the operator did
        // something wrong".
        checks.push({
            id: 'round-transcript',
            title: 'RoundTranscript found in inbox',
            status: 'unavailable',
            detail: `no RoundTranscript for round ${roundId} in the scanned messages — the round may still be open (a transcript is published only when the round settles), the transcript may not have been drained from the outbox yet, or the level range may be too narrow. Which of those it is, is what the verdict below decides.`,
        });

        const receipts = runReceiptProofs(input, roundId, null, checks, findings);

        return {
            roundId,
            gameType: null,
            checks,
            replay: null,
            references,
            findings,
            scan: input.scan ?? null,
            verdict: resolveMissingTranscript(input, roundId, receipts, inTenant, checks, references, findings),
        };
    }

    const transcript: RoundTranscriptMessage = transcriptMessage.envelope.message;
    const clientSeedHex = bytesToHex(transcript.clientSeed);
    const serverSeedHex = bytesToHex(transcript.serverSeed);

    ref(
        transcriptMessage,
        `RoundTranscript — game ${transcript.gameType}, stake ${unitsToDecimalString(transcript.stake, TRANSCRIPT_DECIMALS)} TEZ, ` +
            `seed index ${transcript.serverSeedIndex}, ${transcript.actions.length} action(s), ` +
            `claimed payout ${unitsToDecimalString(transcript.claimedPayout, TRANSCRIPT_DECIMALS)} TEZ`,
    );
    checks.push({
        id: 'round-transcript',
        title: 'RoundTranscript found in inbox',
        status: 'pass',
        // The commitment is shown, not checked: verifying it is a later PR.
        detail: `level ${transcriptMessage.level}, op ${transcriptMessage.operationHash} — the whole round in one signed message, ` +
            `player commitment ${bytesToHex(transcript.playerCommitment)}`,
    });

    // ── Half 2, part 1: find the covering seed batch ────────────────────
    // Located before the signature check so the batch can be authenticated
    // alongside the transcript: a fabricated SeedBatch injected by a third
    // party (the inbox is permissionless) would otherwise let a seed chosen
    // after the fact appear pre-committed.
    const seedIndex = transcript.serverSeedIndex;
    const batch = earliest(
        (m) =>
            m.envelope.message.kind === 'seed-batch' &&
            m.envelope.poolId === transcriptMessage.envelope.poolId &&
            m.envelope.message.startIndex <= seedIndex &&
            seedIndex < m.envelope.message.startIndex + BigInt(m.envelope.message.hashes.length),
        'SeedBatch',
    );

    // ── Signatures ──────────────────────────────────────────────────────
    // ANY key in the tenant's lineage is admissible, and the report names the
    // one that matched. The kernel's grace window governs which key may sign
    // a NEW message; this is a check on historical evidence, where a key that
    // was valid at delivery stays valid forever (ADR 0022 D7). Matching is
    // per-message, not per-round, because a rotation can legitimately land
    // between a seed batch and the transcript that spends one of its seeds.
    const toCheck = [transcriptMessage, ...(batch ? [batch] : [])];
    // Bound to a local const so the narrowing below survives into the `.map`
    // callbacks; TypeScript does not carry a property-access narrowing there.
    const keySet = input.keys;

    if (keySet.status === 'unavailable') {
        checks.push({
            id: 'signatures',
            title: 'Ed25519 signatures verify against a key the tenant registered on-chain',
            status: 'unavailable',
            detail: `the administrator lineage could not be derived, so there is nothing to check against: ${keySet.reason}. This is an absent proof, not a passed one — the inbox is permissionless, so unauthenticated frames prove nothing about who wrote them.`,
        });
    } else if (keySet.keys.length === 0) {
        checks.push({
            id: 'signatures',
            title: 'Ed25519 signatures verify against a key the tenant registered on-chain',
            status: 'unavailable',
            detail: `no signing key has ever been registered on-chain for tenant ${input.tenantId} — check the tenant slug, or the network's origination administrator anchor`,
        });
    } else {
        const admissible = keySet.keys;
        const matches = toCheck.map((message) => ({ message, key: matchSigningKey(message, admissible) }));
        const unmatched = matches.filter((m) => m.key === null);

        checks.push({
            id: 'signatures',
            title: 'Ed25519 signatures verify against a key the tenant registered on-chain',
            status: unmatched.length === 0 ? 'pass' : 'fail',
            detail:
                unmatched.length === 0
                    ? matches
                          .map((m) => `${describeMessage(m.message)} → ${describeKey(m.key as VerifierKey)}`)
                          .join('; ') +
                      `. Each is sig = ed25519(blake2b-256(payload)); the key set is every key registered for this tenant across the administrator lineage (${admissible.length} key(s)), so the whole chain of trust starts at the pinned origination administrator and needs no operator input.`
                    : `${unmatched.length}/${toCheck.length} message(s) verify under NO key this tenant ever registered (${admissible
                          .map((k) => k.edpk)
                          .join(', ')}) — either the frames are not this tenant's, or a key was used that never reached L1`,
        });
    }

    // ── Half 2, part 2: the commitment ──────────────────────────────────
    // One check, not two. The commitment is over the 64 ASCII hex characters
    // that spell the seed, NOT over the 32 raw bytes the wire carries —
    // hashing the bytes gives a different digest, which is the exact mistake
    // a raw-bytes wire invites (pinned by wire-vectors.test.ts).
    if (batch && batch.envelope.message.kind === 'seed-batch') {
        const batchMsg = batch.envelope.message;
        const offset = Number(seedIndex - batchMsg.startIndex);
        const committedHash = batchMsg.hashes[offset];
        const computed = serverSeedCommitment(serverSeedHex);
        const hashMatches = bytesEqual(computed, committedHash);

        ref(
            batch,
            `SeedBatch — indices ${batchMsg.startIndex}..${batchMsg.startIndex + BigInt(batchMsg.hashes.length) - 1n}, drand round ${batchMsg.drandRound}`,
        );
        checks.push({
            id: 'commitment-hash',
            title: 'Revealed server_seed matches the hash committed at its index',
            status: hashMatches ? 'pass' : 'fail',
            detail: `blake2b-256(ascii("${serverSeedHex.slice(0, 16)}…")) = ${bytesToHex(computed)} ${hashMatches ? '=' : '≠'} SeedBatch hash[${offset}] = ${bytesToHex(committedHash)} (the commitment is over the 64 hex CHARACTERS, not the 32 bytes they spell)`,
        });
        checks.push({
            id: 'commitment-order',
            title: 'Commitment strictly precedes the round on L1',
            status: batch.level < transcriptMessage.level ? 'pass' : 'fail',
            detail: `SeedBatch level ${batch.level} vs RoundTranscript level ${transcriptMessage.level} — the kernel enforces commitment_level < message_level (same level rejects)`,
        });
    } else {
        checks.push({
            id: 'commitment-hash',
            title: 'Revealed server_seed matches the hash committed at its index',
            status: 'unavailable',
            detail: `no SeedBatch covering index ${seedIndex} in the scanned messages — seed batches are committed ahead of play, so scan further back`,
        });
    }

    // ── Optional: the client seed the player chose ──────────────────────
    // Two sources, checked independently, and every one supplied must match:
    //
    //   - the `client_seed` inside the round's own PlaceBet command, from the
    //     receipts. Signed by the session key, so it is what the player's
    //     client actually sent — and NOTHING else compares it with the
    //     transcript: the commitment covers the command frames, not the
    //     transcript's seed field, and the kernel never sees the text;
    //   - the text typed into the form, if any.
    //
    // Both are hashed exactly as given, with no trimming: the sequencer hashes
    // the bytes the player submitted, so normalising here would let a
    // mismatched seed pass. `trim` decides only whether anything was typed.
    const seedSources: { label: string; text: string; bytes: Uint8Array }[] = [];
    const fromReceipts = clientSeedFromReceipts(input, roundId);
    const rawClientSeedText = input.clientSeedText ?? '';

    if (fromReceipts) {
        seedSources.push({
            label: `the PlaceBet command in your receipts (request ${fromReceipts.requestId}, signed by the session key)`,
            text: new TextDecoder().decode(fromReceipts.seed),
            bytes: fromReceipts.seed,
        });
    }

    if (rawClientSeedText.trim()) {
        seedSources.push({
            label: 'the text you typed',
            text: rawClientSeedText,
            bytes: new TextEncoder().encode(rawClientSeedText),
        });
    }

    if (seedSources.length > 0) {
        const compared = seedSources.map((source) => {
            const hashed = blake2b(source.bytes, { dkLen: 32 });

            return { ...source, hashed, matches: bytesEqual(hashed, transcript.clientSeed) };
        });

        checks.push({
            id: 'client-seed-text',
            title: 'Transcript client_seed is the hash of your client seed',
            status: compared.every((c) => c.matches) ? 'pass' : 'fail',
            detail:
                compared
                    .map(
                        (c) =>
                            `${c.label}: blake2b-256(utf8 "${c.text}") = ${bytesToHex(c.hashed)} ${c.matches ? '=' : '≠'} transcript client_seed ${clientSeedHex}`,
                    )
                    .join('; ') +
                '. The engine consumes the lowercase hex of those bytes, so this is what ties the replay below to the seed you chose.',
        });
    } else {
        checks.push({
            id: 'client-seed-text',
            title: 'Transcript client_seed is the hash of your client seed',
            status: 'unavailable',
            detail: `no client seed to compare — optional. The transcript carries only the 32-byte hash ${clientSeedHex}; load receipts that include this round's PlaceBet command, or type the original text, to prove the round was played under the seed you chose.`,
        });
    }

    // ── Half 1: replay the round and recompute the payout ───────────────
    let replayResult: ReplayResult | null = null;
    const replayer = REPLAYERS[transcript.gameType];
    const unknownTags = transcript.actions
        .map((a, i) => ({ index: i, tag: a.tag, actionType: a.actionType }))
        .filter((a) => a.actionType === null);

    if (!replayer) {
        checks.push({
            id: 'replay',
            title: 'Round replays to the claimed payout',
            status: 'unavailable',
            detail: `game ${transcript.gameType} is not implemented in this verifier yet (supported: ${supportedGameTypes().join(', ')})`,
        });
    } else if (unknownTags.length > 0) {
        // Mirrors the kernel's `reject-unknown-action-tag`: the message decodes
        // in full, but the round cannot be replayed under this table version.
        checks.push({
            id: 'replay',
            title: 'Round replays to the claimed payout',
            status: 'fail',
            detail: `transcript carries action tag(s) this verifier does not know: ${unknownTags
                .map((a) => `#${a.index} = 0x${a.tag.toString(16).padStart(2, '0')}`)
                .join(', ')} — the kernel rejects such a round as reject-unknown-action-tag`,
        });
    } else {
        // The action's index IS its position in the transcript, so index 0 is
        // always the place-bet and the engine's seed derivation
        // (game_type, server_seed, client_seed, action_index) needs nothing
        // else off the wire.
        const actions: TranscriptAction[] = transcript.actions.map((a, index) => ({
            actionIndex: index,
            actionType: a.actionType as string,
            payload: a.payload,
        }));

        try {
            replayResult = replayer(serverSeedHex, clientSeedHex, actions);

            const computedPayout = payoutUnits(transcript.stake, replayResult.cumulativePpm);
            const payoutMatches = computedPayout === transcript.claimedPayout;

            checks.push({
                id: 'replay-payout',
                title: 'Recomputed payout equals the claimed payout',
                status: payoutMatches ? 'pass' : 'fail',
                detail: `floor(stake ${transcript.stake} × cumulative ${replayResult.cumulativePpm} ppm / 1e6) = ${computedPayout} mutez (${unitsToDecimalString(computedPayout, TRANSCRIPT_DECIMALS)} TEZ) vs claimed ${transcript.claimedPayout}. Derivation inputs are exactly (game_type, server_seed, client_seed, action_index) — there is no operator-controlled nonce, and the action index is the action's position in the transcript.`,
            });
            checks.push({
                id: 'replay-outcome',
                title: 'Transcript settles, and to this outcome',
                status: replayResult.settled ? 'pass' : 'fail',
                detail: replayResult.settled
                    ? `replayed → ${replayResult.outcome} over ${actions.length} action(s). The wire carries no claimed outcome: the kernel derives the outcome from this same replay, and the payout above is the only number the sequencer asserts.`
                    : `the transcript ends without a settling action, so the round never closes — the kernel rejects this as reject-round-unfinished`,
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

    // ── The third proof group: the player's own receipts ────────────────
    const receipts = runReceiptProofs(input, roundId, transcript.playerCommitment, checks, findings);

    const anyFail = checks.some((c) => c.status === 'fail');
    // "verified" requires every proof to have actually run and passed. The
    // payout and commitment halves are the substance, but the SIGNATURE check
    // is load-bearing too: the rollup inbox is permissionless, so without
    // authenticating the frames against the sequencer key, a third party
    // could inject a fabricated transcript + SeedBatch pair that "verifies".
    // The receipts group joins the list for the same reason in the other
    // direction: without it, nothing ties the on-chain round to the commands
    // the PLAYER authorised, and the transcript's `player_commitment` is a
    // number the server chose. The optional client-seed-text check is
    // deliberately NOT in this list — the player may no longer have the text,
    // and its absence proves nothing either way.
    const allProofsRan = (
        [
            'replay-payout',
            'commitment-hash',
            'commitment-order',
            'signatures',
            'receipt-frames-signed',
            'commitment-vs-chain',
            'commitment-vs-receipt',
            'receipt-vs-chain',
        ] as const
    ).every((id) => checks.find((c) => c.id === id)?.status === 'pass');

    // `attested` is the honest name for "only the weak comparison ran": the
    // server's signed statement matched the chain, which detects server
    // self-inconsistency and nothing else. Calling that `verified` would let
    // an unreconstructible round borrow the credibility of a reconstructed
    // one.
    const attested =
        !anyFail &&
        receipts.reconstruction === 'unavailable' &&
        checks.find((c) => c.id === 'receipt-vs-chain')?.status === 'pass';

    return {
        roundId,
        gameType: transcript.gameType,
        checks,
        replay: replayResult,
        references,
        findings,
        scan: input.scan ?? null,
        verdict: anyFail ? 'failed' : allProofsRan ? 'verified' : attested ? 'attested' : 'incomplete',
    };
}


/**
 * The client seed from the round's own PlaceBet command in the receipts, or
 * null when there is none to read.
 *
 * WHICH command is this round's place-bet comes from the recomputation, never
 * from the export's labels: its first command is the one the server's signed
 * frames place at index 0, and index 0 is always the place-bet. The command's
 * own signed request id must name the same request, so a relabelled command
 * cannot stand in. Its session-key signature is checked by the receipts
 * authenticity proof; a forged frame fails that check and the verdict with it.
 *
 * Any gap — no receipts, a declined recomputation, an undecodable frame, a
 * command with no seed — is null, which the caller reports as an absent
 * source rather than a mismatch.
 */
function clientSeedFromReceipts(input: VerifyInput, roundId: string): { requestId: string; seed: Uint8Array } | null {
    if (input.receipts?.status !== 'ok') {
        return null;
    }

    const { commands, frames } = input.receipts.receipts;
    const recomputed = recomputeRoundCommitment({ roundIdHex: roundId, commands, frames });

    if (recomputed.status !== 'ok' || recomputed.orderedRequestIds.length === 0) {
        return null;
    }

    const requestId = recomputed.orderedRequestIds[0];
    const command = commands.find((c) => c.requestId === requestId);

    if (!command) {
        return null;
    }

    try {
        const split = splitSignedFrame(command.frame);

        if (split.tag !== CLIENT_FRAME_TAG) {
            return null;
        }

        const decoded = decodeClientEnvelope(split.body);

        if (decoded.payloadCase !== 'placeBet' || decoded.requestId !== requestId || !decoded.placeBetClientSeed) {
            return null;
        }

        return { requestId, seed: decoded.placeBetClientSeed };
    } catch {
        return null;
    }
}

/** The first admissible key this message's signature verifies under, or null. */
function matchSigningKey(message: InboxMessage, keys: VerifierKey[]): VerifierKey | null {
    for (const key of keys) {
        let raw: Uint8Array;

        try {
            raw = decodeEdpk(key.edpk);
        } catch {
            // A key set built from L1 is already base58-valid; this only
            // catches a typo in the manual override, and skipping it is right:
            // the other keys are still worth trying.
            continue;
        }

        if (verifyInboxSignature(message.envelope.signature, message.envelope.signedPayload, raw)) {
            return key;
        }
    }

    return null;
}

function describeMessage(message: InboxMessage): string {
    return `${message.envelope.message.kind} at level ${message.level}`;
}

function describeKey(key: VerifierKey): string {
    return key.registration
        ? `${key.edpk} (registered by ${key.registration.source} at level ${key.registration.level}, op ${key.registration.operationHash}, administrator ${key.registration.administrator})`
        : `${key.edpk} (MANUAL OVERRIDE — you supplied this key; nothing here says L1 ever registered it)`;
}

// ── The third proof group: the player's receipts ────────────────────────

interface ReceiptState {
    /**
     * `absent`      — nothing to reconstruct from.
     * `unavailable` — receipts present, reconstruction declined (§5.3 step 4).
     * `ok`          — a commitment was reproduced.
     */
    reconstruction: 'absent' | 'unavailable' | 'ok';
    /** Every imported frame verified under an admissible key. */
    framesAuthentic: boolean;
    /** Session id read out of the SIGNED frames, never the export's label. */
    sessionIdHex: string | null;
    /**
     * Whether the SIGNED `RoundEnded` names the round under verification.
     *
     * False on a relabelled export — genuine receipts of some other round,
     * re-pointed at a round the exporter wants a verdict about. The frames are
     * authentic and the reconstruction may well decline (there are no frames
     * for the named round), so without this flag every check that could
     * contradict the relabelling is `unavailable` and the ladder would walk
     * straight to `suppressed` for a round that never existed.
     */
    namesRoundUnderVerification: boolean;
}

/**
 * Run the four receipt proofs, in increasing order of what they prove.
 *
 *   (i)   every imported frame is authentic — a lineage key signed it;
 *   (ii)  the reconstruction matches the ON-CHAIN commitment. This is the
 *         full proof: it ties the round L1 replayed to the commands the player
 *         actually authorised;
 *   (iii) the reconstruction matches the server's SIGNED `RoundEnded`. Also
 *         full, and it is the attributable one — a mismatch here is signed
 *         evidence against a named key;
 *   (iv)  the signed `RoundEnded` matches the chain. WEAK by construction:
 *         both sides are the server's own statements, so it detects server
 *         self-inconsistency and nothing else. It is the only one that still
 *         runs when the reconstruction is unavailable, which is exactly what
 *         `attested` means.
 */
function runReceiptProofs(
    input: VerifyInput,
    roundId: string,
    chainCommitment: Uint8Array | null,
    checks: Check[],
    findings: string[],
): ReceiptState {
    // All four proofs share one cause when there is nothing to run them on, so
    // the reason is stated once and the rest point at it rather than repeating
    // a paragraph four times in the report.
    const idle = (detail: string): ReceiptState => {
        for (const [index, [id, title]] of RECEIPT_CHECKS.entries()) {
            checks.push({
                id,
                title,
                status: 'unavailable',
                detail: index === 0 ? detail : `no receipts to run this on — see the first receipts check above`,
            });
        }

        return {
            reconstruction: 'absent',
            framesAuthentic: false,
            sessionIdHex: null,
            namesRoundUnderVerification: false,
        };
    };

    const receipts = input.receipts ?? { status: 'absent' };

    if (receipts.status === 'absent') {
        return idle(
            'no receipts were supplied. The chain proofs above stand on their own, but nothing here ties ' +
                'the on-chain round to the commands YOU authorised — the transcript’s player_commitment is, ' +
                'without your frames, a number the server chose. Export your receipts from the game client ' +
                'and load them to run this group.',
        );
    }

    if (receipts.status === 'error') {
        return idle(`the receipts document could not be read: ${receipts.message}`);
    }

    const document = receipts.receipts;
    const decoded = decodeReceiptFrames(document.frames);

    if (decoded.status === 'error') {
        return idle(`a frame in the receipts document could not be decoded: ${decoded.message}`);
    }

    let roundEnded: ReceiptFrame;

    try {
        roundEnded = decodeReceiptFrame({
            sequence: 0n,
            payloadCase: 'roundEnded',
            relatedRequestId: null,
            frame: document.roundEndedFrame,
        });
    } catch (error) {
        return idle(`roundEndedFrameHex could not be decoded: ${error instanceof Error ? error.message : String(error)}`);
    }

    findings.push(...labelFindings(decoded.frames, document.roundIdHex));

    // Attribution is RECONSTRUCTED, never trusted (§8.3(e)): the round a frame
    // belongs to is what the SIGNED bytes say, and the export's label is only
    // cross-checked. Without this an exporter could relabel its way to a
    // suppression verdict.
    if (roundEnded.envelope.roundId !== null && roundEnded.envelope.roundId !== roundId) {
        findings.push(
            `the signed RoundEnded names round ${roundEnded.envelope.roundId}, but the round under verification is ${roundId}`,
        );
    }

    if (document.roundIdHex !== roundId) {
        findings.push(`the export labels its round ${document.roundIdHex}, but the round under verification is ${roundId}`);
    }

    // ── (i) authenticity ────────────────────────────────────────────────
    const framesAuthentic = pushFrameAuthenticityCheck(input, document, [...decoded.frames, roundEnded], checks);
    const sessionIdHex = roundEnded.envelope.sessionId;

    // ── the reconstruction ──────────────────────────────────────────────
    const recomputed = recomputeRoundCommitment({
        roundIdHex: roundId,
        commands: document.commands,
        frames: document.frames,
    });
    const stated = roundEnded.envelope.playerCommitment;

    pushCommitmentCheck(
        checks,
        'commitment-vs-chain',
        'Your commands reproduce the commitment ON CHAIN',
        recomputed,
        chainCommitment,
        'the transcript on L1',
        'This is the full proof: the round the kernel replayed commits to the commands you signed, so a server that swapped, dropped or invented one of them cannot match it.',
    );
    pushCommitmentCheck(
        checks,
        'commitment-vs-receipt',
        'Your commands reproduce the commitment the server SIGNED',
        recomputed,
        stated,
        'the signed RoundEnded frame',
        'Attributable: this side is signed by the tenant key, so a mismatch is evidence against a named key rather than an unsigned disagreement.',
    );

    // ── (iv) the weak comparison ────────────────────────────────────────
    if (!stated) {
        checks.push({
            id: 'receipt-vs-chain',
            title: 'The commitment the server signed equals the one on chain',
            status: 'unavailable',
            detail: 'the signed RoundEnded carries no player_commitment — absent only on a voided round, which never settled and so has none',
        });
    } else if (!chainCommitment) {
        checks.push({
            id: 'receipt-vs-chain',
            title: 'The commitment the server signed equals the one on chain',
            status: 'unavailable',
            detail: `no transcript for this round was found on chain, so there is nothing to compare the signed commitment ${bytesToHex(stated)} against`,
        });
    } else {
        const matches = bytesEqual(stated, chainCommitment);

        checks.push({
            id: 'receipt-vs-chain',
            title: 'The commitment the server signed equals the one on chain',
            status: matches ? 'pass' : 'fail',
            detail:
                `signed RoundEnded ${bytesToHex(stated)} ${matches ? '=' : '≠'} transcript ${bytesToHex(chainCommitment)}. ` +
                'WEAK BY CONSTRUCTION: both sides are the server’s own statements, so this detects a server that contradicts itself and nothing more. It is not a substitute for the two comparisons above.',
        });
    }

    return {
        reconstruction: recomputed.status === 'ok' ? 'ok' : 'unavailable',
        framesAuthentic,
        sessionIdHex,
        namesRoundUnderVerification: roundEnded.envelope.roundId === roundId,
    };
}

const RECEIPT_CHECKS: readonly (readonly [string, string])[] = [
    ['receipt-frames-signed', 'Every frame in your receipts is signed by this tenant'],
    ['commitment-vs-chain', 'Your commands reproduce the commitment ON CHAIN'],
    ['commitment-vs-receipt', 'Your commands reproduce the commitment the server SIGNED'],
    ['receipt-vs-chain', 'The commitment the server signed equals the one on chain'],
];

function pushCommitmentCheck(
    checks: Check[],
    id: string,
    title: string,
    recomputed: ReturnType<typeof recomputeRoundCommitment>,
    against: Uint8Array | null,
    againstName: string,
    why: string,
): void {
    if (recomputed.status !== 'ok') {
        checks.push({
            id,
            title,
            status: 'unavailable',
            detail: `the reconstruction declined: ${recomputed.reason}. That is a gap in the evidence this export carries, NOT a mismatch — a holder who cannot see the whole round must never accuse the server of a difference it cannot substantiate.`,
        });

        return;
    }

    if (!against) {
        checks.push({
            id,
            title,
            status: 'unavailable',
            detail: `reconstructed ${bytesToHex(recomputed.commitment)} from ${recomputed.orderedRequestIds.length} command(s), but ${againstName} states no commitment to compare it with`,
        });

        return;
    }

    const matches = bytesEqual(recomputed.commitment, against);

    checks.push({
        id,
        title,
        status: matches ? 'pass' : 'fail',
        detail:
            `blake2b-256(count ‖ (len ‖ frame)*) over ${recomputed.orderedRequestIds.length} command frame(s) in server-index order = ` +
            `${bytesToHex(recomputed.commitment)} ${matches ? '=' : '≠'} ${againstName} = ${bytesToHex(against)}. ${why}`,
    });
}

/**
 * (i) Authenticity. Server frames verify under ANY key in the tenant's
 * lineage, over the domain-separated preimage; command frames verify under the
 * session key — which the EXPORT supplies, so this half proves internal
 * consistency of the export and not who the session belonged to. The L1
 * binding of a session key lives in the vault's `sessions` big_map and is not
 * read here.
 */
function pushFrameAuthenticityCheck(
    input: VerifyInput,
    document: ImportedReceipts,
    frames: ReceiptFrame[],
    checks: Check[],
): boolean {
    const id = 'receipt-frames-signed';
    const title = 'Every frame in your receipts is signed by this tenant';

    if (input.keys.status !== 'available' || input.keys.keys.length === 0) {
        checks.push({
            id,
            title,
            status: 'unavailable',
            detail: 'no admissible signing key was derived, so the frames cannot be authenticated (see the signatures check above)',
        });

        return false;
    }

    const admissible: { key: VerifierKey; raw: Uint8Array }[] = [];

    for (const key of input.keys.keys) {
        try {
            admissible.push({ key, raw: decodeEdpk(key.edpk) });
        } catch {
            continue;
        }
    }

    const badFrames: string[] = [];
    const matched = new Set<string>();

    for (const frame of frames) {
        const hit = admissible.find((candidate) =>
            verifyServerFrameSignature(frame.signature, frame.body, candidate.raw),
        );

        if (hit) {
            matched.add(hit.key.edpk);
        } else {
            badFrames.push(`sequence ${frame.envelope.sequence} (${frame.envelope.payloadCase ?? 'unknown payload'})`);
        }
    }

    let sessionKey: Uint8Array | null = null;
    let sessionKeyError = '';

    try {
        sessionKey = decodeEdpk(document.sessionPublicKey);
    } catch (error) {
        sessionKeyError = error instanceof Error ? error.message : String(error);
    }

    const badCommands: string[] = [];

    for (const command of document.commands) {
        let split;

        try {
            split = splitSignedFrame(command.frame);
        } catch {
            badCommands.push(`${command.requestId} (frame too short)`);
            continue;
        }

        if (split.tag !== CLIENT_FRAME_TAG) {
            badCommands.push(`${command.requestId} (tag 0x${split.tag.toString(16).padStart(2, '0')}, not 0x05)`);
            continue;
        }

        // Commands are signed WITHOUT the receipt domain prefix: the session
        // key signs only this one channel, so there is no second channel to
        // separate it from.
        if (!sessionKey || !verifyInboxSignature(split.signature, split.body, sessionKey)) {
            badCommands.push(command.requestId);
        }
    }

    const ok = badFrames.length === 0 && badCommands.length === 0 && sessionKey !== null;

    checks.push({
        id,
        title,
        status: ok ? 'pass' : 'fail',
        detail: ok
            ? `${frames.length} server frame(s) verify as ed25519(blake2b-256("99dot5:server-frame:v1" ‖ body)) under ${[...matched].join(', ')}, and ${document.commands.length} command frame(s) verify under the session key ${document.sessionPublicKey}. NOTE: the session key is EXPORT-SUPPLIED — this says your commands are internally consistent with the key your client used, not that L1 bound that key to the session (the vault's sessions big_map is where that binding lives, and this build does not read it).`
            : [
                  badFrames.length > 0
                      ? `${badFrames.length}/${frames.length} server frame(s) verify under NO key this tenant registered: ${badFrames.join(', ')}`
                      : '',
                  sessionKey === null ? `the export's sessionPublicKey could not be decoded: ${sessionKeyError}` : '',
                  badCommands.length > 0
                      ? `${badCommands.length}/${document.commands.length} command frame(s) do not verify under the export's session key: ${badCommands.join(', ')}`
                      : '',
              ]
                  .filter(Boolean)
                  .join('; '),
    });

    return ok;
}

// ── The suppression ladder (§8.3) ───────────────────────────────────────

/**
 * Classify a round that is not on chain. FOUR non-accusatory outcomes stand
 * between the observation and `suppressed`, and each has to be excluded
 * explicitly, because "not on chain" and "never going to be on chain" are the
 * same observation at different times.
 *
 * There is deliberately NO minimum-age fallback. An age threshold is a guess
 * about drain latency dressed up as evidence, and a guess is exactly what must
 * not stand behind the one accusatory verdict this tool can reach: without
 * positive proof that the injector moved past this round's outbox row, the
 * answer is `undetermined` and stays there.
 *
 * ONE kind of on-chain evidence reaches `suppressed`, and it is not the
 * obvious one. The injector's `claim_unsent` orders BY id, so any outbox row
 * of this session that is LATER by id proves it drained past this round's row
 * — but the receipts cannot order a SIBLING TRANSCRIPT against this round. A
 * session that played round 1 (published) and then round 2 (still sitting in
 * the outbox) would otherwise read as suppression of round 2 out of nothing
 * but ordinary latency, which is the exact false accusation §8.3(R2) forbids.
 * An `EndSession` of the same session carries the ordering in itself:
 * `run_end_session` (`services/sequencer/src/command_handlers.rs`) refuses
 * while any round of the session is in progress, and the janitor's end path
 * settles every in-progress round first and bails before the session-terminal
 * write if even one settle failed. So the `EndSession` row is written after
 * every round's transcript row of that session, and its id is strictly
 * greater. A sibling transcript stays a reported finding and leaves the
 * verdict `undetermined`.
 */
function resolveMissingTranscript(
    input: VerifyInput,
    roundId: string,
    receipts: ReceiptState,
    inTenant: InboxMessage[],
    checks: Check[],
    references: MessageRef[],
    findings: string[],
): Verdict {
    if (checks.some((c) => c.status === 'fail')) {
        return 'failed';
    }

    // Nothing to allege on behalf of a round nobody can show receipts for.
    if (receipts.reconstruction === 'absent' || !receipts.framesAuthentic) {
        return 'incomplete';
    }

    // A RELABELLED export is authentic receipts pointed at a different round:
    // every frame verifies, the session id is a real one, and the round under
    // verification never existed. Its own reconstruction declines (there are
    // no frames for the named round), so nothing below would contradict it —
    // the label is the only thing that says which round this is about, and
    // §8.3(e) is explicit that the label is never the attribution.
    if (!receipts.namesRoundUnderVerification) {
        findings.push(
            'The signed RoundEnded in these receipts does not name the round under verification, so they ' +
                'are evidence about some other round and cannot support any verdict about this one.',
        );

        return 'incomplete';
    }

    // An accusation needs a reconstruction that actually ran. `unavailable`
    // means the export could not be folded into a commitment at all — too thin
    // to allege suppression on, and indistinguishable from an export assembled
    // to look like one.
    if (receipts.reconstruction !== 'ok') {
        findings.push(
            'The commands in these receipts could not be reconstructed into a commitment, so they do not ' +
                'establish that this round was played as claimed.',
        );

        return 'incomplete';
    }

    const scan = input.scan ?? null;
    const bracket = describeBracket(scan);

    findings.push(
        bracket.status === 'ok'
            ? `Bracketing evidence: ${bracket.reason}.`
            : `The scanned range does not bracket the round: ${bracket.reason}.`,
    );

    if (bracket.status !== 'ok') {
        return 'inconclusive';
    }

    // §8.3(a): the injector's `claim_unsent` orders BY id — the fix for a
    // production wedge, and load-bearing here. A later outbox row of the same
    // session reaching L1 proves the injector drained past this round's row
    // and did not publish it. ONLY an `EndSession` qualifies (see the header):
    // it is provably later by construction, where a sibling transcript is not
    // orderable against this round from the receipts at all.
    const sessionId = receipts.sessionIdHex;
    // Authenticated frames only: this is the evidence behind the ONE accusatory
    // verdict, and a foreign-signed EndSession carrying the session id is
    // exactly what anyone could post to the shared inbox to manufacture it.
    // `framesAuthentic` above already guarantees a usable key set here.
    const admissible = input.keys.status === 'available' ? input.keys.keys : [];
    const ofSession = (m: InboxMessage): boolean => {
        const message = m.envelope.message;

        if (matchSigningKey(m, admissible) === null) {
            return false;
        }

        if (message.kind === 'end-session') {
            return message.sessionId === sessionId;
        }

        return message.kind === 'round-transcript' && message.sessionId === sessionId && message.roundId !== roundId;
    };
    const byPosition = (a: InboxMessage, b: InboxMessage): number =>
        a.level - b.level || a.messageIndex - b.messageIndex;
    const related = sessionId ? inTenant.filter(ofSession).sort(byPosition) : [];
    const endSession = related.find((m) => m.envelope.message.kind === 'end-session') ?? null;
    const siblings = related.filter((m) => m.envelope.message.kind === 'round-transcript');

    if (siblings.length > 0) {
        // Reported either way: on its own it is not enough for an accusation,
        // and alongside an EndSession it is still the reader's context for how
        // much of this session did reach L1.
        findings.push(
            `Sibling rounds on chain: ${siblings.length} transcript(s) of session ${sessionId} (levels ` +
                `${siblings.map((m) => m.level).join(', ')}) are on L1, but the receipts cannot order them ` +
                'against this round, so on their own they are not evidence that the injector passed this ' +
                "round's outbox row — a round played after them would look identical.",
        );
    }

    if (!endSession || endSession.envelope.message.kind !== 'end-session') {
        findings.push(
            'Injector-progress evidence: none. No EndSession for this session reached L1 in the scanned ' +
                'range, so the transcript may simply not have been drained yet. Only an EndSession is ' +
                "provably later than this round's outbox row; there is deliberately no age threshold, and " +
                'no sibling transcript substitutes for it.',
        );

        return 'undetermined';
    }

    findings.push(
        `Injector-progress evidence: an EndSession of session ${sessionId} is on chain at level ` +
            `${endSession.level} (op ${endSession.operationHash}), while this round's transcript is not. ` +
            'The WS end path refuses while any round of the session is in progress, and the janitor settles ' +
            'every in-progress round before the session-terminal write and bails if a settle failed — so the ' +
            "EndSession outbox row is strictly later than this round's, and `claim_unsent` orders BY id.",
    );

    references.push({
        level: endSession.level,
        operationHash: endSession.operationHash,
        summary: `EndSession for session ${sessionId} — the injector drained past every outbox row of this session, this round's transcript included`,
    });

    return 'suppressed';
}

/** Whether the scanned range brackets the round, and why not when it does not. */
function describeBracket(scan: ScanContext | null): { status: 'ok' | 'narrow'; reason: string } {
    if (!scan) {
        return { status: 'narrow', reason: 'the caller did not state what range it scanned' };
    }

    if (scan.headLevel === null) {
        return { status: 'narrow', reason: 'the L1 head level is unknown, so "scanned up to now" cannot be established' };
    }

    if (scan.toLevel < scan.headLevel) {
        return {
            status: 'narrow',
            reason: `the scan stopped at level ${scan.toLevel}, below the head at ${scan.headLevel} — the transcript may sit in the gap`,
        };
    }

    if (!scan.deposit) {
        return {
            status: 'narrow',
            reason: 'the session’s deposit level is unknown, so the range has no L1-anchored lower bound (§8.3(d) — the bound is never client-supplied)',
        };
    }

    if (!scan.deposit.confirmed) {
        return {
            status: 'narrow',
            reason: `the export's depositOperationLevel hint (${scan.deposit.level}) could not be confirmed on L1, and an unconfirmed hint is not a bound`,
        };
    }

    if (scan.fromLevel > scan.deposit.level) {
        return {
            status: 'narrow',
            reason: `the scan started at level ${scan.fromLevel}, after the session's deposit at ${scan.deposit.level} — no round of this session can precede the deposit, so the range must start at or before it`,
        };
    }

    return { status: 'ok', reason: `levels ${scan.fromLevel}–${scan.toLevel} bracket the session's deposit at ${scan.deposit.level} and reach the head at ${scan.headLevel}` };
}
