/**
 * The located run: a game export with no locator hints, found by its signed
 * time and its transcript sender, then judged by the unchanged
 * {@link runChainVerification} over a window that contains today's.
 *
 * Steps, each a hint that only chooses where to look:
 *
 *   1. The receipts' server-signed time ({@link signedRoundTime}) is mapped to
 *      an L1 level L_est by the indexer.
 *   2. The content scan reads `[L_est − 600, L_est + 600]` and, while no
 *      authenticated transcript of the round is found, doubles its reach up to
 *      `L_est + 15,000` or the scan head. T is the authenticated copy's level,
 *      U_read the reach.
 *   3. The senders of the authenticated tenant messages read so far are asked
 *      for their applied operations below T; the levels whose indexer content
 *      holds the round's SeedBatch are confirmed on the node in their own
 *      block ({@link confirmBatchCandidate}). The lowest is B.
 *   4. The window `[max(minLevel, min(T − 20,000, D, B − 2,000)), U_read]` is
 *      judged by `runChainVerification` with no hints, on the same scanner.
 *
 * Below T the window always contains today's unhinted window, so the result
 * is never stronger than today's on the same evidence; the batch and the
 * deposit only reach further down. The judged set is what the content scan
 * reads from the node, never a sender listing.
 *
 * Only a round that was not located falls back to today's run: no signed
 * time, no level for it, or no authenticated transcript up to the cap. An
 * unread range, a declined download, an indexer contradiction and an abort
 * propagate, with no report and no second scan.
 */
import { confirmBatchCandidate } from './chain/batch-candidate';
import type { InboxMessage } from './chain/inbox';
import { IndexerContradictionError, type ScanCoverage } from './chain/inbox-scan';
import type { IndexerHints } from './chain/indexer-hints';
import { isAbort } from './chain/node-queue';
import { appendScanFindings, scanFindings } from './chain/scan-findings';
import { signedRoundTime } from './receipts/round-time';
import { type ChainRunInput, type ChainRunResult, DEFAULT_SCAN_DEPTH, runChainVerification } from './run';
import { authenticatesUnder, selectRoundTranscript, type VerificationReport } from './verifier';

/** Below the batch the sender's operations point at, the window still reads this far. */
export const BATCH_MARGIN_LEVELS = 2_000;

/** The transcript search's reach below the signed time's level (sequencer vs L1 clock). */
export const TIME_LOWER_SLACK_LEVELS = 600;

/** The transcript search's first reach above the signed time's level; doubled while nothing is found. */
export const TIME_UPPER_MARGIN = 600;

/** The farthest the search reaches above the signed time's level. */
export const TIME_EXTENSION_CAP = 15_000;

/** The kernel's seed age bound: a batch older than this below T cannot fund the round (pinned to the kernel's). */
export const MAX_SEED_AGE_LEVELS = 432_000;

/** Window re-runs after the judged copies moved below where they were located. */
export const MAX_REANCHOR_STEPS = 3;

/** What the located run found, and where it read. */
export interface LocationRecord {
    used: boolean;
    estimatedLevel: number | null;
    /** The judged transcript copy's level. */
    transcriptLevel: number | null;
    /** The lowest SeedBatch level confirmed through the sender's operations. */
    batchLevel: number | null;
    floor: number | null;
    uRead: number | null;
    /** Why the round was not located; null when it was. */
    reason: string | null;
    /**
     * The sender search's own indexer traffic (the listing and the candidate
     * reads), which the scan's download prompt does not cover; null when no
     * listing was asked for.
     */
    senderSearch: SenderSearchTraffic | null;
}

export interface SenderSearchTraffic {
    requests: number;
    bytes: number;
    /** The listing stopped at its page cap; the sender's older operations were not read. */
    truncated: boolean;
}

export interface LocatedRunInput extends ChainRunInput {
    indexer: IndexerHints;
    /** Nothing of this rollup sits lower: the administrator's origination level, or 1. */
    minLevel: number;
    /** The run's scanner coverage, read once the report is final. */
    coverage(): Pick<ScanCoverage, 'mismatches'>;
}

export interface LocatedRunResult extends ChainRunResult {
    /** Null when the run was not a candidate for locating (hints, a reader's range or no receipts). */
    location: LocationRecord | null;
}

/** The window run did not judge the transcript the search located: no report. */
export class TranscriptNotRejudgedError extends IndexerContradictionError {
    readonly reason = 'transcript-not-rejudged';

    constructor(readonly transcriptLevel: number) {
        super([transcriptLevel]);
        this.name = 'TranscriptNotRejudgedError';
        this.message =
            `The transcript located at level ${transcriptLevel} was not found again (reorganised near head, or the ` +
            'indexer’s listing changed), so there is no report; press Fetch again.';
    }
}

const RESIDUAL =
    'SeedBatch copies more than 2,000 levels below the batch, and below both the deposit and 20,000 levels before ' +
    'the transcript, were not read unless the transcript’s sender posted them; an earlier conflicting batch there ' +
    'would change this result.';

export async function runLocatedVerification(input: LocatedRunInput): Promise<LocatedRunResult> {
    const receipts = input.verify.receipts;

    if (input.hints.hints !== null || input.fromLevel !== null || input.toLevel !== null || receipts?.status !== 'ok') {
        const result = await runChainVerification(input);

        return { ...result, report: appendScanFindings(result.report, input.coverage()), location: null };
    }

    const progress = input.onProgress ?? (() => undefined);
    const keysOnce = input.resolveKeys();
    let depositOnce: ReturnType<ChainRunInput['resolveDeposit']> | null = null;
    // The flow asks for both again; the run's answers are the same ones.
    const memoised: ChainRunInput = {
        ...input,
        resolveKeys: () => keysOnce,
        resolveDeposit: () => (depositOnce ??= input.resolveDeposit()),
    };
    const insertAt = input.hints.malformed.length;
    const notLocated = async (reason: string, estimatedLevel: number | null = null): Promise<LocatedRunResult> => {
        const result = await runChainVerification(memoised);
        const findings = [...result.report.findings];

        findings.splice(insertAt, 0, `Time location: not used — ${reason}.`, ...scanFindings(input.coverage()));

        return {
            ...result,
            report: { ...result.report, findings },
            location: {
                used: false,
                estimatedLevel,
                transcriptLevel: null,
                batchLevel: null,
                floor: null,
                uRead: null,
                reason,
                senderSearch: null,
            },
        };
    };

    const keys = await keysOnce;
    const domain = input.verify.signingDomain;
    const time = signedRoundTime(receipts, keys);

    if ('reason' in time) {
        return notLocated(time.reason);
    }

    if (domain === null) {
        return notLocated('no signing domain is known, so no transcript copy can be authenticated');
    }

    progress('locating the round by its signed time…');

    const head = await input.chain.headLevel();
    const placed = await input.indexer.levelAtTime(time.lastMs, { minLevel: input.minLevel, maxLevel: head });

    if (placed.status !== 'found') {
        return notLocated(placed.reason);
    }

    const estimated = placed.level;
    const searchFrom = Math.max(input.minLevel, estimated - TIME_LOWER_SLACK_LEVELS);
    const searchCap = Math.min(estimated + TIME_EXTENSION_CAP, head);
    const read: InboxMessage[] = [];
    const transcriptIn = (messages: InboxMessage[]) =>
        selectRoundTranscript({ ...input.verify, messages, keys, signingDomain: domain });
    let margin = TIME_UPPER_MARGIN;
    let reach = Math.min(estimated + margin, head);
    let scannedTo = searchFrom - 1;
    let found: InboxMessage | null = null;

    for (;;) {
        read.push(...(await input.chain.scanRange(scannedTo + 1, reach)));
        scannedTo = Math.max(scannedTo, reach);

        const chosen = transcriptIn(read);

        if (chosen?.authenticated) {
            found = chosen.message;
            break;
        }

        if (reach >= searchCap) {
            break;
        }

        margin *= 2;
        reach = Math.min(estimated + Math.min(margin, TIME_EXTENSION_CAP), head);
    }

    if (found === null || found.envelope.message.kind !== 'round-transcript') {
        return notLocated(
            `no authenticated RoundTranscript for this round between levels ${searchFrom} and ${scannedTo}`,
            estimated,
        );
    }

    const transcriptLevel = found.level;
    const uRead = reach;
    const seedIndex = found.envelope.message.serverSeedIndex;
    const poolId = found.envelope.poolId;

    progress('looking for the seed batch among the sender’s operations…');

    const senders = [
        ...new Set(
            read
                .filter((m) => m.envelope.tenantId === input.verify.tenantId && authenticatesUnder(m, keys, domain))
                .map((m) => m.source)
                .filter((s): s is string => typeof s === 'string' && s.length > 0),
        ),
    ];
    let batchLevel: number | null = null;
    let senderSearch: SenderSearchTraffic | null = null;

    if (senders.length > 0 && transcriptLevel - 1 >= input.minLevel) {
        const listing = await input.indexer.senderOpLevels(
            senders,
            Math.max(transcriptLevel - MAX_SEED_AGE_LEVELS, input.minLevel),
            transcriptLevel - 1,
        );
        const frames =
            listing.status === 'listed' && listing.candidates.length > 0
                ? await input.indexer.candidateFrames(
                      listing.candidates.map((c) => c.level),
                      { tenantId: input.verify.tenantId, poolId, seedIndex },
                  )
                : null;

        senderSearch = {
            requests: listing.requests + (frames?.requests ?? 0),
            bytes: listing.bytes + (frames?.bytes ?? 0),
            truncated: listing.status === 'listed' && listing.truncated,
        };

        // Lowest first: the first one the node confirms is B.
        for (const level of frames?.status === 'read' ? frames.levels : []) {
            let block: InboxMessage[];

            try {
                block = await input.chain.fetchBlock(level);
            } catch (error) {
                if (isAbort(error)) {
                    throw error;
                }

                continue;
            }

            const confirmed = confirmBatchCandidate(block, {
                tenantId: input.verify.tenantId,
                poolId,
                seedIndex,
                keys,
                signingDomain: domain,
            });

            if (confirmed !== null) {
                batchLevel = confirmed.level;
                break;
            }
        }
    }

    const deposit = await memoised.resolveDeposit();
    const depositLevel = deposit?.confirmed ? deposit.level : null;
    const floorOf = (t: number, b: number | null) =>
        Math.max(
            input.minLevel,
            Math.min(
                t - DEFAULT_SCAN_DEPTH,
                ...(depositLevel === null ? [] : [depositLevel]),
                ...(b === null ? [] : [b - BATCH_MARGIN_LEVELS]),
            ),
        );
    const windowRun = async (floor: number): Promise<ChainRunResult> => {
        const result = await runChainVerification({
            ...memoised,
            fromLevel: floor,
            toLevel: uRead,
            hints: { hints: null, source: input.hints.source, malformed: input.hints.malformed },
        });
        const judged = judgedTranscriptLevel(result.report);

        if (judged === null || judged > transcriptLevel) {
            throw new TranscriptNotRejudgedError(transcriptLevel);
        }

        return result;
    };

    let floor = floorOf(transcriptLevel, batchLevel);
    let result = await windowRun(floor);
    let movedFindings: string[] = [];

    for (let step = 0; ; step++) {
        const judgedT = judgedTranscriptLevel(result.report) ?? transcriptLevel;
        const judgedB = judgedBatchLevel(result.report);
        const lowestB =
            judgedB !== null && batchLevel !== null ? Math.min(judgedB, batchLevel) : (judgedB ?? batchLevel);
        const lower = floorOf(judgedT, lowestB);

        if (lower >= floor) {
            break;
        }

        if (step >= MAX_REANCHOR_STEPS) {
            movedFindings = [`The judged copies kept moving earlier; the window ends at level ${floor}.`];
            break;
        }

        progress(`re-anchoring the window: levels ${lower}–${uRead}`);
        floor = lower;
        result = await windowRun(floor);
    }

    const judgedT = judgedTranscriptLevel(result.report) ?? transcriptLevel;
    const timeLine =
        `Time location: the server-signed time (${time.source}, ${new Date(time.lastMs).toISOString()}) maps to ` +
        `L1 level ≈${estimated}; the transcript copy judged is at level ${judgedT}; the SeedBatch covering index ` +
        `${seedIndex} ` +
        (batchLevel === null
            ? 'was not located through the sender’s operations'
            : `was located at level ${batchLevel} through the transcript sender’s operations`) +
        `; levels ${floor}–${uRead} were read. A time and a sender only choose where to look; every check rests on ` +
        'the messages read from the Tezos RPC.';
    const findings = [...result.report.findings];

    findings.splice(insertAt, 0, timeLine, RESIDUAL, ...movedFindings, ...scanFindings(input.coverage()));

    return {
        report: { ...result.report, findings },
        hintedRun: null,
        preliminary: result.preliminary,
        hints: result.hints,
        location: {
            used: true,
            estimatedLevel: estimated,
            transcriptLevel: judgedT,
            batchLevel,
            floor,
            uRead,
            reason: null,
            senderSearch,
        },
    };
}

/** The level of the transcript copy a report judged, when its `round-transcript` check passed. */
function judgedTranscriptLevel(report: VerificationReport): number | null {
    if (report.checks.find((c) => c.id === 'round-transcript')?.status !== 'pass') {
        return null;
    }

    return report.references.find((r) => r.summary.startsWith('RoundTranscript'))?.level ?? null;
}

/** The level of the SeedBatch copy a report judged, if any. */
function judgedBatchLevel(report: VerificationReport): number | null {
    return report.references.find((r) => r.summary.startsWith('SeedBatch'))?.level ?? null;
}
