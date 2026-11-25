/**
 * The inbox scan every chain run goes through.
 *
 * The indexer LOCATES: its external inbox rows say which levels hold messages
 * with this rollup's prefix ({@link locateFrameLevels}). The node is the
 * EVIDENCE: every message returned is read from the reader's node, applied
 * only. On top of the located levels the node is also read at each call's two
 * ends, at a few random levels the indexer called frame-free, at every level
 * already read in this run (a confirmed hint, say), and at up to
 * {@link LAG_TAIL_MAX} levels above the indexer's head.
 *
 * Unread is never empty. A range comes back only when every level in it is
 * covered: its chunk was listed completely (every page down to an empty one,
 * or to an early end the indexer confirmed holds no row beyond those read)
 * and every level the node was asked for was served with its operation
 * results. Otherwise the call rejects, after everything else has finished,
 * with {@link ScanIncompleteError}; a declined download rejects with
 * {@link DownloadDeclinedError}; a level the indexer called frame-free but the
 * node holds frames at rejects with {@link IndexerContradictionError}. None of
 * them leaves anything to judge, so no report can rest on a range nobody read.
 *
 * One scanner serves one run: its spot-check budget, download allowance and
 * node memo are the run's. The {@link RangeCache} outlives it, so a Retry
 * fetches only what the last run could not read.
 */
import {
    blockHeader,
    type BlockInbox,
    type InboxMessage,
    LevelUnreadable,
    type NodeHistory,
    nodeHistory,
    readBlockInbox,
} from './inbox';
import { ByteRate, type FrameLocator, locateFrameLevels } from './inbox-locator';
import { type FetchLike, fetchRetrying, isAbort, NodeQueue, type Sleep } from './node-queue';
import { FINALITY_LEVELS, type LevelInterval, mergeIntervals, RangeCache } from './range-cache';

/** The download a run may make before the reader is asked (bytes of response text). */
export const DOWNLOAD_PROMPT_BYTES = 50_000_000;

/** The most levels above the indexer's head the node is read at directly. */
export const LAG_TAIL_MAX = 10;

/** Random frame-free levels the node is read at, per run. */
export const SPOT_CHECK_LEVELS = 8;

/** A call draws `ceil(SPOT_CHECK_LEVELS × uncachedLevels / SPOT_SPAN_LEVELS)` from what is left of the budget. */
export const SPOT_SPAN_LEVELS = 20_000;

/** Levels the run's rate must rest on before the reader is asked a second time. */
export const PROJECTION_SAMPLE_LEVELS = 1_000;

/** Bytes on the wire over response text, as measured on the public indexer with gzip; for the prompt only. */
export const COMPRESSED_RATIO = 0.44;

/** What the scanner needs from a node; the shell passes {@link rpcNodeInbox}, a test a stub. */
export interface NodeInbox {
    head(): Promise<number>;
    /** One level's applied inbox; throws {@link LevelUnreadable} when the node cannot serve it. */
    read(level: number, fetchImpl: FetchLike): Promise<BlockInbox>;
    /** The node's history limit, best-effort. */
    history(): Promise<NodeHistory | null>;
}

/** The reader's node over its RPC. */
export function rpcNodeInbox(
    rpcUrl: string,
    options: { signal?: AbortSignal; sleep?: Sleep; fetchImpl?: FetchLike } = {},
): NodeInbox {
    const { signal, sleep } = options;
    const retrying: FetchLike = (url) => fetchRetrying(url, { signal, sleep, fetchImpl: options.fetchImpl });

    return {
        head: async () => (await blockHeader(rpcUrl, 'head', { signal, fetchImpl: retrying })).level,
        read: (level, fetchImpl) => readBlockInbox(rpcUrl, level, { signal, fetchImpl }),
        history: () => nodeHistory(rpcUrl, { signal, fetchImpl: options.fetchImpl }),
    };
}

/** What the reader is asked to consent to. */
export interface DownloadRequest {
    fromLevel: number;
    toLevel: number;
    /** Levels still to locate in this call. */
    levels: number;
    /** Projected bytes still to download (response text). */
    estimateBytes: number;
    /** The same, roughly as it travels compressed. */
    compressedApprox: number;
}

export type UnreadReason = 'indexer' | 'level-unreadable' | 'above-head' | 'indexer-lagging';

export interface UnreadRange extends LevelInterval {
    reason: UnreadReason;
    detail: string;
}

/** Some levels of the range could not be read; no report may rest on it. */
export class ScanIncompleteError extends Error {
    constructor(readonly unread: UnreadRange[]) {
        super(
            'The scan could not read every level, so there is no report: ' +
                unread
                    .map(
                        (u) =>
                            `${u.fromLevel === u.toLevel ? `level ${u.fromLevel}` : `levels ${u.fromLevel}–${u.toLevel}`}` +
                            ` (${u.detail})`,
                    )
                    .join('; ') +
                '. Retry reads only what is still missing.',
        );
        this.name = 'ScanIncompleteError';
    }
}

/** The reader declined the download; nothing was judged. */
export class DownloadDeclinedError extends Error {
    constructor(readonly request: DownloadRequest) {
        super(
            `Download declined: levels ${request.fromLevel}–${request.toLevel} were not read, so there is no report.`,
        );
        this.name = 'DownloadDeclinedError';
    }
}

/** The node holds frames at levels the indexer listed as frame-free: the indexer's listing cannot be trusted here. */
export class IndexerContradictionError extends Error {
    constructor(readonly levels: number[]) {
        super(
            `The indexer lists no message for this rollup at level(s) ${levels.join(', ')}, but the Tezos RPC holds ` +
                'applied ones there. The indexer cannot be relied on to choose the levels to read, so there is no ' +
                'report; try another indexer.',
        );
        this.name = 'IndexerContradictionError';
    }
}

/** A level where the indexer's and the node's prefixed counts differ, without the indexer hiding anything. */
export interface CountMismatch {
    level: number;
    indexer: number;
    node: number;
}

export interface ScanCoverage {
    /** Levels every call in the run covered, merged. */
    covered: LevelInterval[];
    mismatches: CountMismatch[];
    /** Response text downloaded from the indexer in this run. */
    indexerBytes: number;
    indexerRequests: number;
    /** Node block requests made in this run (memo hits not counted). */
    nodeReads: number;
    spotLevels: number[];
}

export interface ScanProgress {
    phase: 'locating' | 'reading';
    done: number;
    total: number;
}

export interface ScannerOptions {
    locator: FrameLocator;
    node: NodeInbox;
    /** Shared across runs for the same endpoints; a fresh one when absent. */
    cache?: RangeCache;
    /** Edges and spot checks are never below this level: the administrator's origination, or 1. */
    minLevel?: number;
    confirmDownload(request: DownloadRequest): Promise<boolean>;
    /** Uniform in [0, 1); seeded in tests. */
    random?: () => number;
    signal?: AbortSignal;
    onProgress?(progress: ScanProgress): void;
    fetchImpl?: FetchLike;
    sleep?: Sleep;
    /** The run's initial download allowance. */
    allowanceBytes?: number;
}

export interface Scanner {
    /** `min(nodeHead, indexerHead + LAG_TAIL_MAX)`, read once per run: the newest level both can serve. */
    scanHead(): Promise<number>;
    /** Every decoded applied sequencer message in the inclusive range, by level, node order within a level. */
    scanRange(fromLevel: number, toLevel: number): Promise<InboxMessage[]>;
    /** One block's messages, through the run's node memo. */
    fetchBlock(level: number): Promise<InboxMessage[]>;
    coverage(): ScanCoverage;
}

interface Heads {
    node: number;
    indexer: number;
    scan: number;
}

type SegmentKind = 'cached' | 'located' | 'failed' | 'tail';

interface Segment extends LevelInterval {
    kind: SegmentKind;
    detail: string;
}

const defaultRandom = (): number => crypto.getRandomValues(new Uint32Array(1))[0] / 2 ** 32;

/**
 * New message objects for every caller. The memo holds one read per level,
 * but callers tell copies apart by identity: `run.ts` drops the confirmed
 * batch-hint object from its re-run and keeps a scanned copy of the same
 * message, as it did when every read built its own objects.
 */
function freshCopies(messages: InboxMessage[]): InboxMessage[] {
    return messages.map((m) => ({ ...m }));
}

export function createScanner(options: ScannerOptions): Scanner {
    const cache = options.cache ?? new RangeCache();
    const minLevel = Math.max(1, options.minLevel ?? 1);
    const random = options.random ?? defaultRandom;
    const signal = options.signal;
    const rate = new ByteRate();
    const mismatches = new Map<number, CountMismatch>();
    const covered: LevelInterval[] = [];
    const spotLevels: number[] = [];
    let allowance = options.allowanceBytes ?? DOWNLOAD_PROMPT_BYTES;
    let asked = false;
    let spent = 0;
    let indexerRequests = 0;
    let spotBudget = SPOT_CHECK_LEVELS;
    let finalLevel = Number.NEGATIVE_INFINITY;
    let heads: Promise<Heads> | null = null;
    let history: Promise<NodeHistory | null> | null = null;

    const queue = new NodeQueue<BlockInbox>({
        read: (level, fetchImpl) => options.node.read(level, fetchImpl),
        fetchImpl: options.fetchImpl,
        signal,
        sleep: options.sleep,
        store: {
            get: (level) => cache.nodeRead(level),
            set: (level, value) => cache.setNodeRead(level, value, finalLevel),
        },
    });

    const readHeads = (): Promise<Heads> => {
        heads ??= Promise.all([options.node.head(), options.locator.head()]).then(([node, indexer]) => {
            finalLevel = Math.min(node, indexer) - FINALITY_LEVELS;

            return { node, indexer, scan: Math.min(node, indexer + LAG_TAIL_MAX) };
        });

        return heads;
    };

    /** The unreadable level with the node's history limit named, when that is what it is about. */
    const described = async (error: LevelUnreadable): Promise<LevelUnreadable> => {
        history ??= options.node.history().catch(() => null);

        const limit = await history;

        if (error.reason === 'http-error') {
            // The node answered, and said something else: its own words stand.
            return error;
        }

        if (error.reason !== 'network-error') {
            return error.withHistory(limit);
        }

        // A pruned node often answers an old block with a 404 that carries no
        // CORS header, which a browser can only see as a failed fetch. Below
        // the node's savepoint that failure is the history limit, so say so.
        return limit !== null && error.level < limit.savepoint
            ? new LevelUnreadable(error.level, 'not-served', error.detail, limit)
            : error;
    };

    const progress = (p: ScanProgress) => options.onProgress?.(p);

    async function scanRange(fromLevel: number, toLevel: number): Promise<InboxMessage[]> {
        signal?.throwIfAborted();

        const h = await readHeads();

        signal?.throwIfAborted();

        if (fromLevel > toLevel) {
            return [];
        }

        const unread: UnreadRange[] = [];
        const readTo = Math.min(toLevel, h.scan);

        // Above the scan head nothing is read and nothing is clamped: those
        // levels are unread, and the call rejects once the rest is done.
        const laggingFrom = Math.max(fromLevel, h.scan + 1);
        const laggingTo = Math.min(toLevel, h.node);

        if (laggingFrom <= laggingTo) {
            unread.push({
                fromLevel: laggingFrom,
                toLevel: laggingTo,
                reason: 'indexer-lagging',
                detail: `the indexer is ${h.node - h.indexer} levels behind the Tezos RPC; Retry in a minute`,
            });
        }

        if (toLevel > h.node) {
            unread.push({
                fromLevel: Math.max(fromLevel, h.node + 1),
                toLevel,
                reason: 'above-head',
                detail: `above the scan head, level ${h.scan}, the newest level both the Tezos RPC and the indexer serve`,
            });
        }

        const indexerTo = Math.min(readTo, h.indexer);
        const segments: Segment[] = [];
        const callCounts = new Map<number, number>();
        const reads = new Map<number, Promise<void>>();
        const nodeByLevel = new Map<number, BlockInbox>();
        const failures = new Map<number, LevelUnreadable>();
        const contradictions = new Set<number>();
        let aborted: unknown = null;
        let readsDone = 0;

        const segmentOf = (level: number) => segments.find((s) => s.fromLevel <= level && level <= s.toLevel);
        const locatorCount = (level: number): number | undefined => {
            const segment = segmentOf(level);

            if (segment?.kind === 'cached') {
                return cache.frameCount(level) ?? 0;
            }

            return segment?.kind === 'located' ? (callCounts.get(level) ?? 0) : undefined;
        };
        const check = (level: number, read: BlockInbox) => {
            const indexer = locatorCount(level);

            if (indexer === undefined) {
                return;
            }

            if (indexer === 0 && read.appliedPrefixedCount > 0) {
                contradictions.add(level);
            } else if (indexer !== read.appliedPrefixedCount) {
                mismatches.set(level, { level, indexer, node: read.appliedPrefixedCount });
            }
        };
        const schedule = (level: number) => {
            if (level < fromLevel || level > readTo || reads.has(level)) {
                return;
            }

            reads.set(
                level,
                queue.read(level).then(
                    (read) => {
                        nodeByLevel.set(level, read);
                        progress({ phase: 'reading', done: ++readsDone, total: reads.size });
                    },
                    async (error: unknown) => {
                        if (error instanceof LevelUnreadable) {
                            failures.set(level, await described(error));
                        } else if (isAbort(error) || signal?.aborted) {
                            aborted = error;
                        } else {
                            failures.set(
                                level,
                                new LevelUnreadable(
                                    level,
                                    'network-error',
                                    error instanceof Error ? error.message : String(error),
                                ),
                            );
                        }
                    },
                ),
            );
        };
        const lowEdge = Math.max(fromLevel, minLevel);
        const edges = lowEdge <= readTo ? [lowEdge, readTo] : [];
        const scheduleEdgesIn = (segment: LevelInterval) => {
            for (const edge of edges) {
                if (edge >= segment.fromLevel && edge <= segment.toLevel) {
                    schedule(edge);
                }
            }
        };

        // What the cache already holds: its listed intervals' frame levels and edges.
        const gaps = indexerTo >= fromLevel ? cache.uncovered(fromLevel, indexerTo) : [];
        let next = fromLevel;

        for (const gap of [...gaps, { fromLevel: indexerTo + 1, toLevel: indexerTo }]) {
            if (gap.fromLevel > next) {
                const segment: Segment = { fromLevel: next, toLevel: gap.fromLevel - 1, kind: 'cached', detail: '' };

                segments.push(segment);

                for (const level of cache.frameLevels(segment.fromLevel, segment.toLevel)) {
                    schedule(level);
                }

                scheduleEdgesIn(segment);
            }

            next = gap.toLevel + 1;
        }

        // Every level this run, or an earlier one, already holds a node read
        // for: checked against the indexer at no cost (the known-frame check).
        for (const level of [...queue.memoLevels(), ...cache.nodeReadLevels()]) {
            if (level <= indexerTo) {
                schedule(level);
            }
        }

        // The lag tail above the indexer's head, read from the node directly.
        const tailFrom = Math.max(fromLevel, h.indexer + 1);

        if (tailFrom <= readTo) {
            segments.push({ fromLevel: tailFrom, toLevel: readTo, kind: 'tail', detail: '' });

            for (let level = tailFrom; level <= readTo; level++) {
                schedule(level);
            }
        }

        // Spot checks: drawn over the levels this call has to locate.
        const uncachedLevels = gaps.reduce((sum, g) => sum + g.toLevel - g.fromLevel + 1, 0);
        const eligible = gaps
            .map((g) => ({ fromLevel: Math.max(g.fromLevel, minLevel), toLevel: g.toLevel }))
            .filter((g) => g.fromLevel <= g.toLevel);
        const eligibleCount = eligible.reduce((sum, g) => sum + g.toLevel - g.fromLevel + 1, 0);
        const wanted = Math.min(spotBudget, Math.ceil((SPOT_CHECK_LEVELS * uncachedLevels) / SPOT_SPAN_LEVELS));
        const spots = new Set<number>();

        for (let attempt = 0; spots.size < Math.min(wanted, eligibleCount) && attempt < wanted * 32; attempt++) {
            let offset = Math.floor(random() * eligibleCount);

            for (const g of eligible) {
                const size = g.toLevel - g.fromLevel + 1;

                if (offset < size) {
                    spots.add(g.fromLevel + offset);
                    break;
                }

                offset -= size;
            }
        }

        spotBudget -= spots.size;

        /** A drawn level the indexer lists frames at moves to a frame-free level of the same chunk. */
        const placeSpot = (drawn: number, chunk: LevelInterval): number | null => {
            if ((callCounts.get(drawn) ?? 0) === 0) {
                return drawn;
            }

            const low = Math.max(chunk.fromLevel, minLevel);
            const size = chunk.toLevel - low + 1;

            for (let attempt = 0; attempt < 32 && size > 0; attempt++) {
                const candidate = low + Math.floor(random() * size);

                if ((callCounts.get(candidate) ?? 0) === 0) {
                    return candidate;
                }
            }

            return null;
        };

        let declined: DownloadRequest | null = null;
        let remaining = uncachedLevels;
        let located = 0;

        locating: for (const [gapIndex, gap] of gaps.entries()) {
            for await (const chunk of locateFrameLevels(options.locator, gap.fromLevel, gap.toLevel, rate)) {
                const levels = chunk.toLevel - chunk.fromLevel + 1;

                spent += chunk.bytes;
                indexerRequests += chunk.requests;
                remaining -= levels;
                located += levels;
                progress({ phase: 'locating', done: located, total: uncachedLevels });

                if (chunk.status === 'located') {
                    const segment: Segment = { ...chunk, kind: 'located', detail: '' };

                    segments.push(segment);

                    for (const [level, count] of chunk.frameCountByLevel) {
                        callCounts.set(level, count);
                        schedule(level);
                    }

                    scheduleEdgesIn(segment);

                    for (const drawn of spots) {
                        if (drawn >= chunk.fromLevel && drawn <= chunk.toLevel) {
                            const placed = placeSpot(drawn, chunk);

                            if (placed !== null) {
                                spotLevels.push(placed);
                                schedule(placed);
                            }
                        }
                    }
                } else {
                    segments.push({
                        fromLevel: chunk.fromLevel,
                        toLevel: chunk.toLevel,
                        kind: 'failed',
                        detail: `the indexer could not list them: ${chunk.reason}, ${chunk.detail}`,
                    });
                }

                // Consent: project the rest of this call at the run's mean rate.
                // The first ask comes right after the probe. A later one waits
                // until the rate rests on PROJECTION_SAMPLE_LEVELS, so the
                // noise of the first few chunks does not ask twice, unless the
                // download itself has passed what the reader agreed to.
                const perLevel = rate.meanBytesPerLevel;
                const settled = !asked || rate.levelsSeen >= PROJECTION_SAMPLE_LEVELS || spent > allowance;

                if (remaining > 0 && perLevel !== null && settled) {
                    const projected = spent + perLevel * remaining;

                    if (projected > allowance) {
                        const restFrom =
                            chunk.toLevel < gap.toLevel
                                ? chunk.toLevel + 1
                                : (gaps[gapIndex + 1]?.fromLevel ?? indexerTo);
                        const request: DownloadRequest = {
                            fromLevel: restFrom,
                            toLevel: indexerTo,
                            levels: remaining,
                            estimateBytes: projected - spent,
                            compressedApprox: COMPRESSED_RATIO * (projected - spent),
                        };
                        const accepted = await options.confirmDownload(request);

                        asked = true;

                        signal?.throwIfAborted();

                        if (!accepted) {
                            declined = request;
                            break locating;
                        }

                        allowance = projected * 1.25;
                    }
                }
            }
        }

        await Promise.all(reads.values());

        if (aborted !== null) {
            throw aborted;
        }

        signal?.throwIfAborted();

        // Checked once everything is listed: a level read from the memo
        // resolves before its chunk is.
        for (const [level, read] of nodeByLevel) {
            check(level, read);
        }

        // A level the node could not serve leaves its whole segment uncovered.
        for (const [level, error] of failures) {
            const segment = segmentOf(level);

            if (segment && segment.kind !== 'failed') {
                if (segment.kind === 'tail') {
                    unread.push({
                        fromLevel: level,
                        toLevel: level,
                        reason: 'level-unreadable',
                        detail: error.message,
                    });
                } else {
                    segment.kind = 'failed';
                    segment.detail = error.message;
                    unread.push({ ...segment, reason: 'level-unreadable', detail: error.message });
                }
            }
        }

        // Only a chunk that ended covered is kept for a later run: one whose
        // node reads failed is listed, and spot-checked, again on Retry. A
        // listing the node contradicted is kept nowhere.
        if (contradictions.size === 0) {
            for (const segment of segments) {
                if (segment.kind === 'located') {
                    cache.addLocated(segment.fromLevel, segment.toLevel, callCounts, finalLevel);
                }
            }
        }

        if (declined !== null) {
            throw new DownloadDeclinedError(declined);
        }

        if (contradictions.size > 0) {
            throw new IndexerContradictionError([...contradictions].sort((a, b) => a - b));
        }

        for (const segment of segments) {
            if (segment.kind === 'failed' && !unread.some((u) => u.fromLevel === segment.fromLevel)) {
                unread.push({
                    fromLevel: segment.fromLevel,
                    toLevel: segment.toLevel,
                    reason: 'indexer',
                    detail: segment.detail,
                });
            }
        }

        if (unread.length > 0) {
            throw new ScanIncompleteError(unread.sort((a, b) => a.fromLevel - b.fromLevel));
        }

        covered.push({ fromLevel, toLevel });

        return [...nodeByLevel.keys()]
            .sort((a, b) => a - b)
            .flatMap((level) => freshCopies(nodeByLevel.get(level)?.messages ?? []));
    }

    async function fetchBlock(level: number): Promise<InboxMessage[]> {
        signal?.throwIfAborted();
        await readHeads();

        try {
            return freshCopies((await queue.read(level)).messages);
        } catch (error) {
            throw error instanceof LevelUnreadable ? await described(error) : error;
        }
    }

    return {
        async scanHead() {
            signal?.throwIfAborted();

            return (await readHeads()).scan;
        },
        scanRange,
        fetchBlock,
        coverage: () => ({
            covered: mergeIntervals(covered),
            mismatches: [...mismatches.values()].sort((a, b) => a.level - b.level),
            indexerBytes: spent,
            indexerRequests,
            nodeReads: queue.fetched.length,
            spotLevels: [...spotLevels],
        }),
    };
}
