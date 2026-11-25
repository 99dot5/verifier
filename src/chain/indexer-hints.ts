/**
 * The indexer reads that only choose where a located run looks.
 *
 * Three questions, each a HINT and never evidence:
 *
 *   - {@link IndexerHints.levelAtTime}: which L1 level the round's
 *     server-signed time falls at, so the transcript search starts there;
 *   - {@link IndexerHints.senderOpLevels}: at which levels the transcript's
 *     sender posted applied `smart_rollup_add_messages` operations, so the
 *     round's SeedBatch can be looked for there;
 *   - {@link IndexerHints.candidateFrames}: which of those levels hold, in the
 *     indexer's copy, a SeedBatch of the round's tenant and pool covering its
 *     seed index.
 *
 * Nothing here returns a message: `candidateFrames` decodes the indexer's
 * bytes only to choose levels, and returns levels and summaries. Every
 * candidate is then read from the reader's node and confirmed in its own
 * block before it moves anything, and the judged set is always what the
 * content scan reads from the node. A wrong answer here costs bytes or reach,
 * never soundness.
 *
 * Every request follows the scan's one retry rule ({@link fetchRetrying}) and
 * carries both level bounds where the endpoint takes them. A failed lookup is
 * an absent hint, never an error; only an abort propagates.
 */
import { type DecodedEnvelope, decodeExternalMessage } from '@99dot5/round-replay';
import { PAGE_LIMIT } from './inbox-locator';
import { type FetchLike, fetchRetrying, isAbort, type Sleep } from './node-queue';

/** The most sender operation levels whose indexer content is read for a candidate batch. */
export const SENDER_CANDIDATE_BUDGET = 200;

/**
 * The most pages of the sender listing read, newest operation first: with
 * {@link PAGE_LIMIT} rows a page, the latest 100,000 operations. A batch the
 * sender posted before them is not looked for, and the window then rests on
 * the deposit and 20,000 levels below the transcript, as without a listing.
 * The listing is outside the scan's download prompt, so it is bounded here.
 */
export const SENDER_LISTING_MAX_PAGES = 10;

/** Where a time fell, or why it could not be placed. */
export type LevelAtTime = { status: 'found'; level: number } | { status: 'not-found'; reason: string };

/** One level the sender posted at, with the messages it posted there. */
export interface SenderOpLevel {
    level: number;
    messagesCount: number;
}

/** What a hint lookup cost: requests made and response text read. */
export interface HintTraffic {
    requests: number;
    bytes: number;
}

export type SenderOpLevels = HintTraffic &
    (
        | {
              status: 'listed';
              /** Bursts first (`messagesCount` descending), then the latest level; at most the budget. */
              candidates: SenderOpLevel[];
              /** Operations the listing returned, before any cut. */
              operations: number;
              /** The listing stopped at {@link SENDER_LISTING_MAX_PAGES}; older operations were not read. */
              truncated: boolean;
          }
        | { status: 'unavailable'; reason: string }
    );

/** A SeedBatch the indexer's copy of a level holds: where, and which indices. Never its bytes. */
export interface CandidateSummary {
    level: number;
    startIndex: bigint;
    count: number;
}

export type CandidateFrames = HintTraffic &
    ({ status: 'read'; levels: number[]; summaries: CandidateSummary[] } | { status: 'unavailable'; reason: string });

export interface CandidateQuery {
    tenantId: string;
    poolId: string;
    seedIndex: bigint;
}

/** What a located run asks the indexer; the shell passes {@link tzktIndexerHints}, a test a stub. */
export interface IndexerHints {
    /** The newest level at or before `unixMs`, within `[minLevel, maxLevel]`. */
    levelAtTime(unixMs: number, bounds: { minLevel: number; maxLevel: number }): Promise<LevelAtTime>;
    /** Levels in `[fromLevel, toLevel]` where any of `senders` posted an applied add_messages operation. */
    senderOpLevels(senders: string[], fromLevel: number, toLevel: number): Promise<SenderOpLevels>;
    /** The levels among `levels` whose indexer content holds a SeedBatch matching `query`. */
    candidateFrames(levels: number[], query: CandidateQuery): Promise<CandidateFrames>;
}

export interface TzktHintsOptions {
    tzktApiUrl: string;
    signal?: AbortSignal;
    fetchImpl?: FetchLike;
    sleep?: Sleep;
}

interface Answer {
    body: unknown;
    /** Response text length. */
    bytes: number;
}

function isInteger(value: unknown): value is number {
    return typeof value === 'number' && Number.isSafeInteger(value);
}

function base64Bytes(text: string): Uint8Array | null {
    try {
        return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
    } catch {
        return null;
    }
}

/** The indexer's answers through TzKT's public API. */
export function tzktIndexerHints(options: TzktHintsOptions): IndexerHints {
    const base = options.tzktApiUrl.trim().replace(/\/+$/, '');

    /** One request under the retry rule: the parsed body and status, or why there is none. Aborts throw. */
    const get = async (path: string): Promise<Answer | string> => {
        let response: Response;

        try {
            response = await fetchRetrying(`${base}${path}`, {
                fetchImpl: options.fetchImpl,
                signal: options.signal,
                sleep: options.sleep,
            });
        } catch (error) {
            if (isAbort(error) || options.signal?.aborted) {
                throw error;
            }

            return `the indexer could not be reached (${error instanceof Error ? error.message : String(error)})`;
        }

        if (!response.ok) {
            return `the indexer answered HTTP ${response.status}`;
        }

        let text: string;

        try {
            text = await response.text();
        } catch (error) {
            if (isAbort(error) || options.signal?.aborted) {
                throw error;
            }

            return `the indexer’s answer could not be read (${error instanceof Error ? error.message : String(error)})`;
        }

        try {
            return { body: JSON.parse(text) as unknown, bytes: text.length };
        } catch {
            return 'the indexer answered with something other than JSON';
        }
    };

    return {
        async levelAtTime(unixMs, { minLevel, maxLevel }) {
            if (!Number.isFinite(unixMs) || minLevel > maxLevel) {
                return { status: 'not-found', reason: 'there is no level range to place the time in' };
            }

            const iso = new Date(unixMs).toISOString();
            const answer = await get(
                `/v1/blocks?timestamp.le=${iso}&level.ge=${minLevel}&level.le=${maxLevel}` +
                    '&sort.desc=level&limit=1&select=level',
            );

            if (typeof answer !== 'string') {
                if (!Array.isArray(answer.body)) {
                    return { status: 'not-found', reason: 'the indexer’s block listing is not a list' };
                }

                const [level] = answer.body as unknown[];

                if (answer.body.length === 0) {
                    return {
                        status: 'not-found',
                        reason: `the indexer has no block at or before ${iso} between levels ${minLevel} and ${maxLevel}`,
                    };
                }

                if (!isInteger(level)) {
                    return { status: 'not-found', reason: 'the indexer’s block listing states no level' };
                }

                // Bounded in the request; an answer outside the bounds is not trusted to place anything.
                return level < minLevel || level > maxLevel
                    ? {
                          status: 'not-found',
                          reason: `the indexer placed ${iso} at level ${level}, outside the levels ${minLevel}–${maxLevel} asked for`,
                      }
                    : { status: 'found', level };
            }

            // The block-by-timestamp route takes no level bound, so its
            // answer is clamped to the range here.
            const fallback = await get(`/v1/blocks/${iso}/level`);

            if (typeof fallback === 'string') {
                return { status: 'not-found', reason: `${answer}, and ${fallback} for the block at ${iso}` };
            }

            if (!isInteger(fallback.body) || fallback.body < minLevel) {
                return {
                    status: 'not-found',
                    reason: `the indexer places ${iso} at no level between ${minLevel} and ${maxLevel}`,
                };
            }

            return { status: 'found', level: Math.min(fallback.body, maxLevel) };
        },

        async senderOpLevels(senders, fromLevel, toLevel) {
            const unique = [...new Set(senders)].sort();

            if (unique.length === 0 || fromLevel > toLevel) {
                return { status: 'listed', candidates: [], operations: 0, truncated: false, requests: 0, bytes: 0 };
            }

            const senderFilter = unique.length === 1 ? `sender=${unique[0]}` : `sender.in=${unique.join(',')}`;
            const counts = new Map<number, number>();
            let operations = 0;
            let requests = 0;
            let bytes = 0;
            let truncated = false;
            let lastId: number | null = null;
            const unavailable = (reason: string): SenderOpLevels => ({
                status: 'unavailable',
                reason,
                requests,
                bytes,
            });

            // A page loop ends on an empty page (a server may cap pages below
            // the limit asked for), or at the page cap, newest operations first.
            for (;;) {
                if (requests >= SENDER_LISTING_MAX_PAGES) {
                    truncated = true;
                    break;
                }

                requests += 1;

                const answer = await get(
                    `/v1/operations/sr_add_messages?${senderFilter}&status=applied` +
                        `&level.ge=${fromLevel}&level.le=${toLevel}&select=id,level,messagesCount&sort.desc=id` +
                        `&limit=${PAGE_LIMIT}` +
                        (lastId === null ? '' : `&id.lt=${lastId}`),
                );

                if (typeof answer === 'string') {
                    return unavailable(answer);
                }

                bytes += answer.bytes;

                if (!Array.isArray(answer.body)) {
                    return unavailable('the indexer’s operation listing is not a list');
                }

                if (answer.body.length === 0) {
                    break;
                }

                for (const value of answer.body as unknown[]) {
                    const row = value as { id?: unknown; level?: unknown; messagesCount?: unknown } | null;

                    if (
                        row === null ||
                        typeof row !== 'object' ||
                        !isInteger(row.id) ||
                        !isInteger(row.level) ||
                        !isInteger(row.messagesCount) ||
                        (lastId !== null && row.id >= lastId) ||
                        row.level < fromLevel ||
                        row.level > toLevel
                    ) {
                        return unavailable('the indexer’s operation listing has a malformed row');
                    }

                    operations += 1;
                    lastId = row.id;
                    counts.set(row.level, (counts.get(row.level) ?? 0) + row.messagesCount);
                }
            }

            const candidates = [...counts]
                .map(([level, messagesCount]) => ({ level, messagesCount }))
                .sort((a, b) => b.messagesCount - a.messagesCount || b.level - a.level)
                .slice(0, SENDER_CANDIDATE_BUDGET);

            return { status: 'listed', candidates, operations, truncated, requests, bytes };
        },

        async candidateFrames(levels, query) {
            const wanted = [...new Set(levels)].sort((a, b) => a - b);

            if (wanted.length === 0) {
                return { status: 'read', levels: [], summaries: [], requests: 0, bytes: 0 };
            }

            const low = wanted[0];
            const high = wanted[wanted.length - 1];
            const summaries: CandidateSummary[] = [];
            let requests = 0;
            let bytes = 0;
            let lastId: number | null = null;
            const unavailable = (reason: string): CandidateFrames => ({
                status: 'unavailable',
                reason,
                requests,
                bytes,
            });

            for (;;) {
                requests += 1;

                const answer = await get(
                    `/v1/smart_rollups/inbox?type=external&level.in=${wanted.join(',')}` +
                        `&level.ge=${low}&level.le=${high}&select=id,level,payload&sort.asc=id&limit=${PAGE_LIMIT}` +
                        (lastId === null ? '' : `&id.gt=${lastId}`),
                );

                if (typeof answer === 'string') {
                    return unavailable(answer);
                }

                bytes += answer.bytes;

                if (!Array.isArray(answer.body)) {
                    return unavailable('the indexer’s inbox page is not a list');
                }

                if (answer.body.length === 0) {
                    break;
                }

                for (const value of answer.body as unknown[]) {
                    const row = value as { id?: unknown; level?: unknown; payload?: unknown } | null;

                    if (
                        row === null ||
                        typeof row !== 'object' ||
                        !isInteger(row.id) ||
                        !isInteger(row.level) ||
                        (lastId !== null && row.id <= lastId)
                    ) {
                        return unavailable('the indexer’s inbox page has a malformed row');
                    }

                    lastId = row.id;

                    const payload = typeof row.payload === 'string' ? base64Bytes(row.payload) : null;
                    let envelope: DecodedEnvelope | null;

                    try {
                        envelope = payload === null ? null : decodeExternalMessage(payload);
                    } catch {
                        envelope = null;
                    }

                    const message = envelope?.message;

                    if (
                        envelope &&
                        message?.kind === 'seed-batch' &&
                        envelope.tenantId === query.tenantId &&
                        envelope.poolId === query.poolId &&
                        message.startIndex <= query.seedIndex &&
                        query.seedIndex < message.startIndex + BigInt(message.hashes.length)
                    ) {
                        summaries.push({
                            level: row.level,
                            startIndex: message.startIndex,
                            count: message.hashes.length,
                        });
                    }
                }
            }

            return {
                status: 'read',
                levels: [...new Set(summaries.map((s) => s.level))].sort((a, b) => a - b),
                summaries,
                requests,
                bytes,
            };
        },
    };
}
