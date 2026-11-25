/**
 * Locating this rollup's frames by the indexer's inbox CONTENT.
 *
 * The indexer's external inbox rows carry each message's bytes (base64). The
 * locator pages through them chunk by chunk, keeps the levels whose messages
 * start with the rollup's external-message prefix and how many there are at
 * each, and drops the bytes. Nothing it returns carries a payload: the node is
 * the only source of judged messages, so the indexer's bytes choose levels and
 * nothing else.
 *
 * Fair use: one indexer request at a time, no parallel paging, request
 * starts at least {@link INDEXER_MIN_GAP_MS} apart, and large downloads only
 * with the reader's consent (the scanner asks). The public indexer publishes
 * no rate limit and sends no rate-limit headers, yet answers a quick run of
 * large pages with HTTP 429, so the pace is chosen here, conservatively: each
 * 429 doubles the gap for the rest of the run, up to
 * {@link INDEXER_MAX_GAP_MS}. The indexer is the reader's choice and can be
 * their own instance.
 */
import { hasExternalPrefix } from './inbox';
import { abortableSleep, type FetchLike, fetchRetrying, type Sleep } from './node-queue';

/** Levels in a run's first chunk, before any rate is known. */
export const PROBE_LEVELS = 200;

/** The size a chunk is aimed at, from the measured bytes per level. */
export const CHUNK_TARGET_BYTES = 4_000_000;

export const MIN_CHUNK_LEVELS = 50;
export const MAX_CHUNK_LEVELS = 20_000;

/**
 * A chunk is at most this many times the levels of the one before it, so a
 * quiet stretch cannot size one chunk across a burst the reader never saw.
 */
export const MAX_CHUNK_GROWTH = 4;

/**
 * The most rows asked for per page. A server may return fewer, so a short
 * page never ends a chunk: an empty page does, or a confirmed early end.
 */
export const PAGE_LIMIT = 10_000;

/** The fewest rows asked for per page, however large the rows seen so far. */
export const MIN_PAGE_ROWS = 500;

/** The least time between the starts of two indexer requests in a run, retries included. */
export const INDEXER_MIN_GAP_MS = 500;

/** The most an indexer 429 can stretch that gap to; each 429 doubles it. */
export const INDEXER_MAX_GAP_MS = 4_000;

/** Why a chunk could not be located. */
export type LocatorFailure = 'http-status' | 'network' | 'malformed-page' | 'id-not-ascending' | 'level-out-of-range';

/**
 * A chunk the indexer listed completely, every row valid: every page down to
 * an empty one, or, when its bytes reached the target first, every level
 * below the last row read, once the indexer confirmed it holds no further row
 * there (the chunk's `toLevel` then says where it ends).
 */
export interface LocatedChunk {
    status: 'located';
    fromLevel: number;
    toLevel: number;
    /** Prefixed messages per level; a level absent here holds none. */
    frameCountByLevel: Map<number, number>;
    /** Response text length, summed over the chunk's pages. */
    bytes: number;
    requests: number;
}

/** A chunk that was not located; whatever pages arrived are discarded. */
export interface UnreadChunk {
    status: 'unread';
    fromLevel: number;
    toLevel: number;
    reason: LocatorFailure;
    detail: string;
    bytes: number;
    requests: number;
}

export type ChunkResult = LocatedChunk | UnreadChunk;

/** What the scanner needs from an indexer; the shell passes {@link tzktInboxLocator}, a test a stub. */
export interface FrameLocator {
    /** The indexer's head level. */
    head(): Promise<number>;
    /**
     * Locate one inclusive level range, atomically. A located chunk may end
     * below `toLevel` (its own `toLevel` says where) when its bytes reached
     * the target first; the caller goes on from the level after it.
     */
    locateChunk(fromLevel: number, toLevel: number): Promise<ChunkResult>;
}

const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/**
 * Whether a base64 payload starts with the external-message prefix, judged on
 * the DECODED bytes (the first four characters give the first three bytes),
 * never on the text. Null when the payload is not strict base64.
 */
export function isFramePayload(payload: string): boolean | null {
    if (!BASE64.test(payload)) {
        return null;
    }

    if (payload.length === 0) {
        return false;
    }

    const head = atob(payload.slice(0, 4));

    return hasExternalPrefix(Array.from(head, (c) => c.charCodeAt(0)));
}

/**
 * The bytes-per-level rate, as an exponentially weighted mean over the chunks
 * located so far; it sizes the next chunk and projects a download's size.
 */
export class ByteRate {
    private value: number | null = null;
    private totalBytes = 0;
    private totalLevels = 0;
    private lastLevels: number | null = null;

    constructor(private readonly weight = 0.5) {}

    /** Bytes per level, weighted toward the latest chunks; null before the first chunk. Sizes chunks. */
    get bytesPerLevel(): number | null {
        return this.value;
    }

    /**
     * Bytes per level over every chunk seen; null before the first. Projects a
     * download: indexer traffic comes in bursts, and a projection from the
     * weighted rate swings with each one (measured on mainnet: a burst pushed
     * a 20,000-level projection from about 135 MB to 198 MB for a window that
     * came to 151 MB).
     */
    get meanBytesPerLevel(): number | null {
        return this.totalLevels > 0 ? this.totalBytes / this.totalLevels : null;
    }

    /** Levels observed so far. */
    get levelsSeen(): number {
        return this.totalLevels;
    }

    observe(bytes: number, levels: number): void {
        if (levels <= 0) {
            return;
        }

        const sample = bytes / levels;

        this.totalBytes += bytes;
        this.totalLevels += levels;
        this.lastLevels = levels;
        this.value = this.value === null ? sample : this.weight * sample + (1 - this.weight) * this.value;
    }

    /**
     * The next chunk's size: the probe before any rate is known, else the
     * target over the rate, clamped, and never more than
     * {@link MAX_CHUNK_GROWTH} times the last chunk.
     */
    chunkLevels(): number {
        if (this.value === null) {
            return PROBE_LEVELS;
        }

        const byRate = this.value <= 0 ? MAX_CHUNK_LEVELS : Math.floor(CHUNK_TARGET_BYTES / this.value);
        const grown = this.lastLevels === null ? MAX_CHUNK_LEVELS : this.lastLevels * MAX_CHUNK_GROWTH;

        return Math.min(MAX_CHUNK_LEVELS, Math.max(MIN_CHUNK_LEVELS, Math.min(grown, byRate)));
    }
}

/**
 * Walk `[fromLevel, toLevel]` in adaptive chunks, one indexer request at a
 * time, yielding each chunk's result as it lands. The caller sees every chunk
 * before the next is asked for, so it can stop (a declined download) between
 * any two.
 */
export async function* locateFrameLevels(
    locator: FrameLocator,
    fromLevel: number,
    toLevel: number,
    rate: ByteRate,
): AsyncGenerator<ChunkResult> {
    let next = fromLevel;

    while (next <= toLevel) {
        const end = Math.min(toLevel, next + rate.chunkLevels() - 1);
        const chunk = await locator.locateChunk(next, end);

        if (chunk.status === 'located') {
            rate.observe(chunk.bytes, chunk.toLevel - next + 1);
        }

        yield chunk;
        next = chunk.toLevel + 1;
    }
}

export interface TzktLocatorOptions {
    tzktApiUrl: string;
    signal?: AbortSignal;
    fetchImpl?: FetchLike;
    sleep?: Sleep;
    /** The clock the request gap is measured on; `Date.now` unless a test passes its own. */
    now?: () => number;
}

interface InboxRow {
    id: number;
    level: number;
    payload: string;
}

/**
 * The indexer's inbox through TzKT's `/v1/smart_rollups/inbox`, external rows
 * only. Every request this locator sends, from any of its calls, passes one
 * gate: its start waits until the gap since the last start is at least the
 * current gap, so one locator per run paces the whole run.
 */
export function tzktInboxLocator(options: TzktLocatorOptions): FrameLocator {
    const base = options.tzktApiUrl.trim().replace(/\/+$/, '');
    const doFetch = options.fetchImpl ?? fetch;
    const sleep = options.sleep ?? abortableSleep;
    const now = options.now ?? Date.now;
    let gapMs = INDEXER_MIN_GAP_MS;
    let lastStart: number | null = null;
    // Callers queue on this chain, so the gap holds even for concurrent calls.
    let turn: Promise<void> = Promise.resolve();
    // Runs before every attempt, retries included, and outside the attempt's
    // stall clock: waiting for a turn is not the indexer stalling.
    const gate = async (): Promise<void> => {
        const mine = turn.then(async () => {
            const wait = lastStart === null ? 0 : lastStart + gapMs - now();

            if (wait > 0) {
                await sleep(wait, options.signal);
            }

            lastStart = now();
        });

        turn = mine.catch(() => undefined);
        await mine;
    };
    const throttled: FetchLike = async (url, init) => {
        const response = await doFetch(url, init);

        if (response.status === 429) {
            gapMs = Math.min(INDEXER_MAX_GAP_MS, gapMs * 2);
        }

        return response;
    };
    const get = (url: string) =>
        fetchRetrying(url, { fetchImpl: throttled, signal: options.signal, sleep, beforeAttempt: gate });
    // The largest mean row size of any page so far in this run: it sets how
    // many rows a page asks for, so a page stays near the chunk target.
    let rowBytes: number | null = null;
    const pageRows = () =>
        rowBytes === null
            ? PAGE_LIMIT
            : Math.min(PAGE_LIMIT, Math.max(MIN_PAGE_ROWS, Math.floor(CHUNK_TARGET_BYTES / rowBytes)));

    return {
        async head() {
            const response = await get(`${base}/v1/head`);

            if (!response.ok) {
                throw new Error(`the indexer answered HTTP ${response.status} for its head`);
            }

            const body = (await response.json()) as { level?: unknown };

            if (typeof body.level !== 'number' || !Number.isSafeInteger(body.level)) {
                throw new Error('the indexer stated no head level');
            }

            return body.level;
        },

        async locateChunk(fromLevel, toLevel) {
            const frameCountByLevel = new Map<number, number>();
            let bytes = 0;
            let requests = 0;
            let lastId: number | null = null;
            let lastLevel: number | null = null;
            // Cleared once a confirmation finds a row the pages have not
            // reached yet: the rest of this chunk is then paged to its end.
            let mayEndEarly = true;
            const unread = (reason: LocatorFailure, detail: string): UnreadChunk => ({
                status: 'unread',
                fromLevel,
                toLevel,
                reason,
                detail,
                bytes,
                requests,
            });
            /** One request under the retry rule, its rows parsed: a list, or the chunk unread. */
            const fetchRows = async (url: string): Promise<unknown[] | UnreadChunk> => {
                let text: string;

                requests += 1;

                try {
                    const response = await get(url);

                    if (!response.ok) {
                        return unread('http-status', `the indexer answered HTTP ${response.status}`);
                    }

                    text = await response.text();
                } catch (error) {
                    if (options.signal?.aborted || !(error instanceof TypeError)) {
                        throw error;
                    }

                    return unread('network', error.message);
                }

                bytes += text.length;

                let page: unknown;

                try {
                    page = JSON.parse(text);
                } catch {
                    return unread('malformed-page', 'the page is not JSON');
                }

                if (!Array.isArray(page)) {
                    return unread('malformed-page', 'the page is not a list of rows');
                }

                if (page.length > 0) {
                    rowBytes = Math.max(rowBytes ?? 0, text.length / page.length);
                }

                return page as unknown[];
            };

            for (;;) {
                // Both level bounds on every page: an open-ended level filter
                // has timed out on the public instance.
                const page = await fetchRows(
                    `${base}/v1/smart_rollups/inbox?type=external&level.ge=${fromLevel}&level.le=${toLevel}` +
                        `&select=id,level,payload&sort.asc=id&limit=${pageRows()}` +
                        (lastId === null ? '' : `&id.gt=${lastId}`),
                );

                if (!Array.isArray(page)) {
                    return page;
                }

                if (page.length === 0) {
                    return { status: 'located', fromLevel, toLevel, frameCountByLevel, bytes, requests };
                }

                for (const value of page) {
                    const row = value as Partial<InboxRow> | null;

                    if (
                        typeof row !== 'object' ||
                        row === null ||
                        typeof row.id !== 'number' ||
                        !Number.isSafeInteger(row.id) ||
                        typeof row.level !== 'number' ||
                        !Number.isSafeInteger(row.level) ||
                        typeof row.payload !== 'string'
                    ) {
                        return unread('malformed-page', 'a row lacks an integer id, an integer level or a payload');
                    }

                    if (lastId !== null && row.id <= lastId) {
                        return unread('id-not-ascending', `row id ${row.id} follows id ${lastId}`);
                    }

                    if (row.level < fromLevel || row.level > toLevel) {
                        return unread('level-out-of-range', `row ${row.id} is at level ${row.level}`);
                    }

                    const frame = isFramePayload(row.payload);

                    if (frame === null) {
                        return unread('malformed-page', `row ${row.id}'s payload is not strict base64`);
                    }

                    if (frame) {
                        frameCountByLevel.set(row.level, (frameCountByLevel.get(row.level) ?? 0) + 1);
                    }

                    lastId = row.id;
                    lastLevel = row.level;
                }

                // Past the target, end the chunk below the last row's level
                // instead of paging on through a burst, once the indexer
                // CONFIRMS it holds no row in [fromLevel, lastLevel − 1] beyond
                // the last id read. That is the empty-page argument over the
                // shorter range, so the early end rests on no assumption
                // about how ids are ordered across levels. The next chunk is
                // sized from what this one measured, and the reader is asked
                // before it when the projection calls for it.
                if (
                    mayEndEarly &&
                    bytes >= CHUNK_TARGET_BYTES &&
                    lastId !== null &&
                    lastLevel !== null &&
                    lastLevel > fromLevel
                ) {
                    const end = lastLevel - 1;
                    const rest = await fetchRows(
                        `${base}/v1/smart_rollups/inbox?type=external&level.ge=${fromLevel}&level.le=${end}` +
                            `&id.gt=${lastId}&limit=1&select=id`,
                    );

                    if (!Array.isArray(rest)) {
                        return rest;
                    }

                    if (rest.length === 0) {
                        for (const level of frameCountByLevel.keys()) {
                            if (level > end) {
                                frameCountByLevel.delete(level);
                            }
                        }

                        return { status: 'located', fromLevel, toLevel: end, frameCountByLevel, bytes, requests };
                    }

                    mayEndEarly = false;
                }
            }
        },
    };
}
