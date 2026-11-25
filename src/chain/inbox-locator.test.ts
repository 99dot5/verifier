// @vitest-environment node
// The content locator: real base64 text pages, served the way the
// public indexer serves them.
//
// The capture below was read on 2026-11-24 from the public endpoints named in
// its `evidence`. At every one of its levels the node's messages, in order,
// equal the indexer's decoded payloads, and the node's applied prefixed count
// is recorded beside them; U-L7 holds the locator to those counts.
import { EXTERNAL_MESSAGE_PREFIX } from '@99dot5/round-replay';
import { describe, expect, it } from 'vitest';
import {
    ByteRate,
    type ChunkResult,
    CHUNK_TARGET_BYTES,
    type FrameLocator,
    INDEXER_MAX_GAP_MS,
    INDEXER_MIN_GAP_MS,
    isFramePayload,
    locateFrameLevels,
    MAX_CHUNK_GROWTH,
    MAX_CHUNK_LEVELS,
    MIN_CHUNK_LEVELS,
    PAGE_LIMIT,
    PROBE_LEVELS,
    tzktInboxLocator,
} from './inbox-locator';
import type { FetchLike } from './node-queue';
import capture from './testdata/shadownet-inbox-capture.json';

/** These build megabytes of real indexer pages; a loaded CI runner must not time them out. */
const HEAVY = { timeout: 20_000 };

const TZKT = 'https://indexer.test';
const noSleep = async () => undefined;

interface Row {
    id: number;
    level: number;
    payload: string;
}

const b64 = (bytes: number[]) => btoa(String.fromCharCode(...bytes));
/** A message with this rollup's prefix, `size` bytes long. */
const frame = (size = 8) => b64([...EXTERNAL_MESSAGE_PREFIX, ...new Array<number>(Math.max(0, size - 2)).fill(7)]);
/** Another rollup's message. */
const noise = (size = 8) => b64(new Array<number>(size).fill(1));

/**
 * The indexer's `/v1/smart_rollups/inbox` over `rows`: both level bounds, the
 * `id.gt` cursor, ascending ids, and a page cap the server may set below the
 * requested limit. `answers` overrides a request (by index) with a status or
 * a network failure.
 */
function indexer(
    rows: Row[],
    options: { pageCap?: number; answers?: Record<number, number | 'network'> } = {},
): { fetchImpl: FetchLike; urls: string[] } {
    const urls: string[] = [];
    const fetchImpl: FetchLike = async (url) => {
        urls.push(url);

        const answer = options.answers?.[urls.length - 1];

        if (answer === 'network') {
            throw new TypeError('Failed to fetch');
        }

        if (answer !== undefined) {
            return new Response('busy', { status: answer });
        }

        const query = new URL(url).searchParams;
        const ge = Number(query.get('level.ge'));
        const le = Number(query.get('level.le'));
        const after = Number(query.get('id.gt') ?? 0);
        const limit = Math.min(Number(query.get('limit')), options.pageCap ?? Number.POSITIVE_INFINITY);
        const page = rows
            .filter((r) => r.level >= ge && r.level <= le && r.id > after)
            .sort((a, b) => a.id - b.id)
            .slice(0, limit);

        return new Response(JSON.stringify(page), { status: 200 });
    };

    return { fetchImpl, urls };
}

const located = (result: ChunkResult) => {
    if (result.status !== 'located') {
        throw new Error(`expected a located chunk, got ${result.reason}: ${result.detail}`);
    }

    return result;
};

describe('locating frames by the indexer inbox content', () => {
    it('U-L1: pages by id cursor over 25,001 rows and ends only on an empty page', async () => {
        const rows = Array.from({ length: 25_001 }, (_, i) => ({
            id: 1_000 + i,
            level: 1 + Math.floor(i / 5),
            payload: i % 1_000 === 0 ? frame() : noise(),
        }));
        const { fetchImpl, urls } = indexer(rows);
        const chunk = located(
            await tzktInboxLocator({ tzktApiUrl: TZKT, fetchImpl, sleep: noSleep }).locateChunk(1, 5_001),
        );

        expect(urls).toHaveLength(4);
        expect(urls[0]).toContain(`limit=${PAGE_LIMIT}`);
        expect(urls[0]).toContain('level.ge=1&level.le=5001');
        expect(urls[0]).not.toContain('id.gt');
        expect(urls[1]).toContain(`id.gt=${1_000 + PAGE_LIMIT - 1}`);
        expect([...chunk.frameCountByLevel.values()].reduce((a, b) => a + b, 0)).toBe(26);
        expect(chunk.requests).toBe(4);
    });

    it('U-L2: a server capping pages at 1,000 under limit=10000 still reads to the end', async () => {
        const rows = Array.from({ length: 2_500 }, (_, i) => ({
            id: i + 1,
            level: 10 + i,
            payload: i === 2_499 ? frame() : noise(),
        }));
        const { fetchImpl, urls } = indexer(rows, { pageCap: 1_000 });
        const chunk = located(
            await tzktInboxLocator({ tzktApiUrl: TZKT, fetchImpl, sleep: noSleep }).locateChunk(10, 2_509),
        );

        // 1,000 + 1,000 + 500 rows, then the empty page: a short page is not the end.
        expect(urls).toHaveLength(4);
        expect([...chunk.frameCountByLevel]).toEqual([[2_509, 1]]);
    });

    it('U-L3: retries per the rule; an exhausted chunk is unread and its partial pages are discarded', async () => {
        const rows = Array.from({ length: 30 }, (_, i) => ({ id: i + 1, level: 100 + i, payload: frame() }));
        // Page one lands, then the second request fails five times.
        const failing = indexer(rows, { pageCap: 10, answers: { 1: 503, 2: 503, 3: 503, 4: 503, 5: 503 } });
        const unread = await tzktInboxLocator({
            tzktApiUrl: TZKT,
            fetchImpl: failing.fetchImpl,
            sleep: noSleep,
        }).locateChunk(100, 129);

        expect(unread).toMatchObject({ status: 'unread', reason: 'http-status', fromLevel: 100, toLevel: 129 });
        expect('frameCountByLevel' in unread).toBe(false);
        expect(failing.urls).toHaveLength(6);

        const throttled = indexer(rows, { answers: { 0: 429, 1: 429 } });
        const chunk = located(
            await tzktInboxLocator({ tzktApiUrl: TZKT, fetchImpl: throttled.fetchImpl, sleep: noSleep }).locateChunk(
                100,
                129,
            ),
        );

        expect(chunk.frameCountByLevel.size).toBe(30);

        const offline = indexer(rows, {
            answers: { 0: 'network', 1: 'network', 2: 'network', 3: 'network', 4: 'network' },
        });

        expect(
            await tzktInboxLocator({ tzktApiUrl: TZKT, fetchImpl: offline.fetchImpl, sleep: noSleep }).locateChunk(
                100,
                129,
            ),
        ).toMatchObject({ status: 'unread', reason: 'network' });
        expect(offline.urls).toHaveLength(5);
    });

    it('U-L4: the prefix is tested on the decoded bytes, never on the text', async () => {
        // In the capture, frames read `CZV…`, `CZW…` and `CZX…`: the third
        // character also carries bits of the third byte, so a text compare on
        // one three-letter prefix would miss real frames.
        const captured = capture.rows.filter((r) => isFramePayload(r.payload)).map((r) => r.payload.slice(0, 3));

        expect(new Set(captured)).toEqual(new Set(['CZV', 'CZW', 'CZX']));
        expect(frame().startsWith('CZU')).toBe(true);
        expect(isFramePayload(frame())).toBe(true);
        expect(isFramePayload(b64([0x09, 0x95, 0xaf]))).toBe(true);
        expect(b64([0x09, 0x95, 0xaf]).startsWith('CZW')).toBe(true);
        // Byte 1 differs (0x96): `CZY…`.
        expect(isFramePayload(b64([0x09, 0x96, 0x00]))).toBe(false);
        // A one-byte message, and an empty one.
        expect(isFramePayload(b64([0x09]))).toBe(false);
        expect(isFramePayload('')).toBe(false);
        // Not strict base64.
        expect(isFramePayload('CZX*')).toBeNull();
        expect(isFramePayload('CZX')).toBeNull();

        const { fetchImpl } = indexer([
            { id: 1, level: 5, payload: frame() },
            { id: 2, level: 5, payload: 'not base64!' },
        ]);

        expect(await tzktInboxLocator({ tzktApiUrl: TZKT, fetchImpl, sleep: noSleep }).locateChunk(5, 5)).toMatchObject(
            {
                status: 'unread',
                reason: 'malformed-page',
            },
        );
    });

    it('U-L4b: rows out of order or outside the chunk make it unread', async () => {
        const outOfOrder: FetchLike = async (url) =>
            new Response(
                new URL(url).searchParams.get('id.gt')
                    ? '[]'
                    : JSON.stringify([
                          { id: 2, level: 5, payload: noise() },
                          { id: 1, level: 5, payload: noise() },
                      ]),
            );
        const outside = indexer([{ id: 1, level: 9, payload: noise() }]);

        expect(
            await tzktInboxLocator({ tzktApiUrl: TZKT, fetchImpl: outOfOrder, sleep: noSleep }).locateChunk(5, 5),
        ).toMatchObject({
            status: 'unread',
            reason: 'id-not-ascending',
        });
        // A server ignoring the level filter.
        const ignoring: FetchLike = async (url) =>
            outside.fetchImpl(url.replace('level.ge=5&level.le=5', 'level.ge=0&level.le=99'));

        expect(
            await tzktInboxLocator({ tzktApiUrl: TZKT, fetchImpl: ignoring, sleep: noSleep }).locateChunk(5, 5),
        ).toMatchObject({
            status: 'unread',
            reason: 'level-out-of-range',
        });
    });

    describe('U-L8: a chunk past the target ends early only once the indexer confirms it', HEAVY, () => {
        /** A large message (45,000 bytes is about 60 KB of base64), with or without the prefix. */
        const large = (prefixed: boolean, size = 45_000) => {
            const bytes = new Array<number>(size).fill(7);

            if (prefixed) {
                bytes.splice(0, EXTERNAL_MESSAGE_PREFIX.length, ...EXTERNAL_MESSAGE_PREFIX);
            }

            let text = '';

            for (const byte of bytes) {
                text += String.fromCharCode(byte);
            }

            return btoa(text);
        };
        const FRAME = large(true);
        const NOISE = large(false);

        /** Walk `[from, to]` the way the scanner does; every chunk must be located and they must tile the range. */
        async function walk(rows: Row[], from: number, to: number, options: Parameters<typeof indexer>[1] = {}) {
            const { fetchImpl, urls } = indexer(rows, options);
            const locator = tzktInboxLocator({ tzktApiUrl: TZKT, fetchImpl, sleep: noSleep });
            const counts = new Map<number, number>();
            const spans: [number, number][] = [];
            let next = from;

            for await (const result of locateFrameLevels(locator, from, to, new ByteRate())) {
                const chunk = located(result);

                expect(chunk.fromLevel).toBe(next);
                next = chunk.toLevel + 1;
                spans.push([chunk.fromLevel, chunk.toLevel]);

                for (const [level, count] of chunk.frameCountByLevel) {
                    counts.set(level, (counts.get(level) ?? 0) + count);
                }
            }

            expect(next).toBe(to + 1);

            return { counts, spans, urls };
        }

        const isConfirmation = (url: string) => url.endsWith('&limit=1&select=id');

        it('counts frames on levels split across page boundaries exactly once', async () => {
            // Ten rows of about 6 KB a level, frames among them, and pages of
            // seven rows, so every page boundary splits a level.
            const frame6k = large(true, 4_500);
            const noise6k = large(false, 4_500);
            const rows: Row[] = [];
            const expected = new Map<number, number>();

            for (let level = 1; level <= 400; level++) {
                for (let k = 0; k < 10; k++) {
                    const frame = k % 3 === 0 || k === 9;

                    rows.push({ id: rows.length + 1, level, payload: frame ? frame6k : noise6k });

                    if (frame) {
                        expected.set(level, (expected.get(level) ?? 0) + 1);
                    }
                }
            }

            const { counts, spans, urls } = await walk(rows, 1, 400, { pageCap: 7 });

            expect(spans.some(([from, to]) => to - from + 1 < PROBE_LEVELS && to !== 400)).toBe(true);
            expect(counts).toEqual(expected);

            // The confirmation names both level bounds and the cursor, and asks for one id only.
            const confirmation = new URL(urls.find(isConfirmation) ?? '');

            expect(confirmation.pathname).toBe('/v1/smart_rollups/inbox');
            expect(confirmation.searchParams.get('type')).toBe('external');
            expect(confirmation.searchParams.get('level.ge')).toBe(String(spans[0][0]));
            expect(confirmation.searchParams.get('level.le')).toBe(String(spans[0][1]));
            expect(Number(confirmation.searchParams.get('id.gt'))).toBeGreaterThan(0);
            expect(confirmation.searchParams.get('limit')).toBe('1');
            expect(confirmation.searchParams.get('select')).toBe('id');
        });

        it('counts a late-numbered row for an early level: the confirmation finds it and the chunk pages on', async () => {
            const rows: Row[] = [];

            for (let level = 1; level <= 200; level++) {
                for (let k = 0; k < 3; k++) {
                    rows.push({ id: rows.length + 1, level, payload: NOISE });
                }
            }

            // Ids out of level order: the highest id belongs to level 5.
            rows.push({ id: rows.length + 1, level: 5, payload: FRAME });

            const { counts, spans, urls } = await walk(rows, 1, 200, { pageCap: 50 });

            expect(counts.get(5)).toBe(1);
            expect(spans).toEqual([[1, 200]]);
            expect(urls.filter(isConfirmation)).toHaveLength(1);
        });

        it('a confirmation that fails leaves the chunk unread, never empty', async () => {
            const rows: Row[] = Array.from({ length: 600 }, (_, i) => ({
                id: i + 1,
                level: 1 + Math.floor(i / 3),
                payload: NOISE,
            }));
            const { fetchImpl } = indexer(rows, { pageCap: 50 });
            const failing: FetchLike = async (url) =>
                isConfirmation(url) ? new Response('busy', { status: 503 }) : fetchImpl(url);
            const chunk = await tzktInboxLocator({ tzktApiUrl: TZKT, fetchImpl: failing, sleep: noSleep }).locateChunk(
                1,
                200,
            );

            expect(chunk).toMatchObject({ status: 'unread', reason: 'http-status' });
        });
    });

    it('U-L5: over 100k noise rows only the frame levels and their counts are kept', async () => {
        const frameLevels = new Map([
            [17, 2],
            [40_000, 1],
            [99_999, 3],
        ]);
        const rows: Row[] = [];

        for (let level = 1; level <= 100_000; level++) {
            rows.push({ id: rows.length + 1, level, payload: noise(4) });

            for (let k = 0; k < (frameLevels.get(level) ?? 0); k++) {
                rows.push({ id: rows.length + 1, level, payload: frame() });
            }
        }

        const { fetchImpl } = indexer(rows);
        const locator = tzktInboxLocator({ tzktApiUrl: TZKT, fetchImpl, sleep: noSleep });
        const retained = new Map<number, number>();
        let next = 1;

        for await (const result of locateFrameLevels(locator, 1, 100_000, new ByteRate())) {
            const chunk = located(result);

            // Chunks tile the range with no gap, whether they end early or not.
            expect(chunk.fromLevel).toBe(next);
            next = chunk.toLevel + 1;

            for (const [level, count] of chunk.frameCountByLevel) {
                retained.set(level, (retained.get(level) ?? 0) + count);
            }

            // The only thing a located chunk carries per level is a count.
            // @ts-expect-error A chunk carries no payloads: indexer bytes never leave the locator.
            expect(chunk.payloads).toBeUndefined();
        }

        expect(next).toBe(100_001);
        expect(retained).toEqual(frameLevels);
    });

    it('U-L6: sizes chunks from the measured rate, a 200-level probe first', async () => {
        for (const [bytesPerLevel, expected] of [
            [8_800, Math.floor(CHUNK_TARGET_BYTES / 8_800)],
            [1_335, Math.floor(CHUNK_TARGET_BYTES / 1_335)],
        ] as const) {
            const asked: [number, number][] = [];
            const stub: FrameLocator = {
                head: async () => 0,
                locateChunk: async (fromLevel, toLevel) => {
                    asked.push([fromLevel, toLevel]);

                    return {
                        status: 'located',
                        fromLevel,
                        toLevel,
                        frameCountByLevel: new Map(),
                        bytes: (toLevel - fromLevel + 1) * bytesPerLevel,
                        requests: 1,
                    };
                },
            };
            const rate = new ByteRate();

            for await (const chunk of locateFrameLevels(stub, 1, 10_000, rate)) {
                expect(chunk.status).toBe('located');
            }

            const sizes = asked.map(([from, to]) => to - from + 1);

            expect(asked[0]).toEqual([1, PROBE_LEVELS]);
            // The rate's size, reached by steps of at most MAX_CHUNK_GROWTH.
            expect(sizes[1]).toBe(Math.min(expected, PROBE_LEVELS * MAX_CHUNK_GROWTH));
            expect(sizes.slice(1, -1).every((size, i) => size <= sizes[i] * MAX_CHUNK_GROWTH)).toBe(true);
            expect(Math.max(...sizes.slice(0, -1))).toBe(expected);
            expect(asked[asked.length - 1][1]).toBe(10_000);
            expect(rate.bytesPerLevel).toBeCloseTo(bytesPerLevel);
        }

        const huge = new ByteRate();
        const tiny = new ByteRate();

        huge.observe(10_000_000, 1);
        tiny.observe(1, 10_000);
        expect(huge.chunkLevels()).toBe(MIN_CHUNK_LEVELS);
        expect(tiny.chunkLevels()).toBe(MAX_CHUNK_LEVELS);

        // A quiet chunk cannot be followed by a jump to the largest size.
        const quiet = new ByteRate();

        quiet.observe(PROBE_LEVELS * 100, PROBE_LEVELS);
        expect(quiet.chunkLevels()).toBe(PROBE_LEVELS * MAX_CHUNK_GROWTH);
    });

    it("U-L7: the shadownet capture's frame levels and counts equal the node's applied prefixed counts", async () => {
        const { fetchImpl, urls } = indexer(capture.rows);
        const chunk = located(
            await tzktInboxLocator({
                tzktApiUrl: 'https://api.shadownet.tzkt.io',
                fetchImpl,
                sleep: noSleep,
            }).locateChunk(capture.fromLevel, capture.toLevel),
        );
        const nodeCounts = new Map(
            Object.entries(capture.nodeAppliedPrefixedCount)
                .map(([level, count]) => [Number(level), count] as const)
                .filter(([, count]) => count > 0),
        );

        expect(urls[0]).toBe(
            'https://api.shadownet.tzkt.io/v1/smart_rollups/inbox?type=external&level.ge=6027992&level.le=6027996' +
                '&select=id,level,payload&sort.asc=id&limit=10000',
        );
        expect(capture.evidence[0]).toContain(
            'smart_rollups/inbox?type=external&level.ge=6027992&level.le=6027996&select=id,level,payload',
        );
        expect(chunk.frameCountByLevel).toEqual(nodeCounts);
        expect(chunk.frameCountByLevel.get(6_027_994)).toBe(10);
        expect(capture.rows.filter((r) => r.level === 6_027_994)).toHaveLength(14);
    });
});

describe('pacing the indexer', () => {
    /** A clock that moves only when the locator sleeps, and the start time of every request. */
    function pacedClock() {
        let clock = 0;
        const starts: number[] = [];

        return {
            starts,
            now: () => clock,
            sleep: async (ms: number) => {
                clock += ms;
            },
            stamp: () => starts.push(clock),
        };
    }

    const gaps = (starts: number[]) => starts.slice(1).map((start, i) => start - starts[i]);

    it('starts indexer requests at least 500 ms apart across head, pages and the early-end query', async () => {
        expect(INDEXER_MIN_GAP_MS).toBe(500);

        // Rows large enough that a chunk reaches the byte target and confirms its early end.
        const rows = Array.from({ length: 1_200 }, (_, i) => ({
            id: i + 1,
            level: 1 + Math.floor(i / 2),
            payload: noise(6_000),
        }));
        const clock = pacedClock();
        const { fetchImpl, urls } = indexer(rows, { pageCap: 400 });
        const locator = tzktInboxLocator({
            tzktApiUrl: TZKT,
            fetchImpl: async (url, init) => {
                clock.stamp();

                return url.endsWith('/v1/head') ? new Response('{"level":600}') : fetchImpl(url, init);
            },
            sleep: clock.sleep,
            now: clock.now,
        });

        expect(await locator.head()).toBe(600);
        located(await locator.locateChunk(1, 600));
        expect(await locator.head()).toBe(600);

        expect(urls.some((url) => url.includes('&limit=1&select=id'))).toBe(true);
        expect(clock.starts.length).toBeGreaterThan(4);
        expect(gaps(clock.starts).every((gap) => gap === INDEXER_MIN_GAP_MS)).toBe(true);
    });

    it('doubles the gap after each 429 for the rest of the run, up to 4 s, and still backs off per the retry rule', async () => {
        expect(INDEXER_MAX_GAP_MS).toBe(4_000);

        const answers = [200, 200, 429, 200, 200, 429, 429, 429, 200, 200, 200];
        const clock = pacedClock();
        const locator = tzktInboxLocator({
            tzktApiUrl: TZKT,
            fetchImpl: async () => {
                const status = answers[clock.starts.length];

                clock.stamp();

                return status === 200 ? new Response('{"level":9}') : new Response('busy', { status });
            },
            sleep: clock.sleep,
            now: clock.now,
        });

        for (let i = 0; i < 7; i++) {
            expect(await locator.head()).toBe(9);
        }

        expect(clock.starts).toHaveLength(answers.length);
        // 500 ms; then a 429 (gap 1 s) and its 2 s back-off; 1 s; three 429s in
        // one request (gap 2, 4, then 4 s capped) under back-offs of 2, 4 and
        // 8 s; then 4 s for good.
        expect(gaps(clock.starts)).toEqual([500, 500, 2_000, 1_000, 1_000, 2_000, 4_000, 8_000, 4_000, 4_000]);
    });
});
