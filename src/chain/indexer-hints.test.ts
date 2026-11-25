// @vitest-environment node
// The indexer reads that only choose where a located run looks,
// against a stub serving TzKT's response shapes: a bare level list for the
// block-at-time listing, a bare number for the block-by-timestamp route,
// `{id, level, messagesCount}` rows for the sender listing and base64
// payload rows for the inbox.
import * as ed from '@noble/ed25519';
import { blake2b } from '@noble/hashes/blake2.js';
import { describe, expect, it } from 'vitest';
import { sequencerSigningPreimage, type SigningDomain } from '../wire/signature';
import type { InboxMessage } from './inbox';
import {
    type CandidateQuery,
    SENDER_CANDIDATE_BUDGET,
    SENDER_LISTING_MAX_PAGES,
    tzktIndexerHints,
} from './indexer-hints';
import type { FetchLike } from './node-queue';

const BASE = 'https://indexer.test';
const DOMAIN: SigningDomain = { chainId: 'NetXsqzbfFenSTS', rollupAddress: 'sr1TMxAUtDA4sDL7C4r39L18iQjhRcBRzd8a' };
const SENDER = 'tz1crXV6x6jRJLnR5uTfhuQrqxSo7wQajQJh';
const noSleep = async () => undefined;

const u32 = (v: number) => [v & 0xff, (v >> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff];
const u64 = (v: bigint) => Array.from({ length: 8 }, (_, i) => Number((v >> BigInt(8 * i)) & 0xffn));

function str(v: string): number[] {
    const bytes = Array.from(new TextEncoder().encode(v));

    return [...u32(bytes.length), ...bytes];
}

/** A signed SeedBatch frame's bytes, base64 as TzKT serves a payload. */
function batchPayload(start: bigint, tenant = 'test-tenant', pool = 'standard'): string {
    const payload = new Uint8Array([
        0,
        ...str(tenant),
        ...str(pool),
        0x00,
        ...u64(start),
        ...u32(50),
        ...new Array<number>(50 * 32).fill(3),
        ...u64(1n),
        ...new Array<number>(32).fill(7),
    ]);
    const signature = ed.sign(
        blake2b(sequencerSigningPreimage(DOMAIN, payload), { dkLen: 32 }),
        new Uint8Array(32).fill(1),
    );

    return Buffer.from([0x09, 0x95, ...signature, ...payload]).toString('base64');
}

interface Route {
    match: (url: URL) => boolean;
    answer: (url: URL) => Response;
}

function stub(routes: Route[]) {
    const requests: URL[] = [];
    /** Response text length of every answer, in order. */
    const bodies: number[] = [];
    const fetchImpl: FetchLike = async (raw) => {
        const url = new URL(raw);

        requests.push(url);

        const route = routes.find((r) => r.match(url));
        const response = route ? route.answer(url) : new Response('not found', { status: 404 });

        bodies.push((await response.clone().text()).length);

        return response;
    };

    return { fetchImpl, requests, bodies };
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
const blocksListing = (url: URL) => url.pathname === '/v1/blocks';
const blockByTime = (url: URL) => /^\/v1\/blocks\/[^/]+\/level$/.test(url.pathname);
const ISO = '2026-11-22T12:00:05.123Z';
const MS = Date.parse(ISO);

describe('levelAtTime', () => {
    it('asks once, bounded by both levels, newest first, and reads the bare level list', async () => {
        const { fetchImpl, requests } = stub([{ match: blocksListing, answer: () => json([15_924_940]) }]);
        const hints = tzktIndexerHints({ tzktApiUrl: `${BASE}/`, fetchImpl, sleep: noSleep });

        expect(await hints.levelAtTime(MS, { minLevel: 15_815_593, maxLevel: 15_953_900 })).toEqual({
            status: 'found',
            level: 15_924_940,
        });
        expect(requests).toHaveLength(1);
        expect(Object.fromEntries(requests[0].searchParams)).toEqual({
            'timestamp.le': ISO,
            'level.ge': '15815593',
            'level.le': '15953900',
            'sort.desc': 'level',
            limit: '1',
            select: 'level',
        });
    });

    it('an empty listing is no level, and the fallback is not asked', async () => {
        const { fetchImpl, requests } = stub([{ match: blocksListing, answer: () => json([]) }]);
        const result = await tzktIndexerHints({ tzktApiUrl: BASE, fetchImpl }).levelAtTime(MS, {
            minLevel: 10,
            maxLevel: 20,
        });

        expect(result.status).toBe('not-found');
        expect(requests).toHaveLength(1);
    });

    it('after the listing fails under the retry rule, the block-by-timestamp route answers, clamped to the range', async () => {
        const { fetchImpl, requests } = stub([
            { match: blocksListing, answer: () => new Response('down', { status: 503 }) },
            { match: blockByTime, answer: () => json(15_953_950) },
        ]);
        const hints = tzktIndexerHints({ tzktApiUrl: BASE, fetchImpl, sleep: noSleep });

        expect(await hints.levelAtTime(MS, { minLevel: 15_815_593, maxLevel: 15_953_900 })).toEqual({
            status: 'found',
            level: 15_953_900,
        });
        // Five attempts at the listing, then the fallback.
        expect(requests.filter(blocksListing)).toHaveLength(5);
        expect(requests.at(-1)?.pathname).toBe(`/v1/blocks/${ISO}/level`);
    });

    it('a listing that answers a level outside the bounds it was asked for places nothing', async () => {
        for (const answered of [9, 21]) {
            const { fetchImpl, requests } = stub([{ match: blocksListing, answer: () => json([answered]) }]);
            const result = await tzktIndexerHints({ tzktApiUrl: BASE, fetchImpl }).levelAtTime(MS, {
                minLevel: 10,
                maxLevel: 20,
            });

            expect(result).toMatchObject({ status: 'not-found', reason: expect.stringContaining(`level ${answered}`) });
            expect(requests).toHaveLength(1);
        }
    });

    it('a fallback level below the range, or a second failure, is no level', async () => {
        const below = stub([
            { match: blocksListing, answer: () => new Response('bad', { status: 400 }) },
            { match: blockByTime, answer: () => json(5) },
        ]);
        const both = stub([{ match: blocksListing, answer: () => new Response('bad', { status: 500 }) }]);

        expect(
            (
                await tzktIndexerHints({ tzktApiUrl: BASE, fetchImpl: below.fetchImpl }).levelAtTime(MS, {
                    minLevel: 10,
                    maxLevel: 20,
                })
            ).status,
        ).toBe('not-found');

        const result = await tzktIndexerHints({
            tzktApiUrl: BASE,
            fetchImpl: both.fetchImpl,
            sleep: noSleep,
        }).levelAtTime(MS, {
            minLevel: 10,
            maxLevel: 20,
        });

        expect(result).toMatchObject({ status: 'not-found', reason: expect.stringContaining('HTTP 500') });
    });

    it('an abort propagates', async () => {
        const controller = new AbortController();
        const fetchImpl: FetchLike = async () => {
            controller.abort();

            throw new DOMException('aborted', 'AbortError');
        };

        await expect(
            tzktIndexerHints({ tzktApiUrl: BASE, fetchImpl, signal: controller.signal }).levelAtTime(MS, {
                minLevel: 1,
                maxLevel: 2,
            }),
        ).rejects.toMatchObject({ name: 'AbortError' });
    });
});

describe('senderOpLevels', () => {
    /** Operations of one sender, newest id last; the server returns at most `cap` rows a page. */
    function listing(rows: { level: number; messagesCount: number }[], cap = 3): Route {
        const withIds = rows.map((r, i) => ({ id: 1_000 + i, ...r }));

        return {
            match: (url) => url.pathname === '/v1/operations/sr_add_messages',
            answer: (url) => {
                const below = Number(url.searchParams.get('id.lt') ?? Infinity);
                const limit = Number(url.searchParams.get('limit'));

                return json(
                    withIds
                        .filter((r) => r.id < below)
                        .sort((a, b) => b.id - a.id)
                        .slice(0, Math.min(limit, cap)),
                );
            },
        };
    }

    it('pages down to an empty page and orders bursts first, then the latest level', async () => {
        const { fetchImpl, requests, bodies } = stub([
            listing([
                { level: 100, messagesCount: 1 },
                { level: 200, messagesCount: 10 },
                { level: 300, messagesCount: 1 },
                { level: 300, messagesCount: 2 },
                { level: 400, messagesCount: 1 },
                { level: 500, messagesCount: 10 },
                { level: 600, messagesCount: 1 },
            ]),
        ]);
        const result = await tzktIndexerHints({ tzktApiUrl: BASE, fetchImpl }).senderOpLevels([SENDER], 50, 999);

        expect(result).toEqual({
            status: 'listed',
            candidates: [
                { level: 500, messagesCount: 10 },
                { level: 200, messagesCount: 10 },
                { level: 300, messagesCount: 3 },
                { level: 600, messagesCount: 1 },
                { level: 400, messagesCount: 1 },
                { level: 100, messagesCount: 1 },
            ],
            operations: 7,
            truncated: false,
            requests: 4,
            bytes: bodies.reduce((sum, b) => sum + b, 0),
        });
        expect(bodies.every((b) => b > 0)).toBe(true);
        expect(Object.fromEntries(requests[0].searchParams)).toEqual({
            sender: SENDER,
            status: 'applied',
            'level.ge': '50',
            'level.le': '999',
            select: 'id,level,messagesCount',
            'sort.desc': 'id',
            limit: '10000',
        });
        expect(requests.slice(1).map((r) => r.searchParams.get('id.lt'))).toEqual(['1004', '1001', '1000']);
    });

    it('lists several senders with sender.in, and keeps at most the budget', async () => {
        const rows = Array.from({ length: SENDER_CANDIDATE_BUDGET + 50 }, (_, i) => ({
            level: 1_000 + i,
            messagesCount: 1,
        }));
        const { fetchImpl, requests } = stub([listing(rows, 10_000)]);
        const result = await tzktIndexerHints({ tzktApiUrl: BASE, fetchImpl }).senderOpLevels(
            [SENDER, 'tz1other', SENDER],
            1,
            5_000,
        );

        expect(requests[0].searchParams.get('sender.in')).toBe(`${SENDER},tz1other`);
        expect(result.status === 'listed' && result.candidates.length).toBe(SENDER_CANDIDATE_BUDGET);
        expect(result.status === 'listed' && result.candidates[0].level).toBe(1_249);
    });

    it('stops at the page cap, newest operations first, and keeps the candidates read so far', async () => {
        const rows = Array.from({ length: 2 * SENDER_LISTING_MAX_PAGES + 5 }, (_, i) => ({
            level: 1_000 + i,
            messagesCount: 1,
        }));
        const { fetchImpl, requests, bodies } = stub([listing(rows, 2)]);
        const result = await tzktIndexerHints({ tzktApiUrl: BASE, fetchImpl }).senderOpLevels([SENDER], 1, 5_000);

        expect(requests).toHaveLength(SENDER_LISTING_MAX_PAGES);
        expect(result).toMatchObject({
            status: 'listed',
            operations: 2 * SENDER_LISTING_MAX_PAGES,
            truncated: true,
            requests: SENDER_LISTING_MAX_PAGES,
            bytes: bodies.reduce((sum, b) => sum + b, 0),
        });
        // The five oldest operations were not read.
        expect(result.status === 'listed' && Math.min(...result.candidates.map((c) => c.level))).toBe(1_005);
    });

    it('a 404 or a malformed row leaves no listing', async () => {
        const missing = stub([]);
        const malformed = stub([{ match: () => true, answer: () => json([{ id: 1, level: 'x', messagesCount: 1 }]) }]);

        expect(
            (await tzktIndexerHints({ tzktApiUrl: BASE, fetchImpl: missing.fetchImpl }).senderOpLevels([SENDER], 1, 9))
                .status,
        ).toBe('unavailable');
        expect(
            (
                await tzktIndexerHints({ tzktApiUrl: BASE, fetchImpl: malformed.fetchImpl }).senderOpLevels(
                    [SENDER],
                    1,
                    9,
                )
            ).status,
        ).toBe('unavailable');
    });
});

describe('candidateFrames', () => {
    const QUERY: CandidateQuery = { tenantId: 'test-tenant', poolId: 'standard', seedIndex: 2_007n };
    const rows = [
        // Another rollup's message and an undecodable payload.
        { id: 1, level: 6_027_994, payload: Buffer.from([0x00, 0x27, 0xb7, 0xe1]).toString('base64') },
        { id: 2, level: 6_027_994, payload: '!!not base64!!' },
        // Ten siblings; one covers the index.
        ...Array.from({ length: 10 }, (_, i) => ({
            id: 3 + i,
            level: 6_027_994,
            payload: batchPayload(1_750n + BigInt(50 * i)),
        })),
        { id: 20, level: 6_030_000, payload: batchPayload(2_000n, 'other-tenant') },
        { id: 21, level: 6_031_000, payload: batchPayload(2_000n, 'test-tenant', 'high-roller') },
        { id: 22, level: 6_032_000, payload: batchPayload(2_050n) },
        { id: 23, level: 6_040_000, payload: batchPayload(2_000n) },
    ];
    const inbox: Route = {
        match: (url) => url.pathname === '/v1/smart_rollups/inbox',
        answer: (url) => {
            const levels = (url.searchParams.get('level.in') ?? '').split(',').map(Number);
            const after = Number(url.searchParams.get('id.gt') ?? 0);

            return json(rows.filter((r) => levels.includes(r.level) && r.id > after).slice(0, 4));
        },
    };

    it('decodes the base64 payloads and keeps the levels holding a covering batch of the tenant and pool', async () => {
        const { fetchImpl, requests } = stub([inbox]);
        const result = await tzktIndexerHints({ tzktApiUrl: BASE, fetchImpl }).candidateFrames(
            [6_040_000, 6_027_994, 6_030_000, 6_031_000, 6_032_000],
            QUERY,
        );

        expect(result).toMatchObject({
            status: 'read',
            levels: [6_027_994, 6_040_000],
            summaries: [
                { level: 6_027_994, startIndex: 2_000n, count: 50 },
                { level: 6_040_000, startIndex: 2_000n, count: 50 },
            ],
        });
        expect(Object.fromEntries(requests[0].searchParams)).toMatchObject({
            type: 'external',
            'level.in': '6027994,6030000,6031000,6032000,6040000',
            'level.ge': '6027994',
            'level.le': '6040000',
            select: 'id,level,payload',
            'sort.asc': 'id',
        });
        // Paged by id down to an empty page.
        expect(requests.at(-1)?.searchParams.get('id.gt')).toBe('23');
    });

    it('never returns a message, only levels and summaries', async () => {
        const { fetchImpl } = stub([inbox]);
        const result = await tzktIndexerHints({ tzktApiUrl: BASE, fetchImpl }).candidateFrames([6_027_994], QUERY);

        if (result.status !== 'read') {
            throw new Error('expected a read');
        }

        // @ts-expect-error A candidate summary is not an InboxMessage: indexer bytes never reach the judged set.
        const judged: InboxMessage = result.summaries[0];

        expect(judged).not.toHaveProperty('rawHex');
        expect(judged).not.toHaveProperty('envelope');
    });

    it('a failed page leaves no candidates', async () => {
        const { fetchImpl } = stub([]);

        expect((await tzktIndexerHints({ tzktApiUrl: BASE, fetchImpl }).candidateFrames([1], QUERY)).status).toBe(
            'unavailable',
        );
    });
});
