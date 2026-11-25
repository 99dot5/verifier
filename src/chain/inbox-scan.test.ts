// @vitest-environment node
// The scanner and the node reads it rests on.
//
// The node-read cases (U-I*) feed `readBlockInbox` the node's own JSON
// shapes. The flow cases (U-S*) stub the locator and the node: every chunk
// reports `bytes = levels × bytesPerLevel` and lists frame counts only, and
// the node serves messages per level. U-S1 runs the real locator over base64
// pages instead, because it is about what the indexer's bytes can and cannot
// reach.
import { bytesToHex, EXTERNAL_MESSAGE_PREFIX } from '@99dot5/round-replay';
import { describe, expect, it } from 'vitest';
import { type BlockInbox, type InboxMessage, LevelUnreadable, readBlockInbox } from './inbox';
import { type ChunkResult, CHUNK_TARGET_BYTES, type FrameLocator, tzktInboxLocator } from './inbox-locator';
import {
    createScanner,
    DownloadDeclinedError,
    type DownloadRequest,
    DOWNLOAD_PROMPT_BYTES,
    IndexerContradictionError,
    LAG_TAIL_MAX,
    type NodeInbox,
    rpcNodeInbox,
    ScanIncompleteError,
    type ScannerOptions,
    SPOT_CHECK_LEVELS,
} from './inbox-scan';
import type { FetchLike } from './node-queue';
import { RangeCache } from './range-cache';

/** These build megabytes of real indexer pages; a loaded CI runner must not time them out. */
const HEAVY = { timeout: 20_000 };

const noSleep = async () => undefined;

function u32(v: number): number[] {
    return [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff];
}

function str(v: string): number[] {
    const bytes = Array.from(new TextEncoder().encode(v));

    return [...u32(bytes.length), ...bytes];
}

/** A decodable `EndSession` frame, distinct per `n`. */
function endSessionBytes(n: number): number[] {
    return [
        ...EXTERNAL_MESSAGE_PREFIX,
        ...new Array<number>(64).fill(0),
        0,
        ...str('tenant'),
        ...str('pool'),
        0x02,
        ...u32(n),
        ...new Array<number>(12).fill(0),
        0,
    ];
}

const frameHex = (n: number) => bytesToHex(Uint8Array.from(endSessionBytes(n)));
const foreignHex = (n: number) => bytesToHex(Uint8Array.from([0x00, 0x01, ...u32(n)]));

/** A deterministic uniform source (mulberry32). */
function seeded(seed: number): () => number {
    let a = seed;

    return () => {
        a = (a + 0x6d2b79f5) | 0;

        let t = Math.imul(a ^ (a >>> 15), 1 | a);

        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;

        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

// ── Node reads (`readBlockInbox`) ────────────────────────────────────────

const RPC = 'https://node.test';

function addMessages(messages: string[], metadata: unknown, source = 'tz1sender'): Record<string, unknown> {
    return {
        kind: 'smart_rollup_add_messages',
        source,
        message: messages,
        ...(metadata === undefined ? {} : { metadata }),
    };
}

const applied = { operation_result: { status: 'applied' } };

function nodeServing(byLevel: Record<number, unknown>, extra: Record<string, unknown> = {}): FetchLike {
    return async (url) => {
        const path = new URL(url).pathname;

        if (path in extra) {
            const answer = extra[path];

            return typeof answer === 'number'
                ? new Response('', { status: answer })
                : new Response(JSON.stringify(answer));
        }

        const match = /\/blocks\/(\d+)\/operations\/3$/.exec(path);
        const body = match ? byLevel[Number(match[1])] : undefined;

        return body === undefined ? new Response('not found', { status: 404 }) : new Response(JSON.stringify(body));
    };
}

describe('reading a block inbox from the node, applied only', () => {
    it('U-I1: an operation with 466 applied and 176 skipped messages yields the applied ones only', async () => {
        const appliedMessages = Array.from({ length: 466 }, (_, i) => (i < 6 ? frameHex(i) : foreignHex(i)));
        const skippedMessages = Array.from({ length: 176 }, (_, i) => frameHex(1_000 + i));
        const fetchImpl = nodeServing({
            4_003_346: [
                {
                    hash: 'oniPFAz',
                    contents: [
                        addMessages(appliedMessages, applied),
                        addMessages(skippedMessages, { operation_result: { status: 'skipped' } }),
                    ],
                },
                {
                    hash: 'opBacktracked',
                    contents: [addMessages([frameHex(5_000)], { operation_result: { status: 'backtracked' } })],
                },
            ],
        });
        const block = await readBlockInbox(RPC, 4_003_346, { fetchImpl });

        expect(block.appliedPrefixedCount).toBe(6);
        expect(block.messages.map((m) => m.rawHex)).toEqual(appliedMessages.slice(0, 6));
        expect(block.messages.every((m) => m.operationHash === 'oniPFAz' && m.source === 'tz1sender')).toBe(true);
        expect(block.messages.map((m) => m.messageIndex)).toEqual([0, 1, 2, 3, 4, 5]);
    });

    it('U-I2: an add_messages content without a stated result makes the level unreadable; other kinds are ignored', async () => {
        const cases: [string, unknown, string][] = [
            ['metadata missing', undefined, 'metadata-missing'],
            ['metadata withheld', 'too large', 'metadata-missing'],
            ['no status', { operation_result: {} }, 'status-missing'],
        ];

        for (const [name, metadata, reason] of cases) {
            const fetchImpl = nodeServing({ 10: [{ hash: 'op', contents: [addMessages([frameHex(1)], metadata)] }] });
            const error = await readBlockInbox(RPC, 10, { fetchImpl }).catch((e: unknown) => e);

            expect(error, name).toBeInstanceOf(LevelUnreadable);
            expect((error as LevelUnreadable).reason, name).toBe(reason);
            expect((error as LevelUnreadable).level, name).toBe(10);
        }

        // The same gaps on a transaction in the same block do not matter.
        const fetchImpl = nodeServing({
            11: [
                { hash: 'tx1', contents: [{ kind: 'transaction' }] },
                { hash: 'tx2', contents: [{ kind: 'transaction', metadata: 'too large' }] },
                { hash: 'tx3', contents: [{ kind: 'transaction', metadata: { operation_result: {} } }] },
                { hash: 'op', contents: [addMessages([frameHex(1)], applied)] },
            ],
        });

        expect((await readBlockInbox(RPC, 11, { fetchImpl })).messages).toHaveLength(1);
    });

    it('U-I3: a 404 is unreadable, and the message names the node history limit when it can be read', async () => {
        const unreadable = await readBlockInbox(RPC, 12, { fetchImpl: nodeServing({}) }).catch((e: unknown) => e);

        expect(unreadable).toBeInstanceOf(LevelUnreadable);
        expect((unreadable as LevelUnreadable).reason).toBe('not-served');

        const heads = {
            '/chains/main/blocks/head/header': { level: 100_000 },
        };
        const withHistory = nodeServing(
            {},
            {
                ...heads,
                '/chains/main/levels/caboose': { level: 90_000 },
                '/chains/main/levels/savepoint': { level: 95_000 },
            },
        );
        const scanner = (fetchImpl: FetchLike) =>
            createScanner({
                locator: stubLocator({ indexerHead: 100_000 }).locator,
                node: rpcNodeInbox(RPC, { fetchImpl, sleep: noSleep }),
                fetchImpl,
                sleep: noSleep,
                confirmDownload: async () => true,
            });
        const named = await scanner(withHistory)
            .fetchBlock(12)
            .catch((e: unknown) => e);

        expect(named).toBeInstanceOf(LevelUnreadable);
        expect((named as Error).message).toBe(
            'the Tezos RPC does not serve level 12 (it keeps blocks from level 90000 and operation metadata from ' +
                'level 95000); an archive node serves it',
        );

        const withoutHistory = nodeServing(
            {},
            { ...heads, '/chains/main/levels/caboose': 500, '/chains/main/levels/savepoint': 500 },
        );
        const unnamed = await scanner(withoutHistory)
            .fetchBlock(12)
            .catch((e: unknown) => e);

        expect((unnamed as Error).message).toBe('the Tezos RPC does not serve level 12; an archive node serves it');
    });

    it('U-I3b: a failed fetch below the node savepoint is named as its history limit; above it, as a failed read', async () => {
        // A pruned node's 404 often lacks a CORS header, so a browser sees only a failed fetch.
        const history = {
            '/chains/main/blocks/head/header': { level: 100_000 },
            '/chains/main/levels/caboose': { level: 90_000 },
            '/chains/main/levels/savepoint': { level: 95_000 },
        };
        const serving = nodeServing({ 96_000: [] }, history);
        const blocked: FetchLike = async (url) => {
            if (/\/blocks\/(12|96001)\/operations\/3$/.test(new URL(url).pathname)) {
                throw new TypeError('Failed to fetch');
            }

            if (/\/blocks\/13\/operations\/3$/.test(new URL(url).pathname)) {
                return new Response('internal error', { status: 500 });
            }

            return serving(url);
        };
        const scanner = createScanner({
            locator: stubLocator({ indexerHead: 100_000 }).locator,
            node: rpcNodeInbox(RPC, { fetchImpl: blocked, sleep: noSleep }),
            fetchImpl: blocked,
            sleep: noSleep,
            confirmDownload: async () => true,
        });

        const pruned = await scanner.fetchBlock(12).catch((e: unknown) => e);

        expect((pruned as LevelUnreadable).reason).toBe('not-served');
        expect((pruned as Error).message).toBe(
            'the Tezos RPC does not serve level 12 (it keeps blocks from level 90000 and operation metadata from ' +
                'level 95000); an archive node serves it',
        );

        const flaky = await scanner.fetchBlock(96_001).catch((e: unknown) => e);

        expect((flaky as LevelUnreadable).reason).toBe('network-error');
        expect((flaky as Error).message).toMatch(/^the Tezos RPC could not be read at level 96001: /);

        // A node that answered, even below its savepoint, keeps its own answer.
        const answered = await scanner.fetchBlock(13).catch((e: unknown) => e);

        expect((answered as LevelUnreadable).reason).toBe('http-error');
        expect((answered as Error).message).toBe('the Tezos RPC could not be read at level 13: HTTP 500');
    });
});

// ── The scanner over a stub indexer and a stub node ─────────────────────

interface StubOptions {
    indexerHead: number;
    /** Prefixed messages per level, as the indexer lists them. */
    frames?: Record<number, number>;
    bytesPerLevel?: number | ((level: number) => number);
    failChunk?(fromLevel: number, toLevel: number, call: number): boolean;
}

function stubLocator(options: StubOptions) {
    const calls: [number, number][] = [];
    const locator: FrameLocator = {
        head: async () => options.indexerHead,
        locateChunk: async (fromLevel, toLevel): Promise<ChunkResult> => {
            calls.push([fromLevel, toLevel]);

            const perLevel = options.bytesPerLevel ?? 200;
            let bytes = 0;

            for (let level = fromLevel; level <= toLevel; level++) {
                bytes += typeof perLevel === 'number' ? perLevel : perLevel(level);
            }

            if (options.failChunk?.(fromLevel, toLevel, calls.length - 1)) {
                return {
                    status: 'unread',
                    fromLevel,
                    toLevel,
                    reason: 'http-status',
                    detail: 'HTTP 503',
                    bytes: 0,
                    requests: 5,
                };
            }

            const frameCountByLevel = new Map<number, number>();

            for (const [level, count] of Object.entries(options.frames ?? {})) {
                if (Number(level) >= fromLevel && Number(level) <= toLevel && count > 0) {
                    frameCountByLevel.set(Number(level), count);
                }
            }

            return { status: 'located', fromLevel, toLevel, frameCountByLevel, bytes, requests: 1 };
        },
    };

    return { locator, calls };
}

interface NodeStubOptions {
    nodeHead: number;
    /** Applied frames per level on the node. */
    frames?: Record<number, number>;
    unreadable?(level: number): boolean;
    delay?(level: number): number;
}

function messagesAt(level: number, count: number): InboxMessage[] {
    return Array.from({ length: count }, (_, i) => ({
        level,
        operationHash: `op-${level}`,
        messageIndex: i,
        rawHex: `node-bytes-${level}-${i}`,
        envelope: {
            tenantId: 'tenant',
            poolId: 'pool',
            message: { kind: 'end-session', sessionId: `${level}-${i}`, reason: 'expired' },
            signature: new Uint8Array(64),
            signedPayload: new Uint8Array(),
        },
    }));
}

function stubNode(options: NodeStubOptions) {
    const reads: number[] = [];
    const node: NodeInbox = {
        head: async () => options.nodeHead,
        read: async (level): Promise<BlockInbox> => {
            reads.push(level);

            const wait = options.delay?.(level) ?? 0;

            if (wait > 0) {
                await new Promise((resolve) => setTimeout(resolve, wait));
            }

            if (options.unreadable?.(level)) {
                throw new LevelUnreadable(level, 'http-error', 'HTTP 503');
            }

            const count = options.frames?.[level] ?? 0;

            return { messages: messagesAt(level, count), appliedPrefixedCount: count };
        },
        history: async () => null,
    };

    return { node, reads };
}

interface WorldOptions extends Partial<Omit<ScannerOptions, 'locator' | 'node'>> {
    head?: number;
    nodeHead?: number;
    indexerHead?: number;
    /** On the node; the indexer lists the same unless `indexerFrames` says otherwise. */
    frames?: Record<number, number>;
    indexerFrames?: Record<number, number>;
    bytesPerLevel?: StubOptions['bytesPerLevel'];
    failChunk?: StubOptions['failChunk'];
    unreadable?: NodeStubOptions['unreadable'];
    delay?: NodeStubOptions['delay'];
}

function world(options: WorldOptions = {}) {
    const head = options.head ?? 100_000;
    const indexer = stubLocator({
        indexerHead: options.indexerHead ?? head,
        frames: options.indexerFrames ?? options.frames,
        bytesPerLevel: options.bytesPerLevel,
        failChunk: options.failChunk,
    });
    const node = stubNode({
        nodeHead: options.nodeHead ?? head,
        frames: options.frames,
        unreadable: options.unreadable,
        delay: options.delay,
    });
    const scanner = createScanner({
        confirmDownload: async () => true,
        random: seeded(7),
        sleep: noSleep,
        ...options,
        locator: indexer.locator,
        node: node.node,
    });

    return { scanner, indexer, node };
}

describe('the scanner', () => {
    it('U-S1: judged bytes are the node’s; a frame only the indexer lists never appears', async () => {
        const forged = btoa(String.fromCharCode(...endSessionBytes(999)));
        let id = 0;
        const rows = [
            { level: 50_000, payload: forged },
            { level: 50_000, payload: forged },
            // Listed by the indexer only.
            { level: 50_010, payload: forged },
        ].map((r) => ({ id: ++id, ...r }));
        const fetchImpl: FetchLike = async (url) => {
            const query = new URL(url).searchParams;

            if (new URL(url).pathname === '/v1/head') {
                return new Response(JSON.stringify({ level: 100_000 }));
            }

            const page = rows.filter(
                (r) =>
                    r.level >= Number(query.get('level.ge')) &&
                    r.level <= Number(query.get('level.le')) &&
                    r.id > Number(query.get('id.gt') ?? 0),
            );

            return new Response(JSON.stringify(page));
        };
        const node = stubNode({ nodeHead: 100_000, frames: { 50_000: 2 } });
        const scanner = createScanner({
            locator: tzktInboxLocator({ tzktApiUrl: 'https://indexer.test', fetchImpl, sleep: noSleep }),
            node: node.node,
            confirmDownload: async () => true,
            random: seeded(1),
        });
        const messages = await scanner.scanRange(49_000, 51_000);

        expect(messages.map((m) => m.rawHex)).toEqual(['node-bytes-50000-0', 'node-bytes-50000-1']);
        expect(messages.some((m) => m.rawHex === frameHex(999) || m.level === 50_010)).toBe(false);
        expect(scanner.coverage().mismatches).toEqual([{ level: 50_010, indexer: 1, node: 0 }]);
    });

    it('U-S3: a gap rejects only after the other chunks finish', async () => {
        const { scanner, indexer, node } = world({
            frames: { 1_120: 1, 1_400: 2 },
            bytesPerLevel: 80_000,
            failChunk: (fromLevel) => fromLevel === 1_201,
        });
        const error = await scanner.scanRange(1_001, 1_450).catch((e: unknown) => e);

        expect(error).toBeInstanceOf(ScanIncompleteError);
        expect((error as ScanIncompleteError).unread).toEqual([
            {
                fromLevel: 1_201,
                toLevel: 1_250,
                reason: 'indexer',
                detail: 'the indexer could not list them: http-status, HTTP 503',
            },
        ]);
        // Every later chunk was still located and its frame level read.
        expect(indexer.calls.at(-1)).toEqual([1_401, 1_450]);
        expect(node.reads).toContain(1_400);
    });

    it('U-S4: a frame level the node cannot serve leaves its chunk uncovered', async () => {
        const { scanner } = world({
            frames: { 1_050: 1, 1_300: 1 },
            bytesPerLevel: 80_000,
            unreadable: (level) => level === 1_300,
        });
        const error = await scanner.scanRange(1_001, 1_400).catch((e: unknown) => e);

        expect(error).toBeInstanceOf(ScanIncompleteError);
        expect((error as ScanIncompleteError).unread).toMatchObject([
            { fromLevel: 1_251, toLevel: 1_300, reason: 'level-unreadable' },
        ]);
        expect((error as Error).message).toContain('level 1300');
        expect(scanner.coverage().covered).toEqual([]);
    });

    describe('U-S5: spot checks, edges and the known-frame check', () => {
        const range = [10_001, 30_000] as const;

        it('a frame hidden at a drawn spot level is a contradiction', async () => {
            const clean = world({ frames: { 20_000: 1 }, random: seeded(42) });

            await clean.scanner.scanRange(...range);

            const spots = clean.scanner.coverage().spotLevels;

            expect(spots).toHaveLength(SPOT_CHECK_LEVELS);

            const hidden = world({
                frames: { 20_000: 1, [spots[3]]: 1 },
                indexerFrames: { 20_000: 1 },
                random: seeded(42),
            });
            const error = await hidden.scanner.scanRange(...range).catch((e: unknown) => e);

            expect(error).toBeInstanceOf(IndexerContradictionError);
            expect((error as IndexerContradictionError).levels).toEqual([spots[3]]);
        });

        it('a frame hidden at an edge is a contradiction', async () => {
            for (const edge of range) {
                const { scanner } = world({ frames: { [edge]: 1 }, indexerFrames: {} });

                await expect(scanner.scanRange(...range)).rejects.toBeInstanceOf(IndexerContradictionError);
            }
        });

        it('a level already read in this run (a hint) is checked against the listing at no cost', async () => {
            const { scanner, node } = world({ frames: { 15_000: 1 }, indexerFrames: {} });

            expect(await scanner.fetchBlock(15_000)).toHaveLength(1);

            const error = await scanner.scanRange(...range).catch((e: unknown) => e);

            expect((error as IndexerContradictionError).levels).toEqual([15_000]);
            expect(node.reads.filter((l) => l === 15_000)).toHaveLength(1);
        });

        it('spends at most 8 spot levels per run, spread over calls by size (1 / 7 / 0)', async () => {
            const { scanner } = world({});
            const drawn: number[] = [];

            for (const [from, to] of [
                [1_001, 2_200],
                [3_001, 30_000],
                [40_001, 42_000],
            ]) {
                const before = scanner.coverage().spotLevels.length;

                await scanner.scanRange(from, to);
                drawn.push(scanner.coverage().spotLevels.length - before);
            }

            expect(drawn).toEqual([1, 7, 0]);
        });

        it('draws no edge or spot level below the minimum level', async () => {
            const { scanner, node } = world({ minLevel: 25_000, random: seeded(3) });

            await scanner.scanRange(...range);

            expect(Math.min(...node.reads)).toBe(25_000);
            expect(node.reads).toContain(30_000);
            expect(scanner.coverage().spotLevels.every((l) => l >= 25_000)).toBe(true);
        });
    });

    it('U-S6: the output is by level, node order within a level, whatever order the reads complete in', async () => {
        const frames = { 2_010: 2, 2_020: 1, 2_030: 3, 2_040: 1, 2_050: 2 };
        const levels = Object.keys(frames).map(Number);
        const outputs: string[][] = [];

        for (const permutation of [
            [0, 1, 2, 3, 4],
            [4, 3, 2, 1, 0],
            [2, 0, 4, 1, 3],
        ]) {
            const { scanner } = world({
                frames,
                delay: (level) => (levels.includes(level) ? 1 + 3 * permutation[levels.indexOf(level)] : 0),
            });

            outputs.push((await scanner.scanRange(2_001, 2_100)).map((m) => m.rawHex));
        }

        expect(outputs[1]).toEqual(outputs[0]);
        expect(outputs[2]).toEqual(outputs[0]);
        expect(outputs[0].slice(0, 3)).toEqual(['node-bytes-2010-0', 'node-bytes-2010-1', 'node-bytes-2020-0']);
    });

    it('U-S7: the indexer bytes fetched never exceed the allowance by more than one chunk', async () => {
        // A mainnet-like rate that triples halfway: the first prompt comes up
        // front, the second only once the raised allowance is crossed.
        const bytesPerLevel = (level: number) => (level <= 10_000 ? 8_800 : 26_400);
        const prompts: { spent: number; allowance: number; request: DownloadRequest }[] = [];
        let allowance = DOWNLOAD_PROMPT_BYTES;
        let lastChunk = 0;
        const { scanner, indexer } = world({
            bytesPerLevel,
            confirmDownload: async (request) => {
                const spent = scanner.coverage().indexerBytes;

                prompts.push({ spent, allowance, request });
                allowance = (spent + request.estimateBytes) * 1.25;

                return true;
            },
        });

        await scanner.scanRange(1, 20_000);

        for (const [from, to] of indexer.calls) {
            let bytes = 0;

            for (let level = from; level <= to; level++) {
                bytes += bytesPerLevel(level);
            }

            lastChunk = Math.max(lastChunk, bytes);
        }

        expect(prompts.length).toBeGreaterThanOrEqual(2);
        expect(prompts[0].spent).toBe(200 * 8_800);
        expect(prompts[0].request.fromLevel).toBe(201);
        expect(prompts[0].request.compressedApprox).toBeCloseTo(0.44 * prompts[0].request.estimateBytes);

        for (const prompt of prompts) {
            expect(prompt.spent).toBeLessThanOrEqual(prompt.allowance + lastChunk);
        }

        expect(scanner.coverage().indexerBytes).toBeLessThanOrEqual(allowance + lastChunk);

        // At a steady rate the up-front prompt is the only one.
        let steadyPrompts = 0;
        const steady = world({
            bytesPerLevel: 8_800,
            confirmDownload: async () => {
                steadyPrompts += 1;

                return true;
            },
        });

        await steady.scanner.scanRange(1, 20_000);
        expect(steadyPrompts).toBe(1);

        // A burst inside a window that stays under the raised allowance asks
        // once: the projection follows the run's mean, not the latest chunk.
        let burstPrompts = 0;
        const bursty = world({
            bytesPerLevel: (level: number) => (level > 6_000 && level <= 7_000 ? 15_000 : 6_800),
            confirmDownload: async () => {
                burstPrompts += 1;

                return true;
            },
        });

        await bursty.scanner.scanRange(1, 20_000);
        expect(burstPrompts).toBe(1);

        // Measured on mainnet: the probe read light and the next chunks
        // heavier, and the early mean crossed the raised allowance although
        // the window came in under it. The second ask waits for a settled
        // sample, so this asks once.
        let noisyPrompts = 0;
        const noisy = world({
            bytesPerLevel: (level: number) => (level <= 200 ? 6_850 : level <= 784 ? 9_400 : 7_560),
            confirmDownload: async () => {
                noisyPrompts += 1;

                return true;
            },
        });

        await noisy.scanner.scanRange(1, 20_000);
        expect(noisyPrompts).toBe(1);
    });

    it(
        'U-S7b: a quiet probe followed by heavy traffic never yields an outsized chunk before the reader is asked',
        HEAVY,
        async () => {
            // Levels up to 1,000 hold one small row; above, eight rows of about
            // 1.1 KB (about 9 KB a level, a mainnet-like burst). Ids follow
            // inbox order, 16 per level.
            const quietPayload = btoa(String.fromCharCode(...new Array<number>(20).fill(1)));
            const heavyPayload = btoa(String.fromCharCode(...new Array<number>(820).fill(1)));
            const rowsAt = (level: number) =>
                level <= 1_000
                    ? [{ id: level * 16, level, payload: quietPayload }]
                    : Array.from({ length: 8 }, (_, k) => ({ id: level * 16 + k, level, payload: heavyPayload }));
            const pages: number[] = [];
            const fetchImpl: FetchLike = async (url) => {
                const query = new URL(url).searchParams;
                const after = Number(query.get('id.gt') ?? 0);
                const limit = Number(query.get('limit'));
                const page: { id: number; level: number; payload: string }[] = [];

                for (
                    let level = Math.max(Number(query.get('level.ge')), Math.floor(after / 16));
                    level <= Number(query.get('level.le')) && page.length < limit;
                    level++
                ) {
                    page.push(...rowsAt(level).filter((r) => r.id > after));
                }

                const text = JSON.stringify(page.slice(0, limit));

                pages.push(text.length);

                return new Response(text);
            };
            const real = tzktInboxLocator({ tzktApiUrl: 'https://indexer.test', fetchImpl, sleep: noSleep });
            const chunks: ChunkResult[] = [];
            const locator: FrameLocator = {
                head: async () => 100_000,
                locateChunk: async (fromLevel, toLevel) => {
                    const chunk = await real.locateChunk(fromLevel, toLevel);

                    chunks.push(chunk);

                    return chunk;
                },
            };
            const prompts: number[] = [];
            let scanner: ReturnType<typeof createScanner> | null = null;

            scanner = createScanner({
                locator,
                node: stubNode({ nodeHead: 100_000 }).node,
                random: seeded(5),
                confirmDownload: async () => {
                    prompts.push(scanner?.coverage().indexerBytes ?? -1);

                    return true;
                },
            });

            await scanner.scanRange(1, 8_000);

            const chunkBytes = chunks.map((c) => c.bytes);
            const largest = Math.max(...chunkBytes);

            expect(chunks.every((c) => c.status === 'located')).toBe(true);
            expect(largest).toBeLessThanOrEqual(4 * CHUNK_TARGET_BYTES);
            expect(Math.max(...pages)).toBeLessThanOrEqual(4 * CHUNK_TARGET_BYTES);
            // Once the burst is measured, every page stays near the target.
            expect(Math.max(...pages.slice(pages.indexOf(Math.max(...pages)) + 1))).toBeLessThan(
                1.5 * CHUNK_TARGET_BYTES,
            );
            // The reader is asked as soon as the burst shows, before the allowance is passed.
            expect(prompts.length).toBeGreaterThanOrEqual(1);
            expect(prompts[0]).toBeLessThanOrEqual(DOWNLOAD_PROMPT_BYTES + largest);
            // Chunks still tile the range.
            expect(chunks.map((c) => [c.fromLevel, c.toLevel])).toEqual(
                chunks.map((c, i) => [i === 0 ? 1 : chunks[i - 1].toLevel + 1, c.toLevel]),
            );
            expect(chunks.at(-1)?.toLevel).toBe(8_000);
        },
    );

    it('U-S8: a declined download rejects, and no indexer request follows it', async () => {
        let callsAtPrompt = -1;
        const { scanner, indexer } = world({
            bytesPerLevel: 8_800,
            confirmDownload: async () => {
                callsAtPrompt = indexer.calls.length;

                return false;
            },
        });
        const error = await scanner.scanRange(1, 20_000).catch((e: unknown) => e);

        expect(error).toBeInstanceOf(DownloadDeclinedError);
        expect((error as DownloadDeclinedError).request).toMatchObject({ fromLevel: 201, toLevel: 20_000 });
        expect(callsAtPrompt).toBe(1);
        expect(indexer.calls).toHaveLength(1);
        expect(scanner.coverage().indexerBytes).toBeLessThanOrEqual(DOWNLOAD_PROMPT_BYTES);
    });

    it('U-S10: a retry lists again only the chunks left uncovered, and spot-checks them anew', async () => {
        const cache = new RangeCache();
        const frames = { 1_020: 1, 1_120: 1, 1_330: 1 };
        const first = world({
            cache,
            frames,
            bytesPerLevel: 80_000,
            failChunk: (fromLevel) => fromLevel === 1_201,
            unreadable: (level) => level === 1_120,
        });

        await expect(first.scanner.scanRange(1_001, 1_400)).rejects.toBeInstanceOf(ScanIncompleteError);

        const healed = world({ cache, frames, bytesPerLevel: 80_000 });
        const messages = await healed.scanner.scanRange(1_001, 1_400);

        expect(messages.map((m) => m.level)).toEqual([1_020, 1_120, 1_330]);
        // Only the two chunks that ended uncovered are listed again: the one
        // the indexer failed and the one holding the level the node failed…
        expect(healed.indexer.calls).toEqual([
            [1_001, 1_200],
            [1_201, 1_250],
        ]);
        // …the node is read only inside them, never again where it already answered…
        expect(healed.node.reads.every((l) => l >= 1_001 && l <= 1_250)).toBe(true);
        expect(healed.node.reads).toContain(1_120);
        expect(healed.node.reads).not.toContain(1_020);
        // …and a spot check is drawn there again.
        expect(healed.scanner.coverage().spotLevels).toHaveLength(1);
        expect(healed.scanner.coverage().spotLevels[0]).toBeLessThanOrEqual(1_250);
    });

    it('U-S11: an aborted run throws on entry, even over a fully cached range', async () => {
        const cache = new RangeCache();

        await world({ cache, frames: { 5_000: 1 } }).scanner.scanRange(4_001, 6_000);

        const abort = new AbortController();

        abort.abort();

        const aborted = world({ cache, frames: { 5_000: 1 }, signal: abort.signal });

        await expect(aborted.scanner.scanRange(4_001, 6_000)).rejects.toMatchObject({ name: 'AbortError' });
        await expect(aborted.scanner.scanHead()).rejects.toMatchObject({ name: 'AbortError' });
        await expect(aborted.scanner.fetchBlock(5_000)).rejects.toMatchObject({ name: 'AbortError' });
        expect(aborted.indexer.calls).toHaveLength(0);
        expect(aborted.node.reads).toHaveLength(0);
    });

    describe('U-S12: one scan head', () => {
        it('is min(nodeHead, indexerHead + 10), whichever is behind', async () => {
            expect(await world({ nodeHead: 1_000, indexerHead: 2_000 }).scanner.scanHead()).toBe(1_000);
            expect(await world({ nodeHead: 2_000, indexerHead: 1_000 }).scanner.scanHead()).toBe(1_000 + LAG_TAIL_MAX);
        });

        it('leaves levels above it unread, rejecting after the rest has been read, and clamps nothing', async () => {
            const { scanner, node } = world({ nodeHead: 50_000, indexerHead: 50_000, frames: { 49_990: 1 } });
            const head = await scanner.scanHead();
            const error = await scanner.scanRange(49_001, head + 5).catch((e: unknown) => e);

            expect(error).toBeInstanceOf(ScanIncompleteError);
            expect((error as ScanIncompleteError).unread).toMatchObject([
                { fromLevel: head + 1, toLevel: head + 5, reason: 'above-head' },
            ]);
            expect(node.reads).toContain(49_990);
            expect(node.reads).toContain(head);
            expect(node.reads.some((l) => l > head)).toBe(false);
        });

        it('reads up to 10 levels above a lagging indexer from the node, and leaves the rest unread', async () => {
            const { scanner, node } = world({ nodeHead: 2_000, indexerHead: 1_000, frames: { 1_005: 1 } });
            const error = await scanner.scanRange(901, 1_500).catch((e: unknown) => e);

            expect((error as ScanIncompleteError).unread).toMatchObject([
                { fromLevel: 1_011, toLevel: 1_500, reason: 'indexer-lagging' },
            ]);
            expect((error as Error).message).toContain('the indexer is 1000 levels behind the Tezos RPC');
            expect(node.reads.filter((l) => l > 1_000).sort((a, b) => a - b)).toEqual(
                Array.from({ length: LAG_TAIL_MAX }, (_, i) => 1_001 + i),
            );

            const tail = world({ nodeHead: 2_000, indexerHead: 1_000, frames: { 1_005: 1 } });

            expect((await tail.scanner.scanRange(901, 1_010)).map((m) => m.level)).toEqual([1_005]);
        });
    });

    it('U-S13: a count mismatch either way is an annotation, and the judged messages are the node’s', async () => {
        const { scanner } = world({
            frames: { 7_010: 2, 7_020: 3, 7_030: 0 },
            indexerFrames: { 7_010: 3, 7_020: 2, 7_030: 1 },
        });
        const messages = await scanner.scanRange(7_001, 7_100);

        expect(messages.map((m) => m.rawHex)).toEqual([
            'node-bytes-7010-0',
            'node-bytes-7010-1',
            'node-bytes-7020-0',
            'node-bytes-7020-1',
            'node-bytes-7020-2',
        ]);
        expect(scanner.coverage().mismatches).toEqual([
            { level: 7_010, indexer: 3, node: 2 },
            { level: 7_020, indexer: 2, node: 3 },
            { level: 7_030, indexer: 1, node: 0 },
        ]);
    });
});
