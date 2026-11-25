// @vitest-environment node
// `run.ts`'s chain flow on the content scan.
//
// The flow is the unchanged `runChainVerification`; only the chain under it
// changes. Each world holds real signed frames (a HiLo round: its SeedBatch
// and RoundTranscript, built and signed the way `verifier.test.ts` builds
// them) among other rollups' traffic at every level. The new chain is the
// scanner over a stub indexer (frame counts per level, `bytes = levels ×
// bytesPerLevel`) and a stub node; the old chain, written inline below, is the
// operation listing it replaces: every level holding any add_messages
// operation, each read from the node.
import * as ed from '@noble/ed25519';
import { blake2b } from '@noble/hashes/blake2.js';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
    actionTypeOf,
    bytesToHex,
    decodeExternalMessage,
    hexToBytes,
    hilo,
    serverSeedCommitment,
    tagOf,
    unitsToDecimalString,
} from '@99dot5/round-replay';
import type { AdminLineage } from './chain/admin-lineage';
import { type DepositChain, locateSessionDeposit } from './chain/deposit';
import type { BlockInbox, InboxMessage } from './chain/inbox';
import type { ChunkResult, FrameLocator } from './chain/inbox-locator';
import {
    createScanner,
    DownloadDeclinedError,
    IndexerContradictionError,
    type NodeInbox,
    ScanIncompleteError,
    type Scanner,
} from './chain/inbox-scan';
import { appendScanFindings } from './chain/scan-findings';
import { computeCommitment } from './receipts/commitment';
import { commandFrame, serverFrame, type ServerFrameSpec } from './receipts/fixtures';
import type { LocatorHints } from './receipts/handoff';
import type { ImportedReceipts } from './receipts/import';
import { type ChainRunInput, type ChainRunResult, DEFAULT_SCAN_DEPTH, runChainVerification } from './run';
import type { KeySet } from './verifier';
import { vectorsUrl } from './verify/vectors-path';
import { encodeEdpk, sequencerSigningPreimage, type SigningDomain } from './wire/signature';

/** These build megabytes of real indexer pages; a loaded CI runner must not time them out. */
const HEAVY = { timeout: 20_000 };

// ── A real signed HiLo round ─────────────────────────────────────────────

const SIGNING_SEED = new Uint8Array(32).fill(1);
const PUBLIC_KEY = ed.getPublicKey(SIGNING_SEED);
const TENANT = 'test-tenant';
const POOL = 'standard';
const DOMAIN: SigningDomain = { chainId: 'NetXsqzbfFenSTS', rollupAddress: 'sr1TMxAUtDA4sDL7C4r39L18iQjhRcBRzd8a' };
const ROUND_ID = '9a256790-c7c0-47b0-9a5b-6ed2905d2df1';
const SESSION_ID = 'e2b6419a-ec4b-4eef-bdfa-802b6f338fc2';
const SEED_INDEX = 137n;
const BATCH_START = 100n;
const STAKE_MUTEZ = 100_000_000n;
const STAKE_MONEY = { asset: 'TEZ', value: unitsToDecimalString(STAKE_MUTEZ, 6) };

const u32 = (v: number) => [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff];
const u64 = (v: bigint) => Array.from({ length: 8 }, (_, i) => Number((v >> BigInt(8 * i)) & 0xffn));
const u128 = (v: bigint) => Array.from({ length: 16 }, (_, i) => Number((v >> BigInt(8 * i)) & 0xffn));
const uuid = (hyphenated: string) => Array.from(hexToBytes(hyphenated.replaceAll('-', '')));

function str(v: string): number[] {
    const bytes = Array.from(new TextEncoder().encode(v));

    return [...u32(bytes.length), ...bytes];
}

function frame(level: number, payloadBody: number[]): InboxMessage {
    const payload = new Uint8Array([0, ...str(TENANT), ...str(POOL), ...payloadBody]);
    const signature = ed.sign(blake2b(sequencerSigningPreimage(DOMAIN, payload), { dkLen: 32 }), SIGNING_SEED);
    const raw = new Uint8Array([0x09, 0x95, ...signature, ...payload]);
    const envelope = decodeExternalMessage(raw);

    if (!envelope) {
        throw new Error('test frame failed to decode');
    }

    return { level, operationHash: `op-level-${level}`, messageIndex: 0, rawHex: bytesToHex(raw), envelope };
}

const scenario = (
    JSON.parse(readFileSync(fileURLToPath(vectorsUrl('hilo')), 'utf8')) as {
        hex_scenarios: { name: string; server_seed_hex: string; effective_client_seed_hex: string }[];
    }
).hex_scenarios.find((s) => s.name === 'hilo-higher-wins-at-1');

if (!scenario) {
    throw new Error('hilo vectors.json has no hilo-higher-wins-at-1 scenario');
}

const CLIENT_SEED = hexToBytes(scenario.effective_client_seed_hex);
const SERVER_SEED = hexToBytes(scenario.server_seed_hex);
const SEED_COMMITMENT = serverSeedCommitment(bytesToHex(SERVER_SEED));
const SESSION_SEED = new Uint8Array(32).fill(2);
const BET_REQUEST = '11111111-1111-4111-8111-111111111111';
const CASHOUT_REQUEST = '22222222-2222-4222-8222-222222222222';
const BET_COMMAND = commandFrame(SESSION_SEED, {
    requestId: BET_REQUEST,
    sessionId: SESSION_ID,
    payloadCase: 'placeBet',
    amount: STAKE_MONEY,
    serverSeedHash: SEED_COMMITMENT,
    game: { game: 'hilo' },
});
const CASHOUT_COMMAND = commandFrame(SESSION_SEED, {
    requestId: CASHOUT_REQUEST,
    sessionId: SESSION_ID,
    payloadCase: 'cashOut',
    roundId: ROUND_ID,
    game: { game: 'hilo' },
});
const PLAYER_COMMITMENT = computeCommitment([BET_COMMAND, CASHOUT_COMMAND]);
const ACTIONS = ['place-bet', 'cashout'].map((type) => {
    const tag = tagOf(type);

    if (tag === null) {
        throw new Error(`no tag for ${type}`);
    }

    return tag;
});
const HONEST_PAYOUT = hilo.v1.replay(
    bytesToHex(SERVER_SEED),
    bytesToHex(CLIENT_SEED),
    ACTIONS.map((tag, actionIndex) => ({
        actionIndex,
        actionType: actionTypeOf(tag) ?? '',
        payload: new Uint8Array(),
    })),
    STAKE_MUTEZ,
).payoutUnits;

function buildReceipts(): ImportedReceipts {
    const ended: ServerFrameSpec = {
        sequence: 5,
        sessionId: SESSION_ID,
        relatedRequestId: CASHOUT_REQUEST,
        payload: {
            case: 'roundEnded',
            roundId: ROUND_ID,
            actionIndex: 1,
            playerCommitment: PLAYER_COMMITMENT,
            cause: 'player-action',
            serverSeed: bytesToHex(SERVER_SEED),
        },
    };
    const received = (spec: ServerFrameSpec) => ({
        sequence: BigInt(spec.sequence),
        payloadCase: spec.payload.case,
        relatedRequestId: spec.relatedRequestId,
        frame: serverFrame(SIGNING_SEED, spec),
    });

    return {
        tenantId: TENANT,
        poolId: POOL,
        sessionIdHex: SESSION_ID,
        roundIdHex: ROUND_ID,
        sequencerPublicKey: encodeEdpk(PUBLIC_KEY),
        sessionPublicKey: encodeEdpk(ed.getPublicKey(SESSION_SEED)),
        depositOperationLevel: null,
        locatorHints: null,
        source: 'client',
        commands: [
            { requestId: BET_REQUEST, payloadCase: 'placeBet', frame: BET_COMMAND, sentAtUnixMs: 1, sendCount: 1 },
            {
                requestId: CASHOUT_REQUEST,
                payloadCase: 'cashOut',
                frame: CASHOUT_COMMAND,
                sentAtUnixMs: 2,
                sendCount: 1,
            },
        ],
        frames: [
            received({
                sequence: 2,
                sessionId: SESSION_ID,
                relatedRequestId: BET_REQUEST,
                payload: { case: 'commandAccepted' },
            }),
            received({
                sequence: 3,
                sessionId: SESSION_ID,
                relatedRequestId: BET_REQUEST,
                payload: {
                    case: 'roundStarted',
                    roundId: ROUND_ID,
                    stake: STAKE_MONEY,
                    serverSeedCommitment: { hash: SEED_COMMITMENT, index: SEED_INDEX },
                },
            }),
            received({
                sequence: 4,
                sessionId: SESSION_ID,
                relatedRequestId: CASHOUT_REQUEST,
                payload: { case: 'commandAccepted' },
            }),
            received(ended),
        ],
        roundEndedFrame: serverFrame(SIGNING_SEED, ended),
    };
}

/** The round's SeedBatch at `batchLevel` and its RoundTranscript at `transcriptLevel`. */
function round(batchLevel: number, transcriptLevel: number): InboxMessage[] {
    const hashes = Array.from({ length: 50 }, (_, i) =>
        i === Number(SEED_INDEX - BATCH_START) ? SEED_COMMITMENT : new Uint8Array(32).fill(i),
    );

    return [
        frame(batchLevel, [
            0x00,
            ...u64(BATCH_START),
            ...u32(hashes.length),
            ...hashes.flatMap((h) => Array.from(h)),
            ...u64(4242n),
            ...hexToBytes('52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971'),
        ]),
        frame(transcriptLevel, [
            0x01,
            ...uuid(ROUND_ID),
            ...uuid(SESSION_ID),
            ...str(hilo.v1.GAME_TYPE),
            ...u128(STAKE_MUTEZ),
            ...Array.from(CLIENT_SEED),
            ...Array.from(SERVER_SEED),
            ...u64(SEED_INDEX),
            ...u128(HONEST_PAYOUT),
            ...Array.from(PLAYER_COMMITMENT),
            ...u32(ACTIONS.length),
            ...ACTIONS.flatMap((tag) => [tag, ...u32(0)]),
        ]),
    ];
}

const KEYS: KeySet = {
    status: 'available',
    keys: [
        {
            edpk: encodeEdpk(PUBLIC_KEY),
            registration: {
                level: 1,
                operationHash: 'op-register-tenant',
                source: 'register-tenant',
                administrator: 'KT1TestAdministrator',
            },
        },
    ],
};

// ── The session's deposit: one production vault, one first deposit ──────

const VAULT = 'KT1WiDdttiuqRHVJ8gb1cYte4Xf3YCGwtDty';
const SESSION_HEX = SESSION_ID.replaceAll('-', '');
const SESSIONS_ID = '500';

const LINEAGE: AdminLineage = {
    administrators: [],
    keys: [],
    vaults: [
        { tenantId: TENANT, poolId: POOL, vault: VAULT, status: 'active', level: 1, operationHash: 'op-register' },
    ],
    proposals: [],
    ambiguities: [],
    scannedOperationCount: 0,
    ignoredOperationCount: 0,
};

function depositChain(depositLevel: number): DepositChain {
    const indexer = (async (url: string) => {
        const rows = new URL(url).searchParams.get('id.gt')
            ? []
            : [
                  {
                      id: depositLevel * 10,
                      level: depositLevel,
                      hash: `op-deposit-${depositLevel}`,
                      parameter: { entrypoint: 'deposit', value: { session_id: SESSION_HEX } },
                  },
              ];

        return new Response(JSON.stringify(rows));
    }) as typeof fetch;

    return {
        locateDeposit: (vaultAddresses, sessionIdHex, levelHint) =>
            locateSessionDeposit({
                tzktApiUrl: 'https://indexer.test',
                vaultAddresses,
                sessionIdHex,
                levelHint,
                fetchImpl: indexer,
            }),
        blockOperations: async (level) =>
            level !== depositLevel
                ? []
                : [
                      {
                          hash: `op-deposit-${level}`,
                          contents: [
                              {
                                  kind: 'transaction',
                                  destination: VAULT,
                                  parameters: {
                                      entrypoint: 'deposit',
                                      value: {
                                          prim: 'Pair',
                                          args: [{ bytes: SESSION_HEX }, { prim: 'Pair', args: [] }],
                                      },
                                  },
                                  metadata: {
                                      operation_result: {
                                          status: 'applied',
                                          lazy_storage_diff: [
                                              {
                                                  kind: 'big_map',
                                                  id: SESSIONS_ID,
                                                  diff: {
                                                      action: 'update',
                                                      updates: [
                                                          {
                                                              key: { bytes: SESSION_HEX },
                                                              value: { prim: 'Pair', args: [] },
                                                          },
                                                      ],
                                                  },
                                              },
                                          ],
                                      },
                                  },
                              },
                          ],
                      },
                  ],
        contractStorage: async () => ({
            prim: 'Pair',
            args: [
                { string: 'tz1admin' },
                { string: 'sppk7authoriser' },
                { int: '400' },
                { prim: 'False' },
                { int: '0' },
                [],
                { prim: 'None' },
                { string: POOL },
                { int: SESSIONS_ID },
                { string: 'sr1' },
                { string: TENANT },
                { int: '0' },
                { string: 'KT1treasury' },
            ],
        }),
        bigMapHas: async () => false,
    };
}

// ── The two chains over one world ────────────────────────────────────────

const T = 100_000;
const HEAD = T + 50;

interface World {
    /** Our frames on the node, all applied. */
    messages: InboxMessage[];
    /** The indexer's prefixed counts; defaults to the node's. */
    indexerFrames?: Map<number, number>;
    nodeHead?: number;
    indexerHead?: number;
    /** Other rollups' bytes at every level. */
    bytesPerLevel?: number;
}

const countsOf = (messages: InboxMessage[]) => {
    const counts = new Map<number, number>();

    for (const m of messages) {
        counts.set(m.level, (counts.get(m.level) ?? 0) + 1);
    }

    return counts;
};

/** The content scan over the world, with every node read and indexer chunk logged. */
function newChain(world: World, options: { confirmDownload?: () => Promise<boolean> } = {}) {
    const nodeReads: number[] = [];
    const frameReads = new Set<number>();
    const chunks: [number, number][] = [];
    const indexerFrames = world.indexerFrames ?? countsOf(world.messages);
    const locator: FrameLocator = {
        head: async () => world.indexerHead ?? HEAD,
        locateChunk: async (fromLevel, toLevel): Promise<ChunkResult> => {
            chunks.push([fromLevel, toLevel]);

            return {
                status: 'located',
                fromLevel,
                toLevel,
                frameCountByLevel: new Map([...indexerFrames].filter(([l]) => l >= fromLevel && l <= toLevel)),
                bytes: (toLevel - fromLevel + 1) * (world.bytesPerLevel ?? 200),
                requests: 1,
            };
        },
    };
    const node: NodeInbox = {
        head: async () => world.nodeHead ?? HEAD,
        read: async (level): Promise<BlockInbox> => {
            nodeReads.push(level);

            const messages = world.messages.filter((m) => m.level === level);

            if (messages.length > 0) {
                frameReads.add(level);
            }

            return { messages, appliedPrefixedCount: messages.length };
        },
        history: async () => null,
    };
    const scanner: Scanner = createScanner({
        locator,
        node,
        confirmDownload: options.confirmDownload ?? (async () => true),
        random: () => 0.37,
    });
    const chain: ChainRunInput['chain'] = {
        headLevel: () => scanner.scanHead(),
        scanRange: (from, to) => scanner.scanRange(from, to),
        fetchBlock: (level) => scanner.fetchBlock(level),
    } as ChainRunInput['chain'];

    return { scanner, chain, nodeReads, frameReads, chunks };
}

/**
 * The operation listing the content scan replaces: other rollups' operations
 * sit at every level, so every level in the window is listed and read, and
 * frames are found where the world holds them.
 */
function oldChain(world: World) {
    const frameReads = new Set<number>();
    const readBlock = (level: number) => {
        const messages = world.messages.filter((m) => m.level === level);

        if (messages.length > 0) {
            frameReads.add(level);
        }

        // Every read decoded its own objects, so a scanned copy and a hint
        // confirmed in its own block were never the same object.
        return messages.map((m) => ({ ...m }));
    };
    const chain = {
        headLevel: async () => world.indexerHead ?? HEAD,
        scanRange: async (from: number, to: number) => {
            const messages: InboxMessage[] = [];

            for (let level = from; level <= to; level++) {
                messages.push(...readBlock(level));
            }

            return messages;
        },
        fetchBlock: async (level: number) => readBlock(level),
    } as ChainRunInput['chain'];

    return { chain, frameReads };
}

interface RunOptions {
    hints?: LocatorHints | null;
    /** The session's first deposit on L1, which session-before-transcript proves. */
    deposit: number;
    /** The suppression bracket's deposit; defaults to `deposit`, `null` = not located. */
    scanDeposit?: number | null;
    toLevel?: number | null;
}

function run(chain: ChainRunInput['chain'], options: RunOptions): Promise<ChainRunResult> {
    return runChainVerification({
        verify: {
            roundId: ROUND_ID,
            tenantId: TENANT,
            signingDomain: DOMAIN,
            deploymentListed: true,
            receipts: { status: 'ok', receipts: buildReceipts() },
        },
        fromLevel: null,
        toLevel: options.toLevel ?? null,
        hints: { hints: options.hints ?? null, source: 'the link', malformed: [] },
        resolveKeys: async () => KEYS,
        resolveDeposit: async () => {
            const level = options.scanDeposit === undefined ? options.deposit : options.scanDeposit;

            return level === null ? null : { level, confirmed: true };
        },
        lineage: () => LINEAGE,
        formPoolId: POOL,
        chain: { ...depositChain(options.deposit), ...chain },
    });
}

const hint = (level: number) => ({ level, operationHash: `op-level-${level}` });
const statusOf = (report: { checks: { id: string; status: string }[] }, id: string) =>
    report.checks.find((c) => c.id === id)?.status;

/** Run both chains over one world and return both results. */
async function both(world: World, options: RunOptions) {
    const fresh = newChain(world);
    const old = oldChain(world);
    const [now, before] = [await run(fresh.chain, options), await run(old.chain, options)];

    return { now, before, fresh, old };
}

describe('run.ts on the content scan', () => {
    it('RS1: node-reads exactly the frame levels the old operation listing found frames at, hinted and unhinted', async () => {
        const world: World = { messages: round(T - 500, T) };

        for (const hints of [null, { transcript: hint(T), seedBatch: hint(T - 500) }]) {
            const { now, before, fresh, old } = await both(world, { hints, deposit: T - 1_000 });

            expect(now).toEqual(before);
            expect(now.report.verdict).toBe('verified');
            expect([...fresh.frameReads].sort()).toEqual([...old.frameReads].sort());
            // Far fewer node reads than one per level: frames, two edges, eight spots.
            expect(fresh.nodeReads.length).toBeLessThan(20);
        }
    });

    it('RS2: the hint layouts reach the same verdicts on the new scanner', HEAVY, async () => {
        // A: confirmed transcript and batch hints near the head.
        const a = await both(
            { messages: round(T - 500, T) },
            {
                hints: { transcript: hint(T), seedBatch: hint(T - 500) },
                deposit: T - 1_000,
            },
        );

        expect(a.now).toEqual(a.before);
        expect(a.now.report.verdict).toBe('verified');

        // B: the hinted batch is a later duplicate at T + 3 and no deposit
        // bounds the window, so the hinted run fails; the re-run decides.
        const [duplicate] = round(T + 3, T);
        const b = await both(
            { messages: [...round(T - 5, T), duplicate] },
            {
                hints: { transcript: hint(T), seedBatch: hint(T + 3) },
                deposit: T - 1_000,
                scanDeposit: null,
            },
        );

        expect(b.now).toEqual(b.before);
        expect(b.now.hintedRun?.verdict).toBe('failed');
        expect(b.now.report.verdict).toBe('verified');

        // C: a copy applied before the session existed, far below the head (a preliminary pass runs).
        const layout = { batch: T - 30_000, early: T - 25_000, deposit: T - 22_000 };
        const [, early] = round(layout.batch, layout.early);
        const c = await both(
            { messages: [...round(layout.batch, T), early] },
            {
                hints: { transcript: hint(T), seedBatch: hint(layout.batch) },
                deposit: layout.deposit,
            },
        );

        expect(c.now).toEqual(c.before);
        expect(c.now.preliminary).not.toBeNull();
        expect(c.now.report.verdict).toBe('failed');
        expect(statusOf(c.now.report, 'session-before-transcript')).toBe('fail');
    });

    it('RS3: a declined download rejects the run, and no report is produced', async () => {
        let prompts = 0;
        const fresh = newChain(
            { messages: round(T - 500, T), bytesPerLevel: 8_800 },
            {
                confirmDownload: async () => {
                    prompts += 1;

                    return false;
                },
            },
        );

        await expect(run(fresh.chain, { deposit: T - 1_000 })).rejects.toBeInstanceOf(DownloadDeclinedError);
        expect(prompts).toBe(1);
    });

    it('RS4: an indexer hiding the hinted transcript is a contradiction, and the run rejects', async () => {
        const messages = round(T - 500, T);
        const fresh = newChain({ messages, indexerFrames: new Map([[T - 500, 1]]) });
        const result = run(fresh.chain, { hints: { transcript: hint(T) }, deposit: T - 1_000 });

        await expect(result).rejects.toBeInstanceOf(IndexerContradictionError);
        await expect(result).rejects.toMatchObject({ levels: [T] });
    });

    it('RS5: an indexer 50 levels behind a hinted T leaves the run unread; 5 behind, the tail is read', async () => {
        const messages = round(T - 500, T);
        const lagging = newChain({ messages, nodeHead: HEAD, indexerHead: T - 50 });
        const error = await run(lagging.chain, { hints: { transcript: hint(T) }, deposit: T - 1_000 }).catch(
            (e: unknown) => e,
        );

        expect(error).toBeInstanceOf(ScanIncompleteError);
        expect((error as ScanIncompleteError).unread).toMatchObject([
            { fromLevel: T - 40 + 1, toLevel: T, reason: 'indexer-lagging' },
        ]);

        const close = newChain({ messages, nodeHead: HEAD, indexerHead: T - 5 });
        const result = await run(close.chain, { hints: { transcript: hint(T) }, deposit: T - 1_000 });

        expect(result.report.verdict).toBe('verified');
        expect(close.nodeReads).toEqual(expect.arrayContaining([T - 4, T - 3, T - 2, T - 1, T]));
    });

    it('RS6: appendScanFindings adds a count-mismatch finding and changes nothing else', async () => {
        const messages = round(T - 500, T);
        const fresh = newChain({
            messages,
            indexerFrames: new Map([
                [T - 500, 2],
                [T, 1],
            ]),
        });
        const result = await run(fresh.chain, { deposit: T - 1_000 });
        const report = appendScanFindings(result.report, fresh.scanner.coverage());

        expect(report.verdict).toBe('verified');
        expect(report.checks).toEqual(result.report.checks);
        expect(report.findings.slice(0, -1)).toEqual(result.report.findings);
        expect(report.findings.at(-1)).toBe(
            `Indexer cross-check: at level ${T - 500} the indexer lists 2 message(s) with this rollup's prefix and ` +
                "the Tezos RPC holds 1 applied; the Tezos RPC's messages are the ones judged.",
        );
        expect(appendScanFindings(result.report, { mismatches: [] })).toBe(result.report);
    });

    it('RS8: a batch hint in the transcript’s own block, with no earlier copy, fails on both chains', async () => {
        // The kernel rejects a transcript whose batch landed in the same block.
        // The hinted run fails commitment-order on the hinted copy; the re-run
        // keeps the copy only because the scan itself reads it, as a distinct
        // object from the confirmed hint.
        const sameBlock = round(T, T).map((m, i) => ({ ...m, messageIndex: i, operationHash: `op-level-${T}` }));
        const { now, before, fresh } = await both(
            { messages: sameBlock },
            {
                hints: { transcript: hint(T), seedBatch: hint(T) },
                deposit: T - 1_000,
                scanDeposit: null,
            },
        );

        expect(now).toEqual(before);
        expect(before.hintedRun?.verdict).toBe('failed');
        expect(before.report.verdict).toBe('failed');
        expect(statusOf(now.report, 'commitment-order')).toBe('fail');

        const [viaFetch] = await fresh.scanner.fetchBlock(T);
        const scanned = await fresh.scanner.scanRange(T - 10, T);

        expect(scanned.some((m) => m === viaFetch)).toBe(false);
        expect(scanned.map((m) => m.rawHex)).toContain(viaFetch.rawHex);
    });

    describe('RS7: the node 30 levels behind the indexer', () => {
        const nodeHead = HEAD - 30;
        const world: World = { messages: round(T - 500, T), nodeHead, indexerHead: HEAD };

        it('an unhinted run scans up to the node head, and every level up to it is covered', async () => {
            const fresh = newChain(world);
            const result = await run(fresh.chain, { deposit: T - 1_000 });

            expect(await fresh.scanner.scanHead()).toBe(nodeHead);
            expect(result.report.scan).toMatchObject({
                fromLevel: nodeHead - DEFAULT_SCAN_DEPTH,
                toLevel: nodeHead,
                headLevel: nodeHead,
            });
            expect(fresh.scanner.coverage().covered).toEqual([
                { fromLevel: nodeHead - DEFAULT_SCAN_DEPTH, toLevel: nodeHead },
            ]);
            expect(Math.max(...fresh.nodeReads)).toBe(nodeHead);
            expect(result.report.verdict).toBe('verified');
        });

        it('a reader-pinned upper bound at the indexer head is above the scan head, and rejects', async () => {
            const fresh = newChain(world);
            const error = await run(fresh.chain, { deposit: T - 1_000, toLevel: HEAD }).catch((e: unknown) => e);

            expect(error).toBeInstanceOf(ScanIncompleteError);
            expect((error as ScanIncompleteError).unread).toMatchObject([
                { fromLevel: nodeHead + 1, toLevel: HEAD, reason: 'above-head' },
            ]);
        });
    });
});
