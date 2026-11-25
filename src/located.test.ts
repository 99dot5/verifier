// @vitest-environment node
// The located run end to end: `runLocatedVerification` over the
// content scan, judging through the unchanged
// `runChainVerification` and `verifyRound`.
//
// Each world holds real signed frames (a HiLo round whose SeedBatch is one of
// ten siblings in one operation, and its RoundTranscript), each with the
// account that posted it, among other rollups' traffic at every level. The
// scanner runs over a stub indexer (frame counts per level, `bytes = levels ×
// bytesPerLevel`) and a stub node. The located run's own indexer questions go
// to a stub serving TzKT's response shapes: a level list for the block at a
// time, `{id, level, messagesCount}` rows for the sender's operations, and
// base64 payload rows for the inbox at candidate levels.
//
// The numbers follow a staging round: the transcript at T = 6,053,529, the
// session's first deposit at D = 6,053,518 and its seed batch at
// B = 6,027,994, 25,535 levels below T.
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
    type DownloadRequest,
    IndexerContradictionError,
    type NodeInbox,
    ScanIncompleteError,
} from './chain/inbox-scan';
import { tzktIndexerHints } from './chain/indexer-hints';
import type { FetchLike } from './chain/node-queue';
import { RangeCache } from './chain/range-cache';
import { appendScanFindings } from './chain/scan-findings';
import { type LocatedRunResult, runLocatedVerification } from './located';
import { computeCommitment } from './receipts/commitment';
import { commandFrame, serverFrame, type ServerFrameSpec } from './receipts/fixtures';
import type { LocatorHints } from './receipts/handoff';
import type { ImportedReceipts } from './receipts/import';
import { type ChainRunInput, type ChainRunResult, runChainVerification } from './run';
import type { KeySet, ReceiptsInput, VerificationReport } from './verifier';
import { vectorsUrl } from './verify/vectors-path';
import { encodeEdpk, sequencerSigningPreimage, type SigningDomain } from './wire/signature';

// ── A real signed HiLo round ─────────────────────────────────────────────

const SIGNING_SEED = new Uint8Array(32).fill(1);
const FOREIGN_SEED = new Uint8Array(32).fill(9);
const PUBLIC_KEY = ed.getPublicKey(SIGNING_SEED);
const TENANT = 'test-tenant';
const POOL = 'standard';
const DOMAIN: SigningDomain = { chainId: 'NetXsqzbfFenSTS', rollupAddress: 'sr1TMxAUtDA4sDL7C4r39L18iQjhRcBRzd8a' };
const ROUND_ID = '9a256790-c7c0-47b0-9a5b-6ed2905d2df1';
const SESSION_ID = 'e2b6419a-ec4b-4eef-bdfa-802b6f338fc2';
const OTHER_SESSION_ID = '5d1e5a4c-0b5e-4f3b-9d0e-2f8f9b0d6a11';
const SEED_INDEX = 2_007n;
const STAKE_MUTEZ = 100_000_000n;
const STAKE_MONEY = { asset: 'TEZ', value: unitsToDecimalString(STAKE_MUTEZ, 6) };
/** The account the sequencer posts from (public chain data). */
const SENDER = 'tz1crXV6x6jRJLnR5uTfhuQrqxSo7wQajQJh';
const OTHER_SENDER = 'tz1VsVoKiVC9ARcbR7A7pvEMsjoGcannVuPM';
/** The cash-out's CommandAccepted stamp, the round's server-signed time. */
const TIME_MS = Date.parse('2026-11-22T12:00:05.123Z');

const T = 6_053_529;
const D = 6_053_518;
const B = 6_027_994;

const u32 = (v: number) => [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff];
const u64 = (v: bigint) => Array.from({ length: 8 }, (_, i) => Number((v >> BigInt(8 * i)) & 0xffn));
const u128 = (v: bigint) => Array.from({ length: 16 }, (_, i) => Number((v >> BigInt(8 * i)) & 0xffn));
const uuid = (hyphenated: string) => Array.from(hexToBytes(hyphenated.replaceAll('-', '')));

function str(v: string): number[] {
    const bytes = Array.from(new TextEncoder().encode(v));

    return [...u32(bytes.length), ...bytes];
}

interface FrameOptions {
    source?: string;
    seed?: Uint8Array;
    operationHash?: string;
    messageIndex?: number;
}

function frame(level: number, payloadBody: number[], options: FrameOptions = {}): InboxMessage {
    const payload = new Uint8Array([0, ...str(TENANT), ...str(POOL), ...payloadBody]);
    const signature = ed.sign(
        blake2b(sequencerSigningPreimage(DOMAIN, payload), { dkLen: 32 }),
        options.seed ?? SIGNING_SEED,
    );
    const raw = new Uint8Array([0x09, 0x95, ...signature, ...payload]);
    const envelope = decodeExternalMessage(raw);

    if (!envelope) {
        throw new Error('test frame failed to decode');
    }

    return {
        level,
        operationHash: options.operationHash ?? `op-level-${level}`,
        messageIndex: options.messageIndex ?? 0,
        rawHex: bytesToHex(raw),
        envelope,
        source: options.source ?? SENDER,
    };
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

/** The player's export; `timed: false` leaves every CommandAccepted without its signed stamp. */
function buildReceipts(timed = true): ImportedReceipts {
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
    const accepted = (sequence: number, requestId: string, at: number): ServerFrameSpec => ({
        sequence,
        sessionId: SESSION_ID,
        relatedRequestId: requestId,
        payload: timed ? { case: 'commandAccepted', receivedAtUnixMs: at } : { case: 'commandAccepted' },
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
            // The client clock, far from the server's: never read for the time.
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
            received(accepted(2, BET_REQUEST, TIME_MS - 4_000)),
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
            received(accepted(4, CASHOUT_REQUEST, TIME_MS)),
            received(ended),
        ],
        roundEndedFrame: serverFrame(SIGNING_SEED, ended),
    };
}

/** The ten sibling SeedBatches of one operation; the sixth covers 2000–2049 and commits the round's seed. */
function batches(level: number, options: FrameOptions & { conflicting?: boolean } = {}): InboxMessage[] {
    return Array.from({ length: 10 }, (_, i) => {
        const start = 1_750n + BigInt(50 * i);
        const hashes = Array.from({ length: 50 }, (_, j) =>
            start + BigInt(j) === SEED_INDEX && !options.conflicting
                ? SEED_COMMITMENT
                : new Uint8Array(32).fill(start + BigInt(j) === SEED_INDEX ? 0xee : j),
        );

        return frame(
            level,
            [
                0x00,
                ...u64(start),
                ...u32(hashes.length),
                ...hashes.flatMap((h) => Array.from(h)),
                ...u64(4242n),
                ...hexToBytes('52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971'),
            ],
            { ...options, operationHash: options.operationHash ?? `op-batch-${level}`, messageIndex: i },
        );
    });
}

/** A RoundTranscript; the round's own by default. */
function transcript(level: number, options: FrameOptions & { roundId?: string; sessionId?: string } = {}) {
    return frame(
        level,
        [
            0x01,
            ...uuid(options.roundId ?? ROUND_ID),
            ...uuid(options.sessionId ?? SESSION_ID),
            ...str(hilo.v1.GAME_TYPE),
            ...u128(STAKE_MUTEZ),
            ...Array.from(CLIENT_SEED),
            ...Array.from(SERVER_SEED),
            ...u64(SEED_INDEX),
            ...u128(HONEST_PAYOUT),
            ...Array.from(PLAYER_COMMITMENT),
            ...u32(ACTIONS.length),
            ...ACTIONS.flatMap((tag) => [tag, ...u32(0)]),
        ],
        options,
    );
}

/** Other rounds of another session, posted by the same sender: frames the scan reads and nothing judges. */
function otherRounds(levels: number[]): InboxMessage[] {
    return levels.map((level, i) =>
        transcript(level, { roundId: `0000000${i}-1111-4111-8111-111111111111`, sessionId: OTHER_SESSION_ID }),
    );
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

// ── A located world and the chain over it ────────────────────────────────

interface LocatedWorld {
    /** Our frames on the node, all applied, each with the account that posted it. */
    messages: InboxMessage[];
    /** The session's first deposit, which session-before-transcript proves and the window may reach down to. */
    deposit: number;
    nodeHead: number;
    indexerHead?: number;
    /** The level the indexer places the signed time at. */
    estimatedLevel: number;
    /** Other rollups' bytes at every level. */
    bytesPerLevel?: number;
    /** The administrator's origination: nothing of the rollup sits lower. */
    minLevel?: number;
    /** How the block-at-time listing answers. */
    time?: 'ok' | 'empty' | 500 | 'network-failure';
    /** How the sender listing answers. */
    senderListing?: 'ok' | 404;
    /** More operations of the transcript's sender, holding nothing of this round. */
    extraSenderOps?: { level: number; messagesCount: number }[];
    /** The indexer's prefixed count at a level, given the node's. */
    indexerCount?(level: number, nodeCount: number): number;
}

interface ChainOptions {
    confirmDownload?(request: DownloadRequest): Promise<boolean>;
    cache?: RangeCache;
    signal?: AbortSignal;
    /** Called before each indexer chunk; may change the world or abort. */
    onChunk?(fromLevel: number, toLevel: number): void;
    /** A chunk holding this level comes back unread. */
    failChunkAt?: number;
    /** What each `scanRange` call hands the flow; the scanner's messages when absent. */
    mapScan?(fromLevel: number, toLevel: number, messages: InboxMessage[]): InboxMessage[];
}

/** A seeded uniform source: every chain over a world draws the same spot levels. */
function seeded(seed: number): () => number {
    let state = seed;

    return () => {
        state = (state * 1_103_515_245 + 12_345) % 2 ** 31;

        return state / 2 ** 31;
    };
}

const base64 = (m: InboxMessage) => Buffer.from(hexToBytes(m.rawHex)).toString('base64');

/** The content scan and the located run's indexer over `world`, with every read logged. */
function locatedChainOver(world: LocatedWorld, options: ChainOptions = {}) {
    const nodeReads: number[] = [];
    const frameReads = new Set<number>();
    const chunks: [number, number][] = [];
    const hintRequests: URL[] = [];
    const prompts: DownloadRequest[] = [];
    const indexerHead = world.indexerHead ?? world.nodeHead;
    const atLevel = (level: number) => world.messages.filter((m) => m.level === level);
    const locator: FrameLocator = {
        head: async () => indexerHead,
        locateChunk: async (fromLevel, toLevel): Promise<ChunkResult> => {
            // As the indexer's requests do: an aborted run asks nothing more.
            options.signal?.throwIfAborted();
            options.onChunk?.(fromLevel, toLevel);
            chunks.push([fromLevel, toLevel]);

            const bytes = (toLevel - fromLevel + 1) * (world.bytesPerLevel ?? 200);

            if (
                options.failChunkAt !== undefined &&
                fromLevel <= options.failChunkAt &&
                options.failChunkAt <= toLevel
            ) {
                return {
                    status: 'unread',
                    fromLevel,
                    toLevel,
                    reason: 'http-status',
                    detail: 'HTTP 503',
                    bytes,
                    requests: 1,
                };
            }

            const frameCountByLevel = new Map<number, number>();

            for (const level of new Set(world.messages.map((m) => m.level))) {
                const count = world.indexerCount?.(level, atLevel(level).length) ?? atLevel(level).length;

                if (level >= fromLevel && level <= toLevel && count > 0) {
                    frameCountByLevel.set(level, count);
                }
            }

            return { status: 'located', fromLevel, toLevel, frameCountByLevel, bytes, requests: 1 };
        },
    };
    const node: NodeInbox = {
        head: async () => world.nodeHead,
        read: async (level): Promise<BlockInbox> => {
            nodeReads.push(level);

            const messages = atLevel(level).map((m) => ({ ...m }));

            if (messages.length > 0) {
                frameReads.add(level);
            }

            return { messages, appliedPrefixedCount: messages.length };
        },
        history: async () => null,
    };
    const scanner = createScanner({
        locator,
        node,
        cache: options.cache,
        minLevel: world.minLevel,
        confirmDownload: async (request) => {
            prompts.push(request);

            return options.confirmDownload ? options.confirmDownload(request) : true;
        },
        random: seeded(7),
        signal: options.signal,
    });

    // TzKT's answers to the located run's own questions.
    const senderOps = () => {
        const ops = new Map<string, { level: number; messagesCount: number; sender: string }>();

        for (const m of world.messages) {
            const op = ops.get(m.operationHash) ?? { level: m.level, messagesCount: 0, sender: m.source ?? '' };

            op.messagesCount += 1;
            ops.set(m.operationHash, op);
        }

        return [...ops.values(), ...(world.extraSenderOps ?? []).map((op) => ({ ...op, sender: SENDER }))]
            .sort((a, b) => a.level - b.level)
            .map((op, i) => ({ id: op.level * 1_000 + i, ...op }));
    };
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
    const tzkt: FetchLike = async (raw) => {
        const url = new URL(raw);
        const p = (name: string) => url.searchParams.get(name);
        const ge = Number(p('level.ge') ?? -Infinity);
        const le = Number(p('level.le') ?? Infinity);

        hintRequests.push(url);

        if (url.pathname.startsWith('/v1/blocks') && world.time === 'network-failure') {
            throw new TypeError('Failed to fetch');
        }

        if (url.pathname === '/v1/blocks') {
            if (world.time === 500) {
                return json({}, 500);
            }

            const level = world.estimatedLevel;

            return json(world.time === 'empty' || level < ge || level > le ? [] : [level]);
        }

        if (url.pathname.startsWith('/v1/blocks/')) {
            return world.time === 500 ? json({}, 500) : json(world.estimatedLevel);
        }

        if (url.pathname === '/v1/operations/sr_add_messages') {
            if (world.senderListing === 404) {
                return json({}, 404);
            }

            const senders = (p('sender') ?? p('sender.in') ?? '').split(',');
            const below = Number(p('id.lt') ?? Infinity);

            return json(
                senderOps()
                    .filter((op) => senders.includes(op.sender) && op.level >= ge && op.level <= le && op.id < below)
                    .sort((a, b) => b.id - a.id)
                    .slice(0, Number(p('limit')))
                    .map(({ id, level, messagesCount }) => ({ id, level, messagesCount })),
            );
        }

        if (url.pathname === '/v1/smart_rollups/inbox') {
            const levels = new Set((p('level.in') ?? '').split(',').map(Number));
            const after = Number(p('id.gt') ?? -1);

            return json(
                world.messages
                    .filter((m) => levels.has(m.level) && m.level >= ge && m.level <= le)
                    .map((m) => ({ id: m.level * 1_000 + m.messageIndex, level: m.level, payload: base64(m) }))
                    .filter((row) => row.id > after)
                    .sort((a, b) => a.id - b.id)
                    .slice(0, Number(p('limit'))),
            );
        }

        return json({}, 404);
    };
    const indexer = tzktIndexerHints({
        tzktApiUrl: 'https://indexer.test',
        fetchImpl: tzkt,
        sleep: async () => undefined,
        signal: options.signal,
    });
    const chain: ChainRunInput['chain'] = {
        ...depositChain(world.deposit),
        headLevel: () => scanner.scanHead(),
        scanRange: async (from, to) => {
            const messages = await scanner.scanRange(from, to);

            return options.mapScan ? options.mapScan(from, to, messages) : messages;
        },
        fetchBlock: (level) => scanner.fetchBlock(level),
    };

    return { scanner, chain, indexer, nodeReads, frameReads, chunks, hintRequests, prompts };
}

type LocatedChain = ReturnType<typeof locatedChainOver>;

interface RunOptions {
    hints?: LocatorHints | null;
    malformed?: string[];
    fromLevel?: number | null;
    toLevel?: number | null;
    receipts?: ReceiptsInput;
    /** The deployment's signing domain; the test deployment's when absent. */
    signingDomain?: SigningDomain | null;
}

function inputFor(world: LocatedWorld, chain: LocatedChain, options: RunOptions = {}): ChainRunInput {
    return {
        verify: {
            roundId: ROUND_ID,
            tenantId: TENANT,
            signingDomain: options.signingDomain === undefined ? DOMAIN : options.signingDomain,
            deploymentListed: true,
            receipts: options.receipts ?? { status: 'ok', receipts: buildReceipts() },
        },
        fromLevel: options.fromLevel ?? null,
        toLevel: options.toLevel ?? null,
        hints: { hints: options.hints ?? null, source: 'the link', malformed: options.malformed ?? [] },
        resolveKeys: async () => KEYS,
        resolveDeposit: async () => ({ level: world.deposit, confirmed: true }),
        lineage: () => LINEAGE,
        formPoolId: POOL,
        chain: chain.chain,
    };
}

/** The located run over a fresh chain; the chain is returned before the run settles. */
function located(world: LocatedWorld, options: RunOptions = {}, chainOptions: ChainOptions = {}) {
    const chain = locatedChainOver(world, chainOptions);
    const run = runLocatedVerification({
        ...inputFor(world, chain, options),
        indexer: chain.indexer,
        minLevel: world.minLevel ?? 1,
        coverage: () => chain.scanner.coverage(),
    });

    return { chain, run };
}

/** Today's run on its own fresh chain: `runChainVerification(input)`, with the scan's findings after it. */
async function today(world: LocatedWorld, options: RunOptions = {}): Promise<ChainRunResult & { chain: LocatedChain }> {
    const chain = locatedChainOver(world);
    const result = await runChainVerification(inputFor(world, chain, options));

    return { ...result, report: appendScanFindings(result.report, chain.scanner.coverage()), chain };
}

/** The window the located run judged, run on its own: no hints, the located bounds. */
async function windowRun(world: LocatedWorld, location: LocatedRunResult['location'], malformed: string[] = []) {
    const chain = locatedChainOver(world);

    return runChainVerification(
        inputFor(world, chain, { fromLevel: location?.floor ?? null, toLevel: location?.uRead ?? null, malformed }),
    );
}

const ADDED =
    /^(Time location:|SeedBatch copies more than 2,000 levels|Indexer cross-check:|The judged copies kept moving)/;
const withoutAdded = (report: VerificationReport): VerificationReport => ({
    ...report,
    findings: report.findings.filter((f) => !ADDED.test(f)),
});
const statusOf = (report: VerificationReport, id: string) => report.checks.find((c) => c.id === id)?.status;
const transcriptRef = (report: VerificationReport) =>
    report.references.find((r) => r.summary.startsWith('RoundTranscript'));
const batchRef = (report: VerificationReport) => report.references.find((r) => r.summary.startsWith('SeedBatch'));
const hintRequestsTo = (chain: LocatedChain, path: string) => chain.hintRequests.filter((u) => u.pathname === path);

/** The staging round: seven frame levels, the batch 25,535 levels below T. */
function fCase(overrides: Partial<LocatedWorld> = {}): LocatedWorld {
    return {
        messages: [
            ...batches(B),
            transcript(T),
            ...otherRounds([B + 4_000, B + 9_000, B + 15_000, B + 21_000, T - 40]),
        ],
        deposit: D,
        nodeHead: T + 600,
        estimatedLevel: T - 3,
        bytesPerLevel: 1_335,
        ...overrides,
    };
}

/** A small world: the batch at `batch`, the transcript at T, light noise. */
function small(batch: number, overrides: Partial<LocatedWorld> = {}): LocatedWorld {
    return {
        messages: [...batches(batch), transcript(T)],
        deposit: T - 1_000,
        nodeHead: T + 600,
        estimatedLevel: T - 3,
        bytesPerLevel: 200,
        ...overrides,
    };
}

describe('located scan', () => {
    it('LS1: the staging round is located by its time and sender and verified in one window, with no prompt', async () => {
        const world = fCase();
        const { chain, run } = located(world);
        const result = await run;
        const coverage = chain.scanner.coverage();

        expect(result.location).toEqual({
            used: true,
            estimatedLevel: T - 3,
            transcriptLevel: T,
            batchLevel: B,
            floor: 6_025_994,
            uRead: T + 597,
            reason: null,
            // The listing (two pages) and the candidate reads (two pages), outside the scan's byte count.
            senderSearch: { requests: 4, bytes: expect.any(Number), truncated: false },
        });
        expect(result.location?.senderSearch?.bytes).toBeGreaterThan(0);
        expect(result.report.verdict).toBe('verified');
        expect(result.report.scan).toMatchObject({ fromLevel: 6_025_994, toLevel: T + 597 });
        expect(result.hintedRun).toBeNull();
        expect(chain.prompts).toEqual([]);
        // 28,133 levels at 1.335 KB: about 37.6 MB.
        expect(coverage.indexerBytes).toBe((T + 597 - 6_025_994 + 1) * 1_335);
        expect(coverage.indexerBytes / 1e6).toBeCloseTo(37.6, 1);
        // The frame levels, two edges per call, the run's spot checks, the confirmed candidate.
        expect(coverage.nodeReads).toBeLessThanOrEqual(22);
        expect([...chain.frameReads].sort()).toEqual([...new Set(world.messages.map((m) => m.level))].sort());
        // One time request, at the signed stamp, bounded by both levels.
        const [time] = hintRequestsTo(chain, '/v1/blocks');

        expect(time.searchParams.get('timestamp.le')).toBe(new Date(TIME_MS).toISOString());
        expect(time.searchParams.get('level.le')).toBe(String(T + 600));
        expect(hintRequestsTo(chain, '/v1/blocks')).toHaveLength(1);
        expect(hintRequestsTo(chain, '/v1/operations/sr_add_messages')[0].searchParams.get('level.le')).toBe(
            String(T - 1),
        );
    });

    it('LS1b: a batch another account posted stays out of reach below T − 20,000, as today', async () => {
        const world = fCase({
            messages: [...batches(B, { source: OTHER_SENDER }), transcript(T), ...otherRounds([T - 40])],
        });
        const result = await located(world).run;
        const before = await today(world);

        expect(result.location).toMatchObject({ used: true, batchLevel: null, floor: T - 20_000 });
        expect(result.report.verdict).toBe('incomplete');
        expect(statusOf(result.report, 'commitment-hash')).toBe('unavailable');
        expect(before.report.verdict).toBe('incomplete');
    });

    describe('LS1c: the staging round at mainnet’s bytes per level', () => {
        const world = fCase({ bytesPerLevel: 8_800 });

        it('asks once for about 235 MB, and verifies when accepted', async () => {
            const { chain, run } = located(world);
            const result = await run;

            expect(result.location?.used).toBe(true);
            expect(result.report.verdict).toBe('verified');
            expect(chain.prompts).toHaveLength(1);
            expect(chain.prompts[0].estimateBytes / 1e6).toBeGreaterThan(230);
            expect(chain.prompts[0].estimateBytes / 1e6).toBeLessThan(240);
        });

        it('a decline rejects with no report and no further indexer request', async () => {
            let requestsAtPrompt = -1;
            const { chain, run } = located(
                world,
                {},
                {
                    confirmDownload: async () => {
                        requestsAtPrompt = chain.chunks.length + chain.hintRequests.length;

                        return false;
                    },
                },
            );

            await expect(run).rejects.toBeInstanceOf(DownloadDeclinedError);
            expect(chain.prompts).toHaveLength(1);
            expect(chain.chunks.length + chain.hintRequests.length).toBe(requestsAtPrompt);
        });
    });

    it('LS2: a batch within 20,000 levels of T leaves the parity floor', async () => {
        const world = small(T - 8_000, { deposit: T - 11 });
        const result = await located(world).run;

        expect(result.location).toMatchObject({ used: true, batchLevel: T - 8_000, floor: T - 20_000 });
        expect(result.report.scan?.fromLevel).toBe(Math.min(T - 20_000, T - 11));
        expect(result.report.verdict).toBe('verified');
    });

    describe('LS3: hints, a reader’s range or no receipts leave today’s run as it is', () => {
        const world = small(T - 500);
        const cases: [string, RunOptions][] = [
            ['a transcript hint', { hints: { transcript: { level: T, operationHash: `op-level-${T}` } } }],
            ['a reader’s from', { fromLevel: T - 600 }],
            ['a reader’s to', { toLevel: T + 10 }],
            ['no receipts', { receipts: { status: 'absent' } }],
        ];

        for (const [name, options] of cases) {
            it(name, async () => {
                const { chain, run } = located(world, options);
                const { location, ...result } = await run;
                const before = await today(world, options);

                expect(location?.used ?? false).toBe(false);
                expect(location).toBeNull();
                expect(result).toEqual({
                    report: before.report,
                    hintedRun: before.hintedRun,
                    preliminary: before.preliminary,
                    hints: before.hints,
                });
                expect(chain.hintRequests).toEqual([]);
            });
        }
    });

    describe('LS4: a round that cannot be placed in time falls back to today’s run, with one line saying why', () => {
        const world = small(T - 500);
        const cases: [string, LocatedWorld, RunOptions, RegExp][] = [
            [
                'no signed time',
                world,
                { receipts: { status: 'ok', receipts: buildReceipts(false) } },
                /^no signed CommandAccepted or CommandRejected before RoundEnded/,
            ],
            ['the time lookup answers 500 after the retries', { ...world, time: 500 }, {}, /HTTP 500/],
            ['the time lookup is empty', { ...world, time: 'empty' }, {}, /^the indexer has no block at or before /],
            [
                'the time lookup fails to reach the indexer after the retries',
                { ...world, time: 'network-failure' },
                {},
                /^the indexer could not be reached \(Failed to fetch\)/,
            ],
            ['no signing domain', world, { signingDomain: null }, /^no signing domain is known/],
        ];

        for (const [name, w, options, reason] of cases) {
            it(name, async () => {
                const result = await located(w, options).run;
                const before = await today(w, options);
                const notUsed = result.report.findings.filter((f) => f.startsWith('Time location:'));

                expect(result.location).toMatchObject({
                    used: false,
                    reason: expect.stringMatching(reason),
                    senderSearch: null,
                });
                expect(notUsed).toHaveLength(1);
                expect(result.report.findings[0]).toBe(notUsed[0]);
                expect(notUsed[0]).toMatch(/^Time location: not used — /);
                expect(withoutAdded(result.report)).toEqual(withoutAdded(before.report));
                expect(result.report.verdict).toBe(before.report.verdict);
            });
        }
    });

    it('LS4e: on a fallback the scan’s findings follow the not-used line, before verifyRound’s own', async () => {
        const malformed = ['transcriptLevel is not a level'];
        const world = small(T - 500, {
            time: 'empty',
            indexerCount: (level, count) => (level === T - 500 ? count + 1 : count),
        });
        const result = await located(world, { malformed }).run;
        const before = await runChainVerification(inputFor(world, locatedChainOver(world), { malformed }));
        const findings = result.report.findings;

        expect(result.location?.used).toBe(false);
        expect(findings[0]).toBe(`Locator hint from the link: ignored: malformed (${malformed[0]})`);
        expect(findings[1]).toMatch(/^Time location: not used — /);
        expect(findings[2]).toMatch(new RegExp(`^Indexer cross-check: at level ${T - 500} the indexer lists 11 `));
        expect(findings.slice(3)).toEqual(before.report.findings.slice(1));
    });

    it('LS4b: an unread chunk during the transcript search rejects, with no fallback run', async () => {
        const world = small(T - 500);
        const { chain, run } = located(world, {}, { failChunkAt: T });

        await expect(run).rejects.toBeInstanceOf(ScanIncompleteError);
        expect(chain.chunks.every(([from, to]) => from >= T - 603 && to <= T + 597)).toBe(true);
        expect(hintRequestsTo(chain, '/v1/operations/sr_add_messages')).toEqual([]);
    });

    it('LS4c: a search that has to reach far asks once; a decline rejects, with no fallback scan', async () => {
        // The transcript 6,000 levels above where the time places it: the
        // doubled reach's projection crosses the allowance.
        const world = small(T - 500, { estimatedLevel: T - 6_000, bytesPerLevel: 8_800 });
        const { chain, run } = located(world, {}, { confirmDownload: async () => false });

        await expect(run).rejects.toBeInstanceOf(DownloadDeclinedError);
        expect(chain.prompts).toHaveLength(1);
        expect(chain.chunks.every(([from, to]) => from >= T - 6_600 && to <= T + 600)).toBe(true);
        expect(hintRequestsTo(chain, '/v1/operations/sr_add_messages')).toEqual([]);
    });

    describe('LS4d: a contradiction or an abort during the search rejects, with no fallback', () => {
        it('the indexer hides the transcript at the search’s upper edge', async () => {
            const world = small(T - 500, {
                estimatedLevel: T - 600,
                indexerCount: (level, count) => (level === T ? 0 : count),
            });
            const { chain, run } = located(world);

            await expect(run).rejects.toBeInstanceOf(IndexerContradictionError);
            await expect(run).rejects.toMatchObject({ levels: [T] });
            expect(chain.chunks.every(([from]) => from >= T - 1_200)).toBe(true);
            expect(hintRequestsTo(chain, '/v1/operations/sr_add_messages')).toEqual([]);
        });

        it('an abort', async () => {
            const controller = new AbortController();
            const { chain, run } = located(
                small(T - 500),
                {},
                { signal: controller.signal, onChunk: () => controller.abort() },
            );

            await expect(run).rejects.toMatchObject({ name: 'AbortError' });
            expect(chain.chunks).toHaveLength(1);
            expect(hintRequestsTo(chain, '/v1/operations/sr_add_messages')).toEqual([]);
        });
    });

    it('LS5: only an unauthenticated transcript near the time falls back', async () => {
        const world = small(T - 500, {
            messages: [...batches(T - 500), transcript(T, { seed: FOREIGN_SEED })],
            nodeHead: T + 50,
        });
        const result = await located(world).run;
        const before = await today(world);

        expect(result.location).toMatchObject({
            used: false,
            estimatedLevel: T - 3,
            reason: `no authenticated RoundTranscript for this round between levels ${T - 603} and ${T + 50}`,
        });
        expect(withoutAdded(result.report)).toEqual(withoutAdded(before.report));
    });

    it('LS6: an earlier transcript copy inside the window re-anchors the window to it', async () => {
        const world = small(T - 8_000, {
            messages: [...batches(T - 8_000), transcript(T - 1_000), transcript(T)],
            deposit: T - 2_000,
        });
        const result = await located(world).run;
        const window = await windowRun(world, result.location);

        expect(result.location).toMatchObject({ used: true, transcriptLevel: T - 1_000, floor: T - 21_000 });
        expect(transcriptRef(result.report)?.level).toBe(T - 1_000);
        expect(result.report.verdict).toBe('verified');
        expect(withoutAdded(result.report)).toEqual(window.report);
    });

    it('LS6b: copies that keep moving earlier stop the re-anchoring at its cap, and say so', async () => {
        // Single batch copies another account posted every 1,500 levels below
        // the sender's batch: each re-anchored window reaches the next one.
        const batch = T - 25_000;
        const copies = [1_500, 3_000, 4_500, 6_000, 7_500].map(
            (d) => batches(batch - d, { source: OTHER_SENDER, operationHash: `op-copy-${batch - d}` })[5],
        );
        const world = small(batch, { messages: [...batches(batch), ...copies, transcript(T)] });
        const result = await located(world).run;
        const window = await windowRun(world, result.location);
        // The first window starts at batch − 2,000; three re-anchors follow the copies down.
        const floor = batch - 6_500;

        expect(result.location).toMatchObject({ used: true, batchLevel: batch, floor });
        expect(batchRef(result.report)?.level).toBe(batch - 6_000);
        expect(result.report.findings).toContain(
            `The judged copies kept moving earlier; the window ends at level ${floor}.`,
        );
        expect(result.report.verdict).toBe('verified');
        expect(withoutAdded(result.report)).toEqual(window.report);
        expect(result.report.findings.filter((f) => !window.report.findings.includes(f))).toEqual([
            expect.stringMatching(/^Time location: /),
            expect.stringMatching(/^SeedBatch copies more than 2,000 levels/),
            `The judged copies kept moving earlier; the window ends at level ${floor}.`,
        ]);
    });

    it('LS7: a conflicting earlier batch another account posted is read by the content pass and judged', async () => {
        const world = small(T - 8_000, {
            messages: [
                ...batches(T - 8_000),
                ...batches(T - 9_000, { source: OTHER_SENDER, conflicting: true }),
                transcript(T),
            ],
        });
        const result = await located(world).run;
        const window = await windowRun(world, result.location);

        expect(result.location).toMatchObject({ used: true, batchLevel: T - 8_000 });
        expect(batchRef(result.report)?.level).toBe(T - 9_000);
        expect(statusOf(result.report, 'commitment-hash')).toBe('fail');
        expect(result.report.verdict).toBe('failed');
        expect(withoutAdded(result.report)).toEqual(window.report);
    });

    it('LS8: malformed hint fates, then the time line, the residual line, the scan findings, then verifyRound’s own', async () => {
        const malformed = ['transcriptLevel is not a level', 'seedBatchOp is empty'];
        const world = fCase({
            messages: [...fCase().messages, transcript(T - 100, { seed: FOREIGN_SEED, source: OTHER_SENDER })],
            indexerCount: (level, count) => (level === B ? count + 1 : count),
        });
        const result = await located(world, { malformed }).run;
        const window = await windowRun(world, result.location, malformed);
        const findings = result.report.findings;

        expect(result.location?.used).toBe(true);
        expect(findings.slice(0, 2)).toEqual(
            malformed.map((m) => `Locator hint from the link: ignored: malformed (${m})`),
        );
        expect(findings[2]).toBe(
            `Time location: the server-signed time (CommandAccepted at sequence 4, ${new Date(TIME_MS).toISOString()}) ` +
                `maps to L1 level ≈${T - 3}; the transcript copy judged is at level ${T}; the SeedBatch covering index ` +
                `2007 was located at level ${B} through the transcript sender’s operations; levels 6025994–${T + 597} ` +
                'were read. A time and a sender only choose where to look; every check rests on the messages read from ' +
                'the Tezos RPC.',
        );
        expect(findings[3]).toBe(
            'SeedBatch copies more than 2,000 levels below the batch, and below both the deposit and 20,000 levels ' +
                'before the transcript, were not read unless the transcript’s sender posted them; an earlier ' +
                'conflicting batch there would change this result.',
        );
        expect(findings[4]).toMatch(/^Indexer cross-check: at level 6027994 the indexer lists 11 /);
        expect(findings.slice(5)).toEqual(window.report.findings.slice(2));
        expect(findings.slice(5).some((f) => f.startsWith('Skipped 1 RoundTranscript'))).toBe(true);
    });

    it('LS9: the time off by 5,000 levels either way changes neither the verdict nor the checks', async () => {
        const reports: VerificationReport[] = [];
        const used: (boolean | undefined)[] = [];

        for (const estimatedLevel of [T - 3, T - 5_000, T + 5_000]) {
            const result = await located(small(T - 500, { estimatedLevel, nodeHead: T + 6_000 })).run;

            reports.push(result.report);
            used.push(result.location?.used);
        }

        expect(used).toEqual([true, true, false]);
        expect(reports.map((r) => r.verdict)).toEqual(['verified', 'verified', 'verified']);
        expect(reports.map((r) => r.checks.map((c) => [c.id, c.status]))).toEqual(
            Array.from({ length: 3 }, () => reports[0].checks.map((c) => [c.id, c.status])),
        );
    });

    describe('LS10: on every located world, the report is the window’s, and the reads contain today’s below T', () => {
        const worlds: [string, LocatedWorld][] = [
            ['LS1', fCase()],
            ['LS2', small(T - 8_000, { deposit: T - 11 })],
            [
                'LS6',
                small(T - 8_000, {
                    messages: [...batches(T - 8_000), transcript(T - 1_000), transcript(T)],
                    deposit: T - 2_000,
                }),
            ],
            [
                'LS7',
                small(T - 8_000, {
                    messages: [
                        ...batches(T - 8_000),
                        ...batches(T - 9_000, { source: OTHER_SENDER, conflicting: true }),
                        transcript(T),
                    ],
                }),
            ],
            ['LS16', small(T + 700, { messages: [...batches(T + 700), transcript(T)], nodeHead: T + 900 })],
            [
                'LS18',
                small(T - 50_000, {
                    messages: [...batches(T - 50_000), ...batches(T + 3), transcript(T)],
                    nodeHead: T + 50,
                }),
            ],
            ['LS19', small(T - 100, { deposit: T - 60_000 })],
            [
                'LS20',
                small(T - 30_000, {
                    messages: [...batches(T - 30_000), transcript(T - 25_000), transcript(T)],
                    deposit: T - 22_000,
                }),
            ],
            [
                'LS21',
                small(T - 25_000, {
                    messages: [
                        ...batches(T - 25_000),
                        ...batches(T - 26_500, { operationHash: 'op-duplicate' }).slice(5, 6),
                        transcript(T),
                    ],
                    extraSenderOps: Array.from({ length: 200 }, (_, i) => ({
                        level: T - 30_000 - i,
                        messagesCount: 2,
                    })),
                }),
            ],
            ['LS23', small(T - 500, { minLevel: T - 5_000 })],
            ['a head 14,000 levels above T', small(T - 500, { nodeHead: T + 14_000 })],
        ];

        for (const [name, world] of worlds) {
            it(name, async () => {
                const { chain, run } = located(world);
                const result = await run;
                const window = await windowRun(world, result.location);
                const before = await today(world);
                const todayFrom = Math.max(before.report.scan?.fromLevel ?? Infinity, world.minLevel ?? 1);

                expect(result.location?.used).toBe(true);
                expect(withoutAdded(result.report)).toEqual(window.report);
                // I4(a): every level today's window reads up to T was covered by the located run.
                expect(chain.scanner.coverage().covered.some((c) => c.fromLevel <= todayFrom && c.toLevel >= T)).toBe(
                    true,
                );

                for (const level of before.chain.frameReads) {
                    if (level <= T) {
                        expect(chain.frameReads.has(level)).toBe(true);
                    }
                }
            });
        }
    });

    it('LS11: a sender listing that answers 404 leaves the window without the batch term', async () => {
        const world = small(T - 500, { senderListing: 404 });
        const result = await located(world).run;

        expect(result.location).toMatchObject({ used: true, batchLevel: null, floor: T - 20_000 });
        expect(result.report.verdict).toBe('verified');
    });

    it('LS12 and LS13: an unread chunk in the window rejects; Retry reads only that chunk, then verifies', async () => {
        const world = small(T - 500);
        const cache = new RangeCache();
        const first = located(world, {}, { cache, failChunkAt: T - 15_000 });
        const error = await first.run.catch((e: unknown) => e);

        expect(error).toBeInstanceOf(ScanIncompleteError);

        const [unread] = (error as ScanIncompleteError).unread;
        const retry = located(world, {}, { cache });
        const result = await retry.run;

        expect(result.location?.used).toBe(true);
        expect(result.report.verdict).toBe('verified');
        expect(retry.chain.chunks.length).toBeGreaterThan(0);
        expect(retry.chain.chunks.every(([from, to]) => from >= unread.fromLevel && to <= unread.toLevel)).toBe(true);
    });

    it('LS14: with the head three levels above T, the window ends at the head', async () => {
        const result = await located(small(T - 500, { nodeHead: T + 3 })).run;

        expect(result.location).toMatchObject({ used: true, uRead: T + 3 });
        expect(result.report.scan).toMatchObject({ toLevel: T + 3, headLevel: T + 3 });
        expect(result.report.verdict).toBe('verified');
    });

    it('LS15: a transcript not yet on L1 falls back to today’s run once', async () => {
        const world = small(T - 500, { messages: batches(T - 500) });
        const { chain, run } = located(world);
        const result = await run;
        const before = await today(world);

        expect(result.location).toMatchObject({ used: false });
        expect(result.location?.reason).toMatch(/^no authenticated RoundTranscript/);
        expect(withoutAdded(result.report)).toEqual(withoutAdded(before.report));
        expect(hintRequestsTo(chain, '/v1/blocks')).toHaveLength(1);
    });

    it('LS16: the only covering copy above the window leaves the located run weaker than today’s', async () => {
        const world = small(T + 700, { messages: [...batches(T + 700), transcript(T)], nodeHead: T + 900 });
        const result = await located(world).run;
        const before = await today(world);

        expect(result.location).toMatchObject({ used: true, batchLevel: null, uRead: T + 597 });
        expect(result.report.verdict).toBe('incomplete');
        expect(statusOf(result.report, 'commitment-hash')).toBe('unavailable');
        expect(before.report.verdict).toBe('failed');
        expect(statusOf(before.report, 'commitment-order')).toBe('fail');
    });

    it('LS17: an abort during the window scan rejects, with no report', async () => {
        const controller = new AbortController();
        const { chain, run } = located(
            small(T - 500),
            {},
            {
                signal: controller.signal,
                onChunk: (fromLevel) => {
                    if (fromLevel < T - 603) {
                        controller.abort();
                    }
                },
            },
        );

        await expect(run).rejects.toMatchObject({ name: 'AbortError' });
        // The search and the sender listing ran; the window stopped at its first chunk.
        expect(hintRequestsTo(chain, '/v1/operations/sr_add_messages').length).toBeGreaterThan(0);
        expect(chain.chunks.filter(([from]) => from < T - 603)).toHaveLength(1);
    });

    it('LS18: a sender’s copy 50,000 levels down is judged, where today’s window reads only a later one', async () => {
        const world = small(T - 50_000, {
            messages: [...batches(T - 50_000), ...batches(T + 3), transcript(T)],
            nodeHead: T + 50,
        });
        const result = await located(world).run;
        const before = await today(world);

        expect(result.location).toMatchObject({ used: true, batchLevel: T - 50_000, floor: T - 52_000, uRead: T + 50 });
        expect(result.report.verdict).toBe('verified');
        expect(before.report.verdict).toBe('failed');
        // The difference is a level today's run did not read.
        expect(before.chain.frameReads.has(T - 50_000)).toBe(false);
    });

    it('LS19: a deposit 60,000 levels down takes the window down to it', async () => {
        const result = await located(small(T - 100, { deposit: T - 60_000 })).run;

        expect(result.location).toMatchObject({ used: true, batchLevel: T - 100, floor: T - 60_000 });
        expect(result.report.scan?.fromLevel).toBe(T - 60_000);
        expect(result.report.verdict).toBe('verified');
    });

    it('LS20: a copy applied before the session existed fails session-before-transcript', async () => {
        const world = small(T - 30_000, {
            messages: [...batches(T - 30_000), transcript(T - 25_000), transcript(T)],
            deposit: T - 22_000,
        });
        const result = await located(world).run;
        const check = result.report.checks.find((c) => c.id === 'session-before-transcript');

        expect(result.location).toMatchObject({ used: true, transcriptLevel: T - 25_000, floor: T - 45_000 });
        expect(result.report.verdict).toBe('failed');
        expect(check?.status).toBe('fail');
        expect(check?.detail).toContain('REJECT_SESSION_MISSING');
    });

    it('LS21: a same-sender duplicate inside the margin, past the candidate budget, becomes the judged copy', async () => {
        const batch = T - 25_000;
        const duplicate = batch - 1_500;
        // Two hundred busier operations of the same sender: the duplicate's
        // single message falls outside the budget, the ten-message batch does not.
        const extraSenderOps = Array.from({ length: 200 }, (_, i) => ({ level: T - 30_000 - i, messagesCount: 2 }));
        const world = small(batch, {
            messages: [
                ...batches(batch),
                ...batches(duplicate, { operationHash: 'op-duplicate' }).slice(5, 6),
                transcript(T),
            ],
            extraSenderOps,
        });
        const result = await located(world).run;

        expect(result.location).toMatchObject({ used: true, batchLevel: batch });
        expect(batchRef(result.report)?.level).toBe(duplicate);
        expect(result.report.scan?.fromLevel).toBeLessThanOrEqual(batch - 2_000);
        expect(result.report.verdict).toBe('verified');
    });

    describe('LS22: a transcript that is not judged again by the window run rejects, with no report', () => {
        it('reorganised away near the head between the search and the window: the run’s node read of it contradicts the new listing', async () => {
            const world = small(T - 500, { nodeHead: T + 1 });
            const { run } = located(
                world,
                {},
                {
                    onChunk: (fromLevel) => {
                        if (fromLevel < T - 603) {
                            world.messages = world.messages.filter((m) => m.level !== T);
                        }
                    },
                },
            );

            await expect(run).rejects.toBeInstanceOf(IndexerContradictionError);
            await expect(run).rejects.toMatchObject({ levels: [T] });
        });

        it('the window’s scan no longer holds it: transcript-not-rejudged', async () => {
            const world = small(T - 500, { nodeHead: T + 1 });
            const { run } = located(
                world,
                {},
                {
                    mapScan: (fromLevel, _toLevel, messages) =>
                        fromLevel < T - 603 ? messages.filter((m) => m.level !== T) : messages,
                },
            );

            await expect(run).rejects.toBeInstanceOf(IndexerContradictionError);
            await expect(run).rejects.toMatchObject({
                name: 'TranscriptNotRejudgedError',
                reason: 'transcript-not-rejudged',
                transcriptLevel: T,
            });
            await expect(run).rejects.toThrow(/located at level 6053529 was not found again/);
        });
    });

    it('LS23: the administrator’s origination bounds the window, the sender search and every node read', async () => {
        const world = small(T - 500, { minLevel: T - 5_000 });
        const { chain, run } = located(world);
        const result = await run;

        expect(result.location).toMatchObject({ used: true, floor: T - 5_000 });
        expect(result.report.scan?.fromLevel).toBe(T - 5_000);
        expect(result.report.verdict).toBe('verified');
        expect(Math.min(...chain.nodeReads)).toBeGreaterThanOrEqual(T - 5_000);
        expect(hintRequestsTo(chain, '/v1/operations/sr_add_messages')[0].searchParams.get('level.ge')).toBe(
            String(T - 5_000),
        );
    });
});
