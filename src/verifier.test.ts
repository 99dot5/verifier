// @vitest-environment node
// End-to-end: encode a synthetic round as real wire frames (Borsh + genuine
// Ed25519 signatures over the blake2b pre-hash), then verify it.
//
// A round is now ONE `RoundTranscript` message, so the fixture is a SeedBatch
// at level L and the transcript at L+1. The round's maths is not hard-coded:
// the expected payout is taken from the same replayer the verifier calls, and
// that replayer is pinned against the shared golden vectors by hilo/v1.test.ts /
// plinko/v1.test.ts. What this file exercises is the orchestration around it —
// earliest-wins, the commitment pair, signatures, the optional client-seed
// check, and every way a round can fail to verify.
import * as ed from '@noble/ed25519';
import { blake2b } from '@noble/hashes/blake2.js';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import type { DepositLocation } from './chain/deposit';
import type { InboxMessage } from './chain/inbox';
import {
    ACTIONS_AFTER_SETTLE_CHECK_ID,
    describeBracket,
    evaluateSessionBeforeTranscript,
    SESSION_BEFORE_TRANSCRIPT_CHECK_ID,
    supportedGameTypes,
    verifyRound,
} from './verifier';
import {
    DEFAULT_SCAN_DEPTH,
    resolveReceiptsDeposit,
    runChainVerification,
    runPastedVerification,
    type ChainRunInput,
    type PreliminaryReport,
} from './run';
import type { AdminLineage } from './chain/admin-lineage';
import { locateSessionDeposit, sessionKeyScriptExprHash, type DepositChain } from './chain/deposit';
import type { LocatorHints } from './receipts/handoff';
import {
    actionTypeOf,
    bytesToHex,
    crash,
    decodeExternalMessage,
    GAME_SEED_DERIVATIONS,
    hexToBytes,
    hilo,
    hydra,
    mines,
    plinko,
    type Replayer,
    serverSeedCommitment,
    tagOf,
    unitsToDecimalString,
} from '@99dot5/round-replay';
import { RACE_BAND_TICKS, REJECTION_CHECK_ID } from './verify/rejections';
import { vectorsUrl, type VectorGame } from './verify/vectors-path';
import { encodeEdpk, sequencerSigningPreimage, type SigningDomain } from './wire/signature';
import {
    commandFrame,
    serverFrame,
    type CommandGameSpec,
    type MoneySpec,
    type ServerFrameSpec,
} from './receipts/fixtures';
import { PROJECTION_CHECK_ID } from './verify/projection';
import { STAKE_CHECK_ID } from './verify/stake';
import { OPENER_SEED_CHECK_ID, PRE_BET_SEED_CHECK_ID } from './verify/seed-commitment';
import { computeCommitment } from './receipts/commitment';
import type { ImportedReceipts } from './receipts/import';
import type { KeySet, ReceiptsInput, ScanContext } from './verifier';

/** The seed rule every listed deployment selects today. */

// ── Test-local Borsh writer + frame builder ─────────────────────────────

const SIGNING_SEED = new Uint8Array(32).fill(1);
const PUBLIC_KEY = ed.getPublicKey(SIGNING_SEED);
const TENANT = 'test-tenant';
const POOL = 'standard';

function u8(v: number): number[] {
    return [v];
}

function u32(v: number): number[] {
    return [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff];
}

function u64(v: bigint): number[] {
    return Array.from({ length: 8 }, (_, i) => Number((v >> BigInt(8 * i)) & 0xffn));
}

/** Amounts on the wire are 16-byte little-endian atomic units. */
function u128(v: bigint): number[] {
    return Array.from({ length: 16 }, (_, i) => Number((v >> BigInt(8 * i)) & 0xffn));
}

function str(v: string): number[] {
    const bytes = Array.from(new TextEncoder().encode(v));

    return [...u32(bytes.length), ...bytes];
}

function byteVec(v: Uint8Array): number[] {
    return [...u32(v.length), ...Array.from(v)];
}

function uuid(hyphenated: string): number[] {
    return Array.from(hexToBytes(hyphenated.replaceAll('-', '')));
}

/**
 * Shadownet and the fixture rollup — the SIGNING DOMAIN every test frame is
 * signed for (#952). Hashed ahead of the envelope, never on the wire; the
 * verifier must be told which instance it is checking against.
 */
const DOMAIN: SigningDomain = { chainId: 'NetXsqzbfFenSTS', rollupAddress: 'sr1TMxAUtDA4sDL7C4r39L18iQjhRcBRzd8a' };

/** A second deployment of the same tenant on the same chain, under the same key. */
const OTHER_ROLLUP: SigningDomain = { ...DOMAIN, rollupAddress: 'sr1LVZW8AUSQehXjvn3NV6BJJKdA3vheqhZL' };

function frame(
    level: number,
    payloadBody: number[],
    signingSeed: Uint8Array = SIGNING_SEED,
    domain: SigningDomain = DOMAIN,
): InboxMessage {
    // VersionedEnvelope::V1(PoolScopedMessage { tenant, pool, payload }).
    const payload = new Uint8Array([...u8(0), ...str(TENANT), ...str(POOL), ...payloadBody]);
    // sig = ed25519(blake2b-256(chain_id ‖ rollup_address ‖ payload)) — the
    // injector's rule; the domain is what the kernel hashes in for itself.
    const signature = ed.sign(
        blake2b(sequencerSigningPreimage(domain, payload), { dkLen: 32 }),
        Uint8Array.from(signingSeed),
    );
    const raw = new Uint8Array([0x09, 0x95, ...signature, ...payload]);
    const envelope = decodeExternalMessage(raw);

    if (!envelope) {
        throw new Error('test frame failed to decode');
    }

    return { level, operationHash: `op-level-${level}`, messageIndex: 0, rawHex: bytesToHex(raw), envelope };
}

// ── The round under test ────────────────────────────────────────────────

const ROUND_ID = '9a256790-c7c0-47b0-9a5b-6ed2905d2df1';
const SESSION_ID = 'e2b6419a-ec4b-4eef-bdfa-802b6f338fc2';
const SEED_INDEX = 137n;
const BATCH_START = 100n;
const BATCH_LEVEL = 1000;
const TRANSCRIPT_LEVEL = 1005;
const STAKE_MUTEZ = 100_000_000n;
/**
 * The same amount the transcript carries, as the decimal string a signed
 * `Money` spells it with. DERIVED, never a second literal: the stake
 * cross-check compares exactly these two, so a hand-typed copy could drift
 * and turn a fixture bug into a green verdict.
 */
const STAKE_DECIMAL = unitsToDecimalString(STAKE_MUTEZ, 6);
const STAKE_MONEY = { asset: 'TEZ', value: STAKE_DECIMAL };

/** A named seed scenario from a game's vectors file (`hex_scenarios`). */
interface HexScenario {
    name: string;
    predicate: string;
    server_seed_hex: string;
    effective_client_seed_hex: string;
    /** HiLo scenarios only. */
    winning_direction_at_1?: 'higher' | 'lower';
}

/**
 * Seeds are read from a NAMED scenario, never written here: the vectors
 * generator re-searches each scenario for its predicate whenever the seed
 * derivation changes, so this file follows the seed instead of pinning one.
 */
function hexScenario(game: VectorGame, name: string): HexScenario {
    const file: { hex_scenarios?: HexScenario[] } = JSON.parse(readFileSync(fileURLToPath(vectorsUrl(game)), 'utf8'));
    const scenario = file.hex_scenarios?.find((candidate) => candidate.name === name);

    if (scenario === undefined) {
        throw new Error(`${game} vectors.json has no hex_scenarios entry named ${name}`);
    }

    return scenario;
}

/**
 * `client_seed` on the wire is the blake2b-256 of the player's text, and the
 * engine consumes its lowercase hex. The default pair is the scenario
 * `hilo-higher-wins-at-1` (rank of the card at index 1 >= rank at index 0), so
 * the HiLo `higher` below WINS: a losing guess would settle the round and the
 * cashout would trail the settle, which fails the round under the
 * actions-after-settle check — a different test.
 */
const HILO_SCENARIO = hexScenario('hilo', 'hilo-higher-wins-at-1');
const CLIENT_SEED = hexToBytes(HILO_SCENARIO.effective_client_seed_hex);
const SERVER_SEED = hexToBytes(HILO_SCENARIO.server_seed_hex);
/** The commitment the pool published for `SERVER_SEED` at `SEED_INDEX` — what an honest opener and echo state. */
const SEED_COMMITMENT = serverSeedCommitment(bytesToHex(SERVER_SEED));

// ── The player's receipts for this round ────────────────────────────────
//
// The transcript's `player_commitment` is the REAL fold over the command
// frames below, not a filler pattern: the third proof group compares the two,
// so a fixture that stated an arbitrary 32 bytes could only ever exercise the
// mismatch path.

const SESSION_SEED = new Uint8Array(32).fill(2);
const SESSION_PUBLIC_KEY = ed.getPublicKey(SESSION_SEED);
const BET_REQUEST = '11111111-1111-4111-8111-111111111111';
const CASHOUT_REQUEST = '22222222-2222-4222-8222-222222222222';

/**
 * The default round is HiLo, opened and cashed out with no guess in between —
 * TWO actions and TWO commands, so the action indices and the commands line up
 * one-to-one. The fourth proof compares them, so a fixture whose commands do
 * not correspond to its actions would fail for its own reasons rather than for
 * the reason each case is about.
 *
 * Both arms are SET, where they used to be empty submessages: the projection
 * reads the game arm, so an arm-less command exercises only the "no arm set"
 * path and would leave every rule in the table untested.
 */
const HILO_ARM: CommandGameSpec = { game: 'hilo' };

/**
 * `amount` takes `null` — not `undefined` — to mean "write no amount".
 * Passing `undefined` re-selects the default, which is the footgun that let
 * two of the tests below keep a stake they meant to omit and pass for the
 * wrong reason.
 */
function betCommand(
    game: CommandGameSpec = HILO_ARM,
    clientSeed?: string,
    amount: MoneySpec | null = STAKE_MONEY,
    // The seed commitment the player echoes from the server's promise (ADR
    // 0025). The honest default is the chain's; `null` writes no echo, the
    // shape of a client that held no promise when it bet.
    serverSeedHash: Uint8Array | null = SEED_COMMITMENT,
): Uint8Array {
    return commandFrame(SESSION_SEED, {
        requestId: BET_REQUEST,
        sessionId: SESSION_ID,
        payloadCase: 'placeBet',
        clientSeed,
        amount: amount ?? undefined,
        serverSeedHash: serverSeedHash ?? undefined,
        game,
    });
}

function cashOutCommand(game: CommandGameSpec = HILO_ARM): Uint8Array {
    return commandFrame(SESSION_SEED, {
        requestId: CASHOUT_REQUEST,
        sessionId: SESSION_ID,
        payloadCase: 'cashOut',
        // The round id the PLAYER signs; the suppression rule scopes a command
        // into the round by this field and by nothing the server chose.
        roundId: ROUND_ID,
        game,
    });
}

const BET_COMMAND = betCommand();
const CASHOUT_COMMAND = cashOutCommand();

const PLAYER_COMMITMENT = computeCommitment([BET_COMMAND, CASHOUT_COMMAND]);

/** Everything about an export that is not one of its `ImportedReceipts` fields. */
interface ReceiptShape {
    bet?: Uint8Array;
    /** `RoundStartedEvent.stake`; `null` writes no field (a producer predating it). */
    openerStake?: MoneySpec | null;
    /**
     * `RoundStartedEvent.server_seed_commitment` (ADR 0025);
     * the honest default is the chain's commitment at its index; `null`
     * models a server omitting the required message.
     */
    openerSeed?: { hash: Uint8Array; index: bigint } | null;
    cashOut?: Uint8Array;
    /** `RoundEndedEvent.cause`; the honest default is the player's own action. */
    cause?: 'player-action' | 'system-sweep' | 'transcript-cap';
    /** Omit the cause entirely, reproducing a producer predating field 4. */
    noCause?: boolean;
}

function roundEndedSpec(commitment: Uint8Array, shape: ReceiptShape = {}): ServerFrameSpec {
    return {
        sequence: 5,
        sessionId: SESSION_ID,
        relatedRequestId: CASHOUT_REQUEST,
        payload: {
            case: 'roundEnded',
            roundId: ROUND_ID,
            actionIndex: 1,
            playerCommitment: commitment,
            ...(shape.noCause ? {} : { cause: shape.cause ?? ('player-action' as const) }),
        },
    };
}

/** The opener's seed fields for a shape: the honest default, a stated pair, or none. */
function openerSeedFields(openerSeed: ReceiptShape['openerSeed']): {
    serverSeedCommitment?: { hash: Uint8Array; index: bigint };
} {
    if (openerSeed === null) {
        return {};
    }

    const seed = openerSeed ?? { hash: SEED_COMMITMENT, index: SEED_INDEX };

    return { serverSeedCommitment: seed };
}

/** The commitment over a shape's two commands — what an honest server states. */
function commitmentOf(shape: ReceiptShape = {}): Uint8Array {
    return computeCommitment([shape.bet ?? BET_COMMAND, shape.cashOut ?? CASHOUT_COMMAND]);
}

/** The honest export: two commands, both accepted, both placed by the server. */
function buildReceipts(overrides: Partial<ImportedReceipts> = {}, shape: ReceiptShape = {}): ImportedReceipts {
    const frame = (spec: ServerFrameSpec) => ({
        sequence: BigInt(spec.sequence),
        payloadCase: spec.payload.case,
        relatedRequestId: spec.relatedRequestId,
        frame: serverFrame(SIGNING_SEED, spec),
    });
    const bet = shape.bet ?? BET_COMMAND;
    const cashOut = shape.cashOut ?? CASHOUT_COMMAND;
    const endedSpec = roundEndedSpec(commitmentOf(shape), shape);

    return {
        tenantId: TENANT,
        poolId: POOL,
        sessionIdHex: SESSION_ID,
        roundIdHex: ROUND_ID,
        sequencerPublicKey: encodeEdpk(PUBLIC_KEY),
        sessionPublicKey: encodeEdpk(SESSION_PUBLIC_KEY),
        depositOperationLevel: BATCH_LEVEL - 10,
        locatorHints: null,
        commands: [
            { requestId: BET_REQUEST, payloadCase: 'placeBet', frame: bet, sentAtUnixMs: 1, sendCount: 1 },
            { requestId: CASHOUT_REQUEST, payloadCase: 'cashOut', frame: cashOut, sentAtUnixMs: 2, sendCount: 1 },
        ],
        frames: [
            frame({
                sequence: 2,
                sessionId: SESSION_ID,
                relatedRequestId: BET_REQUEST,
                payload: { case: 'commandAccepted' },
            }),
            frame({
                sequence: 3,
                sessionId: SESSION_ID,
                relatedRequestId: BET_REQUEST,
                payload: {
                    case: 'roundStarted',
                    roundId: ROUND_ID,
                    stake: shape.openerStake === null ? undefined : (shape.openerStake ?? STAKE_MONEY),
                    ...openerSeedFields(shape.openerSeed),
                },
            }),
            frame({
                sequence: 4,
                sessionId: SESSION_ID,
                relatedRequestId: CASHOUT_REQUEST,
                payload: { case: 'commandAccepted' },
            }),
            frame(endedSpec),
        ],
        roundEndedFrame: serverFrame(SIGNING_SEED, endedSpec),
        ...overrides,
    };
}

/** The honest export under `shape`, as the `receipts` input `verifyRound` takes. */
function receiptsFor(shape: ReceiptShape = {}): ReceiptsInput {
    return { status: 'ok', receipts: buildReceipts({}, shape) };
}

/**
 * The session's deposit as the resolver reports it for an honest round: found
 * below the transcript and confirmed on the node, so `session-before-transcript`
 * passes. The default for `verify()`, like the bracketing scan below.
 */
const DEPOSIT_BELOW_TRANSCRIPT: DepositLocation = {
    lookup: 'found',
    level: BATCH_LEVEL - 10,
    operationHash: 'op-deposit',
    vault: 'KT1TestVault',
    firstProven: true,
    otherVaults: null,
    detail: 'first deposit found by the fixture',
};

/** A range that brackets the round: it starts at the deposit and reaches head. */
const BRACKETING_SCAN: ScanContext = {
    fromLevel: BATCH_LEVEL - 100,
    toLevel: TRANSCRIPT_LEVEL + 50,
    headLevel: TRANSCRIPT_LEVEL + 50,
    deposit: { level: BATCH_LEVEL - 10, confirmed: true },
};

interface WireAction {
    tag: number;
    payload: Uint8Array;
}

function action(actionType: string, payload: Uint8Array = new Uint8Array()): WireAction {
    const tag = tagOf(actionType);

    if (tag === null) {
        throw new Error(`no tag for ${actionType}`);
    }

    return { tag, payload };
}

/** `borsh(plinko::Config { rows: u32, risk: enum })` — 5 bytes. */
function plinkoConfig(rows: number, risk: plinko.v1.Risk): Uint8Array {
    return new Uint8Array([...u32(rows), plinko.v1.RISK_BORSH_TAG[risk]]);
}

/**
 * Two actions, matching the two commands of the default export. The HiLo
 * `cashout` immediately after the bet pays 1.00× — the round's maths is not
 * what these cases are about, and a `higher` here would be an action no
 * command of the fixture is bound to.
 */
const HILO_ACTIONS = [action('place-bet'), action('cashout')];

interface RoundOptions {
    gameType?: string;
    actions?: WireAction[];
    clientSeed?: Uint8Array;
    serverSeed?: Uint8Array;
    claimedPayout?: bigint;
    batchLevel?: number;
    transcriptLevel?: number;
    /** Extra transcripts for the same round id, appended after the honest one. */
    extraTranscripts?: { level: number; claimedPayout: bigint }[];
    signingSeed?: Uint8Array;
    /** The instance the frames are signed for; defaults to the one `verify()` checks against. */
    domain?: SigningDomain;
    /** Defaults to the fold over the honest receipts' command frames. */
    playerCommitment?: Uint8Array;
}

/**
 * The payout an honest sequencer would claim, straight from the replayer the
 * verifier itself calls. Deliberately not a hard-coded number: the maths is
 * pinned against the golden vectors in hilo/v1.test.ts / plinko/v1.test.ts, and
 * restating it here would only pin this file to itself.
 */
function honestPayout(gameType: string, options: RoundOptions = {}): bigint {
    const replayers: Record<string, Replayer> = {
        [crash.v1.GAME_TYPE]: crash.v1.replay,
        [hilo.v1.GAME_TYPE]: hilo.v1.replay,
        [hydra.v1.GAME_TYPE]: hydra.v1.replay,
        [mines.v1.GAME_TYPE]: mines.v1.replay,
        [plinko.v1.GAME_TYPE]: plinko.v1.replay,
    };
    const wireActions = options.actions ?? HILO_ACTIONS;
    const replayed = replayers[gameType](
        bytesToHex(options.serverSeed ?? SERVER_SEED),
        bytesToHex(options.clientSeed ?? CLIENT_SEED),
        wireActions.map((a, actionIndex) => ({
            actionIndex,
            actionType: actionTypeOf(a.tag) ?? '',
            payload: a.payload,
        })),
        STAKE_MUTEZ,
    );

    return replayed.payoutUnits;
}

function transcriptBody(options: RoundOptions, claimedPayout: bigint): number[] {
    const wireActions = options.actions ?? HILO_ACTIONS;

    return [
        ...u8(0x01), // SequencerMessage::RoundTranscript
        ...uuid(ROUND_ID),
        ...uuid(SESSION_ID),
        ...str(options.gameType ?? hilo.v1.GAME_TYPE),
        ...u128(STAKE_MUTEZ),
        ...Array.from(options.clientSeed ?? CLIENT_SEED),
        ...Array.from(options.serverSeed ?? SERVER_SEED),
        ...u64(SEED_INDEX),
        ...u128(claimedPayout),
        ...Array.from(options.playerCommitment ?? PLAYER_COMMITMENT),
        ...u32(wireActions.length),
        ...wireActions.flatMap((a) => [...u8(a.tag), ...byteVec(a.payload)]),
    ];
}

function buildRound(options: RoundOptions = {}): InboxMessage[] {
    const serverSeed = options.serverSeed ?? SERVER_SEED;
    const seedHash = serverSeedCommitment(bytesToHex(serverSeed));
    const hashes = Array.from({ length: 50 }, (_, i) =>
        i === Number(SEED_INDEX - BATCH_START) ? seedHash : new Uint8Array(32).fill(i),
    );
    const claimedPayout =
        options.claimedPayout ?? honestPayout(options.gameType ?? hilo.v1.GAME_TYPE, options);

    return [
        frame(
            options.batchLevel ?? BATCH_LEVEL,
            [
                ...u8(0x00), // SequencerMessage::SeedBatch
                ...u64(BATCH_START),
                ...u32(hashes.length),
                ...hashes.flatMap((h) => Array.from(h)),
                ...u64(4242n),
                // drand_chain_hash: [u8; 32], raw bytes on the wire
                ...hexToBytes('52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971'),
            ],
            options.signingSeed,
            options.domain,
        ),
        frame(
            options.transcriptLevel ?? TRANSCRIPT_LEVEL,
            transcriptBody(options, claimedPayout),
            options.signingSeed,
            options.domain,
        ),
        ...(options.extraTranscripts ?? []).map((extra) =>
            frame(extra.level, transcriptBody(options, extra.claimedPayout), options.signingSeed, options.domain),
        ),
    ];
}

function verify(
    messages: InboxMessage[],
    extra: {
        publicKey?: Uint8Array | null;
        clientSeedText?: string;
        receipts?: ReceiptsInput;
        scan?: ScanContext | null;
        /** Verify a round OTHER than the one the fixture's receipts describe. */
        roundId?: string;
        /** The instance to check signatures against; `null` = the shell does not know it. */
        signingDomain?: SigningDomain | null;
        /** Whether the round's rollup is a listed deployment; `false` = a rollup no entry lists. */
        deploymentListed?: boolean;
        /** What the deposit resolver reported; defaults to a confirmed deposit below the transcript. */
        sessionDeposit?: DepositLocation | null;
    } = {},
) {
    const key = extra.publicKey === undefined ? PUBLIC_KEY : extra.publicKey;

    return verifyRound({
        signingDomain: extra.signingDomain === undefined ? DOMAIN : extra.signingDomain,
        deploymentListed: extra.deploymentListed ?? true,
        // The honest export and a bracketing range are the DEFAULTS, so every
        // pre-existing test still exercises a fully-evidenced round; a test
        // that cares about a missing half says so explicitly.
        receipts: extra.receipts ?? { status: 'ok', receipts: buildReceipts() },
        scan: extra.scan === undefined ? BRACKETING_SCAN : extra.scan,
        sessionDeposit: extra.sessionDeposit === undefined ? DEPOSIT_BELOW_TRANSCRIPT : extra.sessionDeposit,
        roundId: extra.roundId ?? ROUND_ID,
        tenantId: TENANT,
        messages,
        // `null` stands for "the lineage walk produced nothing" — the honest
        // shape of a network whose anchor is unset, which is what the suite
        // used to express by passing no key.
        keys:
            key === null
                ? { status: 'unavailable', reason: 'no lineage in this fixture' }
                : {
                      status: 'available',
                      keys: [
                          {
                              edpk: encodeEdpk(key),
                              registration: {
                                  level: 1,
                                  operationHash: 'op-register-tenant',
                                  source: 'register-tenant',
                                  administrator: 'KT1TestAdministrator',
                              },
                          },
                      ],
                  },
        clientSeedText: extra.clientSeedText,
    });
}

const statusOf = (report: { checks: { id: string; status: string }[] }, id: string): string | undefined =>
    report.checks.find((c) => c.id === id)?.status;

describe('verifyRound', () => {
    it('verifies an honest HiLo round end to end (signature, commitment, replay)', () => {
        const report = verify(buildRound());

        expect(report.verdict).toBe('verified');
        expect(report.gameType).toBe('hilo:v1');
        expect(report.replay?.outcome).toBe('cashed-out');
        // The optional client-seed check is the only one allowed to be
        // "unavailable" in a verified round.
        expect(report.checks.filter((c) => c.status !== 'pass').map((c) => c.id)).toEqual(['client-seed-text']);
        expect(report.checks.find((c) => c.id === 'round-transcript')?.detail).toContain(
            `player commitment ${bytesToHex(PLAYER_COMMITMENT)}`,
        );
    });

    it('takes the EARLIEST transcript when the round is redelivered', () => {
        // At-least-once injection: the same round can land twice. The kernel
        // dedups on durable storage and applies the FIRST occurrence, so a
        // later transcript claiming a bigger payout must be ignored, not
        // averaged in and not preferred.
        const inflated = honestPayout(hilo.v1.GAME_TYPE) + 1_000_000n;
        const report = verify(
            buildRound({ extraTranscripts: [{ level: TRANSCRIPT_LEVEL + 3, claimedPayout: inflated }] }),
        );

        expect(report.verdict).toBe('verified');
    });

    it('prefers the authenticated SeedBatch over an EARLIER foreign-signed one covering the same index', () => {
        // Observed live on shadownet: the inbox is shared across deployments,
        // so a batch under the same tenant slug, signed by a key the tenant
        // never registered, landed ahead of the tenant's own. The kernel drops
        // it; the verifier must too, not compare against its hashes.
        const foreignSeed = new Uint8Array(32).fill(7);
        const [foreignBatch] = buildRound({
            serverSeed: new Uint8Array(32).fill(3),
            signingSeed: foreignSeed,
            batchLevel: BATCH_LEVEL - 10,
            // Only the batch frame is used; an explicit payout skips replaying
            // a seed under which the fixture's HiLo guess loses.
            claimedPayout: 0n,
        });
        const report = verify([foreignBatch, ...buildRound()]);

        expect(report.verdict).toBe('verified');
        expect(statusOf(report, 'signatures')).toBe('pass');
        expect(statusOf(report, 'commitment-hash')).toBe('pass');
        expect(report.findings.join('\n')).toContain(`Skipped 1 SeedBatch frame(s)`);
    });

    it('prefers the authenticated transcript over an EARLIER foreign-signed one for the same round', () => {
        const inflated = honestPayout(hilo.v1.GAME_TYPE) + 1_000_000n;
        const [, forged] = buildRound({
            signingSeed: new Uint8Array(32).fill(7),
            transcriptLevel: BATCH_LEVEL + 1,
            claimedPayout: inflated,
        });
        const report = verify([forged, ...buildRound()]);

        expect(report.verdict).toBe('verified');
    });

    it('still fails the signature check when NO candidate SeedBatch authenticates', () => {
        const [foreignBatch] = buildRound({ signingSeed: new Uint8Array(32).fill(7) });
        const [, transcript] = buildRound();
        const report = verify([foreignBatch, transcript]);

        expect(report.verdict).toBe('failed');
        expect(statusOf(report, 'signatures')).toBe('fail');
    });

    it('fails when the claimed payout is inflated', () => {
        const report = verify(buildRound({ claimedPayout: honestPayout(hilo.v1.GAME_TYPE) + 1n }));

        expect(report.verdict).toBe('failed');
        expect(statusOf(report, 'replay-payout')).toBe('fail');
    });

    // ── The stake cross-check ───────────────────────────────────────────
    //
    // Until `RoundStartedEvent` carried a stake there was exactly ONE signed
    // statement of what a round opened at, and the verifier fed it into the
    // payout recomputation while comparing it to nothing.

    it('FAILS a round whose chain stake is not the stake the player signed', () => {
        // The attack this closes: debit 100 ꜩ, publish a transcript saying
        // 1 ꜩ. The kernel derives its payout FROM the transcript's stake, so
        // the round replays perfectly on chain and every other proof here
        // passes — the player's own signed amount is the only evidence.
        const shape = { bet: betCommand(HILO_ARM, undefined, { asset: 'TEZ', value: '1' }) };
        const report = verify(buildRound(), {
            receipts: { status: 'ok', receipts: buildReceipts({}, shape) },
        });

        expect(statusOf(report, STAKE_CHECK_ID)).toBe('fail');
        expect(report.verdict).toBe('failed');
        // The replay still agrees with itself, which is the whole point: the
        // understatement is invisible to every proof but this one.
        expect(statusOf(report, 'replay-payout')).toBe('pass');
        expect(report.checks.find((c) => c.id === STAKE_CHECK_ID)?.detail).toContain('1000000 mutez');
    });

    it('FAILS a round whose chain stake is not the stake the server signed on the opener', () => {
        // The other leg on its own. Weaker evidence — it is the server
        // contradicting itself rather than contradicting the player — but a
        // contradiction is still a contradiction.
        const openerOnlyShape = {
            // Player leg removed so the opener is the only source.
            bet: betCommand(HILO_ARM, undefined, null),
            openerStake: { asset: 'TEZ', value: '1' },
        };
        const report = verify(buildRound({ playerCommitment: commitmentOf(openerOnlyShape) }), {
            receipts: {
                status: 'ok',
                receipts: buildReceipts({}, openerOnlyShape),
            },
        });

        expect(statusOf(report, STAKE_CHECK_ID)).toBe('fail');
        expect(report.verdict).toBe('failed');
    });

    it('does NOT fail a round that simply carries no signed stake — it degrades', () => {
        // Absence is a gap in the evidence, never an accusation. The
        // `STEP_ORIGIN_UNSPECIFIED` rule: a producer's silence is not an
        // assertion, and a tool that read it as one would accuse an honest
        // server.
        const shape = { bet: betCommand(HILO_ARM, undefined, null), openerStake: null };
        const report = verify(buildRound({ playerCommitment: commitmentOf(shape) }), {
            receipts: { status: 'ok', receipts: buildReceipts({}, shape) },
        });

        expect(statusOf(report, STAKE_CHECK_ID)).toBe('unavailable');
        // Nothing else broke: the degrade is the stake check's alone.
        expect(report.checks.filter((c) => c.status === 'fail')).toEqual([]);
        expect(report.verdict).toBe('incomplete');
        expect(report.checks.find((c) => c.id === STAKE_CHECK_ID)?.detail).toContain('NOT a disagreement');
    });

    it('passes on the opener alone, and says the evidence is the server agreeing with itself', () => {
        const shape = { bet: betCommand(HILO_ARM, undefined, null) };
        const report = verify(buildRound({ playerCommitment: commitmentOf(shape) }), {
            receipts: { status: 'ok', receipts: buildReceipts({}, shape) },
        });

        expect(statusOf(report, STAKE_CHECK_ID)).toBe('pass');
        // A reader must never mistake the weak comparison for the strong one.
        expect(report.checks.find((c) => c.id === STAKE_CHECK_ID)?.detail).toContain('server agreeing with itself');
    });

    it('FAILS a round whose opener named a different seed commitment than the chain reveals', () => {
        // The post-bet swap (ADR 0025): the server opened the round against one
        // committed seed and settled it against another. Every on-chain proof
        // replays the swapped seed and passes; only the signed opener sees it.
        const shape = { openerSeed: { hash: new Uint8Array(32).fill(0x42), index: SEED_INDEX } };
        const report = verify(buildRound(), { receipts: receiptsFor(shape) });

        expect(report.verdict).toBe('failed');
        expect(statusOf(report, OPENER_SEED_CHECK_ID)).toBe('fail');
        expect(report.checks.find((c) => c.id === OPENER_SEED_CHECK_ID)?.detail).toContain('swapped seeds');
        // The echo still matches the chain, so the pre-bet proof is not what fails.
        expect(statusOf(report, PRE_BET_SEED_CHECK_ID)).toBe('pass');
    });

    it('FAILS a round whose opener named the right commitment at the wrong index', () => {
        const shape = { openerSeed: { hash: SEED_COMMITMENT, index: SEED_INDEX + 1n } };
        const report = verify(buildRound(), { receipts: receiptsFor(shape) });

        expect(report.verdict).toBe('failed');
        expect(statusOf(report, OPENER_SEED_CHECK_ID)).toBe('fail');
    });

    it('FAILS a round settled against a seed other than the one the player echoed', () => {
        // The #1234 shape made visible: the server promised one seed, the
        // player signed its hash into the bet, and the transcript reveals a
        // different seed — chosen with the client seed already in hand.
        const echoed = new Uint8Array(32).fill(0x24);
        const shape = {
            bet: betCommand(HILO_ARM, undefined, STAKE_MONEY, echoed),
            // The opener agrees with the chain, so only the pre-bet proof fails.
            openerSeed: { hash: SEED_COMMITMENT, index: SEED_INDEX },
        };
        const report = verify(buildRound({ playerCommitment: commitmentOf(shape) }), { receipts: receiptsFor(shape) });

        expect(report.verdict).toBe('failed');
        expect(statusOf(report, PRE_BET_SEED_CHECK_ID)).toBe('fail');
        expect(report.checks.find((c) => c.id === PRE_BET_SEED_CHECK_ID)?.detail).toContain(
            'with the client seed already in hand',
        );
        expect(statusOf(report, OPENER_SEED_CHECK_ID)).toBe('pass');
    });

    it('FAILS when an accepted bet omitted its required promise', () => {
        // The server must never accept this signed bet.
        const shape = { bet: betCommand(HILO_ARM, undefined, STAKE_MONEY, null) };
        const report = verify(buildRound({ playerCommitment: commitmentOf(shape) }), { receipts: receiptsFor(shape) });

        expect(report.verdict).toBe('failed');
        expect(statusOf(report, PRE_BET_SEED_CHECK_ID)).toBe('fail');
        expect(report.checks.find((c) => c.id === PRE_BET_SEED_CHECK_ID)?.detail).toContain(
            'required 32-byte server_seed_hash',
        );
        expect(statusOf(report, OPENER_SEED_CHECK_ID)).toBe('pass');
    });

    it('FAILS when a signed opener omits the required seed commitment', () => {
        const shape = { openerSeed: null };
        const report = verify(buildRound(), { receipts: receiptsFor(shape) });

        expect(report.verdict).toBe('failed');
        expect(statusOf(report, OPENER_SEED_CHECK_ID)).toBe('fail');
        expect(statusOf(report, PRE_BET_SEED_CHECK_ID)).toBe('pass');
    });

    it('keeps the opener proof unavailable when the entire opening receipt is missing', () => {
        const receipts = buildReceipts();

        receipts.frames = receipts.frames.filter((frame) => frame.sequence !== 3n);

        const report = verify(buildRound(), { receipts: { status: 'ok', receipts } });

        expect(statusOf(report, OPENER_SEED_CHECK_ID)).toBe('unavailable');
        expect(report.verdict).not.toBe('failed');
        expect(report.verdict).not.toBe('verified');
    });

    it('fails when an action payload is tampered with', () => {
        // Plinko seals its outcome from the place-bet config, so editing the
        // payload changes the multiplier the round should have paid — the one
        // action field a transcript can carry that is not a bare tag.
        const honestActions = [action('place-bet', plinkoConfig(8, 'low')), action('cashout')];
        const claimed = honestPayout(plinko.v1.GAME_TYPE, { gameType: plinko.v1.GAME_TYPE, actions: honestActions });
        const shape = {
            bet: betCommand({ game: 'plinko', rows: 8, risk: 1 }),
            cashOut: cashOutCommand({ game: 'plinko' }),
        };
        const receipts: ReceiptsInput = { status: 'ok', receipts: buildReceipts({}, shape) };
        const green = verify(
            buildRound({
                gameType: plinko.v1.GAME_TYPE,
                actions: honestActions,
                playerCommitment: commitmentOf(shape),
            }),
            { receipts },
        );

        expect(green.verdict).toBe('verified');

        const report = verify(
            buildRound({
                gameType: plinko.v1.GAME_TYPE,
                actions: [action('place-bet', plinkoConfig(16, 'high')), action('cashout')],
                claimedPayout: claimed,
                playerCommitment: commitmentOf(shape),
            }),
            { receipts },
        );

        expect(report.verdict).toBe('failed');
        expect(statusOf(report, 'replay-payout')).toBe('fail');
        // And the fourth proof catches it independently: the rewritten config
        // is no longer the one the player signed into their PlaceBet.
        expect(statusOf(report, PROJECTION_CHECK_ID)).toBe('fail');
    });

    it('fails when the seed commitment does not strictly precede the transcript', () => {
        const report = verify(buildRound({ batchLevel: TRANSCRIPT_LEVEL }));

        expect(report.verdict).toBe('failed');
        expect(statusOf(report, 'commitment-order')).toBe('fail');
        // The hash itself is still fine — only the ordering is wrong, and the
        // report must say which of the two failed.
        expect(statusOf(report, 'commitment-hash')).toBe('pass');
    });

    it('fails when the revealed seed does not hash to the committed value', () => {
        const messages = buildRound();
        // Re-sign a transcript revealing a different seed against the batch
        // built for the honest one.
        const tampered = frame(
            TRANSCRIPT_LEVEL,
            transcriptBody({ serverSeed: new Uint8Array(32).fill(8) }, honestPayout(hilo.v1.GAME_TYPE)),
        );
        const report = verify([messages[0], tampered]);

        expect(statusOf(report, 'commitment-hash')).toBe('fail');
        expect(report.verdict).toBe('failed');
    });

    it('checks the optional client-seed text, passing on the right one', () => {
        const text = 'player-chosen-seed';
        const messages = buildRound({
            clientSeed: blake2b(new TextEncoder().encode(text), { dkLen: 32 }),
            actions: [action('place-bet'), action('cashout')],
        });

        expect(verify(messages, { clientSeedText: text }).verdict).toBe('verified');
        expect(statusOf(verify(messages, { clientSeedText: text }), 'client-seed-text')).toBe('pass');
    });

    it('checks the optional client-seed text, failing on the wrong one', () => {
        const text = 'player-chosen-seed';
        const messages = buildRound({
            clientSeed: blake2b(new TextEncoder().encode(text), { dkLen: 32 }),
            actions: [action('place-bet'), action('cashout')],
        });
        const report = verify(messages, { clientSeedText: 'not-the-seed-i-typed' });

        expect(statusOf(report, 'client-seed-text')).toBe('fail');
        expect(report.verdict).toBe('failed');
    });

    describe('client seed from the receipts', () => {
        // Plinko, because it settles on its second action under ANY seed pair:
        // these cases vary the client seed, and a HiLo guess could lose.
        const PLINKO_ACTIONS = [action('place-bet', plinkoConfig(8, 'low')), action('cashout')];

        /** The plinko arms matching PLINKO_ACTIONS, so the fourth proof agrees. */
        const PLINKO_BET_ARM: CommandGameSpec = { game: 'plinko', rows: 8, risk: 1 };
        const PLINKO_CASHOUT_ARM: CommandGameSpec = { game: 'plinko' };

        /** Honest receipts whose PlaceBet carries `seedText`, and the commitment over them. */
        function receiptsWithSeed(seedText: string): { receipts: ImportedReceipts; commitment: Uint8Array } {
            const shape = {
                bet: betCommand(PLINKO_BET_ARM, seedText),
                cashOut: cashOutCommand(PLINKO_CASHOUT_ARM),
            };

            return { commitment: commitmentOf(shape), receipts: buildReceipts({}, shape) };
        }

        function plinkoRound(transcriptSeedText: string, commitment: Uint8Array): InboxMessage[] {
            const clientSeed = blake2b(new TextEncoder().encode(transcriptSeedText), { dkLen: 32 });
            const options = { gameType: plinko.v1.GAME_TYPE, actions: PLINKO_ACTIONS, clientSeed, playerCommitment: commitment };

            return buildRound({ ...options, claimedPayout: honestPayout(plinko.v1.GAME_TYPE, options) });
        }

        it('reads the seed from the signed PlaceBet command when none is typed', () => {
            const { receipts, commitment } = receiptsWithSeed('my lucky seed');
            const report = verify(plinkoRound('my lucky seed', commitment), { receipts: { status: 'ok', receipts } });
            const check = report.checks.find((c) => c.id === 'client-seed-text');

            expect(check?.status).toBe('pass');
            expect(check?.detail).toContain(`request ${BET_REQUEST}`);
            expect(check?.detail).toContain('"my lucky seed"');
            expect(report.verdict).toBe('verified');
        });

        it('fails when the transcript seed is not the one the player signed', () => {
            // Every other proof passes: the commitment covers the command
            // frames, not the transcript's seed field, so only this check sees
            // a sequencer that swapped the seed.
            const { receipts, commitment } = receiptsWithSeed('my lucky seed');
            const report = verify(plinkoRound('a seed the server picked', commitment), {
                receipts: { status: 'ok', receipts },
            });

            expect(statusOf(report, 'client-seed-text')).toBe('fail');
            expect(statusOf(report, 'commitment-vs-chain')).toBe('pass');
            expect(report.verdict).toBe('failed');
        });

        it('checks typed text as well, and fails when it disagrees', () => {
            const { receipts, commitment } = receiptsWithSeed('my lucky seed');
            const report = verify(plinkoRound('my lucky seed', commitment), {
                receipts: { status: 'ok', receipts },
                clientSeedText: 'a seed I misremember',
            });
            const check = report.checks.find((c) => c.id === 'client-seed-text');

            expect(check?.status).toBe('fail');
            expect(check?.detail).toContain('the text you typed');
            expect(check?.detail).toContain(`request ${BET_REQUEST}`);
        });

        it('stays unavailable when the PlaceBet command carries no seed', () => {
            // The default fixture's commands have empty payloads.
            expect(statusOf(verify(buildRound()), 'client-seed-text')).toBe('unavailable');
        });
    });

    it('leaves the client-seed check unavailable, not failed, when no text is given', () => {
        const report = verify(buildRound());

        expect(statusOf(report, 'client-seed-text')).toBe('unavailable');
        expect(report.verdict).toBe('verified');
    });

    it('has a replayer for every game version that names a seed derivation', () => {
        // A game with a seed rule but no replayer would reach the replay block
        // and stop at "not implemented", so it could never be `verified`. The
        // two tables move together; a new game that forgets its port fails
        // here rather than shipping rounds that can only ever be incomplete.
        expect([...supportedGameTypes()].sort()).toEqual(Object.keys(GAME_SEED_DERIVATIONS).sort());
    });

    it('rejects a transcript carrying an action tag it does not know', () => {
        // Mirrors the kernel's reject-unknown-action-tag: the message still
        // decodes in full — the tag is a bare u8 precisely so it does — but
        // the round cannot be replayed under this table version.
        const messages = buildRound();
        const withUnknownTag = frame(TRANSCRIPT_LEVEL, [
            ...transcriptBody({ actions: [action('place-bet'), { tag: 0x7f, payload: new Uint8Array() }] }, 0n),
        ]);
        const report = verify([messages[0], withUnknownTag]);

        expect(report.verdict).toBe('failed');
        expect(report.checks.find((c) => c.id === 'replay')?.detail).toContain('0x7f');
    });

    // ── Actions after the settling one ──────────────────────────────────
    //
    // The kernel stops at the first settle, never reads what follows, and
    // records the round as an `actions-after-settle` discrepancy. The verifier
    // fails the round: the payout is unaffected, but the chain refuses to
    // validate the transcript, and a trailing action is how a server would
    // dress a suppressed round up as a settled one.

    it('passes actions-after-settle when the settling action is the last one', () => {
        const report = verify(buildRound());
        const check = report.checks.find((c) => c.id === ACTIONS_AFTER_SETTLE_CHECK_ID);

        expect(check?.status).toBe('pass');
        expect(check?.detail).toContain('the transcript\'s last');
    });

    it('fails a round with actions after the settle, whose payout still matches', () => {
        // A system `abandon` after the cashout: no command of the player's is
        // bound to it, and a system step needs none, so the projection passes
        // and this check is the only one that sees it.
        const padded = [...HILO_ACTIONS, action('abandon')];
        const report = verify(buildRound({ actions: padded, claimedPayout: honestPayout(hilo.v1.GAME_TYPE) }));
        const detail = report.checks.find((c) => c.id === ACTIONS_AFTER_SETTLE_CHECK_ID)?.detail;

        expect(statusOf(report, ACTIONS_AFTER_SETTLE_CHECK_ID)).toBe('fail');
        expect(detail).toContain('action 1 (cashout) settles the round, and 1 action(s) follow it');
        expect(detail).toContain('the payout was unaffected');
        expect(detail).toContain('An honest sequencer never produces this');
        expect(statusOf(report, PROJECTION_CHECK_ID)).toBe('pass');
        // The replay still reports the payout comparison, and it agrees.
        expect(statusOf(report, 'replay-payout')).toBe('pass');
        expect(report.replay?.settledAtIndex).toBe(1);
        expect(report.verdict).toBe('failed');
    });

    it('never reads an unknown tag after the settle, but still fails the round for it', () => {
        const padded = [...HILO_ACTIONS, { tag: 0x7f, payload: new Uint8Array([0xde, 0xad]) }];
        const report = verify(buildRound({ actions: padded, claimedPayout: honestPayout(hilo.v1.GAME_TYPE) }));

        // Not the kernel's reject-unknown-action-tag: the walk never reaches it.
        expect(statusOf(report, 'replay')).toBeUndefined();
        expect(statusOf(report, 'replay-payout')).toBe('pass');
        expect(statusOf(report, ACTIONS_AFTER_SETTLE_CHECK_ID)).toBe('fail');
        expect(report.verdict).toBe('failed');
    });

    it('locates the settle from the shape alone when the round is not replayed', () => {
        // A round on a rollup no deployment entry lists is never replayed, but
        // a cashout settles whenever it is applied, so whatever follows it
        // trails a settle.
        const report = verify(
            buildRound({
                gameType: hydra.v1.GAME_TYPE,
                actions: [action('place-bet', new Uint8Array([2, 0, 0, 0])), action('cashout'), action('abandon')],
                claimedPayout: 0n,
            }),
            { deploymentListed: false },
        );

        expect(statusOf(report, 'replay')).toBe('unavailable');
        expect(report.replay).toBeNull();
        expect(statusOf(report, ACTIONS_AFTER_SETTLE_CHECK_ID)).toBe('fail');
        expect(report.checks.find((c) => c.id === ACTIONS_AFTER_SETTLE_CHECK_ID)?.detail).toContain(
            'action 1 (cashout) settles the round, and 1 action(s) follow it',
        );
        expect(report.verdict).toBe('failed');
    });

    it('is unavailable for an unreplayed round when the shape cannot place the settle', () => {
        // The cashout is last, but an earlier attack may have lost and settled
        // the round first; only a replay could say.
        const report = verify(
            buildRound({
                gameType: hydra.v1.GAME_TYPE,
                actions: [action('place-bet', new Uint8Array([2, 0, 0, 0])), action('physical-attack'), action('cashout')],
                claimedPayout: 0n,
            }),
            { deploymentListed: false },
        );

        expect(report.replay).toBeNull();

        expect(statusOf(report, ACTIONS_AFTER_SETTLE_CHECK_ID)).toBe('unavailable');
    });

    it('fails an unfinished transcript instead of paying the live position', () => {
        // The `higher` must WIN, or the round would settle as a loss and this
        // would not be an unfinished transcript at all. The scenario's
        // predicate guarantees it; restate it so a drifted row fails HERE.
        const opening = hilo.v1.hiloStep(bytesToHex(SERVER_SEED), bytesToHex(CLIENT_SEED), 0);
        const next = hilo.v1.hiloStep(bytesToHex(SERVER_SEED), bytesToHex(CLIENT_SEED), 1);

        expect(next.rankNumeric).toBeGreaterThanOrEqual(opening.rankNumeric);
        expect(HILO_SCENARIO.winning_direction_at_1).toBe('higher');

        const messages = buildRound({ actions: [action('place-bet'), action('higher')] });
        const report = verify(messages);

        expect(statusOf(report, 'replay-outcome')).toBe('fail');
        expect(report.verdict).toBe('failed');
    });

    it('is inconclusive, and replays nothing, on a rollup no deployment entry lists', () => {
        // A hand-typed rollup runs a kernel nobody vouched for. Replaying it
        // could recompute different cards and accuse an honest server, so the
        // round is refused instead.
        const report = verify(buildRound(), { deploymentListed: false });
        const replay = report.checks.find((c) => c.id === 'replay');

        expect(report.verdict).toBe('inconclusive');
        expect(report.replay).toBeNull();
        expect(replay?.status).toBe('unavailable');
        expect(replay?.detail).toContain('unknown deployment');
        expect(statusOf(report, 'replay-payout')).toBeUndefined();
        // Every seed-independent proof still ran.
        expect(statusOf(report, 'signatures')).toBe('pass');
        expect(statusOf(report, 'commitment-hash')).toBe('pass');
    });

    it('is inconclusive on a game type that names no seed derivation this build implements', () => {
        // The seed rule is selected by the round's game version, so a game
        // this verifier does not know has no rule: the replay is refused,
        // never run under a guessed one.
        const report = verify(buildRound({ gameType: 'roulette:v1', claimedPayout: 0n }));

        expect(report.verdict).toBe('inconclusive');
        expect(report.replay).toBeNull();
        expect(report.checks.find((c) => c.id === 'replay')?.detail).toBe(
            'derivation not supported: game roulette:v1 names no seed derivation this verifier implements',
        );
    });

    it('still fails an unknown-deployment round whose seed-independent proof fails', () => {
        // Inconclusive is about the replay alone; a forged frame is still a
        // forged frame under any seed rule.
        const report = verify(buildRound(), {
            deploymentListed: false,
            publicKey: new Uint8Array(32).fill(7),
        });

        expect(statusOf(report, 'signatures')).toBe('fail');
        expect(report.verdict).toBe('failed');
    });

    it('reports signature failure under the wrong key', () => {
        const report = verify(buildRound(), { publicKey: new Uint8Array(32).fill(7) });

        expect(statusOf(report, 'signatures')).toBe('fail');
        expect(report.verdict).toBe('failed');
    });

    it('fails a frame signed for another rollup, under the same slug and key (#952)', () => {
        // The t10_06 replay: the same tenant, the same key, on a second rollup
        // on the same chain. The frame is byte-identical on the wire apart
        // from its signature, and that signature was computed over the OTHER
        // rollup's address — so it does not verify for this one, exactly as
        // this rollup's kernel would drop it.
        const report = verify(buildRound({ domain: OTHER_ROLLUP }));

        expect(statusOf(report, 'signatures')).toBe('fail');
        expect(report.verdict).toBe('failed');
        // And the same frames, checked against the instance they WERE signed
        // for, pass — the signature is bound to an instance, not broken.
        expect(statusOf(verify(buildRound({ domain: OTHER_ROLLUP }), { signingDomain: OTHER_ROLLUP }), 'signatures')).toBe(
            'pass',
        );
    });

    it('fails a frame signed for the same rollup on another chain (#952)', () => {
        const mainnet: SigningDomain = { ...DOMAIN, chainId: 'NetXdQprcVkpaWU' };
        const report = verify(buildRound({ domain: mainnet }));

        expect(statusOf(report, 'signatures')).toBe('fail');
    });

    it('cannot check signatures without knowing the instance (absent proof, not a passed one)', () => {
        const report = verify(buildRound(), { signingDomain: null });

        expect(statusOf(report, 'signatures')).toBe('unavailable');
        expect(report.verdict).toBe('incomplete');
    });

    it('authenticates the seed batch too, not just the transcript', () => {
        // The inbox is permissionless: a third party can inject a SeedBatch.
        // If only the transcript were authenticated, a batch forged to cover a
        // seed chosen after the fact would make the commitment half pass.
        const honest = buildRound();
        const forgedBatch = buildRound({ signingSeed: new Uint8Array(32).fill(3) })[0];
        const report = verify([forgedBatch, honest[1]]);

        expect(statusOf(report, 'signatures')).toBe('fail');
        expect(report.verdict).toBe('failed');
    });

    it('is incomplete, never verified, without a sequencer key (permissionless inbox)', () => {
        const report = verify(buildRound(), { publicKey: null });

        expect(report.verdict).toBe('incomplete');
        expect(statusOf(report, 'signatures')).toBe('unavailable');
    });

    it('is incomplete, never verified, when the seed batch is missing', () => {
        const messages = buildRound().filter((m) => m.envelope.message.kind !== 'seed-batch');
        const report = verify(messages);

        expect(report.verdict).toBe('incomplete');
        expect(statusOf(report, 'commitment-hash')).toBe('unavailable');
    });

    // ── The third proof group ───────────────────────────────────────────

    it('degrades to INCOMPLETE when the export carries no decodable command bodies', () => {
        // The stated consequence of joining the verdict, not a regression to
        // be worked around: without the command bodies nothing ties the
        // transcript's actions to what the player authorised, so the fourth
        // proof did not run and the verdict must say so. Every other proof
        // still passes.
        const shape = {
            bet: commandFrame(SESSION_SEED, {
                requestId: BET_REQUEST,
                sessionId: SESSION_ID,
                payloadCase: 'placeBet' as const,
                serverSeedHash: SEED_COMMITMENT,
            }),
            cashOut: commandFrame(SESSION_SEED, {
                requestId: CASHOUT_REQUEST,
                sessionId: SESSION_ID,
                payloadCase: 'cashOut' as const,
                roundId: ROUND_ID,
            }),
        };
        const report = verify(buildRound({ playerCommitment: commitmentOf(shape) }), {
            receipts: { status: 'ok', receipts: buildReceipts({}, shape) },
        });

        expect(statusOf(report, 'commitment-vs-chain')).toBe('pass');
        expect(statusOf(report, 'replay-payout')).toBe('pass');
        expect(statusOf(report, PROJECTION_CHECK_ID)).toBe('unavailable');
        expect(report.verdict).toBe('incomplete');
    });

    it("is incomplete, never verified, without the player's receipts", () => {
        // The chain proofs all pass, but nothing ties the on-chain round to
        // the commands the player authorised — so the transcript's
        // player_commitment is a number the server chose, and the verdict must
        // say so rather than borrowing the credibility of a full check.
        const report = verify(buildRound(), { receipts: { status: 'absent' } });

        expect(report.verdict).toBe('incomplete');
        expect(statusOf(report, 'commitment-vs-chain')).toBe('unavailable');
        expect(statusOf(report, 'replay-payout')).toBe('pass');
        // The fourth proof gets a stable id on every status, so "did not run"
        // stays distinguishable from "ran and did not pass".
        expect(statusOf(report, PROJECTION_CHECK_ID)).toBe('unavailable');
    });

    it('is incomplete when the receipts document will not import', () => {
        const report = verify(buildRound(), { receipts: { status: 'error', message: 'schema mismatch' } });

        expect(report.verdict).toBe('incomplete');
        expect(report.checks.find((c) => c.id === 'receipt-frames-signed')?.detail).toContain('schema mismatch');
    });

    it('is ATTESTED, not verified, when a peer tab held one of the commands', () => {
        // The exporting tab never saw the cashout it did not send, but the
        // server placed it at index 1. The reconstruction declines, so only
        // the weak signed-vs-chain comparison ran.
        const receipts = buildReceipts();

        receipts.commands = [receipts.commands[0]];

        const report = verify(buildRound(), { receipts: { status: 'ok', receipts } });

        expect(report.verdict).toBe('attested');
        expect(statusOf(report, 'receipt-vs-chain')).toBe('pass');
        expect(statusOf(report, 'commitment-vs-chain')).toBe('unavailable');
        expect(report.checks.find((c) => c.id === 'commitment-vs-chain')?.detail).toContain(
            'server-index-without-command',
        );
    });

    it('FAILS, not incomplete, on a single tampered signature byte', () => {
        const receipts = buildReceipts();
        const tampered = receipts.frames[1].frame.slice();

        tampered[1] ^= 0x01;
        receipts.frames = [
            receipts.frames[0],
            { ...receipts.frames[1], frame: tampered },
            ...receipts.frames.slice(2),
        ];

        const report = verify(buildRound(), { receipts: { status: 'ok', receipts } });

        expect(statusOf(report, 'receipt-frames-signed')).toBe('fail');
        expect(report.verdict).toBe('failed');
    });

    it("fails when the export's commitment does not match the chain", () => {
        // A server that archived different commands than the player sent. The
        // reconstruction succeeds, so the mismatch IS substantiated.
        const receipts = buildReceipts();

        receipts.commands = [
            receipts.commands[0],
            { ...receipts.commands[1], frame: commandFrame(SESSION_SEED, {
                requestId: CASHOUT_REQUEST,
                sessionId: SESSION_ID,
                payloadCase: 'playerAction',
            }) },
        ];

        const report = verify(buildRound(), { receipts: { status: 'ok', receipts } });

        expect(statusOf(report, 'commitment-vs-chain')).toBe('fail');
        expect(statusOf(report, 'commitment-vs-receipt')).toBe('fail');
        expect(report.verdict).toBe('failed');
    });

    it('reports a relabelled round as a finding, and verifies from the bytes anyway', () => {
        const report = verify(buildRound(), {
            receipts: { status: 'ok', receipts: buildReceipts({ roundIdHex: '00000000-0000-4000-8000-000000000000' }) },
        });

        expect(report.verdict).toBe('verified');
        expect(report.findings.join(' ')).toContain('the export labels its round');
    });

    // ── The suppression ladder ──────────────────────────────────────────

    function withoutTranscript(): InboxMessage[] {
        return buildRound().filter((m) => m.envelope.message.kind !== 'round-transcript');
    }

    function endSessionMessage(level: number): InboxMessage {
        return frame(level, [
            ...u8(0x02), // SequencerMessage::EndSession
            ...uuid(SESSION_ID),
            ...u8(0), // EndReason::UserRequested
        ]);
    }

    it('is incomplete when the round has no transcript and no receipts', () => {
        const report = verify(withoutTranscript(), { receipts: { status: 'absent' } });

        expect(report.verdict).toBe('incomplete');
        expect(statusOf(report, 'round-transcript')).toBe('unavailable');
        expect(report.gameType).toBeNull();
    });

    it('is UNDETERMINED when nothing shows the injector moved past the round', () => {
        const report = verify(withoutTranscript());

        expect(report.verdict).toBe('undetermined');
        expect(report.findings.join(' ')).toContain('Injector-progress evidence: none');
    });

    it('is SUPPRESSED when a later EndSession of the same session is on chain', () => {
        const report = verify([...withoutTranscript(), endSessionMessage(TRANSCRIPT_LEVEL + 2)]);

        expect(report.verdict).toBe('suppressed');
        expect(report.references.some((r) => r.summary.includes('EndSession'))).toBe(true);
    });

    it("is INCONCLUSIVE when the scan started after the session's deposit", () => {
        const report = verify(withoutTranscript(), {
            scan: { ...BRACKETING_SCAN, fromLevel: BRACKETING_SCAN.deposit!.level + 1 },
        });

        expect(report.verdict).toBe('inconclusive');
        expect(report.findings.join(' ')).toContain('does not bracket the round');
    });

    it('is INCONCLUSIVE when the deposit level could not be confirmed on L1', () => {
        // A player-supplied bracket is a bracket the player can widen, so an
        // unconfirmed hint is treated as no hint at all (§8.3(d)).
        const report = verify(withoutTranscript(), {
            scan: { ...BRACKETING_SCAN, deposit: { level: BRACKETING_SCAN.deposit!.level, confirmed: false } },
        });

        expect(report.verdict).toBe('inconclusive');
    });

    it('is INCONCLUSIVE when the scan stopped short of the head', () => {
        const report = verify(withoutTranscript(), {
            scan: { ...BRACKETING_SCAN, headLevel: BRACKETING_SCAN.toLevel + 500 },
        });

        expect(report.verdict).toBe('inconclusive');
    });

    it('never reaches suppressed from the offline paste path, which states no range', () => {
        const report = verify(withoutTranscript(), { scan: null });

        expect(report.verdict).toBe('inconclusive');
    });

    // A sibling transcript is NOT injector-progress evidence: the receipts
    // carry nothing that orders it against this round, so a session that
    // played round 1 (published) and then round 2 (still in the outbox) would
    // otherwise read as suppression of round 2 out of ordinary latency.
    const SIBLING_ROUND_ID = '7c17e5b1-0f0f-4a0a-9c0c-0d0d0d0d0d0d';

    function siblingTranscript(level: number): InboxMessage {
        return frame(level, [
            ...u8(0x01), // SequencerMessage::RoundTranscript
            ...uuid(SIBLING_ROUND_ID),
            ...uuid(SESSION_ID),
            ...str(hilo.v1.GAME_TYPE),
            ...u128(STAKE_MUTEZ),
            ...Array.from(CLIENT_SEED),
            ...Array.from(SERVER_SEED),
            ...u64(SEED_INDEX + 1n),
            ...u128(0n),
            ...Array.from(PLAYER_COMMITMENT),
            ...u32(1),
            ...u8(tagOf('place-bet') as number),
            ...u32(0),
        ]);
    }

    it("stays UNDETERMINED when only a sibling round's transcript is on chain", () => {
        const report = verify([...withoutTranscript(), siblingTranscript(TRANSCRIPT_LEVEL + 2)]);

        expect(report.verdict).toBe('undetermined');
        expect(report.findings.join(' ')).toContain('Sibling rounds on chain');
        expect(report.findings.join(' ')).toContain('Injector-progress evidence: none');
    });

    it('names the EndSession, not the sibling, when both are on chain', () => {
        const report = verify([
            ...withoutTranscript(),
            siblingTranscript(TRANSCRIPT_LEVEL + 2),
            endSessionMessage(TRANSCRIPT_LEVEL + 3),
        ]);

        expect(report.verdict).toBe('suppressed');
        expect(report.references.filter((r) => r.summary.includes('EndSession'))).toHaveLength(1);
        expect(report.references.some((r) => r.summary.includes('different round'))).toBe(false);
        expect(report.findings.join(' ')).toContain('Injector-progress evidence: an EndSession');
    });

    it('is INCOMPLETE, never suppressed, for a relabelled export naming another round', () => {
        // Genuine receipts of ROUND_ID, pointed at a round that never existed.
        // Every frame verifies, the session id is real, and ROUND_ID's own
        // transcript is on chain — the exact shape that used to walk to
        // `suppressed` for a round nobody ever played.
        const otherRound = '00000000-0000-4000-8000-0000000000ff';
        const report = verify(buildRound(), { roundId: otherRound });

        expect(report.verdict).toBe('incomplete');
        expect(report.findings.join(' ')).toContain('does not name the round under verification');
    });
});

// ── A suppressed cashout, end to end ────────────────────────

describe('a cashout the server answered with nothing', () => {
    // The attack P2 and P4 were built to expose, run through the whole tool:
    // the player signs a manual-mode crash cashout, the sequencer drops it,
    // the deadline sweep settles the round as an `expire`, and every other
    // proof in the report passes. Only the fourth one can see it.
    const SUPPRESSED_REQUEST = '44444444-4444-4444-8444-444444444444';
    const BET = betCommand({ game: 'crash' });
    const SUPPRESSED = commandFrame(SESSION_SEED, {
        requestId: SUPPRESSED_REQUEST,
        sessionId: SESSION_ID,
        payloadCase: 'cashOut',
        roundId: ROUND_ID,
        game: { game: 'crash', tick: 40 },
    });
    // The fold is over ACKNOWLEDGED commands only, and a dropped command has
    // no acknowledgement — so an honest commitment covers the bet alone. That
    // is exactly why the commitment proofs cannot see this on their own.
    const COMMITMENT = computeCommitment([BET]);

    // `related_request_id` is NULL because nothing of the player's is being
    // replied to: the deadline sweep settled the round on its own. That is
    // also what keeps the reconstruction clean — a sweep's RoundEnded binds no
    // command, so it states no index.
    const ENDED_SPEC: ServerFrameSpec = {
        sequence: 5,
        sessionId: SESSION_ID,
        relatedRequestId: null,
        payload: {
            case: 'roundEnded',
            roundId: ROUND_ID,
            actionIndex: 1,
            playerCommitment: COMMITMENT,
            cause: 'system-sweep',
        },
    };

    function receipts(): ReceiptsInput {
        const frame = (spec: ServerFrameSpec) => ({
            sequence: BigInt(spec.sequence),
            payloadCase: spec.payload.case,
            relatedRequestId: spec.relatedRequestId,
            frame: serverFrame(SIGNING_SEED, spec),
        });

        return {
            status: 'ok',
            receipts: {
                ...buildReceipts(),
                commands: [
                    { requestId: BET_REQUEST, payloadCase: 'placeBet', frame: BET, sentAtUnixMs: 1, sendCount: 1 },
                    {
                        requestId: SUPPRESSED_REQUEST,
                        payloadCase: 'cashOut',
                        frame: SUPPRESSED,
                        sentAtUnixMs: 2,
                        sendCount: 1,
                    },
                ],
                frames: [
                    frame({
                        sequence: 2,
                        sessionId: SESSION_ID,
                        relatedRequestId: BET_REQUEST,
                        payload: { case: 'commandAccepted' },
                    }),
                    frame({
                        sequence: 3,
                        sessionId: SESSION_ID,
                        relatedRequestId: BET_REQUEST,
                        payload: { case: 'roundStarted', roundId: ROUND_ID, ...openerSeedFields(undefined) },
                    }),
                    frame(ENDED_SPEC),
                ],
                roundEndedFrame: serverFrame(SIGNING_SEED, ENDED_SPEC),
            },
        };
    }

    /** A manual crash round that ran to its bust with no cashout recorded. */
    function expiredRound(): InboxMessage[] {
        return buildRound({
            gameType: crash.v1.GAME_TYPE,
            actions: [action('place-bet', new Uint8Array([0x00])), action('expire')],
            playerCommitment: COMMITMENT,
        });
    }

    it('REPORTS it, and does not fail: silence cannot prove delivery', () => {
        // The shape is exactly the attack's, and the report says so — but a
        // command lost in transit leaves the identical document behind, so the
        // evidence goes out as a finding rather than as an accusation against a
        // named server. Every other proof still passes, which is the point: the
        // fourth is the only one that can even SEE this.
        const report = verify(expiredRound(), { receipts: receipts() });

        expect(statusOf(report, 'commitment-vs-chain')).toBe('pass');
        expect(statusOf(report, 'replay-payout')).toBe('pass');
        expect(statusOf(report, PROJECTION_CHECK_ID)).toBe('pass');
        expect(report.verdict).toBe('verified');
        expect(report.findings.join(' ')).toContain('REPORTED, NEVER CONCLUDED');
        expect(report.findings.join(' ')).toContain(SUPPRESSED_REQUEST);
    });
});

// ── A refused cashout, end to end ───────────────────────────────────────

describe('a refusal the round’s own seed contradicts', () => {
    // The unit-level rules live in `verify/rejections.test.ts`. What this
    // block proves is the wiring the unit tests cannot: a refusal in the
    // export reaches `verifyRound`, its check lands beside the others, and a
    // `fail` there carries the whole verdict to `failed` through `anyFail` —
    // even though the check is deliberately NOT in `allProofsRan`, so a round
    // with no refusal is unaffected.
    // Its own seeds, from the crash scenario `crash-mid-curve-53` (predicate
    // 53 <= crash_tick <= 100) — never the HiLo default pair, whose crash tick
    // is an accident of a different game's search.
    const CRASH_SCENARIO = hexScenario('crash', 'crash-mid-curve-53');
    const CRASH_SERVER_SEED = hexToBytes(CRASH_SCENARIO.server_seed_hex);
    const CRASH_CLIENT_SEED = hexToBytes(CRASH_SCENARIO.effective_client_seed_hex);
    /** The commitment of THIS block's seed — what its honest opener and echoes state. */
    const CRASH_SEED_COMMITMENT = serverSeedCommitment(bytesToHex(CRASH_SERVER_SEED));
    const CRASH_OPENER_SEED = { hash: CRASH_SEED_COMMITMENT, index: SEED_INDEX };
    const CRASH_TICK = crash.v1.crashRound(bytesToHex(CRASH_SERVER_SEED), bytesToHex(CRASH_CLIENT_SEED)).crashTick;
    const ANCHOR = 1_700_000_000_000n;
    const QUANTUM = 50n;
    const PEER_CASHOUT = '33333333-3333-4333-8333-333333333333';
    /** `casino.v1.CommandRejectionReason.ROUND_CLOSED`. */
    const ROUND_CLOSED = 2;

    /** `borsh(crash::Config { auto_cashout_tick: None })` — a manual round. */
    const MANUAL_BET = new Uint8Array([0x00]);

    /**
     * A stamp far enough before the crash to be outside the sweep-versus-lock
     * race band, so it reads as a contradiction rather than as latency.
     */
    const WELL_BEFORE_CRASH = CRASH_TICK - 10n;

    /** The player cashed out one tick before the crash, so the round is a win. */
    const CASHOUT_TICK = Number(CRASH_TICK - 1n);
    const CRASH_ACTIONS = [
        action('place-bet', MANUAL_BET),
        action('cashout', new Uint8Array(u32(CASHOUT_TICK))),
    ];

    /**
     * The honest export, with the crash anchor on `RoundStarted` and the peer
     * tab's refused cashout appended.
     *
     * `stampedAtTick` is the tick the refusal's `received_at_unix_ms` maps to.
     */
    /**
     * The crash arms matching CRASH_ACTIONS: a manual bet (no
     * `auto_cashout_ppm`) and a cashout claiming exactly the tick the
     * transcript carries. This is the P2 payoff made concrete — the player's
     * signed tick and the transcript's `borsh(u32)` are the same number, and
     * the fourth proof is what compares them.
     */
    const CRASH_SHAPE = () => ({
        bet: betCommand({ game: 'crash' }, undefined, STAKE_MONEY, CRASH_SEED_COMMITMENT),
        cashOut: cashOutCommand({ game: 'crash', tick: CASHOUT_TICK }),
        openerSeed: CRASH_OPENER_SEED,
    });

    function receiptsWithRefusal(stampedAtTick: bigint): ReceiptsInput {
        const honest = buildReceipts({}, CRASH_SHAPE());
        const rebuilt = honest.frames.map((imported) =>
            imported.payloadCase === 'roundStarted'
                ? {
                      ...imported,
                      frame: serverFrame(SIGNING_SEED, {
                          sequence: imported.sequence,
                          sessionId: SESSION_ID,
                          relatedRequestId: imported.relatedRequestId,
                          payload: {
                              case: 'roundStarted',
                              roundId: ROUND_ID,
                              crashState: { tickQuantumMs: QUANTUM, serverAnchorUnixMs: ANCHOR },
                              ...openerSeedFields(CRASH_OPENER_SEED),
                          },
                      }),
                  }
                : imported,
        );
        const refusalSpec: ServerFrameSpec = {
            sequence: 0,
            sessionId: SESSION_ID,
            relatedRequestId: PEER_CASHOUT,
            payload: {
                case: 'commandRejected',
                reasonCode: ROUND_CLOSED,
                detail: 'round is no longer in progress',
                roundId: ROUND_ID,
                receivedAtUnixMs: ANCHOR + stampedAtTick * QUANTUM,
            },
        };

        return {
            status: 'ok',
            receipts: {
                ...honest,
                commands: [
                    ...honest.commands,
                    {
                        requestId: PEER_CASHOUT,
                        payloadCase: 'cashOut',
                        // The player signed THIS round id into the refused
                        // command, which is what makes the server's echo
                        // trustworthy rather than a label it chose.
                        frame: commandFrame(SESSION_SEED, {
                            requestId: PEER_CASHOUT,
                            sessionId: SESSION_ID,
                            payloadCase: 'cashOut',
                            roundId: ROUND_ID,
                            game: { game: 'crash', tick: CASHOUT_TICK },
                        }),
                        sentAtUnixMs: 3,
                        sendCount: 1,
                    },
                ],
                frames: [
                    ...rebuilt,
                    {
                        sequence: 0n,
                        payloadCase: 'commandRejected',
                        relatedRequestId: PEER_CASHOUT,
                        frame: serverFrame(SIGNING_SEED, refusalSpec),
                    },
                ],
            },
        };
    }

    function verifyCrash(receipts: ReceiptsInput) {
        return verify(
            buildRound({
                gameType: crash.v1.GAME_TYPE,
                serverSeed: CRASH_SERVER_SEED,
                clientSeed: CRASH_CLIENT_SEED,
                actions: CRASH_ACTIONS,
                playerCommitment: commitmentOf(CRASH_SHAPE()),
            }),
            { receipts },
        );
    }

    // ── the same round, settled by the deadline sweep ────────────────────
    //
    // The refusal check can only contradict a seed on a round that settled on
    // an `expire`, because that is the shape a DROPPED cashout produces: a
    // round the player claimed is a round that ended before the crash, and a
    // refusal after that is the correct answer. So the fail path needs its own
    // fixture — one bet, no claim, the sweep's terminal loss — and the
    // cashout-settled round above becomes the case that must NOT fail.

    const EXPIRE_ACTIONS = [action('place-bet', MANUAL_BET), action('expire')];
    const EXPIRE_BET = betCommand({ game: 'crash' }, undefined, STAKE_MONEY, CRASH_SEED_COMMITMENT);
    const EXPIRE_COMMITMENT = computeCommitment([EXPIRE_BET]);

    function expireReceipts(stampedAtTick: bigint): ReceiptsInput {
        const frame = (spec: ServerFrameSpec) => ({
            sequence: BigInt(spec.sequence),
            payloadCase: spec.payload.case,
            relatedRequestId: spec.relatedRequestId,
            frame: serverFrame(SIGNING_SEED, spec),
        });
        // `related_request_id` is NULL: the sweep settled the round on its own,
        // so the frame binds no command and states no index for one.
        const endedSpec: ServerFrameSpec = {
            sequence: 5,
            sessionId: SESSION_ID,
            relatedRequestId: null,
            payload: {
                case: 'roundEnded',
                roundId: ROUND_ID,
                actionIndex: 1,
                playerCommitment: EXPIRE_COMMITMENT,
                cause: 'system-sweep',
            },
        };
        const refusalSpec: ServerFrameSpec = {
            sequence: 0,
            sessionId: SESSION_ID,
            relatedRequestId: PEER_CASHOUT,
            payload: {
                case: 'commandRejected',
                reasonCode: ROUND_CLOSED,
                detail: 'round is no longer in progress',
                roundId: ROUND_ID,
                receivedAtUnixMs: ANCHOR + stampedAtTick * QUANTUM,
            },
        };

        return {
            status: 'ok',
            receipts: {
                ...buildReceipts(),
                commands: [
                    { requestId: BET_REQUEST, payloadCase: 'placeBet', frame: EXPIRE_BET, sentAtUnixMs: 1, sendCount: 1 },
                    {
                        requestId: PEER_CASHOUT,
                        payloadCase: 'cashOut',
                        frame: commandFrame(SESSION_SEED, {
                            requestId: PEER_CASHOUT,
                            sessionId: SESSION_ID,
                            payloadCase: 'cashOut',
                            roundId: ROUND_ID,
                            game: { game: 'crash', tick: CASHOUT_TICK },
                        }),
                        sentAtUnixMs: 3,
                        sendCount: 1,
                    },
                ],
                frames: [
                    frame({
                        sequence: 2,
                        sessionId: SESSION_ID,
                        relatedRequestId: BET_REQUEST,
                        payload: { case: 'commandAccepted' },
                    }),
                    frame({
                        sequence: 3,
                        sessionId: SESSION_ID,
                        relatedRequestId: BET_REQUEST,
                        payload: {
                            case: 'roundStarted',
                            roundId: ROUND_ID,
                            crashState: { tickQuantumMs: QUANTUM, serverAnchorUnixMs: ANCHOR },
                            ...openerSeedFields(CRASH_OPENER_SEED),
                        },
                    }),
                    frame(endedSpec),
                    frame(refusalSpec),
                ],
                roundEndedFrame: serverFrame(SIGNING_SEED, endedSpec),
            },
        };
    }

    function verifyExpired(receipts: ReceiptsInput) {
        return verify(
            buildRound({
                gameType: crash.v1.GAME_TYPE,
                serverSeed: CRASH_SERVER_SEED,
                clientSeed: CRASH_CLIENT_SEED,
                actions: EXPIRE_ACTIONS,
                playerCommitment: EXPIRE_COMMITMENT,
            }),
            { receipts },
        );
    }

    it('has a crash round with room before the bust, or the cases below are vacuous', () => {
        // WELL_BEFORE_CRASH = CRASH_TICK - 10 must clear the race band and
        // stay a positive tick: 10 + RACE_BAND_TICKS + 1 (13 today).
        expect(RACE_BAND_TICKS).toBe(2n);
        expect(CRASH_TICK).toBeGreaterThanOrEqual(10n + RACE_BAND_TICKS + 1n);
    });

    it('verifies the crash round itself when no refusal is in the export', () => {
        // The control. Without it, a `failed` below could be the crash
        // fixture failing for some unrelated reason rather than the refusal
        // doing its job — and the claim that an absent refusal costs nothing
        // would be untested.
        const report = verifyCrash({ status: 'ok', receipts: buildReceipts({}, CRASH_SHAPE()) });

        expect(report.verdict).toBe('verified');
        expect(report.checks.find((check) => check.id === REJECTION_CHECK_ID)).toBeUndefined();
    });

    it('FAILS an expire-settled round when the refusal is stamped before the crash', () => {
        const report = verifyExpired(expireReceipts(WELL_BEFORE_CRASH));
        const check = report.checks.find((entry) => entry.id === REJECTION_CHECK_ID);

        expect(check?.status).toBe('fail');
        expect(report.verdict).toBe('failed');
        // The commitment proofs still ran and still passed: a refused command
        // is not an acknowledged one, so it contributes nothing to the fold.
        expect(report.checks.find((entry) => entry.id === 'commitment-vs-chain')?.status).toBe('pass');
    });

    it('does NOT fail a round that had already settled on the player’s own claim', () => {
        // The same bytes that fail above, on a round whose last action is a
        // cashout. The round ended before the crash by the player's own claim,
        // so a liveness refusal afterwards is the correct answer and there is
        // nothing for the seed to contradict. Checking it anyway would accuse
        // an honest server on every manual crash round the player won.
        const report = verifyCrash(receiptsWithRefusal(WELL_BEFORE_CRASH));
        const check = report.checks.find((entry) => entry.id === REJECTION_CHECK_ID);

        expect(check?.status).toBe('pass');
        expect(check?.detail).toContain('ALREADY SETTLED on a claim');
        expect(report.verdict).toBe('verified');
    });

    it('keeps the round verified when the refusal is stamped after the crash', () => {
        const report = verifyExpired(expireReceipts(CRASH_TICK + 4n));
        const check = report.checks.find((entry) => entry.id === REJECTION_CHECK_ID);

        expect(check?.status).toBe('pass');
        // `verified` even though this check is outside `allProofsRan`: it
        // passed, so nothing degrades, and the margin goes out as a finding.
        expect(report.verdict).toBe('verified');
        expect(report.findings.join(' ')).toContain('4 tick(s) after the crash tick');
    });
});

// ── a clean round of each remaining replayable game ─────────────────────

/**
 * Verdict-level end-to-end cases for MINES and PLINKO.
 *
 * HiLo and crash already have one each, and plinko appears above only inside
 * the client-seed group, where the verdict is incidental to what that group is
 * about. Mines had no end-to-end case at all — it is not in `honestPayout`'s
 * replayer map until this block adds it — so nothing pinned the orchestration
 * (transcript + SeedBatch + signed frames + commands, all four agreeing) for
 * the one shipped game whose round carries a THIRD action between the bet and
 * the settle.
 *
 * Every number here is derived, never stated: the safe tile comes from the
 * same `verify/mines/v1.ts` layout derivation the verifier itself calls (pinned
 * against the shared golden vectors by `mines/v1.test.ts`), and the claimed
 * payout comes from the replayer. A hard-coded tile would pin this file to
 * itself, and would break silently the day the seed constants change.
 */
describe('a clean round of each remaining replayable game', () => {
    const REVEAL_REQUEST = '44444444-4444-4444-8444-444444444444';

    /** Every check a verified round is allowed to leave un-`pass`ed. */
    const OPTIONAL_CHECKS = ['client-seed-text'];

    function nonPassing(report: { checks: { id: string; status: string }[] }): string[] {
        return report.checks.filter((check) => check.status !== 'pass').map((check) => check.id);
    }

    describe('mines:v1', () => {
        const MINE_COUNT = 3;
        /**
         * The first tile the derived layout does NOT hide a mine under. Taken
         * from the layout rather than guessed, so the round is a win by
         * construction under whatever seeds this file happens to use.
         */
        const SAFE_TILES = (() => {
            const layout = mines.v1.deriveLayout(bytesToHex(SERVER_SEED), bytesToHex(CLIENT_SEED), MINE_COUNT);
            const mineSet = new Set(layout.minePositions);

            return [...Array(mines.v1.TOTAL_TILES).keys()].filter((candidate) => !mineSet.has(candidate));
        })();
        const [SAFE_TILE, OTHER_SAFE_TILE] = SAFE_TILES;

        /** bet → one safe reveal → cashout: three actions, three commands. */
        const ACTIONS = [
            action('place-bet', new Uint8Array(u32(MINE_COUNT))),
            action('reveal', new Uint8Array(u32(SAFE_TILE))),
            action('cashout'),
        ];

        const BET = betCommand({ game: 'mines', mineCount: MINE_COUNT });
        const REVEAL = commandFrame(SESSION_SEED, {
            requestId: REVEAL_REQUEST,
            sessionId: SESSION_ID,
            payloadCase: 'playerAction',
            roundId: ROUND_ID,
            game: { game: 'mines', action: 'reveal', tileIndex: SAFE_TILE },
        });
        const CASHOUT = cashOutCommand({ game: 'mines' });
        const COMMITMENT = computeCommitment([BET, REVEAL, CASHOUT]);

        function frameOf(spec: ServerFrameSpec) {
            return {
                sequence: BigInt(spec.sequence),
                payloadCase: spec.payload.case,
                relatedRequestId: spec.relatedRequestId,
                frame: serverFrame(SIGNING_SEED, spec),
            };
        }

        /**
         * The settling frame. `action_index` is 2, which is what binds the
         * cashout command to the third action — the index the reconstruction
         * reads, never the command's position in the export.
         */
        const ENDED_SPEC: ServerFrameSpec = {
            sequence: 7,
            sessionId: SESSION_ID,
            relatedRequestId: CASHOUT_REQUEST,
            payload: {
                case: 'roundEnded',
                roundId: ROUND_ID,
                actionIndex: 2,
                playerCommitment: COMMITMENT,
                cause: 'player-action',
            },
        };

        function receipts(): ImportedReceipts {
            return buildReceipts({
                commands: [
                    { requestId: BET_REQUEST, payloadCase: 'placeBet', frame: BET, sentAtUnixMs: 1, sendCount: 1 },
                    { requestId: REVEAL_REQUEST, payloadCase: 'playerAction', frame: REVEAL, sentAtUnixMs: 2, sendCount: 1 },
                    { requestId: CASHOUT_REQUEST, payloadCase: 'cashOut', frame: CASHOUT, sentAtUnixMs: 3, sendCount: 1 },
                ],
                frames: [
                    frameOf({
                        sequence: 2,
                        sessionId: SESSION_ID,
                        relatedRequestId: BET_REQUEST,
                        payload: { case: 'commandAccepted' },
                    }),
                    frameOf({
                        sequence: 3,
                        sessionId: SESSION_ID,
                        relatedRequestId: BET_REQUEST,
                        payload: { case: 'roundStarted', roundId: ROUND_ID, ...openerSeedFields(undefined) },
                    }),
                    frameOf({
                        sequence: 4,
                        sessionId: SESSION_ID,
                        relatedRequestId: REVEAL_REQUEST,
                        payload: { case: 'commandAccepted' },
                    }),
                    frameOf({
                        sequence: 5,
                        sessionId: SESSION_ID,
                        relatedRequestId: REVEAL_REQUEST,
                        // `origin: 'player'` is the point: a SYSTEM step
                        // occupies an index without binding a command, so a
                        // mislabelled origin here would drop the reveal out of
                        // the fold and break the commitment.
                        payload: { case: 'roundUpdated', roundId: ROUND_ID, actionIndex: 1, origin: 'player' },
                    }),
                    frameOf({
                        sequence: 6,
                        sessionId: SESSION_ID,
                        relatedRequestId: CASHOUT_REQUEST,
                        payload: { case: 'commandAccepted' },
                    }),
                    frameOf(ENDED_SPEC),
                ],
                roundEndedFrame: serverFrame(SIGNING_SEED, ENDED_SPEC),
            });
        }

        function round() {
            return buildRound({
                gameType: mines.v1.GAME_TYPE,
                actions: ACTIONS,
                playerCommitment: COMMITMENT,
            });
        }

        it('has two safe tiles, or the round below is a loss and the swap case is vacuous', () => {
            // The swap case needs a SECOND safe tile: substituting a mine
            // would end the round at the reveal, leaving the cashout after the
            // settle, and the case would test that rather than the proof it is
            // about.
            const layout = mines.v1.deriveLayout(bytesToHex(SERVER_SEED), bytesToHex(CLIENT_SEED), MINE_COUNT);

            expect(SAFE_TILES.length).toBeGreaterThanOrEqual(2);
            expect(layout.minePositions).not.toContain(SAFE_TILE);
            expect(layout.minePositions).not.toContain(OTHER_SAFE_TILE);
            expect(OTHER_SAFE_TILE).not.toBe(SAFE_TILE);
        });

        it('verifies a clean mines round end to end', () => {
            const report = verify(round(), { receipts: { status: 'ok', receipts: receipts() } });

            expect(report.verdict).toBe('verified');
            expect(report.gameType).toBe('mines:v1');
            expect(report.replay?.outcome).toBe('cashed-out');
            expect(nonPassing(report)).toEqual(OPTIONAL_CHECKS);
        });

        it('pays more than the stake, so the reveal actually moved the position', () => {
            // Without this the case would still pass with a replayer that
            // returned 1.00× for everything, and "clean round" would prove
            // nothing about the middle action.
            const report = verify(round(), { receipts: { status: 'ok', receipts: receipts() } });

            expect(report.replay).not.toBeNull();
            expect(report.replay?.cumulativePpm).toBeGreaterThan(1_000_000n);
        });

        it('fails when the reveal names a different tile than the one you signed', () => {
            // The fourth proof, on the one shipped game whose MIDDLE action
            // carries a payload. Both tiles are safe and the mines multiplier
            // keys on the revealed COUNT, so the swap changes neither the
            // payout nor any commitment — the preimage is the command bytes
            // and those are untouched. Nothing but the projection can see it,
            // which is precisely the gap that proof exists to close.
            const swapped = [ACTIONS[0], action('reveal', new Uint8Array(u32(OTHER_SAFE_TILE))), ACTIONS[2]];
            const report = verify(
                buildRound({ gameType: mines.v1.GAME_TYPE, actions: swapped, playerCommitment: COMMITMENT }),
                { receipts: { status: 'ok', receipts: receipts() } },
            );

            expect(statusOf(report, PROJECTION_CHECK_ID)).toBe('fail');
            expect(report.verdict).toBe('failed');
            // The commitment proofs still pass, which is the whole point.
            expect(statusOf(report, 'commitment-vs-chain')).toBe('pass');
            expect(statusOf(report, 'replay-payout')).toBe('pass');
        });
    });

    describe('hydra:v1', () => {
        const ATTACK_REQUEST = '55555555-5555-4555-8555-555555555555';
        const replayHydra = (actions: WireAction[]) =>
            hydra.v1.replay(
                bytesToHex(SERVER_SEED),
                bytesToHex(CLIENT_SEED),
                actions.map((a, actionIndex) => ({ actionIndex, actionType: actionTypeOf(a.tag) ?? '', payload: a.payload })),
                STAKE_MUTEZ,
            );
        /**
         * The first hero whose physical attack SURVIVES under this file's
         * seeds without clearing the round, taken from the replayer itself
         * (pinned against the shared vectors by `hydra/v1.test.ts`). A death would
         * settle at the attack and leave the cashout trailing the settle.
         */
        const HERO = hydra.v1.HEROES.findIndex((_, hero) => {
            const result = replayHydra([action('place-bet', new Uint8Array([hero, 0, 0, 0])), action('physical-attack')]);

            return !result.settled;
        });

        /** bet → one surviving physical attack → cashout: three actions, three commands. */
        const ACTIONS = [action('place-bet', new Uint8Array([HERO, 0, 0, 0])), action('physical-attack'), action('cashout')];

        const BET = betCommand({ game: 'hydra', hero: HERO, weapon: 1, armour: 1, sprite: 1 });
        const ATTACK = commandFrame(SESSION_SEED, {
            requestId: ATTACK_REQUEST,
            sessionId: SESSION_ID,
            payloadCase: 'playerAction',
            roundId: ROUND_ID,
            game: { game: 'hydra', action: 'physical-attack' },
        });
        const CASHOUT = cashOutCommand({ game: 'hydra' });
        const COMMITMENT = computeCommitment([BET, ATTACK, CASHOUT]);

        function frameOf(spec: ServerFrameSpec) {
            return {
                sequence: BigInt(spec.sequence),
                payloadCase: spec.payload.case,
                relatedRequestId: spec.relatedRequestId,
                frame: serverFrame(SIGNING_SEED, spec),
            };
        }

        const ENDED_SPEC: ServerFrameSpec = {
            sequence: 7,
            sessionId: SESSION_ID,
            relatedRequestId: CASHOUT_REQUEST,
            payload: {
                case: 'roundEnded',
                roundId: ROUND_ID,
                actionIndex: 2,
                playerCommitment: COMMITMENT,
                cause: 'player-action',
            },
        };

        function receipts(): ImportedReceipts {
            return buildReceipts({
                commands: [
                    { requestId: BET_REQUEST, payloadCase: 'placeBet', frame: BET, sentAtUnixMs: 1, sendCount: 1 },
                    { requestId: ATTACK_REQUEST, payloadCase: 'playerAction', frame: ATTACK, sentAtUnixMs: 2, sendCount: 1 },
                    { requestId: CASHOUT_REQUEST, payloadCase: 'cashOut', frame: CASHOUT, sentAtUnixMs: 3, sendCount: 1 },
                ],
                frames: [
                    frameOf({
                        sequence: 2,
                        sessionId: SESSION_ID,
                        relatedRequestId: BET_REQUEST,
                        payload: { case: 'commandAccepted' },
                    }),
                    frameOf({
                        sequence: 3,
                        sessionId: SESSION_ID,
                        relatedRequestId: BET_REQUEST,
                        payload: { case: 'roundStarted', roundId: ROUND_ID, ...openerSeedFields(undefined) },
                    }),
                    frameOf({
                        sequence: 4,
                        sessionId: SESSION_ID,
                        relatedRequestId: ATTACK_REQUEST,
                        payload: { case: 'commandAccepted' },
                    }),
                    frameOf({
                        sequence: 5,
                        sessionId: SESSION_ID,
                        relatedRequestId: ATTACK_REQUEST,
                        payload: { case: 'roundUpdated', roundId: ROUND_ID, actionIndex: 1, origin: 'player' },
                    }),
                    frameOf({
                        sequence: 6,
                        sessionId: SESSION_ID,
                        relatedRequestId: CASHOUT_REQUEST,
                        payload: { case: 'commandAccepted' },
                    }),
                    frameOf(ENDED_SPEC),
                ],
                roundEndedFrame: serverFrame(SIGNING_SEED, ENDED_SPEC),
            });
        }

        function round(actions: WireAction[] = ACTIONS) {
            return buildRound({ gameType: hydra.v1.GAME_TYPE, actions, playerCommitment: COMMITMENT });
        }

        it('finds a hero whose attack survives, or the round below is a loss', () => {
            expect(HERO).toBeGreaterThanOrEqual(0);
            expect(replayHydra(ACTIONS).outcome).toBe('cashed-out');
        });

        it('verifies a clean hydra round end to end', () => {
            const report = verify(round(), { receipts: { status: 'ok', receipts: receipts() } });

            expect(report.verdict).toBe('verified');
            expect(report.gameType).toBe('hydra:v1');
            expect(report.replay?.outcome).toBe('cashed-out');
            expect(report.replay?.settledAtIndex).toBe(2);
            expect(nonPassing(report)).toEqual(OPTIONAL_CHECKS);
        });

        it('fails when the claimed payout is not what the attack paid', () => {
            const honest = honestPayout(hydra.v1.GAME_TYPE, { gameType: hydra.v1.GAME_TYPE, actions: ACTIONS });
            const report = verify(
                buildRound({
                    gameType: hydra.v1.GAME_TYPE,
                    actions: ACTIONS,
                    playerCommitment: COMMITMENT,
                    claimedPayout: honest + 1n,
                }),
                { receipts: { status: 'ok', receipts: receipts() } },
            );

            expect(honest).not.toBe(STAKE_MUTEZ);
            expect(statusOf(report, 'replay-payout')).toBe('fail');
            expect(report.verdict).toBe('failed');
        });

        it('fails the projection when the attack is published as magic', () => {
            // The commitment covers the command bytes, which are untouched;
            // only the projection sees the swapped action.
            const swapped = [ACTIONS[0], action('magic-attack'), ACTIONS[2]];
            const replayed = replayHydra(swapped);
            const report = verify(
                buildRound({
                    gameType: hydra.v1.GAME_TYPE,
                    actions: swapped,
                    playerCommitment: COMMITMENT,
                    // Keep the payout honest for whatever the swap replays to, so
                    // the projection is the check that fails.
                    claimedPayout: replayed.payoutUnits,
                }),
                { receipts: { status: 'ok', receipts: receipts() } },
            );

            expect(statusOf(report, PROJECTION_CHECK_ID)).toBe('fail');
            expect(statusOf(report, 'commitment-vs-chain')).toBe('pass');
            expect(report.verdict).toBe('failed');
        });
    });

    describe('plinko:v1', () => {
        const ROWS = 8;
        const ACTIONS = [action('place-bet', plinkoConfig(ROWS, 'low')), action('cashout')];
        /** `Risk.LOW` is the PROTO enum value 1, against the borsh tag 0. */
        const BET_ARM: CommandGameSpec = { game: 'plinko', rows: ROWS, risk: 1 };

        function round(commitment: Uint8Array) {
            return buildRound({ gameType: plinko.v1.GAME_TYPE, actions: ACTIONS, playerCommitment: commitment });
        }

        it('verifies a clean plinko round the player cashed out', () => {
            // The ordinary path: the client's drop animation finished and it
            // sent the payload-free cashout itself, so `cause` is the player's
            // own action and both commands are bound.
            const shape = { bet: betCommand(BET_ARM), cashOut: cashOutCommand({ game: 'plinko' }) };
            const report = verify(round(commitmentOf(shape)), {
                receipts: { status: 'ok', receipts: buildReceipts({}, shape) },
            });

            expect(report.verdict).toBe('verified');
            expect(report.gameType).toBe('plinko:v1');
            expect(nonPassing(report)).toEqual(OPTIONAL_CHECKS);
        });

        it('verifies a clean plinko round the deadline sweep settled', () => {
            // The other half of plinko's "sealed-then-revealed" shape: the tab
            // was closed or throttled, so the `settles_at` sweep substituted
            // the cashout. It pays identically — the settle action cannot
            // change the payout — and it binds NO command, which is why the
            // commitment folds the bet alone and the settling action at index
            // 1 is legal only under `cause = SYSTEM_SWEEP`.
            const bet = betCommand(BET_ARM);
            const commitment = computeCommitment([bet]);
            const endedSpec: ServerFrameSpec = {
                sequence: 5,
                sessionId: SESSION_ID,
                // No related request: the sweep answers no command of the
                // player's, which is exactly what keeps it out of the fold.
                relatedRequestId: null,
                payload: {
                    case: 'roundEnded',
                    roundId: ROUND_ID,
                    actionIndex: 1,
                    playerCommitment: commitment,
                    cause: 'system-sweep',
                },
            };
            const frameOf = (spec: ServerFrameSpec) => ({
                sequence: BigInt(spec.sequence),
                payloadCase: spec.payload.case,
                relatedRequestId: spec.relatedRequestId,
                frame: serverFrame(SIGNING_SEED, spec),
            });
            const report = verify(round(commitment), {
                receipts: {
                    status: 'ok',
                    receipts: buildReceipts({
                        commands: [{ requestId: BET_REQUEST, payloadCase: 'placeBet', frame: bet, sentAtUnixMs: 1, sendCount: 1 }],
                        frames: [
                            frameOf({
                                sequence: 2,
                                sessionId: SESSION_ID,
                                relatedRequestId: BET_REQUEST,
                                payload: { case: 'commandAccepted' },
                            }),
                            frameOf({
                                sequence: 3,
                                sessionId: SESSION_ID,
                                relatedRequestId: BET_REQUEST,
                                payload: { case: 'roundStarted', roundId: ROUND_ID, ...openerSeedFields(undefined) },
                            }),
                            frameOf(endedSpec),
                        ],
                        roundEndedFrame: serverFrame(SIGNING_SEED, endedSpec),
                    }),
                },
            });

            expect(report.verdict).toBe('verified');
            expect(report.gameType).toBe('plinko:v1');
            expect(nonPassing(report)).toEqual(OPTIONAL_CHECKS);
        });
    });
});

// ── Locator hints: confirmed, then used to relocate the scan (US-D2) ─────
//
// `runChainVerification` is the shell's fetch flow without the DOM. The chain
// is a stub over a fixed message list: `scanRange` returns what lies in the
// range, `fetchBlock` one level. Every frame is built with `frame()` and
// signed under the suite's lineage key.

describe('locator hints', () => {
    const T = 100_000;
    const HEAD = T + 50;
    const LINEAGE: KeySet = {
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
    const VERDICT_WORD = /\b(verified|attested|inconclusive|undetermined|suppressed|incomplete|failed)\b/i;

    /** The honest round with its batch at `batchLevel` and transcript at `transcriptLevel`. */
    const round = (batchLevel: number, transcriptLevel: number = T) => buildRound({ batchLevel, transcriptLevel });

    // ── The deposit side of the stub chain ──────────────────────────────
    //
    // A small world of vaults and deposits, read through the same indexer
    // search (`locateSessionDeposit`, over a stubbed fetch) and the same node
    // shapes the D-9 captures pin in `chain/deposit.test.ts`.
    const VAULT_A = 'KT1WiDdttiuqRHVJ8gb1cYte4Xf3YCGwtDty';
    const VAULT_B = 'KT1V9p3YByfpVs1QWmnZPHTNHDy9XaNPLTqz';
    const SESSION_HEX = SESSION_ID.replaceAll('-', '');

    interface WorldDeposit {
        vault: string;
        level: number;
        /** The receipt writes the vault's `sessions` entry for the session (a first deposit). */
        firstWrite: boolean;
    }

    interface DepositWorld {
        /** The pool's vault registrations, all under the signed tenant and pool. */
        vaults: { vault: string; level: number; kind: 'production' | 'preview' | 'unknown-id' }[];
        /** What the indexer returns. */
        indexed: WorldDeposit[];
        /** What the node's blocks hold; defaults to `indexed`. */
        onNode?: WorldDeposit[];
        /** An indexer that answers with this HTTP status instead. */
        indexerStatus?: number;
        /** Whether each vault's `sessions` big_map holds the session at head; 'error' = the lookup fails. */
        heldAt?: Record<string, boolean | 'error'>;
    }

    const worldWith = (depositLevel: number, overrides: Partial<DepositWorld> = {}): DepositWorld => ({
        vaults: [{ vault: VAULT_A, level: 1, kind: 'production' }],
        indexed: [{ vault: VAULT_A, level: depositLevel, firstWrite: true }],
        ...overrides,
    });

    function lineageOf(world: DepositWorld): AdminLineage {
        return {
            administrators: [],
            keys: [],
            vaults: world.vaults.map((v) => ({
                tenantId: TENANT,
                poolId: POOL,
                vault: v.vault,
                status: 'active',
                level: v.level,
                operationHash: `op-register-${v.vault}`,
            })),
            proposals: [],
            ambiguities: [],
            scannedOperationCount: 0,
            ignoredOperationCount: 0,
        };
    }

    /** The node's storage for a vault: the production comb (sessions id at leaf 5), the preview's nine fields, or an 8-leaf comb with no id. */
    function storageOf(world: DepositWorld, vault: string): unknown {
        const index = world.vaults.findIndex((v) => v.vault === vault);
        const kind = world.vaults[index]?.kind ?? 'production';
        const fifth = kind === 'production' ? { int: String(500 + index) } : { prim: 'None' };
        const leaves = [{ string: 'tz1admin' }, { prim: 'False' }, { prim: 'None' }, { string: POOL }, fifth, { string: 'sr1' }, { string: TENANT }, { int: '0' }];

        return { prim: 'Pair', args: kind === 'preview' ? [...leaves, { int: '1000' }] : leaves };
    }

    function depositChainOver(world: DepositWorld): DepositChain {
        const rowsFor = (vault: string) =>
            world.indexed
                .filter((d) => d.vault === vault)
                .map((d, i) => ({
                    id: d.level * 10 + i,
                    level: d.level,
                    hash: `op-deposit-${d.level}`,
                    parameter: { entrypoint: 'deposit', value: { session_id: SESSION_HEX } },
                }));
        const indexer = ((url: string) => {
            const query = new URL(url).searchParams;
            const rows = query.get('id.gt') ? [] : rowsFor(query.get('target') ?? '');
            const status = world.indexerStatus ?? 200;

            return Promise.resolve({ ok: status === 200, status, json: () => Promise.resolve(rows) } as Response);
        }) as unknown as typeof fetch;
        const vaultOfBigMap = (id: string) =>
            world.vaults.find((v) => (storageOf(world, v.vault) as { args: { int?: string }[] }).args[4].int === id);

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
                (world.onNode ?? world.indexed)
                    .filter((d) => d.level === level)
                    .map((d) => {
                        const id = (storageOf(world, d.vault) as { args: { int?: string }[] }).args[4].int ?? 'none';

                        return {
                            hash: `op-deposit-${d.level}`,
                            contents: [
                                {
                                    kind: 'transaction',
                                    destination: d.vault,
                                    parameters: {
                                        entrypoint: 'deposit',
                                        value: { prim: 'Pair', args: [{ bytes: SESSION_HEX }, { prim: 'Pair', args: [] }] },
                                    },
                                    metadata: {
                                        operation_result: {
                                            status: 'applied',
                                            lazy_storage_diff: [
                                                {
                                                    kind: 'big_map',
                                                    id,
                                                    diff: {
                                                        action: 'update',
                                                        updates: d.firstWrite
                                                            ? [{ key: { bytes: SESSION_HEX }, value: { prim: 'Pair', args: [] } }]
                                                            : [],
                                                    },
                                                },
                                            ],
                                        },
                                    },
                                },
                            ],
                        };
                    }),
            contractStorage: async (vault) => storageOf(world, vault),
            bigMapHas: async (id, expr) => {
                expect(expr).toBe(sessionKeyScriptExprHash(SESSION_ID));

                const held = world.heldAt?.[vaultOfBigMap(id)?.vault ?? ''] ?? false;

                if (held === 'error') {
                    throw new Error('RPC 500');
                }

                return held;
            },
        };
    }

    /** A stub chain over `messages` and a deposit world, logging every inbox call in order. */
    function chainOver(messages: InboxMessage[], log: string[] = [], world: DepositWorld = worldWith(T - 1_000)): ChainRunInput['chain'] {
        return {
            ...depositChainOver(world),
            headLevel: async () => {
                log.push('head');

                return HEAD;
            },
            scanRange: async (from, to) => {
                log.push(`scan ${from}-${to}`);

                return messages.filter((m) => m.level >= from && m.level <= to);
            },
            fetchBlock: async (level) => {
                log.push(`block ${level}`);

                return messages.filter((m) => m.level === level);
            },
        };
    }

    function run(
        messages: InboxMessage[],
        options: {
            hints?: LocatorHints | null;
            malformed?: string[];
            /** The suppression bracket's deposit (`scan.deposit`). */
            deposit?: number | null;
            /** The deposit world D10 reads; defaults to one first deposit at `deposit` (or T − 1 000). */
            world?: DepositWorld;
            keys?: KeySet;
            receipts?: ReceiptsInput;
            formPoolId?: string;
            /** `null` = no lineage (an override key). */
            lineage?: AdminLineage | null;
            /** Replace the bracket's deposit lookup (D-8 passes the extracted resolver). */
            resolveDeposit?: () => Promise<ScanContext['deposit']>;
            log?: string[];
            onPreliminary?: (p: PreliminaryReport) => void;
        } = {},
    ) {
        const log = options.log ?? [];
        const world = options.world ?? worldWith(options.deposit ?? T - 1_000);

        return runChainVerification({
            verify: {
                roundId: ROUND_ID,
                tenantId: TENANT,
                signingDomain: DOMAIN,
                deploymentListed: true,
                receipts: options.receipts ?? { status: 'ok', receipts: buildReceipts() },
            },
            fromLevel: null,
            toLevel: null,
            hints: { hints: options.hints ?? null, source: 'the link', malformed: options.malformed ?? [] },
            resolveKeys: async () => {
                log.push('keys');

                return options.keys ?? LINEAGE;
            },
            resolveDeposit:
                options.resolveDeposit ??
                (async () => {
                    log.push('deposit');

                    return options.deposit == null ? null : { level: options.deposit, confirmed: true };
                }),
            lineage: () => (options.lineage === undefined ? lineageOf(world) : options.lineage),
            formPoolId: options.formPoolId ?? POOL,
            chain: chainOver(messages, log, world),
            onPreliminary: options.onPreliminary,
        });
    }

    const transcriptHint = (level: number, operationHash = `op-level-${level}`) => ({ level, operationHash });
    const batchHint = (level: number, operationHash: string | null = `op-level-${level}`) => ({ level, operationHash });

    it('resolves the keys, then the hints, then the deposit, and only then scans (D1)', async () => {
        const log: string[] = [];

        await run(round(T - 5), { hints: { transcript: transcriptHint(T) }, deposit: T - 50, log });

        expect(log.slice(0, 4)).toEqual(['keys', `block ${T}`, 'deposit', 'head']);
        expect(log.slice(4).every((entry) => entry.startsWith('scan '))).toBe(true);
    });

    it('D-1(a): confirmed transcript and batch hints scan [min(D, B_h), T] and verify', async () => {
        const batchLevel = T - 500;
        const deposit = T - 1_000;
        const log: string[] = [];
        const result = await run(round(batchLevel), {
            hints: { transcript: transcriptHint(T), seedBatch: batchHint(batchLevel) },
            deposit,
            log,
        });

        expect(result.report.verdict).toBe('verified');
        expect(result.report.scan).toMatchObject({ fromLevel: Math.min(deposit, batchLevel), toLevel: T, headLevel: HEAD });
        expect(log).toContain(`scan ${deposit}-${T}`);
        expect(result.hintedRun).toBeNull();
        expect(result.hints.map((h) => h.fate)).toEqual([
            `used (confirmed at level ${T}, op op-level-${T})`,
            `used (confirmed at level ${batchLevel}, op op-level-${batchLevel})`,
        ]);
        expect(result.report.findings.join('\n')).toContain(
            `Locator hint (RoundTranscript) from the link: used (confirmed at level ${T}, op op-level-${T})`,
        );
    });

    it('D-1(b): ignores a wrong-level, wrong-op, foreign-signed or wrong-round hint and still verifies', async () => {
        const honest = round(T - 5);
        // The same round signed by a key the tenant never registered.
        const [, foreign] = buildRound({ transcriptLevel: T + 7, signingSeed: new Uint8Array(32).fill(7) });
        // Another round's transcript, authentic, in its own block.
        const otherBody = transcriptBody({}, honestPayout(hilo.v1.GAME_TYPE));

        otherBody.splice(1, 16, ...uuid('0f0f0f0f-0000-4000-8000-000000000000'));

        const otherRound = frame(T + 9, otherBody);
        const messages = [...honest, foreign, otherRound];
        const cases: { name: string; hint: { level: number; operationHash: string }; fate: RegExp }[] = [
            { name: 'wrong level', hint: transcriptHint(T + 1, `op-level-${T}`), fate: /^ignored: not found at the stated level/ },
            { name: 'wrong op', hint: transcriptHint(T, 'op-somewhere-else'), fate: /^ignored: not found at the stated level/ },
            { name: 'foreign-signed', hint: transcriptHint(T + 7), fate: /^ignored: not authenticated/ },
            { name: 'wrong round', hint: transcriptHint(T + 9), fate: /^ignored: not found at the stated level/ },
        ];

        for (const { name, hint, fate } of cases) {
            const result = await run(messages, { hints: { transcript: hint }, deposit: T - 50 });

            expect(result.hints, name).toHaveLength(1);
            expect(result.hints[0].used, name).toBe(false);
            expect(result.hints[0].fate, name).toMatch(fate);
            expect(result.report.verdict, name).toBe('verified');
            // Ignored, so the unhinted range applies: the default depth below the head.
            expect(result.report.scan, name).toMatchObject({ fromLevel: HEAD - DEFAULT_SCAN_DEPTH, toLevel: HEAD });
        }
    });

    it('reports malformed hints, and a batch hint no confirmed transcript ties to a seed index, as ignored', async () => {
        const result = await run(round(T - 5), {
            hints: { seedBatch: batchHint(T - 5) },
            malformed: ["the link's transcriptLevel hint is not a positive integer level; it was ignored"],
        });

        expect(result.hints.map((h) => h.fate)).toEqual([
            "ignored: malformed (the link's transcriptLevel hint is not a positive integer level; it was ignored)",
            'ignored: no confirmed transcript states the seed index this batch must cover',
        ]);
        expect(result.report.verdict).toBe('verified');
        expect(result.report.scan).toMatchObject({ fromLevel: HEAD - DEFAULT_SCAN_DEPTH, toLevel: HEAD });
    });

    it('D-1(d): a hinted batch copy at or after T re-runs without the batch hint, and the re-run decides', async () => {
        const trueBatch = T - 5;
        const duplicateLevel = T + 3;
        const [duplicate] = round(duplicateLevel);
        const result = await run([...round(trueBatch), duplicate], {
            hints: { transcript: transcriptHint(T), seedBatch: batchHint(duplicateLevel) },
            deposit: null,
        });

        expect(result.hintedRun).not.toBeNull();
        expect(result.hintedRun?.verdict).toBe('failed');
        expect(statusOf(result.hintedRun ?? { checks: [] }, 'commitment-order')).toBe('fail');
        expect(result.report.verdict).toBe('verified');
        expect(statusOf(result.report, 'commitment-order')).toBe('pass');
        // The re-run scans the unhinted depth anchored at T, never near the head.
        expect(result.report.scan).toMatchObject({ fromLevel: T - DEFAULT_SCAN_DEPTH, toLevel: T });
        expect(result.report.findings.join('\n')).toContain('re-ran without the batch hint');
    });

    it('D6: any other hinted verdict stands with no re-run', async () => {
        const batchLevel = T - 500;
        const inflated = buildRound({
            batchLevel,
            transcriptLevel: T,
            claimedPayout: honestPayout(hilo.v1.GAME_TYPE) + 1n,
        });
        const result = await run(inflated, {
            hints: { transcript: transcriptHint(T), seedBatch: batchHint(batchLevel) },
            deposit: T - 1_000,
        });

        expect(result.report.verdict).toBe('failed');
        expect(statusOf(result.report, 'replay-payout')).toBe('fail');
        expect(result.hintedRun).toBeNull();
    });

    it('D-1(e): a transcript hint alone keeps the unhinted depth U as the lower bound', async () => {
        const result = await run(round(T - 5), { hints: { transcript: transcriptHint(T) }, deposit: T - 5_000 });

        expect(result.report.verdict).toBe('verified');
        expect(result.report.scan).toMatchObject({
            fromLevel: Math.min(T - DEFAULT_SCAN_DEPTH, T - 5_000),
            toLevel: T,
        });
    });

    it('D-3: a preliminary pass with no verdict word, then the final pass replaces it', async () => {
        const batchLevel = T - 30_000;
        const deposit = T - 10_000;
        // An authenticated early copy of the round between the batch and the
        // deposit: outside the preliminary window, inside the final one.
        const earlyCopy = T - 25_000;
        const [, early] = round(batchLevel, earlyCopy);
        const seen: PreliminaryReport[] = [];
        const result = await run([...round(batchLevel), early], {
            hints: { transcript: transcriptHint(T), seedBatch: batchHint(batchLevel) },
            deposit,
            onPreliminary: (p) => seen.push(p),
        });

        expect(seen).toHaveLength(1);
        expect(seen[0].label).toBe(`Preliminary (scan continuing to level ${batchLevel}): no failure found so far`);
        expect(seen[0].label).not.toMatch(VERDICT_WORD);
        expect('verdict' in seen[0]).toBe(false);
        expect(seen[0].scan).toMatchObject({ fromLevel: deposit, toLevel: T });
        expect(result.preliminary).toBe(seen[0]);
        // The final pass reaches the early copy, and the kernel applies the
        // FIRST copy, so that is the one checked. It lies below the session's
        // first deposit, so the kernel applied it as a session-missing reject:
        // the session-before-transcript check (D10) fails it.
        expect(result.report.scan).toMatchObject({ fromLevel: batchLevel, toLevel: T });
        expect(result.report.references.find((r) => r.summary.startsWith('RoundTranscript'))?.level).toBe(earlyCopy);
        expect(statusOf(seen[0], SESSION_BEFORE_TRANSCRIPT_CHECK_ID)).toBe('pass');
        expect(statusOf(result.report, SESSION_BEFORE_TRANSCRIPT_CHECK_ID)).toBe('fail');
        expect(result.report.findings.join('\n')).toContain('REJECT_SESSION_MISSING');
        expect(result.report.verdict).toBe('failed');
    });

    it('D-4: the bracket is ok at the head with a found deposit, and narrow when the scan stops at T', () => {
        const deposit = { level: T - 1_000, confirmed: true };

        expect(describeBracket({ fromLevel: T - 2_000, toLevel: HEAD, headLevel: HEAD, deposit }).status).toBe('ok');

        const capped = describeBracket({ fromLevel: T - 2_000, toLevel: T, headLevel: HEAD, deposit });

        expect(capped.status).toBe('narrow');
        expect(capped.reason).toContain(`stopped at level ${T}, below the head`);
    });

    it('D3: a found round is never made inconclusive by a scan capped at T below the head', async () => {
        const result = await run(round(T - 5), { hints: { transcript: transcriptHint(T) }, deposit: null });

        expect(result.report.scan?.toLevel).toBeLessThan(HEAD);
        expect(result.report.verdict).toBe('verified');
    });
    // ── session-before-transcript (D10) ─────────────────────────────────

    const d10 = (report: { checks: { id: string; status: string; detail: string }[] }) =>
        report.checks.find((c) => c.id === SESSION_BEFORE_TRANSCRIPT_CHECK_ID);
    const findingsOf = (report: { findings: string[] }) => report.findings.join('\n');

    /**
     * The pre-deposit reject layout: an authenticated copy at T_e, between the
     * batch B and the session's deposit D, and the honest copy at T > D.
     */
    function preDepositReject(layout: { batch: number; early: number }): InboxMessage[] {
        const [, early] = round(layout.batch, layout.early);

        return [...round(layout.batch), early];
    }

    const C_LAYOUT = { batch: T - 30_000, early: T - 25_000, deposit: T - 22_000 };
    const C_HINTS = { transcript: transcriptHint(T), seedBatch: batchHint(C_LAYOUT.batch) };

    it('D-1(c): a copy applied before the session existed fails, outside the default head window', async () => {
        const result = await run(preDepositReject(C_LAYOUT), { hints: C_HINTS, deposit: C_LAYOUT.deposit });

        // The copy is outside [head − 20 000, head], so only the hinted window reaches it.
        expect(C_LAYOUT.early).toBeLessThan(HEAD - DEFAULT_SCAN_DEPTH);
        expect(result.report.references.find((r) => r.summary.startsWith('RoundTranscript'))?.level).toBe(C_LAYOUT.early);
        expect(d10(result.report)?.status).toBe('fail');
        expect(d10(result.report)?.detail).toContain('REJECT_SESSION_MISSING');
        expect(findingsOf(result.report)).toContain('REJECT_SESSION_MISSING');
        expect(findingsOf(result.report)).toContain(`level ${C_LAYOUT.early}) predates the earliest deposit the indexer reports (level ${C_LAYOUT.deposit})`);
        expect(result.report.verdict).toBe('failed');
    });

    it('D-1(f): a deposit and a transcript at the same level are not ordered, so the round is incomplete', async () => {
        const result = await run(round(T - 5), { hints: { transcript: transcriptHint(T) }, deposit: T });

        expect(d10(result.report)?.status).toBe('unavailable');
        expect(d10(result.report)?.detail).toContain(`share level ${T}`);
        expect(result.report.verdict).toBe('incomplete');
    });

    it('D-1(g): with no keys, a forged copy below the deposit is unauthenticated and never fails the round', async () => {
        const deposit = T - 1_000;
        // B < forged copy < D < honest copy, so only the session check can speak to the forged copy.
        const [, forged] = buildRound({ transcriptLevel: deposit - 5, signingSeed: new Uint8Array(32).fill(7) });
        const result = await run([...round(deposit - 100), forged], {
            keys: { status: 'unavailable', reason: 'the lineage walk failed in this fixture' },
            deposit,
        });

        expect(result.report.references.find((r) => r.summary.startsWith('RoundTranscript'))?.level).toBe(deposit - 5);
        expect(d10(result.report)?.status).toBe('unavailable');
        expect(d10(result.report)?.detail).toContain('the transcript copy is not authenticated');
        expect(result.report.verdict).toBe('incomplete');
    });

    it('D-1(h): receipts labelled with another pool fail the lookup, never the round', async () => {
        const result = await run(preDepositReject(C_LAYOUT), {
            hints: C_HINTS,
            deposit: C_LAYOUT.deposit,
            receipts: { status: 'ok', receipts: buildReceipts({ poolId: 'other-pool' }) },
            formPoolId: 'other-pool',
        });

        expect(d10(result.report)?.status).toBe('unavailable');
        expect(d10(result.report)?.detail).toContain('the form names pool other-pool, the signed transcript names pool standard');
        expect(result.report.verdict).toBe('incomplete');
    });

    it('D-1(i): an indexer deposit the node does not hold fails the lookup', async () => {
        const result = await run(round(T - 5), {
            hints: { transcript: transcriptHint(T) },
            world: worldWith(T + 10, { onNode: [] }),
        });

        expect(d10(result.report)?.status).toBe('unavailable');
        expect(d10(result.report)?.detail).toContain('indexer and node disagree');
        expect(result.report.verdict).toBe('incomplete');
    });

    it('D-1(k): a top-up above the transcript, with the first deposit omitted, is not proven first', async () => {
        const result = await run(round(T - 5), {
            hints: { transcript: transcriptHint(T) },
            world: worldWith(T + 10, { indexed: [{ vault: VAULT_A, level: T + 10, firstWrite: false }] }),
        });

        expect(d10(result.report)?.status).toBe('unavailable');
        expect(d10(result.report)?.detail).toContain('not shown to be the session-creating one');
        expect(result.report.verdict).toBe('incomplete');
    });

    it('D-1(k) twin: a preview-vault deposit above the transcript never proves first', async () => {
        const result = await run(round(T - 5), {
            hints: { transcript: transcriptHint(T) },
            world: worldWith(T + 10, { vaults: [{ vault: VAULT_A, level: 1, kind: 'preview' }] }),
        });

        expect(d10(result.report)?.status).toBe('unavailable');
        expect(d10(result.report)?.detail).toContain('not shown to be the session-creating one');
        expect(d10(result.report)?.detail).toContain('keeps no sessions big_map');
        expect(result.report.verdict).toBe('incomplete');
    });

    /** Two production vaults registered before T_e; the indexer returns only V2's first write above T_e. */
    const rotated = (v1: DepositWorld['vaults'][number]['kind'], held: boolean | 'error'): DepositWorld => ({
        vaults: [
            { vault: VAULT_B, level: 1, kind: v1 },
            { vault: VAULT_A, level: 2, kind: 'production' },
        ],
        indexed: [{ vault: VAULT_A, level: T + 10, firstWrite: true }],
        heldAt: { [VAULT_B]: held },
    });

    it('D-1(l): a rotation overlap, where the older vault holds the session, is not a failure', async () => {
        const result = await run(round(T - 5), { hints: { transcript: transcriptHint(T) }, world: rotated('production', true) });

        expect(d10(result.report)?.status).toBe('unavailable');
        expect(d10(result.report)?.detail).toContain('Multi-vault pool; first-deposit proof is per vault');
        expect(d10(result.report)?.detail).toContain(`vault ${VAULT_B} holds a sessions entry for this session`);
        expect(result.report.verdict).toBe('incomplete');
    });

    it('D-1(m): on a rotated pool, a copy below the only binding deposit fails', async () => {
        const result = await run(round(T - 5), { hints: { transcript: transcriptHint(T) }, world: rotated('production', false) });

        expect(d10(result.report)?.status).toBe('fail');
        expect(findingsOf(result.report)).toContain('The node confirms it as the session-creating deposit');
        expect(findingsOf(result.report)).toContain('REJECT_SESSION_MISSING');
        expect(result.report.verdict).toBe('failed');
    });

    for (const [name, world, reason] of [
        ['the older vault lookup returns 500', rotated('production', 'error'), `vault ${VAULT_B} could not be looked up`],
        ['the older vault is a preview vault', rotated('preview', false), `vault ${VAULT_B} keeps no sessions big_map`],
        ['the older vault has no determinable big_map id', rotated('unknown-id', false), `vault ${VAULT_B} keeps no sessions big_map`],
    ] as const) {
        it(`D-1(m) twin: ${name}, so the round is incomplete`, async () => {
            const result = await run(round(T - 5), { hints: { transcript: transcriptHint(T) }, world });

            expect(d10(result.report)?.status).toBe('unavailable');
            expect(d10(result.report)?.detail).toContain('Multi-vault pool');
            expect(d10(result.report)?.detail).toContain(reason);
            expect(result.report.verdict).toBe('incomplete');
        });
    }

    it('D-1(j): an indexer outage with complete receipts reads incomplete (accepted degradation)', async () => {
        const result = await run(round(T - 5), {
            hints: { transcript: transcriptHint(T) },
            world: worldWith(T - 1_000, { indexerStatus: 500 }),
        });

        expect(d10(result.report)?.status).toBe('unavailable');
        expect(d10(result.report)?.detail).toContain('the indexer returned 500');
        // Every other proof passed: without D10 this round read `verified`.
        expect(result.report.checks.filter((c) => c.status !== 'pass').map((c) => c.id)).toEqual(
            expect.arrayContaining([SESSION_BEFORE_TRANSCRIPT_CHECK_ID]),
        );
        expect(result.report.checks.some((c) => c.status === 'fail')).toBe(false);
        expect(result.report.verdict).toBe('incomplete');
    });

    describe('D-2: a bare link (no receipts)', () => {
        const bare = (world: DepositWorld) =>
            run(round(T - 5), { hints: { transcript: transcriptHint(T) }, receipts: { status: 'absent' }, world });

        it('found: the session id comes from the transcript and the check passes; incomplete without receipts', async () => {
            const result = await bare(worldWith(T - 1_000));
            const bracket = describeBracket(result.report.scan);

            expect(d10(result.report)?.status).toBe('pass');
            expect(result.report.verdict).toBe('incomplete');
            expect(bracket.status).toBe('narrow');
            expect(bracket.reason).toContain(`stopped at level ${T}, below the head`);
        });

        it("none: an indexer's silence is reported, never concluded", async () => {
            const result = await bare(worldWith(T - 1_000, { indexed: [] }));
            const bracket = describeBracket(result.report.scan);

            expect(d10(result.report)?.status).toBe('unavailable');
            expect(findingsOf(result.report)).toContain("an indexer's silence is not proof of absence");
            expect(findingsOf(result.report)).toContain('REJECT_SESSION_MISSING');
            expect(result.report.verdict).toBe('incomplete');
            expect(bracket.status).toBe('narrow');
            expect(bracket.reason).toContain(`stopped at level ${T}, below the head`);
        });

        it('failed: an indexer error leaves the check unavailable', async () => {
            const result = await bare(worldWith(T - 1_000, { indexerStatus: 500 }));

            expect(d10(result.report)?.status).toBe('unavailable');
            expect(d10(result.report)?.detail).toContain('the indexer returned 500');
            expect(result.report.verdict).toBe('incomplete');
        });
    });

    it('D-4: session-before-transcript, all eight rows', () => {
        const found = (level: number, firstProven: boolean, clear: boolean | null): DepositLocation => ({
            lookup: 'found',
            level,
            operationHash: 'op-d',
            vault: VAULT_A,
            firstProven,
            otherVaults: clear === null ? null : { clear, detail: clear ? 'no other vault' : `vault ${VAULT_B} holds a sessions entry` },
            detail: 'deposit detail',
        });
        const rows: { name: string; authenticated: boolean; deposit: DepositLocation; status: string; text: string }[] = [
            { name: 'unauthenticated', authenticated: false, deposit: found(T - 1, true, true), status: 'unavailable', text: 'not authenticated' },
            { name: 'found, T_e > D', authenticated: true, deposit: found(T - 1, false, null), status: 'pass', text: `a deposit at level ${T - 1}` },
            { name: 'found, T_e < D, first, clear', authenticated: true, deposit: found(T + 1, true, true), status: 'fail', text: 'REJECT_SESSION_MISSING' },
            { name: 'found, T_e < D, not first', authenticated: true, deposit: found(T + 1, false, null), status: 'unavailable', text: 'not shown to be the session-creating one' },
            { name: 'found, T_e < D, first, another vault holds it', authenticated: true, deposit: found(T + 1, true, false), status: 'unavailable', text: 'Multi-vault pool; first-deposit proof is per vault' },
            { name: 'found, T_e == D', authenticated: true, deposit: found(T, true, true), status: 'unavailable', text: `share level ${T}` },
            {
                name: 'none',
                authenticated: true,
                deposit: { lookup: 'none', level: null, operationHash: null, vault: null, firstProven: false, otherVaults: null, detail: 'paged to the end' },
                status: 'unavailable',
                text: "an indexer's silence is not proof of absence",
            },
            {
                name: 'failed',
                authenticated: true,
                deposit: { lookup: 'failed', level: null, operationHash: null, vault: null, firstProven: false, otherVaults: null, detail: 'the indexer returned 500' },
                status: 'unavailable',
                text: 'lookup failed: the indexer returned 500',
            },
        ];

        for (const row of rows) {
            const { check } = evaluateSessionBeforeTranscript(T, row.authenticated, row.deposit);

            expect(check.status, row.name).toBe(row.status);
            expect(check.detail, row.name).toContain(row.text);
        }
    });

    describe('D-6b: the paste path', () => {
        const paste = (messages: InboxMessage[], options: { keys?: KeySet; lineage?: AdminLineage | null } = {}) => {
            const world = worldWith(T - 1_000);

            return runPastedVerification({
                verify: {
                    roundId: ROUND_ID,
                    tenantId: TENANT,
                    signingDomain: DOMAIN,
                    deploymentListed: true,
                    receipts: { status: 'ok', receipts: buildReceipts() },
                },
                messages,
                keys: options.keys ?? LINEAGE,
                lineage: options.lineage === undefined ? lineageOf(world) : options.lineage,
                formPoolId: POOL,
                chain: depositChainOver(world),
            });
        };

        it('looks the deposit up from a pasted authenticated transcript and verifies, with no scan', async () => {
            const report = await paste(round(T - 5));

            expect(report.scan).toBeNull();
            expect(d10(report)?.status).toBe('pass');
            expect(report.verdict).toBe('verified');
        });

        it('is inconclusive, never suppressed, for a paste with receipts and no transcript', async () => {
            const report = await paste(round(T - 5).filter((m) => m.envelope.message.kind !== 'round-transcript'));

            expect(report.scan).toBeNull();
            expect(d10(report)).toBeUndefined();
            expect(report.verdict).toBe('inconclusive');
        });

        it('is incomplete under the offline key override, which carries no lineage', async () => {
            const report = await paste(round(T - 5), {
                keys: { status: 'available', keys: [{ edpk: encodeEdpk(PUBLIC_KEY), registration: null }] },
                lineage: null,
            });

            expect(d10(report)?.status).toBe('unavailable');
            expect(d10(report)?.detail).toContain('no administrator lineage was derived');
            expect(report.verdict).toBe('incomplete');
        });
    });

    it('D-8: the no-transcript ladder keeps its deposit through the extracted resolver and reaches suppressed', async () => {
        const deposit = T - 1_000;
        const world = worldWith(deposit);
        const endSession = frame(deposit + 50, [...u8(0x02), ...uuid(SESSION_ID), ...u8(0)]);
        const receipts: ReceiptsInput = { status: 'ok', receipts: buildReceipts() };
        const withoutTranscript = round(T - 5).filter((m) => m.envelope.message.kind !== 'round-transcript');
        const result = await run([...withoutTranscript, endSession], {
            receipts,
            world,
            resolveDeposit: () =>
                resolveReceiptsDeposit({
                    receipts,
                    lineage: lineageOf(world),
                    formTenantId: TENANT,
                    formPoolId: POOL,
                    locateDeposit: depositChainOver(world).locateDeposit,
                }),
        });

        expect(result.report.scan).toMatchObject({ toLevel: HEAD, headLevel: HEAD, deposit: { level: deposit, confirmed: true } });
        expect(d10(result.report)).toBeUndefined();
        expect(result.report.verdict).toBe('suppressed');
    });
});
