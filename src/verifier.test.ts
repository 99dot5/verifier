// @vitest-environment node
// End-to-end: encode a synthetic round as real wire frames (Borsh + genuine
// Ed25519 signatures over the blake2b pre-hash), then verify it.
//
// A round is now ONE `RoundTranscript` message, so the fixture is a SeedBatch
// at level L and the transcript at L+1. The round's maths is not hard-coded:
// the expected payout is taken from the same replayer the verifier calls, and
// that replayer is pinned against the shared golden vectors by hilo.test.ts /
// plinko.test.ts. What this file exercises is the orchestration around it —
// earliest-wins, the commitment pair, signatures, the optional client-seed
// check, and every way a round can fail to verify.
import * as ed from '@noble/ed25519';
import { blake2b } from '@noble/hashes/blake2.js';
import { describe, expect, it } from 'vitest';
import type { InboxMessage } from './chain/inbox';
import { supportedGameTypes, verifyRound } from './verifier';
import * as crash from './verify/crash';
import * as hilo from './verify/hilo';
import * as mines from './verify/mines';
import * as plinko from './verify/plinko';
import { REJECTION_CHECK_ID } from './verify/rejections';
import { payoutUnits } from './verify/ints';
import { bytesToHex, hexToBytes, serverSeedCommitment } from './verify/seed';
import type { ReplayResult, TranscriptAction } from './verify/types';
import { actionTypeOf, tagOf } from './wire/action-tags';
import { decodeExternalMessage } from './wire/messages';
import { encodeEdpk } from './wire/signature';
import { commandFrame, serverFrame, type CommandGameSpec, type ServerFrameSpec } from './receipts/fixtures';
import { PROJECTION_CHECK_ID } from './verify/projection';
import { computeCommitment } from './receipts/commitment';
import type { ImportedReceipts } from './receipts/import';
import type { ReceiptsInput, ScanContext } from './verifier';

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

function frame(level: number, payloadBody: number[], signingSeed: Uint8Array = SIGNING_SEED): InboxMessage {
    // VersionedEnvelope::V1(PoolScopedMessage { tenant, pool, payload }).
    const payload = new Uint8Array([...u8(0), ...str(TENANT), ...str(POOL), ...payloadBody]);
    const signature = ed.sign(blake2b(payload, { dkLen: 32 }), Uint8Array.from(signingSeed));
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
 * `client_seed` on the wire is the blake2b-256 of the player's text, and the
 * engine consumes its lowercase hex — so any 32 bytes make a valid round. The
 * default pair is chosen so the HiLo `higher` below WINS: a losing guess would
 * settle the round and the trailing cashout would be rejected as an action
 * after settlement, which is a different test.
 */
const CLIENT_SEED = new Uint8Array(32).fill(1);
const SERVER_SEED = new Uint8Array(32).fill(9);

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

function betCommand(game: CommandGameSpec = HILO_ARM, clientSeed?: string): Uint8Array {
    return commandFrame(SESSION_SEED, {
        requestId: BET_REQUEST,
        sessionId: SESSION_ID,
        payloadCase: 'placeBet',
        clientSeed,
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
                payload: { case: 'roundStarted', roundId: ROUND_ID },
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
function plinkoConfig(rows: number, risk: plinko.Risk): Uint8Array {
    return new Uint8Array([...u32(rows), plinko.RISK_BORSH_TAG[risk]]);
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
    /** Defaults to the fold over the honest receipts' command frames. */
    playerCommitment?: Uint8Array;
}

/**
 * The payout an honest sequencer would claim, straight from the replayer the
 * verifier itself calls. Deliberately not a hard-coded number: the maths is
 * pinned against the golden vectors in hilo.test.ts / plinko.test.ts, and
 * restating it here would only pin this file to itself.
 */
function honestPayout(gameType: string, options: RoundOptions = {}): bigint {
    const replayers: Record<string, (s: string, c: string, a: TranscriptAction[]) => ReplayResult> = {
        [crash.GAME_TYPE]: crash.replay,
        [hilo.GAME_TYPE]: hilo.replay,
        [mines.GAME_TYPE]: mines.replay,
        [plinko.GAME_TYPE]: plinko.replay,
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
    );

    return payoutUnits(STAKE_MUTEZ, replayed.cumulativePpm);
}

function transcriptBody(options: RoundOptions, claimedPayout: bigint): number[] {
    const wireActions = options.actions ?? HILO_ACTIONS;

    return [
        ...u8(0x01), // SequencerMessage::RoundTranscript
        ...uuid(ROUND_ID),
        ...uuid(SESSION_ID),
        ...str(options.gameType ?? hilo.GAME_TYPE),
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
        options.claimedPayout ?? honestPayout(options.gameType ?? hilo.GAME_TYPE, options);

    return [
        frame(
            options.batchLevel ?? BATCH_LEVEL,
            [
                ...u8(0x00), // SequencerMessage::SeedBatch
                ...u64(BATCH_START),
                ...u32(hashes.length),
                ...hashes.flatMap((h) => Array.from(h)),
                ...u64(4242n),
                ...str('52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971'),
            ],
            options.signingSeed,
        ),
        frame(
            options.transcriptLevel ?? TRANSCRIPT_LEVEL,
            transcriptBody(options, claimedPayout),
            options.signingSeed,
        ),
        ...(options.extraTranscripts ?? []).map((extra) =>
            frame(extra.level, transcriptBody(options, extra.claimedPayout), options.signingSeed),
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
    } = {},
) {
    const key = extra.publicKey === undefined ? PUBLIC_KEY : extra.publicKey;

    return verifyRound({
        // The honest export and a bracketing range are the DEFAULTS, so every
        // pre-existing test still exercises a fully-evidenced round; a test
        // that cares about a missing half says so explicitly.
        receipts: extra.receipts ?? { status: 'ok', receipts: buildReceipts() },
        scan: extra.scan === undefined ? BRACKETING_SCAN : extra.scan,
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
        expect(report.replay?.outcome).toBe('cashout');
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
        const inflated = honestPayout(hilo.GAME_TYPE) + 1_000_000n;
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
        const inflated = honestPayout(hilo.GAME_TYPE) + 1_000_000n;
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
        const report = verify(buildRound({ claimedPayout: honestPayout(hilo.GAME_TYPE) + 1n }));

        expect(report.verdict).toBe('failed');
        expect(statusOf(report, 'replay-payout')).toBe('fail');
    });

    it('fails when an action payload is tampered with', () => {
        // Plinko seals its outcome from the place-bet config, so editing the
        // payload changes the multiplier the round should have paid — the one
        // action field a transcript can carry that is not a bare tag.
        const honestActions = [action('place-bet', plinkoConfig(8, 'low')), action('cashout')];
        const claimed = honestPayout(plinko.GAME_TYPE, { gameType: plinko.GAME_TYPE, actions: honestActions });
        const shape = {
            bet: betCommand({ game: 'plinko', rows: 8, risk: 1 }),
            cashOut: cashOutCommand({ game: 'plinko' }),
        };
        const receipts: ReceiptsInput = { status: 'ok', receipts: buildReceipts({}, shape) };
        const green = verify(
            buildRound({
                gameType: plinko.GAME_TYPE,
                actions: honestActions,
                playerCommitment: commitmentOf(shape),
            }),
            { receipts },
        );

        expect(green.verdict).toBe('verified');

        const report = verify(
            buildRound({
                gameType: plinko.GAME_TYPE,
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
            transcriptBody({ serverSeed: new Uint8Array(32).fill(8) }, honestPayout(hilo.GAME_TYPE)),
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
            const options = { gameType: plinko.GAME_TYPE, actions: PLINKO_ACTIONS, clientSeed, playerCommitment: commitment };

            return buildRound({ ...options, claimedPayout: honestPayout(plinko.GAME_TYPE, options) });
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

    it('reports an unimplemented game as unavailable rather than guessing', () => {
        // hydra:v1 is the last shipped game without a replayer here; crash:v1
        // gained one and is exercised by verify/crash.test.ts. The PROJECTION
        // of its commands still runs — that table covers all five games — so
        // this also pins that a missing replayer degrades the verdict without
        // taking the fourth proof down with it.
        const gameType = 'hydra:v1';
        const shape = {
            bet: betCommand({ game: 'hydra', hero: 2 }),
            cashOut: cashOutCommand({ game: 'hydra' }),
        };
        const report = verify(
            buildRound({
                gameType,
                actions: [action('place-bet', new Uint8Array([2])), action('cashout')],
                claimedPayout: 0n,
                playerCommitment: commitmentOf(shape),
            }),
            { receipts: { status: 'ok', receipts: buildReceipts({}, shape) } },
        );

        expect(supportedGameTypes()).not.toContain(gameType);
        expect(statusOf(report, 'replay')).toBe('unavailable');
        expect(statusOf(report, PROJECTION_CHECK_ID)).toBe('pass');
        expect(report.verdict).toBe('incomplete');
        expect(report.checks.find((c) => c.id === 'replay')?.detail).toContain(gameType);
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

    it('fails an unfinished transcript instead of paying the live position', () => {
        const messages = buildRound({ actions: [action('place-bet'), action('higher')] });
        const report = verify(messages);

        expect(statusOf(report, 'replay-outcome')).toBe('fail');
        expect(report.verdict).toBe('failed');
    });

    it('reports signature failure under the wrong key', () => {
        const report = verify(buildRound(), { publicKey: new Uint8Array(32).fill(7) });

        expect(statusOf(report, 'signatures')).toBe('fail');
        expect(report.verdict).toBe('failed');
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

    it('is incomplete, never verified, without the player\u2019s receipts', () => {
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

    it('fails when the export\u2019s commitment does not match the chain', () => {
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

    it('is INCONCLUSIVE when the scan started after the session\u2019s deposit', () => {
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
            ...str(hilo.GAME_TYPE),
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

    it('stays UNDETERMINED when only a sibling round\u2019s transcript is on chain', () => {
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
                        payload: { case: 'roundStarted', roundId: ROUND_ID },
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
            gameType: crash.GAME_TYPE,
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
    const CRASH_TICK = crash.crashRound(bytesToHex(SERVER_SEED), bytesToHex(CLIENT_SEED)).crashTick;
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
        bet: betCommand({ game: 'crash' }),
        cashOut: cashOutCommand({ game: 'crash', tick: CASHOUT_TICK }),
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
                gameType: crash.GAME_TYPE,
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
    const EXPIRE_BET = betCommand({ game: 'crash' });
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
                gameType: crash.GAME_TYPE,
                actions: EXPIRE_ACTIONS,
                playerCommitment: EXPIRE_COMMITMENT,
            }),
            { receipts },
        );
    }

    it('has a crash round with room before the bust, or the cases below are vacuous', () => {
        expect(CRASH_TICK).toBeGreaterThan(2n);
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
 * same `verify/mines.ts` layout derivation the verifier itself calls (pinned
 * against the shared golden vectors by `mines.test.ts`), and the claimed
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
            const layout = mines.deriveLayout(bytesToHex(SERVER_SEED), bytesToHex(CLIENT_SEED), MINE_COUNT);
            const mineSet = new Set(layout.minePositions);

            return [...Array(mines.TOTAL_TILES).keys()].filter((candidate) => !mineSet.has(candidate));
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
                        payload: { case: 'roundStarted', roundId: ROUND_ID },
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
                gameType: mines.GAME_TYPE,
                actions: ACTIONS,
                playerCommitment: COMMITMENT,
            });
        }

        it('has two safe tiles, or the round below is a loss and the swap case is vacuous', () => {
            // The swap case needs a SECOND safe tile: substituting a mine
            // would end the round at the reveal, and the case would fail on
            // "action after settlement" rather than on the proof it is about.
            const layout = mines.deriveLayout(bytesToHex(SERVER_SEED), bytesToHex(CLIENT_SEED), MINE_COUNT);

            expect(SAFE_TILES.length).toBeGreaterThanOrEqual(2);
            expect(layout.minePositions).not.toContain(SAFE_TILE);
            expect(layout.minePositions).not.toContain(OTHER_SAFE_TILE);
            expect(OTHER_SAFE_TILE).not.toBe(SAFE_TILE);
        });

        it('verifies a clean mines round end to end', () => {
            const report = verify(round(), { receipts: { status: 'ok', receipts: receipts() } });

            expect(report.verdict).toBe('verified');
            expect(report.gameType).toBe('mines:v1');
            expect(report.replay?.outcome).toBe('cashout');
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
                buildRound({ gameType: mines.GAME_TYPE, actions: swapped, playerCommitment: COMMITMENT }),
                { receipts: { status: 'ok', receipts: receipts() } },
            );

            expect(statusOf(report, PROJECTION_CHECK_ID)).toBe('fail');
            expect(report.verdict).toBe('failed');
            // The commitment proofs still pass, which is the whole point.
            expect(statusOf(report, 'commitment-vs-chain')).toBe('pass');
            expect(statusOf(report, 'replay-payout')).toBe('pass');
        });
    });

    describe('plinko:v1', () => {
        const ROWS = 8;
        const ACTIONS = [action('place-bet', plinkoConfig(ROWS, 'low')), action('cashout')];
        /** `Risk.LOW` is the PROTO enum value 1, against the borsh tag 0. */
        const BET_ARM: CommandGameSpec = { game: 'plinko', rows: ROWS, risk: 1 };

        function round(commitment: Uint8Array) {
            return buildRound({ gameType: plinko.GAME_TYPE, actions: ACTIONS, playerCommitment: commitment });
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
                                payload: { case: 'roundStarted', roundId: ROUND_ID },
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
