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
import { verifyRound } from './verifier';
import * as hilo from './verify/hilo';
import * as plinko from './verify/plinko';
import { payoutUnits } from './verify/ints';
import { bytesToHex, hexToBytes, serverSeedCommitment } from './verify/seed';
import type { ReplayResult, TranscriptAction } from './verify/types';
import { actionTypeOf, tagOf } from './wire/action-tags';
import { decodeExternalMessage } from './wire/messages';
import { encodeEdpk } from './wire/signature';
import { commandFrame, serverFrame, type ServerFrameSpec } from './receipts/fixtures';
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

const BET_COMMAND = commandFrame(SESSION_SEED, {
    requestId: BET_REQUEST,
    sessionId: SESSION_ID,
    payloadCase: 'placeBet',
});
const CASHOUT_COMMAND = commandFrame(SESSION_SEED, {
    requestId: CASHOUT_REQUEST,
    sessionId: SESSION_ID,
    payloadCase: 'cashOut',
});

const PLAYER_COMMITMENT = computeCommitment([BET_COMMAND, CASHOUT_COMMAND]);

const ROUND_ENDED_SPEC: ServerFrameSpec = {
    sequence: 5,
    sessionId: SESSION_ID,
    relatedRequestId: CASHOUT_REQUEST,
    payload: { case: 'roundEnded', roundId: ROUND_ID, actionIndex: 1, playerCommitment: PLAYER_COMMITMENT },
};

/** The honest export: two commands, both accepted, both placed by the server. */
function buildReceipts(overrides: Partial<ImportedReceipts> = {}): ImportedReceipts {
    const frame = (spec: ServerFrameSpec) => ({
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
        sessionPublicKey: encodeEdpk(SESSION_PUBLIC_KEY),
        depositOperationLevel: BATCH_LEVEL - 10,
        commands: [
            { requestId: BET_REQUEST, payloadCase: 'placeBet', frame: BET_COMMAND, sentAtUnixMs: 1 },
            { requestId: CASHOUT_REQUEST, payloadCase: 'cashOut', frame: CASHOUT_COMMAND, sentAtUnixMs: 2 },
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
            frame(ROUND_ENDED_SPEC),
        ],
        roundEndedFrame: serverFrame(SIGNING_SEED, ROUND_ENDED_SPEC),
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

const HILO_ACTIONS = [action('place-bet'), action('higher'), action('cashout')];

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
}

/**
 * The payout an honest sequencer would claim, straight from the replayer the
 * verifier itself calls. Deliberately not a hard-coded number: the maths is
 * pinned against the golden vectors in hilo.test.ts / plinko.test.ts, and
 * restating it here would only pin this file to itself.
 */
function honestPayout(gameType: string, options: RoundOptions = {}): bigint {
    const replayers: Record<string, (s: string, c: string, a: TranscriptAction[]) => ReplayResult> = {
        [hilo.GAME_TYPE]: hilo.replay,
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
        ...Array.from(PLAYER_COMMITMENT),
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
        const green = verify(buildRound({ gameType: plinko.GAME_TYPE, actions: honestActions }));

        expect(green.verdict).toBe('verified');

        const report = verify(
            buildRound({
                gameType: plinko.GAME_TYPE,
                actions: [action('place-bet', plinkoConfig(16, 'high')), action('cashout')],
                claimedPayout: claimed,
            }),
        );

        expect(report.verdict).toBe('failed');
        expect(statusOf(report, 'replay-payout')).toBe('fail');
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

    it('leaves the client-seed check unavailable, not failed, when no text is given', () => {
        const report = verify(buildRound());

        expect(statusOf(report, 'client-seed-text')).toBe('unavailable');
        expect(report.verdict).toBe('verified');
    });

    it('reports crash and hydra as unavailable rather than guessing', () => {
        for (const gameType of ['crash:v1', 'hydra:v1']) {
            const report = verify(
                buildRound({ gameType, actions: [action('place-bet')], claimedPayout: 0n }),
            );

            expect(statusOf(report, 'replay')).toBe('unavailable');
            expect(report.verdict).toBe('incomplete');
            expect(report.checks.find((c) => c.id === 'replay')?.detail).toContain(gameType);
        }
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

    it('is incomplete, never verified, without the player\u2019s receipts', () => {
        // The chain proofs all pass, but nothing ties the on-chain round to
        // the commands the player authorised — so the transcript's
        // player_commitment is a number the server chose, and the verdict must
        // say so rather than borrowing the credibility of a full check.
        const report = verify(buildRound(), { receipts: { status: 'absent' } });

        expect(report.verdict).toBe('incomplete');
        expect(statusOf(report, 'commitment-vs-chain')).toBe('unavailable');
        expect(statusOf(report, 'replay-payout')).toBe('pass');
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
