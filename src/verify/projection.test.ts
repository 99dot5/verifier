// @vitest-environment node
/**
 * The fourth proof, rule by rule.
 *
 * Every row of the projection table gets a NEGATIVE proof here: a test that
 * mutates the transcript action away from the command the player signed and
 * asserts a `fail`. A rule with no failing test does not ship — a check that
 * cannot fail is worse than no check, because it reads as evidence.
 *
 * The inputs are built directly rather than driven through `verifyRound`, so a
 * case can express shapes an end-to-end fixture cannot reach at all: a
 * place-bet the reconstruction did not bind, a command bound past the end of
 * the transcript, a `RoundEnded` from a producer that predates `cause`. The
 * wiring — that this check reaches the verdict and that its id is stable — is
 * pinned in `verifier.test.ts` instead.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
    analyseProjection,
    autoCashoutTickFromPpm,
    projectionRuleFor,
    PROJECTION_CHECK_ID,
    type ProjectionAction,
    type ProjectionInput,
} from './projection';
import * as crash from './crash';
import { bytesToHex, hexToBytes } from './seed';
import { vectorsUrl } from './vectors-path';
import { commandFrame, serverFrame, type CommandGameSpec } from '../receipts/fixtures';
import { decodeReceiptFrame, type ReceiptFrame } from '../receipts/recompute';
import type { ImportedCommand } from '../receipts/import';
import { encodeUuid, ProtoWriter } from '../wire/proto-writer';
import { decodeClientEnvelope } from '../wire/proto-reader';
import { CLIENT_FRAME_TAG, splitSignedFrame } from '../wire/signature';

const TENANT_SEED = new Uint8Array(32).fill(1);
const SESSION_SEED = new Uint8Array(32).fill(2);
const SESSION_ID = 'e2b6419a-ec4b-4eef-bdfa-802b6f338fc2';
const ROUND_ID = '9a256790-c7c0-47b0-9a5b-6ed2905d2df1';
const OTHER_ROUND_ID = '00000000-0000-4000-8000-0000000000ff';

const BET = '11111111-1111-4111-8111-111111111111';
const MOVE = '22222222-2222-4222-8222-222222222222';
const SETTLE = '33333333-3333-4333-8333-333333333333';

type CommandCase = 'placeBet' | 'playerAction' | 'cashOut';

function command(
    requestId: string,
    payloadCase: CommandCase,
    game: CommandGameSpec,
    roundId: string = ROUND_ID,
): ImportedCommand {
    return {
        requestId,
        payloadCase,
        frame: commandFrame(SESSION_SEED, {
            requestId,
            sessionId: SESSION_ID,
            payloadCase,
            // A `PlaceBet` opens a round rather than naming one.
            roundId: payloadCase === 'placeBet' ? undefined : roundId,
            game,
        }),
        sentAtUnixMs: 1,
        sendCount: 1,
    };
}

function act(index: number, actionType: string | null, payload: Uint8Array = new Uint8Array()): ProjectionAction {
    return { index, actionType, payload };
}

function u32(value: number): Uint8Array {
    const bytes = new Uint8Array(4);

    new DataView(bytes.buffer).setUint32(0, value, true);

    return bytes;
}

/** A signed, decoded `CommandRejected` naming a round. */
function rejection(requestId: string, roundId: string = ROUND_ID, reasonCode = 2): ReceiptFrame {
    return decodeReceiptFrame({
        sequence: 9n,
        payloadCase: 'commandRejected',
        relatedRequestId: requestId,
        frame: serverFrame(TENANT_SEED, {
            sequence: 9,
            sessionId: SESSION_ID,
            relatedRequestId: requestId,
            payload: { case: 'commandRejected', reasonCode, roundId, receivedAtUnixMs: 1 },
        }),
    });
}

/** A signed, decoded `CommandAccepted` for one request — the server answered. */
function acceptance(requestId: string): ReceiptFrame {
    return decodeReceiptFrame({
        sequence: 8n,
        payloadCase: 'commandAccepted',
        relatedRequestId: requestId,
        frame: serverFrame(TENANT_SEED, {
            sequence: 8,
            sessionId: SESSION_ID,
            relatedRequestId: requestId,
            payload: { case: 'commandAccepted', receivedAtUnixMs: 1n },
        }),
    });
}

/** The honest HiLo baseline: bet at index 0, cashout at index 1. */
function base(): ProjectionInput {
    return {
        roundIdHex: ROUND_ID,
        gameType: 'hilo:v1',
        actions: [act(0, 'place-bet'), act(1, 'cashout')],
        binding: [
            { requestId: BET, index: 0 },
            { requestId: SETTLE, index: 1 },
        ],
        bindingReason: null,
        commands: [command(BET, 'placeBet', { game: 'hilo' }), command(SETTLE, 'cashOut', { game: 'hilo' })],
        frames: [],
        endCause: 'player-action',
    };
}

function run(overrides: Partial<ProjectionInput> = {}) {
    const report = analyseProjection({ ...base(), ...overrides });

    expect(report.checks).toHaveLength(1);
    expect(report.checks[0].id).toBe(PROJECTION_CHECK_ID);

    return { status: report.checks[0].status, detail: report.checks[0].detail, findings: report.findings };
}

// ── the clean rounds ────────────────────────────────────────────────────

describe('a clean round of each game', () => {
    it('passes for hilo, with the guess the player signed', () => {
        const result = run({
            actions: [act(0, 'place-bet'), act(1, 'higher'), act(2, 'cashout')],
            binding: [
                { requestId: BET, index: 0 },
                { requestId: MOVE, index: 1 },
                { requestId: SETTLE, index: 2 },
            ],
            commands: [
                command(BET, 'placeBet', { game: 'hilo' }),
                command(MOVE, 'playerAction', { game: 'hilo', action: 'higher' }),
                command(SETTLE, 'cashOut', { game: 'hilo' }),
            ],
        });

        expect(result.status).toBe('pass');
    });

    it('passes for plinko, comparing the sealed config', () => {
        const result = run({
            gameType: 'plinko:v1',
            actions: [act(0, 'place-bet', new Uint8Array([...u32(8), 0])), act(1, 'cashout')],
            commands: [
                command(BET, 'placeBet', { game: 'plinko', rows: 8, risk: 1 }),
                command(SETTLE, 'cashOut', { game: 'plinko' }),
            ],
        });

        expect(result.status).toBe('pass');
    });

    it('passes for mines, comparing the revealed tile', () => {
        const result = run({
            gameType: 'mines:v1',
            actions: [act(0, 'place-bet', u32(3)), act(1, 'reveal', u32(3)), act(2, 'cashout')],
            binding: [
                { requestId: BET, index: 0 },
                { requestId: MOVE, index: 1 },
                { requestId: SETTLE, index: 2 },
            ],
            commands: [
                command(BET, 'placeBet', { game: 'mines', mineCount: 3 }),
                command(MOVE, 'playerAction', { game: 'mines', action: 'reveal', tileIndex: 3 }),
                command(SETTLE, 'cashOut', { game: 'mines' }),
            ],
        });

        expect(result.status).toBe('pass');
    });

    it('passes for crash, comparing the tick the player claimed', () => {
        const result = run({
            gameType: 'crash:v1',
            actions: [act(0, 'place-bet', new Uint8Array([0x00])), act(1, 'cashout', u32(40))],
            commands: [
                command(BET, 'placeBet', { game: 'crash' }),
                command(SETTLE, 'cashOut', { game: 'crash', tick: 40 }),
            ],
        });

        expect(result.status).toBe('pass');
    });

    it('passes for hydra, whose round the verifier cannot replay', () => {
        // There is no hydra replayer, so the round's payout proof is
        // unavailable end to end. The PROJECTION still runs: the table covers
        // all five games, and a missing replayer must not take a proof that
        // does work down with it.
        const result = run({
            gameType: 'hydra:v1',
            actions: [act(0, 'place-bet', new Uint8Array([2])), act(1, 'physical-attack'), act(2, 'cashout')],
            binding: [
                { requestId: BET, index: 0 },
                { requestId: MOVE, index: 1 },
                { requestId: SETTLE, index: 2 },
            ],
            commands: [
                command(BET, 'placeBet', { game: 'hydra', hero: 2 }),
                command(MOVE, 'playerAction', { game: 'hydra', action: 'physical-attack' }),
                command(SETTLE, 'cashOut', { game: 'hydra' }),
            ],
        });

        expect(result.status).toBe('pass');
    });
});

// ── one negative proof per table row ────────────────────────────────────

describe('a rewritten action', () => {
    it('fails when hilo higher became lower', () => {
        const result = run({
            actions: [act(0, 'place-bet'), act(1, 'lower'), act(2, 'cashout')],
            binding: [
                { requestId: BET, index: 0 },
                { requestId: MOVE, index: 1 },
                { requestId: SETTLE, index: 2 },
            ],
            commands: [
                command(BET, 'placeBet', { game: 'hilo' }),
                command(MOVE, 'playerAction', { game: 'hilo', action: 'higher' }),
                command(SETTLE, 'cashOut', { game: 'hilo' }),
            ],
        });

        expect(result.status).toBe('fail');
        expect(result.detail).toContain('projects to "higher"');
    });

    it('fails when a mines reveal of tile 3 became tile 7', () => {
        const result = run({
            gameType: 'mines:v1',
            actions: [act(0, 'place-bet', u32(3)), act(1, 'reveal', u32(7)), act(2, 'cashout')],
            binding: [
                { requestId: BET, index: 0 },
                { requestId: MOVE, index: 1 },
                { requestId: SETTLE, index: 2 },
            ],
            commands: [
                command(BET, 'placeBet', { game: 'mines', mineCount: 3 }),
                command(MOVE, 'playerAction', { game: 'mines', action: 'reveal', tileIndex: 3 }),
                command(SETTLE, 'cashOut', { game: 'mines' }),
            ],
        });

        expect(result.status).toBe('fail');
        expect(result.detail).toContain('tile 3');
    });

    it('fails when a crash cashout at tick 40 was written as tick 12', () => {
        // The P2 payoff. Before the claimed tick rode on the wire there was
        // nothing here to compare: the sequencer supplied the tick, so any
        // value it wrote was self-consistent.
        const result = run({
            gameType: 'crash:v1',
            actions: [act(0, 'place-bet', new Uint8Array([0x00])), act(1, 'cashout', u32(12))],
            commands: [
                command(BET, 'placeBet', { game: 'crash' }),
                command(SETTLE, 'cashOut', { game: 'crash', tick: 40 }),
            ],
        });

        expect(result.status).toBe('fail');
        expect(result.detail).toContain('tick 40');
    });

    it('fails when the plinko rows were rewritten', () => {
        const result = run({
            gameType: 'plinko:v1',
            actions: [act(0, 'place-bet', new Uint8Array([...u32(16), 0])), act(1, 'cashout')],
            commands: [
                command(BET, 'placeBet', { game: 'plinko', rows: 8, risk: 1 }),
                command(SETTLE, 'cashOut', { game: 'plinko' }),
            ],
        });

        expect(result.status).toBe('fail');
        expect(result.detail).toContain('rows = 8');
    });

    it('fails when the hydra hero was rewritten', () => {
        const result = run({
            gameType: 'hydra:v1',
            actions: [act(0, 'place-bet', new Uint8Array([5])), act(1, 'cashout')],
            commands: [
                command(BET, 'placeBet', { game: 'hydra', hero: 2 }),
                command(SETTLE, 'cashOut', { game: 'hydra' }),
            ],
        });

        expect(result.status).toBe('fail');
        expect(result.detail).toContain('hero = 2');
    });

    it('fails when a crash auto target became a different tick', () => {
        const result = run({
            gameType: 'crash:v1',
            actions: [
                act(0, 'place-bet', new Uint8Array([0x01, ...u32(50)])),
                act(1, 'cashout', u32(50)),
            ],
            commands: [
                // 2.00x is tick 100, not 50.
                command(BET, 'placeBet', { game: 'crash', autoCashoutPpm: 2_000_000 }),
                command(SETTLE, 'cashOut', { game: 'crash', tick: 50 }),
            ],
        });

        expect(result.status).toBe('fail');
        expect(result.detail).toContain('auto_cashout_ppm = 2000000');
    });

    it('fails a command of one game against a round of another', () => {
        const result = run({ gameType: 'mines:v1', actions: [act(0, 'place-bet', u32(3)), act(1, 'cashout')] });

        expect(result.status).toBe('fail');
        expect(result.detail).toContain('cannot have produced an action of another');
    });

    it('fails when the server placed a command past the end of the transcript', () => {
        const result = run({ actions: [act(0, 'place-bet')] });

        expect(result.status).toBe('fail');
        expect(result.detail).toContain('carries only 1 action(s)');
    });
});

// ── hydra's set membership ──────────────────────────────────────────────

describe('hydra fight and physical_attack', () => {
    function hydraRound(arm: 'fight' | 'physical-attack') {
        return run({
            gameType: 'hydra:v1',
            actions: [act(0, 'place-bet', new Uint8Array([2])), act(1, 'physical-attack'), act(2, 'cashout')],
            binding: [
                { requestId: BET, index: 0 },
                { requestId: MOVE, index: 1 },
                { requestId: SETTLE, index: 2 },
            ],
            commands: [
                command(BET, 'placeBet', { game: 'hydra', hero: 2 }),
                command(MOVE, 'playerAction', { game: 'hydra', action: arm }),
                command(SETTLE, 'cashOut', { game: 'hydra' }),
            ],
        });
    }

    it('both project to physical-attack, so neither false-fails', () => {
        // A bijection table would fail every round played with `fight`, which
        // is the gap this case exists to keep closed.
        expect(hydraRound('fight').status).toBe('pass');
        expect(hydraRound('physical-attack').status).toBe('pass');
    });

    it('names the residual: the two are indistinguishable on chain', () => {
        expect(hydraRound('fight').detail).toContain('indistinguishable on chain');
    });

    it('still fails a magic attack written as a physical one', () => {
        const result = run({
            gameType: 'hydra:v1',
            actions: [act(0, 'place-bet', new Uint8Array([2])), act(1, 'physical-attack'), act(2, 'cashout')],
            binding: [
                { requestId: BET, index: 0 },
                { requestId: MOVE, index: 1 },
                { requestId: SETTLE, index: 2 },
            ],
            commands: [
                command(BET, 'placeBet', { game: 'hydra', hero: 2 }),
                command(MOVE, 'playerAction', { game: 'hydra', action: 'magic-attack' }),
                command(SETTLE, 'cashOut', { game: 'hydra' }),
            ],
        });

        expect(result.status).toBe('fail');
    });
});

// ── steps with no bound command ─────────────────────────────────────────

describe('an action bound to no command', () => {
    it('passes a de-lever round: the partial-cashout is the sequencer’s own step', () => {
        const result = run({
            actions: [act(0, 'place-bet'), act(1, 'partial-cashout', new Uint8Array(16)), act(2, 'cashout')],
            binding: [
                { requestId: BET, index: 0 },
                { requestId: SETTLE, index: 2 },
            ],
        });

        expect(result.status).toBe('pass');
    });

    it('passes an abandon and an expire for the same reason', () => {
        expect(
            run({ actions: [act(0, 'place-bet'), act(1, 'abandon')], binding: [{ requestId: BET, index: 0 }] }).status,
        ).toBe('pass');
        expect(
            run({
                gameType: 'crash:v1',
                actions: [act(0, 'place-bet', new Uint8Array([0x00])), act(1, 'expire')],
                binding: [{ requestId: BET, index: 0 }],
                commands: [command(BET, 'placeBet', { game: 'crash' })],
            }).status,
        ).toBe('pass');
    });

    it('passes a crash auto round settled by the sweep at its committed target', () => {
        const result = run({
            gameType: 'crash:v1',
            actions: [
                act(0, 'place-bet', new Uint8Array([0x01, ...u32(100)])),
                act(1, 'cashout', u32(100)),
            ],
            binding: [{ requestId: BET, index: 0 }],
            commands: [command(BET, 'placeBet', { game: 'crash', autoCashoutPpm: 2_000_000 })],
            endCause: 'system-sweep',
        });

        expect(result.status).toBe('pass');
        expect(result.detail).toContain('ABSENCE OF A CONTRADICTION');
    });

    it('fails a player action nobody commanded', () => {
        const result = run({
            actions: [act(0, 'place-bet'), act(1, 'higher'), act(2, 'cashout')],
            binding: [
                { requestId: BET, index: 0 },
                { requestId: SETTLE, index: 2 },
            ],
        });

        expect(result.status).toBe('fail');
        expect(result.detail).toContain('not one of the system steps');
    });
});

// ── the cause, used in one direction only ───────────────────────────────

describe('RoundEnded.cause', () => {
    it('fails when the server claims a sweep settled a round your own command settled', () => {
        const result = run({ endCause: 'system-sweep' });

        expect(result.status).toBe('fail');
        expect(result.detail).toContain("Both are the server's statements and they disagree");
    });

    it('fails when the server claims a player action settled a round no command of yours ended', () => {
        const result = run({ binding: [{ requestId: BET, index: 0 }], endCause: 'player-action' });

        expect(result.status).toBe('fail');
        expect(result.detail).toContain('asserts a command of yours settled the round');
    });

    it('states no contradiction when the frame predates the cause field', () => {
        const result = run({ binding: [{ requestId: BET, index: 0 }], endCause: null });

        expect(result.status).toBe('pass');
        expect(result.findings.join(' ')).toContain('states no cause');
    });

    it('reports the transcript-cap substitution as a finding, not a fail', () => {
        const result = run({
            actions: [act(0, 'place-bet'), act(1, 'higher'), act(2, 'cashout')],
            binding: [
                { requestId: BET, index: 0 },
                { requestId: MOVE, index: 1 },
                { requestId: SETTLE, index: 2 },
            ],
            commands: [
                command(BET, 'placeBet', { game: 'hilo' }),
                command(MOVE, 'playerAction', { game: 'hilo', action: 'higher' }),
                // The player sent a `higher`; the sequencer substituted a
                // cashout in place when the round hit the transcript cap.
                command(SETTLE, 'playerAction', { game: 'hilo', action: 'higher' }),
            ],
            endCause: 'transcript-cap',
        });

        expect(result.status).toBe('pass');
        expect(result.findings.join(' ')).toContain('TRANSCRIPT_CAP');
    });
});

// ── the suppression rule ────────────────────────────────────────────────

describe('a cashout the server never answered', () => {
    /** A manual crash round that settled on the deadline sweep's expire. */
    function suppressed(overrides: Partial<ProjectionInput> = {}) {
        return run({
            gameType: 'crash:v1',
            actions: [act(0, 'place-bet', new Uint8Array([0x00])), act(1, 'expire')],
            binding: [{ requestId: BET, index: 0 }],
            commands: [
                command(BET, 'placeBet', { game: 'crash' }),
                command(SETTLE, 'cashOut', { game: 'crash', tick: 40 }),
            ],
            ...overrides,
        });
    }

    it('reports — never fails — when the server produced neither an action nor a refusal', () => {
        // The shape of a suppressed cashout, and not proof of one. A command
        // lost in transit leaves the identical document: `CommandRejected` is
        // ephemeral and never replayed, so its absence is as consistent with a
        // lost reply as with no reply. The finding lays the player's own
        // evidence out; it does not conclude from it.
        const result = suppressed();

        expect(result.status).toBe('pass');
        expect(result.findings.join(' ')).toContain('the transcript carries no cashout action bound to it');
        expect(result.findings.join(' ')).toContain('REPORTED, NEVER CONCLUDED');
        expect(result.findings.join(' ')).toContain('settled on an expire');
    });

    it('quotes the client’s own send count when the command went out more than once', () => {
        // The one fact that separates "an unlucky packet" from "it kept being
        // ignored", and it is the player's label rather than anything signed.
        const settle = command(SETTLE, 'cashOut', { game: 'crash', tick: 40 });
        const result = suppressed({
            commands: [command(BET, 'placeBet', { game: 'crash' }), { ...settle, sendCount: 4 }],
        });

        expect(result.status).toBe('pass');
        expect(result.findings.join(' ')).toContain('sent those bytes 4 time(s) under the same request id');
    });

    it('says a single send leaves an unlucky transport live', () => {
        const result = suppressed();

        expect(result.findings.join(' ')).toContain('sent those bytes once');
        expect(result.findings.join(' ')).toContain('unlucky transport is a live explanation');
    });

    it('reports whether later commands of the same session were answered', () => {
        // Whether the connection was carrying traffic at the time is the other
        // half of the weighing, and the export can actually show it.
        const later = '44444444-4444-4444-8444-444444444444';
        const result = suppressed({
            commands: [
                command(BET, 'placeBet', { game: 'crash' }),
                command(SETTLE, 'cashOut', { game: 'crash', tick: 40 }),
                { ...command(later, 'cashOut', { game: 'crash', tick: 41 }), sentAtUnixMs: 9 },
            ],
            frames: [acceptance(later)],
        });

        expect(result.findings.join(' ')).toContain('1 of the 1 command(s) you sent later in this session WERE answered');
    });

    it('passes when the server signed a refusal naming the round', () => {
        const result = suppressed({ frames: [rejection(SETTLE)] });

        expect(result.status).toBe('pass');
        expect(result.detail).toContain('a refusal is an answer');
        // A liveness code asserts something checkable, so the row carries no
        // qualifier — `rejections.ts` runs its comparison on it instead.
        expect(result.detail).not.toContain('an answer and nothing more');
    });

    it('qualifies the pass when the refusal asserts nothing about liveness', () => {
        // The residual: RATE_LIMITED is an answer under this rule, and the
        // liveness comparison in `rejections.ts` stays silent on it. Still a
        // pass — every such code has an honest reading — but the row names
        // what it is worth instead of reading as a clean answer.
        const result = suppressed({ frames: [rejection(SETTLE, ROUND_ID, 7)] });

        expect(result.status).toBe('pass');
        expect(result.detail).toContain('RATE_LIMITED');
        expect(result.detail).toContain('an answer and nothing more');
    });

    it('does not accept a refusal whose round id the player never signed', () => {
        // The trust rule: the command names OTHER_ROUND_ID, so the server's
        // echo of this round is a label it chose and proves nothing.
        const result = suppressed({
            commands: [
                command(BET, 'placeBet', { game: 'crash' }),
                command(SETTLE, 'cashOut', { game: 'crash', tick: 40 }, OTHER_ROUND_ID),
            ],
            frames: [rejection(SETTLE)],
        });

        // The command is no longer scoped into this round either, so there is
        // nothing to suppress — and nothing is concluded from the refusal.
        expect(result.status).toBe('pass');
    });

    it('reports rather than concludes when the round did not settle on an expire', () => {
        const result = suppressed({
            actions: [act(0, 'place-bet', new Uint8Array([0x00])), act(1, 'abandon')],
        });

        expect(result.status).toBe('pass');
        expect(result.findings.join(' ')).toContain('did not settle on an expire');
    });

    it('is silent when the cashout IS the action at the index it was bound to', () => {
        const result = run({
            gameType: 'crash:v1',
            actions: [act(0, 'place-bet', new Uint8Array([0x00])), act(1, 'cashout', u32(40))],
            commands: [
                command(BET, 'placeBet', { game: 'crash' }),
                command(SETTLE, 'cashOut', { game: 'crash', tick: 40 }),
            ],
        });

        expect(result.status).toBe('pass');
        expect(result.findings).toEqual([]);
    });
});

describe('the demoted auto-mislabel rule', () => {
    it('reports a sequencer-written cashout on a MANUAL crash round', () => {
        const result = run({
            gameType: 'crash:v1',
            actions: [act(0, 'place-bet', new Uint8Array([0x00])), act(1, 'cashout', u32(40))],
            binding: [{ requestId: BET, index: 0 }],
            commands: [command(BET, 'placeBet', { game: 'crash' })],
            endCause: 'system-sweep',
        });

        expect(result.status).toBe('pass');
        expect(result.findings.join(' ')).toContain('MANUAL mode');
    });
});

// ── the unavailable arms ────────────────────────────────────────────────

describe('what the check cannot answer', () => {
    it('is unavailable, naming the arm, for a command from a newer build', () => {
        const result = run({
            commands: [
                command(BET, 'placeBet', { game: 'hilo', armField: 19 }),
                command(SETTLE, 'cashOut', { game: 'hilo' }),
            ],
        });

        expect(result.status).toBe('unavailable');
        expect(result.detail).toContain('field 19');
    });

    it('is unavailable when the reconstruction declined', () => {
        const result = run({ binding: null, bindingReason: 'the reconstruction declined: conflicting-index' });

        expect(result.status).toBe('unavailable');
        expect(result.detail).toContain('conflicting-index');
    });

    it('is unavailable for a game this build has no table for', () => {
        const result = run({ gameType: 'roulette:v1' });

        expect(result.status).toBe('unavailable');
        expect(result.detail).toContain('roulette:v1');
    });

    it('makes every crash rule unavailable when the place-bet is not bound', () => {
        const result = run({
            gameType: 'crash:v1',
            actions: [act(0, 'place-bet', new Uint8Array([0x00])), act(1, 'cashout', u32(40))],
            binding: [{ requestId: SETTLE, index: 1 }],
            commands: [command(SETTLE, 'cashOut', { game: 'crash', tick: 40 })],
        });

        expect(result.status).toBe('unavailable');
        expect(result.detail).toContain('manual or auto mode');
    });

    it('is unavailable for an action tag this build does not know', () => {
        const result = run({ actions: [act(0, 'place-bet'), act(1, null)] });

        expect(result.status).toBe('unavailable');
    });

    it('is unavailable for a crash cashout that carries no tick', () => {
        const result = run({
            gameType: 'crash:v1',
            actions: [act(0, 'place-bet', new Uint8Array([0x00])), act(1, 'cashout', u32(0))],
            commands: [
                command(BET, 'placeBet', { game: 'crash' }),
                command(SETTLE, 'cashOut', { game: 'crash' }),
            ],
        });

        expect(result.status).toBe('unavailable');
        expect(result.detail).toContain('carries no tick');
    });
});

// ── the shared ppm → tick policy ────────────────────────────────────────

interface AutoCashoutVector {
    auto_cashout_ppm: number;
    accepted: boolean;
    auto_cashout_tick: number | null;
    note: string;
}

const AUTO_CASHOUT_VECTORS: AutoCashoutVector[] = JSON.parse(
    readFileSync(fileURLToPath(vectorsUrl('crash')), 'utf8'),
).auto_cashout_ppm_vectors.vectors;

describe('the ppm → tick auto-cashout policy', () => {
    it('has vectors, or every assertion below is vacuous', () => {
        expect(AUTO_CASHOUT_VECTORS.length).toBeGreaterThanOrEqual(6);
        expect(AUTO_CASHOUT_VECTORS.some((v) => v.accepted)).toBe(true);
        expect(AUTO_CASHOUT_VECTORS.some((v) => !v.accepted)).toBe(true);
    });

    it.each(AUTO_CASHOUT_VECTORS.map((v) => [v.note, v] as const))(
        'matches the shared vector: %s',
        (_note, vector) => {
            // The SAME table binds the sequencer's own conversion in
            // `services/sequencer/src/proto_conversions/crash/v1.rs`. Two
            // implementations of a policy is the shape that drifts silently.
            const result = autoCashoutTickFromPpm(vector.auto_cashout_ppm);

            expect(result.ok).toBe(vector.accepted);

            if (result.ok) {
                expect(result.tick).toBe(BigInt(vector.auto_cashout_tick as number));
            }
        },
    );
});

// ── a oneof carrying two arms ───────────────────────────────────────────

describe('a PlayerAction whose kind oneof carries two arms', () => {
    /**
     * A well-formed oneof carries one arm. This one carries two, which the
     * protobuf wire format permits and which the SEQUENCER resolves in one
     * specific way: `prost` overwrites the oneof on every arm it decodes, so it
     * acts on the LAST one in the bytes. The verifier must read it the same
     * way — a reader that took the first would project the player's command
     * from an arm the server never executed, and would then report a mismatch
     * against a server that read the bytes correctly.
     *
     * Hand-built, because no honest client emits this and the fixtures cannot:
     * the point is exactly the frame a fixture would refuse to make.
     *
     * The frame carries a zero signature: nothing in the projection path
     * verifies a command's signature (the frames-signed check is about SERVER
     * frames), so the bytes under test are the protobuf and nothing else.
     */
    function twoArmHydraAction(requestId: string): ImportedCommand {
        // hydra.v1.PlayerAction.kind — `fight` = 1 first, `magic_attack` = 3 last.
        const kinds = new ProtoWriter()
            .bytes(1, new Uint8Array())
            .bytes(3, new Uint8Array())
            .finish();
        // casino.v1.PlayerActionCommand { round_id = 1, hydra_v1_action = 12 }.
        const command = new ProtoWriter().bytes(1, encodeUuid(ROUND_ID)).bytes(12, kinds).finish();
        // casino.v1.ClientEnvelope { request_id = 1, session_id = 2, player_action = 12 }.
        const envelope = new ProtoWriter()
            .bytes(1, encodeUuid(requestId))
            .bytes(2, encodeUuid(SESSION_ID))
            .bytes(12, command)
            .finish();

        return {
            requestId,
            payloadCase: 'playerAction',
            frame: new Uint8Array([CLIENT_FRAME_TAG, ...new Uint8Array(64), ...envelope]),
            sentAtUnixMs: 1,
            sendCount: 1,
        };
    }

    /** The hydra round the command sits in: bet, the contested action, cashout. */
    function hydraRound(middle: string, overrides: Partial<ProjectionInput> = {}) {
        return run({
            gameType: 'hydra:v1',
            actions: [act(0, 'place-bet', new Uint8Array([2])), act(1, middle), act(2, 'cashout')],
            binding: [
                { requestId: BET, index: 0 },
                { requestId: MOVE, index: 1 },
                { requestId: SETTLE, index: 2 },
            ],
            commands: [
                command(BET, 'placeBet', { game: 'hydra', hero: 2 }),
                twoArmHydraAction(MOVE),
                command(SETTLE, 'cashOut', { game: 'hydra' }),
            ],
            ...overrides,
        });
    }

    it('decodes the LAST arm, which is the one prost acts on', () => {
        const frame = twoArmHydraAction(MOVE).frame;
        const body = decodeClientEnvelope(splitSignedFrame(frame).body).commandBody;

        expect(body).toEqual({ case: 'playerAction', game: 'hydra', arm: 'magic-attack' });
    });

    it('passes against the magic-attack the sequencer would have written', () => {
        expect(hydraRound('magic-attack').status).toBe('pass');
    });

    it('fails against the physical-attack the FIRST arm would have projected to', () => {
        // The case that makes the last-wins rule load-bearing rather than a
        // preference: read first-wins, this transcript would have passed.
        const result = hydraRound('physical-attack');

        expect(result.status).toBe('fail');
        expect(result.detail).toContain('magic-attack');
    });
});

// ── the projection against the Rust adapter's own bytes ─────────────────

/**
 * One settled round, as the shipped Rust engine and adapter produce it —
 * the same `transcript_vectors` array `crash.test.ts` replays.
 */
interface TranscriptVector {
    name: string;
    server_seed: string;
    client_seed: string;
    actions: { index: number; action_type: string; payload_hex: string }[];
    expected_outcome: string;
    expected_cumulative_ppm: number;
}

const TRANSCRIPT_VECTORS: TranscriptVector[] = JSON.parse(
    readFileSync(fileURLToPath(vectorsUrl('crash')), 'utf8'),
).transcript_vectors;

describe('the projection reproduces the Rust adapter’s payload bytes', () => {
    // `crash.test.ts` proves the REPLAYER agrees with these rows. This proves
    // the other direction of the fourth proof: that the bytes the projection
    // expects from a signed command are the bytes `encode_action_borsh`
    // actually writes. Without it the projection could be self-consistently
    // wrong — its expectation and its comparison built by the same encoder —
    // and a Rust-side layout change would sail through the verifier.
    //
    // **The tick each expectation is built from is derived INDEPENDENTLY of the
    // payload under test**, and that is the whole design of this block. Reading
    // the tick out of the payload and re-encoding it would be `encode(decode(x))
    // === x` — true for any bijective codec, including a drifted one — so such
    // a test could never fail and would read as evidence while proving nothing.
    // The independent anchor is `expected_cumulative_ppm`: on a winning round
    // the engine settled at `m(tick)`, and `m` is strictly increasing below the
    // cap, so the tick is recoverable from the payout alone.
    //
    // A losing row has `cumulative_ppm = 0` and offers no such anchor, so those
    // rows are checked for SHAPE and for the semantics their name claims, and
    // are counted separately rather than being passed off as byte proofs.

    /** The settling tick a winning row's payout implies, or null when it loses. */
    function anchoredTick(vector: TranscriptVector): bigint | null {
        if (vector.expected_outcome !== 'cashout') {
            return null;
        }

        const ppm = BigInt(vector.expected_cumulative_ppm);
        const tick = crash.crashTick(ppm);

        // `crashTick` is the curve inverse, so this holds only if the payout
        // really is a multiplier the curve reaches exactly. If a future row
        // ever paid something else, the anchor would be wrong and silent.
        expect(crash.multiplierPpm(tick)).toBe(ppm);

        return tick;
    }

    /** The auto target in ppm whose shared ppm→tick policy yields `tick`. */
    function ppmForTick(tick: bigint): number {
        const ppm = crash.multiplierPpm(tick);
        const roundTrip = autoCashoutTickFromPpm(Number(ppm));

        expect(roundTrip.ok).toBe(true);
        expect(roundTrip.ok && roundTrip.tick).toBe(tick);

        return Number(ppm);
    }

    /** `manual-…` / `auto-…`: the mode, read from the row's NAME, not its bytes. */
    function isAuto(vector: TranscriptVector): boolean {
        return vector.name.startsWith('auto-');
    }

    it('has vectors covering every action type, or the walk below is vacuous', () => {
        expect(TRANSCRIPT_VECTORS.length).toBeGreaterThanOrEqual(7);

        const types = new Set(TRANSCRIPT_VECTORS.flatMap((v) => v.actions.map((a) => a.action_type)));

        expect(types).toEqual(new Set(['place-bet', 'cashout', 'expire']));
        // Both modes and both outcomes, or half the table is untested.
        expect(TRANSCRIPT_VECTORS.some(isAuto)).toBe(true);
        expect(TRANSCRIPT_VECTORS.some((v) => !isAuto(v))).toBe(true);
        expect(TRANSCRIPT_VECTORS.some((v) => v.expected_outcome === 'cashout')).toBe(true);
        expect(TRANSCRIPT_VECTORS.some((v) => v.expected_outcome === 'lose')).toBe(true);
    });

    it('anchors enough actions independently for this block to prove anything', () => {
        // The count that keeps the byte-level half from silently emptying out.
        // Without it, a future edit that made every row a loss would leave this
        // describe passing on shape checks alone.
        const anchored = TRANSCRIPT_VECTORS.filter((vector) => anchoredTick(vector) !== null);

        expect(anchored.length).toBeGreaterThanOrEqual(3);
        // Both modes among them, so the `Option` tag byte is covered on the
        // side where the tick is a real number and not just the None case.
        expect(anchored.some(isAuto)).toBe(true);
        expect(anchored.some((vector) => !isAuto(vector))).toBe(true);
    });

    it.each(TRANSCRIPT_VECTORS.map((vector) => [vector.name, vector] as const))(
        'projects every action of %s from the command that would have authorised it',
        (_name, vector) => {
            const tick = anchoredTick(vector);

            for (const action of vector.actions) {
                if (action.action_type === 'place-bet') {
                    if (!isAuto(vector)) {
                        // MANUAL. Fully anchored on every row, winning or not:
                        // the rule's payload is the literal `[0x00]` in
                        // `crashPlaceBetExpectation`, so nothing here is
                        // derived from the bytes under test.
                        const rule = projectionRuleFor({ case: 'placeBet', game: 'crash', autoCashoutPpm: null });

                        expect(rule.ok && rule.actionTypes).toEqual(['place-bet']);
                        expect(rule.ok && bytesToHex(rule.payload)).toBe(action.payload_hex);

                        continue;
                    }

                    if (tick !== null) {
                        // AUTO, anchored: the player signs a ppm target, never
                        // a tick, so the rule has to run the shared ppm→tick
                        // policy to reach these bytes.
                        const rule = projectionRuleFor({
                            case: 'placeBet',
                            game: 'crash',
                            autoCashoutPpm: ppmForTick(tick),
                        });

                        expect(rule.ok && rule.actionTypes).toEqual(['place-bet']);
                        expect(rule.ok && bytesToHex(rule.payload)).toBe(action.payload_hex);

                        continue;
                    }

                    // AUTO, unanchored (the target was above the crash, so the
                    // round paid nothing and the payout names no tick). Shape,
                    // plus the semantics the row's own name claims.
                    const payload = hexToBytes(action.payload_hex);
                    const target = crash.decodeConfig(payload).autoCashoutTick;

                    expect(payload[0]).toBe(0x01);
                    expect(payload).toHaveLength(5);
                    expect(target).not.toBeNull();
                    expect(target as bigint).toBeGreaterThan(
                        crash.crashRound(vector.server_seed, vector.client_seed).crashTick,
                    );

                    continue;
                }

                if (action.action_type === 'cashout') {
                    if (tick !== null) {
                        // Anchored: the tick comes from the payout, and the
                        // rule re-encodes it to the file's own bytes.
                        const rule = projectionRuleFor({ case: 'cashOut', game: 'crash', tick: Number(tick) });

                        expect(rule.ok && rule.actionTypes).toEqual(['cashout']);
                        expect(rule.ok && bytesToHex(rule.payload)).toBe(action.payload_hex);

                        continue;
                    }

                    // Unanchored: a losing claim. The width is still a fact
                    // worth pinning — `borsh(u32)` is four bytes, and the rule
                    // must produce four for whatever tick it is handed.
                    const claimed = crash.decodeCashoutTick(hexToBytes(action.payload_hex));
                    const rule = projectionRuleFor({ case: 'cashOut', game: 'crash', tick: Number(claimed) });

                    expect(action.payload_hex).toHaveLength(8);
                    expect(rule.ok && rule.payload).toHaveLength(4);

                    continue;
                }

                // `expire` is the deadline sweep's own step: no player command
                // authorises it, which is exactly why the projection treats it
                // as a system action rather than giving it a rule.
                expect(action.action_type).toBe('expire');
                expect(action.payload_hex).toBe('');
            }
        },
    );

    it('has no crash command that projects to expire', () => {
        // The other half of the system-action claim: if some crash command DID
        // project to `expire`, the whitelist in `projectUnbound` would be
        // hiding a real mismatch instead of naming a sweep.
        const rules = [
            projectionRuleFor({ case: 'placeBet', game: 'crash', autoCashoutPpm: null }),
            projectionRuleFor({ case: 'placeBet', game: 'crash', autoCashoutPpm: 2_000_000 }),
            projectionRuleFor({ case: 'cashOut', game: 'crash', tick: 40 }),
        ];

        for (const rule of rules) {
            expect(rule.ok).toBe(true);
            expect(rule.ok && rule.actionTypes).not.toContain('expire');
        }
    });
});
