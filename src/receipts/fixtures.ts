/**
 * Builders for signed receipt frames, used by the test suite.
 *
 * They ship with the export for the reason `proto-writer.ts` does: a reader
 * who wants to satisfy themselves that a tampered frame really is rejected has
 * to be able to build one. Every byte a fixture produces goes through the same
 * signing rule the sequencer and the play client use, so a test built on these
 * is testing the format and not a paraphrase of it.
 *
 * Field numbers are named here, at the call sites, against
 * `libs/proto-definitions/casino/v1/{envelopes,events,commands}.proto`.
 */
import * as ed from '@noble/ed25519';
import { blake2b } from '@noble/hashes/blake2.js';
import { encodeUuid, ProtoWriter } from '../wire/proto-writer';
import { CLIENT_FRAME_TAG, RECEIPT_DOMAIN, SERVER_FRAME_TAG } from '../wire/signature';

// ServerEnvelope
const SERVER_SEQUENCE = 1;
const SERVER_RELATED_REQUEST_ID = 2;
const SERVER_SESSION_ID = 3;
const SERVER_COMMAND_ACCEPTED = 11;
const SERVER_COMMAND_REJECTED = 12;
const SERVER_BET_PLACED = 13;
const SERVER_ROUND_STARTED = 14;
const SERVER_ROUND_UPDATED = 15;
const SERVER_ROUND_ENDED = 16;

// CommandAccepted / CommandRejected
const ACCEPTED_RECEIVED_AT_UNIX_MS = 1;
const REJECTED_REASON_CODE = 1;
const REJECTED_DETAIL = 2;
const REJECTED_ROUND_ID = 3;
const REJECTED_RECEIVED_AT_UNIX_MS = 4;

// RoundStartedEvent.game_state, crash arm; crash.v1.State
const ROUND_STARTED_CRASH_STATE = 11;
const CRASH_STATE_TICK_QUANTUM_MS = 4;
const CRASH_STATE_SERVER_ANCHOR_UNIX_MS = 6;

// Round-bearing events
const EVENT_ROUND_ID = 1;
const ROUND_UPDATED_ACTION_INDEX = 2;
const ROUND_UPDATED_ORIGIN = 5;
const ROUND_ENDED_CAUSE = 4;
const ROUND_ENDED_PLAYER_COMMITMENT = 5;
const ROUND_ENDED_ACTION_INDEX = 6;

// ClientEnvelope
const CLIENT_REQUEST_ID = 1;
const CLIENT_SESSION_ID = 2;
const CLIENT_PAYLOAD_FIELDS = {
    ping: 10,
    placeBet: 11,
    playerAction: 12,
    cashOut: 13,
    resumeSession: 14,
    endSession: 15,
    timeSync: 16,
} as const;

// PlaceBetCommand
const PLACE_BET_CLIENT_SEED = 2;

// CashOutCommand / PlayerActionCommand
const COMMAND_ROUND_ID = 1;

/**
 * The per-game `game_data` arms. `PlaceBetCommand` and `CashOutCommand` share
 * the numbering on purpose ("one game keeps one number across commands");
 * `PlayerActionCommand` has only the three games with in-round decisions.
 */
const PLACE_BET_ARM_FIELDS = { hilo: 10, crash: 11, plinko: 12, mines: 13, hydra: 14 } as const;
const CASH_OUT_ARM_FIELDS = PLACE_BET_ARM_FIELDS;
const PLAYER_ACTION_ARM_FIELDS = { hilo: 10, mines: 11, hydra: 12 } as const;

// crash.v1.PlaceBet / crash.v1.CashOut / plinko.v1.PlaceBet /
// mines.v1.PlaceBet / mines.v1.Reveal / hydra.v1.PlaceBet
const CRASH_AUTO_CASHOUT_PPM = 1;
const CRASH_CASHOUT_TICK = 1;
const PLINKO_ROWS = 1;
const PLINKO_RISK = 2;
const MINES_MINE_COUNT = 1;
const MINES_REVEAL_TILE_INDEX = 1;
const HYDRA_HERO = 1;

/** `PlayerAction.kind` arm numbers, per game. */
const ACTION_KIND_FIELDS: Record<string, number> = {
    higher: 1,
    lower: 2,
    reveal: 1,
    fight: 1,
    'physical-attack': 2,
    'magic-attack': 3,
    'drink-potion': 4,
    'drink-mana': 5,
};

/** `casino.v1.StepOrigin` values. */
const ORIGIN_VALUES = { unspecified: 0, player: 1, system: 2 } as const;

/** `casino.v1.RoundEndCause` values. */
const CAUSE_VALUES = {
    unspecified: 0,
    'player-action': 1,
    'system-sweep': 2,
    'transcript-cap': 3,
} as const;

/** The two `crash.v1.State` clock fields a `RoundStarted` can carry. */
export interface CrashStateSpec {
    tickQuantumMs: number | bigint;
    serverAnchorUnixMs: number | bigint;
}

export type ServerPayloadSpec =
    | { case: 'commandAccepted'; receivedAtUnixMs?: number | bigint }
    | {
          case: 'commandRejected';
          reasonCode: number;
          detail?: string;
          /** Present exactly when the refusal concerns a round. */
          roundId?: string;
          receivedAtUnixMs?: number | bigint;
      }
    | { case: 'betPlaced'; roundId: string }
    | { case: 'roundStarted'; roundId: string; crashState?: CrashStateSpec }
    | { case: 'roundUpdated'; roundId: string; actionIndex: number; origin?: keyof typeof ORIGIN_VALUES }
    | {
          case: 'roundEnded';
          roundId: string;
          actionIndex?: number;
          playerCommitment?: Uint8Array;
          /** `RoundEndedEvent.cause`; omitted entirely when absent. */
          cause?: keyof typeof CAUSE_VALUES;
      };

export interface ServerFrameSpec {
    sequence: number | bigint;
    sessionId: string;
    relatedRequestId: string | null;
    payload: ServerPayloadSpec;
}

/** Build and sign `[0x06 | signature | ServerEnvelope]` under a tenant seed. */
export function serverFrame(seed: Uint8Array, spec: ServerFrameSpec): Uint8Array {
    const envelope = new ProtoWriter();

    if (BigInt(spec.sequence) !== 0n) {
        envelope.varint(SERVER_SEQUENCE, spec.sequence);
    }

    if (spec.relatedRequestId) {
        envelope.bytes(SERVER_RELATED_REQUEST_ID, encodeUuid(spec.relatedRequestId));
    }

    envelope.bytes(SERVER_SESSION_ID, encodeUuid(spec.sessionId));

    switch (spec.payload.case) {
        case 'commandAccepted': {
            // Correlation is entirely through `related_request_id`; the one
            // field is the receipt stamp, and it is OPTIONAL because this
            // frame is a durable `client_outbox` row — rows written before the
            // field existed replay without it, so both shapes are real.
            const accepted = new ProtoWriter();

            if (spec.payload.receivedAtUnixMs !== undefined) {
                accepted.varint(ACCEPTED_RECEIVED_AT_UNIX_MS, spec.payload.receivedAtUnixMs);
            }

            envelope.bytes(SERVER_COMMAND_ACCEPTED, accepted.finish());
            break;
        }
        case 'commandRejected': {
            const rejected = new ProtoWriter();

            if (spec.payload.reasonCode !== 0) {
                // proto3 implicit presence: the zero enum never reaches the
                // wire, so a fixture that wrote it would be the one shape a
                // real server cannot produce.
                rejected.varint(REJECTED_REASON_CODE, spec.payload.reasonCode);
            }

            if (spec.payload.detail !== undefined) {
                rejected.bytes(REJECTED_DETAIL, new TextEncoder().encode(spec.payload.detail));
            }

            if (spec.payload.roundId !== undefined) {
                rejected.bytes(REJECTED_ROUND_ID, encodeUuid(spec.payload.roundId));
            }

            if (spec.payload.receivedAtUnixMs !== undefined) {
                rejected.varint(REJECTED_RECEIVED_AT_UNIX_MS, spec.payload.receivedAtUnixMs);
            }

            envelope.bytes(SERVER_COMMAND_REJECTED, rejected.finish());
            break;
        }
        case 'betPlaced':
            envelope.bytes(SERVER_BET_PLACED, roundBearing(spec.payload.roundId).finish());
            break;
        case 'roundStarted': {
            const started = roundBearing(spec.payload.roundId);

            if (spec.payload.crashState) {
                const state = new ProtoWriter();

                state.varint(CRASH_STATE_TICK_QUANTUM_MS, spec.payload.crashState.tickQuantumMs);
                state.varint(
                    CRASH_STATE_SERVER_ANCHOR_UNIX_MS,
                    spec.payload.crashState.serverAnchorUnixMs,
                );
                started.bytes(ROUND_STARTED_CRASH_STATE, state.finish());
            }

            envelope.bytes(SERVER_ROUND_STARTED, started.finish());
            break;
        }
        case 'roundUpdated': {
            const event = roundBearing(spec.payload.roundId);

            if (spec.payload.actionIndex !== 0) {
                // proto3 implicit presence again: `RoundUpdatedEvent
                // .action_index` is a bare `int32`, so index 0 never reaches
                // the wire. A fixture that wrote it anyway would be the one
                // shape a real sequencer cannot produce, and the reader's
                // handling of the real shape would go untested.
                event.varint(ROUND_UPDATED_ACTION_INDEX, spec.payload.actionIndex);
            }

            const origin = ORIGIN_VALUES[spec.payload.origin ?? 'player'];

            if (origin !== 0) {
                // proto3 implicit presence: UNSPECIFIED is omitted, which is
                // exactly what a producer predating the field emits.
                event.varint(ROUND_UPDATED_ORIGIN, origin);
            }

            envelope.bytes(SERVER_ROUND_UPDATED, event.finish());
            break;
        }
        case 'roundEnded': {
            const event = roundBearing(spec.payload.roundId);

            if (spec.payload.playerCommitment) {
                event.bytes(ROUND_ENDED_PLAYER_COMMITMENT, spec.payload.playerCommitment);
            }

            if (spec.payload.cause !== undefined) {
                // `cause` is `optional`, so an explicit value ALWAYS reaches
                // the wire — zero included. Omitting the spec field is what
                // reproduces a producer that predates the field, which is a
                // different thing from stating UNSPECIFIED.
                event.varint(ROUND_ENDED_CAUSE, CAUSE_VALUES[spec.payload.cause]);
            }

            if (spec.payload.actionIndex !== undefined) {
                event.varint(ROUND_ENDED_ACTION_INDEX, spec.payload.actionIndex);
            }

            envelope.bytes(SERVER_ROUND_ENDED, event.finish());
            break;
        }
    }

    const body = envelope.finish();
    const preimage = new Uint8Array(RECEIPT_DOMAIN.length + body.length);

    preimage.set(RECEIPT_DOMAIN, 0);
    preimage.set(body, RECEIPT_DOMAIN.length);

    return frame(SERVER_FRAME_TAG, ed.sign(blake2b(preimage, { dkLen: 32 }), seed), body);
}

export interface CommandFrameSpec {
    requestId: string;
    sessionId: string;
    payloadCase: keyof typeof CLIENT_PAYLOAD_FIELDS;
    /** `PlaceBetCommand.client_seed` text; only meaningful for `placeBet`. */
    clientSeed?: string;
    /**
     * `round_id` inside the command body; only meaningful for `cashOut` and
     * `playerAction`, which are the two arms that carry one.
     *
     * The field a server's echoed rejection round id is checked against, so a
     * fixture needs to be able to write it — including writing a DIFFERENT
     * one, which is how the mismatch arm of the trust rule gets exercised.
     */
    roundId?: string;
    /**
     * The `game_data` arm to write, and the fields inside it.
     *
     * Optional so the pre-existing commitment fixtures — which care only about
     * whole frame bytes — stay byte-stable, but every projection fixture sets
     * it: the fourth proof reads exactly these fields, so an arm-less command
     * exercises only the "no arm set" path.
     */
    game?: CommandGameSpec;
}

/**
 * One command's game arm. `armField` overrides the field number, which is how
 * a test builds the arm of a game this build has no rule for — the shape a
 * client newer than the verifier produces.
 */
export interface CommandGameSpec {
    game: 'hilo' | 'crash' | 'plinko' | 'mines' | 'hydra';
    /** crash `PlaceBet.auto_cashout_ppm` — omitted ⇒ manual mode. */
    autoCashoutPpm?: number;
    /** plinko `PlaceBet`. `risk` is the PROTO enum number (LOW = 1). */
    rows?: number;
    risk?: number;
    /** mines `PlaceBet.mine_count`. */
    mineCount?: number;
    /** hydra `PlaceBet.hero`. */
    hero?: number;
    /** `PlayerAction.kind` arm name. */
    action?: keyof typeof ACTION_KIND_FIELDS;
    /** mines `Reveal.tile_index`. */
    tileIndex?: number;
    /** crash `CashOut.tick`. */
    tick?: number;
    /** Write the arm at this field number instead of the game's own. */
    armField?: number;
}

/** Build and sign `[0x05 | signature | ClientEnvelope]` under a session seed. */
export function commandFrame(seed: Uint8Array, spec: CommandFrameSpec): Uint8Array {
    // The command's own fields are irrelevant to the commitment proofs: the
    // commitment is over whole frames and the ordering comes from the server's
    // index, so an empty payload submessage is a faithful stand-in for any
    // command of that case. The one field a proof DOES read is the place-bet's
    // client seed, so a fixture can carry it.
    const payload = commandPayload(spec);
    const body = new ProtoWriter()
        .bytes(CLIENT_REQUEST_ID, encodeUuid(spec.requestId))
        .bytes(CLIENT_SESSION_ID, encodeUuid(spec.sessionId))
        .bytes(CLIENT_PAYLOAD_FIELDS[spec.payloadCase], payload)
        .finish();

    // No domain prefix: the session key signs this one channel only, so there
    // is no second channel to separate it from.
    return frame(CLIENT_FRAME_TAG, ed.sign(blake2b(body, { dkLen: 32 }), seed), body);
}

function commandPayload(spec: CommandFrameSpec): Uint8Array {
    const writer = new ProtoWriter();

    if (spec.payloadCase === 'placeBet') {
        if (spec.clientSeed !== undefined) {
            writer.bytes(PLACE_BET_CLIENT_SEED, new TextEncoder().encode(spec.clientSeed));
        }
    } else if (spec.payloadCase === 'cashOut' || spec.payloadCase === 'playerAction') {
        if (spec.roundId) {
            writer.bytes(COMMAND_ROUND_ID, encodeUuid(spec.roundId));
        }
    }

    if (spec.game && (spec.payloadCase === 'placeBet' || spec.payloadCase === 'cashOut' || spec.payloadCase === 'playerAction')) {
        writer.bytes(armField(spec.payloadCase, spec.game), gameArm(spec.payloadCase, spec.game));
    }

    return writer.finish();
}

function armField(payloadCase: 'placeBet' | 'cashOut' | 'playerAction', game: CommandGameSpec): number {
    if (game.armField !== undefined) {
        return game.armField;
    }

    if (payloadCase === 'playerAction') {
        const field = PLAYER_ACTION_ARM_FIELDS[game.game as keyof typeof PLAYER_ACTION_ARM_FIELDS];

        if (field === undefined) {
            throw new RangeError(`${game.game} has no PlayerAction arm`);
        }

        return field;
    }

    return payloadCase === 'placeBet' ? PLACE_BET_ARM_FIELDS[game.game] : CASH_OUT_ARM_FIELDS[game.game];
}

/** The bytes inside the arm — empty for every marker-only message. */
function gameArm(payloadCase: 'placeBet' | 'cashOut' | 'playerAction', game: CommandGameSpec): Uint8Array {
    const arm = new ProtoWriter();

    if (payloadCase === 'placeBet') {
        if (game.game === 'crash' && game.autoCashoutPpm !== undefined) {
            // `optional uint32`: explicit presence, so a zero would be written
            // too — absent is the only thing that means manual mode.
            arm.varint(CRASH_AUTO_CASHOUT_PPM, game.autoCashoutPpm);
        }

        if (game.game === 'plinko') {
            // Bare scalars: proto3 implicit presence omits a zero, which is
            // exactly what a real client emits.
            if (game.rows) {
                arm.varint(PLINKO_ROWS, game.rows);
            }

            if (game.risk) {
                arm.varint(PLINKO_RISK, game.risk);
            }
        }

        if (game.game === 'mines' && game.mineCount) {
            arm.varint(MINES_MINE_COUNT, game.mineCount);
        }

        if (game.game === 'hydra' && game.hero) {
            arm.varint(HYDRA_HERO, game.hero);
        }

        return arm.finish();
    }

    if (payloadCase === 'cashOut') {
        if (game.game === 'crash' && game.tick !== undefined) {
            arm.varint(CRASH_CASHOUT_TICK, game.tick);
        }

        return arm.finish();
    }

    if (game.action === undefined) {
        // A `PlayerAction` with no `kind` — the malformed shape the reader has
        // to report rather than guess at.
        return arm.finish();
    }

    const kind = new ProtoWriter();

    if (game.action === 'reveal' && game.tileIndex !== undefined) {
        kind.varint(MINES_REVEAL_TILE_INDEX, game.tileIndex);
    }

    return arm.bytes(ACTION_KIND_FIELDS[game.action], kind.finish()).finish();
}

function roundBearing(roundId: string): ProtoWriter {
    return new ProtoWriter().bytes(EVENT_ROUND_ID, encodeUuid(roundId));
}

function frame(tag: number, signature: Uint8Array, body: Uint8Array): Uint8Array {
    const out = new Uint8Array(1 + signature.length + body.length);

    out[0] = tag;
    out.set(signature, 1);
    out.set(body, 1 + signature.length);

    return out;
}
