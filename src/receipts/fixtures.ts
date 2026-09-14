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
const SERVER_BET_PLACED = 13;
const SERVER_ROUND_STARTED = 14;
const SERVER_ROUND_UPDATED = 15;
const SERVER_ROUND_ENDED = 16;

// Round-bearing events
const EVENT_ROUND_ID = 1;
const ROUND_UPDATED_ACTION_INDEX = 2;
const ROUND_UPDATED_ORIGIN = 5;
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

/** `casino.v1.StepOrigin` values. */
const ORIGIN_VALUES = { unspecified: 0, player: 1, system: 2 } as const;

export type ServerPayloadSpec =
    | { case: 'commandAccepted' }
    | { case: 'betPlaced' | 'roundStarted'; roundId: string }
    | { case: 'roundUpdated'; roundId: string; actionIndex: number; origin?: keyof typeof ORIGIN_VALUES }
    | { case: 'roundEnded'; roundId: string; actionIndex?: number; playerCommitment?: Uint8Array };

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
        case 'commandAccepted':
            // An empty message: correlation is entirely through
            // `related_request_id`, so the payload carries nothing at all.
            envelope.bytes(SERVER_COMMAND_ACCEPTED, new Uint8Array(0));
            break;
        case 'betPlaced':
            envelope.bytes(SERVER_BET_PLACED, roundBearing(spec.payload.roundId).finish());
            break;
        case 'roundStarted':
            envelope.bytes(SERVER_ROUND_STARTED, roundBearing(spec.payload.roundId).finish());
            break;
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
}

/** Build and sign `[0x05 | signature | ClientEnvelope]` under a session seed. */
export function commandFrame(seed: Uint8Array, spec: CommandFrameSpec): Uint8Array {
    // The command's own fields are irrelevant to the commitment proofs: the
    // commitment is over whole frames and the ordering comes from the server's
    // index, so an empty payload submessage is a faithful stand-in for any
    // command of that case. The one field a proof DOES read is the place-bet's
    // client seed, so a fixture can carry it.
    const payload =
        spec.payloadCase === 'placeBet' && spec.clientSeed !== undefined
            ? new ProtoWriter().bytes(PLACE_BET_CLIENT_SEED, new TextEncoder().encode(spec.clientSeed)).finish()
            : new Uint8Array(0);
    const body = new ProtoWriter()
        .bytes(CLIENT_REQUEST_ID, encodeUuid(spec.requestId))
        .bytes(CLIENT_SESSION_ID, encodeUuid(spec.sessionId))
        .bytes(CLIENT_PAYLOAD_FIELDS[spec.payloadCase], payload)
        .finish();

    // No domain prefix: the session key signs this one channel only, so there
    // is no second channel to separate it from.
    return frame(CLIENT_FRAME_TAG, ed.sign(blake2b(body, { dkLen: 32 }), seed), body);
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
