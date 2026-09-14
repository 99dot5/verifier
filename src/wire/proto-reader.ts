/**
 * A minimal protobuf wire reader for the play-receipt frames.
 *
 * The verifier must import receipts without importing the protobuf runtime:
 * every dependency in the published tree is something a suspicious reader has
 * to audit, and the whole point of the export is that there is nothing to
 * audit but the source in front of them. The frames it has to read are a
 * handful of messages with a handful of fields, so this reads the wire
 * directly — the same trade that made the base58 decoder and the Borsh reader
 * hand-rolled.
 *
 * What it deliberately does NOT do: reconstruct a message. It extracts the
 * fields the receipt proofs need and skips everything else, unknown field
 * numbers included, exactly as a protobuf decoder must. The FRAME BYTES are
 * the evidence — the commitment is over them and the signature covers them —
 * so nothing here ever re-encodes anything, and a field this reader ignores
 * is still inside the bytes that were hashed and signed.
 *
 * Field numbers come from `libs/proto-definitions/casino/v1/*.proto`; each is
 * named at its use site so a drift shows up as an obviously wrong number
 * rather than an anonymous constant.
 */

export class ProtoError extends Error {}

/** Wire types (protobuf spec). Groups (3/4) are not emitted by proto3. */
const WIRE_VARINT = 0;
const WIRE_FIXED64 = 1;
const WIRE_LENGTH_DELIMITED = 2;
const WIRE_FIXED32 = 5;

interface Field {
    number: number;
    wireType: number;
    /** Varint / fixed payloads, as an unsigned bigint. */
    value: bigint;
    /** Length-delimited payloads. */
    bytes: Uint8Array;
}

class Reader {
    private offset = 0;

    constructor(private readonly bytes: Uint8Array) {}

    get done(): boolean {
        return this.offset >= this.bytes.length;
    }

    field(): Field {
        const tag = this.varint();
        const number = Number(tag >> 3n);
        const wireType = Number(tag & 0x07n);

        switch (wireType) {
            case WIRE_VARINT:
                return { number, wireType, value: this.varint(), bytes: EMPTY };
            case WIRE_FIXED64:
                return { number, wireType, value: this.fixed(8), bytes: EMPTY };
            case WIRE_FIXED32:
                return { number, wireType, value: this.fixed(4), bytes: EMPTY };
            case WIRE_LENGTH_DELIMITED: {
                const length = Number(this.varint());

                if (this.offset + length > this.bytes.length) {
                    throw new ProtoError(`field ${number}: length ${length} runs past the end of the message`);
                }

                const slice = this.bytes.subarray(this.offset, this.offset + length);

                this.offset += length;

                return { number, wireType, value: 0n, bytes: slice };
            }
            default:
                throw new ProtoError(`field ${number}: unsupported wire type ${wireType}`);
        }
    }

    private varint(): bigint {
        let result = 0n;
        let shift = 0n;

        for (;;) {
            if (this.offset >= this.bytes.length) {
                throw new ProtoError('message ended mid-varint');
            }

            const byte = this.bytes[this.offset++];

            result |= BigInt(byte & 0x7f) << shift;

            if ((byte & 0x80) === 0) {
                return result;
            }

            shift += 7n;

            if (shift > 63n) {
                throw new ProtoError('varint longer than 64 bits');
            }
        }
    }

    private fixed(width: number): bigint {
        if (this.offset + width > this.bytes.length) {
            throw new ProtoError('message ended mid-fixed-width field');
        }

        let result = 0n;

        for (let i = width - 1; i >= 0; i -= 1) {
            result = (result << 8n) | BigInt(this.bytes[this.offset + i]);
        }

        this.offset += width;

        return result;
    }
}

const EMPTY = new Uint8Array(0);

/**
 * A sub-message field's bytes, or a decode error.
 *
 * Without this, a `UUID` field arriving as a varint reads as `EMPTY` and
 * decodes to the all-zero UUID `00000000-0000-0000-0000-000000000000` — a
 * plausible-looking session or request id the caller would then match against.
 * A wire type the schema does not have is a malformed message, and the reader
 * must say so rather than invent a value. The payload-case table applies the
 * same rule by skipping a non-length-delimited match.
 */
function expectLengthDelimited(field: Field, name: string): Uint8Array {
    if (field.wireType !== WIRE_LENGTH_DELIMITED) {
        throw new ProtoError(`${name}: expected a length-delimited sub-message, got wire type ${field.wireType}`);
    }

    return field.bytes;
}

/** Walk every field of a message; the callback ignores what it does not want. */
function forEachField(bytes: Uint8Array, visit: (field: Field) => void): void {
    const reader = new Reader(bytes);

    while (!reader.done) {
        visit(reader.field());
    }
}

/**
 * `int32` on the wire is a varint sign-extended to 64 bits, so a negative
 * value arrives as ten bytes with the high bits set. Reading it as unsigned
 * would turn `-1` into 18446744073709551615.
 */
function asInt32(value: bigint): number {
    const signed = value >= 1n << 63n ? value - (1n << 64n) : value;

    return Number(signed);
}

// ── common.v1.UUID ──────────────────────────────────────────────────────

const UUID_HIGH = 1;
const UUID_LOW = 2;

/**
 * Render a proto `UUID{high, low}` in the canonical hyphenated form.
 *
 * Reproduces `libs/proto-ts`'s `uuidToHex`, which is what the play client and
 * therefore the export use as a record key. Reproduced rather than imported:
 * the exported verifier must not reach into `@99dot5/*`, and the rule is four
 * lines.
 */
export function uuidFromParts(high: bigint, low: bigint): string {
    const highHex = high.toString(16).padStart(16, '0');
    const lowHex = low.toString(16).padStart(16, '0');

    return `${highHex.slice(0, 8)}-${highHex.slice(8, 12)}-${highHex.slice(12, 16)}-${lowHex.slice(0, 4)}-${lowHex.slice(4, 16)}`;
}

function decodeUuid(bytes: Uint8Array): string {
    let high = 0n;
    let low = 0n;

    forEachField(bytes, (field) => {
        if (field.number === UUID_HIGH) {
            high = field.value;
        } else if (field.number === UUID_LOW) {
            low = field.value;
        }
    });

    return uuidFromParts(high, low);
}

// ── casino.v1.ServerEnvelope ────────────────────────────────────────────

const SERVER_SEQUENCE = 1;
const SERVER_RELATED_REQUEST_ID = 2;
const SERVER_SESSION_ID = 3;

/**
 * The `ServerEnvelope.payload` oneof, by field number. The names match
 * protobuf-es's camelCase `payload.case`, which is what the play client writes
 * into its receipts store and therefore what the export's `payloadCase` says.
 */
const SERVER_PAYLOAD_CASES: Record<number, ServerPayloadCase> = {
    10: 'pong',
    11: 'commandAccepted',
    12: 'commandRejected',
    13: 'betPlaced',
    14: 'roundStarted',
    15: 'roundUpdated',
    16: 'roundEnded',
    17: 'balanceChanged',
    18: 'sessionEnding',
    19: 'sessionCreated',
    20: 'sessionResumed',
    21: 'timeSync',
};

export type ServerPayloadCase =
    | 'pong'
    | 'commandAccepted'
    | 'commandRejected'
    | 'betPlaced'
    | 'roundStarted'
    | 'roundUpdated'
    | 'roundEnded'
    | 'balanceChanged'
    | 'sessionEnding'
    | 'sessionCreated'
    | 'sessionResumed'
    | 'timeSync';

/** `casino.v1.StepOrigin`, the author of the step a `RoundUpdated` reports. */
export type StepOrigin = 'unspecified' | 'player' | 'system';

const STEP_ORIGINS: Record<number, StepOrigin> = { 0: 'unspecified', 1: 'player', 2: 'system' };

export interface DecodedServerEnvelope {
    sequence: bigint;
    /** Hyphenated, or null when the frame is not a reply to a command. */
    relatedRequestId: string | null;
    sessionId: string | null;
    /** null for a payload case this reader does not have in its table. */
    payloadCase: ServerPayloadCase | null;
    /** From whichever round-bearing payload is present. */
    roundId: string | null;
    /** `RoundUpdated.action_index` / `RoundEnded.action_index`, absent elsewhere. */
    actionIndex: number | null;
    /** `RoundUpdated.origin` only. Absent (null) on every other payload. */
    origin: StepOrigin | null;
    /** `RoundEnded.player_commitment`, 32 bytes; absent on a voided round. */
    playerCommitment: Uint8Array | null;
}

// Inner round-bearing events. `round_id` is field 1 on all four.
const EVENT_ROUND_ID = 1;
const ROUND_UPDATED_ACTION_INDEX = 2;
const ROUND_UPDATED_ORIGIN = 5;
const ROUND_ENDED_PLAYER_COMMITMENT = 5;
const ROUND_ENDED_ACTION_INDEX = 6;

/** Decode the protobuf BODY of a server frame (the bytes after tag+signature). */
export function decodeServerEnvelope(body: Uint8Array): DecodedServerEnvelope {
    const out: DecodedServerEnvelope = {
        sequence: 0n,
        relatedRequestId: null,
        sessionId: null,
        payloadCase: null,
        roundId: null,
        actionIndex: null,
        origin: null,
        playerCommitment: null,
    };

    forEachField(body, (field) => {
        switch (field.number) {
            case SERVER_SEQUENCE:
                out.sequence = field.value;
                return;
            case SERVER_RELATED_REQUEST_ID:
                out.relatedRequestId = decodeUuid(expectLengthDelimited(field, 'ServerEnvelope.related_request_id'));
                return;
            case SERVER_SESSION_ID:
                out.sessionId = decodeUuid(expectLengthDelimited(field, 'ServerEnvelope.session_id'));
                return;
            default:
                break;
        }

        const payloadCase = SERVER_PAYLOAD_CASES[field.number];

        if (!payloadCase || field.wireType !== WIRE_LENGTH_DELIMITED) {
            // An unknown field number, or `trace_id` (4). Skipping is not
            // lossy for this reader's purpose: the bytes stay in the frame the
            // signature and the commitment cover.
            return;
        }

        out.payloadCase = payloadCase;

        switch (payloadCase) {
            case 'betPlaced':
            case 'roundStarted':
            case 'roundUpdated':
            case 'roundEnded':
                readRoundBearingEvent(field.bytes, out, payloadCase);
                return;
            default:
                // `commandAccepted` is an empty message by design: correlation
                // is entirely through `related_request_id` above.
                return;
        }
    });

    return out;
}

function readRoundBearingEvent(
    bytes: Uint8Array,
    out: DecodedServerEnvelope,
    payloadCase: 'betPlaced' | 'roundStarted' | 'roundUpdated' | 'roundEnded',
): void {
    forEachField(bytes, (field) => {
        if (field.number === EVENT_ROUND_ID && field.wireType === WIRE_LENGTH_DELIMITED) {
            out.roundId = decodeUuid(field.bytes);

            return;
        }

        if (payloadCase === 'roundUpdated') {
            if (field.number === ROUND_UPDATED_ACTION_INDEX && field.wireType === WIRE_VARINT) {
                out.actionIndex = asInt32(field.value);
            } else if (field.number === ROUND_UPDATED_ORIGIN && field.wireType === WIRE_VARINT) {
                // An enum value this build does not know reads as
                // `unspecified`, which is the conservative arm: it keeps the
                // pre-field behaviour rather than inventing an origin.
                out.origin = STEP_ORIGINS[Number(field.value)] ?? 'unspecified';
            }

            return;
        }

        if (payloadCase === 'roundEnded') {
            if (field.number === ROUND_ENDED_ACTION_INDEX && field.wireType === WIRE_VARINT) {
                out.actionIndex = asInt32(field.value);
            } else if (field.number === ROUND_ENDED_PLAYER_COMMITMENT && field.wireType === WIRE_LENGTH_DELIMITED) {
                out.playerCommitment = field.bytes.slice();
            }
        }
    });

    // proto3 implicit presence: `RoundUpdated.origin` is omitted when it is
    // STEP_ORIGIN_UNSPECIFIED, so an absent field and a producer predating the
    // field are indistinguishable — both mean "no origin stated", which is
    // what `unspecified` says.
    if (payloadCase === 'roundUpdated' && out.origin === null) {
        out.origin = 'unspecified';
    }
}

// ── casino.v1.ClientEnvelope ────────────────────────────────────────────

const CLIENT_REQUEST_ID = 1;
const CLIENT_SESSION_ID = 2;

const CLIENT_PAYLOAD_CASES: Record<number, ClientPayloadCase> = {
    10: 'ping',
    11: 'placeBet',
    12: 'playerAction',
    13: 'cashOut',
    14: 'resumeSession',
    15: 'endSession',
    16: 'timeSync',
};

export type ClientPayloadCase =
    | 'ping'
    | 'placeBet'
    | 'playerAction'
    | 'cashOut'
    | 'resumeSession'
    | 'endSession'
    | 'timeSync';

export interface DecodedClientEnvelope {
    requestId: string | null;
    sessionId: string | null;
    payloadCase: ClientPayloadCase | null;
    /**
     * `PlaceBetCommand.client_seed` as the raw UTF-8 bytes on the wire, or
     * null when the command is not a `PlaceBet` or carries no seed.
     *
     * Bytes, not a decoded string: the sequencer hashes exactly these bytes
     * into the transcript's `client_seed`, so a decode/re-encode round trip
     * is a place a normalisation could hide.
     */
    placeBetClientSeed: Uint8Array | null;
}

// casino.v1.PlaceBetCommand
const PLACE_BET_CLIENT_SEED = 2;

/** Decode the protobuf BODY of a client command frame. */
export function decodeClientEnvelope(body: Uint8Array): DecodedClientEnvelope {
    const out: DecodedClientEnvelope = {
        requestId: null,
        sessionId: null,
        payloadCase: null,
        placeBetClientSeed: null,
    };

    forEachField(body, (field) => {
        if (field.number === CLIENT_REQUEST_ID && field.wireType === WIRE_LENGTH_DELIMITED) {
            out.requestId = decodeUuid(field.bytes);
        } else if (field.number === CLIENT_SESSION_ID && field.wireType === WIRE_LENGTH_DELIMITED) {
            out.sessionId = decodeUuid(field.bytes);
        } else {
            const payloadCase = CLIENT_PAYLOAD_CASES[field.number];

            if (payloadCase && field.wireType === WIRE_LENGTH_DELIMITED) {
                out.payloadCase = payloadCase;

                if (payloadCase === 'placeBet') {
                    forEachField(field.bytes, (inner) => {
                        if (inner.number === PLACE_BET_CLIENT_SEED && inner.wireType === WIRE_LENGTH_DELIMITED) {
                            out.placeBetClientSeed = inner.bytes.slice();
                        }
                    });
                }
            }
        }
    });

    return out;
}
