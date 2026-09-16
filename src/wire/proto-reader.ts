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

/**
 * `casino.v1.RoundEndCause` — the server's own statement of WHY the round
 * ended, off `RoundEndedEvent.cause` (field 4).
 *
 * Explicit presence, so an absent field is a real absence (a producer that
 * predates the field) and never the zero value. `unspecified` is therefore
 * only ever an explicitly-written zero, which a real sequencer does not emit —
 * kept in the table so an unknown future value has somewhere honest to land
 * rather than being mapped onto a cause that carries meaning.
 *
 * It is a SERVER ASSERTION. A rule may use it to detect a contradiction with
 * what the player's own signed commands show; it may never be read as proof
 * on its own.
 */
export type RoundEndCause = 'unspecified' | 'player-action' | 'system-sweep' | 'transcript-cap';

const ROUND_END_CAUSES: Record<number, RoundEndCause> = {
    0: 'unspecified',
    1: 'player-action',
    2: 'system-sweep',
    3: 'transcript-cap',
};

/**
 * The two `crash.v1.State` fields that turn a wall-clock instant into a tick.
 *
 * Read off a `RoundStarted`'s `game_state` oneof, which the tenant key signed
 * — so the anchor a rejection's timestamp is measured against is the server's
 * own signed statement of when the round began, not a number supplied
 * alongside the complaint.
 */
export interface DecodedCrashState {
    /** `tick_quantum_ms` (field 4): milliseconds per integer tick. */
    tickQuantumMs: bigint | null;
    /** `server_anchor_unix_ms` (field 6): the round's wall-clock origin. */
    serverAnchorUnixMs: bigint | null;
}

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
    /**
     * `CommandRejected.reason_code` as the RAW enum number, null elsewhere.
     *
     * Raw rather than mapped to a name: an unknown code must stay
     * distinguishable from a known one, and a reader that folded it into an
     * `unspecified` arm would let a future refusal class read as the
     * zero-value one — which is exactly the class a liveness rule must not
     * treat as "the server said nothing".
     */
    rejectionReasonCode: number | null;
    /**
     * `CommandRejected.received_at_unix_ms` (4) or
     * `CommandAccepted.received_at_unix_ms` (1) — the SAME binding on both, so
     * one field carries it and the payload case says which reply it belongs
     * to.
     *
     * **It attests when the bytes arrived, not that the command was
     * well-formed**: the server stamps it at receipt, BEFORE it verifies the
     * session-key signature. Nothing exploitable follows, but a report that
     * described it as the instant a valid command arrived would overstate it.
     */
    receivedAtUnixMs: bigint | null;
    /** `crash.v1.State` off a `RoundStarted`'s `game_state`; null elsewhere. */
    crashState: DecodedCrashState | null;
    /**
     * `RoundEnded.cause` (field 4), null when the frame states none.
     *
     * Null is NOT a default: the field is `optional`, so a producer that never
     * wrote it is distinguishable from one that stated a cause, and a rule
     * that folded the two would read silence as an assertion.
     */
    roundEndCause: RoundEndCause | null;
}

// Inner round-bearing events. `round_id` is field 1 on all four.
const EVENT_ROUND_ID = 1;
const ROUND_UPDATED_ACTION_INDEX = 2;
const ROUND_UPDATED_ORIGIN = 5;
const ROUND_ENDED_CAUSE = 4;
const ROUND_ENDED_PLAYER_COMMITMENT = 5;
const ROUND_ENDED_ACTION_INDEX = 6;

// casino.v1.CommandRejected. `round_id` is field 3 — a FIFTH payload carrying
// a round id, and the only optional one: a refusal names a round exactly when
// it concerns one.
const REJECTED_REASON_CODE = 1;
const REJECTED_ROUND_ID = 3;
const REJECTED_RECEIVED_AT_UNIX_MS = 4;

// casino.v1.CommandAccepted — one field, the same stamp under the same rule.
const ACCEPTED_RECEIVED_AT_UNIX_MS = 1;

// casino.v1.RoundStartedEvent.game_state, the crash arm.
const ROUND_STARTED_CRASH_STATE = 11;

// crash.v1.State
const CRASH_STATE_TICK_QUANTUM_MS = 4;
const CRASH_STATE_SERVER_ANCHOR_UNIX_MS = 6;

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
        rejectionReasonCode: null,
        receivedAtUnixMs: null,
        crashState: null,
        roundEndCause: null,
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
            case 'commandRejected':
                readCommandRejected(field.bytes, out);
                return;
            case 'commandAccepted':
                readCommandAccepted(field.bytes, out);
                return;
            default:
                // Everything else correlates entirely through
                // `related_request_id` above and carries nothing this reader
                // needs.
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

        if (
            payloadCase === 'roundStarted' &&
            field.number === ROUND_STARTED_CRASH_STATE &&
            field.wireType === WIRE_LENGTH_DELIMITED
        ) {
            out.crashState = readCrashState(field.bytes);

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
            } else if (field.number === ROUND_ENDED_CAUSE && field.wireType === WIRE_VARINT) {
                // A value this build does not know stays `unspecified` rather
                // than borrowing the meaning of a cause it is not: every rule
                // over `cause` treats `unspecified` as "nothing stated", which
                // is the only safe reading of a cause nobody here can name.
                out.roundEndCause = ROUND_END_CAUSES[Number(field.value)] ?? 'unspecified';
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

/**
 * `crash.v1.State`'s two clock fields.
 *
 * Both stay `null` when absent rather than defaulting to 0: they are
 * implicit-presence `uint32`/`uint64`, so a producer that never wrote them is
 * indistinguishable on the wire from one that wrote zero — and a zero quantum
 * would make the tick derivation a division by zero, while a zero anchor would
 * silently place the round at the Unix epoch. A caller that cannot get both
 * must report that it cannot, not compute from a default.
 */
function readCrashState(bytes: Uint8Array): DecodedCrashState {
    const state: DecodedCrashState = { tickQuantumMs: null, serverAnchorUnixMs: null };

    forEachField(bytes, (field) => {
        if (field.wireType !== WIRE_VARINT) {
            return;
        }

        if (field.number === CRASH_STATE_TICK_QUANTUM_MS) {
            state.tickQuantumMs = field.value;
        } else if (field.number === CRASH_STATE_SERVER_ANCHOR_UNIX_MS) {
            state.serverAnchorUnixMs = field.value;
        }
    });

    return state;
}

/**
 * `casino.v1.CommandRejected`.
 *
 * `round_id` lands on the shared `roundId` field, beside the four event
 * classes', because it is the same fact: the round these signed bytes are
 * about. That is what makes a refusal a ROUND frame — the export scopes it in
 * on the server's own signed field, with no command body decoded — and it is
 * also why a refusal naming some OTHER round shows up in the label findings
 * rather than passing unnoticed.
 *
 * `detail` (field 2) is deliberately not read. It is free text the server
 * chose; nothing here may draw a conclusion from it.
 */
function readCommandRejected(bytes: Uint8Array, out: DecodedServerEnvelope): void {
    forEachField(bytes, (field) => {
        if (field.number === REJECTED_REASON_CODE && field.wireType === WIRE_VARINT) {
            out.rejectionReasonCode = Number(field.value);
        } else if (field.number === REJECTED_ROUND_ID && field.wireType === WIRE_LENGTH_DELIMITED) {
            out.roundId = decodeUuid(field.bytes);
        } else if (field.number === REJECTED_RECEIVED_AT_UNIX_MS && field.wireType === WIRE_VARINT) {
            out.receivedAtUnixMs = field.value;
        }
    });

    // proto3 implicit presence: `reason_code` is a bare enum, so the
    // zero value (UNSPECIFIED) never reaches the wire. Absent therefore MEANS
    // zero here, and saying so is what keeps a rule from reading an
    // unspecified refusal as "no code stated".
    if (out.rejectionReasonCode === null) {
        out.rejectionReasonCode = 0;
    }
}

/**
 * `casino.v1.CommandAccepted` — one field, and it is the null distribution a
 * refusal's timing is read against.
 *
 * Unlike the refusal's, this frame is a DURABLE `client_outbox` row, so two
 * things follow that a consumer must not misread: an idempotent retry replays
 * the FIRST attempt's stamp, and the dispatcher broadcasts the row to every
 * connection of the session, so a tab can hold an acknowledgement for a
 * command it never sent.
 */
function readCommandAccepted(bytes: Uint8Array, out: DecodedServerEnvelope): void {
    forEachField(bytes, (field) => {
        if (field.number === ACCEPTED_RECEIVED_AT_UNIX_MS && field.wireType === WIRE_VARINT) {
            out.receivedAtUnixMs = field.value;
        }
    });
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
    /**
     * The round id inside the PLAYER-SIGNED command body — `round_id`, field 1
     * on both `CashOutCommand` and `PlayerActionCommand`. Null on every other
     * arm (`PlaceBet` opens a round rather than naming one) and on an arm that
     * omitted it.
     *
     * This is what makes a server-supplied round id checkable. A refusal can
     * echo the client's own round id back with any reason code the server
     * likes, so the verifier trusts the echo only when it equals the id the
     * player themselves signed — attribution BY SIGNATURE, never by inferring
     * a step from a body (which stays forbidden, D9).
     */
    commandRoundId: string | null;
    /**
     * The command's own game arm and the fields inside it, or null when the
     * payload is not one of the three game commands (`Ping`, `ResumeSession`,
     * `EndSession`, `TimeSync` carry nothing a round projection can read).
     *
     * This is what the fourth proof compares against the transcript: the
     * transcript says what the sequencer WROTE, and this says what the player
     * SIGNED. A body this reader cannot name is `unrecognised` and carries the
     * arm's field number, because the honest answer to "a command from a build
     * newer than this one" is to say so, never to pick the nearest known arm.
     */
    commandBody: DecodedCommandBody | null;
}

/**
 * A decoded command body, keyed by `(payload case, game arm)`.
 *
 * Only the fields the projection rules compare are carried; everything else in
 * the frame stays inside the bytes the signature and the commitment cover. The
 * amounts are deliberately absent: a stake is checked against the transcript's
 * `stake` field by nothing here, and inventing a comparison the kernel does
 * not make would be a rule of this tool's own.
 */
export type DecodedCommandBody =
    | { case: 'placeBet'; game: 'hilo' }
    /** `crash.v1.PlaceBet.auto_cashout_ppm` — absent ⇒ MANUAL mode. */
    | { case: 'placeBet'; game: 'crash'; autoCashoutPpm: number | null }
    /** `plinko.v1.PlaceBet` — `risk` is the PROTO enum number, not the Borsh tag. */
    | { case: 'placeBet'; game: 'plinko'; rows: number; risk: number }
    | { case: 'placeBet'; game: 'mines'; mineCount: number }
    | { case: 'placeBet'; game: 'hydra'; hero: number }
    | { case: 'playerAction'; game: 'hilo'; arm: 'higher' | 'lower' }
    /** `mines.v1.Reveal.tile_index` is `optional`: absent is a real absence. */
    | { case: 'playerAction'; game: 'mines'; arm: 'reveal'; tileIndex: number | null }
    | {
          case: 'playerAction';
          game: 'hydra';
          arm: 'fight' | 'physical-attack' | 'magic-attack' | 'drink-potion' | 'drink-mana';
      }
    | { case: 'cashOut'; game: 'hilo' | 'plinko' | 'mines' | 'hydra' }
    /** `crash.v1.CashOut.tick` is `optional`: tick 0 is a legal claim. */
    | { case: 'cashOut'; game: 'crash'; tick: number | null }
    /** An arm (or a nested `kind`) this build has no rule for. */
    | { case: 'unrecognised'; description: string };

// casino.v1.PlaceBetCommand
const PLACE_BET_CLIENT_SEED = 2;

/**
 * The per-game arms of the three command messages.
 *
 * `PlaceBetCommand` and `CashOutCommand` deliberately share the numbering
 * (10..14) — "one game keeps one number across commands" — and
 * `PlayerActionCommand` has only the three games with in-round decisions.
 */
const PLACE_BET_ARMS: Record<number, 'hilo' | 'crash' | 'plinko' | 'mines' | 'hydra'> = {
    10: 'hilo',
    11: 'crash',
    12: 'plinko',
    13: 'mines',
    14: 'hydra',
};

const PLAYER_ACTION_ARMS: Record<number, 'hilo' | 'mines' | 'hydra'> = {
    10: 'hilo',
    11: 'mines',
    12: 'hydra',
};

const CASH_OUT_ARMS: Record<number, 'hilo' | 'crash' | 'plinko' | 'mines' | 'hydra'> = {
    10: 'hilo',
    11: 'crash',
    12: 'plinko',
    13: 'mines',
    14: 'hydra',
};

// crash.v1.PlaceBet / crash.v1.CashOut
const CRASH_AUTO_CASHOUT_PPM = 1;
const CRASH_CASHOUT_TICK = 1;

// plinko.v1.PlaceBet
const PLINKO_ROWS = 1;
const PLINKO_RISK = 2;

// mines.v1.PlaceBet / mines.v1.PlayerAction.kind / mines.v1.Reveal
const MINES_MINE_COUNT = 1;
const MINES_ACTION_REVEAL = 1;
const MINES_REVEAL_TILE_INDEX = 1;

// hydra.v1.PlaceBet
const HYDRA_HERO = 1;

/** `hilo.v1.PlayerAction.kind`. */
const HILO_ACTION_ARMS: Record<number, 'higher' | 'lower'> = { 1: 'higher', 2: 'lower' };

/**
 * `hydra.v1.PlayerAction.kind` — FIVE arms, and `fight` is not a synonym the
 * schema documents: it is a separate arm that the sequencer maps onto the same
 * engine action as `physical_attack`. The projection table is what records
 * that, not this reader, which reports the arm the player actually signed.
 */
const HYDRA_ACTION_ARMS: Record<number, 'fight' | 'physical-attack' | 'magic-attack' | 'drink-potion' | 'drink-mana'> = {
    1: 'fight',
    2: 'physical-attack',
    3: 'magic-attack',
    4: 'drink-potion',
    5: 'drink-mana',
};

// casino.v1.CashOutCommand / casino.v1.PlayerActionCommand — `round_id` is
// field 1 on both, deliberately: one game keeps one number across commands.
const COMMAND_ROUND_ID = 1;

/**
 * Read one varint field out of a message, or `null` when it is absent.
 *
 * `null` for absent is what keeps an `optional` scalar honest: `mines.Reveal
 * .tile_index` and `crash.CashOut.tick` both have explicit presence precisely
 * because zero is a legal value, so a reader that defaulted them to 0 would
 * turn "no payload" into "tile 0" / "tick 0" — the exact confusion the schema
 * comments say the `optional` is there to prevent. Bare scalars default at
 * their call sites instead, where absent genuinely MEANS zero.
 */
function varintField(bytes: Uint8Array, number: number): number | null {
    let found: number | null = null;

    forEachField(bytes, (field) => {
        if (field.number === number && field.wireType === WIRE_VARINT) {
            found = Number(field.value);
        }
    });

    return found;
}

/**
 * The length-delimited arm of a oneof, as `[field number, bytes]` — LAST WINS.
 *
 * A well-formed oneof carries exactly one arm, so the rule only matters for a
 * message that carries two. It matters absolutely there: the sequencer decodes
 * with `prost`, which overwrites the oneof on every arm it meets and therefore
 * acts on the LAST one. A reader that took the first would project the player's
 * command from an arm the server never executed, and the fourth proof would
 * report a mismatch against a server that read the bytes correctly — or, worse,
 * report agreement when the two actually disagreed.
 *
 * So this is not a preference: it is the sequencer's reading, reproduced. Every
 * other reader in this file already resolves the same way (`varintField` keeps
 * the last match, and the `decode*Body` walkers overwrite `body` as they go),
 * and they must stay in step for the same reason.
 */
function oneofArm(bytes: Uint8Array): [number, Uint8Array] | null {
    let arm: [number, Uint8Array] | null = null;

    forEachField(bytes, (field) => {
        if (field.wireType === WIRE_LENGTH_DELIMITED) {
            arm = [field.number, field.bytes];
        }
    });

    return arm;
}

function decodePlaceBetBody(bytes: Uint8Array): DecodedCommandBody {
    let body: DecodedCommandBody = {
        case: 'unrecognised',
        description: 'a PlaceBet command with no game_data arm set',
    };

    forEachField(bytes, (field) => {
        if (field.wireType !== WIRE_LENGTH_DELIMITED) {
            return;
        }

        const game = PLACE_BET_ARMS[field.number];

        if (!game) {
            if (field.number !== PLACE_BET_CLIENT_SEED && field.number !== 1) {
                body = {
                    case: 'unrecognised',
                    description: `a PlaceBet game_data arm this build has no rule for (field ${field.number})`,
                };
            }

            return;
        }

        switch (game) {
            case 'hilo':
                body = { case: 'placeBet', game: 'hilo' };
                return;
            case 'crash':
                body = {
                    case: 'placeBet',
                    game: 'crash',
                    autoCashoutPpm: varintField(field.bytes, CRASH_AUTO_CASHOUT_PPM),
                };
                return;
            case 'plinko':
                // `rows` and `risk` are BARE scalars, so absent means zero —
                // and zero is out of range for both, which is what makes an
                // empty plinko arm fail the projection rather than pass it.
                body = {
                    case: 'placeBet',
                    game: 'plinko',
                    rows: varintField(field.bytes, PLINKO_ROWS) ?? 0,
                    risk: varintField(field.bytes, PLINKO_RISK) ?? 0,
                };
                return;
            case 'mines':
                body = {
                    case: 'placeBet',
                    game: 'mines',
                    mineCount: varintField(field.bytes, MINES_MINE_COUNT) ?? 0,
                };
                return;
            case 'hydra':
                // `hero` is a bare `uint32` and hero 0 is a legal selection, so
                // absent means 0 here — unlike the `optional` scalars above.
                body = { case: 'placeBet', game: 'hydra', hero: varintField(field.bytes, HYDRA_HERO) ?? 0 };
                return;
        }
    });

    return body;
}

function decodePlayerActionBody(bytes: Uint8Array): DecodedCommandBody {
    let body: DecodedCommandBody = {
        case: 'unrecognised',
        description: 'a PlayerAction command with no game_data arm set',
    };

    forEachField(bytes, (field) => {
        if (field.wireType !== WIRE_LENGTH_DELIMITED || field.number === COMMAND_ROUND_ID) {
            return;
        }

        const game = PLAYER_ACTION_ARMS[field.number];

        if (!game) {
            body = {
                case: 'unrecognised',
                description: `a PlayerAction game_data arm this build has no rule for (field ${field.number})`,
            };

            return;
        }

        const arm = oneofArm(field.bytes);

        if (!arm) {
            body = {
                case: 'unrecognised',
                description: `a ${game} PlayerAction with no kind set`,
            };

            return;
        }

        const [armNumber, armBytes] = arm;

        switch (game) {
            case 'hilo': {
                const kind = HILO_ACTION_ARMS[armNumber];

                body = kind
                    ? { case: 'playerAction', game: 'hilo', arm: kind }
                    : { case: 'unrecognised', description: `a hilo PlayerAction kind this build has no rule for (field ${armNumber})` };

                return;
            }
            case 'mines':
                body =
                    armNumber === MINES_ACTION_REVEAL
                        ? {
                              case: 'playerAction',
                              game: 'mines',
                              arm: 'reveal',
                              tileIndex: varintField(armBytes, MINES_REVEAL_TILE_INDEX),
                          }
                        : {
                              case: 'unrecognised',
                              description: `a mines PlayerAction kind this build has no rule for (field ${armNumber})`,
                          };

                return;
            case 'hydra': {
                const kind = HYDRA_ACTION_ARMS[armNumber];

                body = kind
                    ? { case: 'playerAction', game: 'hydra', arm: kind }
                    : { case: 'unrecognised', description: `a hydra PlayerAction kind this build has no rule for (field ${armNumber})` };

                return;
            }
        }
    });

    return body;
}

function decodeCashOutBody(bytes: Uint8Array): DecodedCommandBody {
    let body: DecodedCommandBody = {
        case: 'unrecognised',
        description: 'a CashOut command with no game_data arm set',
    };

    forEachField(bytes, (field) => {
        if (field.wireType !== WIRE_LENGTH_DELIMITED || field.number === COMMAND_ROUND_ID) {
            return;
        }

        const game = CASH_OUT_ARMS[field.number];

        if (!game) {
            body = {
                case: 'unrecognised',
                description: `a CashOut game_data arm this build has no rule for (field ${field.number})`,
            };

            return;
        }

        body =
            game === 'crash'
                ? { case: 'cashOut', game: 'crash', tick: varintField(field.bytes, CRASH_CASHOUT_TICK) }
                : { case: 'cashOut', game };
    });

    return body;
}

/** Decode the protobuf BODY of a client command frame. */
export function decodeClientEnvelope(body: Uint8Array): DecodedClientEnvelope {
    const out: DecodedClientEnvelope = {
        requestId: null,
        sessionId: null,
        payloadCase: null,
        placeBetClientSeed: null,
        commandRoundId: null,
        commandBody: null,
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
                    out.commandBody = decodePlaceBetBody(field.bytes);
                } else if (payloadCase === 'cashOut' || payloadCase === 'playerAction') {
                    forEachField(field.bytes, (inner) => {
                        if (inner.number === COMMAND_ROUND_ID && inner.wireType === WIRE_LENGTH_DELIMITED) {
                            out.commandRoundId = decodeUuid(inner.bytes);
                        }
                    });
                    out.commandBody =
                        payloadCase === 'cashOut'
                            ? decodeCashOutBody(field.bytes)
                            : decodePlayerActionBody(field.bytes);
                }
            }
        }
    });

    return out;
}
