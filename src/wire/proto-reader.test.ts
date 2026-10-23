import { describe, expect, it } from 'vitest';
import {
    CLIENT_PAYLOAD_CASES,
    COMMAND_GAME_ARMS,
    decodeClientEnvelope,
    decodeServerEnvelope,
    GAME_ARMS,
    ONEOF_BAND,
    ONEOF_BASE,
} from './proto-reader';
import { encodeUuid, ProtoWriter } from './proto-writer';

const ROUND = '0b1e6f2a-4c3d-4e5f-8a9b-0c1d2e3f4a5b';

/** A `ServerEnvelope` carrying `RoundDeadlineReachedEvent` (payload tag 112). */
function deadlineEnvelope(): Uint8Array {
    const deadline = new ProtoWriter().varint(1, 2_340_000).varint(2, 37).finish();
    const event = new ProtoWriter()
        .bytes(1, encodeUuid(ROUND))
        .varint(2, 1_700_000_003_000n)
        .bytes(3, new TextEncoder().encode('crash:v1'))
        .bytes(101, deadline)
        .finish();

    return new ProtoWriter().varint(1, 9n).bytes(112, event).finish();
}

describe('decodeServerEnvelope on the round deadline notice', () => {
    it('names payload case 112 and reads its round id', () => {
        const decoded = decodeServerEnvelope(deadlineEnvelope());

        expect(decoded.payloadCase).toBe('roundDeadlineReached');
        expect(decoded.sequence).toBe(9n);
        expect(decoded.roundId).toBe(ROUND);
    });

    it('projects nothing else: no action index, no commitment, no seed', () => {
        // Field 2 is the deadline instant here, a varint like `RoundEnded.ending`
        // and `RoundUpdated.action_index`; it must not be read as either.
        const decoded = decodeServerEnvelope(deadlineEnvelope());

        expect(decoded.actionIndex).toBeNull();
        expect(decoded.origin).toBeNull();
        expect(decoded.playerCommitment).toBeNull();
        expect(decoded.roundEndedServerSeed).toBeNull();
        expect(decoded.roundEndedVoided).toBe(false);
        expect(decoded.crashState).toBeNull();
    });
});

/** The `ClientEnvelope.payload` number of a payload case, from the reader's own table. */
function clientPayloadField(payloadCase: 'placeBet' | 'cashOut'): number {
    const entry = Object.entries(CLIENT_PAYLOAD_CASES).find(([, name]) => name === payloadCase);

    if (!entry) {
        throw new Error(`no ClientEnvelope payload for ${payloadCase}`);
    }

    return Number(entry[0]);
}

/**
 * A `ClientEnvelope` whose command carries the hilo arm plus one extra
 * length-delimited field at `extra`, written AFTER the arm so that a reader
 * applying "last arm wins" to it would pick it.
 */
function commandWithExtraField(payloadCase: 'placeBet' | 'cashOut', extra: number): Uint8Array {
    const command = new ProtoWriter();

    if (payloadCase === 'placeBet') {
        command.bytes(2, new TextEncoder().encode('seed'));
    } else {
        command.bytes(1, encodeUuid(ROUND));
    }

    const hilo = COMMAND_GAME_ARMS[payloadCase]['hilo:v1'];

    if (hilo === undefined) {
        throw new Error(`${payloadCase} has no hilo arm`);
    }

    command.bytes(hilo, new Uint8Array(0)).bytes(extra, new Uint8Array([0x08, 0x01]));

    return new ProtoWriter()
        .bytes(1, encodeUuid(ROUND))
        .bytes(clientPayloadField(payloadCase), command.finish())
        .finish();
}

describe('decodeClientEnvelope classifies an unknown command field by its band', () => {
    it('anchors the band on the game table', () => {
        // Every game arm sits inside the first oneof band.
        for (const number of Object.values(GAME_ARMS)) {
            expect(number).toBeGreaterThanOrEqual(ONEOF_BASE);
            expect(number).toBeLessThan(ONEOF_BASE + ONEOF_BAND);
        }
    });

    it.each(['placeBet', 'cashOut'] as const)(
        'ignores a %s field at ONEOF_BASE + ONEOF_BAND: a later oneof, never the arm',
        (payloadCase) => {
            const body = decodeClientEnvelope(commandWithExtraField(payloadCase, ONEOF_BASE + ONEOF_BAND)).commandBody;

            expect(body).toEqual({ case: payloadCase, game: 'hilo' });
        },
    );

    it('skips an unknown PlaceBet field below ONEOF_BASE: a later scalar', () => {
        // 1, 2 and 3 are the known scalars; the next free one is unknown here.
        const unknownScalar = 4;

        expect(unknownScalar).toBeLessThan(ONEOF_BASE);

        const body = decodeClientEnvelope(commandWithExtraField('placeBet', unknownScalar)).commandBody;

        expect(body).toEqual({ case: 'placeBet', game: 'hilo' });
    });

    it('reports an unknown PlaceBet field inside the band as an unrecognised arm, naming it', () => {
        const known = new Set(Object.values(GAME_ARMS));
        const unknownArm = ONEOF_BASE + ONEOF_BAND - 1;

        expect(known.has(unknownArm)).toBe(false);

        const body = decodeClientEnvelope(commandWithExtraField('placeBet', unknownArm)).commandBody;

        expect(body?.case).toBe('unrecognised');
        expect(body?.case === 'unrecognised' ? body.description : '').toContain(`field ${unknownArm}`);
    });
});
