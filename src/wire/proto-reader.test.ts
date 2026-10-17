import { describe, expect, it } from 'vitest';
import { decodeServerEnvelope } from './proto-reader';
import { encodeUuid, ProtoWriter } from './proto-writer';

const ROUND = '0b1e6f2a-4c3d-4e5f-8a9b-0c1d2e3f4a5b';

/** A `ServerEnvelope` carrying `RoundDeadlineReachedEvent` (payload tag 23). */
function deadlineEnvelope(): Uint8Array {
    const deadline = new ProtoWriter().varint(1, 2_340_000).varint(2, 37).finish();
    const event = new ProtoWriter()
        .bytes(1, encodeUuid(ROUND))
        .varint(2, 1_700_000_003_000n)
        .bytes(3, new TextEncoder().encode('crash:v1'))
        .bytes(10, deadline)
        .finish();

    return new ProtoWriter().varint(1, 9n).bytes(23, event).finish();
}

describe('decodeServerEnvelope on the round deadline notice', () => {
    it('names payload case 23 and reads its round id', () => {
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
