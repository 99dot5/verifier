// @vitest-environment node
// The round's server-signed time: the latest lineage-verified
// CommandAccepted/CommandRejected stamp before RoundEnded, by sequence.
import * as ed from '@noble/ed25519';
import { describe, expect, it } from 'vitest';
import type { KeySet, ReceiptsInput } from '../verifier';
import { encodeEdpk } from '../wire/signature';
import { serverFrame, type ServerFrameSpec, type ServerPayloadSpec } from './fixtures';
import type { ImportedCommand, ImportedReceipts } from './import';
import { signedRoundTime } from './round-time';

const SIGNING_SEED = new Uint8Array(32).fill(1);
const FOREIGN_SEED = new Uint8Array(32).fill(9);
const SESSION_ID = 'e2b6419a-ec4b-4eef-bdfa-802b6f338fc2';
const ROUND_ID = '9a256790-c7c0-47b0-9a5b-6ed2905d2df1';
const KEYS: KeySet = {
    status: 'available',
    keys: [{ edpk: encodeEdpk(ed.getPublicKey(SIGNING_SEED)), registration: null }],
};

interface FrameSpec {
    sequence: number;
    payload: ServerPayloadSpec;
    seed?: Uint8Array;
}

const spec = (f: FrameSpec): ServerFrameSpec => ({
    sequence: f.sequence,
    sessionId: SESSION_ID,
    relatedRequestId: null,
    payload: f.payload,
});
const ended = (sequence: number): FrameSpec => ({
    sequence,
    payload: {
        case: 'roundEnded',
        roundId: ROUND_ID,
        actionIndex: 1,
        playerCommitment: new Uint8Array(32),
        cause: 'player-action',
        serverSeed: '00'.repeat(32),
    },
});

function receipts(frames: FrameSpec[], end: FrameSpec = ended(10), commands: ImportedCommand[] = []): ReceiptsInput {
    const document: ImportedReceipts = {
        tenantId: 'test-tenant',
        poolId: 'standard',
        sessionIdHex: SESSION_ID,
        roundIdHex: ROUND_ID,
        sequencerPublicKey: encodeEdpk(ed.getPublicKey(SIGNING_SEED)),
        sessionPublicKey: encodeEdpk(ed.getPublicKey(new Uint8Array(32).fill(2))),
        depositOperationLevel: null,
        locatorHints: null,
        source: 'client',
        commands,
        frames: [...frames, end].map((f) => ({
            sequence: BigInt(f.sequence),
            payloadCase: f.payload.case,
            relatedRequestId: null,
            frame: serverFrame(f.seed ?? SIGNING_SEED, spec(f)),
        })),
        roundEndedFrame: serverFrame(end.seed ?? SIGNING_SEED, spec(end)),
    };

    return { status: 'ok', receipts: document };
}

const accepted = (sequence: number, receivedAtUnixMs?: number, seed?: Uint8Array): FrameSpec => ({
    sequence,
    payload: { case: 'commandAccepted', ...(receivedAtUnixMs === undefined ? {} : { receivedAtUnixMs }) },
    seed,
});
const rejected = (sequence: number, receivedAtUnixMs: number): FrameSpec => ({
    sequence,
    payload: { case: 'commandRejected', reasonCode: 3, roundId: ROUND_ID, receivedAtUnixMs },
});

describe('signedRoundTime', () => {
    it('R1: the latest verified stamp before RoundEnded, accepted or rejected', () => {
        expect(signedRoundTime(receipts([accepted(2, 1_000), accepted(5, 3_000), accepted(4, 2_000)]), KEYS)).toEqual({
            lastMs: 3_000,
            source: 'CommandAccepted at sequence 5',
        });
        expect(signedRoundTime(receipts([accepted(2, 1_000), rejected(7, 4_000)]), KEYS)).toEqual({
            lastMs: 4_000,
            source: 'CommandRejected at sequence 7',
        });
    });

    it('R2: a frame that verifies under no registered key is ignored, and so is a forged RoundEnded', () => {
        expect(signedRoundTime(receipts([accepted(2, 1_000), accepted(5, 9_000, FOREIGN_SEED)]), KEYS)).toEqual({
            lastMs: 1_000,
            source: 'CommandAccepted at sequence 2',
        });
        expect(
            signedRoundTime(receipts([accepted(2, 1_000)], { ...ended(10), seed: FOREIGN_SEED }), KEYS),
        ).toHaveProperty('reason');
    });

    it('R3: stamps at or after RoundEnded do not count, nor a frame that states no stamp', () => {
        expect(
            signedRoundTime(
                receipts([accepted(2, 1_000), accepted(3), accepted(10, 8_000), accepted(11, 9_000)]),
                KEYS,
            ),
        ).toEqual({ lastMs: 1_000, source: 'CommandAccepted at sequence 2' });
        expect(signedRoundTime(receipts([accepted(11, 9_000)]), KEYS)).toHaveProperty('reason');
    });

    it('R4: no key set gives a reason', () => {
        expect(
            signedRoundTime(receipts([accepted(2, 1_000)]), { status: 'unavailable', reason: 'no lineage' }),
        ).toEqual({ reason: expect.stringContaining('no lineage') });
        expect(signedRoundTime(receipts([accepted(2, 1_000)]), { status: 'available', keys: [] })).toHaveProperty(
            'reason',
        );
    });

    it('R5: receipts that are not ok give a reason', () => {
        expect(signedRoundTime({ status: 'absent' }, KEYS)).toHaveProperty('reason');
        expect(signedRoundTime({ status: 'error', message: 'bad json' }, KEYS)).toHaveProperty('reason');
        expect(signedRoundTime(undefined, KEYS)).toHaveProperty('reason');
    });

    it('R6: the client clock (sentAtUnixMs) is never read', () => {
        const command = {
            requestId: '11111111-1111-4111-8111-111111111111',
            payloadCase: 'placeBet',
            frame: new Uint8Array(),
            sendCount: 1,
            get sentAtUnixMs(): number {
                throw new Error('sentAtUnixMs was read');
            },
        } as ImportedCommand;

        expect(signedRoundTime(receipts([accepted(2, 1_000)], ended(10), [command]), KEYS)).toEqual({
            lastMs: 1_000,
            source: 'CommandAccepted at sequence 2',
        });
    });
});
