// @vitest-environment node
/**
 * The receipts half: the commitment rule against the cross-language vectors,
 * the protobuf reader against frames this suite builds, the import's shape
 * validation, and the ported reconstruction against every §5.3 outcome.
 *
 * The commitment and signing vectors are the pins that matter most. They are
 * written by `libs/proto-definitions/scripts/gen_receipt_vectors.py` and
 * asserted by the sequencer's Rust tests and the play client's TypeScript
 * ones; this file is the third reader of the same bytes, so a drift between
 * any two implementations surfaces here instead of in a dispute.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as ed from '@noble/ed25519';
import { describe, expect, it } from 'vitest';
import { computeCommitment } from './commitment';
import { commandFrame, serverFrame, type ServerFrameSpec } from './fixtures';
import { importReceipts, RECEIPTS_SCHEMA, type ImportedFrame } from './import';
import { recomputeRoundCommitment } from './recompute';
import { receiptsExportFixtureUrl, receiptVectorsUrl } from './receipt-vectors-path';
import { bytesToHex, hexToBytes } from '../verify/seed';
import { decodeClientEnvelope, decodeServerEnvelope, ProtoError, uuidFromParts } from '../wire/proto-reader';
import { encodeUuid, ProtoWriter } from '../wire/proto-writer';
import {
    decodeEdpk,
    encodeEdpk,
    splitSignedFrame,
    verifyInboxSignature,
    verifyServerFrameSignature,
} from '../wire/signature';

interface ReceiptVectors {
    commitment: { name: string; frames_hex: string[]; expected_hex: string }[];
    receipt_domain: { ascii: string; hex: string };
    signing: {
        body_hex: string;
        domain_ascii: string;
        framed_hex: string;
        public_key_hex: string;
        seed_hex: string;
        signature_hex: string;
    };
}

const VECTORS = JSON.parse(readFileSync(fileURLToPath(receiptVectorsUrl()), 'utf8')) as ReceiptVectors;

const TENANT_SEED = new Uint8Array(32).fill(7);
const TENANT_PUBLIC_KEY = ed.getPublicKey(TENANT_SEED);
const SESSION_SEED = new Uint8Array(32).fill(8);
const SESSION_PUBLIC_KEY = ed.getPublicKey(SESSION_SEED);

const SESSION_ID = 'e2b6419a-ec4b-4eef-bdfa-802b6f338fc2';
const ROUND_ID = '9a256790-c7c0-47b0-9a5b-6ed2905d2df1';
const BET_REQUEST = '11111111-1111-4111-8111-111111111111';
const CASHOUT_REQUEST = '22222222-2222-4222-8222-222222222222';
const END_SESSION_REQUEST = '33333333-3333-4333-8333-333333333333';

describe('computeCommitment', () => {
    it.each(VECTORS.commitment.map((v) => [v.name, v] as const))('matches the %s vector', (_name, vector) => {
        const commitment = computeCommitment(vector.frames_hex.map((hex) => hexToBytes(hex)));

        expect(bytesToHex(commitment)).toBe(vector.expected_hex);
    });

    it('distinguishes the two concatenation-collision vectors', () => {
        // `["ab","c"]` and `["a","bc"]` concatenate to the same bytes. The
        // length prefixes are the whole reason they hash differently, and this
        // is the pair the vector file exists to pin.
        const a = VECTORS.commitment.find((v) => v.name === 'concat-collision-a');
        const b = VECTORS.commitment.find((v) => v.name === 'concat-collision-b');

        expect(a?.expected_hex).not.toBe(b?.expected_hex);
    });
});

describe('server frame signatures', () => {
    it('verifies the shared signing vector', () => {
        const split = splitSignedFrame(hexToBytes(VECTORS.signing.framed_hex));

        expect(split.tag).toBe(0x06);
        expect(bytesToHex(split.signature)).toBe(VECTORS.signing.signature_hex);
        expect(bytesToHex(split.body)).toBe(VECTORS.signing.body_hex);
        expect(
            verifyServerFrameSignature(split.signature, split.body, hexToBytes(VECTORS.signing.public_key_hex)),
        ).toBe(true);
    });

    it('rejects the same signature without the domain prefix', () => {
        // The domain is the ONLY thing separating a WS-frame signature from an
        // inbox-message signature over the same bytes under the same key. If
        // this ever passed, a signature harvested from one channel would be
        // presentable on the other.
        const split = splitSignedFrame(hexToBytes(VECTORS.signing.framed_hex));
        const publicKey = hexToBytes(VECTORS.signing.public_key_hex);

        expect(verifyServerFrameSignature(split.signature, split.body, publicKey)).toBe(true);
        expect(ed.verify(split.signature, split.body, publicKey)).toBe(false);
    });

    it('rejects a one-byte tamper of a frame this suite built', () => {
        const frame = serverFrame(TENANT_SEED, {
            sequence: 4,
            sessionId: SESSION_ID,
            relatedRequestId: BET_REQUEST,
            payload: { case: 'roundStarted', roundId: ROUND_ID },
        });
        const tampered = frame.slice();

        tampered[1] ^= 0x01;

        const split = splitSignedFrame(tampered);

        expect(verifyServerFrameSignature(split.signature, split.body, TENANT_PUBLIC_KEY)).toBe(false);
    });
});

describe('proto-reader', () => {
    it('decodes every field the receipt proofs read', () => {
        const commitment = new Uint8Array(32).fill(0xab);
        const frames: ServerFrameSpec[] = [
            { sequence: 2, sessionId: SESSION_ID, relatedRequestId: BET_REQUEST, payload: { case: 'commandAccepted' } },
            {
                sequence: 3,
                sessionId: SESSION_ID,
                relatedRequestId: BET_REQUEST,
                payload: { case: 'betPlaced', roundId: ROUND_ID },
            },
            {
                sequence: 4,
                sessionId: SESSION_ID,
                relatedRequestId: CASHOUT_REQUEST,
                payload: { case: 'roundUpdated', roundId: ROUND_ID, actionIndex: 1, origin: 'system' },
            },
            {
                sequence: 5,
                sessionId: SESSION_ID,
                relatedRequestId: CASHOUT_REQUEST,
                payload: { case: 'roundEnded', roundId: ROUND_ID, actionIndex: 2, playerCommitment: commitment },
            },
        ];
        const decoded = frames.map((spec) => decodeServerEnvelope(splitSignedFrame(serverFrame(TENANT_SEED, spec)).body));

        expect(decoded[0]).toMatchObject({
            sequence: 2n,
            relatedRequestId: BET_REQUEST,
            sessionId: SESSION_ID,
            payloadCase: 'commandAccepted',
            roundId: null,
        });
        expect(decoded[1]).toMatchObject({ payloadCase: 'betPlaced', roundId: ROUND_ID, actionIndex: null });
        expect(decoded[2]).toMatchObject({ payloadCase: 'roundUpdated', actionIndex: 1, origin: 'system' });
        expect(decoded[3]).toMatchObject({ payloadCase: 'roundEnded', actionIndex: 2 });
        expect(bytesToHex(decoded[3].playerCommitment as Uint8Array)).toBe(bytesToHex(commitment));
    });

    it('refuses a UUID field that arrives with the wrong wire type', () => {
        // A varint where a sub-message belongs used to decode to the all-zero
        // UUID — a plausible-looking session or request id invented out of a
        // malformed frame. Both fields are guarded; `session_id` is the one
        // the suppression ladder reads.
        const relatedAsVarint = new ProtoWriter().varint(2, 7).bytes(3, encodeUuid(SESSION_ID)).finish();
        const sessionAsVarint = new ProtoWriter().bytes(2, encodeUuid(BET_REQUEST)).varint(3, 7).finish();

        expect(() => decodeServerEnvelope(relatedAsVarint)).toThrow(ProtoError);
        expect(() => decodeServerEnvelope(sessionAsVarint)).toThrow(ProtoError);
    });

    it('reads an omitted origin as unspecified, the pre-field shape', () => {
        const frame = serverFrame(TENANT_SEED, {
            sequence: 4,
            sessionId: SESSION_ID,
            relatedRequestId: CASHOUT_REQUEST,
            payload: { case: 'roundUpdated', roundId: ROUND_ID, actionIndex: 1, origin: 'unspecified' },
        });

        expect(decodeServerEnvelope(splitSignedFrame(frame).body).origin).toBe('unspecified');
    });

    it('decodes a command envelope', () => {
        const frame = commandFrame(SESSION_SEED, {
            requestId: BET_REQUEST,
            sessionId: SESSION_ID,
            payloadCase: 'placeBet',
        });

        expect(decodeClientEnvelope(splitSignedFrame(frame).body)).toEqual({
            requestId: BET_REQUEST,
            sessionId: SESSION_ID,
            payloadCase: 'placeBet',
            placeBetClientSeed: null,
        });
    });

    it("reads a PlaceBet's client seed as the raw bytes on the wire", () => {
        const frame = commandFrame(SESSION_SEED, {
            requestId: BET_REQUEST,
            sessionId: SESSION_ID,
            payloadCase: 'placeBet',
            clientSeed: 'zürich 🎲',
        });
        const decoded = decodeClientEnvelope(splitSignedFrame(frame).body);

        expect(decoded.placeBetClientSeed).toEqual(new TextEncoder().encode('zürich 🎲'));
    });

    it('reads no client seed off a command that is not a PlaceBet', () => {
        const frame = commandFrame(SESSION_SEED, {
            requestId: CASHOUT_REQUEST,
            sessionId: SESSION_ID,
            payloadCase: 'cashOut',
            clientSeed: 'ignored',
        });

        expect(decodeClientEnvelope(splitSignedFrame(frame).body).placeBetClientSeed).toBeNull();
    });

    it('formats a UUID the way the play client keys its records', () => {
        expect(uuidFromParts(0x9a256790c7c047b0n, 0x9a5b6ed2905d2df1n)).toBe(ROUND_ID);
    });
});

describe('importReceipts', () => {
    const document = () => ({
        schema: RECEIPTS_SCHEMA,
        tenantId: 'test-tenant',
        poolId: 'standard',
        sessionIdHex: SESSION_ID,
        roundIdHex: ROUND_ID,
        sequencerPublicKey: encodeEdpk(TENANT_PUBLIC_KEY),
        sessionPublicKey: encodeEdpk(SESSION_PUBLIC_KEY),
        depositOperationLevel: 1000,
        commands: [
            {
                requestId: BET_REQUEST,
                payloadCase: 'placeBet',
                frameHex: bytesToHex(
                    commandFrame(SESSION_SEED, {
                        requestId: BET_REQUEST,
                        sessionId: SESSION_ID,
                        payloadCase: 'placeBet',
                    }),
                ),
                sentAtUnixMs: 1,
            },
        ],
        frames: [
            {
                sequence: '2',
                payloadCase: 'commandAccepted',
                relatedRequestId: BET_REQUEST,
                frameHex: bytesToHex(
                    serverFrame(TENANT_SEED, {
                        sequence: 2,
                        sessionId: SESSION_ID,
                        relatedRequestId: BET_REQUEST,
                        payload: { case: 'commandAccepted' },
                    }),
                ),
            },
        ],
        roundEndedFrameHex: bytesToHex(
            serverFrame(TENANT_SEED, {
                sequence: 3,
                sessionId: SESSION_ID,
                relatedRequestId: BET_REQUEST,
                payload: { case: 'roundEnded', roundId: ROUND_ID, actionIndex: 0 },
            }),
        ),
    });

    it('reads a well-formed document', () => {
        const result = importReceipts(JSON.stringify(document()));

        expect(result.status).toBe('ok');

        if (result.status !== 'ok') {
            return;
        }

        expect(result.receipts.frames[0].sequence).toBe(2n);
        expect(result.receipts.depositOperationLevel).toBe(1000);
        expect(result.receipts.commands).toHaveLength(1);
    });

    it('rejects text that is not JSON', () => {
        const result = importReceipts('{not json');

        expect(result.status).toBe('error');
        expect(result.status === 'error' && result.message).toMatch(/not valid JSON/);
    });

    it('rejects an unknown schema rather than guessing at the fields', () => {
        const result = importReceipts(JSON.stringify({ ...document(), schema: '99dot5.receipts.v2' }));

        expect(result.status === 'error' && result.message).toMatch(/unsupported schema/);
    });

    it('rejects a malformed hex frame, naming the field', () => {
        const broken = document();

        broken.frames[0].frameHex = 'not-hex';

        expect(importReceipts(JSON.stringify(broken))).toEqual({
            status: 'error',
            message: 'frames[0].frameHex: expected a non-empty even-length hex string',
        });
    });

    it('rejects a missing required field rather than defaulting it', () => {
        const broken = document() as Record<string, unknown>;

        delete broken.sessionPublicKey;

        expect(importReceipts(JSON.stringify(broken))).toEqual({
            status: 'error',
            message: 'sessionPublicKey: expected a string, got undefined',
        });
    });
});

// ── The reconstruction ──────────────────────────────────────────────────

function importedFrame(spec: ServerFrameSpec, label?: Partial<ImportedFrame>): ImportedFrame {
    return {
        sequence: BigInt(spec.sequence),
        payloadCase: spec.payload.case,
        relatedRequestId: spec.relatedRequestId,
        frame: serverFrame(TENANT_SEED, spec),
        ...label,
    };
}

function command(requestId: string, payloadCase: 'placeBet' | 'cashOut' | 'playerAction' | 'endSession', at: number) {
    return {
        requestId,
        payloadCase,
        frame: commandFrame(SESSION_SEED, { requestId, sessionId: SESSION_ID, payloadCase }),
        sentAtUnixMs: at,
    };
}

/** The happy round: a bet at index 0, a cashout at index 1, both accepted. */
function honestRound() {
    return {
        roundIdHex: ROUND_ID,
        commands: [command(BET_REQUEST, 'placeBet', 1), command(CASHOUT_REQUEST, 'cashOut', 2)],
        frames: [
            importedFrame({
                sequence: 2,
                sessionId: SESSION_ID,
                relatedRequestId: BET_REQUEST,
                payload: { case: 'commandAccepted' },
            }),
            importedFrame({
                sequence: 3,
                sessionId: SESSION_ID,
                relatedRequestId: BET_REQUEST,
                payload: { case: 'roundStarted', roundId: ROUND_ID },
            }),
            importedFrame({
                sequence: 4,
                sessionId: SESSION_ID,
                relatedRequestId: CASHOUT_REQUEST,
                payload: { case: 'commandAccepted' },
            }),
            importedFrame({
                sequence: 5,
                sessionId: SESSION_ID,
                relatedRequestId: CASHOUT_REQUEST,
                payload: { case: 'roundEnded', roundId: ROUND_ID, actionIndex: 1 },
            }),
        ],
    };
}

describe('recomputeRoundCommitment', () => {
    it('reproduces the commitment over the ordered command frames', () => {
        const round = honestRound();
        const result = recomputeRoundCommitment(round);

        expect(result.status).toBe('ok');

        if (result.status !== 'ok') {
            return;
        }

        expect(result.orderedRequestIds).toEqual([BET_REQUEST, CASHOUT_REQUEST]);
        expect(bytesToHex(result.commitment)).toBe(
            bytesToHex(computeCommitment([round.commands[0].frame, round.commands[1].frame])),
        );
    });

    it('orders by the server index, not by send order', () => {
        const round = honestRound();

        // The cashout was SENT first (a peer tab raced), but the server placed
        // it second. The preimage follows the server.
        round.commands = [command(CASHOUT_REQUEST, 'cashOut', 1), command(BET_REQUEST, 'placeBet', 2)];

        const result = recomputeRoundCommitment(round);

        expect(result.status === 'ok' && result.orderedRequestIds).toEqual([BET_REQUEST, CASHOUT_REQUEST]);
    });

    it('ignores a retry of the same request id', () => {
        const round = honestRound();
        const first = round.commands[0];

        round.commands = [{ ...first, sentAtUnixMs: 9 }, first, round.commands[1]];

        const result = recomputeRoundCommitment(round);

        expect(result.status === 'ok' && result.orderedRequestIds).toEqual([BET_REQUEST, CASHOUT_REQUEST]);
    });

    it('leaves an EndSession command out of scope instead of calling the round ambiguous', () => {
        const round = honestRound();

        round.commands.push(command(END_SESSION_REQUEST, 'endSession', 3));
        round.frames.push(
            importedFrame({
                sequence: 6,
                sessionId: SESSION_ID,
                relatedRequestId: END_SESSION_REQUEST,
                payload: { case: 'commandAccepted' },
            }),
        );

        expect(recomputeRoundCommitment(round).status).toBe('ok');
    });

    it('reads an omitted RoundUpdated action_index as 0, the way protobuf-es does', () => {
        // `RoundUpdatedEvent.action_index` is a proto3 IMPLICIT-presence
        // `int32`, so index 0 is absent from the wire and the play client (via
        // protobuf-es) reads it back as 0. A port that read "no index" would
        // answer `accepted-command-without-index` and degrade an honest round
        // the day a game reports step 0 as an update.
        const round = honestRound();

        round.frames = [
            round.frames[0],
            importedFrame({
                sequence: 3,
                sessionId: SESSION_ID,
                relatedRequestId: BET_REQUEST,
                payload: { case: 'roundUpdated', roundId: ROUND_ID, actionIndex: 0 },
            }),
            round.frames[2],
            round.frames[3],
        ];

        // The index WAS read (as 0), so this is not
        // `accepted-command-without-index`. What this export actually lacks is
        // the opening BetPlaced/RoundStarted that says which command is the bet.
        expect(recomputeRoundCommitment(round)).toEqual({ status: 'unavailable', reason: 'no-place-bet' });
    });

    it('counts a SYSTEM step as a position and not as a command', () => {
        // The max-win de-lever: a `partial-cashout` the sequencer wrote itself,
        // riding the triggering command's related_request_id. Before
        // `RoundUpdatedEvent.origin` existed this was `conflicting-index`.
        const round = honestRound();

        round.frames.splice(
            3,
            0,
            importedFrame({
                sequence: 4,
                sessionId: SESSION_ID,
                relatedRequestId: CASHOUT_REQUEST,
                payload: { case: 'roundUpdated', roundId: ROUND_ID, actionIndex: 1, origin: 'system' },
            }),
        );
        // The player's cashout moves to index 2, behind the system step.
        round.frames[round.frames.length - 1] = importedFrame({
            sequence: 6,
            sessionId: SESSION_ID,
            relatedRequestId: CASHOUT_REQUEST,
            payload: { case: 'roundEnded', roundId: ROUND_ID, actionIndex: 2 },
        });

        const result = recomputeRoundCommitment(round);

        expect(result.status).toBe('ok');
        expect(result.status === 'ok' && result.orderedRequestIds).toEqual([BET_REQUEST, CASHOUT_REQUEST]);
    });

    it('declines when an unmarked second index cannot be told from a conflict', () => {
        const round = honestRound();

        round.frames.splice(
            3,
            0,
            importedFrame({
                sequence: 4,
                sessionId: SESSION_ID,
                relatedRequestId: CASHOUT_REQUEST,
                payload: { case: 'roundUpdated', roundId: ROUND_ID, actionIndex: 1, origin: 'unspecified' },
            }),
        );
        round.frames[round.frames.length - 1] = importedFrame({
            sequence: 6,
            sessionId: SESSION_ID,
            relatedRequestId: CASHOUT_REQUEST,
            payload: { case: 'roundEnded', roundId: ROUND_ID, actionIndex: 2 },
        });

        expect(recomputeRoundCommitment(round)).toEqual({ status: 'unavailable', reason: 'conflicting-index' });
    });

    it('declines when the server placed a command this export does not carry', () => {
        const round = honestRound();

        round.commands = [round.commands[0]];

        expect(recomputeRoundCommitment(round)).toEqual({
            status: 'unavailable',
            reason: 'server-index-without-command',
        });
    });

    it('declines when no frame opens the round', () => {
        const round = honestRound();

        round.frames = round.frames.filter((frame) => frame.payloadCase !== 'roundStarted');

        expect(recomputeRoundCommitment(round)).toEqual({ status: 'unavailable', reason: 'no-place-bet' });
    });

    it('declines on a RoundEnded with no action index', () => {
        const round = honestRound();

        round.frames[3] = importedFrame({
            sequence: 5,
            sessionId: SESSION_ID,
            relatedRequestId: CASHOUT_REQUEST,
            payload: { case: 'roundEnded', roundId: ROUND_ID },
        });

        expect(recomputeRoundCommitment(round)).toEqual({
            status: 'unavailable',
            reason: 'round-ended-without-index',
        });
    });

    it('never infers acceptance from a missing rejection', () => {
        const round = honestRound();

        // Drop the cashout's CommandAccepted. The server still placed it at
        // index 1, so the round is ambiguous rather than a two-command round.
        round.frames = round.frames.filter(
            (frame) => !(frame.payloadCase === 'commandAccepted' && frame.relatedRequestId === CASHOUT_REQUEST),
        );

        expect(recomputeRoundCommitment(round)).toEqual({
            status: 'unavailable',
            reason: 'server-index-without-command',
        });
    });

    it('declines on a frame that is not a server frame', () => {
        const round = honestRound();

        round.frames[0] = { ...round.frames[0], frame: new Uint8Array([0x05, ...new Uint8Array(70)]) };

        expect(recomputeRoundCommitment(round)).toEqual({ status: 'unavailable', reason: 'undecodable-frame' });
    });
});

// ── The cross-language export fixture ───────────────────────────────────

interface ExportFixture {
    schema: string;
    cases: {
        name: string;
        export: unknown;
        expected: {
            frames: {
                index: number;
                sequence: string;
                payloadCase: string;
                relatedRequestId: string | null;
                roundIdHex: string | null;
                actionIndex: number | null;
                origin: string | null;
                playerCommitmentHex: string | null;
            }[];
            commands: { requestId: string; payloadCase: string; sessionIdHex: string }[];
            recompute: { status: string; commitmentHex?: string; orderedRequestIds?: string[]; reason?: string };
        };
    }[];
}

const FIXTURE = JSON.parse(readFileSync(fileURLToPath(receiptsExportFixtureUrl()), 'utf8')) as ExportFixture;

/**
 * Whole export documents written by the PLAY CLIENT's own export path, with
 * the facts a verifier must read back out of them.
 *
 * This is the pin that matters most for the third proof: every other test in
 * this file builds its own frames, so it can only prove the verifier agrees
 * with itself. These documents come from the other side of the protocol, and
 * the reconstruction they expect is the one the play client computes — so the
 * two implementations of §5.3 are held to identical answers, including the
 * de-lever case where one of them says `unavailable` on purpose.
 */
describe('client seed in the export fixture', () => {
    // Frames the PLAY CLIENT encoded, not this suite: the seed decoder is held
    // to real protobuf-es output rather than to the fixtures it was written with.
    it('reads a client seed off every PlaceBet command', () => {
        let placeBets = 0;

        for (const testCase of FIXTURE.cases) {
            const imported = importReceipts(JSON.stringify(testCase.export));

            if (imported.status !== 'ok') {
                throw new Error(`${testCase.name}: ${imported.message}`);
            }

            for (const command of imported.receipts.commands.filter((c) => c.payloadCase === 'placeBet')) {
                const decoded = decodeClientEnvelope(splitSignedFrame(command.frame).body);

                expect(decoded.placeBetClientSeed, testCase.name).not.toBeNull();
                placeBets += 1;
            }
        }

        expect(placeBets).toBeGreaterThan(0);
    });

    it('reads the exact seed text the play client sent', () => {
        const hiloPlain = FIXTURE.cases.find((c) => c.name === 'hilo-plain');
        const imported = importReceipts(JSON.stringify(hiloPlain?.export));

        expect(imported.status).toBe('ok');

        if (imported.status !== 'ok') {
            return;
        }

        const placeBet = imported.receipts.commands.find((c) => c.payloadCase === 'placeBet');

        if (!placeBet) {
            throw new Error('hilo-plain carries no PlaceBet command');
        }

        const seed = decodeClientEnvelope(splitSignedFrame(placeBet.frame).body).placeBetClientSeed;

        expect(seed === null ? null : new TextDecoder().decode(seed)).toBe('fixture-client-seed');
    });
});

describe('receipts export fixture', () => {
    it('is the schema this build reads', () => {
        expect(FIXTURE.schema).toBe('99dot5.receipts-export-fixture.v1');
        expect(FIXTURE.cases.length).toBeGreaterThan(0);
    });

    it.each(FIXTURE.cases.map((c) => [c.name, c] as const))('%s', (_name, testCase) => {
        const imported = importReceipts(JSON.stringify(testCase.export));

        expect(imported.status).toBe('ok');

        if (imported.status !== 'ok') {
            return;
        }

        const receipts = imported.receipts;
        const tenantKey = decodeEdpk(receipts.sequencerPublicKey);
        const sessionKey = decodeEdpk(receipts.sessionPublicKey);

        // Every frame decodes to exactly the fields the other side says it
        // carries, and verifies under the key the document names.
        expect(receipts.frames).toHaveLength(testCase.expected.frames.length);

        for (const [index, expected] of testCase.expected.frames.entries()) {
            const split = splitSignedFrame(receipts.frames[index].frame);
            const decoded = decodeServerEnvelope(split.body);

            expect(split.tag).toBe(0x06);
            expect(verifyServerFrameSignature(split.signature, split.body, tenantKey)).toBe(true);
            expect(decoded.sequence.toString()).toBe(expected.sequence);
            expect(decoded.payloadCase).toBe(expected.payloadCase);
            expect(decoded.relatedRequestId).toBe(expected.relatedRequestId);
            expect(decoded.roundId).toBe(expected.roundIdHex);
            expect(decoded.actionIndex).toBe(expected.actionIndex);
            // The fixture writes `null` both for a frame class with no origin
            // field and for STEP_ORIGIN_UNSPECIFIED, because proto3 omits a
            // zero enum from the wire and the two are indistinguishable there.
            // This reader keeps them apart only by frame class, so an
            // `unspecified` on a RoundUpdated normalises to the fixture's null.
            expect(decoded.origin === 'unspecified' ? null : decoded.origin).toBe(expected.origin);
            expect(decoded.playerCommitment === null ? null : bytesToHex(decoded.playerCommitment)).toBe(
                expected.playerCommitmentHex,
            );
        }

        for (const [index, expected] of testCase.expected.commands.entries()) {
            const split = splitSignedFrame(receipts.commands[index].frame);

            expect(split.tag).toBe(0x05);
            // Commands are signed WITHOUT the receipt domain: the session key
            // signs one channel only.
            expect(verifyInboxSignature(split.signature, split.body, sessionKey)).toBe(true);
            // The seed a PlaceBet carries is pinned by the client-seed tests above.
            expect(decodeClientEnvelope(split.body)).toMatchObject({
                requestId: expected.requestId,
                sessionId: expected.sessionIdHex,
                payloadCase: expected.payloadCase,
            });
        }

        const result = recomputeRoundCommitment({
            roundIdHex: receipts.roundIdHex,
            commands: receipts.commands,
            frames: receipts.frames,
        });

        expect(result.status).toBe(testCase.expected.recompute.status);

        if (result.status === 'ok') {
            expect(bytesToHex(result.commitment)).toBe(testCase.expected.recompute.commitmentHex);
            expect(result.orderedRequestIds).toEqual(testCase.expected.recompute.orderedRequestIds);
        } else {
            expect(result.reason).toBe(testCase.expected.recompute.reason);
        }
    });
});
