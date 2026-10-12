// @vitest-environment node
/**
 * A receipts document the SEQUENCER built (`source: "sequencer"`), carried
 * end to end: the golden its history API serves for a pinned round imports,
 * reconstructs, matches a transcript on a synthetic inbox, and reads
 * `attested` — never `verified`, because which rows a server-built document
 * contains is the server's choice.
 *
 * The ceiling is ADVISORY and this file pins that too: the label is unsigned,
 * so the same golden with `source` stripped reads as browser-held and
 * verifies. Every frame in it really is server-signed; what the label carries
 * is only the completeness claim.
 *
 * The inbox half is built here, not read from a fixture: a `SeedBatch` and the
 * round's `RoundTranscript`, Borsh-encoded and signed under the same tenant
 * key the golden's frames verify under (seed `[0x42; 32]`), at the levels the
 * golden's locator hints name.
 */
import * as ed from '@noble/ed25519';
import { blake2b } from '@noble/hashes/blake2.js';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { bytesToHex, decodeExternalMessage, hexToBytes, hilo, serverSeedCommitment, tagOf } from '@99dot5/round-replay';
import type { DepositLocation } from '../chain/deposit';
import type { InboxMessage } from '../chain/inbox';
import { SERVER_BUILT_SUPPRESSION_FINDING, verifyRound, type ReceiptsInput, type ScanContext } from '../verifier';
import { decodeClientEnvelope, decodeServerEnvelope } from '../wire/proto-reader';
import { encodeEdpk, sequencerSigningPreimage, splitSignedFrame, type SigningDomain } from '../wire/signature';
import { computeCommitment } from './commitment';
import { importReceipts } from './import';
import { receiptsExportServerFixtureUrl } from './receipt-vectors-path';
import { decodeReceiptFrame, recomputeRoundCommitment } from './recompute';

interface ServerFixture {
    schema: string;
    export: Record<string, unknown> & {
        tenantId: string;
        poolId: string;
        sessionIdHex: string;
        roundIdHex: string;
        sequencerPublicKey: string;
        commands: { payloadCase: string; frameHex: string }[];
        roundEndedFrameHex: string;
        locatorHints: { transcript: { level: number }; seedBatch: { level: number } };
    };
}

const FIXTURE = JSON.parse(readFileSync(fileURLToPath(receiptsExportServerFixtureUrl()), 'utf8')) as ServerFixture;
const GOLDEN = FIXTURE.export;

/** The golden as text, optionally edited — `importReceipts` reads text. */
function goldenText(edit?: (document: Record<string, unknown>) => void): string {
    const document = structuredClone(GOLDEN) as Record<string, unknown>;

    edit?.(document);

    return JSON.stringify(document);
}

// ── The round the golden pins ───────────────────────────────────────────
//
// Named by the golden's own comment: tenant key seed [0x42; 32], server seed
// [0x5d; 32] committed at index 137, client seed text "fixture-client-seed",
// a 1 TEZ hilo:v1 bet, `higher` (wins), cashout.

const TENANT_SEED = new Uint8Array(32).fill(0x42);
const TENANT_PUBLIC_KEY = ed.getPublicKey(TENANT_SEED);
const SERVER_SEED = new Uint8Array(32).fill(0x5d);
const CLIENT_SEED = blake2b(new TextEncoder().encode('fixture-client-seed'), { dkLen: 32 });
const SEED_INDEX = 137n;
const BATCH_START = 100n;
const STAKE_UNITS = 1_000_000n;
const BATCH_LEVEL = GOLDEN.locatorHints.seedBatch.level;
const TRANSCRIPT_LEVEL = GOLDEN.locatorHints.transcript.level;
const ACTIONS = ['place-bet', 'higher', 'cashout'] as const;

/** The signing domain every inbox frame here is signed for. */
const DOMAIN: SigningDomain = { chainId: 'NetXsqzbfFenSTS', rollupAddress: 'sr1TMxAUtDA4sDL7C4r39L18iQjhRcBRzd8a' };

// ── A test-local Borsh writer, the same shapes the inbox decoder reads ──

function u8(v: number): number[] {
    return [v];
}

function u32(v: number): number[] {
    return [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff];
}

function u64(v: bigint): number[] {
    return Array.from({ length: 8 }, (_, i) => Number((v >> BigInt(8 * i)) & 0xffn));
}

function u128(v: bigint): number[] {
    return Array.from({ length: 16 }, (_, i) => Number((v >> BigInt(8 * i)) & 0xffn));
}

function str(v: string): number[] {
    const bytes = Array.from(new TextEncoder().encode(v));

    return [...u32(bytes.length), ...bytes];
}

function uuid(hyphenated: string): number[] {
    return Array.from(hexToBytes(hyphenated.replaceAll('-', '')));
}

/** One signed external inbox message of the golden's tenant and pool. */
function frame(level: number, payloadBody: number[]): InboxMessage {
    const payload = new Uint8Array([...u8(0), ...str(GOLDEN.tenantId), ...str(GOLDEN.poolId), ...payloadBody]);
    const signature = ed.sign(blake2b(sequencerSigningPreimage(DOMAIN, payload), { dkLen: 32 }), TENANT_SEED);
    const raw = new Uint8Array([0x09, 0x95, ...signature, ...payload]);
    const envelope = decodeExternalMessage(raw);

    if (!envelope) {
        throw new Error('test frame failed to decode');
    }

    return { level, operationHash: `op-level-${level}`, messageIndex: 0, rawHex: bytesToHex(raw), envelope };
}

function seedBatch(): InboxMessage {
    const committed = serverSeedCommitment(bytesToHex(SERVER_SEED));
    const hashes = Array.from({ length: 50 }, (_, i) =>
        i === Number(SEED_INDEX - BATCH_START) ? committed : new Uint8Array(32).fill(i),
    );

    return frame(BATCH_LEVEL, [
        ...u8(0x00), // SequencerMessage::SeedBatch
        ...u64(BATCH_START),
        ...u32(hashes.length),
        ...hashes.flatMap((h) => Array.from(h)),
        ...u64(4242n),
        ...hexToBytes('52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971'),
    ]);
}

/** The payout an honest sequencer claims: the replayer's, never a literal. */
function honestPayout(): bigint {
    return hilo.v1.replay(
        bytesToHex(SERVER_SEED),
        bytesToHex(CLIENT_SEED),
        ACTIONS.map((actionType, actionIndex) => ({ actionIndex, actionType, payload: new Uint8Array() })),
        STAKE_UNITS,
    ).payoutUnits;
}

function transcript(): InboxMessage {
    const commitment = computeCommitment(GOLDEN.commands.map((c) => hexToBytes(c.frameHex)));

    return frame(TRANSCRIPT_LEVEL, [
        ...u8(0x01), // SequencerMessage::RoundTranscript
        ...uuid(GOLDEN.roundIdHex),
        ...uuid(GOLDEN.sessionIdHex),
        ...str(hilo.v1.GAME_TYPE),
        ...u128(STAKE_UNITS),
        ...Array.from(CLIENT_SEED),
        ...Array.from(SERVER_SEED),
        ...u64(SEED_INDEX),
        ...u128(honestPayout()),
        ...Array.from(commitment),
        ...u32(ACTIONS.length),
        ...ACTIONS.flatMap((actionType) => [...u8(tagOf(actionType)!), ...u32(0)]),
    ]);
}

function endSession(level: number): InboxMessage {
    return frame(level, [
        ...u8(0x02), // SequencerMessage::EndSession
        ...uuid(GOLDEN.sessionIdHex),
        ...u8(0), // EndReason::UserRequested
    ]);
}

/** The session's first deposit, found on L1 below everything else here. */
const DEPOSIT_LEVEL = BATCH_LEVEL - 10;
const DEPOSIT: DepositLocation = {
    lookup: 'found',
    level: DEPOSIT_LEVEL,
    operationHash: 'op-deposit',
    vault: 'KT1TestVault',
    firstProven: true,
    otherVaults: null,
    detail: 'first deposit found by the fixture',
};
const BRACKETING_SCAN: ScanContext = {
    fromLevel: DEPOSIT_LEVEL - 10,
    toLevel: TRANSCRIPT_LEVEL + 50,
    headLevel: TRANSCRIPT_LEVEL + 50,
    deposit: { level: DEPOSIT_LEVEL, confirmed: true },
};

function imported(text: string): ReceiptsInput {
    const result = importReceipts(text);

    if (result.status !== 'ok') {
        throw new Error(`the golden did not import: ${result.message}`);
    }

    return { status: 'ok', receipts: result.receipts };
}

function verify(receipts: ReceiptsInput, messages: InboxMessage[] = [seedBatch(), transcript()]) {
    return verifyRound({
        signingDomain: DOMAIN,
        deploymentListed: true,
        receipts,
        scan: BRACKETING_SCAN,
        sessionDeposit: DEPOSIT,
        roundId: GOLDEN.roundIdHex,
        tenantId: GOLDEN.tenantId,
        messages,
        // The lineage stub: the one tenant key, as a walk of the
        // administrator contract would derive it.
        keys: {
            status: 'available',
            keys: [
                {
                    edpk: encodeEdpk(TENANT_PUBLIC_KEY),
                    registration: {
                        level: 1,
                        operationHash: 'op-register-tenant',
                        source: 'register-tenant',
                        administrator: 'KT1TestAdministrator',
                    },
                },
            ],
        },
    });
}

/** Every check a `verified` needs; the cap must be the ONLY thing between them and it. */
const PASSING_CHECKS = [
    'signatures',
    'commitment-hash',
    'commitment-order',
    'replay-payout',
    'receipt-frames-signed',
    'commitment-vs-chain',
    'commitment-vs-receipt',
    'receipt-vs-chain',
];

describe('a sequencer-built receipts document', () => {
    it('is the wrapper the sequencer writes, around a document labelled source "sequencer"', () => {
        expect(FIXTURE.schema).toBe('99dot5.receipts-export-server-fixture.v1');
        expect(GOLDEN.source).toBe('sequencer');
        expect(GOLDEN.sequencerPublicKey).toBe(encodeEdpk(TENANT_PUBLIC_KEY));
        expect(GOLDEN).not.toHaveProperty('depositOperationLevel');
    });

    it('commits to the seed this suite reveals, in both the opener and the player-signed echo', () => {
        const committed = bytesToHex(serverSeedCommitment(bytesToHex(SERVER_SEED)));
        const frames = (GOLDEN.frames as { frameHex: string }[]).map((f) =>
            decodeServerEnvelope(splitSignedFrame(hexToBytes(f.frameHex)).body),
        );
        const opener = frames.find((f) => f.payloadCase === 'roundStarted' && f.roundId === GOLDEN.roundIdHex);
        const bet = GOLDEN.commands.find((c) => c.payloadCase === 'placeBet')!;

        expect(opener?.roundStartedServerSeedCommitment?.index).toBe(SEED_INDEX);
        expect(bytesToHex(opener!.roundStartedServerSeedCommitment!.hash)).toBe(committed);
        expect(
            bytesToHex(decodeClientEnvelope(splitSignedFrame(hexToBytes(bet.frameHex)).body).placeBetServerSeedHash!),
        ).toBe(committed);
    });

    it('imports as source "sequencer" and reconstructs the commitment its RoundEnded signed', () => {
        const result = importReceipts(goldenText());

        expect(result.status).toBe('ok');

        if (result.status !== 'ok') {
            return;
        }

        expect(result.receipts.source).toBe('sequencer');
        expect(result.findings).toEqual([]);

        const recomputed = recomputeRoundCommitment({
            roundIdHex: GOLDEN.roundIdHex,
            commands: result.receipts.commands,
            frames: result.receipts.frames,
        });
        const ended = decodeReceiptFrame({
            sequence: 0n,
            payloadCase: 'roundEnded',
            relatedRequestId: null,
            frame: result.receipts.roundEndedFrame,
        });

        expect(recomputed.status).toBe('ok');
        expect(recomputed.status === 'ok' && bytesToHex(recomputed.commitment)).toBe(
            bytesToHex(ended.envelope.playerCommitment!),
        );
    });

    it('reads ATTESTED, never VERIFIED, with every proof passing', () => {
        const report = verify(imported(goldenText()));

        expect(report.verdict).toBe('attested');

        for (const id of PASSING_CHECKS) {
            expect(report.checks.find((c) => c.id === id)?.status, id).toBe('pass');
        }

        // Nothing failed and nothing was missing: the cap is the only reason.
        expect(report.checks.filter((c) => c.status !== 'pass')).toEqual([]);
        expect(report.findings.join('\n')).toContain('Verdict capped at ATTESTED');
        expect(report.findings).toContain(SERVER_BUILT_SUPPRESSION_FINDING);
    });

    it('reads VERIFIED once the unsigned label is stripped — the ceiling is advisory', () => {
        const report = verify(imported(goldenText((document) => delete document.source)));

        expect(report.verdict).toBe('verified');
        expect(report.findings.join('\n')).not.toContain('Verdict capped at ATTESTED');
        expect(report.findings).not.toContain(SERVER_BUILT_SUPPRESSION_FINDING);
    });

    it('is REFUSED under an unknown source, not read as browser-held', () => {
        const result = importReceipts(goldenText((document) => (document.source = 'relay')));

        expect(result.status).toBe('error');
        expect(result.status === 'error' && result.message).toMatch(/^source: unknown provenance "relay"/);
    });

    it('never reaches SUPPRESSED, where the same receipts unlabelled would', () => {
        const withoutTranscript = [seedBatch(), endSession(TRANSCRIPT_LEVEL + 2)];
        const serverBuilt = verify(imported(goldenText()), withoutTranscript);
        const unlabelled = verify(imported(goldenText((document) => delete document.source)), withoutTranscript);

        expect(unlabelled.verdict).toBe('suppressed');
        expect(serverBuilt.verdict).toBe('undetermined');
        expect(serverBuilt.findings.join('\n')).toContain('Not escalated to SUPPRESSED');
    });
});
