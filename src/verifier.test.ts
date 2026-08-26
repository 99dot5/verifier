// @vitest-environment node
// End-to-end: encode a synthetic round as real wire frames (Borsh + genuine
// Ed25519 signatures over the blake2b pre-hash), then verify it. The round's
// maths comes from the first hilo round vector, so this also ties the
// orchestrator to the golden vectors.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { vectorsUrl } from './verify/vectors-path';
import * as ed from '@noble/ed25519';
import { blake2b } from '@noble/hashes/blake2.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';
import type { InboxMessage } from './chain/inbox';
import { verifyRound } from './verifier';
import { decimalStringToUnits, payoutUnits } from './verify/ints';
import { bytesToHex, hexToBytes, serverSeedCommitment } from './verify/seed';
import { decodeExternalMessage } from './wire/messages';

interface HiloRoundVector {
    server_seed: string;
    client_seed: string;
    stake: string;
    steps: { action_index: number; action: string }[];
    final: { outcome: string; cumulative_multiplier_ppm: number; payout: string };
}

const hiloVectors: { round_vectors: HiloRoundVector[] } = JSON.parse(
    readFileSync(
        fileURLToPath(vectorsUrl('hilo')),
        'utf8',
    ),
);

// ── Test-local Borsh writer + frame builder ─────────────────────────────

const SIGNING_SEED = new Uint8Array(32).fill(1);
const PUBLIC_KEY = ed.getPublicKey(SIGNING_SEED);

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

function byteVec(v: Uint8Array): number[] {
    return [...u32(v.length), ...Array.from(v)];
}

function uuid(hyphenated: string): number[] {
    return Array.from(hexToBytes(hyphenated.replaceAll('-', '')));
}

function frame(level: number, payloadBody: number[]): InboxMessage {
    // VersionedEnvelope::V1(PoolScopedMessage { tenant, pool, payload }).
    const payload = new Uint8Array([...u8(0), ...str('test-tenant'), ...str('standard'), ...payloadBody]);
    const signature = ed.sign(blake2b(payload, { dkLen: 32 }), SIGNING_SEED);
    const raw = new Uint8Array([0x09, 0x95, ...signature, ...payload]);
    const envelope = decodeExternalMessage(raw);

    if (!envelope) {
        throw new Error('test frame failed to decode');
    }

    return {
        level,
        operationHash: `op-level-${level}`,
        messageIndex: 0,
        rawHex: bytesToHex(raw),
        envelope,
    };
}

/** Base58check-encode 32 raw Ed25519 public key bytes as `edpk…`. */
function encodeEdpk(raw: Uint8Array): string {
    const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    const body = new Uint8Array([13, 15, 37, 217, ...raw]);
    const checksum = sha256(sha256(body)).slice(0, 4);
    let big = 0n;

    for (const byte of [...body, ...checksum]) {
        big = (big << 8n) | BigInt(byte);
    }

    let out = '';

    while (big > 0n) {
        out = ALPHABET[Number(big % 58n)] + out;
        big /= 58n;
    }

    return out;
}

// ── Build the synthetic round from the first hilo vector ────────────────

const ROUND_ID = '9a256790-c7c0-47b0-9a5b-6ed2905d2df1';
const SESSION_ID = 'e2b6419a-ec4b-4eef-bdfa-802b6f338fc2';
const SEED_INDEX = 137n;
const BATCH_START = 100n;

function buildRound(vector: HiloRoundVector, overrides?: { claimedPayoutUnits?: bigint; batchLevel?: number }) {
    const stakeUnits = decimalStringToUnits(vector.stake, 6);
    const seedHash = serverSeedCommitment(vector.server_seed);
    const hashes = Array.from({ length: 50 }, (_, i) =>
        i === Number(SEED_INDEX - BATCH_START) ? seedHash : new Uint8Array(32).fill(i),
    );
    const claimedPayout =
        overrides?.claimedPayoutUnits ??
        payoutUnits(stakeUnits, BigInt(vector.final.cumulative_multiplier_ppm));
    const claimedOutcome = vector.final.outcome === 'cashed-out' ? 'cashout' : 'lose';

    const messages: InboxMessage[] = [
        frame(overrides?.batchLevel ?? 1000, [
            ...u8(0x00), // SeedBatch
            ...u64(BATCH_START),
            ...u32(hashes.length),
            ...hashes.flatMap((h) => Array.from(h)),
            ...u64(4242n),
            ...str('52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971'),
        ]),
        frame(1005, [
            ...u8(0x01), // RoundCreated
            ...uuid(ROUND_ID),
            ...uuid(SESSION_ID),
            ...str('tz1TestPlayerAddress'),
            ...str('hilo:v1'),
            ...str('TEZ'),
            ...u128(stakeUnits),
            ...u32(6),
            ...str(vector.client_seed),
            ...u64(SEED_INDEX),
            ...Array.from(seedHash),
        ]),
        ...vector.steps.map((step, i) =>
            frame(1005 + i, [
                ...u8(0x02), // PlayerAction
                ...uuid(ROUND_ID),
                ...uuid(SESSION_ID),
                ...u64(BigInt(step.action_index)),
                ...str(step.action),
                ...byteVec(new Uint8Array()),
            ]),
        ),
        frame(1010, [
            ...u8(0x03), // RoundSettled
            ...uuid(ROUND_ID),
            ...uuid(SESSION_ID),
            ...str(vector.server_seed),
            ...str('TEZ'),
            ...u128(claimedPayout),
            ...u32(6),
            ...str(claimedOutcome),
        ]),
    ];

    return messages;
}

describe('verifyRound', () => {
    const vector = hiloVectors.round_vectors[0];

    it('verifies an honest round end to end (signatures, commitment, replay)', () => {
        const report = verifyRound({
            roundId: ROUND_ID,
            tenantId: 'test-tenant',
            messages: buildRound(vector),
            sequencerPublicKey: encodeEdpk(PUBLIC_KEY),
        });

        expect(report.verdict).toBe('verified');
        expect(report.checks.every((c) => c.status === 'pass')).toBe(true);
        expect(report.replay?.cumulativePpm).toBe(BigInt(vector.final.cumulative_multiplier_ppm));
    });

    it('tolerates at-least-once duplicate frames (observed live on shadownet)', () => {
        const messages = buildRound(vector);
        const duplicates = messages.map((m) => ({ ...m, level: m.level + 1 }));
        const report = verifyRound({
            roundId: ROUND_ID,
            tenantId: 'test-tenant',
            messages: [...duplicates, ...messages],
            sequencerPublicKey: encodeEdpk(PUBLIC_KEY),
        });

        expect(report.verdict).toBe('verified');
    });

    it('fails when the claimed payout is inflated', () => {
        const stakeUnits = decimalStringToUnits(vector.stake, 6);
        const honest = payoutUnits(stakeUnits, BigInt(vector.final.cumulative_multiplier_ppm));
        const report = verifyRound({
            roundId: ROUND_ID,
            tenantId: 'test-tenant',
            messages: buildRound(vector, { claimedPayoutUnits: honest + 1n }),
            sequencerPublicKey: encodeEdpk(PUBLIC_KEY),
        });

        expect(report.verdict).toBe('failed');
        expect(report.checks.find((c) => c.id === 'replay-payout')?.status).toBe('fail');
    });

    it('fails when the seed commitment does not strictly precede the round', () => {
        const report = verifyRound({
            roundId: ROUND_ID,
            tenantId: 'test-tenant',
            messages: buildRound(vector, { batchLevel: 1005 }),
            sequencerPublicKey: encodeEdpk(PUBLIC_KEY),
        });

        expect(report.verdict).toBe('failed');
        expect(report.checks.find((c) => c.id === 'commitment-order')?.status).toBe('fail');
    });

    it('reports signature failure under the wrong key', () => {
        const report = verifyRound({
            roundId: ROUND_ID,
            tenantId: 'test-tenant',
            messages: buildRound(vector),
            sequencerPublicKey: encodeEdpk(new Uint8Array(32).fill(7)),
        });

        expect(report.checks.find((c) => c.id === 'signatures')?.status).toBe('fail');
    });

    it('is incomplete, never verified, without a sequencer key (permissionless inbox)', () => {
        const report = verifyRound({
            roundId: ROUND_ID,
            tenantId: 'test-tenant',
            messages: buildRound(vector),
            sequencerPublicKey: null,
        });

        expect(report.verdict).toBe('incomplete');
        expect(report.checks.find((c) => c.id === 'signatures')?.status).toBe('unavailable');
    });

    it('is incomplete, never verified, when the seed batch is missing', () => {
        const messages = buildRound(vector).filter((m) => m.envelope.message.kind !== 'seed-batch');
        const report = verifyRound({
            roundId: ROUND_ID,
            tenantId: 'test-tenant',
            messages,
            sequencerPublicKey: encodeEdpk(PUBLIC_KEY),
        });

        expect(report.verdict).toBe('incomplete');
        expect(report.checks.find((c) => c.id === 'commitment-hash')?.status).toBe('unavailable');
    });
});
