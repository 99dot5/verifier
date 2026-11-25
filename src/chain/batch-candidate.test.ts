// @vitest-environment node
// The SeedBatch candidate rule of the located run: the rule of
// `confirmHints`' batch branch, applied to one block the node served.
import * as ed from '@noble/ed25519';
import { blake2b } from '@noble/hashes/blake2.js';
import { describe, expect, it } from 'vitest';
import { bytesToHex, decodeExternalMessage } from '@99dot5/round-replay';
import type { KeySet } from '../verifier';
import { encodeEdpk, sequencerSigningPreimage, type SigningDomain } from '../wire/signature';
import { type BatchCandidateQuery, confirmBatchCandidate } from './batch-candidate';
import type { InboxMessage } from './inbox';

const SIGNING_SEED = new Uint8Array(32).fill(1);
const FOREIGN_SEED = new Uint8Array(32).fill(9);
const DOMAIN: SigningDomain = { chainId: 'NetXsqzbfFenSTS', rollupAddress: 'sr1TMxAUtDA4sDL7C4r39L18iQjhRcBRzd8a' };
const LEVEL = 6_027_994;

const u32 = (v: number) => [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff];
const u64 = (v: bigint) => Array.from({ length: 8 }, (_, i) => Number((v >> BigInt(8 * i)) & 0xffn));

function str(v: string): number[] {
    const bytes = Array.from(new TextEncoder().encode(v));

    return [...u32(bytes.length), ...bytes];
}

interface BatchSpec {
    tenant?: string;
    pool?: string;
    start: bigint;
    seed?: Uint8Array;
    index?: number;
}

/** A signed 50-index SeedBatch starting at `start`, as the node would serve it. */
function batch(spec: BatchSpec): InboxMessage {
    const hashes = Array.from({ length: 50 }, (_, i) => new Uint8Array(32).fill(i));
    const payload = new Uint8Array([
        0,
        ...str(spec.tenant ?? 'test-tenant'),
        ...str(spec.pool ?? 'standard'),
        0x00,
        ...u64(spec.start),
        ...u32(hashes.length),
        ...hashes.flatMap((h) => Array.from(h)),
        ...u64(4242n),
        ...new Array<number>(32).fill(7),
    ]);
    const signature = ed.sign(
        blake2b(sequencerSigningPreimage(DOMAIN, payload), { dkLen: 32 }),
        spec.seed ?? SIGNING_SEED,
    );
    const raw = new Uint8Array([0x09, 0x95, ...signature, ...payload]);
    const envelope = decodeExternalMessage(raw);

    if (!envelope) {
        throw new Error('test batch failed to decode');
    }

    return {
        level: LEVEL,
        operationHash: 'op-batch',
        messageIndex: spec.index ?? 0,
        rawHex: bytesToHex(raw),
        envelope,
    };
}

const KEYS: KeySet = {
    status: 'available',
    keys: [{ edpk: encodeEdpk(ed.getPublicKey(SIGNING_SEED)), registration: null }],
};
const query = (seedIndex: bigint, overrides: Partial<BatchCandidateQuery> = {}): BatchCandidateQuery => ({
    tenantId: 'test-tenant',
    poolId: 'standard',
    seedIndex,
    keys: KEYS,
    signingDomain: DOMAIN,
    ...overrides,
});

describe('confirmBatchCandidate', () => {
    // Ten sibling batches of 50 in one operation, as the sequencer posts them.
    const siblings = Array.from({ length: 10 }, (_, i) => batch({ start: 1_750n + BigInt(50 * i), index: i }));

    it('confirms the one sibling covering the index', () => {
        expect(confirmBatchCandidate(siblings, query(2_007n))).toBe(siblings[5]);
    });

    it('confirms the index at the start and at the end of a batch, and nothing just outside', () => {
        const only = [batch({ start: 2_000n })];

        expect(confirmBatchCandidate(only, query(2_000n))).toBe(only[0]);
        expect(confirmBatchCandidate(only, query(2_049n))).toBe(only[0]);
        expect(confirmBatchCandidate(only, query(1_999n))).toBeNull();
        expect(confirmBatchCandidate(only, query(2_050n))).toBeNull();
    });

    it('refuses another tenant’s batch and another pool’s batch', () => {
        expect(confirmBatchCandidate([batch({ start: 2_000n, tenant: 'other-tenant' })], query(2_007n))).toBeNull();
        expect(confirmBatchCandidate([batch({ start: 2_000n, pool: 'high-roller' })], query(2_007n))).toBeNull();
    });

    it('refuses a batch no registered key signed, and every batch without a key set or signing domain', () => {
        const forged = [batch({ start: 2_000n, seed: FOREIGN_SEED })];
        const honest = [batch({ start: 2_000n })];

        expect(confirmBatchCandidate(forged, query(2_007n))).toBeNull();
        expect(
            confirmBatchCandidate(honest, query(2_007n, { keys: { status: 'unavailable', reason: 'no lineage' } })),
        ).toBeNull();
        expect(confirmBatchCandidate(honest, query(2_007n, { signingDomain: null }))).toBeNull();
    });

    it('returns one copy when the block holds two, the first in node order', () => {
        const copies = [
            batch({ start: 2_000n, seed: FOREIGN_SEED }),
            batch({ start: 2_000n, index: 1 }),
            batch({ start: 2_000n, index: 2 }),
        ];

        expect(confirmBatchCandidate(copies, query(2_007n))).toBe(copies[1]);
    });
});
