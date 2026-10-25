// @vitest-environment node
/**
 * The kernel's records, decoded from the bytes the public payout watcher
 * recorded off a rollup node, and the comparison that reads them.
 */
import { describe, expect, it } from 'vitest';
import {
    checkFastPayoutAgainstKernel,
    decodeStoredSession,
    decodeStoredTransaction,
    payoutKey,
    sessionKey,
} from './kernel';
import type { RollupNodeReads } from './rollup-node';
import { loadWatcherSnapshot, snapshotRollupNode } from './snapshot-fixtures';

const TENANT = 'golden-tenant';
const POOL = 'golden-pool';
const VAULT = 'KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc';
const OWNER = 'tz1UyQDepgtUBnWjyzzonqeDwaiWoQzRKSP5';
const SESSION = '01020304-0506-0708-090a-0b0c0d0e0f10';

/** A recorded value that the test knows is present. */
function must(value: Uint8Array | null): Uint8Array {
    if (value === null) {
        throw new Error('the recording holds no value at that key');
    }

    return value;
}

function store(values: Record<string, Uint8Array>): RollupNodeReads {
    return { finalizedLevel: async () => 130, durableValue: async (key) => values[key] ?? null };
}

describe('kernel records', () => {
    it('builds the keys the validator and the watcher read', () => {
        expect(sessionKey('t', 'p', '660e8400-e29b-41d4-a716-446655440099')).toBe(
            '/tenants/t/pools/p/sessions/660e8400-e29b-41d4-a716-446655440099',
        );
        expect(payoutKey('t', 'p', 'TEZ', '660e8400-e29b-41d4-a716-446655440099')).toBe(
            '/tenants/t/pools/p/transactions/TEZ/payout-660e8400-e29b-41d4-a716-446655440099',
        );
    });

    it('decodes the recorded session and payout records', async () => {
        const node = snapshotRollupNode(loadWatcherSnapshot('clean'));
        const session = decodeStoredSession(must(await node.durableValue(sessionKey(TENANT, POOL, SESSION))));

        expect(session).toEqual({
            owner: OWNER,
            asset: 'TEZ',
            balance: 0n,
            fundingVaultAddress: VAULT,
            ended: true,
            endReason: 'player',
        });

        const payout = decodeStoredTransaction(must(await node.durableValue(payoutKey(TENANT, POOL, 'TEZ', SESSION))));

        expect(payout).toEqual({ accountAddress: OWNER, asset: 'TEZ', kind: 'session-end-payout', amount: 1_500_000n });

        const sweep = decodeStoredTransaction(
            must(await node.durableValue(`/tenants/${TENANT}/pools/${POOL}/transactions/TEZ/sweep-102-3`)),
        );

        expect(sweep.kind).toBe('sweep');
        expect(sweep.accountAddress).toBe(VAULT);
    });

    it('refuses another envelope version, an unknown kind and trailing bytes', async () => {
        const node = snapshotRollupNode(loadWatcherSnapshot('clean'));
        const session = must(await node.durableValue(sessionKey(TENANT, POOL, SESSION)));
        const payout = must(await node.durableValue(payoutKey(TENANT, POOL, 'TEZ', SESSION)));

        expect(() => decodeStoredSession(new Uint8Array([1, ...session.slice(1)]))).toThrow(/envelope version 1/);
        expect(() => decodeStoredSession(new Uint8Array([...session, 0]))).toThrow(/trailing/);
        expect(() => decodeStoredSession(session.slice(0, -1))).toThrow(/end of input/);

        const unknownKind = new Uint8Array(payout);

        unknownKind[payout.length - 17] = 9;
        expect(() => decodeStoredTransaction(unknownKind)).toThrow(/kind tag 9/);
    });

    it('compares a fast payout with the records: backed, short, above, and every refusal', async () => {
        const clean = snapshotRollupNode(loadWatcherSnapshot('clean'));

        expect(await checkFastPayoutAgainstKernel(clean, TENANT, POOL, VAULT, SESSION, 1_500_000n)).toEqual({
            kind: 'backed',
            kernelAmount: 1_500_000n,
        });
        expect(await checkFastPayoutAgainstKernel(clean, TENANT, POOL, VAULT, SESSION, 1_000_000n)).toEqual({
            kind: 'short',
            kernelAmount: 1_500_000n,
        });
        expect(await checkFastPayoutAgainstKernel(clean, TENANT, POOL, VAULT, SESSION, 1_500_001n)).toEqual({
            kind: 'above-kernel',
            kernelAmount: 1_500_000n,
        });

        const over = snapshotRollupNode(loadWatcherSnapshot('overpayment'));

        expect(await checkFastPayoutAgainstKernel(over, TENANT, POOL, VAULT, SESSION, 1_500_000n)).toEqual({
            kind: 'above-kernel',
            kernelAmount: 1_000_000n,
        });

        const notEnded = snapshotRollupNode(loadWatcherSnapshot('session_not_ended'));

        expect(await checkFastPayoutAgainstKernel(notEnded, TENANT, POOL, VAULT, SESSION, 1_500_000n)).toEqual({
            kind: 'session-not-ended',
        });
        expect(
            await checkFastPayoutAgainstKernel(clean, TENANT, POOL, VAULT, 'b0b0b0b0-b0b0-b0b0-b0b0-b0b0b0b0b0b1', 1n),
        ).toEqual({ kind: 'session-not-recorded' });
        expect(
            await checkFastPayoutAgainstKernel(
                clean,
                TENANT,
                POOL,
                'KT1EfTusMLoeCAAGd9MZJn5yKzFr6kJU5U91',
                SESSION,
                1n,
            ),
        ).toEqual({
            kind: 'funding-vault-mismatch',
            recorded: VAULT,
        });

        const session = must(await clean.durableValue(sessionKey(TENANT, POOL, SESSION)));
        const sweep = must(await clean.durableValue(`/tenants/${TENANT}/pools/${POOL}/transactions/TEZ/sweep-102-3`));

        expect(
            await checkFastPayoutAgainstKernel(
                store({ [sessionKey(TENANT, POOL, SESSION)]: session }),
                TENANT,
                POOL,
                VAULT,
                SESSION,
                1n,
            ),
        ).toEqual({ kind: 'payout-not-recorded' });
        expect(
            await checkFastPayoutAgainstKernel(
                store({
                    [sessionKey(TENANT, POOL, SESSION)]: session,
                    [payoutKey(TENANT, POOL, 'TEZ', SESSION)]: sweep,
                }),
                TENANT,
                POOL,
                VAULT,
                SESSION,
                1n,
            ),
        ).toEqual({ kind: 'payout-record-not-a-session-end-payout', recordKind: 'sweep' });
        expect(
            await checkFastPayoutAgainstKernel(
                store({ [sessionKey(TENANT, POOL, SESSION)]: new Uint8Array([0, 1]) }),
                TENANT,
                POOL,
                VAULT,
                SESSION,
                1n,
            ),
        ).toMatchObject({ kind: 'corrupt-record', key: sessionKey(TENANT, POOL, SESSION) });
    });
});
