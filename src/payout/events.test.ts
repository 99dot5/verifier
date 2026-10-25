// @vitest-environment node
/**
 * The block decoder: payout events paired with their calls, in the shapes a
 * node renders them, pinned both to hand-built blocks and to the public
 * payout watcher's recorded ones.
 */
import { describe, expect, it } from 'vitest';
import type { RpcManagerOperationGroup } from '../chain/inbox';
import { scanBlockPayouts } from './events';
import { bytesToHex } from './micheline';
import { loadWatcherSnapshot, snapshotBlock } from './snapshot-fixtures';

const VAULT = 'KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc';
const OTHER = 'KT1EfTusMLoeCAAGd9MZJn5yKzFr6kJU5U91';
const SPPK = 'sppk7bWq3wGj9AuTowUc7N2dpRhMCWtw6pmDFcLrSTLyA1mnBJ9hL5T';
const SPSIG = 'spsig1T44Ls6CqyU9xqnDbB7QU4oZRdkXUDbx8Edi2hoPsmxKfmi1nj1GCic3GBzC7xssqPqJwVELB9uzoqEeLYQePdPdLbPDQE';
const SESSION = '0102030405060708090a0b0c0d0e0f10';

function event(tag: string, amountField: string, status: string, source = VAULT): Record<string, unknown> {
    return {
        kind: 'event',
        source,
        tag,
        type: {
            prim: 'pair',
            args: [
                { prim: 'mutez', annots: [`%${amountField}`] },
                {
                    prim: 'pair',
                    args: [
                        { prim: 'mutez', annots: ['%paid_now'] },
                        {
                            prim: 'pair',
                            args: [
                                { prim: 'mutez', annots: ['%paid_total'] },
                                { prim: 'bytes', annots: ['%session_id'] },
                            ],
                        },
                    ],
                },
            ],
        },
        payload: { prim: 'Pair', args: [{ int: '5' }, { int: '5' }, { int: '5' }, { bytes: SESSION }] },
        result: { status },
    };
}

function callValue(): unknown {
    return {
        prim: 'Pair',
        args: [
            { int: '5' },
            {
                prim: 'Pair',
                args: [{ bytes: SESSION }, [{ prim: 'Elt', args: [{ string: SPPK }, { string: SPSIG }] }]],
            },
        ],
    };
}

function block(content: Record<string, unknown>): RpcManagerOperationGroup[] {
    return [
        {
            hash: 'oo1',
            chain_id: 'NetXdQprcVkpaWU',
            contents: [content as unknown as RpcManagerOperationGroup['contents'][number]],
        },
    ];
}

const watched = new Set([VAULT]);

describe('scanBlockPayouts', () => {
    it('pairs a fast payout with its direct call', () => {
        const items = scanBlockPayouts(
            block({
                kind: 'transaction',
                destination: VAULT,
                parameters: { entrypoint: 'fast_payout', value: callValue() },
                metadata: {
                    operation_result: { status: 'applied' },
                    internal_operation_results: [event('fast_payout', 'fast', 'applied')],
                },
            }),
            watched,
        );

        expect(items).toHaveLength(1);

        const item = items[0];

        if (item.kind !== 'event') {
            throw new Error('expected an event');
        }

        expect(item.event.path).toBe('fast');
        expect([item.event.amount, item.event.paidNow, item.event.paidTotal]).toEqual([5n, 5n, 5n]);
        expect(item.event.chainId).toBe('NetXdQprcVkpaWU');
        expect(item.event.operationHash).toBe('oo1');
        expect(bytesToHex(item.event.sessionId)).toBe(SESSION);
        expect(item.event.call?.ok).toBe(true);

        if (item.event.call?.ok) {
            expect(item.event.call.call.signatures[0].publicKey).toBe(SPPK);
            expect(item.event.call.call.amount).toBe(5n);
        }
    });

    it('finds a call batched through a contract in the internal results', () => {
        const items = scanBlockPayouts(
            block({
                kind: 'transaction',
                destination: OTHER,
                parameters: { entrypoint: 'default', value: { prim: 'Unit' } },
                metadata: {
                    operation_result: { status: 'applied' },
                    internal_operation_results: [
                        {
                            kind: 'transaction',
                            destination: VAULT,
                            parameters: { entrypoint: 'fast_payout', value: callValue() },
                            result: { status: 'applied' },
                        },
                        event('fast_payout', 'fast', 'applied'),
                    ],
                },
            }),
            watched,
        );

        expect(items[0].kind === 'event' && items[0].event.call?.ok).toBe(true);
    });

    it('ignores reverted events and other vaults, and reads a cemented payout from an outbox execution', () => {
        const content = (source: string, status: string): Record<string, unknown> => ({
            kind: 'smart_rollup_execute_outbox_message',
            metadata: {
                operation_result: { status: 'applied' },
                internal_operation_results: [event('cemented_payout', 'cemented', status, source)],
            },
        });

        expect(scanBlockPayouts(block(content(VAULT, 'backtracked')), watched)).toEqual([]);
        expect(scanBlockPayouts(block(content(OTHER, 'applied')), watched)).toEqual([]);

        const items = scanBlockPayouts(block(content(VAULT, 'applied')), watched);

        expect(items).toHaveLength(1);
        expect(items[0].kind === 'event' && items[0].event.path).toBe('cemented');
        expect(items[0].kind === 'event' && items[0].event.call).toBeNull();
    });

    it('reports an event that does not decode rather than skipping it', () => {
        const bad = event('fast_payout', 'fast', 'applied');

        bad.payload = { int: '5' };

        const items = scanBlockPayouts(
            block({
                kind: 'transaction',
                metadata: { operation_result: { status: 'applied' }, internal_operation_results: [bad] },
            }),
            watched,
        );

        expect(items).toHaveLength(1);
        expect(items[0].kind).toBe('undecodable');
        expect(items[0].kind === 'undecodable' && items[0].tag).toBe('fast_payout');
    });

    it('carries no call for a fast payout whose operation holds none, and an error for one that does not decode', () => {
        const without = scanBlockPayouts(
            block({
                kind: 'transaction',
                metadata: {
                    operation_result: { status: 'applied' },
                    internal_operation_results: [event('fast_payout', 'fast', 'applied')],
                },
            }),
            watched,
        );

        expect(without[0].kind === 'event' && without[0].event.call).toBeNull();

        const broken = scanBlockPayouts(
            block({
                kind: 'transaction',
                destination: VAULT,
                parameters: { entrypoint: 'fast_payout', value: { int: '5' } },
                metadata: {
                    operation_result: { status: 'applied' },
                    internal_operation_results: [event('fast_payout', 'fast', 'applied')],
                },
            }),
            watched,
        );

        expect(broken[0].kind === 'event' && broken[0].event.call?.ok).toBe(false);
    });

    it('reads the watcher’s recorded blocks: a fast payout with its call, then two cemented payouts', () => {
        const snapshot = loadWatcherSnapshot('clean');
        const vault = snapshot.l1.scripts[0].contract;
        const fast = scanBlockPayouts(snapshotBlock(snapshot, 105), new Set([vault]));

        expect(fast).toHaveLength(1);
        expect(fast[0].kind === 'event' && fast[0].event.path).toBe('fast');
        expect(fast[0].kind === 'event' && fast[0].event.amount).toBe(1_500_000n);
        expect(fast[0].kind === 'event' && bytesToHex(fast[0].event.sessionId)).toBe(SESSION);
        expect(fast[0].kind === 'event' && fast[0].event.call?.ok && fast[0].event.call.call.signatures.length).toBe(2);

        const cemented = scanBlockPayouts(snapshotBlock(snapshot, 120), new Set([vault]));

        expect(cemented.map((item) => item.kind === 'event' && item.event.path)).toEqual(['cemented', 'cemented']);
        // The sweep at level 125 is not a payout event and is not read here.
        expect(scanBlockPayouts(snapshotBlock(snapshot, 125), new Set([vault]))).toEqual([]);
        expect(scanBlockPayouts(snapshotBlock(snapshot, 999), new Set([vault]))).toEqual([]);
    });
});
