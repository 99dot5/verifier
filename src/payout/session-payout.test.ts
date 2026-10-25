// @vitest-environment node
/**
 * The session payout check end to end, over the public payout watcher's
 * recorded nodes: the clean payout, the overpayment, the signature failures
 * and the kernel refusals it is tested on, plus the L1-only outcomes a
 * cemented payout decides without any rollup node.
 */
import { describe, expect, it } from 'vitest';
import type { RpcManagerOperationGroup } from '../chain/inbox';
import {
    normaliseSessionId,
    PAYOUT_CEMENTED_CHECK_ID,
    PAYOUT_EVENTS_CHECK_ID,
    PAYOUT_KERNEL_CHECK_ID,
    PAYOUT_LEDGER_CHECK_ID,
    PAYOUT_SIGNATURES_CHECK_ID,
    type PayoutChain,
    type SessionPayoutReport,
    verifySessionPayout,
} from './session-payout';
import { loadWatcherSnapshot, snapshotChain, type WatcherSnapshot } from './snapshot-fixtures';
import type { WatcherSnapshotCase } from './fast-payout-vectors-path';

const VAULT = 'KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc';
const SESSION = '01020304-0506-0708-090a-0b0c0d0e0f10';
const SESSION_HEX = SESSION.replaceAll('-', '');
const OTHER_SESSION = 'b0b0b0b0-b0b0-b0b0-b0b0-b0b0b0b0b0b0';
const CHAIN_ID = 'NetXdQprcVkpaWU';

function status(report: SessionPayoutReport, id: string): string {
    const found = report.checks.find((c) => c.id === id);

    if (!found) {
        throw new Error(`no ${id} check in ${report.checks.map((c) => c.id).join(', ')}`);
    }

    return found.status;
}

function detail(report: SessionPayoutReport, id: string): string {
    return report.checks.find((c) => c.id === id)?.detail ?? '';
}

/** A hand-built `cemented_payout` outbox execution, in the shape the node renders it. */
function cementedGroup(level: number, amount: bigint, paidNow: bigint, paidTotal: bigint): RpcManagerOperationGroup {
    return {
        hash: `ooCemented${level}`,
        chain_id: CHAIN_ID,
        contents: [
            {
                kind: 'smart_rollup_execute_outbox_message',
                metadata: {
                    operation_result: { status: 'applied' },
                    internal_operation_results: [
                        {
                            kind: 'event',
                            source: VAULT,
                            tag: 'cemented_payout',
                            type: {
                                prim: 'pair',
                                args: [
                                    { prim: 'mutez', annots: ['%cemented'] },
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
                            payload: {
                                prim: 'Pair',
                                args: [
                                    { int: String(amount) },
                                    { int: String(paidNow) },
                                    { int: String(paidTotal) },
                                    { bytes: SESSION_HEX },
                                ],
                            },
                            result: { status: 'applied' },
                        },
                    ],
                },
            },
        ],
    };
}

function withBlocks(snapshot: WatcherSnapshot, blocks: Record<number, RpcManagerOperationGroup[]>): WatcherSnapshot {
    const copy = structuredClone(snapshot);

    for (const [level, groups] of Object.entries(blocks)) {
        copy.l1.blocks[level] = [[], [], [], groups];
    }

    return copy;
}

async function run(
    snapshotCase: WatcherSnapshotCase,
    options: { rollupNode: boolean; session?: string; snapshot?: WatcherSnapshot } = { rollupNode: true },
) {
    const snapshot = options.snapshot ?? loadWatcherSnapshot(snapshotCase);

    return verifySessionPayout({
        sessionId: options.session ?? SESSION,
        vaultAddresses: [VAULT],
        chainId: CHAIN_ID,
        chain: snapshotChain(snapshot, { rollupNode: options.rollupNode }),
    });
}

describe('verifySessionPayout', () => {
    it('finds the clean payout backed by the cemented payout on L1 and by the kernel’s record', async () => {
        const report = await run('clean');

        expect(report.sessionId).toBe(SESSION);
        expect(report.outcome).toBe('backed');
        expect(report.checks.map((c) => [c.id, c.status])).toEqual([
            [PAYOUT_EVENTS_CHECK_ID, 'pass'],
            [PAYOUT_SIGNATURES_CHECK_ID, 'pass'],
            [PAYOUT_LEDGER_CHECK_ID, 'pass'],
            [PAYOUT_CEMENTED_CHECK_ID, 'pass'],
            [PAYOUT_KERNEL_CHECK_ID, 'pass'],
        ]);
        expect(report.events.map((e) => [e.path, e.level, e.amountMutez, e.paidNowMutez, e.paidTotalMutez])).toEqual([
            ['fast', 105, 1_500_000n, 1_500_000n, 1_500_000n],
            ['cemented', 120, 1_500_000n, 0n, 1_500_000n],
        ]);
        expect(report.payoutSigners).toHaveLength(4);
        expect(report.references).toHaveLength(2);
        expect(report.findings).toEqual([]);
        expect(detail(report, PAYOUT_SIGNATURES_CHECK_ID)).toContain('2 of the 4 payout_signers signed');
        expect(detail(report, PAYOUT_CEMENTED_CHECK_ID)).toContain('the same amount');
        expect(detail(report, PAYOUT_KERNEL_CHECK_ID)).toContain('session-end payout of 1500000 mutez');
    });

    it('is backed from L1 alone when no rollup node is configured, and says why the kernel check did not run', async () => {
        const report = await run('clean', { rollupNode: false });

        expect(report.outcome).toBe('backed');
        expect(status(report, PAYOUT_KERNEL_CHECK_ID)).toBe('unavailable');
        expect(detail(report, PAYOUT_KERNEL_CHECK_ID)).toContain('no rollup node configured');
    });

    it('treats a session paid by the cemented path only as backed, with nothing to compare', async () => {
        const report = await run('clean', { rollupNode: true, session: OTHER_SESSION });

        expect(report.outcome).toBe('backed');
        expect(report.events.map((e) => e.path)).toEqual(['cemented']);
        expect(status(report, PAYOUT_SIGNATURES_CHECK_ID)).toBe('unavailable');
        expect(status(report, PAYOUT_LEDGER_CHECK_ID)).toBe('pass');
        expect(status(report, PAYOUT_CEMENTED_CHECK_ID)).toBe('unavailable');
        expect(status(report, PAYOUT_KERNEL_CHECK_ID)).toBe('unavailable');
        expect(report.payoutSigners).toBeNull();
    });

    it('proves an overpayment from the kernel’s record within minutes, and reads pending without a node', async () => {
        const proven = await run('overpayment');

        expect(proven.outcome).toBe('overpaid');
        expect(status(proven, PAYOUT_SIGNATURES_CHECK_ID)).toBe('pass');
        expect(status(proven, PAYOUT_CEMENTED_CHECK_ID)).toBe('unavailable');
        expect(status(proven, PAYOUT_KERNEL_CHECK_ID)).toBe('fail');
        expect(detail(proven, PAYOUT_KERNEL_CHECK_ID)).toContain(
            'session-end payout of 1000000 mutez: the fast payout exceeds it',
        );

        const pending = await run('overpayment', { rollupNode: false });

        expect(pending.outcome).toBe('pending');
        expect(detail(pending, PAYOUT_CEMENTED_CHECK_ID)).toContain('no cemented payout for this session on L1 yet');
    });

    it('proves the same overpayment from L1 alone once the cemented payout has executed', async () => {
        const snapshot = withBlocks(loadWatcherSnapshot('overpayment'), {
            120: [cementedGroup(120, 1_000_000n, 0n, 1_500_000n)],
        });
        const report = await run('overpayment', { rollupNode: false, snapshot });

        expect(report.outcome).toBe('overpaid');
        expect(status(report, PAYOUT_LEDGER_CHECK_ID)).toBe('pass');
        expect(status(report, PAYOUT_CEMENTED_CHECK_ID)).toBe('fail');
        expect(detail(report, PAYOUT_CEMENTED_CHECK_ID)).toContain('an overpayment of 500000 mutez');
        expect(status(report, PAYOUT_KERNEL_CHECK_ID)).toBe('unavailable');
    });

    it('reports a short fast payout as topped up by the cemented one, not as a finding', async () => {
        const snapshot = withBlocks(loadWatcherSnapshot('clean'), {
            120: [cementedGroup(120, 1_600_000n, 100_000n, 1_600_000n)],
        });
        const report = await run('clean', { rollupNode: false, snapshot });

        expect(report.outcome).toBe('short');
        expect(status(report, PAYOUT_CEMENTED_CHECK_ID)).toBe('pass');
        expect(detail(report, PAYOUT_CEMENTED_CHECK_ID)).toContain('100000 mutez short');
    });

    it('fails the ledger when a cemented payout pays in full over a fast payout', async () => {
        const snapshot = withBlocks(loadWatcherSnapshot('clean'), {
            120: [cementedGroup(120, 1_500_000n, 1_500_000n, 3_000_000n)],
        });
        const report = await run('clean', { rollupNode: true, snapshot });

        expect(report.outcome).toBe('unbacked');
        expect(status(report, PAYOUT_LEDGER_CHECK_ID)).toBe('fail');
        expect(detail(report, PAYOUT_LEDGER_CHECK_ID)).toContain(
            'the rule gives paid_now 0 mutez, paid_total 1500000 mutez',
        );
        expect(status(report, PAYOUT_CEMENTED_CHECK_ID)).toBe('pass');
    });

    it('fails the signatures on a member that does not verify, and on a key outside the set', async () => {
        const under = await run('under_threshold');

        expect(under.outcome).toBe('unbacked');
        expect(status(under, PAYOUT_SIGNATURES_CHECK_ID)).toBe('fail');
        expect(detail(under, PAYOUT_SIGNATURES_CHECK_ID)).toContain('does not verify');
        expect(detail(under, PAYOUT_SIGNATURES_CHECK_ID)).toContain('1 valid signature(s)');
        expect(status(under, PAYOUT_KERNEL_CHECK_ID)).toBe('pass');

        const outside = await run('signer_outside_set');

        expect(outside.outcome).toBe('unbacked');
        expect(detail(outside, PAYOUT_SIGNATURES_CHECK_ID)).toContain('a key outside payout_signers');
    });

    it('fails on a session the kernel has not ended, and names the refusal', async () => {
        const report = await run('session_not_ended');

        expect(report.outcome).toBe('unbacked');
        expect(status(report, PAYOUT_KERNEL_CHECK_ID)).toBe('fail');
        expect(detail(report, PAYOUT_KERNEL_CHECK_ID)).toContain('NOT ended');
        expect((await run('session_not_ended', { rollupNode: false })).outcome).toBe('pending');
    });

    it('reads an unpaid session as unpaid, a node that disagrees with the indexer as a finding, and a failed lookup as unavailable', async () => {
        const unpaid = await run('clean', { rollupNode: true, session: 'cccccccc-cccc-cccc-cccc-cccccccccccc' });

        expect(unpaid.outcome).toBe('unpaid');
        expect(unpaid.checks.map((c) => c.id)).toEqual([PAYOUT_EVENTS_CHECK_ID]);
        expect(detail(unpaid, PAYOUT_EVENTS_CHECK_ID)).toContain('paid only after it ends');

        const base = snapshotChain(loadWatcherSnapshot('clean'));
        const disagreeing: PayoutChain = {
            ...base,
            locatePayoutEvents: async () => ({
                lookup: 'ok',
                levels: [{ vault: VAULT, level: 125 }],
                detail: 'one level',
            }),
        };
        const disagreed = await verifySessionPayout({
            sessionId: SESSION,
            vaultAddresses: [VAULT],
            chainId: CHAIN_ID,
            chain: disagreeing,
        });

        expect(disagreed.outcome).toBe('unpaid');
        expect(disagreed.findings[0]).toContain('indexer and node disagree');

        const failing: PayoutChain = {
            ...base,
            locatePayoutEvents: async () => ({ lookup: 'failed', levels: [], detail: 'the indexer returned 503' }),
        };
        const failed = await verifySessionPayout({
            sessionId: SESSION,
            vaultAddresses: [VAULT],
            chainId: CHAIN_ID,
            chain: failing,
        });

        expect(failed.outcome).toBe('unavailable');
        expect(detail(failed, PAYOUT_EVENTS_CHECK_ID)).toBe('the indexer returned 503');
    });

    it('reads unavailable when the rollup node has not finalised the payout’s level', async () => {
        const snapshot = loadWatcherSnapshot('overpayment');

        snapshot.rollup.finalized_level = 104;

        const report = await run('overpayment', { rollupNode: true, snapshot });

        expect(report.outcome).toBe('pending');
        expect(status(report, PAYOUT_KERNEL_CHECK_ID)).toBe('unavailable');
        expect(detail(report, PAYOUT_KERNEL_CHECK_ID)).toContain('finalised level 104, below the payout’s level 105');
    });

    it('accepts a session id hyphenated or bare and refuses anything else', () => {
        expect(normaliseSessionId(SESSION_HEX)).toEqual({ hex: SESSION_HEX, hyphenated: SESSION });
        expect(normaliseSessionId(SESSION.toUpperCase())).toEqual({ hex: SESSION_HEX, hyphenated: SESSION });
        expect(() => normaliseSessionId('0102')).toThrow(RangeError);
        expect(() => normaliseSessionId('')).toThrow(RangeError);
    });
});
