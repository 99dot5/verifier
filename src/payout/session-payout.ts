/**
 * The session payout check: was the session paid what the rollup kernel
 * said it was owed, by the signers the vault really holds?
 *
 * A session's balance leaves the rollup in one of two ways. The CEMENTED
 * payout is the rollup's own outbox message, executable about two weeks
 * after the session ends, once the commitment covering it cements. The FAST
 * payout is the same payment minutes after the session ends, authorised by
 * two of the vault's four payout signers — and the vault cannot check its
 * amount, because before cementation only a rollup node knows what the
 * kernel computed. So two signers acting together could pay more than the
 * session was owed. That cannot be prevented without capital; this check is
 * what makes it impossible to do quietly.
 *
 * Five checks, from public L1 data (the indexer locates, the node is read):
 *
 *   1. `payout-events`      the vault's `fast_payout` / `cemented_payout`
 *                           events for the session, decoded by annotation
 *                           from the block's own receipts;
 *   2. `payout-signatures`  every signature the fast payout carried,
 *                           re-verified over the shared PACK payload against
 *                           the `payout_signers` the vault held at the block
 *                           before — a key outside the set, a failing member
 *                           or fewer than two valid ones fails it;
 *   3. `payout-ledger`      the vault's per-session paid ledger moved by its
 *                           rule, replayed from this tool's own reading of the
 *                           earlier events, never the event's claim;
 *   4. `payout-cemented`    the L1-ONLY kernel comparison: the cemented
 *                           payout's amount is the kernel's figure as the
 *                           outbox message carried it, so once it has
 *                           executed, a fast payout above it is an
 *                           overpayment provable from L1 alone;
 *   5. `payout-kernel`      the SAME comparison within minutes rather than
 *                           weeks, against the kernel's `payout-{session}`
 *                           record read from a rollup node the READER runs
 *                           (never a default: the operator's node can only
 *                           confirm the operator).
 *
 * Paying LESS than the kernel's figure is not a finding: the cemented payout
 * pays the remainder, so the player's floor is always the kernel's number.
 */
import type { RpcManagerOperationGroup } from '../chain/inbox';
import type { Check, MessageRef } from '../verifier';
import { type PayoutEvent, type PayoutPath, scanBlockPayouts } from './events';
import { checkFastPayoutAgainstKernel, type KernelFinding } from './kernel';
import { checkCemented, checkFast } from './ledger';
import type { PayoutLocation } from './locate';
import { bytesToHex } from './micheline';
import { PAYOUT_THRESHOLD } from './payload';
import type { RollupNodeReads } from './rollup-node';
import { underThreshold, verifyCall } from './signatures';
import { decodeVaultScript, type VaultStorage } from './vault-storage';

/** The chain reads the check needs; the shell passes TzKT, the node RPC and the reader's rollup node, a test passes stubs. */
export interface PayoutChain {
    locatePayoutEvents(vaultAddresses: string[], sessionIdHex: string): Promise<PayoutLocation>;
    /** `operations/3` of one block, receipts included. */
    blockOperations(level: number): Promise<RpcManagerOperationGroup[]>;
    /** A contract's script (code and storage) at `level`, as the node renders it. */
    contractScript(address: string, level: number): Promise<unknown>;
    /** The reader's own rollup node, or null when none is configured. */
    rollupNode: RollupNodeReads | null;
}

export interface SessionPayoutInput {
    /** Hyphenated or bare-hex session id. */
    sessionId: string;
    /** The pool's vaults, from the lineage; the session's deposit bound it to one of them. */
    vaultAddresses: string[];
    /** The selected network's chain id, used only when the node states none on the operation group. */
    chainId: string | null;
    chain: PayoutChain;
    onProgress?(text: string): void;
}

/**
 * What the check concludes about the session's payout. Not the round
 * verdicts: a payout is a fact about the SESSION, judged by different rules,
 * and the two vocabularies are kept apart so neither reads as the other.
 *
 *   `backed`       the fast payout equals the kernel's figure (from the
 *                  cemented payout on L1, or the record on the reader's
 *                  rollup node), its signatures hold and the ledger holds; or
 *                  the session was paid by the cemented path only.
 *   `short`        the fast payout is below the kernel's figure; the cemented
 *                  payout pays (or paid) the remainder. Not an accusation.
 *   `overpaid`     the fast payout is ABOVE the kernel's figure: two signers
 *                  paid what the kernel does not back. The one accusatory
 *                  outcome, and the reason this check exists.
 *   `unbacked`     a check failed for another reason: the signatures, the
 *                  ledger, or a kernel record that does not back the payout
 *                  (a session never ended, a different vault, no record).
 *   `pending`      a fast payout exists but nothing yet says what the kernel
 *                  owed: no cemented payout on L1, and no rollup node to ask.
 *   `unpaid`       no payout event for the session on any of the pool's
 *                  vaults: not ended, or not paid yet.
 *   `unavailable`  the lookups could not be made or could not be trusted.
 */
export type PayoutOutcome = 'backed' | 'short' | 'overpaid' | 'unbacked' | 'pending' | 'unpaid' | 'unavailable';

export interface PayoutEventSummary {
    vault: string;
    level: number;
    path: PayoutPath;
    amountMutez: bigint;
    paidNowMutez: bigint;
    paidTotalMutez: bigint;
    operationHash: string;
}

export interface SessionPayoutReport {
    /** Hyphenated. */
    sessionId: string;
    outcome: PayoutOutcome;
    checks: Check[];
    events: PayoutEventSummary[];
    /** The vault's `payout_signers` at the block before the fast payout, as the vault held them; null without a fast payout. */
    payoutSigners: string[] | null;
    /** Observations that are not proofs. */
    findings: string[];
    references: MessageRef[];
}

export const PAYOUT_EVENTS_CHECK_ID = 'payout-events';
export const PAYOUT_SIGNATURES_CHECK_ID = 'payout-signatures';
export const PAYOUT_LEDGER_CHECK_ID = 'payout-ledger';
export const PAYOUT_CEMENTED_CHECK_ID = 'payout-cemented';
export const PAYOUT_KERNEL_CHECK_ID = 'payout-kernel';

const TITLES: Record<string, string> = {
    [PAYOUT_EVENTS_CHECK_ID]: 'The vault’s payout events for this session were found and read',
    [PAYOUT_SIGNATURES_CHECK_ID]: 'Two of the vault’s own payout signers authorised the fast payout',
    [PAYOUT_LEDGER_CHECK_ID]: 'The vault’s paid ledger moved by its rule',
    [PAYOUT_CEMENTED_CHECK_ID]: 'The fast payout does not exceed the rollup’s cemented figure',
    [PAYOUT_KERNEL_CHECK_ID]: 'The kernel’s own record, on your rollup node, backs the fast payout',
};

function check(id: string, status: Check['status'], detail: string): Check {
    return { id, title: TITLES[id], status, detail };
}

/** Accept a session id as 32 bare hex digits or already hyphenated; return both forms. */
export function normaliseSessionId(value: string): { hex: string; hyphenated: string } {
    const hex = value.trim().toLowerCase().replaceAll('-', '');

    if (!/^[0-9a-f]{32}$/.test(hex)) {
        throw new RangeError(`a session id is 16 bytes (32 hex digits, hyphenated or not), got "${value}"`);
    }

    return {
        hex,
        hyphenated: `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`,
    };
}

interface LocatedEvent {
    level: number;
    event: PayoutEvent;
}

function mutez(amount: bigint): string {
    return `${amount} mutez`;
}

function summarise(located: LocatedEvent): PayoutEventSummary {
    const { level, event } = located;

    return {
        vault: event.vault,
        level,
        path: event.path,
        amountMutez: event.amount,
        paidNowMutez: event.paidNow,
        paidTotalMutez: event.paidTotal,
        operationHash: event.operationHash,
    };
}

function reference(located: LocatedEvent): MessageRef {
    const { level, event } = located;

    return {
        level,
        operationHash: event.operationHash,
        summary:
            `${event.path === 'fast' ? 'fast_payout' : 'cemented_payout'} event on ${event.vault}: ` +
            `${event.path} ${mutez(event.amount)}, paid_now ${mutez(event.paidNow)}, paid_total ${mutez(event.paidTotal)}`,
    };
}

/** Run the five checks for one session. */
export async function verifySessionPayout(input: SessionPayoutInput): Promise<SessionPayoutReport> {
    const progress = input.onProgress ?? (() => undefined);
    const { hex, hyphenated } = normaliseSessionId(input.sessionId);
    const findings: string[] = [];
    const unavailable = (detail: string): SessionPayoutReport => ({
        sessionId: hyphenated,
        outcome: 'unavailable',
        checks: [check(PAYOUT_EVENTS_CHECK_ID, 'unavailable', detail)],
        events: [],
        payoutSigners: null,
        findings,
        references: [],
    });

    progress('locating the session’s payout events via the indexer…');

    const location = await input.chain.locatePayoutEvents(input.vaultAddresses, hex);

    if (location.lookup !== 'ok') {
        return unavailable(location.detail);
    }

    // ── 1. The events, from the node's own receipts ─────────────────────
    const events: LocatedEvent[] = [];
    const eventProblems: string[] = [];
    const storages = new Map<string, VaultStorage | null>();

    for (const { vault, level } of location.levels) {
        progress(`reading block ${level} from the node…`);

        let groups: RpcManagerOperationGroup[];

        try {
            groups = await input.chain.blockOperations(level);
        } catch (error) {
            return unavailable(
                `the node could not read block ${level}, which the indexer names for a payout event: ${errorText(error)}`,
            );
        }

        const items = scanBlockPayouts(groups, new Set([vault]));
        let found = 0;

        for (const item of items) {
            if (item.kind === 'undecodable') {
                eventProblems.push(
                    `block ${level} holds an applied ${item.tag} event of ${item.vault} (op ${item.operationHash}) that does not decode: ${item.reason}`,
                );
                continue;
            }

            if (bytesToHex(item.event.sessionId) !== hex) {
                continue;
            }

            events.push({ level, event: item.event });
            found += 1;
        }

        if (found === 0) {
            findings.push(
                `indexer and node disagree: the indexer names level ${level} for a payout event of ${vault} naming this ` +
                    'session, but the node’s block holds no applied payout event of that vault naming it; the level is ignored',
            );
        }

        // The vault as it was BEFORE the block, once per level: the scope
        // every kernel read needs, and the signer set the fast payout's
        // signatures were checked against.
        if (found > 0 && !storages.has(`${vault}@${level}`)) {
            progress(`reading vault ${vault} as it stood before level ${level}…`);

            try {
                storages.set(
                    `${vault}@${level}`,
                    decodeVaultScript(await input.chain.contractScript(vault, level - 1)),
                );
            } catch (error) {
                storages.set(`${vault}@${level}`, null);
                findings.push(
                    `the storage of vault ${vault} before level ${level} could not be read: ${errorText(error)}`,
                );
            }
        }
    }

    if (events.length === 0) {
        const report = unavailable(
            eventProblems.length > 0
                ? eventProblems.join('; ')
                : `${location.detail}. A session is paid only after it ends; the fast payout follows within minutes, the cemented payout about two weeks later`,
        );

        return { ...report, outcome: eventProblems.length > 0 ? 'unbacked' : 'unpaid' };
    }

    const checks: Check[] = [];

    checks.push(
        eventProblems.length > 0
            ? check(PAYOUT_EVENTS_CHECK_ID, 'fail', eventProblems.join('; '))
            : check(
                  PAYOUT_EVENTS_CHECK_ID,
                  'pass',
                  `${events.length} payout event(s) read from the node’s receipts: ` +
                      events
                          .map(
                              (e) => `${e.event.path} ${mutez(e.event.amount)} at level ${e.level} on ${e.event.vault}`,
                          )
                          .join(', '),
              ),
    );

    const fast = events.filter((e) => e.event.path === 'fast');
    const cemented = events.filter((e) => e.event.path === 'cemented');
    const storageOf = (located: LocatedEvent): VaultStorage | null =>
        storages.get(`${located.event.vault}@${located.level}`) ?? null;

    // ── 2. The signatures ───────────────────────────────────────────────
    let payoutSigners: string[] | null = null;

    if (fast.length === 0) {
        checks.push(
            check(
                PAYOUT_SIGNATURES_CHECK_ID,
                'unavailable',
                'no fast payout: the session was paid by the rollup’s own cemented path only, which carries no signatures to check',
            ),
        );
    } else {
        const problems: string[] = [];
        const passes: string[] = [];
        let unavailableReason: string | null = null;

        for (const located of fast) {
            const { event, level } = located;
            const where = `the fast payout at level ${level} (op ${event.operationHash})`;
            const storage = storageOf(located);

            if (event.call === null) {
                problems.push(`${where}: no fast_payout call naming this session in the operation`);
                continue;
            }

            if (!event.call.ok) {
                problems.push(`${where}: the fast_payout call does not decode: ${event.call.reason}`);
                continue;
            }

            const { call } = event.call;

            if (call.amount !== event.amount) {
                problems.push(
                    `${where}: the call asked for ${mutez(call.amount)}, the event reports ${mutez(event.amount)}`,
                );
            }

            if (storage === null) {
                unavailableReason = `${where}: the vault’s storage before the payout could not be read, so the signer set is unknown`;
                continue;
            }

            if (storage.payoutSigners === null) {
                problems.push(`${where}: a fast payout on a vault whose storage holds no payout_signers`);
                continue;
            }

            const chainId = event.chainId ?? input.chainId;

            if (chainId === null) {
                unavailableReason = `${where}: the operation names no chain id and no network is selected, so the signed payload cannot be built`;
                continue;
            }

            if (event.chainId === null) {
                findings.push(
                    `${where}: the node stated no chain id on the operation group; the selected network’s (${chainId}) was used`,
                );
            }

            payoutSigners = storage.payoutSigners;

            const verdict = verifyCall(
                chainId,
                event.vault,
                call.sessionId,
                call.amount,
                call.signatures,
                new Set(storage.payoutSigners),
            );

            for (const foreign of verdict.foreign) {
                problems.push(
                    `${where}: a signature from ${foreign.publicKey}, a key outside payout_signers (it ${foreign.verified ? 'verifies' : 'does not verify'})`,
                );
            }

            for (const invalid of verdict.invalid) {
                problems.push(
                    `${where}: payout signer ${invalid.publicKey}’s signature does not verify: ${invalid.reason}`,
                );
            }

            if (underThreshold(verdict)) {
                problems.push(
                    `${where}: ${verdict.valid.length} valid signature(s) from payout_signers on a payout the vault applied; the threshold is ${PAYOUT_THRESHOLD}`,
                );
            }

            if (problems.length === 0) {
                passes.push(
                    `${where}: ${verdict.valid.length} of the ${storage.payoutSigners.length} payout_signers signed ` +
                        `PACK(("fast-payout:v1", ${chainId}, ${event.vault}, ${hex}, ${call.amount})) and each signature verifies: ` +
                        verdict.valid.join(', '),
                );
            }
        }

        checks.push(
            problems.length > 0
                ? check(PAYOUT_SIGNATURES_CHECK_ID, 'fail', problems.join('; '))
                : unavailableReason !== null
                  ? check(PAYOUT_SIGNATURES_CHECK_ID, 'unavailable', unavailableReason)
                  : check(PAYOUT_SIGNATURES_CHECK_ID, 'pass', passes.join('; ')),
        );
    }

    // ── 3. The paid ledger ──────────────────────────────────────────────
    {
        const problems: string[] = [];
        const moves: string[] = [];
        let previous = 0n;

        for (const { event, level } of events) {
            const reported = { paidNow: event.paidNow, paidTotal: event.paidTotal };
            const mismatch =
                event.path === 'fast'
                    ? checkFast(previous, event.amount, reported)
                    : checkCemented(previous, event.amount, reported);

            if (mismatch) {
                problems.push(
                    `the ${event.path} payout at level ${level} reports paid_now ${mutez(reported.paidNow)}, paid_total ${mutez(reported.paidTotal)} ` +
                        `over a previous total of ${mutez(previous)}; the rule gives ` +
                        (mismatch.expected
                            ? `paid_now ${mutez(mismatch.expected.paidNow)}, paid_total ${mutez(mismatch.expected.paidTotal)}`
                            : 'no move at all (a fast payout over a non-zero ledger should have been refused)'),
                );
            } else {
                moves.push(
                    `${event.path} ${mutez(event.amount)} over ${mutez(previous)} → paid_now ${mutez(event.paidNow)}, paid_total ${mutez(event.paidTotal)}`,
                );
            }

            // Follow what the vault reported, so one bad move is one finding.
            previous = event.paidTotal;
        }

        checks.push(
            problems.length > 0
                ? check(PAYOUT_LEDGER_CHECK_ID, 'fail', problems.join('; '))
                : check(PAYOUT_LEDGER_CHECK_ID, 'pass', `replayed from an empty ledger: ${moves.join('; ')}`),
        );
    }

    // ── 4. The L1-only kernel figure: the cemented payout ───────────────
    let kernelFigure: { amount: bigint; source: string } | null = null;
    let overpaid = false;

    if (fast.length === 0) {
        checks.push(
            check(
                PAYOUT_CEMENTED_CHECK_ID,
                'unavailable',
                'no fast payout to compare: the cemented payout is the kernel’s own figure, paid by the rollup’s outbox message',
            ),
        );
    } else if (cemented.length === 0) {
        checks.push(
            check(
                PAYOUT_CEMENTED_CHECK_ID,
                'unavailable',
                'no cemented payout for this session on L1 yet: the rollup’s own outbox message executes about two weeks after ' +
                    'the session ends, and its amount is the kernel’s figure. Until then only a rollup node can say what the ' +
                    'kernel recorded (the next check)',
            ),
        );
    } else {
        const first = fast[0];
        const figure = cemented[0];
        const paid = first.event.amount;
        const kernel = figure.event.amount;

        kernelFigure = { amount: kernel, source: `the cemented payout at level ${figure.level}` };

        if (paid > kernel) {
            overpaid = true;
            checks.push(
                check(
                    PAYOUT_CEMENTED_CHECK_ID,
                    'fail',
                    `the fast payout at level ${first.level} paid ${mutez(paid)}; the rollup’s cemented payout at level ${figure.level} ` +
                        `carries the kernel’s figure of ${mutez(kernel)}: an overpayment of ${mutez(paid - kernel)} that two signers ` +
                        'authorised and the kernel does not back',
                ),
            );
        } else {
            checks.push(
                check(
                    PAYOUT_CEMENTED_CHECK_ID,
                    'pass',
                    `the fast payout at level ${first.level} paid ${mutez(paid)}; the rollup’s cemented payout at level ${figure.level} ` +
                        `carries the kernel’s figure of ${mutez(kernel)}` +
                        (paid < kernel
                            ? `, so the fast payout was ${mutez(kernel - paid)} short and the cemented payout paid the remainder (paid_now ${mutez(figure.event.paidNow)})`
                            : ', the same amount'),
                ),
            );
        }
    }

    // ── 5. The kernel's record, on the reader's rollup node ─────────────
    if (fast.length === 0) {
        checks.push(check(PAYOUT_KERNEL_CHECK_ID, 'unavailable', 'no fast payout to compare with the kernel’s record'));
    } else if (input.chain.rollupNode === null) {
        checks.push(
            check(
                PAYOUT_KERNEL_CHECK_ID,
                'unavailable',
                'no rollup node configured. The kernel’s `payout-{session}` record is readable from any rollup node that ' +
                    'follows this rollup, but a node is one party’s replay — the operator’s can only confirm the operator — so ' +
                    'this page has no default; enter the RPC of a node you run (an observer node is enough) to make this ' +
                    'comparison within minutes of the payout instead of waiting for the cemented payout',
            ),
        );
    } else {
        const first = fast[0];
        const storage = storageOf(first);
        const node = input.chain.rollupNode;

        if (storage === null) {
            checks.push(
                check(
                    PAYOUT_KERNEL_CHECK_ID,
                    'unavailable',
                    'the vault’s storage before the payout could not be read, so the tenant and pool the kernel keys the session under are unknown',
                ),
            );
        } else {
            progress('reading the kernel’s record from your rollup node…');

            try {
                const finalized = await node.finalizedLevel();

                if (finalized < first.level) {
                    checks.push(
                        check(
                            PAYOUT_KERNEL_CHECK_ID,
                            'unavailable',
                            `your rollup node has finalised level ${finalized}, below the payout’s level ${first.level}; its record is read only at ` +
                                'a finalised block, so try again once the node has caught up',
                        ),
                    );
                } else {
                    const finding = await checkFastPayoutAgainstKernel(
                        node,
                        storage.tenantId,
                        storage.poolId,
                        first.event.vault,
                        hyphenated,
                        first.event.amount,
                    );
                    const where = `the fast payout at level ${first.level} paid ${mutez(first.event.amount)}; the kernel’s record for session ${hyphenated} under ${storage.tenantId}/${storage.poolId}, read at your node’s finalised level ${finalized},`;

                    checks.push(kernelCheck(finding, where, first.event.amount));

                    if (finding.kind === 'above-kernel') {
                        overpaid = true;
                    }

                    if (finding.kind === 'backed' || finding.kind === 'short' || finding.kind === 'above-kernel') {
                        if (kernelFigure !== null && kernelFigure.amount !== finding.kernelAmount) {
                            findings.push(
                                `${kernelFigure.source} carries ${mutez(kernelFigure.amount)} but your rollup node’s record says ${mutez(finding.kernelAmount)}: ` +
                                    'the two kernel figures disagree, which no honest node and vault can produce; check the node',
                            );
                        }

                        kernelFigure ??= { amount: finding.kernelAmount, source: 'your rollup node’s record' };
                    }
                }
            } catch (error) {
                checks.push(
                    check(
                        PAYOUT_KERNEL_CHECK_ID,
                        'unavailable',
                        `your rollup node could not be read: ${errorText(error)}`,
                    ),
                );
            }
        }
    }

    // ── The outcome ─────────────────────────────────────────────────────
    const failed = checks.some((c) => c.status === 'fail');
    let outcome: PayoutOutcome;

    if (overpaid) {
        outcome = 'overpaid';
    } else if (failed) {
        outcome = 'unbacked';
    } else if (fast.length === 0) {
        outcome = 'backed';
    } else if (kernelFigure === null) {
        outcome = 'pending';
    } else {
        outcome = fast[0].event.amount < kernelFigure.amount ? 'short' : 'backed';
    }

    return {
        sessionId: hyphenated,
        outcome,
        checks,
        events: events.map(summarise),
        payoutSigners,
        findings,
        references: events.map(reference),
    };
}

function kernelCheck(finding: KernelFinding, where: string, paid: bigint): Check {
    switch (finding.kind) {
        case 'backed':
            return check(
                PAYOUT_KERNEL_CHECK_ID,
                'pass',
                `${where} is a session-end payout of ${mutez(finding.kernelAmount)}: the same amount`,
            );
        case 'short':
            return check(
                PAYOUT_KERNEL_CHECK_ID,
                'pass',
                `${where} is a session-end payout of ${mutez(finding.kernelAmount)}: the fast payout is ` +
                    `${mutez(finding.kernelAmount - paid)} short, and the cemented payout pays the remainder`,
            );
        case 'above-kernel':
            return check(
                PAYOUT_KERNEL_CHECK_ID,
                'fail',
                `${where} is a session-end payout of ${mutez(finding.kernelAmount)}: the fast payout exceeds it, an overpayment two signers authorised and the kernel does not back`,
            );
        case 'session-not-recorded':
            return check(
                PAYOUT_KERNEL_CHECK_ID,
                'fail',
                `${where} does not exist: the kernel has no record of this session under the paying vault’s tenant and pool`,
            );
        case 'session-not-ended':
            return check(
                PAYOUT_KERNEL_CHECK_ID,
                'fail',
                `${where} shows the session NOT ended: the kernel has not computed a payout for it, yet the vault paid one`,
            );
        case 'funding-vault-mismatch':
            return check(
                PAYOUT_KERNEL_CHECK_ID,
                'fail',
                `${where} names ${finding.recorded} as the vault that funded the session, not the vault that paid`,
            );
        case 'session-asset-not-tez':
            return check(
                PAYOUT_KERNEL_CHECK_ID,
                'fail',
                `${where} is a ${finding.asset} session; a fast payout pays TEZ only`,
            );
        case 'payout-not-recorded':
            return check(
                PAYOUT_KERNEL_CHECK_ID,
                'fail',
                `${where} shows the session ended with NO payout record: the kernel owes it nothing, yet the vault paid`,
            );
        case 'payout-record-not-a-session-end-payout':
            return check(
                PAYOUT_KERNEL_CHECK_ID,
                'fail',
                `${where} holds a ${finding.recordKind} row at the payout key, not the session-end payout`,
            );
        case 'corrupt-record':
            return check(
                PAYOUT_KERNEL_CHECK_ID,
                'fail',
                `${where} does not decode at ${finding.key}: ${finding.reason}`,
            );
    }
}

function errorText(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}
