/**
 * Comparing a fast payout with what the kernel recorded, read from the
 * READER'S OWN rollup node at its finalised block.
 *
 * The records and keys are the ones the validator signs from: the session
 * at `/tenants/{tenant}/pools/{pool}/sessions/{id}` and its payout at
 * `…/transactions/TEZ/payout-{id}`. A fast payout is sound only when the
 * session exists, has ended, was funded through the vault that paid, is a
 * TEZ session, and the row at its payout key is the kernel's session-end
 * payout (the session's balance leaving the rollup) of at least the amount
 * paid. Anything else is a finding: the fast path paid a number the kernel
 * does not back.
 *
 * Paying LESS than the kernel's number is not a finding. The cemented payout
 * tops it up to the kernel's figure, so the player's floor is unaffected.
 *
 * The records are Borsh, in a one-byte versioned envelope (`00` = V1). The
 * layouts here are the kernel's frozen V1 ones, pinned by `kernel.test.ts`
 * against values recorded off a rollup node by the public payout watcher's
 * own fixtures.
 */
import { BorshError, BorshReader } from '@99dot5/round-replay';
import type { RollupNodeReads } from './rollup-node';

/** The only asset a fast payout pays in: the vault's `mutez` is the kernel's atomic unit 1:1. */
export const TEZ = 'TEZ';

/** The durable key of a session's record. */
export function sessionKey(tenant: string, pool: string, sessionId: string): string {
    return `/tenants/${tenant}/pools/${pool}/sessions/${sessionId}`;
}

/**
 * The durable key of a session's payout record: the kernel's
 * `payout-{session_id}` reference under the pool's transaction ledger for
 * `asset`. The row there is the session-end payout `EndSession` writes.
 */
export function payoutKey(tenant: string, pool: string, asset: string, sessionId: string): string {
    return `/tenants/${tenant}/pools/${pool}/transactions/${asset}/payout-${sessionId}`;
}

export interface StoredSession {
    owner: string;
    asset: string;
    /** Atomic units of `asset`. */
    balance: bigint;
    /** The vault that accepted the first deposit; the session's payout targets it for life. */
    fundingVaultAddress: string;
    /** The kernel processed `EndSession` and queued the payout. */
    ended: boolean;
    endReason: string | null;
}

/** The kinds of the kernel's transaction rows, in the kernel's declaration order. */
export const TRANSACTION_KINDS = [
    'deposit',
    'session-end-payout',
    'stake',
    'round-end-payout',
    'fund',
    'sweep',
] as const;

export type TransactionKind = (typeof TRANSACTION_KINDS)[number];

export interface StoredTransaction {
    accountAddress: string;
    asset: string;
    kind: TransactionKind;
    /** Atomic units of `asset`. */
    amount: bigint;
}

const V1 = 0;

function bool(reader: BorshReader): boolean {
    const byte = reader.u8();

    if (byte > 1) {
        throw new BorshError(`a bool is 0 or 1, found ${byte}`);
    }

    return byte === 1;
}

function optionString(reader: BorshReader): string | null {
    const tag = reader.u8();

    if (tag > 1) {
        throw new BorshError(`an option tag is 0 or 1, found ${tag}`);
    }

    return tag === 1 ? reader.string() : null;
}

function envelopeV1(reader: BorshReader, what: string): void {
    const version = reader.u8();

    if (version !== V1) {
        throw new BorshError(`${what}: envelope version ${version} is not the V1 this reader knows`);
    }
}

/** Decode a `StoredSessionEnvelope` (V1). */
export function decodeStoredSession(bytes: Uint8Array): StoredSession {
    const reader = new BorshReader(bytes);

    envelopeV1(reader, 'session record');

    const session: StoredSession = {
        owner: reader.string(),
        asset: reader.string(),
        balance: reader.u128(),
        fundingVaultAddress: reader.string(),
        ended: bool(reader),
        endReason: optionString(reader),
    };

    reader.expectEnd();

    return session;
}

/** Decode a `StoredTransactionEnvelope` (V1). */
export function decodeStoredTransaction(bytes: Uint8Array): StoredTransaction {
    const reader = new BorshReader(bytes);

    envelopeV1(reader, 'transaction record');

    const accountAddress = reader.string();
    const asset = reader.string();
    const kindTag = reader.u8();
    const kind = TRANSACTION_KINDS[kindTag];

    if (kind === undefined) {
        throw new BorshError(`transaction kind tag ${kindTag} is not one this reader knows`);
    }

    const amount = reader.u128();

    reader.expectEnd();

    return { accountAddress, asset, kind, amount };
}

/** What the kernel's records say about one fast payout. */
export type KernelFinding =
    /** The kernel recorded exactly the amount paid: the payout is backed. */
    | { kind: 'backed'; kernelAmount: bigint }
    /** Paid less than the kernel recorded; the cemented payout tops it up. */
    | { kind: 'short'; kernelAmount: bigint }
    /** Paid MORE than the kernel recorded: the overpayment this check exists to prove. */
    | { kind: 'above-kernel'; kernelAmount: bigint }
    /** No session record under the paying vault's scope. */
    | { kind: 'session-not-recorded' }
    /** The session exists but the kernel has not ended it. */
    | { kind: 'session-not-ended' }
    /** The kernel recorded the session against another vault. */
    | { kind: 'funding-vault-mismatch'; recorded: string }
    /** The session is not a TEZ session; a fast payout pays TEZ only. */
    | { kind: 'session-asset-not-tez'; asset: string }
    /** The session ended with no payout record: the kernel owes nothing. */
    | { kind: 'payout-not-recorded' }
    /** The record at the payout key is not the session-end payout. */
    | { kind: 'payout-record-not-a-session-end-payout'; recordKind: TransactionKind }
    /** A record that does not decode as its envelope. */
    | { kind: 'corrupt-record'; key: string; reason: string };

/**
 * Compare a fast payout of `amount` mutez on `vault` with the kernel's
 * records for `sessionId` (hyphenated) under `(tenant, pool)`.
 */
export async function checkFastPayoutAgainstKernel(
    node: RollupNodeReads,
    tenant: string,
    pool: string,
    vault: string,
    sessionId: string,
    amount: bigint,
): Promise<KernelFinding> {
    const sessionAt = sessionKey(tenant, pool, sessionId);
    const sessionBytes = await node.durableValue(sessionAt);

    if (sessionBytes === null) {
        return { kind: 'session-not-recorded' };
    }

    let session: StoredSession;

    try {
        session = decodeStoredSession(sessionBytes);
    } catch (error) {
        return { kind: 'corrupt-record', key: sessionAt, reason: errorText(error) };
    }

    if (!session.ended) {
        return { kind: 'session-not-ended' };
    }

    if (session.fundingVaultAddress !== vault) {
        return { kind: 'funding-vault-mismatch', recorded: session.fundingVaultAddress };
    }

    if (session.asset !== TEZ) {
        return { kind: 'session-asset-not-tez', asset: session.asset };
    }

    const payoutAt = payoutKey(tenant, pool, session.asset, sessionId);
    const payoutBytes = await node.durableValue(payoutAt);

    if (payoutBytes === null) {
        return { kind: 'payout-not-recorded' };
    }

    let record: StoredTransaction;

    try {
        record = decodeStoredTransaction(payoutBytes);
    } catch (error) {
        return { kind: 'corrupt-record', key: payoutAt, reason: errorText(error) };
    }

    if (record.kind !== 'session-end-payout') {
        return { kind: 'payout-record-not-a-session-end-payout', recordKind: record.kind };
    }

    if (amount > record.amount) {
        return { kind: 'above-kernel', kernelAmount: record.amount };
    }

    if (amount < record.amount) {
        return { kind: 'short', kernelAmount: record.amount };
    }

    return { kind: 'backed', kernelAmount: record.amount };
}

function errorText(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}
