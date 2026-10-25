/**
 * The vault's payout events, read out of one L1 block's operations, each
 * fast payout paired with the `fast_payout` call that carried its
 * signatures.
 *
 * Both payout paths emit a contract event naming the session, the amount
 * asked for, the amount paid now and the running total (the vault's paid
 * ledger):
 *
 *   | tag               | amount field | emitted by                                      |
 *   | ----------------- | ------------ | ----------------------------------------------- |
 *   | `fast_payout`     | `fast`       | `fast_payout(session_id, amount, signatures)`   |
 *   | `cemented_payout` | `cemented`   | `execute_cemented_payout((session_id, amount))` |
 *
 * An event is an internal operation result of the manager operation that
 * triggered it: the submitter's `transaction` for a fast payout, the
 * `smart_rollup_execute_outbox_message` for a cemented payout. The event is
 * what the vault DID; the `fast_payout` call's parameters, in the same
 * operation, are what it was SHOWN — the signatures that are re-verified.
 * Only `applied` results count: a reverted call changed nothing.
 */
import type { RpcManagerOperation, RpcManagerOperationGroup } from '../chain/inbox';
import { keyText, signatureText } from './keys';
import { asBytes, asMap, asNat, field, fields, MichelineError } from './micheline';
import type { SignatureEntry } from './signatures';

export const FAST_PAYOUT_TAG = 'fast_payout';
export const CEMENTED_PAYOUT_TAG = 'cemented_payout';

/** The vault entrypoint whose parameters carry the signatures. */
export const FAST_PAYOUT_ENTRYPOINT = 'fast_payout';

/**
 * The `fast_payout` entrypoint's parameter type, as the compiled vault
 * declares it: `pair (mutez %amount) (pair (bytes %session_id) (map
 * %signatures key signature))`. A node returns an operation's parameter
 * value without its type, so the type is pinned here; read by annotation
 * like everything else.
 */
export function fastPayoutParameterType(): unknown {
    return {
        prim: 'pair',
        args: [
            { prim: 'mutez', annots: ['%amount'] },
            {
                prim: 'pair',
                args: [
                    { prim: 'bytes', annots: ['%session_id'] },
                    { prim: 'map', args: [{ prim: 'key' }, { prim: 'signature' }], annots: ['%signatures'] },
                ],
            },
        ],
    };
}

export type PayoutPath = 'fast' | 'cemented';

export function payoutTag(path: PayoutPath): string {
    return path === 'fast' ? FAST_PAYOUT_TAG : CEMENTED_PAYOUT_TAG;
}

function amountField(path: PayoutPath): string {
    return path === 'fast' ? 'fast' : 'cemented';
}

/** The parameters of an applied `fast_payout` call. */
export interface FastPayoutCall {
    sessionId: Uint8Array;
    amount: bigint;
    signatures: SignatureEntry[];
}

/** One decoded payout event. */
export interface PayoutEvent {
    path: PayoutPath;
    vault: string;
    sessionId: Uint8Array;
    /** `fast` or `cemented`: the amount the path asked to pay, in mutez. */
    amount: bigint;
    paidNow: bigint;
    paidTotal: bigint;
    /** The operation group's hash: the reference of every finding about it. */
    operationHash: string;
    /** The chain the operation group was included on (`Net…`), when the node states it. */
    chainId: string | null;
    /**
     * For a fast payout, the call in the same operation naming the same
     * session; `null` when none was found, an error when one was found but
     * does not decode.
     */
    call: { ok: true; call: FastPayoutCall } | { ok: false; reason: string } | null;
}

/** What a block holds for the watched vaults. */
export type BlockItem =
    | { kind: 'event'; event: PayoutEvent }
    /** An applied payout event of a watched vault that did not decode: the vault moved money in a shape this reader cannot read. */
    | { kind: 'undecodable'; vault: string; tag: string; operationHash: string; reason: string };

type Json = Record<string, unknown>;

function isObject(node: unknown): node is Json {
    return typeof node === 'object' && node !== null && !Array.isArray(node);
}

function str(node: unknown, key: string): string | null {
    return isObject(node) && typeof node[key] === 'string' ? (node[key] as string) : null;
}

function statusApplied(node: unknown, resultKey: string): boolean {
    return isObject(node) && str(node[resultKey], 'status') === 'applied';
}

/** `(vault, parameter value)` when `node` is a transaction to a watched vault's `fast_payout` entrypoint. */
function fastPayoutCallOf(node: unknown, vaults: ReadonlySet<string>): [string, unknown] | null {
    if (!isObject(node) || node.kind !== 'transaction') {
        return null;
    }

    const vault = str(node, 'destination');

    if (vault === null || !vaults.has(vault)) {
        return null;
    }

    const parameters = node.parameters;

    if (!isObject(parameters) || parameters.entrypoint !== FAST_PAYOUT_ENTRYPOINT || !('value' in parameters)) {
        return null;
    }

    return [vault, parameters.value];
}

function sessionIdOf(node: unknown): Uint8Array {
    const bytes = asBytes(node);

    if (bytes.length !== 16) {
        throw new MichelineError(`a session id is 16 bytes, found ${bytes.length}`);
    }

    return bytes;
}

/** Decode a `fast_payout` call's parameter value. */
export function decodeFastPayoutCall(value: unknown): FastPayoutCall {
    const found = fields(fastPayoutParameterType(), value);
    const signatures = asMap(field(found, 'signatures')).map(([key, signature]) => ({
        publicKey: keyText(key),
        signature: signatureText(signature),
    }));

    return {
        sessionId: sessionIdOf(field(found, 'session_id')),
        amount: asNat(field(found, 'amount')),
        signatures,
    };
}

function decodeEvent(
    path: PayoutPath,
    ty: unknown,
    payload: unknown,
): { sessionId: Uint8Array; amount: bigint; paidNow: bigint; paidTotal: bigint } {
    const found = fields(ty, payload);

    return {
        sessionId: sessionIdOf(field(found, 'session_id')),
        amount: asNat(field(found, amountField(path))),
        paidNow: asNat(field(found, 'paid_now')),
        paidTotal: asNat(field(found, 'paid_total')),
    };
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
    return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

/**
 * The call to `vault` naming `sessionId`; a call that does not decode is
 * reported as such rather than skipped, so its signatures are never assumed.
 */
function findCall(calls: [string, unknown][], vault: string, sessionId: Uint8Array): PayoutEvent['call'] {
    let undecodable: PayoutEvent['call'] = null;

    for (const [to, value] of calls) {
        if (to !== vault) {
            continue;
        }

        try {
            const call = decodeFastPayoutCall(value);

            if (sameBytes(call.sessionId, sessionId)) {
                return { ok: true, call };
            }
        } catch (error) {
            undecodable = { ok: false, reason: error instanceof Error ? error.message : String(error) };
        }
    }

    return undecodable;
}

/**
 * Every payout event of a vault in `vaults` in this block, in block order.
 *
 * `groups` is the node's `/chains/main/blocks/{level}/operations/3` answer:
 * the block's manager operation groups, receipts included.
 */
export function scanBlockPayouts(
    groups: readonly RpcManagerOperationGroup[],
    vaults: ReadonlySet<string>,
): BlockItem[] {
    const items: BlockItem[] = [];

    for (const group of groups) {
        for (const content of group.contents) {
            scanContent(content, group.hash, group.chain_id ?? null, vaults, items);
        }
    }

    return items;
}

function scanContent(
    content: RpcManagerOperation,
    hash: string,
    chainId: string | null,
    vaults: ReadonlySet<string>,
    items: BlockItem[],
): void {
    const metadata = content.metadata;

    if (!metadata) {
        return;
    }

    const internal = metadata.internal_operation_results ?? [];
    // The fast_payout calls of this operation: the manager operation itself
    // (its status is in `metadata.operation_result`), or an internal
    // transaction (a contract batching the call; its status is in `result`).
    const calls: [string, unknown][] = [];

    if (metadata.operation_result?.status === 'applied') {
        const call = fastPayoutCallOf(content, vaults);

        if (call) {
            calls.push(call);
        }
    }

    for (const node of internal) {
        if (statusApplied(node, 'result')) {
            const call = fastPayoutCallOf(node, vaults);

            if (call) {
                calls.push(call);
            }
        }
    }

    for (const node of internal) {
        if (!isObject(node) || node.kind !== 'event' || !statusApplied(node, 'result')) {
            continue;
        }

        const vault = str(node, 'source');

        if (vault === null || !vaults.has(vault)) {
            continue;
        }

        const tag = str(node, 'tag') ?? '';
        const path: PayoutPath | null =
            tag === FAST_PAYOUT_TAG ? 'fast' : tag === CEMENTED_PAYOUT_TAG ? 'cemented' : null;

        if (path === null) {
            continue;
        }

        const undecodable = (reason: string): BlockItem => ({
            kind: 'undecodable',
            vault,
            tag,
            operationHash: hash,
            reason,
        });

        if (!('type' in node) || !('payload' in node)) {
            items.push(undecodable('the event carries no type or no payload'));
            continue;
        }

        let decoded;

        try {
            decoded = decodeEvent(path, node.type, node.payload);
        } catch (error) {
            items.push(undecodable(error instanceof Error ? error.message : String(error)));
            continue;
        }

        items.push({
            kind: 'event',
            event: {
                path,
                vault,
                ...decoded,
                operationHash: hash,
                chainId,
                call: path === 'fast' ? findCall(calls, vault, decoded.sessionId) : null,
            },
        });
    }
}
