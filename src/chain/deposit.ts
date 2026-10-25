/**
 * Locating the session's deposit on L1.
 *
 * The suppression ladder's lower bound is the level of the session's own
 * deposit operation (§8.3(d)): no round can SETTLE before the deposit; a copy
 * posted earlier is applied as a session-missing reject (rollup `rounds.rs`,
 * step 8). A scan starting after it cannot honestly claim "the transcript is
 * nowhere in range".
 *
 * THE VERIFIER FINDS THE DEPOSIT ITSELF. The export carries an optional
 * `depositOperationLevel`, but the shipped client never writes one — and even
 * when a level is present, a bracket the player supplies is a bracket the
 * player can widen, and the one accusatory verdict must not rest on it. So the
 * level is derived here from L1: the pool's vault contract comes from the
 * administrator lineage's `RegisterPoolVault` operations, and the vault's
 * `deposit` entrypoint takes `session_id` as a parameter field, so the
 * indexer can be asked for exactly that session's deposits. The export's hint
 * is reported alongside the derived level as a cross-check and never used as
 * a bound.
 *
 * The session's FIRST deposit is the bound: it is the one that binds
 * `(owner, session_public_key)` in the vault's `sessions` big_map and moves
 * the session to `active`. Top-ups are later and irrelevant to the lower
 * bound, so the lowest matching level wins.
 *
 * TzKT's `parameter.<field>` filter does the selection server-side (measured
 * live on shadownet 2026-09-12: `parameter.session_id=b191ce…50e0` on
 * KT1GCjZwMGnZhJzGw36rm8gyKeh2ZJe9vjNE returns the two deposits of that
 * session, and a session id that never existed returns `[]`). The filter is
 * still re-checked against each row's own parameter here, for the same reason
 * the lineage walk re-checks `sender=`: an indexer that silently ignored an
 * unknown filter would otherwise hand back every deposit on the contract and
 * the lowest one would become someone else's bound.
 */
import { blake2b } from '@noble/hashes/blake2.js';
import { encodeScriptExprHash } from '../wire/signature';
import { type AdminLineage, vaultsForPool } from './admin-lineage';
import type { InboxMessage, RpcManagerOperation, RpcManagerOperationGroup } from './inbox';

export interface DepositLocation {
    /**
     * `found`: the indexer returned an applied deposit naming the session (the
     * lowest one is kept). `none`: every vault was paged to the end with no
     * match. `failed`: the lookup could not be made, or its answer could not be
     * trusted; `detail` says why. Only `found` carries a level.
     */
    lookup: 'found' | 'none' | 'failed';
    /** L1 level of the session's first deposit; null unless `found`. */
    level: number | null;
    operationHash: string | null;
    /** The vault it landed on. */
    vault: string | null;
    /**
     * The NODE shows this deposit wrote the vault's `sessions` entry for the
     * session, i.e. it is the session-creating deposit on that vault. Never
     * set from the indexer alone; see {@link resolveSessionDeposit}.
     */
    firstProven: boolean;
    /**
     * Whether any OTHER vault of the signed pool, registered at or before the
     * transcript, could have created the session first. `clear` only when the
     * node shows none of them holds a `sessions` entry for it (or there is no
     * other vault). Null when it was not asked: no proven first deposit above
     * the transcript.
     */
    otherVaults: { clear: boolean; detail: string } | null;
    /** Why, either way — this goes straight into the report. */
    detail: string;
}

interface TzktDepositOperation {
    id: number;
    level: number;
    hash: string;
    parameter: { entrypoint: string; value: unknown } | null;
}

export interface LocateDepositOptions {
    tzktApiUrl: string;
    /** Candidate vaults for the pool, from `vaultsForPool`. */
    vaultAddresses: string[];
    /** Hyphenated session id, taken from the SIGNED frames. */
    sessionIdHex: string;
    /**
     * The export's `depositOperationLevel`, when it carries one. A HINT: it is
     * cross-checked against the derived level and reported, never substituted
     * for it. The shipped client writes no such field, which is precisely why
     * the derivation above cannot depend on it.
     */
    levelHint?: number | null;
    signal?: AbortSignal;
    fetchImpl?: typeof fetch;
}

const PAGE_SIZE = 1000;

/**
 * Find the session's first `deposit` on any of the pool's vaults.
 *
 * One indexer query per vault, paged by `id.gt` so a busy contract's history
 * is never truncated at a page boundary.
 */
export async function locateSessionDeposit(options: LocateDepositOptions): Promise<DepositLocation> {
    const absent = (lookup: 'none' | 'failed', detail: string): DepositLocation => ({
        lookup,
        level: null,
        operationHash: null,
        vault: null,
        firstProven: false,
        otherVaults: null,
        detail,
    });

    if (options.vaultAddresses.length === 0) {
        return absent('failed', 'no vault is registered on-chain for this pool, so there is no contract to look for the deposit on');
    }

    // The vault types `session_id` as `sp.bytes` of length 16, and TzKT
    // renders Michelson bytes as bare lowercase hex — no `0x`.
    const needle = options.sessionIdHex.replaceAll('-', '').toLowerCase();
    const doFetch = options.fetchImpl ?? fetch;
    const base = options.tzktApiUrl.replace(/\/$/, '');

    let best: { level: number; hash: string; vault: string } | null = null;
    let ignoredOperationCount = 0;

    for (const vault of options.vaultAddresses) {
        let lastId = 0;

        for (;;) {
            const url =
                `${base}/v1/operations/transactions` +
                `?target=${encodeURIComponent(vault)}&entrypoint=deposit&status=applied` +
                `&parameter.session_id=${encodeURIComponent(needle)}` +
                `&select=id,level,hash,parameter&sort=id&limit=${PAGE_SIZE}` +
                (lastId ? `&id.gt=${lastId}` : '');

            let page: TzktDepositOperation[];

            try {
                const response = await doFetch(url, { signal: options.signal });

                if (!response.ok) {
                    return absent('failed', `the indexer returned ${response.status} while looking for the session's deposit`);
                }

                page = (await response.json()) as TzktDepositOperation[];
            } catch (error) {
                return absent('failed', `the session's deposit could not be looked up: ${errorText(error)}`);
            }

            for (const operation of page) {
                lastId = Math.max(lastId, operation.id);

                // Re-check the indexer's own filter (see the header): a row
                // whose parameter does not name this session is not evidence,
                // whatever the query asked for.
                if (!namesSession(operation.parameter?.value, needle)) {
                    ignoredOperationCount += 1;
                    continue;
                }

                if (!best || operation.level < best.level) {
                    best = { level: operation.level, hash: operation.hash, vault };
                }
            }

            if (page.length < PAGE_SIZE) {
                break;
            }
        }
    }

    const ignoredNote =
        ignoredOperationCount > 0
            ? ` (${ignoredOperationCount} row(s) the indexer returned did not name this session and were ignored)`
            : '';

    if (!best) {
        return absent(
            'none',
            `no applied deposit naming session ${options.sessionIdHex} was found on ${options.vaultAddresses.join(', ')}` +
                `${ignoredNote} — without it the range has no L1-anchored lower bound`,
        );
    }

    return {
        lookup: 'found',
        level: best.level,
        operationHash: best.hash,
        vault: best.vault,
        firstProven: false,
        otherVaults: null,
        detail:
            `first deposit for session ${options.sessionIdHex} found at level ${best.level} (op ${best.hash}) on vault ` +
            `${best.vault}${ignoredNote}${describeHint(options.levelHint ?? null, best.level)}`,
    };
}

/**
 * What the export claimed, against what L1 says. Stated rather than acted on:
 * a disagreement is a finding about the export, and the derived level is the
 * bound either way.
 */
function describeHint(hint: number | null, derived: number): string {
    if (hint === null) {
        return '. The export carried no depositOperationLevel hint; none is needed — this level is derived from L1.';
    }

    return hint === derived
        ? `. The export's depositOperationLevel hint (${hint}) agrees.`
        : `. NOTE: the export's depositOperationLevel hint says ${hint}, which is not where L1 puts the session's first deposit; the derived level is used.`;
}

/**
 * Whether a TzKT-rendered `deposit` parameter names this session.
 *
 * Matching the 32-hex session id anywhere in the rendered record, rather than
 * reaching for `value.session_id`, so a change in how the indexer shapes the
 * JSON cannot silently turn every row into a non-match. A 16-byte UUID does
 * not collide with the record's other fields (base58 keys and signatures and
 * an RFC 3339 authorisation expiry, nothing else).
 */
function namesSession(value: unknown, needle: string): boolean {
    return JSON.stringify(value ?? null)
        .toLowerCase()
        .includes(needle);
}

// ── The session-creating deposit (the `session-before-transcript` check) ──

/** The node reads the deposit proof needs; the shell passes the RPC, a test passes stubs. */
export interface DepositNode {
    /** `operations/3` of one block, receipts included. */
    blockOperations(level: number): Promise<RpcManagerOperationGroup[]>;
    /** A contract's storage at head, as Micheline JSON. */
    contractStorage(address: string): Promise<unknown>;
    /** Whether a big_map holds a key at head: true on 200, false on 404; throws on any other answer. */
    bigMapHas(bigMapId: string, scriptExprHash: string): Promise<boolean>;
}

/** {@link DepositNode} plus the indexer's search, i.e. {@link locateSessionDeposit} over the given vaults. */
export interface DepositChain extends DepositNode {
    locateDeposit(vaultAddresses: string[], sessionIdHex: string, levelHint?: number | null): Promise<DepositLocation>;
}

export interface SessionDepositInput {
    /**
     * The transcript copy the check judges: the earliest AUTHENTICATED one
     * (`selectEarliestAuthenticated`). Its envelope is signed, so its tenant
     * and pool decide the vault set and its session id is the needle.
     */
    transcript: InboxMessage;
    lineage: AdminLineage | null;
    /** The form's pool field, '' when empty. Compared with the signed pool, never used to pick vaults. */
    formPoolId: string;
    chain: DepositChain;
}

/**
 * Find the session's earliest deposit for the transcript copy `earliest()`
 * chose, and prove on the node what it is.
 *
 * Three steps, each of which can only take evidence away:
 *
 *   1. The indexer search, over every vault the lineage ever registered for
 *      the SIGNED tenant and pool. The form's pool is an unsigned exporter
 *      label or hand-typed, so a form that names another pool fails the
 *      lookup instead of choosing the vaults.
 *   2. The node confirms the indexer's row: the block at that level holds an
 *      applied `deposit` call to that vault, in that operation, naming the
 *      session. Otherwise the two disagree and the lookup fails.
 *   3. `firstProven`: the call's TOP-LEVEL receipt writes the vault's
 *      `sessions` big_map at this session's key with a value. The production
 *      vault writes that entry only on a session's first deposit and never
 *      deletes it, so the write is the node's own proof that this deposit
 *      created the session on that vault (its other big_map, the `paid`
 *      ledger, is listed in the same receipt and told apart by id). A write
 *      inside `internal_operation_results` (a deposit routed through a
 *      contract wallet) is not read, and a vault with no `sessions` big_map
 *      (the preview vault binds statelessly on every deposit) never proves
 *      it.
 *
 * "First" is per vault, and the kernel binds a session to one vault for life.
 * When the proven first deposit lies above the transcript, every OTHER vault
 * of the pool registered at or before the transcript is looked up at head:
 * an entry there means the session may have been created earlier on that
 * vault, at a deposit the indexer did not return. Entries are never deleted,
 * so "no entry at head" means "never bound there".
 */
export async function resolveSessionDeposit(input: SessionDepositInput): Promise<DepositLocation> {
    const failed = (detail: string): DepositLocation => ({
        lookup: 'failed',
        level: null,
        operationHash: null,
        vault: null,
        firstProven: false,
        otherVaults: null,
        detail,
    });
    const { envelope, level: transcriptLevel } = input.transcript;
    const message = envelope.message;

    if (message.kind !== 'round-transcript') {
        return failed('the chosen message is not a RoundTranscript, so there is no session id to look up');
    }

    if (input.formPoolId && input.formPoolId !== envelope.poolId) {
        return failed(`the form names pool ${input.formPoolId}, the signed transcript names pool ${envelope.poolId}`);
    }

    if (!input.lineage) {
        return failed(
            "no administrator lineage was derived (a typed override key carries none), so the signed pool's vaults are unknown",
        );
    }

    const lineage = input.lineage;
    let located: DepositLocation;

    try {
        located = await input.chain.locateDeposit(
            vaultsForPool(lineage, envelope.tenantId, envelope.poolId),
            message.sessionId,
        );
    } catch (error) {
        return failed(`the session's deposit could not be looked up: ${errorText(error)}`);
    }

    if (located.lookup !== 'found' || located.level === null || located.vault === null || !located.operationHash) {
        return located;
    }

    const level = located.level;
    const vault = located.vault;
    const needle = message.sessionId.replaceAll('-', '').toLowerCase();
    let call: RpcManagerOperation | undefined;

    try {
        const groups = await input.chain.blockOperations(level);

        call = groups
            .filter((group) => group.hash === located.operationHash)
            .flatMap((group) => group.contents)
            .find(
                (content) =>
                    content.kind === 'transaction' &&
                    content.destination === vault &&
                    content.parameters?.entrypoint === 'deposit' &&
                    content.metadata?.operation_result?.status === 'applied' &&
                    namesSession(content.parameters.value, needle),
            );
    } catch (error) {
        return failed(`the node could not read block ${level} to confirm the indexer's deposit: ${errorText(error)}`);
    }

    if (!call) {
        return failed(
            `indexer and node disagree: the indexer reports a deposit naming session ${message.sessionId} at level ` +
                `${level} (op ${located.operationHash}) on ${vault}, but the node's block ${level} holds no applied ` +
                'deposit call of that operation to that vault naming the session',
        );
    }

    let sessionsId: string | null;

    try {
        sessionsId = sessionsBigMapId(await input.chain.contractStorage(vault));
    } catch (error) {
        return failed(`the node could not read the storage of vault ${vault}: ${errorText(error)}`);
    }

    const firstProven = sessionsId !== null && writesSessionEntry(call, sessionsId, needle);
    const confirmed =
        `${located.detail} The node confirms it: block ${level} holds the applied deposit call. ` +
        (sessionsId === null
            ? `Vault ${vault} keeps no sessions big_map (a vault that records no binding, such as the preview vault), so the node cannot show this deposit created the session.`
            : firstProven
              ? `Its receipt writes the vault's sessions big_map ${sessionsId} at this session's key, which the vault does only on a session's first deposit.`
              : `Its receipt does not write the vault's sessions big_map ${sessionsId} at this session's key, so it is not shown to be the session-creating deposit (a top-up, or a call routed through a contract).`);
    const otherVaults =
        firstProven && level > transcriptLevel
            ? await checkOtherVaults(input.chain, lineage, envelope.tenantId, envelope.poolId, vault, transcriptLevel, needle)
            : null;

    return { ...located, firstProven, otherVaults, detail: confirmed };
}

/**
 * Rule 4: does any other production vault of the pool, registered at or
 * before the transcript, hold a `sessions` entry for the session at head?
 */
async function checkOtherVaults(
    node: DepositNode,
    lineage: AdminLineage,
    tenantId: string,
    poolId: string,
    foundOn: string,
    transcriptLevel: number,
    needle: string,
): Promise<{ clear: boolean; detail: string }> {
    const others = [
        ...new Set(
            lineage.vaults
                .filter(
                    (v) =>
                        v.tenantId === tenantId &&
                        v.poolId === poolId &&
                        v.vault !== foundOn &&
                        v.level <= transcriptLevel,
                )
                .map((v) => v.vault),
        ),
    ];

    if (others.length === 0) {
        return {
            clear: true,
            detail: `no other vault of pool ${poolId} was registered at or before level ${transcriptLevel}`,
        };
    }

    const expr = sessionKeyScriptExprHash(needle);
    const problems: string[] = [];

    for (const other of others) {
        try {
            const id = sessionsBigMapId(await node.contractStorage(other));

            if (id === null) {
                problems.push(`vault ${other} keeps no sessions big_map (a preview or non-production vault), so it cannot be ruled out`);
            } else if (await node.bigMapHas(id, expr)) {
                problems.push(`vault ${other} holds a sessions entry for this session (big_map ${id}, key ${expr})`);
            }
        } catch (error) {
            problems.push(`vault ${other} could not be looked up: ${errorText(error)}`);
        }
    }

    return problems.length === 0
        ? {
              clear: true,
              detail: `no other vault of pool ${poolId} registered at or before level ${transcriptLevel} holds a sessions entry for this session at head (${others.join(', ')})`,
          }
        : { clear: false, detail: problems.join('; ') };
}

/**
 * The production vault's storage is a right-comb pair of thirteen leaves in
 * SmartPy's alphabetical field order: `admin_address`, `deposit_authoriser`,
 * `paid`, `paused`, `payout_signer_nonce`, `payout_signers`,
 * `pending_admin_address`, `pool_id`, `sessions`, `smart_rollup_address`,
 * `tenant_id`, `total_deposits`, `treasury`. Only the current generation is
 * read: nothing is deployed, every vault on the rollups `networks.json` lists
 * has this shape, and an older comb is some other contract. A new generation
 * moves both constants (the index by one when the added field sorts before
 * `sessions`) and re-captures `testdata/shadownet-treasury-vault-storage.json`.
 */
const PRODUCTION_VAULT_LEAF_COUNT = 13;
const SESSIONS_LEAF_INDEX = 8;

/**
 * The production vault's `sessions` big_map id from its storage, or null for
 * any other contract.
 *
 * The node renders the big_map as `{ "int": "<id>" }` at
 * {@link SESSIONS_LEAF_INDEX}. The leaf count is checked because the preview
 * vault (nine fields, no big_map) carries an `int` near that place too, and
 * must read as null.
 */
export function sessionsBigMapId(storage: unknown): string | null {
    const leaves = combLeaves(storage);
    const leaf = leaves.length === PRODUCTION_VAULT_LEAF_COUNT ? (leaves[SESSIONS_LEAF_INDEX] as { int?: unknown } | undefined) : undefined;

    return typeof leaf?.int === 'string' && /^\d+$/.test(leaf.int) ? leaf.int : null;
}

/** The leaves of a right-comb pair, in either the nested or the flattened Micheline form. */
function combLeaves(node: unknown): unknown[] {
    const args = Array.isArray(node)
        ? node
        : (node as { prim?: unknown; args?: unknown[] } | null)?.prim === 'Pair'
          ? (node as { args?: unknown[] }).args
          : undefined;

    if (!args || args.length < 2) {
        return [node];
    }

    return [...args.slice(0, -1), ...combLeaves(args[args.length - 1])];
}

/**
 * Whether a deposit call's TOP-LEVEL receipt writes `big_map <id>` at the
 * session's key with a value (an absent value is a removal). Writes under
 * `internal_operation_results` are deliberately not read.
 */
export function writesSessionEntry(call: RpcManagerOperation, bigMapId: string, sessionHex: string): boolean {
    const needle = sessionHex.replaceAll('-', '').toLowerCase();

    return (call.metadata?.operation_result?.lazy_storage_diff ?? []).some(
        (entry) =>
            entry.kind === 'big_map' &&
            entry.id === bigMapId &&
            entry.diff.action === 'update' &&
            (entry.diff.updates ?? []).some(
                (update) =>
                    (update.key as { bytes?: unknown } | undefined)?.bytes === needle &&
                    update.value !== undefined &&
                    update.value !== null,
            ),
    );
}

/**
 * The node's `script_expr_hash` of a `sessions` key: the key type is `bytes`,
 * so PACK is `0x05 ‖ 0x0a ‖ u32be(16) ‖ <16 session-id bytes>`, hashed with
 * blake2b-256 and base58check-encoded with the `expr` prefix. A measurement,
 * not a derivation taken on faith: `deposit.test.ts` pins it against a real
 * shadownet `sessions` entry and the hash the node reported for it.
 */
export function sessionKeyScriptExprHash(sessionHex: string): string {
    const hex = sessionHex.replaceAll('-', '').toLowerCase();

    if (!/^[0-9a-f]{32}$/.test(hex)) {
        throw new RangeError(`a session id is 16 bytes, got "${sessionHex}"`);
    }

    const packed = new Uint8Array(6 + 16);

    packed.set([0x05, 0x0a, 0, 0, 0, 16], 0);

    for (let i = 0; i < 16; i++) {
        packed[6 + i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }

    return encodeScriptExprHash(blake2b(packed, { dkLen: 32 }));
}

/** A vault contract's storage at head, from the node. */
export async function fetchContractStorage(rpcUrl: string, address: string, signal?: AbortSignal): Promise<unknown> {
    const url = `${rpcUrl.replace(/\/$/, '')}/chains/main/blocks/head/context/contracts/${address}/storage`;
    const response = await fetch(url, { signal });

    if (!response.ok) {
        throw new Error(`RPC ${response.status} for ${url}`);
    }

    return response.json();
}

/** Whether a big_map holds a key at head: 200 is an entry, 404 is none, anything else throws. */
export async function fetchBigMapHas(
    rpcUrl: string,
    bigMapId: string,
    scriptExprHash: string,
    signal?: AbortSignal,
): Promise<boolean> {
    const url = `${rpcUrl.replace(/\/$/, '')}/chains/main/blocks/head/context/big_maps/${bigMapId}/${scriptExprHash}`;
    const response = await fetch(url, { signal });

    if (response.status === 404) {
        return false;
    }

    if (!response.ok) {
        throw new Error(`RPC ${response.status} for ${url}`);
    }

    return true;
}

function errorText(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}
