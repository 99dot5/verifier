// @vitest-environment node
// Locating the session's deposit — the suppression ladder's lower bound.
//
// The query shape is not invented: it was probed live against shadownet on
// 2026-09-12, and the mock below reproduces what came back.
//
//   GET https://api.shadownet.tzkt.io/v1/operations/transactions
//       ?target=KT1GCjZwMGnZhJzGw36rm8gyKeh2ZJe9vjNE&entrypoint=deposit
//       &status=applied&parameter.session_id=b191ce6645534ddab02e45ed771550e0
//     → two rows, levels 4219556 and 4219565
//
//   …&parameter.session_id=00000000000000000000000000000000
//     → []
//
// The second query is what says the server-side filter is real rather than
// silently ignored; the client-side re-check below is what keeps the tool
// honest if an indexer ever does ignore it.
import { describe, expect, it } from 'vitest';
import type { AdminLineage } from './admin-lineage';
import {
    type DepositChain,
    locateSessionDeposit,
    resolveSessionDeposit,
    sessionKeyScriptExprHash,
    sessionsBigMapId,
    writesSessionEntry,
} from './deposit';
import type { InboxMessage, RpcManagerOperation, RpcManagerOperationGroup } from './inbox';
import firstDepositCapture from './testdata/shadownet-first-deposit.json';
import topUpCapture from './testdata/shadownet-top-up.json';
import sessionsEntryCapture from './testdata/shadownet-sessions-entry.json';
import treasuryVaultStorageCapture from './testdata/shadownet-treasury-vault-storage.json';

const TZKT = 'https://api.shadownet.tzkt.io';
const VAULT = 'KT1GCjZwMGnZhJzGw36rm8gyKeh2ZJe9vjNE';
const OTHER_VAULT = 'KT1V9p3YByfpVs1QWmnZPHTNHDy9XaNPLTqz';
const SESSION = 'b191ce66-4553-4dda-b02e-45ed771550e0';
const SESSION_HEX = 'b191ce6645534ddab02e45ed771550e0';

interface Row {
    id: number;
    level: number;
    hash: string;
    parameter: { entrypoint: 'deposit'; value: Record<string, string> } | null;
}

/** A row in the shape TzKT returns for a `deposit` call. */
function row(id: number, level: number, sessionHex: string): Row {
    return {
        id,
        level,
        hash: `op-${id}`,
        parameter: {
            entrypoint: 'deposit',
            value: {
                session_id: sessionHex,
                session_signature: 'edsigtzza9x2yMZaVc5zadtEsh6mgDDY8ZkNgM5PBvNx5ykKF5dYgSy4WU7JrAHkEzfQAP6o74yYKBtsQvDotwoV8BWw49h9L2y',
                session_public_key: 'edpkv5tf5wXgHDgfN6T4zvwRJshgHsgwmw76SSzp1V6pZSuNjJV9Er',
            },
        },
    };
}

/**
 * An indexer keyed by `target=`, which APPLIES the `parameter.session_id`
 * filter — the live behaviour. `requested` records every URL so a test can
 * assert what was asked for.
 */
function mockIndexer(byVault: Record<string, Row[]>, requested: string[] = []): typeof fetch {
    return ((url: string) => {
        requested.push(url);

        const query = new URL(url).searchParams;
        const wanted = query.get('parameter.session_id');
        const rows = (byVault[query.get('target') ?? ''] ?? []).filter(
            (r) => r.parameter?.value.session_id === wanted,
        );

        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(rows) } as Response);
    }) as unknown as typeof fetch;
}

describe('locateSessionDeposit', () => {
    it('derives the level from L1 with no hint at all', async () => {
        // The shipped client writes no `depositOperationLevel`, so this is the
        // ONLY path a real export takes.
        const located = await locateSessionDeposit({
            tzktApiUrl: TZKT,
            vaultAddresses: [VAULT],
            sessionIdHex: SESSION,
            fetchImpl: mockIndexer({ [VAULT]: [row(1, 4219556, SESSION_HEX), row(2, 4219565, SESSION_HEX)] }),
        });

        expect(located.level).toBe(4219556);
        expect(located.operationHash).toBe('op-1');
        expect(located.vault).toBe(VAULT);
        expect(located.detail).toContain('carried no depositOperationLevel hint');
    });

    it('asks the indexer for this session only, by parameter field', async () => {
        const requested: string[] = [];

        await locateSessionDeposit({
            tzktApiUrl: `${TZKT}/`,
            vaultAddresses: [VAULT],
            sessionIdHex: SESSION,
            fetchImpl: mockIndexer({ [VAULT]: [row(1, 4219556, SESSION_HEX)] }, requested),
        });

        expect(requested).toHaveLength(1);
        expect(requested[0]).toContain(`parameter.session_id=${SESSION_HEX}`);
        expect(requested[0]).toContain('entrypoint=deposit');
        expect(requested[0]).toContain('status=applied');
        // One trailing slash on the base URL must not become two.
        expect(requested[0]).not.toContain('//v1/');
    });

    it('takes the FIRST deposit across every vault of the pool', async () => {
        // Top-ups are later and irrelevant: the binding deposit is what moves
        // the session to `active`, so the lowest level is the bound.
        const located = await locateSessionDeposit({
            tzktApiUrl: TZKT,
            vaultAddresses: [VAULT, OTHER_VAULT],
            sessionIdHex: SESSION,
            fetchImpl: mockIndexer({
                [VAULT]: [row(2, 4219565, SESSION_HEX)],
                [OTHER_VAULT]: [row(1, 4219500, SESSION_HEX)],
            }),
        });

        expect(located.level).toBe(4219500);
        expect(located.vault).toBe(OTHER_VAULT);
    });

    it('reports no bound when the session has no deposit on any vault', async () => {
        const located = await locateSessionDeposit({
            tzktApiUrl: TZKT,
            vaultAddresses: [VAULT],
            sessionIdHex: SESSION,
            fetchImpl: mockIndexer({ [VAULT]: [row(1, 4219556, 'ffffffffffffffffffffffffffffffff')] }),
        });

        expect(located.lookup).toBe('none');
        expect(located.level).toBeNull();
        expect(located.detail).toContain('no applied deposit naming session');
    });

    it('ignores rows the indexer returned that do not name this session', async () => {
        // The `parameter.session_id=` filter is the indexer's claim about
        // itself. An indexer that ignored an unknown filter would hand back
        // every deposit on the contract, and the lowest would be somebody
        // else's bound — so each row is re-checked against its own parameter.
        const ignoring = ((url: string) => {
            const target = new URL(url).searchParams.get('target') ?? '';
            const rows =
                target === VAULT
                    ? [row(1, 4219000, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'), row(2, 4219556, SESSION_HEX)]
                    : [];

            return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(rows) } as Response);
        }) as unknown as typeof fetch;

        const located = await locateSessionDeposit({
            tzktApiUrl: TZKT,
            vaultAddresses: [VAULT],
            sessionIdHex: SESSION,
            fetchImpl: ignoring,
        });

        expect(located.level).toBe(4219556);
        expect(located.detail).toContain('1 row(s) the indexer returned did not name this session');
    });

    it('states a hint that disagrees with L1, and uses L1 anyway', async () => {
        const located = await locateSessionDeposit({
            tzktApiUrl: TZKT,
            vaultAddresses: [VAULT],
            sessionIdHex: SESSION,
            levelHint: 4_000_000,
            fetchImpl: mockIndexer({ [VAULT]: [row(1, 4219556, SESSION_HEX)] }),
        });

        expect(located.level).toBe(4219556);
        expect(located.detail).toContain('hint says 4000000');
    });

    it('has no bound when the pool has no registered vault', async () => {
        const located = await locateSessionDeposit({
            tzktApiUrl: TZKT,
            vaultAddresses: [],
            sessionIdHex: SESSION,
            fetchImpl: mockIndexer({}),
        });

        expect(located.lookup).toBe('failed');
        expect(located.level).toBeNull();
        expect(located.detail).toContain('no vault is registered on-chain for this pool');
    });

    it('reports an indexer error rather than inventing a bound', async () => {
        const failing = (() =>
            Promise.resolve({ ok: false, status: 503, json: () => Promise.resolve([]) } as Response)) as unknown as typeof fetch;

        const located = await locateSessionDeposit({
            tzktApiUrl: TZKT,
            vaultAddresses: [VAULT],
            sessionIdHex: SESSION,
            fetchImpl: failing,
        });

        expect(located.lookup).toBe('failed');
        expect(located.level).toBeNull();
        expect(located.detail).toContain('503');
    });
});

// ── The session-creating deposit: receipts captured from shadownet (D-9) ──
//
// Every shape the `firstProven` rule reads is pinned against REAL node
// output, captured read-only from the public shadownet node and indexer (the
// URLs are in each fixture's `capturedFrom`), all from the one vault the
// shadownet rollup's `networks.json` entry registers: its storage before any
// deposit (2026-10-24), then the first deposit of one session, a top-up of the
// same session, and that session's `sessions` entry with the script expression
// hash the node and the indexer report for its key (2026-10-25). A vault of
// this generation keeps two big_maps, `paid` and `sessions`, and a deposit
// receipt lists both; the rule matches the `sessions` one by id.

const REAL_VAULT = sessionsEntryCapture.vault;
const REAL_SESSION_HEX = sessionsEntryCapture.sessionIdHex;
const REAL_SESSION = '01a17098-a9b8-7c69-831c-42ce11cb8b0f';
/** The level of the `RegisterPoolVault` that registered the vault for the pool. */
const REAL_VAULT_REGISTERED_AT = 5_625_985;
/** The vault's other big_map, `paid` (ADR 0027's payout ledger), the third leaf of its storage. */
const PAID_BIG_MAP_ID = (sessionsEntryCapture.storageAtHead.args[2] as { int: string }).int;
const firstDepositGroup = firstDepositCapture.operationGroup as unknown as RpcManagerOperationGroup;
const topUpGroup = topUpCapture.operationGroup as unknown as RpcManagerOperationGroup;
const firstDepositCall = firstDepositGroup.contents[0];
const topUpCall = topUpGroup.contents[0];

/** The receipt's `lazy_storage_diff` entry for the vault's `sessions` big_map. */
function sessionsDiff(call: RpcManagerOperation) {
    return (call.metadata?.operation_result?.lazy_storage_diff ?? []).find((entry) => entry.id === sessionsEntryCapture.bigMapId);
}

describe('the deposit receipt shape (captured)', () => {
    it("reads the sessions big_map id from the current vault's storage, as captured", () => {
        expect(sessionsBigMapId(treasuryVaultStorageCapture.storageAtHead)).toBe(treasuryVaultStorageCapture.bigMapId);
        // The flattened sequence form a receipt renders agrees.
        expect(sessionsBigMapId(treasuryVaultStorageCapture.storageAtHead.args)).toBe(treasuryVaultStorageCapture.bigMapId);
    });

    it('reads the same id from the storage after the deposits, as captured', () => {
        expect(sessionsBigMapId(sessionsEntryCapture.storageAtHead)).toBe(sessionsEntryCapture.bigMapId);
        expect(sessionsEntryCapture.vault).toBe(treasuryVaultStorageCapture.vault);
    });

    it('reads it only from the current generation: an earlier comb, or one leaf more, is some other contract', () => {
        const current = treasuryVaultStorageCapture.storageAtHead.args as unknown[];

        // The generation before `treasury` was appended (twelve leaves).
        expect(sessionsBigMapId(current.slice(0, -1))).toBeNull();
        expect(sessionsBigMapId([...current, { int: '7' }])).toBeNull();
        // A thirteen-leaf comb whose sessions leaf is not an int.
        expect(sessionsBigMapId([...current.slice(0, 8), { prim: 'None' }, ...current.slice(9)])).toBeNull();
    });

    it('pins the first deposit: a top-level big_map update of the sessions id at the session key, with a value', () => {
        const diff = firstDepositCall.metadata?.operation_result?.lazy_storage_diff ?? [];
        const sessions = sessionsDiff(firstDepositCall);

        expect(firstDepositCall.destination).toBe(REAL_VAULT);
        expect(firstDepositCall.parameters?.entrypoint).toBe('deposit');
        // Both of the vault's big_maps are listed; only `sessions` is written.
        expect(diff.map((entry) => entry.id).sort()).toEqual([sessionsEntryCapture.bigMapId, PAID_BIG_MAP_ID].sort());
        expect(sessions).toMatchObject({ kind: 'big_map', id: sessionsEntryCapture.bigMapId, diff: { action: 'update' } });
        expect(sessions?.diff.updates).toHaveLength(1);
        expect(sessions?.diff.updates?.[0].key).toEqual({ bytes: REAL_SESSION_HEX });
        expect(sessions?.diff.updates?.[0].value).toBeDefined();
        expect(diff.find((entry) => entry.id === PAID_BIG_MAP_ID)?.diff.updates).toEqual([]);
        expect(writesSessionEntry(firstDepositCall, sessionsEntryCapture.bigMapId, REAL_SESSION)).toBe(true);
    });

    it('pins the top-up: the same big_maps are touched with NO update, so it proves nothing', () => {
        const diff = topUpCall.metadata?.operation_result?.lazy_storage_diff ?? [];

        expect(topUpCall.parameters?.entrypoint).toBe('deposit');
        expect(JSON.stringify(topUpCall.parameters?.value)).toContain(REAL_SESSION_HEX);
        expect(diff).toEqual([
            { kind: 'big_map', id: sessionsEntryCapture.bigMapId, diff: { action: 'update', updates: [] } },
            { kind: 'big_map', id: PAID_BIG_MAP_ID, diff: { action: 'update', updates: [] } },
        ]);
        expect(writesSessionEntry(topUpCall, sessionsEntryCapture.bigMapId, REAL_SESSION)).toBe(false);
    });

    it("derives the node's script expression hash for a sessions key (rule 4's lookup key)", () => {
        const derived = sessionKeyScriptExprHash(REAL_SESSION);

        expect(derived).toBe(sessionsEntryCapture.nodeScriptExprHash);
        expect(derived).toBe(sessionsEntryCapture.tzktKeyHash);
        // The receipt reports the same hash for the key it wrote.
        expect(sessionsDiff(firstDepositCall)?.diff.updates?.[0].key_hash).toBe(derived);
        expect(sessionKeyScriptExprHash(REAL_SESSION_HEX)).toBe(derived);
    });

    it('does not read a write that sits only under internal_operation_results (a contract-wallet deposit)', () => {
        const topLevel = firstDepositCall.metadata?.operation_result;
        const moved: RpcManagerOperation = {
            ...firstDepositCall,
            metadata: {
                operation_result: { ...topLevel, status: 'applied', lazy_storage_diff: undefined },
                internal_operation_results: [{ kind: 'transaction', result: topLevel }],
            },
        };

        expect(writesSessionEntry(moved, sessionsEntryCapture.bigMapId, REAL_SESSION)).toBe(false);
    });

    it('reads an update with no value as a removal, and another big_map or session as no write', () => {
        const withUpdate = (update: object, id = sessionsEntryCapture.bigMapId): RpcManagerOperation => ({
            ...firstDepositCall,
            metadata: {
                operation_result: {
                    status: 'applied',
                    lazy_storage_diff: [{ kind: 'big_map', id, diff: { action: 'update', updates: [update] } }],
                },
            },
        });

        expect(writesSessionEntry(withUpdate({ key: { bytes: REAL_SESSION_HEX } }), sessionsEntryCapture.bigMapId, REAL_SESSION)).toBe(false);
        expect(
            writesSessionEntry(withUpdate({ key: { bytes: REAL_SESSION_HEX }, value: {} }, '999'), sessionsEntryCapture.bigMapId, REAL_SESSION),
        ).toBe(false);
        expect(
            writesSessionEntry(withUpdate({ key: { bytes: 'ff'.repeat(16) }, value: {} }), sessionsEntryCapture.bigMapId, REAL_SESSION),
        ).toBe(false);
    });

    it('reads no sessions id from a preview vault (nine fields, no big_map, an int in the sessions place) or any other contract', () => {
        const preview = {
            prim: 'Pair',
            args: [
                { string: 'tz1dBStuxore6uR3E2s5NAhjSGc3EtpkwCp7' },
                [{ string: 'tz1g3LZAHCeHkW7hgmE2HuNX6xGE7JGJAe7X' }],
                { prim: 'False' },
                { prim: 'None' },
                { string: 'preview' },
                { int: '1000' },
                { string: 'sr1G1TRpqmwhJhHhH7Fx8ejxtAaRqptzCvBK' },
                { string: 'stg-99dot5-com-shadownet' },
                { int: '0' },
            ],
        };

        expect(sessionsBigMapId(preview)).toBeNull();
        expect(sessionsBigMapId({ prim: 'Unit' })).toBeNull();
        expect(sessionsBigMapId(null)).toBeNull();
    });
});

// ── resolveSessionDeposit: the lookup the session-before-transcript check reads (D-6) ──

const TRANSCRIPT_LEVEL = 5_629_000;

/** The chosen transcript copy, reduced to what the resolver reads off its signed envelope. */
function transcriptCopy(poolId = 'standard', level = TRANSCRIPT_LEVEL): InboxMessage {
    return {
        level,
        operationHash: 'op-transcript',
        messageIndex: 0,
        rawHex: '',
        envelope: {
            tenantId: 'stg-99dot5-com-shadownet',
            poolId,
            message: { kind: 'round-transcript', roundId: 'r', sessionId: REAL_SESSION },
        },
    } as unknown as InboxMessage;
}

function lineageWith(vaults: { vault: string; level: number; poolId?: string }[]): AdminLineage {
    return {
        administrators: [],
        keys: [],
        vaults: vaults.map((v) => ({
            tenantId: 'stg-99dot5-com-shadownet',
            poolId: v.poolId ?? 'standard',
            vault: v.vault,
            status: 'active',
            level: v.level,
            operationHash: `op-register-${v.vault}`,
        })),
        proposals: [],
        ambiguities: [],
        scannedOperationCount: 0,
        ignoredOperationCount: 0,
    };
}

/** A chain over the captured shadownet data: the indexer reports the first deposit, the node has its block. */
function capturedChain(overrides: Partial<DepositChain> & { indexer?: typeof fetch } = {}): DepositChain {
    return {
        locateDeposit: (vaultAddresses, sessionIdHex) =>
            locateSessionDeposit({
                tzktApiUrl: TZKT,
                vaultAddresses,
                sessionIdHex,
                fetchImpl:
                    overrides.indexer ??
                    mockIndexer({
                        [REAL_VAULT]: [
                            { id: 2, level: topUpCapture.level, hash: topUpGroup.hash, parameter: { entrypoint: 'deposit', value: { session_id: REAL_SESSION_HEX } } },
                            { id: 1, level: firstDepositCapture.level, hash: firstDepositGroup.hash, parameter: { entrypoint: 'deposit', value: { session_id: REAL_SESSION_HEX } } },
                        ],
                    }),
            }),
        blockOperations: async (level) =>
            level === firstDepositCapture.level ? [firstDepositGroup] : level === topUpCapture.level ? [topUpGroup] : [],
        contractStorage: async () => sessionsEntryCapture.storageAtHead,
        bigMapHas: async () => false,
        ...overrides,
    };
}

describe('resolveSessionDeposit', () => {
    it('found: the indexer and the node agree, and the receipt proves the deposit created the session', async () => {
        const located = await resolveSessionDeposit({
            transcript: transcriptCopy('standard', firstDepositCapture.level - 10),
            lineage: lineageWith([{ vault: REAL_VAULT, level: REAL_VAULT_REGISTERED_AT }]),
            formPoolId: '',
            chain: capturedChain(),
        });

        expect(located).toMatchObject({
            lookup: 'found',
            level: firstDepositCapture.level,
            operationHash: firstDepositGroup.hash,
            vault: REAL_VAULT,
            firstProven: true,
            otherVaults: { clear: true },
        });
        expect(located.detail).toContain('The node confirms it');
        expect(located.otherVaults?.detail).toContain('no other vault of pool standard');
    });

    it('found, not first: the indexer omits the first deposit and returns the top-up', async () => {
        const located = await resolveSessionDeposit({
            transcript: transcriptCopy('standard', firstDepositCapture.level),
            lineage: lineageWith([{ vault: REAL_VAULT, level: REAL_VAULT_REGISTERED_AT }]),
            formPoolId: 'standard',
            chain: capturedChain({
                indexer: mockIndexer({
                    [REAL_VAULT]: [{ id: 2, level: topUpCapture.level, hash: topUpGroup.hash, parameter: { entrypoint: 'deposit', value: { session_id: REAL_SESSION_HEX } } }],
                }),
            }),
        });

        expect(located).toMatchObject({ lookup: 'found', level: topUpCapture.level, firstProven: false, otherVaults: null });
        expect(located.detail).toContain('not shown to be the session-creating deposit');
    });

    it('none: every page exhausted with no row naming the session', async () => {
        const requested: string[] = [];
        // An indexer that ignores the filter: a full page of another session's
        // rows, then an empty page. Every page is read, none matches.
        const paging = ((url: string) => {
            requested.push(url);

            const rows = new URL(url).searchParams.get('id.gt')
                ? []
                : Array.from({ length: 1000 }, (_, i) => row(i + 1, 5_000_000 + i, 'ab'.repeat(16)));

            return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(rows) } as Response);
        }) as unknown as typeof fetch;
        const located = await resolveSessionDeposit({
            transcript: transcriptCopy(),
            lineage: lineageWith([{ vault: REAL_VAULT, level: REAL_VAULT_REGISTERED_AT }]),
            formPoolId: '',
            chain: capturedChain({ indexer: paging }),
        });

        expect(requested).toHaveLength(2);
        expect(requested[1]).toContain('id.gt=1000');
        expect(located.lookup).toBe('none');
    });

    const failures: { name: string; reason: string; input: () => Parameters<typeof resolveSessionDeposit>[0] }[] = [
        {
            name: 'HTTP 500 from the indexer',
            reason: 'the indexer returned 500',
            input: () => ({
                transcript: transcriptCopy(),
                lineage: lineageWith([{ vault: REAL_VAULT, level: 1 }]),
                formPoolId: '',
                chain: capturedChain({
                    indexer: (() => Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve([]) } as Response)) as unknown as typeof fetch,
                }),
            }),
        },
        {
            name: 'a fetch error',
            reason: 'could not be looked up: network down',
            input: () => ({
                transcript: transcriptCopy(),
                lineage: lineageWith([{ vault: REAL_VAULT, level: 1 }]),
                formPoolId: '',
                chain: capturedChain({ indexer: (() => Promise.reject(new Error('network down'))) as unknown as typeof fetch }),
            }),
        },
        {
            name: 'no vault registered for the signed pool',
            reason: 'no vault is registered on-chain for this pool',
            input: () => ({
                transcript: transcriptCopy(),
                lineage: lineageWith([{ vault: REAL_VAULT, level: 1, poolId: 'another-pool' }]),
                formPoolId: '',
                chain: capturedChain(),
            }),
        },
        {
            name: 'the node disagrees with the indexer',
            reason: 'indexer and node disagree',
            input: () => ({
                transcript: transcriptCopy(),
                lineage: lineageWith([{ vault: REAL_VAULT, level: 1 }]),
                formPoolId: '',
                chain: capturedChain({ blockOperations: async () => [] }),
            }),
        },
        {
            name: 'the form names another pool than the signed transcript',
            reason: 'the form names pool another-pool, the signed transcript names pool standard',
            input: () => ({
                transcript: transcriptCopy(),
                lineage: lineageWith([{ vault: REAL_VAULT, level: 1 }]),
                formPoolId: 'another-pool',
                chain: capturedChain(),
            }),
        },
        {
            name: 'no lineage (an override key)',
            reason: 'no administrator lineage was derived',
            input: () => ({ transcript: transcriptCopy(), lineage: null, formPoolId: '', chain: capturedChain() }),
        },
        {
            name: 'the vault storage cannot be read',
            reason: 'could not read the storage of vault',
            input: () => ({
                transcript: transcriptCopy(),
                lineage: lineageWith([{ vault: REAL_VAULT, level: 1 }]),
                formPoolId: '',
                chain: capturedChain({ contractStorage: () => Promise.reject(new Error('RPC 500')) }),
            }),
        },
    ];

    for (const { name, reason, input } of failures) {
        it(`failed: ${name}`, async () => {
            const located = await resolveSessionDeposit(input());

            expect(located.lookup).toBe('failed');
            expect(located.level).toBeNull();
            expect(located.firstProven).toBe(false);
            expect(located.detail).toContain(reason);
        });
    }

    it('rule 4: another production vault registered before the transcript that holds the session clears nothing', async () => {
        const OLD_VAULT = 'KT1V9p3YByfpVs1QWmnZPHTNHDy9XaNPLTqz';
        const asked: string[] = [];
        const located = await resolveSessionDeposit({
            transcript: transcriptCopy('standard', firstDepositCapture.level - 10),
            lineage: lineageWith([
                { vault: OLD_VAULT, level: 5_000_000 },
                { vault: REAL_VAULT, level: REAL_VAULT_REGISTERED_AT },
                // Registered after the transcript: it cannot have held a credited deposit before it.
                { vault: 'KT1LateVaultLateVaultLateVaultLat', level: firstDepositCapture.level },
            ]),
            formPoolId: '',
            chain: capturedChain({
                contractStorage: async (address) => {
                    asked.push(address);

                    return sessionsEntryCapture.storageAtHead;
                },
                bigMapHas: async (id, expr) => id === sessionsEntryCapture.bigMapId && expr === sessionsEntryCapture.nodeScriptExprHash,
            }),
        });

        expect(located.firstProven).toBe(true);
        expect(located.otherVaults?.clear).toBe(false);
        expect(located.otherVaults?.detail).toContain(`vault ${OLD_VAULT} holds a sessions entry for this session`);
        expect(asked).not.toContain('KT1LateVaultLateVaultLateVaultLat');
    });
});
