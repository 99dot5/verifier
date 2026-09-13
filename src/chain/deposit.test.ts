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
import { locateSessionDeposit } from './deposit';

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

        expect(located.level).toBeNull();
        expect(located.detail).toContain('503');
    });
});
