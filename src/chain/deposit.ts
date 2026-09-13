/**
 * Locating the session's deposit on L1.
 *
 * The suppression ladder's lower bound is the level of the session's own
 * deposit operation (§8.3(d)): the session is not `active` until the deposit
 * is processed, so no round of it can precede that level, and a scan starting
 * after it cannot honestly claim "the transcript is nowhere in range".
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

export interface DepositLocation {
    /** L1 level of the session's first deposit; null when none was found. */
    level: number | null;
    operationHash: string | null;
    /** The vault it landed on. */
    vault: string | null;
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
    const absent = (detail: string): DepositLocation => ({ level: null, operationHash: null, vault: null, detail });

    if (options.vaultAddresses.length === 0) {
        return absent('no vault is registered on-chain for this pool, so there is no contract to look for the deposit on');
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
                    return absent(`the indexer returned ${response.status} while looking for the session's deposit`);
                }

                page = (await response.json()) as TzktDepositOperation[];
            } catch (error) {
                return absent(
                    `the session's deposit could not be looked up: ${error instanceof Error ? error.message : String(error)}`,
                );
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
            `no applied deposit naming session ${options.sessionIdHex} was found on ${options.vaultAddresses.join(', ')}` +
                `${ignoredNote} — without it the range has no L1-anchored lower bound`,
        );
    }

    return {
        level: best.level,
        operationHash: best.hash,
        vault: best.vault,
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
 * not collide with the record's other fields (an `edpk`/`edsig` base58 string
 * and nothing else).
 */
function namesSession(value: unknown, needle: string): boolean {
    return JSON.stringify(value ?? null)
        .toLowerCase()
        .includes(needle);
}
