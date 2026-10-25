/**
 * Locating a session's payout events on L1 through the indexer.
 *
 * Both payout paths emit a contract event naming the session: `fast_payout`
 * from the signed fast path, `cemented_payout` from the rollup's own outbox
 * execution. TzKT indexes contract events with their typed payload, so it
 * can be asked for exactly this session's events on each of the pool's
 * vaults (`payload.session_id=<hex>`). The indexer only LOCATES: each level it
 * names is then read from the node, and the events decoded from the block's
 * own receipts by annotation. Its filter is re-checked against every row's
 * payload too, for the same reason the deposit lookup re-checks `parameter`:
 * an indexer that silently ignored an unknown filter would otherwise hand
 * back every payout on the contract.
 */

export const FAST_PAYOUT_TAG = 'fast_payout';
export const CEMENTED_PAYOUT_TAG = 'cemented_payout';

export interface LocatedPayoutLevel {
    vault: string;
    level: number;
}

export interface PayoutLocation {
    /** `ok`: the indexer answered for every vault (possibly with no rows). `failed`: a lookup could not be made. */
    lookup: 'ok' | 'failed';
    /** Distinct `(vault, level)` pairs, ascending by level. */
    levels: LocatedPayoutLevel[];
    detail: string;
}

export interface LocatePayoutOptions {
    tzktApiUrl: string;
    /** Candidate vaults for the pool, from the lineage. */
    vaultAddresses: string[];
    /** Hyphenated or bare-hex session id. */
    sessionIdHex: string;
    signal?: AbortSignal;
    fetchImpl?: typeof fetch;
}

interface TzktEvent {
    id: number;
    level: number;
    tag: string;
    payload: unknown;
}

const PAGE_SIZE = 1000;

/** Whether a TzKT-rendered event payload names this session (the 32-hex id anywhere in it). */
export function namesSession(payload: unknown, needle: string): boolean {
    return JSON.stringify(payload ?? null)
        .toLowerCase()
        .includes(needle);
}

/** Every level at which one of `vaultAddresses` emitted a payout event naming the session. */
export async function locatePayoutEvents(options: LocatePayoutOptions): Promise<PayoutLocation> {
    const needle = options.sessionIdHex.replaceAll('-', '').toLowerCase();
    const doFetch = options.fetchImpl ?? fetch;
    const base = options.tzktApiUrl.replace(/\/$/, '');
    const seen = new Map<string, LocatedPayoutLevel>();
    let ignoredCount = 0;

    if (options.vaultAddresses.length === 0) {
        return {
            lookup: 'failed',
            levels: [],
            detail: 'no vault is registered on-chain for this pool, so there is no contract to look for payouts on',
        };
    }

    for (const vault of options.vaultAddresses) {
        let lastId = 0;

        for (;;) {
            const url =
                `${base}/v1/contracts/events` +
                `?contract=${encodeURIComponent(vault)}&tag.in=${FAST_PAYOUT_TAG},${CEMENTED_PAYOUT_TAG}` +
                `&payload.session_id=${encodeURIComponent(needle)}` +
                `&select=id,level,tag,payload&sort=id&limit=${PAGE_SIZE}` +
                (lastId ? `&id.gt=${lastId}` : '');
            let page: TzktEvent[];

            try {
                const response = await doFetch(url, { signal: options.signal });

                if (!response.ok) {
                    return {
                        lookup: 'failed',
                        levels: [],
                        detail: `the indexer returned ${response.status} while looking for the session's payout events`,
                    };
                }

                page = (await response.json()) as TzktEvent[];
            } catch (error) {
                return {
                    lookup: 'failed',
                    levels: [],
                    detail: `the session's payout events could not be looked up: ${errorText(error)}`,
                };
            }

            for (const event of page) {
                lastId = Math.max(lastId, event.id);

                if (!namesSession(event.payload, needle)) {
                    ignoredCount += 1;
                    continue;
                }

                seen.set(`${vault}@${event.level}`, { vault, level: event.level });
            }

            if (page.length < PAGE_SIZE) {
                break;
            }
        }
    }

    const levels = [...seen.values()].sort((a, b) => a.level - b.level || a.vault.localeCompare(b.vault));
    const ignoredNote =
        ignoredCount > 0
            ? ` (${ignoredCount} row(s) the indexer returned did not name this session and were ignored)`
            : '';

    return {
        lookup: 'ok',
        levels,
        detail:
            levels.length === 0
                ? `no payout event naming session ${options.sessionIdHex} was found on ${options.vaultAddresses.join(', ')}${ignoredNote}`
                : `the indexer names ${levels.length} level(s) with a payout event for session ${options.sessionIdHex}: ` +
                  levels.map((l) => `${l.level} on ${l.vault}`).join(', ') +
                  ignoredNote,
    };
}

function errorText(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}
