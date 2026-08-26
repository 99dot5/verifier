/**
 * Reading the public rollup inbox from PUBLIC chain sources.
 *
 * Every sequencer→rollup message reaches L1: the injector POSTs signed frames
 * to the rollup node's batcher, which injects `smart_rollup_add_messages`
 * operations. Those operations — and therefore every `RoundCreated`,
 * `PlayerAction`, `RoundSettled`, `SeedBatch` and `EndSession` — are
 * ordinary manager operations in ordinary blocks, readable from any archive
 * node and locatable through any indexer.
 *
 * Split of responsibilities:
 *   - TzKT (indexer) LOCATES candidate operations fast — raw block scanning
 *     is far too slow in a browser. It returns levels/hashes, not payloads.
 *   - The node RPC (archive) supplies the actual message bytes for those
 *     levels, which also serves as an independent cross-check on the indexer.
 *
 * Both endpoints are user-configurable; neither belongs to 99dot5.
 */
import { hexToBytes } from '../verify/seed';
import { decodeExternalMessage, type DecodedEnvelope } from '../wire/messages';

export interface InboxMessage {
    level: number;
    operationHash: string;
    /** Index of this message within its operation's message array. */
    messageIndex: number;
    rawHex: string;
    envelope: DecodedEnvelope;
}

export interface ScanProgress {
    phase: 'locating' | 'fetching';
    done: number;
    total: number;
}

interface TzktSrAddMessagesOp {
    level: number;
    hash: string;
}

/**
 * Locate `smart_rollup_add_messages` operation levels via TzKT within an
 * inclusive level range. Pages through results; sr_add_messages traffic is
 * sparse enough that 1000-per-page is generous.
 */
export async function locateInboxLevels(
    tzktApiUrl: string,
    fromLevel: number,
    toLevel: number,
    signal?: AbortSignal,
): Promise<number[]> {
    const levels = new Set<number>();
    let lastId = 0;

    for (;;) {
        const url =
            `${tzktApiUrl.replace(/\/$/, '')}/v1/operations/sr_add_messages` +
            `?level.ge=${fromLevel}&level.le=${toLevel}&limit=1000&select=id,level,hash` +
            (lastId ? `&id.gt=${lastId}` : '');
        const response = await fetch(url, { signal });

        if (!response.ok) {
            throw new Error(`TzKT ${response.status} for ${url}`);
        }

        const page = (await response.json()) as (TzktSrAddMessagesOp & { id: number })[];

        for (const op of page) {
            levels.add(op.level);
            lastId = Math.max(lastId, op.id);
        }

        if (page.length < 1000) {
            break;
        }
    }

    return [...levels].sort((a, b) => a - b);
}

/** Current head level via TzKT (used to default the scan range). */
export async function headLevel(tzktApiUrl: string, signal?: AbortSignal): Promise<number> {
    const response = await fetch(`${tzktApiUrl.replace(/\/$/, '')}/v1/head`, { signal });

    if (!response.ok) {
        throw new Error(`TzKT ${response.status} for /v1/head`);
    }

    return ((await response.json()) as { level: number }).level;
}

interface RpcOperationContent {
    kind: string;
    message?: string[];
}

interface RpcOperationGroup {
    hash: string;
    contents: RpcOperationContent[];
}

/**
 * Fetch every sequencer inbox frame in one block from the node RPC (archive
 * data — pruned nodes drop old operations). Validation pass 3 holds manager
 * operations, which is where `smart_rollup_add_messages` lives.
 */
export async function fetchBlockInboxMessages(
    rpcUrl: string,
    level: number,
    signal?: AbortSignal,
): Promise<InboxMessage[]> {
    const url = `${rpcUrl.replace(/\/$/, '')}/chains/main/blocks/${level}/operations/3`;
    const response = await fetch(url, { signal });

    if (!response.ok) {
        throw new Error(`RPC ${response.status} for ${url} (archive node required for old levels)`);
    }

    const groups = (await response.json()) as RpcOperationGroup[];
    const messages: InboxMessage[] = [];

    for (const group of groups) {
        for (const content of group.contents) {
            if (content.kind !== 'smart_rollup_add_messages' || !content.message) {
                continue;
            }

            for (const [messageIndex, rawHex] of content.message.entries()) {
                let envelope: DecodedEnvelope | null;

                try {
                    envelope = decodeExternalMessage(hexToBytes(rawHex));
                } catch {
                    // Malformed sequencer-prefixed frame, or another rollup's
                    // traffic that happens to share the prefix — skip. The
                    // kernel drops undecodable frames the same way.
                    continue;
                }

                if (envelope) {
                    messages.push({ level, operationHash: group.hash, messageIndex, rawHex, envelope });
                }
            }
        }
    }

    return messages;
}

/**
 * Scan a level range: locate via TzKT, fetch bytes via RPC. Reports progress
 * and respects aborts — a browser scanning tens of levels must stay honest
 * about what it is doing.
 */
export async function scanRange(
    tzktApiUrl: string,
    rpcUrl: string,
    fromLevel: number,
    toLevel: number,
    onProgress: (progress: ScanProgress) => void,
    signal?: AbortSignal,
): Promise<InboxMessage[]> {
    onProgress({ phase: 'locating', done: 0, total: 1 });

    const levels = await locateInboxLevels(tzktApiUrl, fromLevel, toLevel, signal);
    const messages: InboxMessage[] = [];

    for (const [index, level] of levels.entries()) {
        onProgress({ phase: 'fetching', done: index, total: levels.length });
        messages.push(...(await fetchBlockInboxMessages(rpcUrl, level, signal)));
    }

    onProgress({ phase: 'fetching', done: levels.length, total: levels.length });

    return messages;
}
