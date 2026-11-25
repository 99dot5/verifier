/**
 * Reading the public rollup inbox from PUBLIC chain sources.
 *
 * Every sequencer→rollup message reaches L1: the injector POSTs signed frames
 * to the rollup node's batcher, which injects `smart_rollup_add_messages`
 * operations. Those operations — and therefore every message the schema
 * carries today: `SeedBatch` (0x00), `RoundTranscript` (0x01) and
 * `EndSession` (0x02) — are ordinary manager operations in ordinary blocks.
 *
 * Who decides what, stated exactly:
 *
 *   - The INDEXER CHOOSES THE LEVELS. The scan reads the levels where the
 *     indexer's applied external inbox rows hold a message starting with this
 *     rollup's external-message prefix, plus the window's two ends, a few
 *     random levels and a tail of at most ten levels above the indexer's head.
 *     (Before, it read every level where the indexer listed any
 *     `smart_rollup_add_messages` operation, which incidentally re-read nearly
 *     every busy level.) An indexer that omits a level, or alters a frame's
 *     first bytes, hides that frame, unless a random level, an end or a level
 *     already read catches it. There is no completeness proof yet; a proof
 *     against the rollup's inbox commitment could provide one.
 *   - The NODE SUPPLIES THE EVIDENCE. Every judged message is read from the
 *     reader's node, and only messages the node reports as `applied` count —
 *     the rollup never sees the others. Indexer bytes are decoded only to
 *     choose levels and never reach the verdict.
 *   - At every level the node is read, the indexer's prefixed count is
 *     compared with the node's applied prefixed count. A level the indexer
 *     called frame-free but the node holds frames at is a contradiction and
 *     yields no report; any other mismatch is reported as a finding.
 *
 * Both endpoints are user-configurable; neither belongs to 99dot5.
 */
import { type DecodedEnvelope, decodeExternalMessage, EXTERNAL_MESSAGE_PREFIX, hexToBytes } from '@99dot5/round-replay';
import { type FetchLike, isAbort } from './node-queue';

export interface InboxMessage {
    level: number;
    operationHash: string;
    /** Index of this message within its operation's message array. */
    messageIndex: number;
    rawHex: string;
    envelope: DecodedEnvelope;
    /** The `tz…` account that posted the operation, as the node reports it. */
    source?: string;
}

/** Whether a message's first bytes are this rollup's external-message prefix. */
export function hasExternalPrefix(bytes: ArrayLike<number>): boolean {
    return (
        bytes.length >= EXTERNAL_MESSAGE_PREFIX.length &&
        EXTERNAL_MESSAGE_PREFIX.every((byte, index) => bytes[index] === byte)
    );
}

/** One block's inbox as the node serves it: the applied messages that decode, and how many applied ones carry the prefix. */
export interface BlockInbox {
    messages: InboxMessage[];
    /** Applied messages starting with the prefix, decodable or not: what the indexer's count is compared with. */
    appliedPrefixedCount: number;
}

/** What the node keeps: blocks from `caboose`, operation metadata from `savepoint`. */
export interface NodeHistory {
    caboose: number;
    savepoint: number;
}

export type UnreadableReason = 'not-served' | 'metadata-missing' | 'status-missing' | 'http-error' | 'network-error';

/**
 * A level the node cannot serve with operation results. Never read as empty:
 * whatever it holds is unknown, so a scan over it yields no report.
 */
export class LevelUnreadable extends Error {
    constructor(
        readonly level: number,
        readonly reason: UnreadableReason,
        readonly detail: string,
        readonly historyLimit: NodeHistory | null = null,
    ) {
        super(LevelUnreadable.describe(level, reason, detail, historyLimit));
        this.name = 'LevelUnreadable';
    }

    /** The same level, with the node's history limit named in the message. */
    withHistory(historyLimit: NodeHistory | null): LevelUnreadable {
        return new LevelUnreadable(this.level, this.reason, this.detail, historyLimit);
    }

    private static describe(
        level: number,
        reason: UnreadableReason,
        detail: string,
        history: NodeHistory | null,
    ): string {
        const kept =
            history === null
                ? ''
                : ` (it keeps blocks from level ${history.caboose} and operation metadata from level ${history.savepoint})`;

        switch (reason) {
            case 'not-served':
                return `the Tezos RPC does not serve level ${level}${kept}; an archive node serves it`;
            case 'metadata-missing':
            case 'status-missing':
                return (
                    `the Tezos RPC serves level ${level} without the operation results that say which messages were ` +
                    `applied (${detail})${kept}; an archive node serves them`
                );
            case 'http-error':
            case 'network-error':
                return `the Tezos RPC could not be read at level ${level}: ${detail}`;
        }
    }
}

interface RpcAddMessagesContent {
    kind: string;
    source?: string;
    message?: string[];
    metadata?: unknown;
}

interface RpcOperationGroup {
    hash: string;
    contents: RpcAddMessagesContent[];
}

export interface NodeReadOptions {
    signal?: AbortSignal;
    fetchImpl?: FetchLike;
}

/**
 * One block's inbox from the node RPC, APPLIED messages only. Validation pass
 * 3 holds manager operations, which is where `smart_rollup_add_messages`
 * lives. An add_messages content whose result the node does not state (no
 * metadata, metadata the node withheld, no status) makes the whole level
 * unreadable, as does a block the node does not serve; other kinds of
 * operation are ignored. No query parameter is added to the request.
 */
export async function readBlockInbox(
    rpcUrl: string,
    level: number,
    options: NodeReadOptions = {},
): Promise<BlockInbox> {
    const url = `${rpcUrl.replace(/\/$/, '')}/chains/main/blocks/${level}/operations/3`;
    let response: Response;

    try {
        response = await (options.fetchImpl ?? fetch)(url, { signal: options.signal });
    } catch (error) {
        if (isAbort(error) || options.signal?.aborted) {
            throw error;
        }

        throw new LevelUnreadable(level, 'network-error', error instanceof Error ? error.message : String(error));
    }

    if (response.status === 404) {
        throw new LevelUnreadable(level, 'not-served', 'HTTP 404');
    }

    if (!response.ok) {
        throw new LevelUnreadable(level, 'http-error', `HTTP ${response.status}`);
    }

    let groups: RpcOperationGroup[];

    try {
        groups = (await response.json()) as RpcOperationGroup[];
    } catch (error) {
        if (isAbort(error) || options.signal?.aborted) {
            throw error;
        }

        throw new LevelUnreadable(level, 'http-error', 'the response is not JSON');
    }

    if (!Array.isArray(groups)) {
        throw new LevelUnreadable(level, 'http-error', 'the response is not a list of operations');
    }

    const messages: InboxMessage[] = [];
    let appliedPrefixedCount = 0;

    for (const group of groups) {
        for (const content of group.contents ?? []) {
            if (content.kind !== 'smart_rollup_add_messages') {
                continue;
            }

            const metadata = content.metadata;

            if (typeof metadata !== 'object' || metadata === null || Array.isArray(metadata)) {
                throw new LevelUnreadable(
                    level,
                    'metadata-missing',
                    metadata === undefined
                        ? `operation ${group.hash} has no metadata`
                        : `operation ${group.hash} has metadata ${JSON.stringify(metadata)}`,
                );
            }

            const status = (metadata as { operation_result?: { status?: unknown } }).operation_result?.status;

            if (typeof status !== 'string') {
                throw new LevelUnreadable(level, 'status-missing', `operation ${group.hash} states no result status`);
            }

            if (status !== 'applied') {
                // Failed, skipped and backtracked operations never reach the
                // rollup's inbox, so their messages are not evidence of anything.
                continue;
            }

            for (const [messageIndex, rawHex] of (content.message ?? []).entries()) {
                let bytes: Uint8Array;

                try {
                    bytes = hexToBytes(rawHex);
                } catch {
                    continue;
                }

                if (hasExternalPrefix(bytes)) {
                    appliedPrefixedCount += 1;
                }

                let envelope: DecodedEnvelope | null;

                try {
                    envelope = decodeExternalMessage(bytes);
                } catch {
                    // Malformed sequencer-prefixed frame, or another rollup's
                    // traffic that happens to share the prefix — skip. The
                    // kernel drops undecodable frames the same way.
                    continue;
                }

                if (envelope) {
                    messages.push({
                        level,
                        operationHash: group.hash,
                        messageIndex,
                        rawHex,
                        envelope,
                        ...(content.source === undefined ? {} : { source: content.source }),
                    });
                }
            }
        }
    }

    return { messages, appliedPrefixedCount };
}

/** A block's header fields the scan reads. */
export interface BlockHeader {
    level: number;
}

/** The node's header for `block` (a level or `head`). */
export async function blockHeader(
    rpcUrl: string,
    block: number | 'head',
    options: NodeReadOptions = {},
): Promise<BlockHeader> {
    const url = `${rpcUrl.replace(/\/$/, '')}/chains/main/blocks/${block}/header`;
    const response = await (options.fetchImpl ?? fetch)(url, { signal: options.signal });

    if (!response.ok) {
        throw new Error(`RPC ${response.status} for ${url}`);
    }

    const header = (await response.json()) as { level?: unknown };

    if (typeof header.level !== 'number' || !Number.isSafeInteger(header.level)) {
        throw new Error(`RPC ${url} returned no level`);
    }

    return { level: header.level };
}

/**
 * How far back the node keeps blocks and operation metadata, read from
 * `/chains/main/levels/caboose` and `/savepoint`. Best-effort: null when either
 * cannot be read, and the message about an unreadable level then omits it.
 */
export async function nodeHistory(rpcUrl: string, options: NodeReadOptions = {}): Promise<NodeHistory | null> {
    const levelAt = async (name: 'caboose' | 'savepoint'): Promise<number | null> => {
        try {
            const response = await (options.fetchImpl ?? fetch)(
                `${rpcUrl.replace(/\/$/, '')}/chains/main/levels/${name}`,
                { signal: options.signal },
            );

            if (!response.ok) {
                return null;
            }

            const body = (await response.json()) as { level?: unknown };

            return typeof body.level === 'number' && Number.isSafeInteger(body.level) ? body.level : null;
        } catch (error) {
            if (isAbort(error) || options.signal?.aborted) {
                throw error;
            }

            return null;
        }
    };
    const [caboose, savepoint] = await Promise.all([levelAt('caboose'), levelAt('savepoint')]);

    return caboose === null || savepoint === null ? null : { caboose, savepoint };
}

/** One `lazy_storage_diff` entry of an operation receipt, as the node renders it. */
export interface RpcLazyStorageDiff {
    kind: string;
    id: string;
    diff: {
        action: string;
        updates?: { key_hash?: string; key?: unknown; value?: unknown }[];
    };
}

/** A manager operation in a block, with its receipt; only the fields the deposit proof reads are typed. */
export interface RpcManagerOperation {
    kind: string;
    destination?: string;
    parameters?: { entrypoint: string; value: unknown };
    metadata?: {
        operation_result?: { status: string; lazy_storage_diff?: RpcLazyStorageDiff[] };
        internal_operation_results?: unknown[];
    };
}

export interface RpcManagerOperationGroup {
    hash: string;
    /** The `NetX…` chain the group was included on; every signature in it was made for this chain. */
    chain_id?: string;
    contents: RpcManagerOperation[];
}

/**
 * Every manager operation group in one block, receipts included, as the node
 * returns them. The sibling of {@link readBlockInbox} for the
 * deposit proof, which reads a vault call's receipt rather than inbox bytes.
 */
export async function fetchBlockOperations(
    rpcUrl: string,
    level: number,
    signal?: AbortSignal,
): Promise<RpcManagerOperationGroup[]> {
    const url = `${rpcUrl.replace(/\/$/, '')}/chains/main/blocks/${level}/operations/3`;
    const response = await fetch(url, { signal });

    if (!response.ok) {
        throw new Error(`RPC ${response.status} for ${url} (archive node required for old levels)`);
    }

    return (await response.json()) as RpcManagerOperationGroup[];
}
