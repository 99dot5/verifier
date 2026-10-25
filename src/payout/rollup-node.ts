/**
 * The two reads the payout check makes of a smart-rollup node: the level it
 * has finalised, and a value of the kernel's durable storage at that block.
 *
 * THE NODE IS THE READER'S OWN. A rollup node is not a public chain source
 * the way an L1 archive node or an indexer is: it is one party's replay of
 * the rollup, and the operator's node can only ever confirm the operator.
 * So this field has no default, and the kernel-record check reads
 * `unavailable` until the reader points it at a node they run (an observer
 * node is enough: only `value` and `level` are read, which the node's default
 * secure RPC ACL allows). The L1-only comparison with the cemented payout
 * needs no rollup node at all.
 */

export interface RollupNodeReads {
    /** The L1 level of the node's `finalized` block. */
    finalizedLevel(): Promise<number>;
    /** The bytes at a durable key at the `finalized` block, or null when the key is absent. */
    durableValue(key: string): Promise<Uint8Array | null>;
}

const PVM = 'wasm_2_0_0';

function hexToBytes(hex: string): Uint8Array {
    if (!/^([0-9a-fA-F]{2})*$/.test(hex)) {
        throw new Error('the node returned a durable value that is not hex');
    }

    const out = new Uint8Array(hex.length / 2);

    for (let i = 0; i < out.length; i++) {
        out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }

    return out;
}

/** {@link RollupNodeReads} over the RPC of a rollup node at `rollupNodeUrl`. */
export function rollupNodeReads(rollupNodeUrl: string, signal?: AbortSignal): RollupNodeReads {
    const base = rollupNodeUrl.replace(/\/$/, '');

    return {
        async finalizedLevel() {
            const url = `${base}/global/block/finalized/level`;
            const response = await fetch(url, { signal });

            if (!response.ok) {
                throw new Error(`rollup node ${response.status} for ${url}`);
            }

            const level = (await response.json()) as unknown;

            if (typeof level !== 'number' || !Number.isInteger(level)) {
                throw new Error('the rollup node returned a finalised level that is not an integer');
            }

            return level;
        },
        async durableValue(key) {
            const url = `${base}/global/block/finalized/durable/${PVM}/value?key=${encodeURIComponent(key)}`;
            const response = await fetch(url, { signal });

            if (!response.ok) {
                throw new Error(`rollup node ${response.status} for ${url}`);
            }

            const value = (await response.json()) as unknown;

            if (value === null) {
                return null;
            }

            if (typeof value !== 'string') {
                throw new Error('the rollup node returned a durable value that is not a hex string');
            }

            return hexToBytes(value);
        },
    };
}
