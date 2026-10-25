/**
 * The public payout watcher's recorded node snapshots as a {@link PayoutChain}:
 * one recording per case of what an L1 node and a rollup node answered
 * around one payout, replayed here so the payout check is held to the SAME
 * blocks, scripts and kernel records its Rust sibling is tested on. The
 * "indexer" over a recording is a scan of its blocks for the vault's applied
 * events naming the session, which is exactly what the live indexer query
 * asks TzKT for.
 */
import { readFileSync } from 'node:fs';
import type { RpcManagerOperationGroup } from '../chain/inbox';
import { type WatcherSnapshotCase, watcherSnapshotUrl } from './fast-payout-vectors-path';
import { scanBlockPayouts } from './events';
import { bytesToHex } from './micheline';
import { type LocatedPayoutLevel, type PayoutLocation } from './locate';
import type { RollupNodeReads } from './rollup-node';
import type { PayoutChain } from './session-payout';

export interface WatcherSnapshot {
    l1: {
        finalized_level: number;
        /** Level → the block's four validation passes; the manager pass is the fourth. */
        blocks: Record<string, RpcManagerOperationGroup[][]>;
        /** A vault's script from a level on. */
        scripts: { contract: string; from_level: number; script: unknown }[];
    };
    rollup: {
        finalized_level: number;
        /** Durable key → hex value at the finalised block. */
        durable: Record<string, string>;
        durable_at_level: Record<string, Record<string, string>>;
    };
}

export function loadWatcherSnapshot(snapshotCase: WatcherSnapshotCase): WatcherSnapshot {
    return JSON.parse(readFileSync(watcherSnapshotUrl(snapshotCase), 'utf8')) as WatcherSnapshot;
}

/** The manager pass of one recorded block; a level the recording does not hold is an empty block. */
export function snapshotBlock(snapshot: WatcherSnapshot, level: number): RpcManagerOperationGroup[] {
    return snapshot.l1.blocks[String(level)]?.[3] ?? [];
}

/** The recorded script of `vault` as of `level`, or a thrown error when the recording has none. */
export function snapshotScript(snapshot: WatcherSnapshot, vault: string, level: number): unknown {
    const candidates = snapshot.l1.scripts
        .filter((entry) => entry.contract === vault && entry.from_level <= level)
        .sort((a, b) => b.from_level - a.from_level);

    if (candidates.length === 0) {
        throw new Error(`the recording holds no script of ${vault} at level ${level}`);
    }

    return candidates[0].script;
}

function hexToBytes(hex: string): Uint8Array {
    const out = new Uint8Array(hex.length / 2);

    for (let i = 0; i < out.length; i++) {
        out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }

    return out;
}

/** The recording's rollup node: its finalised level and its durable values at that block. */
export function snapshotRollupNode(snapshot: WatcherSnapshot): RollupNodeReads {
    return {
        finalizedLevel: async () => snapshot.rollup.finalized_level,
        durableValue: async (key) => {
            const hex = snapshot.rollup.durable[key];

            return hex === undefined ? null : hexToBytes(hex);
        },
    };
}

/** The levels at which `vault` emitted a payout event naming `sessionHex`, from the recording's blocks. */
export function snapshotLocate(
    snapshot: WatcherSnapshot,
    vaultAddresses: string[],
    sessionHex: string,
): PayoutLocation {
    const levels: LocatedPayoutLevel[] = [];

    for (const [level, passes] of Object.entries(snapshot.l1.blocks)) {
        for (const vault of vaultAddresses) {
            const items = scanBlockPayouts(passes[3] ?? [], new Set([vault]));

            if (items.some((item) => item.kind === 'event' && bytesToHex(item.event.sessionId) === sessionHex)) {
                levels.push({ vault, level: Number(level) });
            }
        }
    }

    levels.sort((a, b) => a.level - b.level);

    return { lookup: 'ok', levels, detail: `${levels.length} level(s) in the recording` };
}

/** A {@link PayoutChain} over the recording, with or without its rollup node. */
export function snapshotChain(
    snapshot: WatcherSnapshot,
    options: { rollupNode: boolean } = { rollupNode: true },
): PayoutChain {
    return {
        locatePayoutEvents: async (vaultAddresses, sessionHex) => snapshotLocate(snapshot, vaultAddresses, sessionHex),
        blockOperations: async (level) => snapshotBlock(snapshot, level),
        contractScript: async (address, level) => snapshotScript(snapshot, address, level),
        rollupNode: options.rollupNode ? snapshotRollupNode(snapshot) : null,
    };
}
