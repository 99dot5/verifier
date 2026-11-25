/**
 * What a scan already read, kept across runs so that a Retry, or a second
 * press of Fetch, asks only for what is still missing.
 *
 * Two things are kept, per pair of endpoints:
 *   - the level intervals the indexer listed completely, with the prefixed
 *     message count at each level that has any (frame counts only, never
 *     payloads, so memory stays flat however wide the scan);
 *   - each level the node served, as the node served it.
 *
 * Only FINAL levels are stored: at least {@link FINALITY_LEVELS} below the
 * head, where Tezos no longer reorganises. A fetch that failed stores nothing,
 * so it covers nothing. The key is the normalised indexer URL and node URL
 * together: another node's answer is never reused for this one.
 */
import type { BlockInbox } from './inbox';

/** A block this many levels below the head is final. */
export const FINALITY_LEVELS = 2;

/** An endpoint URL in the form the cache keys on: trimmed, no trailing slash, lower-case scheme and host. */
export function normaliseEndpoint(url: string): string {
    const trimmed = url.trim().replace(/\/+$/, '');

    try {
        // `URL` lower-cases the scheme and host and drops a default port.
        const parsed = new URL(trimmed);

        return `${parsed.protocol}//${parsed.host}${parsed.pathname.replace(/\/+$/, '')}${parsed.search}`;
    } catch {
        return trimmed;
    }
}

/** The cache key for an indexer and a node. */
export function rangeCacheKey(tzktApiUrl: string, rpcUrl: string): string {
    return `${normaliseEndpoint(tzktApiUrl)}‖${normaliseEndpoint(rpcUrl)}`;
}

/** An inclusive level interval. */
export interface LevelInterval {
    fromLevel: number;
    toLevel: number;
}

/** `intervals` sorted, with overlapping and adjacent ones joined; the input is not modified. */
export function mergeIntervals(intervals: LevelInterval[]): LevelInterval[] {
    const sorted = [...intervals].sort((a, b) => a.fromLevel - b.fromLevel);
    const merged: LevelInterval[] = [];

    for (const interval of sorted) {
        const last = merged[merged.length - 1];

        if (last && interval.fromLevel <= last.toLevel + 1) {
            last.toLevel = Math.max(last.toLevel, interval.toLevel);
        } else {
            merged.push({ ...interval });
        }
    }

    return merged;
}

export class RangeCache {
    /** Sorted, disjoint, non-adjacent. */
    private intervals: LevelInterval[] = [];
    private readonly frameCounts = new Map<number, number>();
    private readonly nodeReads = new Map<number, BlockInbox>();

    /** The intervals the indexer listed completely. */
    located(): LevelInterval[] {
        return this.intervals.map((i) => ({ ...i }));
    }

    /** The parts of `[fromLevel, toLevel]` the indexer has not listed, in order. */
    uncovered(fromLevel: number, toLevel: number): LevelInterval[] {
        const gaps: LevelInterval[] = [];
        let next = fromLevel;

        for (const interval of this.intervals) {
            if (interval.toLevel < next) {
                continue;
            }

            if (interval.fromLevel > toLevel) {
                break;
            }

            if (interval.fromLevel > next) {
                gaps.push({ fromLevel: next, toLevel: interval.fromLevel - 1 });
            }

            next = Math.max(next, interval.toLevel + 1);
        }

        if (next <= toLevel) {
            gaps.push({ fromLevel: next, toLevel });
        }

        return gaps;
    }

    isLocated(level: number): boolean {
        return this.intervals.some((i) => i.fromLevel <= level && level <= i.toLevel);
    }

    /** The indexer's prefixed count at a listed level (0 when it listed none there); undefined when not listed. */
    frameCount(level: number): number | undefined {
        return this.isLocated(level) ? (this.frameCounts.get(level) ?? 0) : undefined;
    }

    /** The listed levels in `[fromLevel, toLevel]` the indexer counted frames at, ascending. */
    frameLevels(fromLevel: number, toLevel: number): number[] {
        return [...this.frameCounts.keys()].filter((l) => l >= fromLevel && l <= toLevel).sort((a, b) => a - b);
    }

    /** Record a chunk the indexer listed completely, clipped to `finalLevel`. */
    addLocated(
        fromLevel: number,
        toLevel: number,
        frameCountByLevel: ReadonlyMap<number, number>,
        finalLevel: number,
    ): void {
        const end = Math.min(toLevel, finalLevel);

        if (end < fromLevel) {
            return;
        }

        for (const [level, count] of frameCountByLevel) {
            if (level >= fromLevel && level <= end && count > 0) {
                this.frameCounts.set(level, count);
            }
        }

        this.intervals = mergeIntervals([...this.intervals, { fromLevel, toLevel: end }]);
    }

    nodeRead(level: number): BlockInbox | undefined {
        return this.nodeReads.get(level);
    }

    /** Record what the node served at `level`, when the level is final. */
    setNodeRead(level: number, read: BlockInbox, finalLevel: number): void {
        if (level <= finalLevel) {
            this.nodeReads.set(level, read);
        }
    }

    /** Every level the node was read at, ascending. */
    nodeReadLevels(): number[] {
        return [...this.nodeReads.keys()].sort((a, b) => a - b);
    }
}

/** One cache per pair of endpoints, for the page's lifetime. */
export class RangeCaches {
    private readonly caches = new Map<string, RangeCache>();

    for(tzktApiUrl: string, rpcUrl: string): RangeCache {
        const key = rangeCacheKey(tzktApiUrl, rpcUrl);
        let cache = this.caches.get(key);

        if (!cache) {
            cache = new RangeCache();
            this.caches.set(key, cache);
        }

        return cache;
    }
}
