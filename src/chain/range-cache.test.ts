// @vitest-environment node
// What a scan keeps across runs: listed intervals with their frame
// counts, and node reads, final levels only, per pair of endpoints.
import { describe, expect, it } from 'vitest';
import type { BlockInbox } from './inbox';
import type { FrameLocator } from './inbox-locator';
import { createScanner, type NodeInbox, ScanIncompleteError } from './inbox-scan';
import { FINALITY_LEVELS, normaliseEndpoint, RangeCache, RangeCaches, rangeCacheKey } from './range-cache';

const read = (count: number): BlockInbox => ({ messages: [], appliedPrefixedCount: count });

describe('the range cache', () => {
    it('C1: reports the unlisted parts of a range, and merges overlapping and adjacent intervals', () => {
        const cache = new RangeCache();

        expect(cache.uncovered(100, 200)).toEqual([{ fromLevel: 100, toLevel: 200 }]);

        cache.addLocated(120, 140, new Map(), Number.POSITIVE_INFINITY);
        cache.addLocated(160, 170, new Map(), Number.POSITIVE_INFINITY);

        expect(cache.uncovered(100, 200)).toEqual([
            { fromLevel: 100, toLevel: 119 },
            { fromLevel: 141, toLevel: 159 },
            { fromLevel: 171, toLevel: 200 },
        ]);
        expect(cache.uncovered(125, 135)).toEqual([]);

        // Adjacent (141 follows 140) and overlapping (165) both merge into one.
        cache.addLocated(141, 165, new Map(), Number.POSITIVE_INFINITY);

        expect(cache.located()).toEqual([{ fromLevel: 120, toLevel: 170 }]);
        expect(cache.uncovered(100, 200)).toEqual([
            { fromLevel: 100, toLevel: 119 },
            { fromLevel: 171, toLevel: 200 },
        ]);
    });

    it('C2: keeps the frame count per listed level and the node read per level, nothing else', () => {
        const cache = new RangeCache();

        cache.addLocated(
            10,
            20,
            new Map([
                [12, 3],
                [18, 1],
                [25, 9],
            ]),
            Number.POSITIVE_INFINITY,
        );
        cache.setNodeRead(12, read(3), Number.POSITIVE_INFINITY);

        expect(cache.frameCount(12)).toBe(3);
        expect(cache.frameCount(13)).toBe(0);
        // Outside the listed interval nothing is known, not even "no frames".
        expect(cache.frameCount(25)).toBeUndefined();
        expect(cache.frameLevels(0, 100)).toEqual([12, 18]);
        expect(cache.nodeRead(12)).toEqual(read(3));
        expect(cache.nodeRead(18)).toBeUndefined();
        expect(cache.nodeReadLevels()).toEqual([12]);
    });

    it('C3: one cache per normalised indexer and node pair', () => {
        expect(normaliseEndpoint(' https://API.Example.org/ ')).toBe('https://api.example.org');
        expect(normaliseEndpoint('https://rpc.example.org:443/path//')).toBe('https://rpc.example.org/path');
        expect(rangeCacheKey('https://api.example.org/', 'https://rpc.example.org')).toBe(
            rangeCacheKey('HTTPS://api.example.org', 'https://RPC.example.org/'),
        );

        const caches = new RangeCaches();
        const a = caches.for('https://api.example.org/', 'https://rpc.example.org');

        expect(caches.for('https://API.example.org', 'https://rpc.example.org/')).toBe(a);
        expect(caches.for('https://api.example.org', 'https://another-node.example.org')).not.toBe(a);
    });

    it('C4: a failed fetch covers nothing', async () => {
        const cache = new RangeCache();
        const locator: FrameLocator = {
            head: async () => 100_000,
            locateChunk: async (fromLevel, toLevel) =>
                fromLevel === 1_201
                    ? {
                          status: 'unread',
                          fromLevel,
                          toLevel,
                          reason: 'network',
                          detail: 'offline',
                          bytes: 0,
                          requests: 5,
                      }
                    : {
                          status: 'located',
                          fromLevel,
                          toLevel,
                          frameCountByLevel: new Map(fromLevel === 1_001 ? [[1_100, 1]] : []),
                          bytes: (toLevel - fromLevel + 1) * 80_000,
                          requests: 1,
                      },
        };
        const node: NodeInbox = {
            head: async () => 100_000,
            read: async (level) => {
                if (level === 1_100) {
                    throw new Error('node down');
                }

                return read(0);
            },
            history: async () => null,
        };
        const scanner = createScanner({ locator, node, cache, confirmDownload: async () => true, random: () => 0.5 });

        await expect(scanner.scanRange(1_001, 1_300)).rejects.toBeInstanceOf(ScanIncompleteError);

        // The chunk the indexer failed, and the chunk whose node read failed:
        // neither ended covered, so neither is kept.
        expect(cache.uncovered(1_001, 1_300)).toEqual([{ fromLevel: 1_001, toLevel: 1_250 }]);
        expect(cache.nodeRead(1_100)).toBeUndefined();
        expect(cache.nodeRead(1_001)).toEqual(read(0));
    });

    it(`C5: nothing above head − ${FINALITY_LEVELS} is cached`, () => {
        const cache = new RangeCache();
        const head = 5_000;
        const finalLevel = head - FINALITY_LEVELS;

        cache.addLocated(
            4_990,
            head,
            new Map([
                [4_995, 1],
                [4_999, 1],
            ]),
            finalLevel,
        );
        cache.setNodeRead(finalLevel, read(0), finalLevel);
        cache.setNodeRead(finalLevel + 1, read(1), finalLevel);

        expect(cache.located()).toEqual([{ fromLevel: 4_990, toLevel: finalLevel }]);
        expect(cache.frameLevels(0, 10_000)).toEqual([4_995]);
        expect(cache.nodeReadLevels()).toEqual([finalLevel]);

        // A chunk entirely above the final level stores nothing.
        cache.addLocated(head - 1, head, new Map([[head, 2]]), finalLevel);
        expect(cache.located()).toEqual([{ fromLevel: 4_990, toLevel: finalLevel }]);
    });
});
