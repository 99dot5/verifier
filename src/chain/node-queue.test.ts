// @vitest-environment node
// The one retry rule and the adaptive node queue.
import { describe, expect, it } from 'vitest';
import {
    CLEAN_READS_TO_GROW,
    fetchRetrying,
    type FetchLike,
    INITIAL_CONCURRENCY,
    NodeQueue,
    RETRY_ATTEMPTS,
    retryDelayMs,
} from './node-queue';

/** A fetch answering each call from `answers` in order (a status, or 'network' for a fetch TypeError). */
function scripted(answers: (number | 'network')[], headers: Record<string, string> = {}) {
    const calls: string[] = [];
    const fetchImpl: FetchLike = async (url) => {
        calls.push(url);

        const answer = answers[Math.min(calls.length - 1, answers.length - 1)];

        if (answer === 'network') {
            throw new TypeError('Failed to fetch');
        }

        return new Response('[]', { status: answer, headers });
    };

    return { calls, fetchImpl };
}

const noSleep = async () => undefined;

describe('the retry rule', () => {
    it('retries 429, 502, 503 and 504, up to five attempts in all', async () => {
        for (const status of [429, 502, 503, 504]) {
            const { calls, fetchImpl } = scripted([status]);
            const response = await fetchRetrying('https://node.test/x', { fetchImpl, sleep: noSleep });

            expect(response.status, String(status)).toBe(status);
            expect(calls, String(status)).toHaveLength(RETRY_ATTEMPTS);
        }
    });

    it('returns as soon as a retried status turns into an answer', async () => {
        const { calls, fetchImpl } = scripted([429, 429, 200]);
        const response = await fetchRetrying('https://node.test/x', { fetchImpl, sleep: noSleep });

        expect(response.status).toBe(200);
        expect(calls).toHaveLength(3);
    });

    it('never retries any other status, a 404 included', async () => {
        for (const status of [400, 404, 500, 501]) {
            const { calls, fetchImpl } = scripted([status, 200]);
            const response = await fetchRetrying('https://node.test/x', { fetchImpl, sleep: noSleep });

            expect(response.status, String(status)).toBe(status);
            expect(calls, String(status)).toHaveLength(1);
        }
    });

    it('retries a network failure (fetch TypeError) and rethrows it after the last attempt', async () => {
        const { calls, fetchImpl } = scripted(['network']);

        await expect(fetchRetrying('https://node.test/x', { fetchImpl, sleep: noSleep })).rejects.toBeInstanceOf(
            TypeError,
        );
        expect(calls).toHaveLength(RETRY_ATTEMPTS);
    });

    it('backs off 2, 4, 8, 16 s, and honours a readable Retry-After capped at 16 s', async () => {
        const waits: number[] = [];
        const { fetchImpl } = scripted([503]);

        await fetchRetrying('https://node.test/x', {
            fetchImpl,
            sleep: async (ms) => {
                waits.push(ms);
            },
        });

        expect(RETRY_ATTEMPTS).toBe(5);
        expect(waits).toEqual([2_000, 4_000, 8_000, 16_000]);
        expect(retryDelayMs(6, null)).toBe(16_000);
        expect(retryDelayMs(1, '3')).toBe(3_000);
        expect(retryDelayMs(1, '120')).toBe(16_000);
        expect(retryDelayMs(2, 'soon')).toBe(4_000);
        expect(retryDelayMs(1, 'Thu, 01 Jan 2026 00:00:05 GMT', Date.parse('2026-01-01T00:00:00Z'))).toBe(5_000);
    });

    it('stops at once on an abort, without retrying', async () => {
        const abort = new AbortController();
        const { calls, fetchImpl } = scripted([503]);

        abort.abort();

        await expect(
            fetchRetrying('https://node.test/x', { fetchImpl, sleep: noSleep, signal: abort.signal }),
        ).rejects.toThrow();
        expect(calls).toHaveLength(0);
    });
});

/** A fetch that never answers; it only rejects, as the browser's does, once its signal aborts. */
const neverAnswers = (init?: RequestInit) =>
    new Promise<Response>((_, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), {
            once: true,
        });
    });

/** A 200 whose body sends `pieces` one by one, `gapMs` apart, then stalls for good unless `ends`. */
function trickle(pieces: string[], gapMs: number, ends: boolean, signal?: AbortSignal | null): Response {
    const encoder = new TextEncoder();
    let sent = 0;
    const body = new ReadableStream<Uint8Array>({
        async pull(controller) {
            await new Promise((resolve) => setTimeout(resolve, gapMs));

            if (signal?.aborted) {
                controller.error(new DOMException('aborted', 'AbortError'));

                return;
            }

            if (sent < pieces.length) {
                controller.enqueue(encoder.encode(pieces[sent++]));
            } else if (ends) {
                controller.close();
            } else {
                // Stalled: no piece and no end, until the reader gives up.
                await new Promise<void>((resolve) =>
                    signal?.addEventListener('abort', () => resolve(), { once: true }),
                );
                controller.error(new DOMException('aborted', 'AbortError'));
            }
        },
    });

    return new Response(body, { status: 200 });
}

describe('a stalled request', () => {
    it('is abandoned after the stall limit when no headers arrive, and retried as a network failure', async () => {
        let attempts = 0;
        const fetchImpl: FetchLike = async (_url, init) => {
            attempts += 1;

            return attempts === 1 ? neverAnswers(init) : new Response('[1]', { status: 200 });
        };
        const response = await fetchRetrying('https://indexer.test/x', { fetchImpl, sleep: noSleep, stallMs: 30 });

        expect(attempts).toBe(2);
        expect(await response.text()).toBe('[1]');
    });

    it('is abandoned when its body stops arriving part way, and the retry starts the body afresh', async () => {
        let attempts = 0;
        const fetchImpl: FetchLike = async (_url, init) => {
            attempts += 1;

            return attempts === 1 ? trickle(['[1,'], 5, false, init?.signal) : trickle(['[1,', '2]'], 5, true);
        };
        const response = await fetchRetrying('https://indexer.test/x', { fetchImpl, sleep: noSleep, stallMs: 40 });

        expect(attempts).toBe(2);
        expect(await response.json()).toEqual([1, 2]);
    });

    it('limits the silence between pieces, not the whole download: a slow, steady body is never cut off', async () => {
        const pieces = Array.from({ length: 8 }, (_, i) => (i === 0 ? '[0' : `,${i}`)).concat(']');
        let attempts = 0;
        const fetchImpl: FetchLike = async () => {
            attempts += 1;

            return trickle(pieces, 15, true);
        };
        // 9 pieces 15 ms apart take about 135 ms in all, far past the 60 ms limit.
        const response = await fetchRetrying('https://indexer.test/x', { fetchImpl, sleep: noSleep, stallMs: 60 });

        expect(attempts).toBe(1);
        expect(await response.json()).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
    });

    it('gives up as a network failure once every attempt has stalled', async () => {
        let attempts = 0;
        const fetchImpl: FetchLike = async (_url, init) => {
            attempts += 1;

            return neverAnswers(init);
        };

        await expect(
            fetchRetrying('https://indexer.test/x', { fetchImpl, sleep: noSleep, stallMs: 10 }),
        ).rejects.toThrow(new TypeError('nothing arrived for 0 s'));
        expect(attempts).toBe(RETRY_ATTEMPTS);
    });

    it('rejects as an abort, not a stall, when the run is aborted mid-attempt', async () => {
        const run = new AbortController();
        let attempts = 0;
        const fetchImpl: FetchLike = async (_url, init) => {
            attempts += 1;
            setTimeout(() => run.abort(), 5);

            return neverAnswers(init);
        };
        const outcome = fetchRetrying('https://indexer.test/x', {
            fetchImpl,
            signal: run.signal,
            sleep: noSleep,
            stallMs: 1_000,
        });

        await expect(outcome).rejects.toSatisfy((error) => !(error instanceof TypeError));
        expect(attempts).toBe(1);
    });

    it('does not count the wait before an attempt (a pacing gate) as a stall', async () => {
        let attempts = 0;
        const fetchImpl: FetchLike = async () => {
            attempts += 1;

            return new Response('[]', { status: 200 });
        };
        const response = await fetchRetrying('https://indexer.test/x', {
            fetchImpl,
            sleep: noSleep,
            stallMs: 20,
            beforeAttempt: () => new Promise((resolve) => setTimeout(resolve, 60)),
        });

        expect(attempts).toBe(1);
        expect(response.status).toBe(200);
    });

    it('hands on the status and headers of the answer it read', async () => {
        const fetchImpl: FetchLike = async () =>
            new Response('gone', { status: 404, statusText: 'Not Found', headers: { 'x-probe': 'kept' } });
        const response = await fetchRetrying('https://node.test/x', { fetchImpl, sleep: noSleep, stallMs: 50 });

        expect([response.status, response.statusText, response.headers.get('x-probe')]).toEqual([
            404,
            'Not Found',
            'kept',
        ]);
        expect(await response.text()).toBe('gone');
    });
});

describe('the node queue', () => {
    it('halves its concurrency on a 429 down to 1, then recovers one step per 50 clean reads', async () => {
        let throttle = 3;
        const queue = new NodeQueue<number>({
            sleep: noSleep,
            fetchImpl: async () => {
                if (throttle > 0) {
                    throttle -= 1;

                    return new Response('', { status: 429 });
                }

                return new Response('', { status: 200 });
            },
            read: async (level, fetchImpl) => {
                await fetchImpl(`https://node.test/${level}`);

                return level;
            },
        });

        expect(queue.concurrency).toBe(INITIAL_CONCURRENCY);
        await queue.read(1);
        expect(queue.concurrency).toBe(1);

        for (let level = 2; level < 2 + CLEAN_READS_TO_GROW; level++) {
            await queue.read(level);
        }

        expect(queue.concurrency).toBe(2);

        for (let level = 1_000; level < 1_000 + 4 * CLEAN_READS_TO_GROW; level++) {
            await queue.read(level);
        }

        expect(queue.concurrency).toBe(INITIAL_CONCURRENCY);
    });

    it('starts at 2 reads at once and never recovers past 2', async () => {
        const queue = new NodeQueue<number>({
            sleep: noSleep,
            fetchImpl: async () => new Response('', { status: 200 }),
            read: async (level, fetchImpl) => {
                await fetchImpl(`https://node.test/${level}`);

                return level;
            },
        });

        expect(INITIAL_CONCURRENCY).toBe(2);
        expect(queue.concurrency).toBe(2);

        for (let level = 0; level < 3 * CLEAN_READS_TO_GROW; level++) {
            await queue.read(level);
        }

        expect(queue.concurrency).toBe(2);
    });

    it('never runs more reads at once than its concurrency', async () => {
        let active = 0;
        let peak = 0;
        const queue = new NodeQueue<number>({
            read: async (level) => {
                active += 1;
                peak = Math.max(peak, active);
                await new Promise((resolve) => setTimeout(resolve, 1));
                active -= 1;

                return level;
            },
        });

        await Promise.all(Array.from({ length: 20 }, (_, i) => queue.read(i)));

        expect(peak).toBe(INITIAL_CONCURRENCY);
    });

    it('a 404 is not retried, and reaches the reader as it is', async () => {
        const { calls, fetchImpl } = scripted([404]);
        const queue = new NodeQueue<number>({
            fetchImpl,
            sleep: noSleep,
            read: async (level, f) => (await f(`https://node.test/${level}`)).status,
        });

        expect(await queue.read(7)).toBe(404);
        expect(calls).toHaveLength(1);
    });

    it('memoises successes only: a failed read is asked again, a successful one never', async () => {
        let failNext = true;
        const reads: number[] = [];
        const queue = new NodeQueue<string>({
            read: async (level) => {
                reads.push(level);

                if (failNext) {
                    failNext = false;
                    throw new Error('unreadable');
                }

                return `block ${level}`;
            },
        });

        await expect(queue.read(5)).rejects.toThrow('unreadable');
        expect(queue.known(5)).toBeUndefined();
        expect(await queue.read(5)).toBe('block 5');
        expect(await queue.read(5)).toBe('block 5');
        expect(reads).toEqual([5, 5]);
        expect(queue.memoLevels()).toEqual([5]);
    });

    it('shares one request between concurrent asks for the same level, and reads through its store', async () => {
        const reads: number[] = [];
        const stored = new Map<number, string>([[9, 'from the store']]);
        const queue = new NodeQueue<string>({
            read: async (level) => {
                reads.push(level);

                return `block ${level}`;
            },
            store: { get: (level) => stored.get(level), set: (level, value) => stored.set(level, value) },
        });

        const [a, b] = await Promise.all([queue.read(3), queue.read(3)]);

        expect(a).toBe('block 3');
        expect(b).toBe('block 3');
        expect(await queue.read(9)).toBe('from the store');
        expect(reads).toEqual([3]);
        expect(stored.get(3)).toBe('block 3');
    });
});
