/**
 * The one retry rule every scan request follows, and the queue the node reads
 * go through.
 *
 * Retry rule, shared by the indexer locator and the node reads: HTTP 429, 502,
 * 503 and 504 and a network failure (a fetch `TypeError`, or an attempt that
 * receives nothing for {@link STALL_TIMEOUT_MS}) are retried, up to
 * {@link RETRY_ATTEMPTS} attempts in all, with a back-off of 2, 4, 8 and 16
 * seconds; a readable `Retry-After` replaces the back-off, capped at 16
 * seconds. Any other status is returned as it is and never retried: a 404 from
 * a node means the block is not served there, which asking again cannot
 * change. After the last attempt the caller treats the chunk or level as
 * unread, never as empty.
 *
 * The queue runs node reads concurrently, 2 at a time at most. A 429 halves
 * that (down to 1), and 50 reads in a row without one add 1 back, up to 2. A
 * public node is shared with everyone else and publishes no rate limit, so
 * the queue asks gently from the start and backs off the moment it is told
 * to.
 */

/** Attempts per request, the first included. */
export const RETRY_ATTEMPTS = 5;

/** The statuses worth asking again: rate limiting and a gateway or upstream that is briefly down. */
export const RETRYABLE_STATUSES: ReadonlySet<number> = new Set([429, 502, 503, 504]);

/** The back-off before the second attempt; each later one doubles it. */
export const FIRST_BACKOFF_MS = 2_000;

/** The longest wait between attempts, whether a back-off or a `Retry-After` header asks for it. */
export const RETRY_AFTER_CAP_MS = 16_000;

/** Node reads in flight at the start, and the most the queue ever recovers to. */
export const INITIAL_CONCURRENCY = 2;

/** Clean reads in a row after which one more concurrent read is allowed. */
export const CLEAN_READS_TO_GROW = 50;

/** A `fetch`-compatible function; the shell passes the browser's, a test a stub. */
export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

/** Whether `error` is an abort, rather than a failure of the request itself. */
export function isAbort(error: unknown): boolean {
    return error instanceof DOMException && error.name === 'AbortError';
}

/** Waits `ms`, or rejects as soon as `signal` aborts. */
export type Sleep = (ms: number, signal?: AbortSignal) => Promise<void>;

export const abortableSleep: Sleep = (ms, signal) =>
    new Promise((resolve, reject) => {
        if (signal?.aborted) {
            reject(signal.reason);

            return;
        }

        const onAbort = () => {
            clearTimeout(timer);
            reject(signal?.reason);
        };
        const timer = setTimeout(() => {
            signal?.removeEventListener('abort', onAbort);
            resolve();
        }, ms);

        signal?.addEventListener('abort', onAbort, { once: true });
    });

/**
 * An attempt that receives nothing for this long, neither its headers nor
 * another piece of its body, is abandoned and counts as a network failure.
 * A connection can stall without ever erroring, and the browser then waits
 * for it forever; a scan's largest page (about 4 MB) still gets this long
 * between any two pieces, however slow the line.
 */
export const STALL_TIMEOUT_MS = 20_000;

export interface RetryOptions {
    fetchImpl?: FetchLike;
    signal?: AbortSignal;
    sleep?: Sleep;
    /** Called on every 429, before the wait. */
    onThrottle?(): void;
    /** Awaited before every attempt, outside the stall clock: a pacing gate's wait is not a stall. */
    beforeAttempt?(): Promise<void>;
    /** {@link STALL_TIMEOUT_MS} unless a test passes its own. */
    stallMs?: number;
}

/** Statuses whose response carries no body, which `new Response` refuses one for. */
const NULL_BODY_STATUSES: ReadonlySet<number> = new Set([101, 204, 205, 304]);

/**
 * One attempt: the fetch, then its whole body, read here so that a stall
 * anywhere is caught. The answer is handed on as a fresh `Response` over the
 * bytes already read. A stall rejects with a `TypeError`, as a dropped
 * connection would; an abort of `signal` rejects as an abort.
 */
async function fetchOnce(
    url: string,
    doFetch: FetchLike,
    signal: AbortSignal | undefined,
    stallMs: number,
): Promise<Response> {
    const attempt = new AbortController();
    const forward = () => attempt.abort(signal?.reason);
    let stalled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    // (Re)starts the stall clock: on sending, on the headers, on every piece of the body.
    const heard = () => {
        clearTimeout(timer);
        timer = setTimeout(() => {
            stalled = true;
            attempt.abort();
        }, stallMs);
    };

    signal?.addEventListener('abort', forward, { once: true });

    try {
        heard();

        const response = await doFetch(url, { signal: attempt.signal });
        const reader = response.body?.getReader();

        if (!reader) {
            return response;
        }

        heard();

        const pieces: Uint8Array[] = [];

        for (;;) {
            const { done, value } = await reader.read();

            if (done) {
                break;
            }

            pieces.push(value);
            heard();
        }

        const body = new Uint8Array(pieces.reduce((total, piece) => total + piece.length, 0));
        let offset = 0;

        for (const piece of pieces) {
            body.set(piece, offset);
            offset += piece.length;
        }

        return new Response(NULL_BODY_STATUSES.has(response.status) ? null : body, {
            status: response.status,
            statusText: response.statusText,
            headers: response.headers,
        });
    } catch (error) {
        if (stalled && !signal?.aborted) {
            throw new TypeError(`nothing arrived for ${Math.round(stallMs / 1_000)} s`);
        }

        throw error;
    } finally {
        clearTimeout(timer);
        signal?.removeEventListener('abort', forward);
    }
}

/**
 * The wait before attempt `attempt + 1`: the server's `Retry-After` when it
 * is readable (seconds or an HTTP date), else 2, 4, 8, 16 s; capped either way.
 */
export function retryDelayMs(attempt: number, retryAfter: string | null, now: number = Date.now()): number {
    if (retryAfter !== null) {
        const trimmed = retryAfter.trim();
        const seconds = /^\d+$/.test(trimmed) ? Number(trimmed) * 1_000 : Date.parse(trimmed) - now;

        if (Number.isFinite(seconds)) {
            return Math.min(RETRY_AFTER_CAP_MS, Math.max(0, seconds));
        }
    }

    return Math.min(RETRY_AFTER_CAP_MS, FIRST_BACKOFF_MS * 2 ** (attempt - 1));
}

/**
 * Fetch `url` under the retry rule. Resolves with the last response, whatever
 * its status (the caller decides what a non-2xx means); rejects with the last
 * network error once the attempts run out, and at once on an abort.
 */
export async function fetchRetrying(url: string, options: RetryOptions = {}): Promise<Response> {
    const doFetch = options.fetchImpl ?? fetch;
    const sleep = options.sleep ?? abortableSleep;

    for (let attempt = 1; ; attempt++) {
        options.signal?.throwIfAborted();

        let response: Response;

        await options.beforeAttempt?.();

        try {
            response = await fetchOnce(url, doFetch, options.signal, options.stallMs ?? STALL_TIMEOUT_MS);
        } catch (error) {
            if (!(error instanceof TypeError) || attempt >= RETRY_ATTEMPTS || options.signal?.aborted) {
                throw error;
            }

            await sleep(retryDelayMs(attempt, null), options.signal);

            continue;
        }

        if (!RETRYABLE_STATUSES.has(response.status) || attempt >= RETRY_ATTEMPTS) {
            return response;
        }

        if (response.status === 429) {
            options.onThrottle?.();
        }

        const retryAfter = typeof response.headers?.get === 'function' ? response.headers.get('Retry-After') : null;

        await sleep(retryDelayMs(attempt, retryAfter), options.signal);
    }
}

/** A store the queue reads through and writes successes to; the range cache keeps only final levels in it. */
export interface NodeReadStore<T> {
    get(level: number): T | undefined;
    set(level: number, value: T): void;
}

export interface NodeQueueOptions<T> {
    /** One level's read; `fetchImpl` already applies the retry rule and reports 429s to the queue. */
    read(level: number, fetchImpl: FetchLike): Promise<T>;
    fetchImpl?: FetchLike;
    signal?: AbortSignal;
    sleep?: Sleep;
    store?: NodeReadStore<T>;
}

/**
 * Node reads with adaptive concurrency and a success-only memo. A level read
 * once in a run is never read again in it, whether the scan or a hint
 * confirmation asked first; a failed read is not remembered, so asking again
 * retries it.
 */
export class NodeQueue<T> {
    private limit = INITIAL_CONCURRENCY;
    private active = 0;
    private cleanStreak = 0;
    private readonly waiting: (() => void)[] = [];
    private readonly memo = new Map<number, T>();
    private readonly inflight = new Map<number, Promise<T>>();
    /** Every level a request went out for, in order, retries not repeated. */
    readonly fetched: number[] = [];

    constructor(private readonly options: NodeQueueOptions<T>) {}

    /** How many reads may run at once right now. */
    get concurrency(): number {
        return this.limit;
    }

    /** The level's read when this run, or the store, already holds one. */
    known(level: number): T | undefined {
        return this.memo.get(level) ?? this.options.store?.get(level);
    }

    /** Every level this run holds a read for. */
    memoLevels(): number[] {
        return [...this.memo.keys()];
    }

    read(level: number): Promise<T> {
        const known = this.known(level);

        if (known !== undefined) {
            this.memo.set(level, known);

            return Promise.resolve(known);
        }

        const pending = this.inflight.get(level);

        if (pending) {
            return pending;
        }

        const started = this.run(level);
        const settle = () => {
            this.inflight.delete(level);
        };

        this.inflight.set(level, started);
        started.then(settle, settle);

        return started;
    }

    private async run(level: number): Promise<T> {
        await this.acquire();

        let throttled = false;

        try {
            this.options.signal?.throwIfAborted();
            this.fetched.push(level);

            const fetchImpl: FetchLike = (url) =>
                fetchRetrying(url, {
                    fetchImpl: this.options.fetchImpl,
                    signal: this.options.signal,
                    sleep: this.options.sleep,
                    onThrottle: () => {
                        throttled = true;
                        this.throttle();
                    },
                });
            const value = await this.options.read(level, fetchImpl);

            this.memo.set(level, value);
            this.options.store?.set(level, value);

            if (!throttled) {
                this.cleanRead();
            }

            return value;
        } finally {
            this.release();
        }
    }

    private throttle(): void {
        this.limit = Math.max(1, Math.floor(this.limit / 2));
        this.cleanStreak = 0;
    }

    private cleanRead(): void {
        this.cleanStreak += 1;

        if (this.cleanStreak >= CLEAN_READS_TO_GROW) {
            this.cleanStreak = 0;
            this.limit = Math.min(INITIAL_CONCURRENCY, this.limit + 1);
            this.wake();
        }
    }

    private acquire(): Promise<void> {
        if (this.active < this.limit) {
            this.active += 1;

            return Promise.resolve();
        }

        return new Promise((resolve) => {
            this.waiting.push(() => {
                this.active += 1;
                resolve();
            });
        });
    }

    private release(): void {
        this.active -= 1;
        this.wake();
    }

    private wake(): void {
        while (this.active < this.limit) {
            const next = this.waiting.shift();

            if (!next) {
                return;
            }

            next();
        }
    }
}
