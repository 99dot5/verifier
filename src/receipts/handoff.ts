/**
 * Receipts handed over in the URL fragment by a game's "Verify this round"
 * (ADR 0026 §2.3).
 *
 * The game opens this page at `…/verify/#receipts=<scheme>.<base64url>` with
 * the round's `ReceiptsExportV1` inside, so the reader lands with the round
 * loaded instead of saving a file and picking it again. The fragment is never
 * sent to a server, which keeps this page's promise — nothing is uploaded —
 * true for the hand-off too.
 *
 * Schemes:
 * - `gz`   — gzip of the export's JSON text;
 * - `json` — the UTF-8 JSON text itself (a browser without `CompressionStream`).
 *
 * The encoder is `libs/casino-client/src/receipts/handoff.ts`. This module only
 * turns the fragment back into the text the file picker would have produced;
 * whether that text is a valid export is `importReceipts`'s question, asked
 * exactly as it is for a file, so a hand-off is no more trusted than a file.
 *
 * A link may instead carry only a round id (`#round=<uuid>`), which prefills
 * the round field and nothing else. When both are present the receipts win:
 * they name their own round. Beside the round id the link may carry the
 * round's L1 locators (`transcriptLevel`, `transcriptOp`, `seedBatchLevel`,
 * `seedBatchOp`, {@link readHintHandoff}): hints this page confirms against
 * L1, never evidence.
 */

/** The fragment parameter the game writes. */
export const RECEIPTS_FRAGMENT_KEY = 'receipts';

/**
 * The fragment parameter carrying a bare round id (`#round=<uuid>`), from a
 * page that knows the round but holds no receipts for it. It only fills in the
 * round field: the round is then checked against the chain alone, exactly as
 * if the reader had typed the id.
 */
export const ROUND_FRAGMENT_KEY = 'round';

/** The fragment parameters carrying the locator hints beside a bare round id; each is optional. */
export const TRANSCRIPT_LEVEL_FRAGMENT_KEY = 'transcriptLevel';
export const TRANSCRIPT_OP_FRAGMENT_KEY = 'transcriptOp';
export const SEED_BATCH_LEVEL_FRAGMENT_KEY = 'seedBatchLevel';
export const SEED_BATCH_OP_FRAGMENT_KEY = 'seedBatchOp';

/**
 * Where the round's transcript and its seed batch sit on L1, as the sender
 * reported them: HINTS this page confirms against L1, never evidence. A hint
 * narrows or relocates a search within kernel-sound bounds and never decides
 * a verdict. The same shape arrives as an export's `locatorHints` or as the
 * hand-off's fragment keys. A batch known only by the level the kernel
 * recorded has `operationHash: null`.
 */
export interface LocatorHints {
    transcript?: { level: number; operationHash: string };
    seedBatch?: { level: number; operationHash: string | null };
}

/** An L1 block level as a hint states it: a positive safe integer. */
export function isLocatorLevel(value: unknown): value is number {
    return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

/** A Tezos operation hash (`o…`, base58check, 51 characters). Grammar only; L1 decides whether it exists. */
export function isOperationHash(value: unknown): value is string {
    return typeof value === 'string' && /^o[1-9A-HJ-NP-Za-km-z]{50}$/.test(value);
}

/** The largest decoded document this page accepts from a fragment (bytes). */
export const MAX_HANDOFF_JSON_BYTES = 32 * 1024 * 1024;

function fromBase64Url(text: string): Uint8Array {
    if (!/^[A-Za-z0-9_-]*$/.test(text)) {
        throw new Error('the receipts in the link are not base64url');
    }

    const padded = text.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - (text.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i += 1) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
}

async function gunzip(bytes: Uint8Array): Promise<Uint8Array> {
    if (typeof DecompressionStream !== 'function') {
        throw new Error('this browser cannot decompress the receipts in the link; export them as a file instead');
    }

    const source = new ReadableStream<Uint8Array>({
        start(controller) {
            controller.enqueue(bytes);
            controller.close();
        },
    });
    const stream = source.pipeThrough(
        new DecompressionStream('gzip') as unknown as TransformStream<Uint8Array, Uint8Array>,
    );
    const reader = stream.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;

    for (;;) {
        const { done, value } = await reader.read();

        if (done) {
            break;
        }

        total += value.length;

        // A bounded read: a small fragment must not inflate into a page-killer.
        if (total > MAX_HANDOFF_JSON_BYTES) {
            await reader.cancel();
            throw new Error('the receipts in the link are too large');
        }

        chunks.push(value);
    }

    const out = new Uint8Array(total);
    let offset = 0;

    for (const chunk of chunks) {
        out.set(chunk, offset);
        offset += chunk.length;
    }

    return out;
}

/**
 * The receipts JSON text carried by a location fragment (`#receipts=…`), or
 * `null` when the fragment carries none. Throws, with a reader-facing
 * message, when it carries something that does not decode.
 */
export async function readReceiptsHandoff(hash: string): Promise<string | null> {
    const params = new URLSearchParams(hash.startsWith('#') ? hash.slice(1) : hash);
    const value = params.get(RECEIPTS_FRAGMENT_KEY);

    if (value === null) {
        return null;
    }

    const dot = value.indexOf('.');
    const scheme = dot < 0 ? '' : value.slice(0, dot);
    const payload = fromBase64Url(value.slice(dot + 1));

    let bytes: Uint8Array;

    switch (scheme) {
        case 'gz':
            bytes = await gunzip(payload);
            break;
        case 'json':
            if (payload.length > MAX_HANDOFF_JSON_BYTES) {
                throw new Error('the receipts in the link are too large');
            }

            bytes = payload;
            break;
        default:
            throw new Error(`the receipts in the link use an unknown encoding "${scheme}"`);
    }

    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

/**
 * The round id carried by a location fragment (`#round=…`), as a lowercase
 * hyphenated UUID, or `null` when the fragment carries none. Accepts the
 * hyphenated form and the bare 32-hex form. Throws, with a reader-facing
 * message, when the value is not a UUID — it is never passed on as typed.
 */
export function readRoundHandoff(hash: string): string | null {
    const params = new URLSearchParams(hash.startsWith('#') ? hash.slice(1) : hash);
    const value = params.get(ROUND_FRAGMENT_KEY);

    if (value === null) {
        return null;
    }

    const text = value.trim().toLowerCase();
    const hex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(text)
        ? text.replaceAll('-', '')
        : text;

    if (!/^[0-9a-f]{32}$/.test(hex)) {
        throw new Error('the round ID in the link is not a UUID');
    }

    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** The locator hints a fragment carried, and what was wrong with any it dropped. */
export interface HintHandoff {
    /** `null` when the fragment carries no usable hint. */
    hints: LocatorHints | null;
    /** Reader-facing notes, one per dropped key or hint. Findings, never failures. */
    findings: string[];
}

/**
 * The locator hints carried beside a bare round id
 * (`#round=<uuid>&transcriptLevel=<n>&transcriptOp=<o…>&seedBatchLevel=<n>&seedBatchOp=<o…>`).
 *
 * Never throws, and reads nothing about the round itself: a malformed hint is
 * dropped with a finding while `round` stands, because a hint only narrows a
 * search and losing one costs a slower scan, never a verdict. A transcript
 * hint needs both its level and its operation hash; a batch hint needs its
 * level, and a missing or malformed `seedBatchOp` leaves the level alone.
 */
export function readHintHandoff(hash: string): HintHandoff {
    const params = new URLSearchParams(hash.startsWith('#') ? hash.slice(1) : hash);
    const findings: string[] = [];
    const hints: LocatorHints = {};

    /** A present key's value through `parse`; `undefined` when it is absent, or malformed (with a finding). */
    const read = <T>(key: string, parse: (text: string) => T | null, grammar: string): T | undefined => {
        const text = params.get(key);

        if (text === null) {
            return undefined;
        }

        const value = parse(text);

        if (value === null) {
            findings.push(`the link's ${key} hint is not ${grammar}; it was ignored`);

            return undefined;
        }

        return value;
    };
    const level = (text: string) => (/^[1-9]\d*$/.test(text) && isLocatorLevel(Number(text)) ? Number(text) : null);
    const operation = (text: string) => (isOperationHash(text) ? text : null);
    const LEVEL = 'a positive integer level';
    const OPERATION = 'an operation hash (o…)';

    const transcriptLevel = read(TRANSCRIPT_LEVEL_FRAGMENT_KEY, level, LEVEL);
    const transcriptOp = read(TRANSCRIPT_OP_FRAGMENT_KEY, operation, OPERATION);

    if (transcriptLevel !== undefined && transcriptOp !== undefined) {
        hints.transcript = { level: transcriptLevel, operationHash: transcriptOp };
    } else if (transcriptLevel !== undefined || transcriptOp !== undefined) {
        findings.push(
            `the link's transcript hint needs both ${TRANSCRIPT_LEVEL_FRAGMENT_KEY} and ${TRANSCRIPT_OP_FRAGMENT_KEY}; it was ignored`,
        );
    }

    const batchLevel = read(SEED_BATCH_LEVEL_FRAGMENT_KEY, level, LEVEL);
    const batchOp = read(SEED_BATCH_OP_FRAGMENT_KEY, operation, OPERATION);

    if (batchLevel !== undefined) {
        hints.seedBatch = { level: batchLevel, operationHash: batchOp ?? null };
    } else if (batchOp !== undefined) {
        findings.push(
            `the link's seed batch hint needs ${SEED_BATCH_LEVEL_FRAGMENT_KEY}; ${SEED_BATCH_OP_FRAGMENT_KEY} alone was ignored`,
        );
    }

    return { hints: hints.transcript || hints.seedBatch ? hints : null, findings };
}
