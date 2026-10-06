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
 * The encoder is `libs/game-shell/src/receipts-handoff.ts`. This module only
 * turns the fragment back into the text the file picker would have produced;
 * whether that text is a valid export is `importReceipts`'s question, asked
 * exactly as it is for a file, so a hand-off is no more trusted than a file.
 */

/** The fragment parameter the game writes. */
export const RECEIPTS_FRAGMENT_KEY = 'receipts';

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
