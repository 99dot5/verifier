/**
 * Finds the identifiers in a line of report text — addresses, operation
 * hashes, keys, round and session ids, 32-byte hashes, big map ids and keys,
 * L1 levels — so the page can render each one as a value the reader copies
 * with a click.
 *
 * Pure text in, pieces out: the page builds DOM nodes from the pieces with
 * `textContent`, so nothing here is ever parsed as markup, whatever the text
 * carries (it quotes the indexer, the node and the receipts the reader pasted).
 *
 * The list of shapes is closed on purpose. A shape not listed stays plain
 * text, which costs a click; a wrong match would offer the wrong value to
 * copy, which is why bare numbers (stakes, payouts, indices) are never
 * matched and a value the report shortened with `…` is left alone.
 */

export type IdentifierKind =
    | 'address'
    | 'operation'
    | 'block'
    | 'public-key'
    | 'signature'
    | 'chain-id'
    | 'uuid'
    | 'hash'
    | 'big-map'
    | 'expression'
    | 'level';

export interface Identifier {
    readonly kind: IdentifierKind;
    readonly value: string;
}

/** Plain text, or one identifier to render as a copyable value. */
export type Piece = string | Identifier;

const B58 = '[1-9A-HJ-NP-Za-km-z]';

// Each shape is matched whole: never inside a longer run of letters and
// digits, and never when the report cut it short with `…`.
const whole = (body: string): string => `(?<![0-9A-Za-z])(?:${body})(?![0-9A-Za-z…])`;

const SHAPES: readonly (readonly [IdentifierKind, RegExp])[] = [
    // tz1–tz4 implicit accounts, KT1 contracts, sr1 smart rollups: 36 characters.
    ['address', new RegExp(whole(`(?:tz[1-4]|KT1|sr1)${B58}{33}`), 'g')],
    // Operation hashes: `o` and 50 more.
    ['operation', new RegExp(whole(`o${B58}{50}`), 'g')],
    // Block hashes: `B` and 50 more.
    ['block', new RegExp(whole(`B${B58}{50}`), 'g')],
    // Ed25519, secp256k1 and P-256 public keys.
    ['public-key', new RegExp(whole(`edpk${B58}{50}|(?:sppk|p2pk)${B58}{51}`), 'g')],
    // Ed25519 signatures.
    ['signature', new RegExp(whole(`edsig${B58}{94}`), 'g')],
    // Script expression hashes: the key a big map entry is read at.
    ['expression', new RegExp(whole(`expr${B58}{50}`), 'g')],
    // Chain ids: `Net` and 12 more.
    ['chain-id', new RegExp(whole(`Net${B58}{12}`), 'g')],
    // Round and session ids.
    ['uuid', new RegExp(whole('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'), 'g')],
    // 32-byte digests in hex: commitments, seed hashes, client seeds.
    ['hash', new RegExp(whole('[0-9a-f]{64}'), 'g')],
    // A big map's id, which the Tezos RPC takes to read an entry of it
    // (`/context/big_maps/<id>/<key hash>`): only where the text names it one.
    ['big-map', /(?<=\bbig map (?:\()?id )\d+(?!\d|[.,]\d|…)/g],
    // A level is a number only where the text names it one: right after
    // "level", "levels" or "head", or as the far end of a "levels A–B" range.
    // An approximate level (`≈6053538`) is taken without its `≈`, which stays
    // in the text beside it; a count such as `2,000` (a separator followed by
    // more digits) is not a level.
    ['level', /(?<=\b(?:[Ll]evels?|head) ≈?)\d+(?!\d|[.,]\d|…)|(?<=\b[Ll]evels \d+–)\d+(?!\d|[.,]\d|…)/g],
];

// A URL stays whole and plain: an address in its query string is part of the
// URL, and lifting it out would leave neither one easy to copy.
const URLS = /\bhttps?:\/\/\S+/g;

/** Split `text` into plain runs and the identifiers between them. */
export function splitIdentifiers(text: string): Piece[] {
    const urls = [...text.matchAll(URLS)].map((m) => ({ start: m.index, end: m.index + m[0].length }));
    const inUrl = (start: number, end: number) => urls.some((u) => start < u.end && end > u.start);
    const found: { start: number; end: number; identifier: Identifier }[] = [];

    for (const [kind, pattern] of SHAPES) {
        for (const match of text.matchAll(pattern)) {
            const start = match.index;
            const end = start + match[0].length;

            if (!inUrl(start, end)) {
                found.push({ start, end, identifier: { kind, value: match[0] } });
            }
        }
    }

    found.sort((a, b) => a.start - b.start);

    const pieces: Piece[] = [];
    let at = 0;

    for (const { start, end, identifier } of found) {
        // The shapes cannot overlap as written; if one ever does, the first wins.
        if (start < at) {
            continue;
        }

        if (start > at) {
            pieces.push(text.slice(at, start));
        }

        pieces.push(identifier);
        at = end;
    }

    if (at < text.length) {
        pieces.push(text.slice(at));
    }

    return pieces;
}
