/**
 * Reading Micheline JSON, as a Tezos node renders it in block metadata and
 * contract scripts, by FIELD ANNOTATION rather than by position.
 *
 * The vault's events are emitted with their type (`with_type=True`), its
 * storage type is in its script, and the `fast_payout` parameter type is
 * fixed by the contract. Walking a value through its type and keeping the
 * `%field`-annotated leaves makes the reader independent of how the record
 * is laid out (SmartPy emits a right comb in alphabetical field order today)
 * and turns any shape surprise into a named error instead of a misread
 * amount. The same rule, in the same words, is what the public payout
 * watcher reads the chain by; this is its port.
 */

export class MichelineError extends Error {}

type Json = Record<string, unknown>;

function isObject(node: unknown): node is Json {
    return typeof node === 'object' && node !== null && !Array.isArray(node);
}

function prim(node: unknown): string | null {
    return isObject(node) && typeof node.prim === 'string' ? node.prim : null;
}

function args(node: unknown): unknown[] {
    return isObject(node) && Array.isArray(node.args) ? node.args : [];
}

/** The `%name` field annotation of a type node, if any. */
function fieldAnnotation(ty: unknown): string | null {
    if (!isObject(ty) || !Array.isArray(ty.annots)) {
        return null;
    }

    for (const annotation of ty.annots) {
        if (typeof annotation === 'string' && annotation.startsWith('%')) {
            return annotation.slice(1);
        }
    }

    return null;
}

function describe(node: unknown): string {
    return JSON.stringify(node ?? null);
}

/**
 * Split an n-ary `pair` type into its first component and the comb of the
 * rest (`pair a b c` is `pair a (pair b c)`).
 */
function splitPairType(ty: unknown): [unknown, unknown] {
    const parts = args(ty);

    if (parts.length < 2) {
        throw new MichelineError('a pair type with fewer than two components');
    }

    return parts.length === 2 ? [parts[0], parts[1]] : [parts[0], { prim: 'pair', args: parts.slice(1) }];
}

/**
 * Split a pair VALUE the same way: `Pair a b c`, `Pair a (Pair b c)` and the
 * sequence form `[a, b, c]` the node may render a comb as are all accepted.
 */
function splitPairValue(value: unknown): [unknown, unknown] {
    let parts: unknown[];

    if (Array.isArray(value)) {
        parts = value;
    } else if (prim(value) === 'Pair') {
        parts = args(value);
    } else {
        throw new MichelineError(`expected a Pair, found ${describe(value)}`);
    }

    if (parts.length < 2) {
        throw new MichelineError('a Pair with fewer than two components');
    }

    return parts.length === 2 ? [parts[0], parts[1]] : [parts[0], { prim: 'Pair', args: parts.slice(1) }];
}

/** Every `%field`-annotated node of `value`, read through its type `ty`. */
export function fields(ty: unknown, value: unknown): Map<string, unknown> {
    const out = new Map<string, unknown>();

    collect(ty, value, out);

    return out;
}

function collect(ty: unknown, value: unknown, out: Map<string, unknown>): void {
    const name = fieldAnnotation(ty);

    if (name !== null) {
        if (out.has(name)) {
            throw new MichelineError(`field %${name} appears twice in the type`);
        }

        out.set(name, value);
    }

    if (prim(ty) === 'pair') {
        const [tyFirst, tyRest] = splitPairType(ty);
        const [first, rest] = splitPairValue(value);

        collect(tyFirst, first, out);
        collect(tyRest, rest, out);
    }
}

/** The named field, or an error naming it. */
export function field(found: Map<string, unknown>, name: string): unknown {
    if (!found.has(name)) {
        throw new MichelineError(`no %${name} field`);
    }

    return found.get(name);
}

/**
 * An `int` node (a `mutez`, a `nat`) as a non-negative bigint. Negative or
 * non-numeric text is refused: no amount in this protocol is negative.
 */
export function asNat(node: unknown): bigint {
    const text = isObject(node) && typeof node.int === 'string' ? node.int : null;

    if (text === null) {
        throw new MichelineError(`expected an int, found ${describe(node)}`);
    }

    if (!/^\d+$/.test(text)) {
        throw new MichelineError(`'${text}' is not a non-negative integer`);
    }

    return BigInt(text);
}

/** A `bytes` node. */
export function asBytes(node: unknown): Uint8Array {
    const text = isObject(node) && typeof node.bytes === 'string' ? node.bytes : null;

    if (text === null) {
        throw new MichelineError(`expected bytes, found ${describe(node)}`);
    }

    if (!/^([0-9a-fA-F]{2})*$/.test(text)) {
        throw new MichelineError('bytes are not hex');
    }

    const out = new Uint8Array(text.length / 2);

    for (let i = 0; i < out.length; i++) {
        out[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
    }

    return out;
}

/** A `string` node. */
export function asString(node: unknown): string {
    if (isObject(node) && typeof node.string === 'string') {
        return node.string;
    }

    throw new MichelineError(`expected a string, found ${describe(node)}`);
}

/** The elements of a `set` / `list` node. */
export function asSequence(node: unknown): unknown[] {
    if (Array.isArray(node)) {
        return node;
    }

    throw new MichelineError(`expected a sequence, found ${describe(node)}`);
}

/** The `(key, value)` entries of a `map` node. */
export function asMap(node: unknown): [unknown, unknown][] {
    return asSequence(node).map((elt) => {
        const parts = args(elt);

        if (prim(elt) !== 'Elt' || parts.length !== 2) {
            throw new MichelineError(`expected an Elt, found ${describe(elt)}`);
        }

        return [parts[0], parts[1]];
    });
}

/** Lowercase hex of `bytes`, the form a session id is compared in. */
export function bytesToHex(bytes: Uint8Array): string {
    let out = '';

    for (const byte of bytes) {
        out += byte.toString(16).padStart(2, '0');
    }

    return out;
}
