/**
 * Public keys, signatures and addresses as they appear in an operation or a
 * contract's storage, normalised to their base58check text.
 *
 * A node renders a `key` or a `signature` the way it was submitted: the
 * readable `{"string": "sppk…"}` form, or the optimised `{"bytes": …}` form
 * some wallets and SDKs send. Both are turned into the one base58check text
 * here, so a signer set read from storage compares equal to the keys in an
 * operation whichever form either used.
 *
 * The prefix tables are the Tezos protocol's, hand-rolled like the rest of
 * the verifier's base58 handling so nothing load-bearing hides in a
 * dependency, and pinned by `keys.test.ts` against keys and addresses read
 * off a live vault. Three curves are wallet-signable (`tz1`/`tz2`/`tz3` and
 * their keys); a BLS key (`BLpk…`, forged tag `03`) is refused, as the vault
 * cannot hold one, while a BLS `tz4` ADDRESS is a chain address a treasury
 * can have and is rendered.
 */
import { base58CheckBody, encodeBase58Check } from '../wire/signature';
import { asBytes, asString, MichelineError } from './micheline';

export type KeyCurve = 'ed25519' | 'secp256k1' | 'p256';

export const CURVES: readonly KeyCurve[] = ['ed25519', 'secp256k1', 'p256'];

interface Prefixed {
    prefix: readonly number[];
    length: number;
}

const PUBLIC_KEY: Record<KeyCurve, Prefixed> = {
    ed25519: { prefix: [13, 15, 37, 217], length: 32 }, // edpk
    secp256k1: { prefix: [3, 254, 226, 86], length: 33 }, // sppk
    p256: { prefix: [3, 178, 139, 127], length: 33 }, // p2pk
};

const SIGNATURE: Record<KeyCurve, Prefixed> = {
    ed25519: { prefix: [9, 245, 205, 134, 18], length: 64 }, // edsig
    secp256k1: { prefix: [13, 115, 101, 19, 63], length: 64 }, // spsig1
    p256: { prefix: [54, 240, 44, 52], length: 64 }, // p2sig
};

/** `sig…`: a 64-byte signature that names no curve; it verifies under the key's. */
const GENERIC_SIGNATURE: Prefixed = { prefix: [4, 130, 43], length: 64 };

/** `BLpk…`, refused: the vault's `key` fields never hold one. */
const BLS_PUBLIC_KEY: Prefixed = { prefix: [6, 149, 135, 204], length: 48 };

/** Implicit-account hashes by forged curve tag, then the originated contract. */
const ADDRESS_BY_TAG: readonly Prefixed[] = [
    { prefix: [6, 161, 159], length: 20 }, // tz1, tag 00
    { prefix: [6, 161, 161], length: 20 }, // tz2, tag 01
    { prefix: [6, 161, 164], length: 20 }, // tz3, tag 02
    { prefix: [6, 161, 166], length: 20 }, // tz4, tag 03
];
const KT1: Prefixed = { prefix: [2, 90, 121], length: 20 };

/** The forged `key` tag of each curve: `00` Ed25519, `01` secp256k1, `02` P-256. */
const FORGE_TAG: Record<KeyCurve, number> = { ed25519: 0, secp256k1: 1, p256: 2 };

export interface PublicKey {
    curve: KeyCurve;
    /** 32 raw bytes for Ed25519, 33 (compressed) for the two ECDSA curves. */
    raw: Uint8Array;
    /** Base58check text under the curve's prefix. */
    text: string;
}

export interface Signature {
    /** Null for the generic `sig…` form. */
    curve: KeyCurve | null;
    /** 64 raw bytes (`r ‖ s`, or Ed25519's `R ‖ S`). */
    raw: Uint8Array;
    text: string;
}

function startsWith(body: Uint8Array, prefix: readonly number[]): boolean {
    return prefix.every((byte, index) => body[index] === byte);
}

/** Split a checksum-verified body into `(prefix, payload)` when it matches one of `candidates`. */
function classify<T extends string>(
    body: Uint8Array,
    candidates: readonly [T, Prefixed][],
): { kind: T; payload: Uint8Array } | null {
    for (const [kind, { prefix, length }] of candidates) {
        if (body.length === prefix.length + length && startsWith(body, prefix)) {
            return { kind, payload: body.slice(prefix.length) };
        }
    }

    return null;
}

/** Decode `edpk…` / `sppk…` / `p2pk…` by prefix; a BLS key or anything else is refused. */
export function decodePublicKey(text: string): PublicKey {
    const body = base58CheckBody(text);

    if (startsWith(body, BLS_PUBLIC_KEY.prefix)) {
        throw new RangeError('unsupported public key: BLS');
    }

    const found = classify(
        body,
        CURVES.map((curve) => [curve, PUBLIC_KEY[curve]] as [KeyCurve, Prefixed]),
    );

    if (!found) {
        throw new RangeError('not a public key');
    }

    return { curve: found.kind, raw: found.payload, text: text.trim() };
}

/** Decode `edsig…` / `spsig1…` / `p2sig…` / `sig…` by prefix. */
export function decodeSignature(text: string): Signature {
    const body = base58CheckBody(text);
    const found = classify(body, [
        ...CURVES.map((curve) => [curve, SIGNATURE[curve]] as [KeyCurve | 'generic', Prefixed]),
        ['generic', GENERIC_SIGNATURE],
    ]);

    if (!found) {
        throw new RangeError('not a signature');
    }

    return { curve: found.kind === 'generic' ? null : found.kind, raw: found.payload, text: text.trim() };
}

/** A public key from its forged `tag ‖ raw` form (Michelson `PACK` of a `key`). */
export function publicKeyFromForged(bytes: Uint8Array): PublicKey {
    const tag = bytes[0];
    const curve = CURVES.find((candidate) => FORGE_TAG[candidate] === tag);

    if (bytes.length === 0) {
        throw new RangeError('an empty key');
    }

    if (curve === undefined) {
        throw new RangeError(`key tag 0x${tag.toString(16).padStart(2, '0')} is not a supported curve`);
    }

    const { prefix, length } = PUBLIC_KEY[curve];

    if (bytes.length !== 1 + length) {
        throw new RangeError(`a ${curve} key is ${length} bytes, found ${bytes.length - 1}`);
    }

    const raw = bytes.slice(1);

    return { curve, raw, text: encodeBase58Check(prefix, raw) };
}

/** The forged `tag ‖ raw` form of a public key, as `PACK` emits it. */
export function forgedPublicKey(key: PublicKey): Uint8Array {
    const out = new Uint8Array(1 + key.raw.length);

    out[0] = FORGE_TAG[key.curve];
    out.set(key.raw, 1);

    return out;
}

/**
 * An address from its 22-byte forged form: `00 ‖ curve tag ‖ hash20` for an
 * implicit account (`tz1`–`tz4`), `01 ‖ hash20 ‖ 00` for an originated
 * contract with the default entrypoint.
 */
export function addressFromForged(bytes: Uint8Array): string {
    if (bytes.length !== 22) {
        throw new RangeError(`a forged address is 22 bytes, found ${bytes.length}`);
    }

    if (bytes[0] === 0x00) {
        const prefixed = ADDRESS_BY_TAG[bytes[1]];

        if (prefixed) {
            return encodeBase58Check(prefixed.prefix, bytes.slice(2));
        }
    } else if (bytes[0] === 0x01 && bytes[21] === 0x00) {
        return encodeBase58Check(KT1.prefix, bytes.slice(1, 21));
    }

    throw new RangeError(
        'forged address is neither an implicit account nor an originated contract with the default entrypoint',
    );
}

/** Check that `text` is a `tz1`–`tz4` or `KT1` address, and return it trimmed. */
export function addressTextChecked(text: string): string {
    const body = base58CheckBody(text);
    const found = classify(body, [
        ...ADDRESS_BY_TAG.map((p, i) => [`tz${i + 1}`, p] as [string, Prefixed]),
        ['KT1', KT1],
    ]);

    if (!found) {
        throw new RangeError('not an address');
    }

    return text.trim();
}

/**
 * A `key` node as `edpk…` / `sppk…` / `p2pk…`. A string is checked to decode
 * under its own prefix; bytes are the forged tag and the raw key.
 */
export function keyText(node: unknown): string {
    if (hasString(node)) {
        const text = asString(node);

        try {
            decodePublicKey(text);
        } catch (error) {
            throw new MichelineError(`'${text}' is not a public key: ${message(error)}`);
        }

        return text;
    }

    try {
        return publicKeyFromForged(asBytes(node)).text;
    } catch (error) {
        throw error instanceof MichelineError ? error : new MichelineError(message(error));
    }
}

/**
 * An `address` node as `tz1…`/`tz2…`/`tz3…`/`tz4…`/`KT1…` text. A string is
 * checked to decode under one of those prefixes; bytes are the forged form.
 */
export function addressText(node: unknown): string {
    if (hasString(node)) {
        const text = asString(node);

        try {
            return addressTextChecked(text);
        } catch (error) {
            throw new MichelineError(`'${text}' is not an address: ${message(error)}`);
        }
    }

    try {
        return addressFromForged(asBytes(node));
    } catch (error) {
        throw error instanceof MichelineError ? error : new MichelineError(message(error));
    }
}

/**
 * A `signature` node as base58check text. A string is checked to decode; 64
 * raw bytes carry no curve, so they become the generic `sig…` form, which
 * verifies against a key of any supported curve.
 */
export function signatureText(node: unknown): string {
    if (hasString(node)) {
        const text = asString(node);

        try {
            decodeSignature(text);
        } catch (error) {
            throw new MichelineError(`'${text}' is not a signature: ${message(error)}`);
        }

        return text;
    }

    const raw = asBytes(node);

    if (raw.length !== GENERIC_SIGNATURE.length) {
        throw new MichelineError(`a signature is ${GENERIC_SIGNATURE.length} bytes, found ${raw.length}`);
    }

    return encodeBase58Check(GENERIC_SIGNATURE.prefix, raw);
}

function hasString(node: unknown): boolean {
    return typeof node === 'object' && node !== null && typeof (node as { string?: unknown }).string === 'string';
}

function message(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}
