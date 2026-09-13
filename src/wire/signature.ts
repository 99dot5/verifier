/**
 * Ed25519 verification of sequencer inbox messages.
 *
 * The injector signs `blake2b-256(borsh(VersionedEnvelope))` — the Tezos
 * convention of a Blake2b pre-hash, applied explicitly (mirrors
 * `services/sequencer/src/injector/signer.rs` and the kernel's
 * `libs/smart-rollup/src/signature.rs`). The public key is the tenant's
 * sequencer key, registered ON-CHAIN by the administrator contract's
 * `RegisterTenant` / `RotateSequencerKey` operations and stored in rollup
 * durable storage at `/tenants/{t}/sequencer-keys/current` — so the
 * whole chain of trust is derivable from L1 without any operator input.
 *
 * `@noble/ed25519` v2 ships without a hash; wire its synchronous SHA-512 in
 * once, as an import side effect (same pattern as libs/casino-client).
 */
import * as ed from '@noble/ed25519';
import { blake2b } from '@noble/hashes/blake2.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

/** Base58 alphabet (Bitcoin/Tezos). */
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/** Tezos edpk prefix bytes (ed25519 public key, base58check payload 32 bytes). */
const EDPK_PREFIX = [13, 15, 37, 217] as const;

/** Tezos KT1 prefix bytes (originated contract, base58check payload = 20-byte hash). */
const KT1_PREFIX = [2, 90, 121] as const;

/**
 * Decode a Tezos `edpk…` base58check string to the 32 raw Ed25519 public key
 * bytes. Self-contained (~30 lines) rather than a dependency, so the
 * published verifier source has nothing load-bearing hidden in node_modules.
 */
export function decodeEdpk(edpk: string): Uint8Array {
    const decoded = base58Decode(edpk.trim());

    if (decoded.length !== 4 + 32 + 4) {
        throw new RangeError(`not an edpk: decoded length ${decoded.length}`);
    }

    const body = decoded.slice(0, 36);
    const checksum = decoded.slice(36);
    const digest = sha256sha256(body);

    for (let i = 0; i < 4; i++) {
        if (checksum[i] !== digest[i]) {
            throw new RangeError('bad base58check checksum');
        }

        if (body[i] !== EDPK_PREFIX[i]) {
            throw new RangeError('not an edpk prefix');
        }
    }

    return body.slice(4);
}

/**
 * Base58check-ENCODE a prefixed payload. The mirror of {@link decodeEdpk},
 * needed because the administrator lineage reads keys and addresses off L1 as
 * RAW BYTES (Michelson `PACK` emits `00 ‖ 32` for an Ed25519 key and
 * `01 ‖ 20 ‖ 00` for an originated address), while every human-facing
 * comparison — the operator's `tenants.yaml`, a block explorer, the `Welcome`
 * frame — is in base58. Hand-rolled for the same reason the decoder is: the
 * published verifier must have nothing load-bearing hidden in node_modules.
 */
function encodeBase58Check(prefix: readonly number[], payload: Uint8Array): string {
    const body = new Uint8Array(prefix.length + payload.length);

    body.set(prefix, 0);
    body.set(payload, prefix.length);

    const checked = new Uint8Array(body.length + 4);

    checked.set(body, 0);
    checked.set(sha256sha256(body).slice(0, 4), body.length);

    let big = 0n;

    for (const byte of checked) {
        big = (big << 8n) | BigInt(byte);
    }

    let out = '';

    while (big > 0n) {
        out = ALPHABET[Number(big % 58n)] + out;
        big /= 58n;
    }

    // Each leading zero byte is one leading '1' — base58 loses them to the
    // bigint, and a KT1/edpk payload can legitimately start with 0x00.
    for (const byte of checked) {
        if (byte !== 0) {
            break;
        }

        out = '1' + out;
    }

    return out;
}

/** Encode 32 raw Ed25519 public-key bytes as `edpk…`. */
export function encodeEdpk(raw: Uint8Array): string {
    if (raw.length !== 32) {
        throw new RangeError(`edpk payload must be 32 bytes, got ${raw.length}`);
    }

    return encodeBase58Check(EDPK_PREFIX, raw);
}

/** Encode a 20-byte originated-contract hash as `KT1…`. */
export function encodeKt1(hash: Uint8Array): string {
    if (hash.length !== 20) {
        throw new RangeError(`KT1 payload must be 20 bytes, got ${hash.length}`);
    }

    return encodeBase58Check(KT1_PREFIX, hash);
}

/** Verify one inbox message signature: `ed25519.verify(sig, blake2b256(payload), pk)`. */
export function verifyInboxSignature(
    signature: Uint8Array,
    signedPayload: Uint8Array,
    publicKey: Uint8Array,
): boolean {
    const digest = blake2b(signedPayload, { dkLen: 32 });

    try {
        return ed.verify(signature, digest, publicKey);
    } catch {
        return false;
    }
}

function base58Decode(value: string): Uint8Array {
    let big = 0n;

    for (const char of value) {
        const index = ALPHABET.indexOf(char);

        if (index < 0) {
            throw new RangeError(`invalid base58 character: ${JSON.stringify(char)}`);
        }

        big = big * 58n + BigInt(index);
    }

    const bytes: number[] = [];

    while (big > 0n) {
        bytes.unshift(Number(big & 0xffn));
        big >>= 8n;
    }

    for (const char of value) {
        if (char !== '1') {
            break;
        }

        bytes.unshift(0);
    }

    return new Uint8Array(bytes);
}

function sha256sha256(bytes: Uint8Array): Uint8Array {
    return sha256(sha256(bytes));
}

// ── Play-receipt frames (ADR 0022) ──────────────────────────────────────

/** Tag byte of a signed server frame: `[0x06 | signature(64) | protobuf]`. */
export const SERVER_FRAME_TAG = 0x06;

/** Tag byte of a signed player command: `[0x05 | signature(64) | protobuf]`. */
export const CLIENT_FRAME_TAG = 0x05;

export const SIGNATURE_LENGTH = 64;

/**
 * Domain separator hashed in front of a SERVER frame's protobuf body.
 *
 * ASCII `99dot5:server-frame:v1`, owned by `services/sequencer/src/codec.rs`
 * and pinned by `libs/proto-definitions/testdata/receipt-vectors.json`. The
 * sequencer key signs both WS frames and rollup inbox messages through the
 * same `ed25519(blake2b-256(bytes))` chain, so the prefix is the ONLY thing
 * that stops a signature harvested from one channel being presented as valid
 * on the other. A verifier that dropped it would accept exactly that forgery.
 */
export const RECEIPT_DOMAIN = new TextEncoder().encode('99dot5:server-frame:v1');

export interface SignedFrame {
    tag: number;
    signature: Uint8Array;
    /** The protobuf body — what the signature covers, and nothing else. */
    body: Uint8Array;
}

/** Split `[tag | signature(64) | body]`; throws on anything shorter. */
export function splitSignedFrame(bytes: Uint8Array): SignedFrame {
    if (bytes.length < 1 + SIGNATURE_LENGTH) {
        throw new RangeError(`signed frame is ${bytes.length} bytes, shorter than tag + signature`);
    }

    return {
        tag: bytes[0],
        signature: bytes.slice(1, 1 + SIGNATURE_LENGTH),
        body: bytes.slice(1 + SIGNATURE_LENGTH),
    };
}

/** `ed25519.verify(sig, blake2b-256(RECEIPT_DOMAIN ‖ body), pk)`. */
export function verifyServerFrameSignature(
    signature: Uint8Array,
    body: Uint8Array,
    publicKey: Uint8Array,
): boolean {
    const preimage = new Uint8Array(RECEIPT_DOMAIN.length + body.length);

    preimage.set(RECEIPT_DOMAIN, 0);
    preimage.set(body, RECEIPT_DOMAIN.length);

    return verifyInboxSignature(signature, preimage, publicKey);
}
