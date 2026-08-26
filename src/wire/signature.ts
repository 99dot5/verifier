/**
 * Ed25519 verification of sequencer inbox messages.
 *
 * The injector signs `blake2b-256(borsh(VersionedEnvelope))` — the Tezos
 * convention of a Blake2b pre-hash, applied explicitly (mirrors
 * `services/sequencer/src/injector/signer.rs` and the kernel's
 * `libs/smart-rollup/src/signature.rs`). The public key is the tenant's
 * sequencer key, registered ON-CHAIN by the administrator contract's
 * `RegisterTenant` / `RotateSequencerKey` operations and stored in rollup
 * durable storage at `/tenants/{t}/config/sequencer-keys/current` — so the
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
