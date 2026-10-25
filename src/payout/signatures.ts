/**
 * Re-verifying a submitted fast payout's signatures against the vault's own
 * `payout_signers`, over the one shared payload.
 *
 * The vault counts an entry only when its key is in the set and its signature
 * verifies over `PACK(("fast-payout:v1", chain_id, vault, session_id,
 * amount))`, and ignores keys outside the set. This port reports what the
 * vault ignores, too: an entry from outside the set means a key nobody
 * registered was handed a signing request.
 *
 * Every Tezos signature is over `blake2b-256(message)`: Ed25519 signs the
 * digest as its message, the two ECDSA curves sign the digest as their
 * prehash. secp256k1 signatures must be low-S, as the chain requires; P-256
 * has no such rule. A signature whose prefix names one curve offered against
 * a key of another is a mismatch, never verified under either.
 */
import { p256 } from '@noble/curves/p256';
import { secp256k1 } from '@noble/curves/secp256k1';
import { blake2b } from '@noble/hashes/blake2.js';
import { verifyPrehashedSignature } from '../wire/signature';
import { decodePublicKey, decodeSignature } from './keys';
import { fastPayoutPayload, PAYOUT_THRESHOLD } from './payload';

export type SignatureCheck = { ok: true } | { ok: false; reason: string };

/** Verify one `(key, signature)` entry over `payload`. */
export function verifyFastPayoutSignature(publicKey: string, signature: string, payload: Uint8Array): SignatureCheck {
    let key;
    let sig;

    try {
        key = decodePublicKey(publicKey);
    } catch (error) {
        return { ok: false, reason: `the key does not decode: ${message(error)}` };
    }

    try {
        sig = decodeSignature(signature);
    } catch (error) {
        return { ok: false, reason: `the signature does not decode: ${message(error)}` };
    }

    if (sig.curve !== null && sig.curve !== key.curve) {
        return { ok: false, reason: `a ${sig.curve} signature offered against a ${key.curve} key` };
    }

    let verified: boolean;

    try {
        switch (key.curve) {
            case 'ed25519':
                verified = verifyPrehashedSignature(sig.raw, payload, key.raw);
                break;
            case 'secp256k1':
                verified = secp256k1.verify(sig.raw, blake2b(payload, { dkLen: 32 }), key.raw, {
                    lowS: true,
                    prehash: false,
                });
                break;
            case 'p256':
                verified = p256.verify(sig.raw, blake2b(payload, { dkLen: 32 }), key.raw, {
                    lowS: false,
                    prehash: false,
                });
                break;
        }
    } catch (error) {
        return { ok: false, reason: `the signature could not be checked: ${message(error)}` };
    }

    return verified ? { ok: true } : { ok: false, reason: 'the signature does not verify over the payload' };
}

/** One key's entry in a `fast_payout` call's `signatures` map. */
export interface SignatureEntry {
    publicKey: string;
    signature: string;
}

/** What the signatures of one fast payout amount to. */
export interface SignatureVerdict {
    /** Keys of the set whose signature verifies: what the vault counted. */
    valid: string[];
    /** Keys outside the set, with whether their signature verified. */
    foreign: { publicKey: string; verified: boolean }[];
    /** Keys of the set whose signature does not verify, and why. */
    invalid: { publicKey: string; reason: string }[];
}

/** Fewer valid in-set signatures than the vault's threshold. */
export function underThreshold(verdict: SignatureVerdict): boolean {
    return verdict.valid.length < PAYOUT_THRESHOLD;
}

/**
 * Verify every entry of a call against `signers`, over the payload the vault
 * would have checked for `(chainId, vault, sessionId, amountMutez)`.
 */
export function verifyCall(
    chainId: string,
    vault: string,
    sessionId: Uint8Array,
    amountMutez: bigint,
    entries: readonly SignatureEntry[],
    signers: ReadonlySet<string>,
): SignatureVerdict {
    const payload = fastPayoutPayload(chainId, vault, sessionId, amountMutez);
    const verdict: SignatureVerdict = { valid: [], foreign: [], invalid: [] };

    for (const entry of entries) {
        const check = verifyFastPayoutSignature(entry.publicKey, entry.signature, payload);

        if (!signers.has(entry.publicKey)) {
            verdict.foreign.push({ publicKey: entry.publicKey, verified: check.ok });
        } else if (check.ok) {
            verdict.valid.push(entry.publicKey);
        } else {
            verdict.invalid.push({ publicKey: entry.publicKey, reason: check.reason });
        }
    }

    return verdict;
}

function message(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}
