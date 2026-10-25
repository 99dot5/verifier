// @vitest-environment node
/**
 * The signature verdict, pinned to the shared fast-payout vectors: every
 * `fast_payout_cases` row is rendered as the parameter value a node would
 * show for that call, in the readable form (keys and signatures as base58
 * strings) and in the optimised form (forged bytes), decoded, verified
 * against the fixture's `payout_signers`, and the verdict compared with the
 * one the fixture's independent generator wrote.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { decodeFastPayoutCall } from './events';
import { fastPayoutVectorsUrl } from './fast-payout-vectors-path';
import { decodePublicKey, decodeSignature, forgedPublicKey } from './keys';
import { bytesToHex } from './micheline';
import { fastPayoutPayload } from './payload';
import { underThreshold, verifyCall, verifyFastPayoutSignature } from './signatures';
import { encodeBase58Check } from '../wire/signature';

interface Vectors {
    chain_id: string;
    vault: string;
    payout_signers: string[];
    payloads: Record<string, { session_id: string; amount_mutez: number; bytes: string }>;
    signers: Record<string, { public_key: string; signatures: Record<string, string> }>;
    fast_payout_cases: {
        name: string;
        signatures: { key: string; payload: string; signed_by: string }[];
        verdict: string;
    }[];
}

const v = JSON.parse(readFileSync(fastPayoutVectorsUrl(), 'utf8')) as Vectors;
const fast = v.payloads.fast_payout;
const signers = new Set(v.payout_signers);

function hexToBytes(hex: string): Uint8Array {
    return new Uint8Array((hex.match(/.{2}/g) ?? []).map((byte) => Number.parseInt(byte, 16)));
}

function caseNamed(name: string): Vectors['fast_payout_cases'][number] {
    const found = v.fast_payout_cases.find((c) => c.name === name);

    if (!found) {
        throw new Error(`no ${name} case in the fixture`);
    }

    return found;
}

type Form = 'readable' | 'optimised';

const session = hexToBytes(fast.session_id);

function keyNode(key: string, form: Form): unknown {
    return form === 'readable' ? { string: key } : { bytes: bytesToHex(forgedPublicKey(decodePublicKey(key))) };
}

function signatureNode(signature: string, form: Form): unknown {
    return form === 'readable' ? { string: signature } : { bytes: bytesToHex(decodeSignature(signature).raw) };
}

/** The parameter value of the case's call: `Pair amount (Pair session_id {Elt key signature; …})`. */
function callValue(entries: Vectors['fast_payout_cases'][number]['signatures'], form: Form): unknown {
    return {
        prim: 'Pair',
        args: [
            { int: String(fast.amount_mutez) },
            {
                prim: 'Pair',
                args: [
                    { bytes: fast.session_id },
                    entries.map((e) => ({
                        prim: 'Elt',
                        args: [
                            keyNode(v.signers[e.key].public_key, form),
                            signatureNode(v.signers[e.signed_by].signatures[e.payload], form),
                        ],
                    })),
                ],
            },
        ],
    };
}

describe('fast-payout signatures', () => {
    it('exercises every case of the fixture', () => {
        expect(v.fast_payout_cases.length).toBeGreaterThanOrEqual(13);
        expect(v.payout_signers).toHaveLength(4);
    });

    const forms: Form[] = ['readable', 'optimised'];

    it.each(v.fast_payout_cases.flatMap((c) => forms.map((form) => [c.name, form, c] as const)))(
        'decodes %s in the %s form and gets the vault’s verdict',
        (_name, form, c) => {
            const call = decodeFastPayoutCall(callValue(c.signatures, form));

            expect(bytesToHex(call.sessionId)).toBe(fast.session_id);
            expect(call.amount).toBe(BigInt(fast.amount_mutez));
            expect(call.signatures).toHaveLength(c.signatures.length);

            const verdict = verifyCall(
                v.chain_id,
                v.vault,
                call.sessionId,
                BigInt(fast.amount_mutez),
                call.signatures,
                signers,
            );

            expect(underThreshold(verdict) ? 'Under threshold' : 'accepted').toBe(c.verdict);

            // Keys outside the set are reported, never counted.
            const mallory = v.signers.mallory.public_key;
            const hasMallory = c.signatures.some((e) => v.signers[e.key].public_key === mallory);

            expect(verdict.foreign.some((f) => f.publicKey === mallory)).toBe(hasMallory);
            expect(verdict.valid.every((k) => signers.has(k))).toBe(true);
        },
    );

    it('reports a signature over another amount as invalid, not foreign', () => {
        const c = caseNamed('one_right_one_over_other_amount');
        const call = decodeFastPayoutCall(callValue(c.signatures, 'readable'));
        const verdict = verifyCall(
            v.chain_id,
            v.vault,
            call.sessionId,
            BigInt(fast.amount_mutez),
            call.signatures,
            signers,
        );

        expect(verdict.valid).toEqual([v.signers.sp_a.public_key]);
        expect(verdict.invalid).toHaveLength(1);
        expect(verdict.invalid[0].publicKey).toBe(v.signers.sp_b.public_key);
        expect(verdict.foreign).toEqual([]);
    });

    it('verifies every signer’s own fast-payout signature on every curve the fixture carries, and nobody else’s', () => {
        const payload = fastPayoutPayload(v.chain_id, v.vault, session, BigInt(fast.amount_mutez));
        const curves = new Set<string>();

        for (const [label, signer] of Object.entries(v.signers)) {
            const signature = signer.signatures.fast_payout;

            if (!signature) {
                continue;
            }

            curves.add(decodePublicKey(signer.public_key).curve);
            expect(verifyFastPayoutSignature(signer.public_key, signature, payload), label).toEqual({ ok: true });

            // The same signature under the other payloads fails: it binds the amount, the session, the vault and the chain.
            for (const [name, other] of Object.entries(v.payloads)) {
                if (name !== 'fast_payout' && name.startsWith('fast_payout')) {
                    const otherPayload = hexToBytes(other.bytes);

                    expect(
                        verifyFastPayoutSignature(signer.public_key, signature, otherPayload).ok,
                        `${label} over ${name}`,
                    ).toBe(false);
                }
            }
        }

        expect([...curves].sort()).toEqual(['ed25519', 'p256', 'secp256k1']);
    });

    it('accepts the generic sig… form under the key’s curve and refuses a signature of another curve', () => {
        const payload = fastPayoutPayload(v.chain_id, v.vault, session, BigInt(fast.amount_mutez));
        const sp = v.signers.sp_a;
        const ed = v.signers.ed_a;
        const generic = encodeBase58Check([4, 130, 43], decodeSignature(sp.signatures.fast_payout).raw);

        expect(generic.startsWith('sig')).toBe(true);
        expect(verifyFastPayoutSignature(sp.public_key, generic, payload)).toEqual({ ok: true });

        const mismatch = verifyFastPayoutSignature(ed.public_key, sp.signatures.fast_payout, payload);

        expect(mismatch.ok).toBe(false);
        expect(mismatch.ok ? '' : mismatch.reason).toMatch(/secp256k1 signature offered against a ed25519 key/);
        expect(verifyFastPayoutSignature('not a key', ed.signatures.fast_payout, payload).ok).toBe(false);
        expect(verifyFastPayoutSignature(ed.public_key, 'not a signature', payload).ok).toBe(false);
    });
});
