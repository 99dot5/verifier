// @vitest-environment node
/**
 * The key, signature and address codecs: the readable and the forged forms
 * of every value a vault's storage or a `fast_payout` call can carry
 * normalise to one base58check text, and anything else is refused by name.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { base58CheckBody } from '../wire/signature';
import { fastPayoutVectorsUrl } from './fast-payout-vectors-path';
import {
    addressFromForged,
    addressText,
    decodePublicKey,
    decodeSignature,
    forgedPublicKey,
    keyText,
    publicKeyFromForged,
    signatureText,
} from './keys';
import { bytesToHex, MichelineError } from './micheline';

interface Vectors {
    signers: Record<string, { public_key: string; signatures: Record<string, string> }>;
}

const v = JSON.parse(readFileSync(fastPayoutVectorsUrl(), 'utf8')) as Vectors;

const EDPK = 'edpkvHGNFNUxqbtfVujAwR3tRtbGK5UP5BMAY8PDvd6CfpAu3TpRUn';
const SPPK = 'sppk7bWq3wGj9AuTowUc7N2dpRhMCWtw6pmDFcLrSTLyA1mnBJ9hL5T';
const P2PK = 'p2pk67wNGpJKdARvrVyts9kCAK9a1pkHBzCCGuJGAWjkeTs8dRL9BaF';
const BLPK = 'BLpk1v6UU2PNtycJRJkn5X7qVgVFNGbgTDcWVLPy2fx2upHFzDkcvQzzV8fT8TzPHXHfDQPbu73i';
const KT1 = 'KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc';

/** The 20-byte hash behind an address: the base58check body less its 3-byte prefix. */
function hashOf(address: string): Uint8Array {
    return base58CheckBody(address).slice(3);
}

describe('keys', () => {
    it('decodes every signer of the fixture by prefix and round-trips through the forged form', () => {
        for (const [label, signer] of Object.entries(v.signers)) {
            const key = decodePublicKey(signer.public_key);
            const forged = forgedPublicKey(key);

            expect(forged[0], label).toBe({ ed25519: 0, secp256k1: 1, p256: 2 }[key.curve]);
            expect(forged.length, label).toBe(1 + (key.curve === 'ed25519' ? 32 : 33));
            expect(publicKeyFromForged(forged).text, label).toBe(signer.public_key);
            expect(keyText({ string: signer.public_key })).toBe(signer.public_key);
            expect(keyText({ bytes: bytesToHex(forged) })).toBe(signer.public_key);
        }

        expect(decodePublicKey(EDPK).curve).toBe('ed25519');
        expect(decodePublicKey(SPPK).curve).toBe('secp256k1');
        expect(decodePublicKey(P2PK).curve).toBe('p256');
    });

    it('refuses a key of the wrong length, tag or prefix, and a BLS key in both forms', () => {
        const forged = bytesToHex(forgedPublicKey(decodePublicKey(SPPK)));

        expect(() => keyText({ bytes: forged.slice(0, -4) })).toThrow(MichelineError);
        expect(() => keyText({ bytes: `03${forged.slice(2)}` })).toThrow(/0x03 is not a supported curve/);
        expect(() => keyText({ string: KT1 })).toThrow(/not a public key/);
        expect(() => keyText({ bytes: `03${'11'.repeat(48)}` })).toThrow(/0x03 is not a supported curve/);
        expect(() => keyText({ string: BLPK })).toThrow(/BLS/);
        expect(() => keyText({ int: '1' })).toThrow(MichelineError);
    });

    it('normalises the readable and the forged address forms to the same text, every curve and KT1', () => {
        const implicit: [string, number][] = [
            ['tz1UyQDepgtUBnWjyzzonqeDwaiWoQzRKSP5', 0x00],
            ['tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq', 0x01],
            ['tz3WXYtyDUNL91qfiCJtVUX746QpNv5i5ve5', 0x02],
            ['tz4FMuvpW4vRVaER72VgCdonjM1Pqgk2QVXR', 0x03],
        ];

        for (const [text, tag] of implicit) {
            const forged = new Uint8Array([0x00, tag, ...hashOf(text)]);

            expect(addressText({ string: text })).toBe(text);
            expect(addressText({ bytes: bytesToHex(forged) })).toBe(text);
        }

        const kt1 = new Uint8Array([0x01, ...hashOf(KT1), 0x00]);

        expect(addressText({ string: KT1 })).toBe(KT1);
        expect(addressText({ bytes: bytesToHex(kt1) })).toBe(KT1);
        expect(addressFromForged(kt1)).toBe(KT1);
    });

    it('refuses a forged address of the wrong width, tag, padding or entrypoint', () => {
        const tz1 = hashOf('tz1UyQDepgtUBnWjyzzonqeDwaiWoQzRKSP5');
        const kt1 = hashOf(KT1);
        const refused = [
            [0x00, 0x00, ...tz1.slice(0, 19)],
            [0x00, 0x00, ...tz1, 0x00],
            [0x01, ...kt1.slice(0, 19), 0x00],
            [0x01, ...kt1, 0x00, 0x00],
            [0x00, 0x04, ...tz1],
            [0x01, ...kt1, 0x01],
            [0x01, ...kt1, 0xff],
            [0x02, ...kt1, 0x00],
        ];

        for (const bytes of refused) {
            expect(
                () => addressText({ bytes: bytesToHex(new Uint8Array(bytes)) }),
                bytesToHex(new Uint8Array(bytes)),
            ).toThrow(MichelineError);
        }

        expect(() => addressText({ string: EDPK })).toThrow(/not an address/);
        expect(() => addressText({ string: 'not an address' })).toThrow(/not an address/);
    });

    it('decodes every signature prefix, and renders raw bytes as the generic form', () => {
        const ed = v.signers.ed_a.signatures.fast_payout;
        const sp = v.signers.sp_a.signatures.fast_payout;
        const p2 = v.signers.p2_a.signatures.fast_payout;

        expect(decodeSignature(ed).curve).toBe('ed25519');
        expect(decodeSignature(sp).curve).toBe('secp256k1');
        expect(decodeSignature(p2).curve).toBe('p256');
        expect(decodeSignature(sp).raw).toHaveLength(64);
        expect(signatureText({ string: sp })).toBe(sp);

        const generic = signatureText({ bytes: '11'.repeat(64) });

        expect(generic.startsWith('sig')).toBe(true);
        expect(decodeSignature(generic).curve).toBeNull();
        expect(bytesToHex(decodeSignature(generic).raw)).toBe('11'.repeat(64));
        expect(() => signatureText({ bytes: '11'.repeat(63) })).toThrow(/64 bytes/);
        expect(() => signatureText({ string: EDPK })).toThrow(/not a signature/);
        expect(() => decodeSignature('sig')).toThrow(RangeError);
    });
});
