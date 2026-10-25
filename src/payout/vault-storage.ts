/**
 * What the payout check reads from a vault's own L1 storage: the scope it
 * was originated for, and its fast-payout signers.
 *
 * `tenant_id` and `pool_id` are baked into the vault at origination and
 * immutable, so the kernel records a fast payout is compared with are found
 * from the vault itself, never from the form. `payout_signers` is read at
 * the block BEFORE the payout: the set the vault checked the signatures
 * against. Both are read by annotation through the storage type in the
 * vault's script, so a later vault generation that adds a field still reads,
 * and one that renames a field is a named error rather than a misread.
 */
import { addressText, keyText } from './keys';
import { asSequence, asString, field, fields, MichelineError } from './micheline';

/** The fields of a vault's storage the payout check uses. */
export interface VaultStorage {
    tenantId: string;
    poolId: string;
    /**
     * Base58check public keys, whatever form the node rendered them in.
     * `null` on a vault generation without the fast payout, whose cemented
     * payouts are still checked.
     */
    payoutSigners: string[] | null;
    /** The address every house sweep pays, baked at origination; `null` on a generation without sweeps. */
    treasury: string | null;
}

type Json = Record<string, unknown>;

function isObject(node: unknown): node is Json {
    return typeof node === 'object' && node !== null && !Array.isArray(node);
}

/**
 * Decode the node's `/context/contracts/{KT1}/script` answer: the storage
 * value read through the storage type in the script's code.
 */
export function decodeVaultScript(script: unknown): VaultStorage {
    if (!isObject(script)) {
        throw new MichelineError('the script is not an object');
    }

    const code = Array.isArray(script.code) ? script.code : [];
    const section = code.find((part) => isObject(part) && part.prim === 'storage');
    const storageType = isObject(section) && Array.isArray(section.args) ? section.args[0] : undefined;

    if (storageType === undefined) {
        throw new MichelineError('the script has no storage section');
    }

    if (!('storage' in script)) {
        throw new MichelineError('the script has no storage value');
    }

    const found = fields(storageType, script.storage);
    const signers = found.get('payout_signers');
    const treasury = found.get('treasury');

    return {
        tenantId: asString(field(found, 'tenant_id')),
        poolId: asString(field(found, 'pool_id')),
        payoutSigners: signers === undefined ? null : asSequence(signers).map(keyText),
        treasury: treasury === undefined ? null : addressText(treasury),
    };
}
