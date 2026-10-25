// @vitest-environment node
/**
 * The vault's storage, read by annotation through the storage type in its
 * script: pinned against the first vault of the treasury generation as the
 * shadownet node rendered it (forged keys and addresses), the watcher's
 * recorded script (readable keys), and shapes a reader must refuse.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { MichelineError } from './micheline';
import { loadWatcherSnapshot, snapshotScript } from './snapshot-fixtures';
import { decodeVaultScript } from './vault-storage';

interface Fixture {
    vault: string;
    level: number;
    expected: { tenantId: string; poolId: string; payoutSigners: string[]; treasury: string; adminAddress: string };
    script: { code: unknown[]; storage: unknown };
}

const live = JSON.parse(
    readFileSync(new URL('./testdata/shadownet-vault-script.json', import.meta.url), 'utf8'),
) as Fixture;

describe('vault storage', () => {
    it('reads the live shadownet vault, rendered by the node in the forged form', () => {
        const storage = decodeVaultScript(live.script);

        expect(storage).toEqual({
            tenantId: live.expected.tenantId,
            poolId: live.expected.poolId,
            payoutSigners: live.expected.payoutSigners,
            treasury: live.expected.treasury,
        });
    });

    it('reads the watcher’s recorded vault, rendered in the readable form', () => {
        const snapshot = loadWatcherSnapshot('clean');
        const vault = snapshot.l1.scripts[0].contract;
        const storage = decodeVaultScript(snapshotScript(snapshot, vault, 105));

        expect(storage.tenantId).toBe('golden-tenant');
        expect(storage.poolId).toBe('golden-pool');
        expect(storage.payoutSigners).toHaveLength(4);
        expect(storage.payoutSigners?.every((key) => /^(edpk|sppk|p2pk)/.test(key))).toBe(true);
        expect(storage.treasury).toBe('KT1FNqdhr7P6FM9rx6P1CoPasUYE5JPSCqup');
    });

    it('reads a generation without the fast payout as having no signers, and refuses a script without the scope', () => {
        const withoutSigners = {
            code: [
                {
                    prim: 'storage',
                    args: [
                        {
                            prim: 'pair',
                            args: [
                                { prim: 'string', annots: ['%pool_id'] },
                                { prim: 'string', annots: ['%tenant_id'] },
                            ],
                        },
                    ],
                },
            ],
            storage: { prim: 'Pair', args: [{ string: 'p' }, { string: 't' }] },
        };

        expect(decodeVaultScript(withoutSigners)).toEqual({
            tenantId: 't',
            poolId: 'p',
            payoutSigners: null,
            treasury: null,
        });

        const renamed = structuredClone(withoutSigners);

        (renamed.code[0].args[0].args[1] as { annots: string[] }).annots = ['%tenant'];

        expect(() => decodeVaultScript(renamed)).toThrow(/no %tenant_id field/);
        expect(() => decodeVaultScript({ code: [], storage: {} })).toThrow(MichelineError);
        expect(() => decodeVaultScript({ code: withoutSigners.code })).toThrow(/no storage value/);
        expect(() => decodeVaultScript({ code: withoutSigners.code, storage: { int: '1' } })).toThrow(
            /expected a Pair/,
        );
    });
});
