// @vitest-environment node
// The administrator lineage: the Michelson PACK decoder against LIVE shadownet
// payloads, and the propose→activate walk against a mocked indexer.
//
// The live payloads are the point of this file. A hand-rolled decoder that is
// only ever fed its own synthetic output proves nothing about the format it
// claims to read; every hex string marked "live" below was fetched on
// 2026-09-12 from https://api.shadownet.tzkt.io and is reproducible by anyone:
//
//   GET /v1/operations/transactions
//       ?target=sr1D3nG1QgW88iS5owT9gneusBU38K5oHGLS
//       &sender=KT1HBEQTLqD54X5hFM3HeicbQ5UVF12RwivW
//       &status=applied&select=id,level,hash,sender,parameter&sort=id
import { describe, expect, it } from 'vitest';
import {
    AdminPayloadError,
    decodeAdminPayload,
    fetchAdminLineage,
    keysForTenant,
    vaultsForPool,
    type AdminLineage,
} from './admin-lineage';
import { bytesToHex, hexToBytes } from '../verify/seed';
import { decodeEdpk, encodeEdpk, encodeKt1 } from '../wire/signature';

// ── Live payloads ───────────────────────────────────────────────────────

/** RegisterTenant (0x0100) at level 4100731, op ooUdhd6cRRQ… */
const LIVE_REGISTER_TENANT =
    '010005070701000000103939646f74352d736861646f776e65740a0000002100' +
    '30715c3d90bd2f37acccf74fb3cfe1654445b0a5b6f37892b1d5085e839e5717';

/** RegisterPoolVault (0x0101) at level 4100753 — names the pool's vault contract. */
const LIVE_REGISTER_POOL_VAULT =
    '010105070701000000103939646f74352d736861646f776e6574070701000000087374616e6461726407070a0000' +
    '00160153963025d3fadb1997729123dd8b9ed952b978d7000100000006616374697665';

/** SetTenantStatus (0x0102) at level 4100782 — a subtag this decoder ignores. */
const LIVE_SET_TENANT_STATUS = '010205070701000000103939646f74352d736861646f776e65740100000006616374697665';

/** ProposeAdminContract (0x0107) at level 4376452 — never activated on chain. */
const LIVE_PROPOSE = '0107050a0000001601e1a24fc87223233b225c2d388e5fbb1446b8e47b00';

const LIVE_TENANT = '99dot5-shadownet';
// A PUBLIC key read off L1 (the RegisterTenant above), not a secret: the scanner's
// generic-api-key rule matches on the `KEY` in the name plus the hex entropy.
// `infisical scan` honours only the gitleaks signature — its docs' `infisical-scan:ignore`
// is not in the CLI (detect/detect.go, gitleaksAllowSignature) and did not suppress this.
const LIVE_KEY_HEX = '30715c3d90bd2f37acccf74fb3cfe1654445b0a5b6f37892b1d5085e839e5717'; // gitleaks:allow
const LIVE_PROPOSED_ADMIN = 'KT1V9p3YByfpVs1QWmnZPHTNHDy9XaNPLTqz';

describe('decodeAdminPayload', () => {
    it('decodes the live RegisterTenant to its slug and raw Ed25519 key', () => {
        const payload = decodeAdminPayload(LIVE_REGISTER_TENANT);

        expect(payload.kind).toBe('register-tenant');

        if (payload.kind !== 'register-tenant') {
            return;
        }

        expect(payload.tenantId).toBe(LIVE_TENANT);
        expect(bytesToHex(payload.publicKeyRaw)).toBe(LIVE_KEY_HEX);
        // 33 packed bytes in, 32 raw out: the `00` curve tag is stripped, the
        // same way the rollup's and the indexer's parsers strip it.
        expect(payload.publicKeyRaw.length).toBe(32);
    });

    it('round-trips the live key through the base58check encoder and the existing decoder', () => {
        const payload = decodeAdminPayload(LIVE_REGISTER_TENANT);

        if (payload.kind !== 'register-tenant') {
            throw new Error('expected register-tenant');
        }

        const edpk = encodeEdpk(payload.publicKeyRaw);

        expect(edpk).toBe('edpku1ZLswxamcxqoTUJwwpRLWqtqT2DCTaLR9h4okM8PiFdtDGi7j');
        // The encoder is new; the decoder has been verifying live inbox
        // signatures since August. Closing the loop through it is what says
        // the new half is right, rather than merely self-consistent.
        expect(bytesToHex(decodeEdpk(edpk))).toBe(LIVE_KEY_HEX);
    });

    it('decodes the live ProposeAdminContract to a KT1', () => {
        expect(decodeAdminPayload(LIVE_PROPOSE)).toEqual({
            kind: 'propose-admin-contract',
            administrator: LIVE_PROPOSED_ADMIN,
        });
    });

    it('decodes the live RegisterPoolVault, which names the pool\u2019s vault', () => {
        // The vault address is what the deposit bracket (§8.3(d)) is checked
        // against, so it is derived from the same lineage as the keys rather
        // than being a second address a reader has to take on trust.
        expect(decodeAdminPayload(LIVE_REGISTER_POOL_VAULT)).toEqual({
            kind: 'register-pool-vault',
            tenantId: LIVE_TENANT,
            poolId: 'standard',
            vault: 'KT1GCjZwMGnZhJzGw36rm8gyKeh2ZJe9vjNE',
            status: 'active',
        });
    });

    it('reports a subtag it does not route as `other` rather than throwing', () => {
        // SetTenantStatus (0x0102), live at level 4100782. The rollup ignores
        // what it does not route; a verifier that threw here would stop
        // walking at the first unfamiliar operation.
        expect(decodeAdminPayload(LIVE_SET_TENANT_STATUS)).toEqual({
            kind: 'other',
            classByte: 0x01,
            subtag: 0x02,
        });
    });

    it('reports a vault-class payload as `other`', () => {
        // Class 0x00 subtag 0x00 — a deposit. Vault traffic shares the rollup
        // inbox with administrator traffic, so the class byte must be checked.
        expect(decodeAdminPayload('0000050707')).toEqual({ kind: 'other', classByte: 0x00, subtag: 0x00 });
    });

    it('decodes the bare ActivateAdminContract', () => {
        expect(decodeAdminPayload('0108')).toEqual({ kind: 'activate-admin-contract' });
    });

    it('rejects a non-Ed25519 curve tag', () => {
        // secp256k1: 34 packed bytes behind curve tag 0x01. The rollup drops
        // such a key (`InvalidPublicKeyLen`), so it never signed anything and
        // must not be presented as a lineage key.
        const key = packBytes(new Uint8Array([0x01, ...new Uint8Array(33).fill(0xab)]));
        const hex = '0100' + '05' + '0707' + packString(LIVE_TENANT) + key;

        expect(() => decodeAdminPayload(hex)).toThrow(AdminPayloadError);
        expect(() => decodeAdminPayload(hex)).toThrow(/secp256k1/);
    });

    it('reads a zarith nat the signed way', () => {
        // `80897a` is 1_000_000 — the mutez amount in a live deposit PACK
        // (level 4104279). Reading the first byte as seven unsigned value bits
        // instead of six-plus-a-sign shifts every nat, silently.
        const rotate = rotatePayloadHex(LIVE_TENANT, hexToBytes(LIVE_KEY_HEX), '80897a');
        const payload = decodeAdminPayload(rotate);

        expect(payload.kind).toBe('rotate-sequencer-key');

        if (payload.kind !== 'rotate-sequencer-key') {
            return;
        }

        expect(payload.graceLevels).toBe(1_000_000n);
        expect(payload.tenantId).toBe(LIVE_TENANT);
    });
});

// ── The walk ────────────────────────────────────────────────────────────

const ROOT = 'KT1HBEQTLqD54X5hFM3HeicbQ5UVF12RwivW';
const SUCCESSOR = LIVE_PROPOSED_ADMIN;
const FOREIGN = encodeKt1(new Uint8Array(20).fill(0x77));
const SECOND_SUCCESSOR_RAW = new Uint8Array(20).fill(0x2b);
const SECOND_SUCCESSOR = encodeKt1(SECOND_SUCCESSOR_RAW);
const ROTATED_KEY = new Uint8Array(32).fill(0x5a);
const FOREIGN_KEY = new Uint8Array(32).fill(0x33);

interface MockRow {
    id: number;
    level: number;
    hash: string;
    sender: { address: string };
    parameter: { entrypoint: 'default'; value: string };
}

function row(id: number, level: number, sender: string, value: string): MockRow {
    return { id, level, hash: `op-${id}`, sender: { address: sender }, parameter: { entrypoint: 'default', value } };
}

/**
 * A mocked indexer keyed by the `sender=` query parameter — the same shape the
 * real walk issues, one query per administrator.
 */
function mockFetch(bySender: Record<string, MockRow[]>): typeof fetch {
    return ((url: string) => {
        const sender = new URL(url).searchParams.get('sender') ?? '';

        return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(bySender[sender] ?? []),
        } as Response);
    }) as unknown as typeof fetch;
}

/** The walk every test below runs: one mocked indexer, one pinned root. */
function walk(bySender: Record<string, MockRow[]>): Promise<AdminLineage> {
    return fetchAdminLineage({
        tzktApiUrl: 'https://indexer.example',
        rollupAddress: 'sr1D3nG1QgW88iS5owT9gneusBU38K5oHGLS',
        originationAdministrator: ROOT,
        fetchImpl: mockFetch(bySender),
    });
}

describe('fetchAdminLineage', () => {
    it('follows an activated proposal and keeps every key both administrators registered', async () => {
        const lineage = await walk({
            [ROOT]: [
                row(1, 100, ROOT, LIVE_REGISTER_TENANT),
                // A foreign KT1's RegisterTenant, returned in the ROOT's
                // page: the indexer's `sender=` filter is its own claim,
                // and a smuggled key is exactly what re-checking it stops.
                row(2, 101, FOREIGN, registerTenantHex(LIVE_TENANT, FOREIGN_KEY)),
                row(3, 102, ROOT, LIVE_PROPOSE),
            ],
            [SUCCESSOR]: [
                row(4, 110, SUCCESSOR, '0108'),
                row(5, 120, SUCCESSOR, rotatePayloadHex(LIVE_TENANT, ROTATED_KEY, '0a')),
            ],
        });

        expect(lineage.administrators.map((a) => a.address)).toEqual([ROOT, SUCCESSOR]);
        expect(lineage.administrators[1]).toMatchObject({
            entry: 'activation',
            activationLevel: 110,
            proposedBy: ROOT,
        });
        expect(lineage.proposals).toEqual([
            { address: SUCCESSOR, proposedBy: ROOT, level: 102, operationHash: 'op-3', activationLevel: 110, followed: true },
        ]);

        // BOTH keys, not just the current one: a receipt signed under the
        // pre-rotation key stays valid evidence (D7).
        expect(keysForTenant(lineage, LIVE_TENANT).map((k) => k.rawHex)).toEqual([
            LIVE_KEY_HEX,
            bytesToHex(ROTATED_KEY),
        ]);
        expect(keysForTenant(lineage, LIVE_TENANT).map((k) => k.source)).toEqual([
            'register-tenant',
            'rotate-sequencer-key',
        ]);
        expect(keysForTenant(lineage, LIVE_TENANT)[1].graceLevels).toBe(10n);
        expect(lineage.keys.some((k) => k.rawHex === bytesToHex(FOREIGN_KEY))).toBe(false);
        expect(lineage.ignoredOperationCount).toBe(1);
        expect(lineage.scannedOperationCount).toBe(4);
        expect(vaultsForPool(lineage, LIVE_TENANT, 'standard')).toEqual([]);
    });

    it('stops at a proposal that never activated, and says so', async () => {
        const lineage = await walk({
            [ROOT]: [row(1, 100, ROOT, LIVE_REGISTER_TENANT), row(2, 102, ROOT, LIVE_PROPOSE)],
            // The successor exists but never sent 0x0108 — this is the
            // live shadownet state as of 2026-09-12.
            [SUCCESSOR]: [row(3, 130, SUCCESSOR, rotatePayloadHex(LIVE_TENANT, ROTATED_KEY, '0a'))],
        });

        expect(lineage.administrators.map((a) => a.address)).toEqual([ROOT]);
        expect(lineage.proposals).toEqual([
            { address: SUCCESSOR, proposedBy: ROOT, level: 102, operationHash: 'op-2', activationLevel: null, followed: false },
        ]);
        // The un-activated successor's rotation is NOT evidence: that contract
        // never controlled the rollup, so the kernel never accepted its key.
        expect(keysForTenant(lineage, LIVE_TENANT).map((k) => k.rawHex)).toEqual([LIVE_KEY_HEX]);
    });

    it('collects the pool vaults the lineage registered', async () => {
        const lineage = await walk({
            [ROOT]: [
                row(1, 100, ROOT, LIVE_REGISTER_TENANT),
                row(2, 101, ROOT, LIVE_REGISTER_POOL_VAULT),
                // A repeat registration (a status change re-registers the
                // same address) must not produce a duplicate candidate.
                row(3, 102, ROOT, LIVE_REGISTER_POOL_VAULT),
            ],
        });

        expect(vaultsForPool(lineage, LIVE_TENANT, 'standard')).toEqual(['KT1GCjZwMGnZhJzGw36rm8gyKeh2ZJe9vjNE']);
        expect(vaultsForPool(lineage, LIVE_TENANT, 'preview')).toEqual([]);
    });

    // Two proposals from one administrator that BOTH activated on L1. The
    // kernel's pending record holds one at a time, so a later
    // `ProposeAdminContract` overwrites the first and at most one of the two
    // activations was accepted — L1 does not say which, because an internal
    // transaction is applied regardless of what the kernel does with it.
    it('follows the LATEST activation when two proposals both activated', async () => {
        const lineage = await walk({
            [ROOT]: [
                row(1, 100, ROOT, LIVE_REGISTER_TENANT),
                row(2, 102, ROOT, LIVE_PROPOSE),
                row(3, 104, ROOT, proposeHex(SECOND_SUCCESSOR_RAW)),
            ],
            // The superseded proposal activates FIRST and lower. Following
            // it (the old first-in-proposal-order rule) walks onto a dead
            // branch and never sees the rotated key below.
            [SUCCESSOR]: [row(4, 110, SUCCESSOR, '0108')],
            [SECOND_SUCCESSOR]: [
                row(5, 115, SECOND_SUCCESSOR, '0108'),
                row(6, 120, SECOND_SUCCESSOR, rotatePayloadHex(LIVE_TENANT, ROTATED_KEY, '0a')),
            ],
        });

        expect(lineage.administrators.map((a) => a.address)).toEqual([ROOT, SECOND_SUCCESSOR]);
        expect(lineage.proposals.map((p) => p.followed)).toEqual([false, true]);
        // The key that would have been missed, and a missed key is a `fail`
        // against an honest frame — the false accusation this rule prevents.
        expect(keysForTenant(lineage, LIVE_TENANT).map((k) => k.rawHex)).toEqual([
            LIVE_KEY_HEX,
            bytesToHex(ROTATED_KEY),
        ]);
    });

    it('flags the ambiguity when more than one proposal activated', async () => {
        const lineage = await walk({
            [ROOT]: [
                row(1, 100, ROOT, LIVE_REGISTER_TENANT),
                row(2, 102, ROOT, LIVE_PROPOSE),
                row(3, 104, ROOT, proposeHex(SECOND_SUCCESSOR_RAW)),
            ],
            [SUCCESSOR]: [row(4, 110, SUCCESSOR, '0108')],
            [SECOND_SUCCESSOR]: [row(5, 115, SECOND_SUCCESSOR, '0108')],
        });

        expect(lineage.ambiguities).toHaveLength(1);
        expect(lineage.ambiguities[0]).toContain(SUCCESSOR);
        expect(lineage.ambiguities[0]).toContain(SECOND_SUCCESSOR);
    });

    it('flags nothing when exactly one proposal activated', async () => {
        const lineage = await walk({
            [ROOT]: [
                row(1, 100, ROOT, LIVE_REGISTER_TENANT),
                row(2, 102, ROOT, LIVE_PROPOSE),
                row(3, 104, ROOT, proposeHex(SECOND_SUCCESSOR_RAW)),
            ],
            [SECOND_SUCCESSOR]: [row(5, 115, SECOND_SUCCESSOR, '0108')],
        });

        expect(lineage.ambiguities).toEqual([]);
        expect(lineage.administrators.map((a) => a.address)).toEqual([ROOT, SECOND_SUCCESSOR]);
    });

    it('keeps the keys it already has when a later operation is undecodable', async () => {
        const lineage = await walk({
            [ROOT]: [row(1, 100, ROOT, LIVE_REGISTER_TENANT), row(2, 101, ROOT, '0100059999')],
        });

        expect(keysForTenant(lineage, LIVE_TENANT)).toHaveLength(1);
    });
});

// ── PACK builders, for the shapes no live sample covers ─────────────────

function packU32(value: number): string {
    return value.toString(16).padStart(8, '0');
}

function packString(value: string): string {
    const bytes = new TextEncoder().encode(value);

    return `01${packU32(bytes.length)}${bytesToHex(bytes)}`;
}

function packBytes(value: Uint8Array): string {
    return `0a${packU32(value.length)}${bytesToHex(value)}`;
}

function packKey(raw: Uint8Array): string {
    return packBytes(new Uint8Array([0x00, ...raw]));
}

function registerTenantHex(tenant: string, key: Uint8Array): string {
    return `0100050707${packString(tenant)}${packKey(key)}`;
}

/** `0x0107 ‖ PACK(new_admin)` — the same shape as LIVE_PROPOSE, for a second successor. */
function proposeHex(kt1Raw: Uint8Array): string {
    return `010705${packBytes(new Uint8Array([0x01, ...kt1Raw, 0x00]))}`;
}

/** `0x0105 ‖ PACK((tenant, new_public_key, grace_levels))` — a right comb of 3. */
function rotatePayloadHex(tenant: string, key: Uint8Array, graceZarithHex: string): string {
    return `0105050707${packString(tenant)}0707${packKey(key)}00${graceZarithHex}`;
}
