// @vitest-environment node
/**
 * The receipts hand-off fragment (`#receipts=<scheme>.<base64url>`), as the
 * games write it (the play client's encoder, whose own tests
 * round-trip through this format). The vectors below are fixed strings — a
 * `gz.` one produced by Node's zlib, not by the game's encoder — so this side
 * pins the format, not one implementation's output.
 */
import { describe, expect, it } from 'vitest';
import { NETWORKS, parseNetworks } from '../chain/networks';
import {
    planFragmentArrival,
    readHintHandoff,
    readReceiptsHandoff,
    readRoundHandoff,
    readScopeHandoff,
    resolveScopeHandoff,
} from './handoff';

const TEXT = '{"schema":"99dot5.receipts.v1","note":"hand-off vector"}';
const GZ = 'gz.H4sIAAAAAAACE6tWKk7OSM1NVLJSsrRMyS8x1StKTU7NLCgp1iszVNJRyssvSQXKZSTmpejmp6UplKUml-QXKdUCAENy2fA4AAAA';
const JSON_FORM = 'json.eyJzY2hlbWEiOiI5OWRvdDUucmVjZWlwdHMudjEiLCJub3RlIjoiaGFuZC1vZmYgdmVjdG9yIn0';

describe('readReceiptsHandoff', () => {
    it('reads nothing from a fragment that carries no receipts', async () => {
        await expect(readReceiptsHandoff('')).resolves.toBeNull();
        await expect(readReceiptsHandoff('#round=abc')).resolves.toBeNull();
    });

    it('decodes the gzip form', async () => {
        await expect(readReceiptsHandoff(`#receipts=${GZ}`)).resolves.toBe(TEXT);
    });

    it('decodes the plain JSON form, with or without the leading #', async () => {
        await expect(readReceiptsHandoff(`#receipts=${JSON_FORM}`)).resolves.toBe(TEXT);
        await expect(readReceiptsHandoff(`receipts=${JSON_FORM}`)).resolves.toBe(TEXT);
    });

    it('refuses an unknown scheme rather than guessing', async () => {
        await expect(readReceiptsHandoff('#receipts=zstd.AAAA')).rejects.toThrow(/unknown encoding "zstd"/);
        await expect(readReceiptsHandoff('#receipts=AAAA')).rejects.toThrow(/unknown encoding/);
    });

    it('refuses characters outside base64url', async () => {
        await expect(readReceiptsHandoff('#receipts=json.ab+/')).rejects.toThrow(/base64url/);
    });

    it('refuses bytes that are not gzip, and text that is not UTF-8', async () => {
        await expect(readReceiptsHandoff('#receipts=gz.AAAA')).rejects.toThrow();
        // 0xff 0xfe is not valid UTF-8.
        await expect(readReceiptsHandoff('#receipts=json._-4')).rejects.toThrow();
    });

    it('still reads the receipts when the link also names a round', async () => {
        await expect(readReceiptsHandoff(`#round=${ROUND}&receipts=${JSON_FORM}`)).resolves.toBe(TEXT);
    });
});

const ROUND = '9a256790-c7c0-47b0-9a5b-6ed2905d2df1';

describe('readRoundHandoff', () => {
    it('reads nothing from a fragment that carries no round', () => {
        expect(readRoundHandoff('')).toBeNull();
        expect(readRoundHandoff(`#receipts=${JSON_FORM}`)).toBeNull();
    });

    it('reads the hyphenated form, with or without the leading #', () => {
        expect(readRoundHandoff(`#round=${ROUND}`)).toBe(ROUND);
        expect(readRoundHandoff(`round=${ROUND}`)).toBe(ROUND);
    });

    it('normalises the bare 32-hex form and upper case to the hyphenated lowercase form', () => {
        expect(readRoundHandoff(`#round=${ROUND.replaceAll('-', '')}`)).toBe(ROUND);
        expect(readRoundHandoff(`#round=${ROUND.toUpperCase()}`)).toBe(ROUND);
    });

    it('refuses anything that is not a UUID rather than passing it on', () => {
        expect(() => readRoundHandoff('#round=')).toThrow(/not a UUID/);
        expect(() => readRoundHandoff('#round=9a256790-c7c0-47b0-9a5b')).toThrow(/not a UUID/);
        expect(() => readRoundHandoff(`#round=${ROUND}0`)).toThrow(/not a UUID/);
        expect(() => readRoundHandoff('#round=<script>')).toThrow(/not a UUID/);
    });
});

describe('readHintHandoff', () => {
    const TRANSCRIPT_OP = 'ooxa3P8hPVb3cX7YQ7e4H9SpX2nWm3kD5aQe8vRrZ1t6Ug7Fh2J';
    const BATCH_OP = 'onyxCAJ2FSiVUv8fEzSgfrYQtCbqQd8ZLjnGx1qEKmrBV3cWPdT';
    // The fragment the sender writes (the play client's `roundHandoffUrl`).
    const ALL = `#round=${ROUND}&transcriptLevel=1234567&transcriptOp=${TRANSCRIPT_OP}&seedBatchLevel=1234500&seedBatchOp=${BATCH_OP}`;

    it('reads no hint, and no finding, from a link that carries none', () => {
        expect(readHintHandoff('')).toEqual({ hints: null, findings: [] });
        expect(readHintHandoff(`#round=${ROUND}`)).toEqual({ hints: null, findings: [] });
    });

    it('reads every hint key the sender writes, beside the round id', () => {
        expect(readHintHandoff(ALL)).toEqual({
            hints: {
                transcript: { level: 1_234_567, operationHash: TRANSCRIPT_OP },
                seedBatch: { level: 1_234_500, operationHash: BATCH_OP },
            },
            findings: [],
        });
        expect(readRoundHandoff(ALL)).toBe(ROUND);
    });

    it('reads a level-only seed batch as one with no operation hash', () => {
        expect(readHintHandoff(`#round=${ROUND}&seedBatchLevel=42`)).toEqual({
            hints: { seedBatch: { level: 42, operationHash: null } },
            findings: [],
        });
    });

    it('drops a malformed key with a finding, and never drops the round', () => {
        const cases: { fragment: string; hints: unknown; finding: RegExp }[] = [
            {
                fragment: `#round=${ROUND}&transcriptLevel=0&transcriptOp=${TRANSCRIPT_OP}`,
                hints: null,
                finding: /transcriptLevel hint is not a positive integer level/,
            },
            {
                fragment: `#round=${ROUND}&transcriptLevel=12.5&transcriptOp=${TRANSCRIPT_OP}`,
                hints: null,
                finding: /transcriptLevel hint is not a positive integer level/,
            },
            {
                fragment: `#round=${ROUND}&transcriptLevel=99999999999999999999&transcriptOp=${TRANSCRIPT_OP}`,
                hints: null,
                finding: /transcriptLevel hint is not a positive integer level/,
            },
            {
                fragment: `#round=${ROUND}&transcriptLevel=7&transcriptOp=${TRANSCRIPT_OP.slice(0, -1)}0`,
                hints: null,
                finding: /transcriptOp hint is not an operation hash/,
            },
            {
                fragment: `#round=${ROUND}&transcriptLevel=7`,
                hints: null,
                finding: /transcript hint needs both transcriptLevel and transcriptOp/,
            },
            {
                fragment: `#round=${ROUND}&seedBatchLevel=-3&seedBatchOp=${BATCH_OP}`,
                hints: null,
                finding: /seedBatchLevel hint is not a positive integer level/,
            },
            {
                fragment: `#round=${ROUND}&seedBatchLevel=42&seedBatchOp=<script>`,
                hints: { seedBatch: { level: 42, operationHash: null } },
                finding: /seedBatchOp hint is not an operation hash/,
            },
            {
                fragment: `#round=${ROUND}&seedBatchOp=${BATCH_OP}`,
                hints: null,
                finding: /seedBatchOp alone was ignored/,
            },
        ];

        for (const { fragment, hints, finding } of cases) {
            const read = readHintHandoff(fragment);

            expect(read.hints, fragment).toEqual(hints);
            expect(read.findings.join('\n'), fragment).toMatch(finding);
            expect(readRoundHandoff(fragment), fragment).toBe(ROUND);
        }
    });

    it('keeps the good hint when only the other one is malformed', () => {
        const read = readHintHandoff(
            `#round=${ROUND}&transcriptLevel=x&transcriptOp=${TRANSCRIPT_OP}&seedBatchLevel=42&seedBatchOp=${BATCH_OP}`,
        );

        expect(read.hints).toEqual({ seedBatch: { level: 42, operationHash: BATCH_OP } });
        expect(read.findings).toHaveLength(2);
    });
});

describe('readScopeHandoff', () => {
    it('reads nothing from a fragment that names no tenant or pool', () => {
        expect(readScopeHandoff(`#round=${ROUND}`)).toEqual({ tenantId: null, poolId: null, findings: [] });
        expect(readScopeHandoff('')).toEqual({ tenantId: null, poolId: null, findings: [] });
    });

    it('reads the tenant and pool beside the round id, with or without the leading #', () => {
        const scope = { tenantId: 'stg-99dot5-com-shadownet', poolId: 'standard', findings: [] };

        expect(readScopeHandoff(`#round=${ROUND}&tenant=stg-99dot5-com-shadownet&pool=standard`)).toEqual(scope);
        expect(readScopeHandoff(`round=${ROUND}&tenant=stg-99dot5-com-shadownet&pool=standard`)).toEqual(scope);
        expect(readScopeHandoff(`#round=${ROUND}&pool=preview`)).toEqual({
            tenantId: null,
            poolId: 'preview',
            findings: [],
        });
    });

    it('drops a value that is not a slug with a finding that never echoes it, and the round stands', () => {
        const cases = [
            { key: 'tenant', value: '' },
            { key: 'tenant', value: 'Stg-99dot5' },
            { key: 'tenant', value: '<img src=x onerror=alert(1)>' },
            { key: 'pool', value: 'standard pool' },
            { key: 'pool', value: 'a'.repeat(33) },
            { key: 'pool', value: 'stándard' },
        ];

        for (const { key, value } of cases) {
            const fragment = `#round=${ROUND}&${key}=${encodeURIComponent(value)}`;
            const read = readScopeHandoff(fragment);

            expect(read.tenantId, fragment).toBeNull();
            expect(read.poolId, fragment).toBeNull();
            expect(read.findings, fragment).toEqual([
                `the link's ${key} is not a slug (a-z, 0-9 and -, at most 32); it was ignored`,
            ]);
            expect(readRoundHandoff(fragment), fragment).toBe(ROUND);
        }
    });

    it('keeps the good key when only the other one is malformed', () => {
        const read = readScopeHandoff(`#round=${ROUND}&tenant=stg-99dot5-com-shadownet&pool=%3Cb%3E`);

        expect(read.tenantId).toBe('stg-99dot5-com-shadownet');
        expect(read.poolId).toBeNull();
        expect(read.findings).toHaveLength(1);
    });
});

describe('resolveScopeHandoff', () => {
    const deployment = (tenantId: string, rollupAddress: string, status: 'active' | 'retired' = 'active') => ({
        status,
        tenantId,
        rollupAddress,
        originationAdministrator: { address: 'KT1HBEQTLqD54X5hFM3HeicbQ5UVF12RwivW', level: 4085587 },
        evidence: ['sr_originate at level 4085587'],
    });
    const ROLLUP_A = 'sr1D3nG1QgW88iS5owT9gneusBU38K5oHGLS';
    const ROLLUP_B = 'sr1LVZW8AUSQehXjvn3NV6BJJKdA3vheqhZL';
    const network = (id: string, deployments: unknown[]) => ({
        id,
        label: id,
        chainId: id === 'mainnet' ? 'NetXdQprcVkpaWU' : 'NetXsqzbfFenSTS',
        tzktApiUrl: `https://api.${id}.example`,
        rpcUrl: `https://rpc.${id}.example`,
        deployments,
    });
    const networks = (mainnet: unknown[], shadownet: unknown[]) =>
        parseNetworks({ networks: [network('mainnet', mainnet), network('shadownet', shadownet)] });
    const scope = (tenantId: string | null, poolId: string | null) => ({ tenantId, poolId, findings: [] });

    it('changes nothing for a link that names neither', () => {
        expect(resolveScopeHandoff(NETWORKS, scope(null, null), false)).toEqual({
            deployment: null,
            poolId: null,
            findings: [],
        });
    });

    it('selects the one live deployment carrying the tenant, on whichever network it lives, and fills the pool', () => {
        const known = networks(
            [deployment('main-tenant', ROLLUP_A)],
            [deployment('stg-tenant', ROLLUP_B), deployment('stg-tenant', ROLLUP_A, 'retired')],
        );
        const resolved = resolveScopeHandoff(known, scope('stg-tenant', 'preview'), false);

        expect(resolved.deployment?.network.id).toBe('shadownet');
        expect(resolved.deployment?.deployment.rollupAddress).toBe(ROLLUP_B);
        expect(resolved.poolId).toBe('preview');
        expect(resolved.findings).toEqual([]);
    });

    it('takes the staging tenant of the compiled-in list to shadownet', () => {
        const resolved = resolveScopeHandoff(NETWORKS, scope('stg-99dot5-com-shadownet', 'standard'), false);

        expect(resolved.deployment?.network.id).toBe('shadownet');
        expect(resolved.deployment?.deployment.tenantId).toBe('stg-99dot5-com-shadownet');
        expect(resolved.poolId).toBe('standard');
    });

    it('keeps the default, and drops the pool with it, for a tenant no live deployment carries', () => {
        const known = networks([deployment('main-tenant', ROLLUP_A)], [deployment('old-tenant', ROLLUP_B, 'retired')]);

        for (const tenant of ['unknown-tenant', 'old-tenant']) {
            const resolved = resolveScopeHandoff(known, scope(tenant, 'standard'), false);

            expect(resolved.deployment, tenant).toBeNull();
            expect(resolved.poolId, tenant).toBeNull();
            expect(resolved.findings, tenant).toEqual([
                `the link's tenant ${tenant} is carried by no live deployment this page knows; ` +
                    'it was ignored, choose the network and deployment yourself',
                "the link's pool was ignored with its tenant",
            ]);
        }
    });

    it('keeps the default for a tenant two live deployments carry', () => {
        const known = networks([deployment('twice', ROLLUP_A)], [deployment('twice', ROLLUP_B)]);
        const resolved = resolveScopeHandoff(known, scope('twice', null), false);

        expect(resolved.deployment).toBeNull();
        expect(resolved.findings).toEqual([
            "the link's tenant twice is carried by 2 live deployments; it was ignored, choose the one this round was played on",
        ]);
    });

    it('drops a pool named beside no tenant, since a pool belongs to its tenant', () => {
        expect(resolveScopeHandoff(NETWORKS, scope(null, 'preview'), false)).toEqual({
            deployment: null,
            poolId: null,
            findings: ["the link's pool was ignored: the link names no tenant"],
        });
    });

    it('lets loaded receipts win over the link’s tenant and pool', () => {
        expect(resolveScopeHandoff(NETWORKS, scope('stg-99dot5-com-shadownet', 'standard'), true)).toEqual({
            deployment: null,
            poolId: null,
            findings: ["the link's tenant and pool were ignored: the loaded receipts name their own"],
        });
    });

    it('carries the parser’s findings first, and drops the pool with a malformed tenant', () => {
        const parsed = readScopeHandoff(`#round=${ROUND}&tenant=BAD&pool=standard`);

        expect(resolveScopeHandoff(NETWORKS, parsed, false)).toEqual({
            deployment: null,
            poolId: null,
            findings: [
                "the link's tenant is not a slug (a-z, 0-9 and -, at most 32); it was ignored",
                "the link's pool was ignored: the link names no tenant",
            ],
        });
    });
});

describe('planFragmentArrival', () => {
    const OTHER = '01920000-0000-7000-8000-0000000000bb';

    it('ignores a fragment that carries neither receipts nor a round', () => {
        for (const hash of ['', '#', '#tenant=stg-99dot5-com-shadownet', '#section-2']) {
            expect(planFragmentArrival(hash, ROUND), hash).toEqual({
                carries: 'nothing',
                reset: false,
                clearReceipts: false,
                note: null,
            });
        }
    });

    it('replaces whatever receipts are loaded with new ones, whichever round they name', () => {
        for (const loaded of [null, ROUND, OTHER]) {
            expect(planFragmentArrival(`#receipts=${JSON_FORM}`, loaded)).toEqual({
                carries: 'receipts',
                reset: true,
                clearReceipts: true,
                note: null,
            });
        }
    });

    it('moves to a linked round, keeping receipts for that same round', () => {
        for (const loaded of [null, ROUND]) {
            expect(planFragmentArrival(`#round=${ROUND.replaceAll('-', '').toUpperCase()}`, loaded)).toEqual({
                carries: 'round',
                reset: true,
                clearReceipts: false,
                note: null,
            });
        }
    });

    it('clears receipts for another round, saying why, so they are not checked in the linked round’s place', () => {
        expect(planFragmentArrival(`#round=${ROUND}&tenant=stg-99dot5-com-shadownet`, OTHER)).toEqual({
            carries: 'round',
            reset: true,
            clearReceipts: true,
            note:
                `the receipts loaded for round ${OTHER} were cleared: the link names round ${ROUND}, ` +
                'and those receipts would have been checked in its place',
        });
    });

    it('changes nothing for a malformed round id', () => {
        expect(planFragmentArrival('#round=<script>', OTHER)).toEqual({
            carries: 'round',
            reset: false,
            clearReceipts: false,
            note: null,
        });
    });
});
