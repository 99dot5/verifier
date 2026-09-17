import { describe, expect, it } from 'vitest';

import rawNetworks from './networks.json';
import { deploymentsForTenant, NETWORKS, parseNetworks } from './networks';

/** A minimal valid document; each negative test breaks exactly one thing in a copy. */
function validDocument() {
    return {
        networks: [
            {
                id: 'shadownet',
                label: 'Shadownet',
                chainId: 'NetXsqzbfFenSTS',
                tzktApiUrl: 'https://api.shadownet.tzkt.io',
                rpcUrl: 'https://rpc.shadownet.teztnets.com',
                deployments: [
                    {
                        status: 'active',
                        tenantId: '99dot5-shadownet',
                        rollupAddress: 'sr1D3nG1QgW88iS5owT9gneusBU38K5oHGLS',
                        originationAdministrator: { address: 'KT1HBEQTLqD54X5hFM3HeicbQ5UVF12RwivW', level: 4085587 },
                        evidence: ['sr_originate at level 4085587'],
                    },
                ],
            },
        ],
    };
}

describe('deploymentsForTenant', () => {
    const OTHER_DEPLOYMENT = {
        status: 'active',
        tenantId: 'stg-99dot5-com-shadownet',
        rollupAddress: 'sr1LVZW8AUSQehXjvn3NV6BJJKdA3vheqhZL',
        originationAdministrator: { address: 'KT1JrXpRDfHFUBCNT944VYJTTYUmqiq2YuF6', level: 5050472 },
        evidence: ['sr_originate at level 5050472'],
    };

    function twoNetworks(secondNetworkDeployments: unknown[]) {
        const document = validDocument();

        return parseNetworks({
            networks: [
                ...document.networks,
                {
                    id: 'mainnet',
                    label: 'Mainnet',
                    chainId: 'NetXdQprcVkpaWU',
                    tzktApiUrl: 'https://api.tzkt.io',
                    rpcUrl: 'https://rpc.tzkt.io/mainnet',
                    deployments: secondNetworkDeployments,
                },
            ],
        });
    }

    it('finds the one deployment carrying a slug, on whichever network it lives', () => {
        const matches = deploymentsForTenant(twoNetworks([OTHER_DEPLOYMENT]), 'stg-99dot5-com-shadownet');

        expect(matches.map((m) => [m.network.id, m.deployment.rollupAddress])).toEqual([
            ['mainnet', 'sr1LVZW8AUSQehXjvn3NV6BJJKdA3vheqhZL'],
        ]);
    });

    it('returns every deployment when a re-origination kept the slug', () => {
        const retired = { ...validDocument().networks[0].deployments[0], status: 'retired', tenantId: 'stg-99dot5-com-shadownet' };
        const networks = twoNetworks([OTHER_DEPLOYMENT, retired]);

        expect(deploymentsForTenant(networks, 'stg-99dot5-com-shadownet')).toHaveLength(2);
    });

    it('returns nothing for a slug no deployment carries', () => {
        expect(deploymentsForTenant(twoNetworks([OTHER_DEPLOYMENT]), 'unknown-tenant')).toEqual([]);
    });
});

describe('networks.json', () => {
    it('parses the shipped file', () => {
        expect(parseNetworks(rawNetworks)).toEqual(NETWORKS);
        expect(NETWORKS.map((n) => n.id)).toContain('shadownet');
    });

    it('accepts a network with no deployments as the not-yet-originated state', () => {
        const doc = validDocument();

        doc.networks[0].deployments = [];

        expect(parseNetworks(doc)[0].deployments).toEqual([]);
    });

    it('accepts the minimal valid document', () => {
        expect(() => parseNetworks(validDocument())).not.toThrow();
    });

    // Each case must fail on its own: the valid document above proves the
    // parser is not simply refusing everything.
    const defects: [string, (doc: ReturnType<typeof validDocument>) => void, RegExp][] = [
        ['a misspelt field', (doc) => Object.assign(doc.networks[0].deployments[0], { rollupAdress: 'x' }), /unknown field "rollupAdress"/],
        // A pool is a session fact, not a deployment one; the field must not creep back.
        ['a per-deployment pool', (doc) => Object.assign(doc.networks[0].deployments[0], { poolId: 'standard' }), /unknown field "poolId"/],
        ['a non-sr1 rollup address', (doc) => (doc.networks[0].deployments[0].rollupAddress = 'KT1HBEQTLqD54X5hFM3HeicbQ5UVF12RwivW'), /rollupAddress/],
        ['a truncated administrator address', (doc) => (doc.networks[0].deployments[0].originationAdministrator.address = 'KT1HBEQTLqD54X5hFM3'), /originationAdministrator.address/],
        ['a non-integer level', (doc) => (doc.networks[0].deployments[0].originationAdministrator.level = 4085587.5), /level/],
        ['an unknown status', (doc) => (doc.networks[0].deployments[0].status = 'paused'), /status/],
        ['a tenant slug outside the grammar', (doc) => (doc.networks[0].deployments[0].tenantId = '99dot5_Shadownet'), /tenantId/],
        ['empty evidence', (doc) => (doc.networks[0].deployments[0].evidence = []), /evidence/],
        ['a plain-http endpoint', (doc) => (doc.networks[0].tzktApiUrl = 'http://api.shadownet.tzkt.io'), /https/],
        ['a rollup listed twice', (doc) => doc.networks[0].deployments.push({ ...doc.networks[0].deployments[0] }), /listed twice/],
        ['a duplicate network id', (doc) => doc.networks.push({ ...doc.networks[0], deployments: [] }), /duplicate network id/],
    ];

    it.each(defects)('refuses %s', (_name, breakIt, message) => {
        const doc = validDocument();

        breakIt(doc);

        expect(() => parseNetworks(doc)).toThrow(message);
    });
});
