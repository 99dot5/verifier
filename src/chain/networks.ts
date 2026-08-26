/**
 * Per-network defaults. EVERYTHING here is a default, not an authority: each
 * value is editable in the UI, because a verifier whose endpoints cannot be
 * swapped out asks you to trust its operator. The trust chain is:
 *
 *   - the rollup address is public knowledge (it is where the funds sit);
 *   - the sequencer public key is derivable from L1 alone — the administrator
 *     contract's RegisterTenant / RotateSequencerKey internal operations to
 *     the rollup carry it, and it lives in rollup durable storage at
 *     /tenants/{t}/config/sequencer-keys/current;
 *   - TzKT and the node RPC are read paths to PUBLIC chain data — use any
 *     indexer/archive node you like, or run your own. Cross-checking two
 *     independent sources is the point of making both configurable.
 *
 * None of these endpoints belong to 99dot5. That is deliberate: a verifier
 * that depends on the operator's infrastructure asks people to trust the
 * operator in order to check whether they need to trust the operator.
 */

export interface NetworkConfig {
    id: string;
    label: string;
    tenantId: string;
    poolId: string;
    /** `sr1…` rollup address; null = rollup not originated on this network yet. */
    rollupAddress: string | null;
    /** Tenant sequencer public key (`edpk…`); null = tenant not registered yet. */
    sequencerPublicKey: string | null;
    tzktApiUrl: string;
    rpcUrl: string;
}

export const NETWORKS: NetworkConfig[] = [
    {
        id: 'mainnet',
        label: 'Mainnet',
        tenantId: '99dot5-com-mainnet',
        poolId: 'standard',
        // Not originated yet (tenants.yaml carries no mainnet vault either).
        // When mainnet ships, fill the address + key here — the UI treats null
        // as the honest empty state: "no rounds on this network yet".
        rollupAddress: null,
        sequencerPublicKey: null,
        tzktApiUrl: 'https://api.tzkt.io',
        rpcUrl: 'https://rpc.tzkt.io/mainnet',
    },
    {
        id: 'shadownet',
        label: 'Shadownet',
        // The tenants.yaml SSOT slug. NOTE: live inbox traffic observed on
        // 2026-08-22 was on the `stg-99dot5-com-shadownet` tenant (the staging
        // clients); switch the tenant field in the UI to verify those rounds.
        tenantId: '99dot5-com-shadownet',
        poolId: 'standard',
        // Confirmed live 2026-08-22: 413 cemented commitments and current
        // sequencer inbox traffic; the other originated candidate
        // (sr1TMxAUtDA4sDL7C4r39L18iQjhRcBRzd8a, the tenants.example.yaml
        // fixture) never progressed past its genesis commitment.
        rollupAddress: 'sr1D3nG1QgW88iS5owT9gneusBU38K5oHGLS',
        // TODO(operator): seed the real key. The tenants.example.yaml fixture
        // key (edpkvWR5truf7AMF3PZVCXx7ieQLCW4MpNDzM3VwPfmFWVbBZwswBw) was
        // checked against live inbox signatures on 2026-08-22 and does NOT
        // verify — it is a fixture, so shipping it would only manufacture
        // signature failures. Until a key is set, verification honestly caps
        // at "incomplete" (the payout/commitment halves still run).
        sequencerPublicKey: null,
        // Both endpoints probed live 2026-08-22 (chain NetXsqzbfFenSTS).
        tzktApiUrl: 'https://api.shadownet.tzkt.io',
        rpcUrl: 'https://rpc.shadownet.teztnets.com',
    },
];

export const DRAND_URLS = ['https://api.drand.sh', 'https://drand.cloudflare.com'];
