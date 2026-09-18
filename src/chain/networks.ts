/**
 * Per-network defaults. EVERYTHING here is a default, not an authority: each
 * value is editable in the UI, because a verifier whose endpoints cannot be
 * swapped out asks you to trust its operator. The trust chain is:
 *
 *   - the rollup address is public knowledge (it is where the funds sit);
 *   - the sequencer public keys are DERIVED from L1, not pinned here — the
 *     administrator contract's RegisterTenant / RotateSequencerKey internal
 *     operations to the rollup carry them, and `chain/admin-lineage.ts` walks
 *     that history. The rollup mirrors the current one in durable storage at
 *     /tenants/{t}/sequencer-keys/current, but a verifier wants the HISTORICAL
 *     set, which only the operation history has;
 *   - TzKT and the node RPC are read paths to PUBLIC chain data — use any
 *     indexer/archive node you like, or run your own. Cross-checking two
 *     independent sources is the point of making both configurable.
 *
 * None of these endpoints belong to 99dot5. That is deliberate: a verifier
 * that depends on the operator's infrastructure asks people to trust the
 * operator in order to check whether they need to trust the operator.
 *
 * The data lives in `networks.json`, compiled in, never fetched: the published
 * source IS the trust story, and a list served at runtime would be a value the
 * operator could change without a commit. A network holds a LIST of
 * deployments because a re-origination replaces both the rollup and its
 * administrator, and rounds played on the old rollup stay provable from L1
 * history forever — so an entry is appended, marked `retired` when superseded,
 * and never deleted. Order is newest first; the first entry is the default.
 * An empty list is the honest "nothing originated on this network yet".
 *
 * EVERY ANCHOR MUST BE CONFIRMED BY THE OPERATOR. An anchor taken from an
 * indexer query is evidence, not proof: the administrator address is the root
 * of the whole key chain, so a reader who takes it on trust has reintroduced
 * exactly the trust this tool removes. Each entry's `evidence` says how it was
 * established; cross-check it against the origination ceremony's own records
 * (docs/runbooks/onboard-tenant.md, Step 8).
 */
import rawNetworks from './networks.json';

/**
 * The lineage root: the administrator contract the rollup was originated
 * against, and the level it was originated at.
 *
 * This is the ONE value in the key chain that cannot be derived, which is
 * exactly what makes it the trust anchor. The lineage walk starts here and
 * follows `ProposeAdminContract` (0x0107) → `ActivateAdminContract` (0x0108)
 * hops forward; every key any administrator in that chain registered is
 * admissible evidence (ADR 0022 D7). Pinning the KEY instead — what this file
 * used to do — pins a value that legitimately rotates.
 */
export interface OriginationAdministrator {
    /** `KT1…` administrator contract address. */
    address: string;
    /** L1 level of the rollup's `sr_originate` operation. */
    level: number;
}

/** `active` = rounds are being played on it; `retired` = superseded, still verifiable. */
export type DeploymentStatus = 'active' | 'retired';

/** One originated rollup and the lineage root it was originated against. */
export interface Deployment {
    status: DeploymentStatus;
    /**
     * The ON-CHAIN slug this rollup's lineage registered, not a config value:
     * a slug the lineage never registered derives an EMPTY key set and leaves
     * the signature proof permanently `unavailable`.
     */
    tenantId: string;
    // No pool: a pool is a fact about the SESSION, not the rollup — one tenant
    // runs several (shadownet: `standard` and the play-money `preview`), so any
    // default here is wrong for somebody. The UI takes it from the receipts or
    // from the pools the lineage registered.
    /** `sr1…` rollup address. */
    rollupAddress: string;
    originationAdministrator: OriginationAdministrator;
    /** How each value was established — shown to the reader, never parsed. */
    evidence: string[];
}

export interface NetworkConfig {
    id: string;
    label: string;
    /**
     * The network's `NetX…` chain id. Every sequencer signature is computed
     * over the chain and the rollup the message was signed for (#952), so the
     * verifier needs this beside the selected deployment's rollup address to
     * check any signature at all — and a frame another deployment signed
     * under the same slug fails that check, exactly as it would on this
     * rollup's kernel.
     */
    chainId: string;
    tzktApiUrl: string;
    rpcUrl: string;
    /** Newest first; empty = nothing originated on this network yet. */
    deployments: Deployment[];
}

const SLUG = /^[a-z0-9-]{1,32}$/;
const BASE58 = '[1-9A-HJ-NP-Za-km-z]';
const ROLLUP_ADDRESS = new RegExp(`^sr1${BASE58}{33}$`);
const CONTRACT_ADDRESS = new RegExp(`^KT1${BASE58}{33}$`);
const CHAIN_ID = new RegExp(`^NetX${BASE58}{11}$`);

type Json = Record<string, unknown>;

function object(value: unknown, path: string, keys: readonly string[]): Json {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${path}: expected an object`);
    }

    // Unknown keys are refused so a misspelt field ("rollupAdress") fails the
    // build instead of silently shipping a default-less deployment.
    for (const key of Object.keys(value)) {
        if (!keys.includes(key)) {
            throw new Error(`${path}: unknown field "${key}"`);
        }
    }

    return value as Json;
}

function array(value: unknown, path: string): unknown[] {
    if (!Array.isArray(value)) {
        throw new Error(`${path}: expected an array`);
    }

    return value;
}

function string(value: unknown, path: string, pattern?: RegExp): string {
    if (typeof value !== 'string' || value.length === 0) {
        throw new Error(`${path}: expected a non-empty string`);
    }

    if (pattern && !pattern.test(value)) {
        throw new Error(`${path}: "${value}" does not match ${pattern}`);
    }

    return value;
}

function httpsUrl(value: unknown, path: string): string {
    const url = string(value, path);

    if (!url.startsWith('https://')) {
        throw new Error(`${path}: "${url}" is not an https URL`);
    }

    return url;
}

function parseDeployment(value: unknown, path: string): Deployment {
    const d = object(value, path, [
        'status',
        'tenantId',
        'rollupAddress',
        'originationAdministrator',
        'evidence',
    ]);
    const status = string(d.status, `${path}.status`);

    if (status !== 'active' && status !== 'retired') {
        throw new Error(`${path}.status: "${status}" is neither "active" nor "retired"`);
    }

    const admin = object(d.originationAdministrator, `${path}.originationAdministrator`, ['address', 'level']);
    const level = admin.level;

    if (typeof level !== 'number' || !Number.isSafeInteger(level) || level <= 0) {
        throw new Error(`${path}.originationAdministrator.level: expected a positive integer L1 level`);
    }

    const evidence = array(d.evidence, `${path}.evidence`).map((line, i) => string(line, `${path}.evidence[${i}]`));

    if (evidence.length === 0) {
        throw new Error(`${path}.evidence: an anchor with no stated evidence cannot be cross-checked`);
    }

    return {
        status,
        tenantId: string(d.tenantId, `${path}.tenantId`, SLUG),
        rollupAddress: string(d.rollupAddress, `${path}.rollupAddress`, ROLLUP_ADDRESS),
        originationAdministrator: {
            address: string(admin.address, `${path}.originationAdministrator.address`, CONTRACT_ADDRESS),
            level,
        },
        evidence,
    };
}

/**
 * Validate the compiled-in network list. Throws on the first defect: a
 * malformed file must fail the test suite, never render a half-filled form.
 */
export function parseNetworks(raw: unknown): NetworkConfig[] {
    const root = object(raw, 'networks.json', ['networks']);
    const networks = array(root.networks, 'networks').map((value, i): NetworkConfig => {
        const path = `networks[${i}]`;
        const n = object(value, path, ['id', 'label', 'chainId', 'tzktApiUrl', 'rpcUrl', 'deployments']);

        return {
            id: string(n.id, `${path}.id`, SLUG),
            label: string(n.label, `${path}.label`),
            chainId: string(n.chainId, `${path}.chainId`, CHAIN_ID),
            tzktApiUrl: httpsUrl(n.tzktApiUrl, `${path}.tzktApiUrl`),
            rpcUrl: httpsUrl(n.rpcUrl, `${path}.rpcUrl`),
            deployments: array(n.deployments, `${path}.deployments`).map((d, j) =>
                parseDeployment(d, `${path}.deployments[${j}]`),
            ),
        };
    });

    if (networks.length === 0) {
        throw new Error('networks: at least one network is required');
    }

    const ids = new Set<string>();

    for (const network of networks) {
        if (ids.has(network.id)) {
            throw new Error(`networks: duplicate network id "${network.id}"`);
        }

        ids.add(network.id);

        const rollups = new Set<string>();

        for (const deployment of network.deployments) {
            if (rollups.has(deployment.rollupAddress)) {
                throw new Error(`${network.id}: rollup ${deployment.rollupAddress} is listed twice`);
            }

            rollups.add(deployment.rollupAddress);
        }
    }

    return networks;
}

export const NETWORKS: NetworkConfig[] = parseNetworks(rawNetworks);

/** A deployment together with the network it lives on. */
export interface DeploymentMatch {
    network: NetworkConfig;
    deployment: Deployment;
}

/**
 * Every deployment, across every network, whose on-chain slug is `tenantId`.
 *
 * Used to preselect the form from a receipts document, which names its tenant
 * but not its network or rollup. The caller acts only on a SINGLE match: a
 * re-origination that kept the slug leaves the retired and the new rollup both
 * matching, and guessing between them could verify an honest round against a
 * lineage that never registered its key.
 */
export function deploymentsForTenant(networks: NetworkConfig[], tenantId: string): DeploymentMatch[] {
    return networks.flatMap((network) =>
        network.deployments
            .filter((deployment) => deployment.tenantId === tenantId)
            .map((deployment) => ({ network, deployment })),
    );
}

export const DRAND_URLS = ['https://api.drand.sh', 'https://drand.cloudflare.com'];
