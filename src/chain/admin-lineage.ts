/**
 * Deriving a tenant's sequencer public keys from L1 alone.
 *
 * The `Welcome` frame states a key, and the rollup mirrors the current one in
 * durable storage — but a verifier must not take either on trust: a rogue
 * server states a rogue key, and durable storage is reachable only through a
 * node whose ACL usually blocks it. What IS public, permanent and
 * permissionless to read is the administrator contract's operation history:
 * every key a tenant ever signed with reached the rollup as an internal
 * transaction carrying `[0x01 | subtag | Michelson PACK]` (ADR 0007 §6.2,
 * ADR 0022 D7).
 *
 * Two things make that history a chain rather than a list:
 *
 *   - The administrator contract itself is replaceable. `ProposeAdminContract`
 *     (0x0107) names a successor and `ActivateAdminContract` (0x0108), sent by
 *     the successor itself, completes the two-phase hand-over. So the set of
 *     administrators is a LINEAGE walked forward from a root, and the root —
 *     the administrator the rollup was originated against — is the one value
 *     that cannot be derived. It is pinned per deployment in `networks.json`,
 *     which is what makes it the trust anchor.
 *
 *   - The key set is HISTORICAL, not current. The kernel's grace window
 *     (`RotateSequencerKey.grace_levels`, capped at 5000 ≈ eight hours)
 *     governs which key may sign NEW inbox messages. A verifier checks
 *     historical evidence: a receipt signed under a key that was valid when it
 *     was delivered stays valid evidence forever. Applying the kernel's rule
 *     here would reject every receipt older than one grace window after any
 *     rotation — the tool would break itself on a routine operation.
 *
 * Everything below reads PUBLIC chain data through a user-supplied indexer.
 */
import { hexToBytes } from '../verify/seed';
import { encodeEdpk, encodeKt1 } from '../wire/signature';

/** Class byte for administrator→rollup internal messages (`CLASS_ADMIN`). */
const CLASS_ADMIN = 0x01;

const SUBTAG_REGISTER_TENANT = 0x00;
const SUBTAG_REGISTER_POOL_VAULT = 0x01;
const SUBTAG_ROTATE_SEQUENCER_KEY = 0x05;
const SUBTAG_PROPOSE_ADMIN_CONTRACT = 0x07;
const SUBTAG_ACTIVATE_ADMIN_CONTRACT = 0x08;

/** One key registration, with the L1 provenance that makes it evidence. */
export interface LineageKey {
    tenantId: string;
    /** `edpk…` base58check — the form an operator, a wallet and `Welcome` all use. */
    edpk: string;
    /** The 32 raw Ed25519 bytes, hex, as they appeared inside the PACK. */
    rawHex: string;
    level: number;
    operationHash: string;
    /** Which administrator operation carried it. */
    source: 'register-tenant' | 'rotate-sequencer-key';
    /** The administrator contract that sent it. */
    administrator: string;
    /** Present on a rotation only: the kernel's admission window for the OLD key. */
    graceLevels: bigint | null;
}

/**
 * A vault the lineage registered for a pool.
 *
 * Collected because the suppression ladder's lower bound is the session's
 * DEPOSIT, and a deposit is an L1 call to the pool's vault — so the verifier
 * needs to know which contract that is. Deriving it from the same lineage that
 * gives the keys keeps the whole chain of trust rooted at the one pinned
 * anchor, instead of adding a second address a reader has to take on faith.
 */
export interface VaultRegistration {
    tenantId: string;
    poolId: string;
    /** `KT1…` vault address. */
    vault: string;
    /** The status the registration carried (`active`, `draining`, …). */
    status: string;
    level: number;
    operationHash: string;
}

/** One administrator contract in the lineage, and how it got there. */
export interface AdministratorHop {
    address: string;
    entry: 'origination' | 'activation';
    /** The 0x0108 that activated it; null for the origination root. */
    activationLevel: number | null;
    activationHash: string | null;
    /** The administrator whose 0x0107 named it; null for the root. */
    proposedBy: string | null;
}

/**
 * Every `ProposeAdminContract` the walk saw, and what became of it. A proposal
 * that never activated is NOT in the lineage and its keys are not evidence —
 * reported here rather than dropped, because "someone proposed a successor and
 * it never took" is exactly the kind of thing a reader wants to see.
 */
export interface ProposalRecord {
    address: string;
    proposedBy: string;
    level: number;
    operationHash: string;
    /** Level of the successor's own 0x0108, or null if it never sent one. */
    activationLevel: number | null;
    /** Whether the walk continued into this contract. */
    followed: boolean;
}

export interface AdminLineage {
    administrators: AdministratorHop[];
    keys: LineageKey[];
    vaults: VaultRegistration[];
    proposals: ProposalRecord[];
    /**
     * Points where the walk could not decide which successor actually took
     * control, one sentence each. NON-EMPTY MEANS THE KEY SET IS NOT
     * TRUSTWORTHY: the caller must degrade the signature proof to
     * `unavailable` rather than report a `fail` it cannot stand behind.
     *
     * The trigger is two proposals from one administrator that BOTH have an
     * activation on L1. The kernel's pending record holds one proposal at a
     * time — a second `ProposeAdminContract` overwrites the first — so at most
     * one of those activations was accepted, and L1 alone does not say which:
     * an internal transaction is applied whether the kernel honours it or not.
     * Picking wrong walks onto a dead branch and misses the real successor's
     * keys, which turns an honest signature into a `fail`.
     */
    ambiguities: string[];
    /** Operations examined across every lineage sender. */
    scannedOperationCount: number;
    /**
     * Operations the indexer returned whose sender is NOT the administrator
     * they were requested for. The `sender=` filter is the indexer's claim
     * about itself; re-checking it here is the same discipline the rest of
     * this tool applies — and a payload from a KT1 outside the lineage is
     * exactly what an attacker would inject to smuggle in a key.
     */
    ignoredOperationCount: number;
}

/** Everything this decoder understands; anything else is `other`. */
export type AdminPayload =
    | { kind: 'register-tenant'; tenantId: string; publicKeyRaw: Uint8Array }
    | { kind: 'register-pool-vault'; tenantId: string; poolId: string; vault: string; status: string }
    | { kind: 'rotate-sequencer-key'; tenantId: string; publicKeyRaw: Uint8Array; graceLevels: bigint }
    | { kind: 'propose-admin-contract'; administrator: string }
    | { kind: 'activate-admin-contract' }
    | { kind: 'other'; classByte: number; subtag: number | null };

export class AdminPayloadError extends Error {}

// ── The Michelson PACK reader ───────────────────────────────────────────
//
// Hand-rolled, and deliberately tiny: it understands exactly the four node
// kinds these four payloads use. A general-purpose Michelson library would be
// a dependency in the published verifier's trust path for the sake of shapes
// that fit on one screen.

/** A decoded Michelson node — only the kinds `sp.pack` emits for these types. */
type Node =
    | { kind: 'int'; value: bigint }
    | { kind: 'string'; value: string }
    | { kind: 'bytes'; value: Uint8Array }
    | { kind: 'pair'; left: Node; right: Node };

class PackReader {
    private offset = 0;

    constructor(private readonly bytes: Uint8Array) {}

    node(): Node {
        const tag = this.u8();

        switch (tag) {
            case 0x00:
                return { kind: 'int', value: this.zarith() };
            case 0x01:
                return { kind: 'string', value: new TextDecoder().decode(this.lengthPrefixed()) };
            case 0x0a:
                return { kind: 'bytes', value: this.lengthPrefixed() };
            case 0x07: {
                // `07 07` is the two-argument prim with no annotation — Pair.
                // SmartPy packs an n-tuple as a RIGHT COMB of these, so
                // `(a, b, c)` is `Pair a (Pair b c)`; `comb` below flattens it.
                const prim = this.u8();

                if (prim !== 0x07) {
                    throw new AdminPayloadError(`unsupported Michelson prim 0x07 0x${prim.toString(16)}`);
                }

                return { kind: 'pair', left: this.node(), right: this.node() };
            }
            default:
                throw new AdminPayloadError(`unsupported Michelson node tag 0x${tag.toString(16)}`);
        }
    }

    expectEnd(): void {
        if (this.offset !== this.bytes.length) {
            throw new AdminPayloadError(`${this.bytes.length - this.offset} trailing byte(s) after the PACK`);
        }
    }

    private u8(): number {
        if (this.offset >= this.bytes.length) {
            throw new AdminPayloadError('PACK ended mid-node');
        }

        return this.bytes[this.offset++];
    }

    private lengthPrefixed(): Uint8Array {
        // Big-endian u32 — the one place this format is NOT little-endian, and
        // the opposite of the Borsh wire the rest of the verifier reads.
        const length = (this.u8() << 24) | (this.u8() << 16) | (this.u8() << 8) | this.u8();

        if (length < 0 || this.offset + length > this.bytes.length) {
            throw new AdminPayloadError(`PACK length prefix ${length} runs past the end`);
        }

        const slice = this.bytes.slice(this.offset, this.offset + length);

        this.offset += length;

        return slice;
    }

    /**
     * Michelson zarith. `int` and `nat` share ONE encoding: the first byte
     * carries a sign bit at 0x40 and six value bits, every later byte seven,
     * little-endian by group, with 0x80 as the continuation flag. Reading a
     * `nat` as if it were unsigned-from-the-first-byte shifts every value —
     * pinned by the live `1000000` mutez sample in the tests.
     */
    private zarith(): bigint {
        const first = this.u8();
        const negative = (first & 0x40) !== 0;
        let value = BigInt(first & 0x3f);
        let shift = 6n;
        let more = (first & 0x80) !== 0;

        while (more) {
            const byte = this.u8();

            value |= BigInt(byte & 0x7f) << shift;
            shift += 7n;
            more = (byte & 0x80) !== 0;
        }

        return negative ? -value : value;
    }
}

/** Flatten a right-comb of pairs into exactly `size` leaves. */
function comb(node: Node, size: number): Node[] {
    const out: Node[] = [];
    let current = node;

    for (let remaining = size; remaining > 1; remaining -= 1) {
        if (current.kind !== 'pair') {
            throw new AdminPayloadError(`expected a ${size}-tuple, found a ${current.kind} at position ${out.length}`);
        }

        out.push(current.left);
        current = current.right;
    }

    out.push(current);

    return out;
}

function asString(node: Node, what: string): string {
    if (node.kind !== 'string') {
        throw new AdminPayloadError(`${what}: expected a string, found ${node.kind}`);
    }

    return node.value;
}

function asBytes(node: Node, what: string): Uint8Array {
    if (node.kind !== 'bytes') {
        throw new AdminPayloadError(`${what}: expected bytes, found ${node.kind}`);
    }

    return node.value;
}

function asNat(node: Node, what: string): bigint {
    if (node.kind !== 'int') {
        throw new AdminPayloadError(`${what}: expected a nat, found ${node.kind}`);
    }

    if (node.value < 0n) {
        throw new AdminPayloadError(`${what}: expected a nat, found ${node.value}`);
    }

    return node.value;
}

/**
 * A packed `sp.key`: the Michelson curve tag then the raw key. Only Ed25519 is
 * admissible — the rollup's own parser drops every other curve
 * (`InvalidPublicKeyLen`), so a non-Ed25519 key here never became a signing
 * key and must not be presented as one.
 */
function asEd25519PublicKey(node: Node, what: string): Uint8Array {
    const bytes = asBytes(node, what);

    if (bytes.length === 0) {
        throw new AdminPayloadError(`${what}: empty key`);
    }

    const curve = bytes[0];

    if (curve !== 0x00) {
        const named = { 0x01: 'secp256k1', 0x02: 'p256', 0x03: 'bls' }[curve] ?? `unknown (0x${curve.toString(16)})`;

        throw new AdminPayloadError(
            `${what}: curve tag ${named} — only Ed25519 (tag 0x00) keys are admissible, and the rollup drops the rest`,
        );
    }

    if (bytes.length !== 33) {
        throw new AdminPayloadError(`${what}: Ed25519 key must be 33 packed bytes (tag + 32), got ${bytes.length}`);
    }

    return bytes.slice(1);
}

/**
 * A packed `sp.address`. An ORIGINATED address is `01 ‖ 20-byte hash ‖ 00`,
 * where the trailing byte is the (empty) entrypoint. An administrator is
 * always a contract, so an implicit address here is a malformed proposal.
 */
function asOriginatedAddress(node: Node, what: string): string {
    const bytes = asBytes(node, what);

    if (bytes.length !== 22 || bytes[0] !== 0x01 || bytes[21] !== 0x00) {
        throw new AdminPayloadError(
            `${what}: expected an originated (KT1) address as 01‖20‖00, got ${bytes.length} byte(s) starting 0x${(bytes[0] ?? 0).toString(16)}`,
        );
    }

    return encodeKt1(bytes.slice(1, 21));
}

/**
 * Decode one whole `[class | subtag | PACK]` administrator payload, exactly as
 * TzKT hands it back in `parameter.value`.
 *
 * Unknown class bytes and unknown subtags decode to `other` rather than
 * throwing: the rollup's own dispatch ignores what it does not route, and a
 * verifier that threw on a payload class added after it shipped would stop
 * walking the lineage at the first unfamiliar operation.
 */
export function decodeAdminPayload(payloadHex: string): AdminPayload {
    const bytes = hexToBytes(payloadHex.startsWith('0x') ? payloadHex.slice(2) : payloadHex);

    if (bytes.length < 1 || bytes[0] !== CLASS_ADMIN) {
        return { kind: 'other', classByte: bytes[0] ?? -1, subtag: bytes.length > 1 ? bytes[1] : null };
    }

    if (bytes.length < 2) {
        throw new AdminPayloadError('administrator payload carries a class byte but no subtag');
    }

    const subtag = bytes[1];

    if (subtag === SUBTAG_ACTIVATE_ADMIN_CONTRACT) {
        // The one payload-free subtag: `activate()` transfers a bare 0x0108.
        if (bytes.length !== 2) {
            throw new AdminPayloadError(`ActivateAdminContract carries ${bytes.length - 2} unexpected payload byte(s)`);
        }

        return { kind: 'activate-admin-contract' };
    }

    if (
        subtag !== SUBTAG_REGISTER_TENANT &&
        subtag !== SUBTAG_REGISTER_POOL_VAULT &&
        subtag !== SUBTAG_ROTATE_SEQUENCER_KEY &&
        subtag !== SUBTAG_PROPOSE_ADMIN_CONTRACT
    ) {
        return { kind: 'other', classByte: CLASS_ADMIN, subtag };
    }

    if (bytes[2] !== 0x05) {
        throw new AdminPayloadError(`expected a 0x05 PACK prefix after subtag 0x${subtag.toString(16)}`);
    }

    const reader = new PackReader(bytes.slice(3));
    const root = reader.node();

    reader.expectEnd();

    switch (subtag) {
        case SUBTAG_REGISTER_TENANT: {
            const [slug, key] = comb(root, 2);

            return {
                kind: 'register-tenant',
                tenantId: asString(slug, 'RegisterTenant.slug'),
                publicKeyRaw: asEd25519PublicKey(key, 'RegisterTenant.sequencer_public_key'),
            };
        }
        case SUBTAG_REGISTER_POOL_VAULT: {
            const [tenant, pool, vault, status] = comb(root, 4);

            return {
                kind: 'register-pool-vault',
                tenantId: asString(tenant, 'RegisterPoolVault.tenant'),
                poolId: asString(pool, 'RegisterPoolVault.pool'),
                vault: asOriginatedAddress(vault, 'RegisterPoolVault.vault'),
                status: asString(status, 'RegisterPoolVault.status'),
            };
        }
        case SUBTAG_ROTATE_SEQUENCER_KEY: {
            const [tenant, key, grace] = comb(root, 3);

            return {
                kind: 'rotate-sequencer-key',
                tenantId: asString(tenant, 'RotateSequencerKey.tenant'),
                publicKeyRaw: asEd25519PublicKey(key, 'RotateSequencerKey.new_public_key'),
                graceLevels: asNat(grace, 'RotateSequencerKey.grace_levels'),
            };
        }
        default:
            return {
                kind: 'propose-admin-contract',
                administrator: asOriginatedAddress(root, 'ProposeAdminContract.new_admin'),
            };
    }
}

// ── The walk ────────────────────────────────────────────────────────────

interface TzktInternalTransaction {
    id: number;
    level: number;
    hash: string;
    sender: { address: string } | null;
    parameter: { entrypoint: string; value: unknown } | null;
}

export interface LineageOptions {
    tzktApiUrl: string;
    /** `sr1…` — the rollup every administrator message is addressed to. */
    rollupAddress: string;
    /** The pinned lineage root from `networks.json`. */
    originationAdministrator: string;
    signal?: AbortSignal;
    /** Injectable for tests; defaults to the global `fetch`. */
    fetchImpl?: typeof fetch;
}

/**
 * Walk the administrator lineage and collect every key it ever registered.
 *
 * One indexer query per administrator, paged by `id.gt` so a long-lived
 * administrator's history is never truncated at a page boundary. The walk
 * follows a proposal only when the proposed contract itself sent a 0x0108 —
 * a successor that was named but never activated never controlled the rollup
 * and its operations are not evidence.
 *
 * KNOWN LIMIT, and it is NOT a safe one. L1 applies an internal transaction
 * regardless of what the kernel does with it, so a 0x0108 from a KT1 that was
 * proposed but was no longer the PENDING administrator is applied on chain and
 * rejected by the kernel — the kernel's pending record holds one proposal at a
 * time, and a later `ProposeAdminContract` overwrites the earlier one. With
 * two activated proposals the walk therefore has to guess, and guessing wrong
 * is not a merely over-large key set: it walks onto a DEAD BRANCH, never
 * reaches the real successor, and misses every key that successor registered.
 * Missing keys make an honest frame verify under nothing, i.e. a `fail` — a
 * false accusation, the one outcome this tool must never manufacture.
 *
 * So: follow the activation with the GREATEST level (the kernel's pending
 * record holds the most recent proposal, so the last activation is the one
 * likeliest to have been accepted), and when more than one proposal from the
 * same administrator has an activation, record an `ambiguities` entry. The
 * caller degrades the signature proof to `unavailable` on a non-empty list —
 * closing the gap properly needs the kernel's maturity-level rule and the
 * pending-record state, neither of which is on L1.
 */
export async function fetchAdminLineage(options: LineageOptions): Promise<AdminLineage> {
    const doFetch = options.fetchImpl ?? fetch;
    const administrators: AdministratorHop[] = [];
    const keys: LineageKey[] = [];
    const vaults: VaultRegistration[] = [];
    const proposals: ProposalRecord[] = [];
    const ambiguities: string[] = [];
    const visited = new Set<string>();

    let scannedOperationCount = 0;
    let ignoredOperationCount = 0;

    let hop: AdministratorHop = {
        address: options.originationAdministrator,
        entry: 'origination',
        activationLevel: null,
        activationHash: null,
        proposedBy: null,
    };

    for (;;) {
        if (visited.has(hop.address)) {
            // A cycle means a re-proposed ancestor. Stop rather than loop; the
            // keys already collected stand.
            break;
        }

        visited.add(hop.address);
        administrators.push(hop);

        const operations = await fetchOperations(doFetch, options, hop.address);
        const proposed: { address: string; level: number; operationHash: string }[] = [];

        for (const operation of operations) {
            if (operation.sender?.address !== hop.address) {
                ignoredOperationCount += 1;
                continue;
            }

            scannedOperationCount += 1;

            const value = operation.parameter?.value;

            if (typeof value !== 'string') {
                // The rollup inbox entrypoint takes bare `bytes`, so anything
                // else is another contract's traffic shape, not ours.
                continue;
            }

            let payload: AdminPayload;

            try {
                payload = decodeAdminPayload(value);
            } catch {
                // An undecodable payload from a genuine administrator is not
                // a key and not a hop; skip it rather than abandoning the walk
                // and losing every later key.
                continue;
            }

            switch (payload.kind) {
                case 'register-tenant':
                case 'rotate-sequencer-key':
                    keys.push({
                        tenantId: payload.tenantId,
                        edpk: encodeEdpk(payload.publicKeyRaw),
                        rawHex: Array.from(payload.publicKeyRaw, (b) => b.toString(16).padStart(2, '0')).join(''),
                        level: operation.level,
                        operationHash: operation.hash,
                        source: payload.kind,
                        administrator: hop.address,
                        graceLevels: payload.kind === 'rotate-sequencer-key' ? payload.graceLevels : null,
                    });
                    break;
                case 'register-pool-vault':
                    vaults.push({
                        tenantId: payload.tenantId,
                        poolId: payload.poolId,
                        vault: payload.vault,
                        status: payload.status,
                        level: operation.level,
                        operationHash: operation.hash,
                    });
                    break;
                case 'propose-admin-contract':
                    proposed.push({
                        address: payload.administrator,
                        level: operation.level,
                        operationHash: operation.hash,
                    });
                    break;
                default:
                    break;
            }
        }

        // Resolve the hop: among the proposals whose own contract sent a
        // 0x0108, follow the one whose activation is at the GREATEST level.
        // The kernel's pending record holds one proposal at a time and a later
        // `ProposeAdminContract` overwrites it, so an activation from a
        // superseded proposal is applied on L1 and rejected by the kernel —
        // the LAST activation is the one likeliest to have been the accepted
        // one, and following an earlier one walks onto a dead branch.
        const resolved: { proposal: (typeof proposed)[number]; activation: { level: number; hash: string } | null }[] =
            [];

        for (const proposal of proposed) {
            resolved.push({ proposal, activation: await findActivation(doFetch, options, proposal.address) });
        }

        const activated = resolved.filter(
            (entry): entry is { proposal: (typeof proposed)[number]; activation: { level: number; hash: string } } =>
                entry.activation !== null,
        );
        // `reduce`, not `sort`: the proposal list stays in proposal order for
        // the report, and only the CHOICE keys on the activation level.
        const chosen =
            activated.length === 0
                ? null
                : activated.reduce((best, entry) => (entry.activation.level > best.activation.level ? entry : best));

        if (activated.length > 1) {
            // Two activations, at most one of which the kernel accepted, and
            // L1 does not say which. The walk still has to pick one to make
            // progress; the caller is told the key set may be missing a branch.
            ambiguities.push(
                `administrator ${hop.address} proposed ${activated.length} successors that each activated on L1 (` +
                    activated
                        .map((a) => `${a.proposal.address} at level ${a.activation.level}`)
                        .join(', ') +
                    '); the kernel accepts at most one, and which one is not on chain, so the walk followed the ' +
                    'latest activation and the derived key set may be missing a branch',
            );
        }

        for (const entry of resolved) {
            proposals.push({
                address: entry.proposal.address,
                proposedBy: hop.address,
                level: entry.proposal.level,
                operationHash: entry.proposal.operationHash,
                activationLevel: entry.activation?.level ?? null,
                followed: entry === chosen,
            });
        }

        if (!chosen) {
            break;
        }

        hop = {
            address: chosen.proposal.address,
            entry: 'activation',
            activationLevel: chosen.activation.level,
            activationHash: chosen.activation.hash,
            proposedBy: hop.address,
        };
    }

    return { administrators, keys, vaults, proposals, ambiguities, scannedOperationCount, ignoredOperationCount };
}

/** Every vault the lineage registered for one pool, in registration order. */
export function vaultsForPool(lineage: AdminLineage, tenantId: string, poolId: string): string[] {
    const seen: string[] = [];

    for (const vault of lineage.vaults) {
        if (vault.tenantId === tenantId && vault.poolId === poolId && !seen.includes(vault.vault)) {
            seen.push(vault.vault);
        }
    }

    return seen;
}

/** Every key any administrator in the lineage registered for one tenant. */
export function keysForTenant(lineage: AdminLineage, tenantId: string): LineageKey[] {
    return lineage.keys.filter((key) => key.tenantId === tenantId);
}

async function findActivation(
    doFetch: typeof fetch,
    options: LineageOptions,
    candidate: string,
): Promise<{ level: number; hash: string } | null> {
    for (const operation of await fetchOperations(doFetch, options, candidate)) {
        if (operation.sender?.address !== candidate || typeof operation.parameter?.value !== 'string') {
            continue;
        }

        try {
            if (decodeAdminPayload(operation.parameter.value).kind === 'activate-admin-contract') {
                return { level: operation.level, hash: operation.hash };
            }
        } catch {
            continue;
        }
    }

    return null;
}

const PAGE_SIZE = 1000;

async function fetchOperations(
    doFetch: typeof fetch,
    options: LineageOptions,
    sender: string,
): Promise<TzktInternalTransaction[]> {
    const base = options.tzktApiUrl.replace(/\/$/, '');
    const out: TzktInternalTransaction[] = [];
    let lastId = 0;

    for (;;) {
        const url =
            `${base}/v1/operations/transactions` +
            `?target=${encodeURIComponent(options.rollupAddress)}&sender=${encodeURIComponent(sender)}` +
            `&status=applied&select=id,level,hash,sender,parameter&sort=id&limit=${PAGE_SIZE}` +
            (lastId ? `&id.gt=${lastId}` : '');
        const response = await doFetch(url, { signal: options.signal });

        if (!response.ok) {
            throw new Error(`TzKT ${response.status} for ${url}`);
        }

        const page = (await response.json()) as TzktInternalTransaction[];

        out.push(...page);

        for (const operation of page) {
            lastId = Math.max(lastId, operation.id);
        }

        if (page.length < PAGE_SIZE) {
            return out;
        }
    }
}
