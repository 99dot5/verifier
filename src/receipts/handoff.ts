/**
 * Receipts handed over in the URL fragment by a game's "Verify this round".
 *
 * The game opens this page at `…/verify/#receipts=<scheme>.<base64url>` with
 * the round's `ReceiptsExportV1` inside, so the reader lands with the round
 * loaded instead of saving a file and picking it again. The fragment is never
 * sent to a server, which keeps this page's promise — nothing is uploaded —
 * true for the hand-off too.
 *
 * Schemes:
 * - `gz`   — gzip of the export's JSON text;
 * - `json` — the UTF-8 JSON text itself (a browser without `CompressionStream`).
 *
 * The encoder is the play client's. This module only
 * turns the fragment back into the text the file picker would have produced;
 * whether that text is a valid export is `importReceipts`'s question, asked
 * exactly as it is for a file, so a hand-off is no more trusted than a file.
 *
 * A link may instead carry only a round id (`#round=<uuid>`), which prefills
 * the round field and nothing else. When both are present the receipts win:
 * they name their own round. Beside the round id the link may carry the
 * round's L1 locators (`transcriptLevel`, `transcriptOp`, `seedBatchLevel`,
 * `seedBatchOp`, {@link readHintHandoff}): hints this page confirms against
 * L1, never evidence. It may also name the round's tenant and pool (`tenant`,
 * `pool`, {@link readScopeHandoff}), which pick the network and deployment a
 * receipts document would otherwise have named; loaded receipts name their
 * own and win.
 */
import { deploymentsForTenant, type DeploymentMatch, type NetworkConfig } from '../chain/networks';

/** The fragment parameter the game writes. */
export const RECEIPTS_FRAGMENT_KEY = 'receipts';

/**
 * The fragment parameter carrying a bare round id (`#round=<uuid>`), from a
 * page that knows the round but holds no receipts for it. It only fills in the
 * round field: the round is then checked against the chain alone, exactly as
 * if the reader had typed the id.
 */
export const ROUND_FRAGMENT_KEY = 'round';

/** The fragment parameters carrying the locator hints beside a bare round id; each is optional. */
export const TRANSCRIPT_LEVEL_FRAGMENT_KEY = 'transcriptLevel';
export const TRANSCRIPT_OP_FRAGMENT_KEY = 'transcriptOp';
export const SEED_BATCH_LEVEL_FRAGMENT_KEY = 'seedBatchLevel';
export const SEED_BATCH_OP_FRAGMENT_KEY = 'seedBatchOp';

/** The fragment parameters naming the round's tenant and pool beside a bare round id; each is optional. */
export const TENANT_FRAGMENT_KEY = 'tenant';
export const POOL_FRAGMENT_KEY = 'pool';

/** A tenant or pool slug: 1 to 32 of `a-z`, `0-9` and `-`, as the tenant registry accepts them. */
export function isScopeSlug(value: unknown): value is string {
    return typeof value === 'string' && /^[a-z0-9-]{1,32}$/.test(value);
}

/**
 * Where the round's transcript and its seed batch sit on L1, as the sender
 * reported them: HINTS this page confirms against L1, never evidence. A hint
 * narrows or relocates a search within kernel-sound bounds and never decides
 * a verdict. The same shape arrives as an export's `locatorHints` or as the
 * hand-off's fragment keys. A batch known only by the level the kernel
 * recorded has `operationHash: null`.
 */
export interface LocatorHints {
    transcript?: { level: number; operationHash: string };
    seedBatch?: { level: number; operationHash: string | null };
}

/** An L1 block level as a hint states it: a positive safe integer. */
export function isLocatorLevel(value: unknown): value is number {
    return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

/** A Tezos operation hash (`o…`, base58check, 51 characters). Grammar only; L1 decides whether it exists. */
export function isOperationHash(value: unknown): value is string {
    return typeof value === 'string' && /^o[1-9A-HJ-NP-Za-km-z]{50}$/.test(value);
}

/** The largest decoded document this page accepts from a fragment (bytes). */
export const MAX_HANDOFF_JSON_BYTES = 32 * 1024 * 1024;

function fromBase64Url(text: string): Uint8Array {
    if (!/^[A-Za-z0-9_-]*$/.test(text)) {
        throw new Error('the receipts in the link are not base64url');
    }

    const padded = text.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - (text.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i += 1) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
}

async function gunzip(bytes: Uint8Array): Promise<Uint8Array> {
    if (typeof DecompressionStream !== 'function') {
        throw new Error('this browser cannot decompress the receipts in the link; export them as a file instead');
    }

    const source = new ReadableStream<Uint8Array>({
        start(controller) {
            controller.enqueue(bytes);
            controller.close();
        },
    });
    const stream = source.pipeThrough(
        new DecompressionStream('gzip') as unknown as TransformStream<Uint8Array, Uint8Array>,
    );
    const reader = stream.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;

    for (;;) {
        const { done, value } = await reader.read();

        if (done) {
            break;
        }

        total += value.length;

        // A bounded read: a small fragment must not inflate into a page-killer.
        if (total > MAX_HANDOFF_JSON_BYTES) {
            await reader.cancel();
            throw new Error('the receipts in the link are too large');
        }

        chunks.push(value);
    }

    const out = new Uint8Array(total);
    let offset = 0;

    for (const chunk of chunks) {
        out.set(chunk, offset);
        offset += chunk.length;
    }

    return out;
}

/**
 * The receipts JSON text carried by a location fragment (`#receipts=…`), or
 * `null` when the fragment carries none. Throws, with a reader-facing
 * message, when it carries something that does not decode.
 */
export async function readReceiptsHandoff(hash: string): Promise<string | null> {
    const params = new URLSearchParams(hash.startsWith('#') ? hash.slice(1) : hash);
    const value = params.get(RECEIPTS_FRAGMENT_KEY);

    if (value === null) {
        return null;
    }

    const dot = value.indexOf('.');
    const scheme = dot < 0 ? '' : value.slice(0, dot);
    const payload = fromBase64Url(value.slice(dot + 1));

    let bytes: Uint8Array;

    switch (scheme) {
        case 'gz':
            bytes = await gunzip(payload);
            break;
        case 'json':
            if (payload.length > MAX_HANDOFF_JSON_BYTES) {
                throw new Error('the receipts in the link are too large');
            }

            bytes = payload;
            break;
        default:
            throw new Error(`the receipts in the link use an unknown encoding "${scheme}"`);
    }

    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

/**
 * The round id carried by a location fragment (`#round=…`), as a lowercase
 * hyphenated UUID, or `null` when the fragment carries none. Accepts the
 * hyphenated form and the bare 32-hex form. Throws, with a reader-facing
 * message, when the value is not a UUID — it is never passed on as typed.
 */
export function readRoundHandoff(hash: string): string | null {
    const params = new URLSearchParams(hash.startsWith('#') ? hash.slice(1) : hash);
    const value = params.get(ROUND_FRAGMENT_KEY);

    if (value === null) {
        return null;
    }

    const text = value.trim().toLowerCase();
    const hex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(text)
        ? text.replaceAll('-', '')
        : text;

    if (!/^[0-9a-f]{32}$/.test(hex)) {
        throw new Error('the round ID in the link is not a UUID');
    }

    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** The locator hints a fragment carried, and what was wrong with any it dropped. */
export interface HintHandoff {
    /** `null` when the fragment carries no usable hint. */
    hints: LocatorHints | null;
    /** Reader-facing notes, one per dropped key or hint. Findings, never failures. */
    findings: string[];
}

/**
 * The locator hints carried beside a bare round id
 * (`#round=<uuid>&transcriptLevel=<n>&transcriptOp=<o…>&seedBatchLevel=<n>&seedBatchOp=<o…>`).
 *
 * Never throws, and reads nothing about the round itself: a malformed hint is
 * dropped with a finding while `round` stands, because a hint only narrows a
 * search and losing one costs a slower scan, never a verdict. A transcript
 * hint needs both its level and its operation hash; a batch hint needs its
 * level, and a missing or malformed `seedBatchOp` leaves the level alone.
 */
export function readHintHandoff(hash: string): HintHandoff {
    const params = new URLSearchParams(hash.startsWith('#') ? hash.slice(1) : hash);
    const findings: string[] = [];
    const hints: LocatorHints = {};

    /** A present key's value through `parse`; `undefined` when it is absent, or malformed (with a finding). */
    const read = <T>(key: string, parse: (text: string) => T | null, grammar: string): T | undefined => {
        const text = params.get(key);

        if (text === null) {
            return undefined;
        }

        const value = parse(text);

        if (value === null) {
            findings.push(`the link's ${key} hint is not ${grammar}; it was ignored`);

            return undefined;
        }

        return value;
    };
    const level = (text: string) => (/^[1-9]\d*$/.test(text) && isLocatorLevel(Number(text)) ? Number(text) : null);
    const operation = (text: string) => (isOperationHash(text) ? text : null);
    const LEVEL = 'a positive integer level';
    const OPERATION = 'an operation hash (o…)';

    const transcriptLevel = read(TRANSCRIPT_LEVEL_FRAGMENT_KEY, level, LEVEL);
    const transcriptOp = read(TRANSCRIPT_OP_FRAGMENT_KEY, operation, OPERATION);

    if (transcriptLevel !== undefined && transcriptOp !== undefined) {
        hints.transcript = { level: transcriptLevel, operationHash: transcriptOp };
    } else if (transcriptLevel !== undefined || transcriptOp !== undefined) {
        findings.push(
            `the link's transcript hint needs both ${TRANSCRIPT_LEVEL_FRAGMENT_KEY} and ${TRANSCRIPT_OP_FRAGMENT_KEY}; it was ignored`,
        );
    }

    const batchLevel = read(SEED_BATCH_LEVEL_FRAGMENT_KEY, level, LEVEL);
    const batchOp = read(SEED_BATCH_OP_FRAGMENT_KEY, operation, OPERATION);

    if (batchLevel !== undefined) {
        hints.seedBatch = { level: batchLevel, operationHash: batchOp ?? null };
    } else if (batchOp !== undefined) {
        findings.push(
            `the link's seed batch hint needs ${SEED_BATCH_LEVEL_FRAGMENT_KEY}; ${SEED_BATCH_OP_FRAGMENT_KEY} alone was ignored`,
        );
    }

    return { hints: hints.transcript || hints.seedBatch ? hints : null, findings };
}

/** The tenant and pool a fragment named, and what was wrong with any it dropped. */
export interface ScopeHandoff {
    /** `null` when the fragment names no tenant, or a malformed one. */
    tenantId: string | null;
    /** `null` when the fragment names no pool, or a malformed one. */
    poolId: string | null;
    /** Reader-facing notes, one per dropped key. Findings, never failures. */
    findings: string[];
}

/**
 * The tenant and pool named beside a bare round id
 * (`#round=<uuid>&tenant=<slug>&pool=<slug>`).
 *
 * Never throws: like a hint, a malformed slug is dropped with a finding while
 * `round` stands, and the page keeps its own default. Whether a well-formed
 * tenant names a deployment this page knows is the caller's question. A value
 * is never echoed into a finding — it may be anything a link can carry.
 */
export function readScopeHandoff(hash: string): ScopeHandoff {
    const params = new URLSearchParams(hash.startsWith('#') ? hash.slice(1) : hash);
    const findings: string[] = [];

    const read = (key: string): string | null => {
        const text = params.get(key);

        if (text === null) {
            return null;
        }

        if (!isScopeSlug(text)) {
            findings.push(`the link's ${key} is not a slug (a-z, 0-9 and -, at most 32); it was ignored`);

            return null;
        }

        return text;
    };

    return { tenantId: read(TENANT_FRAGMENT_KEY), poolId: read(POOL_FRAGMENT_KEY), findings };
}

/** What a link's tenant and pool do to the form. */
export interface ScopeAdoption {
    /** The one deployment to select, or `null` to keep the page's own. */
    deployment: DeploymentMatch | null;
    /** The pool to fill in, or `null` to leave the field alone. */
    poolId: string | null;
    /** Reader-facing notes, one per dropped key: the parser's, then this step's. */
    findings: string[];
}

/**
 * Where a link's tenant and pool ({@link readScopeHandoff}) take the form.
 *
 * Loaded receipts name their own tenant and pool and win, as they win over
 * the link's round id. Otherwise the tenant selects its network and
 * deployment only when exactly one deployment that is not retired carries it:
 * with none or several, the page keeps its default and says so, because
 * verifying against the wrong lineage would fail an honest round's
 * signatures. A pool belongs to its tenant, so it applies only beside a
 * tenant that selected its deployment: beside none, or one that was dropped,
 * it is dropped too.
 */
export function resolveScopeHandoff(
    networks: NetworkConfig[],
    scope: ScopeHandoff,
    receiptsLoaded: boolean,
): ScopeAdoption {
    const findings = [...scope.findings];
    const none: ScopeAdoption = { deployment: null, poolId: null, findings };

    if (scope.tenantId === null && scope.poolId === null) {
        return none;
    }

    if (receiptsLoaded) {
        findings.push("the link's tenant and pool were ignored: the loaded receipts name their own");

        return none;
    }

    if (scope.tenantId === null) {
        findings.push("the link's pool was ignored: the link names no tenant");

        return none;
    }

    const live = deploymentsForTenant(networks, scope.tenantId).filter(
        ({ deployment }) => deployment.status !== 'retired',
    );

    if (live.length !== 1) {
        findings.push(
            live.length === 0
                ? `the link's tenant ${scope.tenantId} is carried by no live deployment this page knows; ` +
                      'it was ignored, choose the network and deployment yourself'
                : `the link's tenant ${scope.tenantId} is carried by ${live.length} live deployments; ` +
                      'it was ignored, choose the one this round was played on',
        );

        if (scope.poolId !== null) {
            findings.push("the link's pool was ignored with its tenant");
        }

        return none;
    }

    return { deployment: live[0], poolId: scope.poolId, findings };
}

/** What a fragment arriving into the page does to what the page already holds. */
export interface FragmentArrival {
    /** What the fragment carries; `nothing` (an empty or foreign fragment) is ignored. */
    carries: 'receipts' | 'round' | 'nothing';
    /**
     * Whether the page moves to another round: the previous report, scan
     * status, round fields and link hints are cleared, and a run still going
     * stops writing to the page. False for a link this page refuses.
     */
    reset: boolean;
    /** Whether the receipts box (and its scope and provenance line) is emptied first. */
    clearReceipts: boolean;
    /** Why the receipts were cleared, for the reader; `null` when they were not. */
    note: string | null;
}

/**
 * Plan a fragment's arrival, at load or by `hashchange` into a page already in
 * use. `loadedRoundId` is the round the receipts box's document names
 * (hyphenated lowercase), or `null` when the box holds no readable document.
 *
 * New receipts replace the box exactly as at load. A round link keeps a
 * document for the SAME round and clears one for any other, which would
 * otherwise win over the link and be verified in its place. A malformed round
 * id changes nothing but the message saying so.
 */
export function planFragmentArrival(hash: string, loadedRoundId: string | null): FragmentArrival {
    const params = new URLSearchParams(hash.startsWith('#') ? hash.slice(1) : hash);

    if (params.has(RECEIPTS_FRAGMENT_KEY)) {
        return { carries: 'receipts', reset: true, clearReceipts: true, note: null };
    }

    if (!params.has(ROUND_FRAGMENT_KEY)) {
        return { carries: 'nothing', reset: false, clearReceipts: false, note: null };
    }

    let roundId: string | null;

    try {
        roundId = readRoundHandoff(hash);
    } catch {
        return { carries: 'round', reset: false, clearReceipts: false, note: null };
    }

    if (loadedRoundId === null || roundId === loadedRoundId) {
        return { carries: 'round', reset: true, clearReceipts: false, note: null };
    }

    return {
        carries: 'round',
        reset: true,
        clearReceipts: true,
        note:
            `the receipts loaded for round ${loadedRoundId} were cleared: the link names round ${roundId}, ` +
            'and those receipts would have been checked in its place',
    };
}
