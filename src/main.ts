/**
 * 99dot5 round verifier — UI shell.
 *
 * All verification runs client-side in this page; there is no server
 * round-trip for any of the maths, and no 99dot5 endpoint in the trust path.
 * The page only fetches from the chain sources configured below (TzKT + a
 * Tezos archive RPC — both swappable) or verifies messages you paste in.
 */
import { deploymentsForTenant, isListedRollup, NETWORKS, type Deployment, type NetworkConfig } from './chain/networks';
import {
    fetchBlockInboxMessages,
    fetchBlockOperations,
    headLevel,
    scanRange,
    type InboxMessage,
    type ScanProgress,
} from './chain/inbox';
import { fetchAdminLineage, keysForTenant, type AdminLineage } from './chain/admin-lineage';
import {
    keySetFromLineage,
    supportedGameTypes,
    type KeySet,
    type ReceiptsInput,
    type ScanContext,
    type VerificationReport,
    type VerifyInput,
} from './verifier';
import { decodeExternalMessage, hexToBytes } from '@99dot5/round-replay';
import { importReceipts } from './receipts/import';
import { type HintHandoff, readHintHandoff, readReceiptsHandoff, readRoundHandoff } from './receipts/handoff';
import { type DepositChain, fetchBigMapHas, fetchContractStorage, locateSessionDeposit } from './chain/deposit';
import {
    resolveReceiptsDeposit,
    runChainVerification,
    runPastedVerification,
    type HintInput,
    type PreliminaryReport,
} from './run';

const app = document.getElementById('app')!;

app.innerHTML = `
    <header>
        <h1>99dot5 round verifier</h1>
        <p class="tagline">Don’t trust us — replay us.</p>
        <p class="intro">
            This page proves four independent things about a round. The first two come from the public
            Tezos L1 inbox alone; the last two need the receipts your own game client kept:
        </p>
        <ol class="intro">
            <li><strong>The payout was correct.</strong> It re-derives the outcome from
                <code>(game_type, server_seed, client_seed, decision, chunk)</code> — blake2b-256 over
                <code>"99dot5:engine-seed:v1"</code> and the length-prefixed fields, keyed by the round’s
                decision rather than its action index — and applies the game’s payout rule in exact integer
                arithmetic. There is <em>no operator-controlled nonce</em> anywhere in the derivation. Each
                game version names its own derivation (<code>v1</code> for every game today); a round on a rollup
                the list does not name is reported inconclusive, never replayed under a guessed rule.</li>
            <li><strong>The seed was committed before the round.</strong> It finds the on-chain
                <code>SeedBatch</code> that published the seed’s hash and checks it landed at an L1 level
                strictly before the round’s message. Without this half, a correct payout could still come
                from a seed chosen after seeing your actions.</li>
            <li><strong>The round was built from your commands.</strong> Load your exported receipts and it
                rebuilds the round’s <code>player_commitment</code> from the commands you signed, then
                compares it with the one on chain. Without this, that commitment is a number the server
                chose; with it, a server that swapped, dropped or invented one of your commands cannot
                match it.</li>
            <li><strong>Each action is the one you authorised.</strong> The commitment above proves
                <em>which</em> commands the round was built from, not what they said — so this compares
                each action in the transcript with what your own signed command at that index projects to:
                the tile you revealed, the tick you claimed, the config you chose. It also asks the other
                way round: for every cashout you signed for this round, the server owes you either a
                cashout action or a signed refusal, and neither on a round that expired is the one thing
                this page will call out.</li>
        </ol>
        <p class="intro">
            Supported games: <code>${supportedGameTypes().join('</code>, <code>')}</code>.
            Everything below runs in your browser; view the source — it is published precisely so you can.
        </p>
    </header>

    <section class="panel" id="config-panel">
        <h2>Network</h2>
        <div class="grid">
            <label>Network
                <select id="network"></select>
            </label>
            <label>Deployment (rollup — pick the one your round was played on)
                <select id="deployment"></select>
            </label>
            <label>Tenant
                <input id="tenant" spellcheck="false" list="tenant-slugs" />
                <datalist id="tenant-slugs"></datalist>
            </label>
            <label>Pool
                <input id="pool" spellcheck="false" list="pool-slugs" />
                <datalist id="pool-slugs"></datalist>
            </label>
            <label>TzKT API (indexer — locates operations)
                <input id="tzkt" spellcheck="false" />
            </label>
            <label>Tezos RPC (archive node — supplies message bytes)
                <input id="rpc" spellcheck="false" />
            </label>
            <label>Rollup address (sr1 — the lineage walk’s target)
                <input id="rollup" spellcheck="false" />
            </label>
            <label>Origination administrator (KT1 — the trust anchor)
                <input id="admin" spellcheck="false" />
            </label>
            <label>Sequencer public key — OVERRIDE, normally empty
                <input id="edpk" spellcheck="false" placeholder="leave blank to derive from L1" />
            </label>
        </div>
        <p class="note" id="network-note"></p>
        <p class="note">
            The signing keys are <strong>derived from L1</strong>, not configured: starting at the
            origination administrator above, the verifier follows every
            <code>ProposeAdminContract</code> → <code>ActivateAdminContract</code> hop and collects every
            key those contracts ever registered for the tenant. The set is <em>historical</em> — a receipt
            signed under a key that was valid when it was delivered stays valid evidence, so a rotation
            never invalidates an old round. Typing a key above overrides the derivation; a match then
            proves only that <em>that</em> key signed the bytes, not that the tenant ever owned it.
        </p>
        <div id="key-set"></div>
    </section>

    <section class="panel">
        <h2>Verify a round</h2>
        <div class="grid">
            <label>Round ID (UUID)
                <input id="round-id" placeholder="9a256790-c7c0-47b0-9a5b-6ed2905d2df1" spellcheck="false" />
            </label>
            <label>Scan from level
                <input id="from-level" type="number" min="0" />
            </label>
            <label>Scan to level
                <input id="to-level" type="number" min="0" />
            </label>
            <label>Client seed text (optional)
                <input id="client-seed-text" placeholder="read from your receipts when loaded" spellcheck="false" />
            </label>
        </div>
        <p class="note">
            The scan needs archive data — pruned nodes drop old operations. A round reaches L1 as one
            <code>RoundTranscript</code> message when it settles, and seed batches are committed ahead of
            play, so if the commitment isn’t found, widen the range backwards.
        </p>
        <p class="note">
            The transcript carries only <code>blake2b-256</code> of your client-seed text, not the text
            itself. Every other check works from that hash alone; the original text adds one more proof —
            that the round was played under the seed <em>you</em> chose. Loaded receipts supply it from your
            signed bet command; type it here only to check the text you remember as well.
        </p>
        <details open>
            <summary>Your play receipts (optional — adds the third proof)</summary>
            <p class="note">
                Your game client stores every command it sent and every signed frame it received. Exporting
                them and loading the JSON here adds the proof the chain alone cannot give: that the round
                L1 replayed commits to the commands <em>you</em> authorised. Without it, the transcript’s
                <code>player_commitment</code> is a number the server chose, and the verdict caps at
                <strong>INCOMPLETE</strong>. Nothing is uploaded — the file is read in this page, and loading
                it fills in the round, tenant and pool for you.
            </p>
            <div class="actions">
                <input id="receipts-file" type="file" accept="application/json,.json" />
            </div>
            <textarea id="receipts-json" rows="4" spellcheck="false"
                placeholder='{"schema":"99dot5.receipts.v1", …}'></textarea>
            <p class="note" id="receipts-status"></p>
        </details>
        <div class="actions">
            <button id="fetch-verify" class="primary">Fetch from chain &amp; verify</button>
            <button id="abort" hidden>Abort</button>
            <span id="progress" role="status"></span>
        </div>
        <details>
            <summary>Offline mode: paste inbox messages instead</summary>
            <p class="note">
                One message per line, as <code>level:hex</code> (level enables the commitment-ordering
                check) or bare hex. Get them from any block explorer’s raw
                <code>smart_rollup_add_messages</code> view.
            </p>
            <textarea id="paste" rows="6" spellcheck="false"
                placeholder="1005:0995…&#10;1010:0995…"></textarea>
            <div class="actions">
                <button id="paste-verify">Verify pasted messages</button>
            </div>
        </details>
    </section>

    <section class="panel" id="report-panel" hidden>
        <h2>Report</h2>
        <div id="verdict"></div>
        <div id="runs"></div>
        <h3>Checks</h3>
        <ul id="checks"></ul>
        <h3>The working</h3>
        <div id="working"></div>
        <h3>Evidence and findings</h3>
        <div id="evidence"></div>
        <h3>Inbox references</h3>
        <ul id="references"></ul>
    </section>

    <footer>
        <p>
            Algorithms are pinned by golden vectors shared with the Rust engine and the wasm rollup
            kernel (<code>libs/games/src/*/v1/testdata/vectors.json</code>); this page’s implementation
            is asserted against the same files in CI. What this page verifies is the per-round
            chain: each server seed against the commitment published on-chain before the round
            existed, and the outcome recomputed from that seed and your client seed. The batch salt
            stays private and is never published, so batch-level derivation is not independently
            checkable.
        </p>
    </footer>
`;

const el = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;

const networkSelect = el<HTMLSelectElement>('network');
const tenantInput = el<HTMLInputElement>('tenant');
const tenantSlugList = el<HTMLDataListElement>('tenant-slugs');
const poolSlugList = el<HTMLDataListElement>('pool-slugs');
const poolInput = el<HTMLInputElement>('pool');
const tzktInput = el<HTMLInputElement>('tzkt');
const rpcInput = el<HTMLInputElement>('rpc');
const edpkInput = el<HTMLInputElement>('edpk');
const rollupInput = el<HTMLInputElement>('rollup');
const adminInput = el<HTMLInputElement>('admin');
const keySetPanel = el<HTMLDivElement>('key-set');
const networkNote = el<HTMLParagraphElement>('network-note');
const roundIdInput = el<HTMLInputElement>('round-id');
const clientSeedTextInput = el<HTMLInputElement>('client-seed-text');
const fromLevelInput = el<HTMLInputElement>('from-level');
const toLevelInput = el<HTMLInputElement>('to-level');
const receiptsFileInput = el<HTMLInputElement>('receipts-file');
const receiptsTextarea = el<HTMLTextAreaElement>('receipts-json');
const receiptsStatus = el<HTMLParagraphElement>('receipts-status');
const fetchButton = el<HTMLButtonElement>('fetch-verify');
const abortButton = el<HTMLButtonElement>('abort');
const progress = el<HTMLSpanElement>('progress');

const deploymentSelect = el<HTMLSelectElement>('deployment');

/**
 * Tenant and pool from the loaded receipts, or null when none are loaded.
 *
 * Changing the network or deployment used to overwrite both — tenant with the
 * deployment's slug, pool with nothing — so picking a deployment AFTER loading
 * receipts silently dropped the pool they named. While receipts are loaded
 * their scope wins over the deployment defaults. Declared before the first
 * `applyNetwork` call below, which reads it.
 */
let receiptsScope: { tenantId: string; poolId: string } | null = null;

for (const network of NETWORKS) {
    const option = document.createElement('option');

    option.value = network.id;
    option.textContent = network.label;
    networkSelect.appendChild(option);
}

function currentNetwork(): NetworkConfig {
    return NETWORKS.find((n) => n.id === networkSelect.value) ?? NETWORKS[0];
}

function deploymentLabel(deployment: Deployment): string {
    const rollup = `${deployment.rollupAddress.slice(0, 8)}…${deployment.rollupAddress.slice(-4)}`;

    return (
        `${deployment.tenantId} · ${rollup} · originated at level ${deployment.originationAdministrator.level}` +
        (deployment.status === 'retired' ? ' · retired' : '')
    );
}

function applyNetwork(network: NetworkConfig): void {
    tzktInput.value = network.tzktApiUrl;
    rpcInput.value = network.rpcUrl;
    deploymentSelect.innerHTML = '';

    for (const deployment of network.deployments) {
        const option = document.createElement('option');

        option.value = deployment.rollupAddress;
        option.textContent = deploymentLabel(deployment);
        deploymentSelect.appendChild(option);
    }

    deploymentSelect.disabled = network.deployments.length === 0;

    if (network.deployments.length === 0) {
        const option = document.createElement('option');

        option.textContent = 'none originated yet';
        deploymentSelect.appendChild(option);
    }

    applyDeployment(network, network.deployments[0] ?? null);
}

function applyDeployment(network: NetworkConfig, deployment: Deployment | null): void {
    tenantInput.value = receiptsScope?.tenantId ?? deployment?.tenantId ?? '';
    // The pool is a fact about the SESSION, not the rollup: it comes from the
    // receipts, from the lineage when the tenant has a single pool, or from the
    // reader. A deployment default would be wrong for every other pool's player.
    poolInput.value = receiptsScope?.poolId ?? '';
    rollupInput.value = deployment?.rollupAddress ?? '';
    adminInput.value = deployment?.originationAdministrator.address ?? '';
    // The override starts EMPTY on every deployment: the derived set is the
    // answer, and pre-filling a key would quietly turn the anchor back into a
    // configured value. The slug datalists belong to the previous lineage.
    edpkInput.value = '';
    keySetPanel.innerHTML = '';
    tenantSlugList.innerHTML = '';
    poolSlugList.innerHTML = '';

    const editable =
        'Every field is editable — swap in your own indexer, archive node, or anchor if you don’t ' +
        'want to take these defaults on trust.';

    if (!deployment) {
        networkNote.textContent =
            `${network.label} lists no deployment — no rollup this verifier can replay is originated on it ` +
            `yet. That is expected, not an error; switch networks to verify live rounds.`;
    } else {
        const evidence = `Anchor evidence: ${deployment.evidence.join(' ')}`;

        networkNote.textContent =
            deployment.status === 'retired'
                ? `This rollup is retired: its rounds stay verifiable from L1 history, but new rounds are ` +
                  `played on a newer deployment. ${editable} ${evidence}`
                : `${editable} ${evidence}`;
    }
}

networkSelect.addEventListener('change', () => applyNetwork(currentNetwork()));
deploymentSelect.addEventListener('change', () => {
    const network = currentNetwork();

    applyDeployment(network, network.deployments.find((d) => d.rollupAddress === deploymentSelect.value) ?? null);
});
applyNetwork(NETWORKS[0]);

let controller: AbortController | null = null;

function setProgress(p: ScanProgress): void {
    progress.textContent =
        p.phase === 'locating'
            ? 'locating inbox operations via TzKT…'
            : `fetching message bytes: level ${p.done}/${p.total}`;
}

fetchButton.addEventListener('click', async () => {
    const roundId = roundIdInput.value.trim();

    if (!roundId) {
        progress.textContent = 'enter a round ID first';

        return;
    }

    controller = new AbortController();
    fetchButton.disabled = true;
    abortButton.hidden = false;

    const signal = controller.signal;
    const tzkt = tzktInput.value;
    const rpc = rpcInput.value;

    try {
        const receipts = readReceiptsWithFindings();
        let lineage: AdminLineage | null = null;
        // The flow itself lives in `run.ts`, DOM-free: keys, then the locator
        // hints, then the deposit, then the scan the three of them bound.
        const result = await runChainVerification({
            verify: verifyInputBase(roundId, receipts.input),
            fromLevel: Number(fromLevelInput.value) || null,
            toLevel: Number(toLevelInput.value) || null,
            hints: selectHints(receipts.input, receipts.findings),
            resolveKeys: async () => {
                const resolved = await resolveKeySet(signal);

                lineage = resolved.lineage;

                return resolved.keys;
            },
            resolveDeposit: () => resolveDeposit(receipts.input, lineage, signal),
            lineage: () => lineage,
            formPoolId: poolInput.value.trim(),
            chain: {
                ...depositChain(signal),
                // The head is fetched even when the reader pinned an upper
                // bound: the suppression ladder needs to know whether the
                // scan reached "now".
                headLevel: () => headLevel(tzkt, signal),
                scanRange: (from, to) => scanRange(tzkt, rpc, from, to, setProgress, signal),
                fetchBlock: (level) => fetchBlockInboxMessages(rpc, level, signal),
            },
            onPreliminary: renderPreliminary,
            onProgress: (text) => {
                progress.textContent = text;
            },
        });
        const scanned = result.report.scan;

        // Echo the default range into empty fields, as before; a range a hint
        // relocated is stated in the report instead, so a second press does
        // not pin the reader to it.
        if (scanned && !result.hints.some((h) => h.used)) {
            fromLevelInput.value ||= String(scanned.fromLevel);
            toLevelInput.value ||= String(scanned.toLevel);
        }

        progress.textContent = 'done';
        renderReport(result.report, result.hintedRun);
    } catch (error) {
        progress.textContent = error instanceof Error ? error.message : String(error);
    } finally {
        fetchButton.disabled = false;
        abortButton.hidden = true;
        controller = null;
    }
});

/**
 * The hints to consume: the receipts document's when it carries any, else
 * the link's. Malformed ones arrive as their parser's findings and are
 * reported as "ignored: malformed".
 */
function selectHints(receipts: ReceiptsInput, receiptFindings: string[]): HintInput {
    const documentHints = receipts.status === 'ok' ? receipts.receipts.locatorHints : null;
    const documentMalformed = receiptFindings.filter((finding) => finding.includes('locatorHints'));

    if (documentHints) {
        return { hints: documentHints, source: 'the receipts document', malformed: documentMalformed };
    }

    return {
        hints: handedOverHints?.hints ?? null,
        source: handedOverHints?.hints ? 'the link' : 'the receipts document or the link',
        malformed: [...documentMalformed, ...(handedOverHints?.findings ?? [])],
    };
}

abortButton.addEventListener('click', () => controller?.abort());

el<HTMLButtonElement>('paste-verify').addEventListener('click', async () => {
    const roundId = roundIdInput.value.trim();
    const lines = el<HTMLTextAreaElement>('paste')
        .value.split('\n')
        .map((line) => line.trim())
        .filter(Boolean);
    const messages: InboxMessage[] = [];

    for (const [index, line] of lines.entries()) {
        const match = /^(?:(\d+):)?(?:0x)?([0-9a-fA-F]+)$/.exec(line);

        if (!match) {
            progress.textContent = `line ${index + 1} is not level:hex`;

            return;
        }

        try {
            const envelope = decodeExternalMessage(hexToBytes(match[2]));

            if (envelope) {
                messages.push({
                    level: match[1] ? Number(match[1]) : 0,
                    operationHash: `(pasted line ${index + 1})`,
                    messageIndex: 0,
                    rawHex: match[2],
                    envelope,
                });
            }
        } catch (error) {
            progress.textContent = `line ${index + 1}: ${error instanceof Error ? error.message : error}`;

            return;
        }
    }

    progress.textContent = `decoded ${messages.length} pasted message(s)`;
    // Pasted bytes still need a key set, and the only source of one is L1; an
    // offline reader supplies the override instead, and the signature check
    // states which it used. The scan stays NULL (`runPastedVerification`), so
    // a round with no transcript resolves as `inconclusive`; a pasted
    // authenticated transcript still gets its session's deposit looked up.
    const resolved = await resolveKeySet();

    renderReport(
        await runPastedVerification({
            verify: verifyInputBase(roundId, readReceipts()),
            messages,
            keys: resolved.keys,
            lineage: resolved.lineage,
            formPoolId: poolInput.value.trim(),
            chain: depositChain(),
        }),
    );
});

/** The indexer and node reads behind the deposit lookups, over the form's endpoints. */
function depositChain(signal?: AbortSignal): DepositChain {
    const tzkt = tzktInput.value.trim();
    const rpc = rpcInput.value.trim();

    return {
        locateDeposit: (vaultAddresses, sessionIdHex, levelHint) =>
            locateSessionDeposit({ tzktApiUrl: tzkt, vaultAddresses, sessionIdHex, levelHint, signal }),
        blockOperations: (level) => fetchBlockOperations(rpc, level, signal),
        contractStorage: (address) => fetchContractStorage(rpc, address, signal),
        bigMapHas: (bigMapId, scriptExprHash) => fetchBigMapHas(rpc, bigMapId, scriptExprHash, signal),
    };
}

receiptsFileInput.addEventListener('change', async () => {
    const file = receiptsFileInput.files?.[0];

    if (!file) {
        return;
    }

    receiptsTextarea.value = await file.text();
    adoptReceiptsScope(`loaded ${file.name} (${file.size} bytes) — it is read in this page and never uploaded`);
    // Clear the input so re-selecting the same (possibly re-exported) file
    // fires `change` again.
    receiptsFileInput.value = '';
});

/**
 * Receipts handed over by a game's "Verify this round" (ADR 0026 §2.3): the
 * export rides in the URL fragment, which no server ever sees. Loaded exactly
 * as a picked file is — same box, same import, same scope adoption — and the
 * fragment is then dropped from the address bar so a reload or a copied link
 * does not carry the player's receipts along.
 */
async function adoptHandedOverReceipts(): Promise<void> {
    let text: string | null;

    try {
        text = await readReceiptsHandoff(window.location.hash);
    } catch (error) {
        receiptsStatus.textContent = `receipts from the game could not be read: ${(error as Error).message}`;

        return;
    }

    if (text === null) {
        adoptHandedOverRound();

        return;
    }

    history.replaceState(null, '', window.location.pathname + window.location.search);
    receiptsTextarea.value = text;
    adoptReceiptsScope('loaded from the game — read in this page, never uploaded. Press “Fetch from chain & verify”.');
}

/**
 * The locator hints a `#round=` link carried, kept for the next "Fetch from
 * chain & verify". A receipts document's own hints win over these.
 */
let handedOverHints: HintHandoff | null = null;

/**
 * A link that carries only a round id (`#round=…`) prefills the round field.
 * Read only when the link carries no receipts, which name their own round.
 */
function adoptHandedOverRound(): void {
    let roundId: string | null;

    try {
        roundId = readRoundHandoff(window.location.hash);
    } catch (error) {
        // Dropped too: a reload must not report the same bad link again.
        history.replaceState(null, '', window.location.pathname + window.location.search);
        progress.textContent = (error as Error).message;

        return;
    }

    if (roundId === null) {
        return;
    }

    // Malformed locator hints are dropped with a note; the round id stands.
    handedOverHints = readHintHandoff(window.location.hash);

    const { findings } = handedOverHints;

    history.replaceState(null, '', window.location.pathname + window.location.search);
    roundIdInput.value = roundId;
    progress.textContent = ['round ID filled in from the link — press “Fetch from chain & verify”', ...findings].join(
        '. ',
    );
}

void adoptHandedOverReceipts();

/** Parse whatever is in the receipts box; an empty box is `absent`, not an error. */
function readReceipts(): ReceiptsInput {
    return readReceiptsWithFindings().input;
}

/** {@link readReceipts}, plus the import's findings (the locator-hint ones are reported per hint). */
function readReceiptsWithFindings(): { input: ReceiptsInput; findings: string[] } {
    const text = receiptsTextarea.value.trim();

    if (!text) {
        return { input: { status: 'absent' }, findings: [] };
    }

    const result = importReceipts(text);

    if (result.status === 'error') {
        receiptsStatus.textContent = `receipts rejected: ${result.message}`;

        return { input: { status: 'error', message: result.message }, findings: [] };
    }

    receiptsStatus.textContent = [
        `receipts read: ${result.receipts.commands.length} command(s), ${result.receipts.frames.length} frame(s), ` +
            `labelled round ${result.receipts.roundIdHex} of session ${result.receipts.sessionIdHex}`,
        ...result.findings,
    ].join('. ');

    return { input: { status: 'ok', receipts: result.receipts }, findings: result.findings };
}

/** The suppression bracket's lower bound, derived from L1 by {@link resolveReceiptsDeposit}. */
function resolveDeposit(
    receipts: ReceiptsInput,
    lineage: AdminLineage | null,
    signal?: AbortSignal,
): Promise<ScanContext['deposit']> {
    return resolveReceiptsDeposit({
        receipts,
        lineage,
        formTenantId: tenantInput.value.trim(),
        formPoolId: poolInput.value.trim(),
        locateDeposit: depositChain(signal).locateDeposit,
        onProgress: (text) => {
            progress.textContent = text;
        },
    });
}

/**
 * Resolve the tenant's admissible signing keys: the manual override if one was
 * typed, otherwise the administrator lineage walked from the pinned anchor.
 *
 * Every failure path returns `unavailable` with its reason rather than
 * throwing or falling back — an unchecked signature must read as an absent
 * proof, never as a passed one.
 */
interface ResolvedKeys {
    keys: KeySet;
    /** null when the override was used or the walk failed. */
    lineage: AdminLineage | null;
}

async function resolveKeySet(signal?: AbortSignal): Promise<ResolvedKeys> {
    const override = edpkInput.value.trim();

    if (override) {
        renderKeySet(null, [override]);

        return { keys: { status: 'available', keys: [{ edpk: override, registration: null }] }, lineage: null };
    }

    const administrator = adminInput.value.trim();
    const rollupAddress = rollupInput.value.trim();

    if (!administrator || !rollupAddress) {
        renderKeySet(null, []);

        return {
            keys: {
                status: 'unavailable',
                reason:
                    'no origination administrator or rollup address is set for this network, so the lineage ' +
                    'walk has no root to start from (supply an override key to check the signatures anyway)',
            },
            lineage: null,
        };
    }

    try {
        progress.textContent = 'walking the administrator lineage on L1…';

        const lineage = await fetchAdminLineage({
            tzktApiUrl: tzktInput.value.trim(),
            rollupAddress,
            originationAdministrator: administrator,
            signal,
        });
        const tenantKeys = keysForTenant(lineage, tenantInput.value.trim());

        renderKeySet(lineage, tenantKeys.map((key) => key.edpk));
        renderTenantSlugs(lineage);
        renderPoolSlugs(lineage);

        return { keys: keySetFromLineage(lineage, tenantKeys), lineage };
    } catch (error) {
        renderKeySet(null, []);

        return {
            keys: {
                status: 'unavailable',
                reason: `the lineage walk failed: ${error instanceof Error ? error.message : String(error)}`,
            },
            lineage: null,
        };
    }
}

function renderKeySet(lineage: AdminLineage | null, edpks: string[]): void {
    const lines: string[] = [];

    if (lineage) {
        lines.push(
            `Administrator lineage (${lineage.administrators.length}): ` +
                lineage.administrators
                    .map((hop) =>
                        hop.entry === 'origination'
                            ? `${hop.address} (origination anchor)`
                            : `${hop.address} (activated at level ${hop.activationLevel})`,
                    )
                    .join(' → '),
        );

        for (const proposal of lineage.proposals.filter((p) => !p.followed)) {
            lines.push(
                `Proposed but never activated, so NOT in the lineage: ${proposal.address} ` +
                    `(proposed at level ${proposal.level} by ${proposal.proposedBy})`,
            );
        }

        for (const ambiguity of lineage.ambiguities) {
            lines.push(`AMBIGUOUS LINEAGE — the signature proof is withheld: ${ambiguity}.`);
        }

        if (lineage.ignoredOperationCount > 0) {
            lines.push(
                `${lineage.ignoredOperationCount} operation(s) the indexer returned under a sender that ` +
                    'did not match the one requested were ignored.',
            );
        }
    }

    lines.push(
        edpks.length > 0
            ? `Admissible signing keys (${edpks.length}): ${edpks.join(', ')}`
            : 'No admissible signing key derived.',
    );

    keySetPanel.innerHTML = '';

    for (const line of lines) {
        const p = document.createElement('p');

        p.className = 'note';
        p.textContent = line;
        keySetPanel.appendChild(p);
    }
}

/**
 * Offer the slugs the lineage actually registered. A tenant field whose value
 * matches no registered slug yields an empty key set and a permanently
 * `unavailable` signature proof, which reads as the tool's failure rather than
 * as a typo — so the registered slugs are put in front of the reader.
 */
function renderTenantSlugs(lineage: AdminLineage): void {
    const slugs = [...new Set(lineage.keys.map((key) => key.tenantId))].sort();

    tenantSlugList.innerHTML = '';

    for (const slug of slugs) {
        const option = document.createElement('option');

        option.value = slug;
        tenantSlugList.appendChild(option);
    }

    if (slugs.length > 0 && !slugs.includes(tenantInput.value.trim())) {
        const p = document.createElement('p');

        p.className = 'note';
        p.textContent =
            `The tenant field says "${tenantInput.value.trim()}", which this lineage never registered. ` +
            `Registered slug(s): ${slugs.join(', ')}.`;
        keySetPanel.appendChild(p);
    }
}

/**
 * Offer the pools the lineage registered a vault for under the current tenant.
 * The pool decides which vaults the deposit lookup searches, so a pool with no
 * registered vault silently loses the suppression bracket's lower bound.
 */
function renderPoolSlugs(lineage: AdminLineage): void {
    const tenantId = tenantInput.value.trim();
    const pools = [...new Set(lineage.vaults.filter((v) => v.tenantId === tenantId).map((v) => v.poolId))].sort();

    poolSlugList.innerHTML = '';

    for (const pool of pools) {
        const option = document.createElement('option');

        option.value = pool;
        poolSlugList.appendChild(option);
    }

    if (!poolInput.value.trim() && pools.length === 1) {
        poolInput.value = pools[0];
    }

    if (poolInput.value.trim() && pools.length > 0 && !pools.includes(poolInput.value.trim())) {
        const p = document.createElement('p');

        p.className = 'note';
        p.textContent =
            `The pool field says "${poolInput.value.trim()}", which has no vault registered under ` +
            `${tenantId}. Registered pool(s): ${pools.join(', ')}.`;
        keySetPanel.appendChild(p);
    }
}

/**
 * Prefill tenant and pool from a receipts document as soon as it is loaded, so
 * a preview-pool player never has to know which pool they played in. These are
 * the EXPORTER'S LABELS, used only as form defaults: the keys still come from
 * the lineage, and a wrong label derives an empty key set, never a pass.
 */
function adoptReceiptsScope(statusPrefix: string): void {
    const text = receiptsTextarea.value.trim();

    // Every load starts a fresh status line; the notes below are appended to
    // THIS load's prefix, never to a previous load's.
    receiptsStatus.textContent = text ? statusPrefix : '';

    if (!text) {
        receiptsScope = null;

        return;
    }

    const result = importReceipts(text);

    if (result.status !== 'ok') {
        receiptsScope = null;
        receiptsStatus.textContent = `receipts rejected: ${result.message}`;

        return;
    }

    const { tenantId, poolId } = result.receipts;
    const roundId = hyphenateUuid(result.receipts.roundIdHex);
    const changed: string[] = [];
    const previous = { tenant: tenantInput.value.trim(), pool: poolInput.value.trim() };

    receiptsScope = { tenantId, poolId };

    // The receipts name a tenant but no network or rollup. Select both only when
    // exactly one known deployment carries that slug; with several (a
    // re-origination that kept it) or none, the reader picks, because verifying
    // against the wrong lineage would fail an honest round's signatures.
    const matches = deploymentsForTenant(NETWORKS, tenantId);

    if (matches.length === 1) {
        const { network, deployment } = matches[0];

        if (networkSelect.value !== network.id || rollupInput.value.trim() !== deployment.rollupAddress) {
            networkSelect.value = network.id;
            applyNetwork(network);
            deploymentSelect.value = deployment.rollupAddress;
            applyDeployment(network, deployment);
            changed.push(`${network.label} deployment ${deploymentLabel(deployment)}`);
        } else {
            // Same deployment: re-apply only the receipts' tenant and pool, so
            // the lineage already shown is not thrown away.
            tenantInput.value = tenantId;
            poolInput.value = poolId;
        }
    } else {
        tenantInput.value = tenantId;
        poolInput.value = poolId;
        receiptsStatus.textContent +=
            matches.length === 0
                ? ` — NOTE: no known deployment registers tenant ${tenantId}; choose the network and deployment yourself`
                : ` — NOTE: ${matches.length} deployments register tenant ${tenantId}; choose the one this round was played on`;
    }

    // The round ID is filled only when the field is empty: a reader who typed a
    // round and then loaded receipts for a different one should see the
    // mismatch in the report, not have their input silently replaced.
    if (!roundIdInput.value.trim()) {
        roundIdInput.value = roundId;
        changed.push(`round ${roundId}`);
    } else if (roundIdInput.value.trim().toLowerCase() !== roundId) {
        receiptsStatus.textContent +=
            ` — NOTE: these receipts are labelled round ${roundId}, not the round ID entered above`;
    }

    if (previous.tenant !== tenantId) {
        changed.push(`tenant ${tenantId}`);
    }

    if (previous.pool !== poolId) {
        changed.push(`pool ${poolId}`);
    }

    if (changed.length > 0) {
        receiptsStatus.textContent +=
            ` — filled ${changed.join(', ')} from the receipts (a label, not proof; edit if it looks wrong)`;
    }

    progress.textContent = 'receipts loaded — press “Fetch from chain & verify”';
    fetchButton.focus();
}

/** Accept a round id as 32 bare hex digits or already hyphenated. */
function hyphenateUuid(value: string): string {
    const hex = value.trim().toLowerCase();

    return /^[0-9a-f]{32}$/.test(hex)
        ? `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
        : hex;
}

receiptsTextarea.addEventListener('change', () => adoptReceiptsScope('receipts read from the text box'));

/** Everything `verifyRound` takes from the form, i.e. all but the messages, keys, scan and session deposit. */
function verifyInputBase(
    roundId: string,
    receipts: ReceiptsInput,
): Omit<VerifyInput, 'messages' | 'keys' | 'scan' | 'sessionDeposit'> {
    const rollupAddress = rollupInput.value.trim();

    return {
        roundId,
        tenantId: tenantInput.value.trim(),
        // The instance every signature is checked against (#952): the
        // selected network's chain id and the rollup the round was played on.
        // The rollup field is editable, and an empty one means the instance
        // is unknown — the signatures check then reports `unavailable` rather
        // than guessing.
        signingDomain: rollupAddress ? { chainId: currentNetwork().chainId, rollupAddress } : null,
        // Looked up by the rollup actually in the field, so a hand-typed
        // rollup no entry lists is an unknown deployment and is not replayed.
        // The seed rule itself comes from the round's game version.
        deploymentListed: rollupAddress ? isListedRollup(NETWORKS, rollupAddress) : false,
        receipts,
        clientSeedText: clientSeedTextInput.value || undefined,
    };
}

// Seven labels, because the seven verdicts are not interchangeable: four of
// them are different reasons the tool is NOT alleging anything, and wording
// any two of them alike would either hide a finding or invent one.
const VERDICT_LABELS: Record<VerificationReport['verdict'], string> = {
        verified: 'VERIFIED — authentic messages, pre-committed seed, correct payout, and your own commands behind it',
        attested: 'ATTESTED — checked, but weakly: your receipts could not be reconstructed, so only the server’s own signed statement was compared',
        inconclusive:
            'INCONCLUSIVE — the scanned range does not bracket this round, or its rollup is not a listed deployment (or its game names a seed derivation this verifier does not implement); see the replay row',
        undetermined: 'UNDETERMINED — not on chain yet, and no EndSession for this session is on chain either, so nothing shows the operator moved past this round. Not an accusation; try again later',
        suppressed: 'SUPPRESSED — your receipts are valid, the round is not on chain, and this session’s EndSession is — which is written only after every round of the session settled',
        failed: 'FAILED — at least one check did not hold; see below',
        incomplete: 'INCOMPLETE — not all evidence was found; nothing is proven either way',
};

/**
 * The preliminary pass (scan still running): its checks, under a label that
 * states no verdict. The final report replaces it.
 */
function renderPreliminary(preliminary: PreliminaryReport): void {
    const verdict = el('verdict');

    renderBody(preliminary);
    verdict.className = 'verdict preliminary';
    verdict.textContent = preliminary.label;
    el('runs').innerHTML = '';
}

/**
 * The final report. With `hintedRun`, the narrowed fallback re-ran without
 * the sequencer's batch hint: both runs are shown side by side and the
 * verdict is the re-run's.
 */
function renderReport(report: VerificationReport, hintedRun: VerificationReport | null = null): void {
    const verdict = el('verdict');
    const runs = el('runs');

    renderBody(report);
    verdict.className = `verdict ${report.verdict}`;
    verdict.textContent = VERDICT_LABELS[report.verdict];
    runs.innerHTML = '';

    if (hintedRun) {
        for (const [label, run] of [
            ['With the sequencer’s batch hint', hintedRun],
            ['Without it (this verdict stands)', report],
        ] as const) {
            const p = document.createElement('p');
            const failing = run.checks.filter((c) => c.status === 'fail').map((c) => c.id);

            p.className = 'note';
            p.textContent =
                `${label}: ${run.verdict.toUpperCase()}` +
                (run.scan ? `, levels ${run.scan.fromLevel}–${run.scan.toLevel}` : '') +
                (failing.length > 0 ? `, failing: ${failing.join(', ')}` : '');
            runs.appendChild(p);
        }
    }
}

function renderBody(report: Omit<VerificationReport, 'verdict'>): void {
    el('report-panel').hidden = false;

    const checks = el('checks');

    checks.innerHTML = '';

    for (const check of report.checks) {
        const li = document.createElement('li');
        const badge = { pass: '✓', fail: '✗', unavailable: '–' }[check.status];

        li.className = `check ${check.status}`;
        li.innerHTML = `<span class="badge">${badge}</span><div><strong></strong><p></p></div>`;
        li.querySelector('strong')!.textContent = check.title;
        li.querySelector('p')!.textContent = check.detail;
        checks.appendChild(li);
    }

    const working = el('working');

    working.innerHTML = '';

    if (report.replay) {
        for (const step of report.replay.steps) {
            const details = document.createElement('details');
            const summary = document.createElement('summary');

            summary.textContent = `#${step.actionIndex} ${step.title}`;
            details.appendChild(summary);

            const dl = document.createElement('dl');

            for (const [key, value] of step.details) {
                const dt = document.createElement('dt');
                const dd = document.createElement('dd');

                dt.textContent = key;
                dd.textContent = value;
                dl.append(dt, dd);
            }

            details.appendChild(dl);
            working.appendChild(details);
        }
    } else {
        working.innerHTML = '<p class="note">No replay ran (missing settle data or unsupported game).</p>';
    }

    const evidence = el('evidence');

    evidence.innerHTML = '';

    if (report.scan) {
        const line = document.createElement('p');

        line.className = 'note';
        line.textContent =
            `Scanned levels ${report.scan.fromLevel}–${report.scan.toLevel}` +
            (report.scan.headLevel === null ? ' (L1 head unknown)' : ` (L1 head ${report.scan.headLevel})`) +
            (report.scan.deposit
                ? `; the session's first deposit was located on L1 at level ${report.scan.deposit.level}, before which ` +
                  'no round of this session can settle'
                : '; the session’s deposit could not be located on L1, so the range has no lower bound');
        evidence.appendChild(line);
    }

    for (const finding of report.findings) {
        const line = document.createElement('p');

        line.className = 'note';
        line.textContent = finding;
        evidence.appendChild(line);
    }

    const references = el('references');

    references.innerHTML = '';

    for (const reference of report.references) {
        const li = document.createElement('li');

        li.textContent = `level ${reference.level} — ${reference.summary} (op ${reference.operationHash})`;
        references.appendChild(li);
    }
}
