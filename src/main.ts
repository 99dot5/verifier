/**
 * 99dot5 round verifier — UI shell.
 *
 * All verification runs client-side in this page; there is no server
 * round-trip for any of the maths, and no 99dot5 endpoint in the trust path.
 * The page only fetches from the chain sources configured below (TzKT + a
 * Tezos archive RPC — both swappable) or verifies messages you paste in.
 */
import { deploymentsForTenant, isListedRollup, NETWORKS, type Deployment, type NetworkConfig } from './chain/networks';
import { fetchBlockOperations, type InboxMessage } from './chain/inbox';
import { tzktInboxLocator } from './chain/inbox-locator';
import {
    createScanner,
    DownloadDeclinedError,
    type DownloadRequest,
    IndexerContradictionError,
    rpcNodeInbox,
    ScanIncompleteError,
    type ScanProgress,
} from './chain/inbox-scan';
import { tzktIndexerHints } from './chain/indexer-hints';
import { RangeCaches } from './chain/range-cache';
import { splitIdentifiers } from './identifiers';
import { runLocatedVerification } from './located';
import { fetchAdminLineage, keysForTenant, vaultsForPool, type AdminLineage } from './chain/admin-lineage';
import {
    keySetFromLineage,
    supportedGameTypes,
    type Check,
    type KeySet,
    type ReceiptsInput,
    type ScanContext,
    type VerificationReport,
    type VerifyInput,
} from './verifier';
import { decodeExternalMessage, hexToBytes } from '@99dot5/round-replay';
import { importReceipts, receiptsSourceLine, type ReceiptsSource } from './receipts/import';
import {
    type HintHandoff,
    planFragmentArrival,
    readHintHandoff,
    readReceiptsHandoff,
    readRoundHandoff,
    readScopeHandoff,
    resolveScopeHandoff,
} from './receipts/handoff';
import {
    type DepositChain,
    fetchBigMapHas,
    fetchContractScript,
    fetchContractStorage,
    locateSessionDeposit,
} from './chain/deposit';
import { resolveReceiptsDeposit, runPastedVerification, type HintInput, type PreliminaryReport } from './run';
import { locatePayoutEvents } from './payout/locate';
import { rollupNodeReads } from './payout/rollup-node';
import { type PayoutOutcome, type SessionPayoutReport, verifySessionPayout } from './payout/session-payout';

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
        <p class="intro">
            A fifth check, further down, is about your <strong>session’s payout</strong> rather than a round:
            that the fast payout your wallet received was authorised by two of the vault’s own payout signers and
            does not exceed what the rollup kernel said the session was owed.
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
            <label>Client seed text (optional)
                <input id="client-seed-text" placeholder="read from your receipts when loaded" spellcheck="false" />
            </label>
        </div>
        <p class="note">
            The transcript carries only <code>blake2b-256</code> of your client-seed text, not the text
            itself. Every other check works from that hash alone; the original text adds one more proof —
            that the round was played under the seed <em>you</em> chose. Loaded receipts supply it from your
            signed bet command; type it here only to check the text you remember as well.
        </p>
        <details open>
            <summary>Your play receipts (optional — adds the third proof)</summary>
            <p class="note" id="receipts-source" hidden></p>
            <p class="note">
                Your game client stores every command it sent and every signed frame it received. Exporting
                them and loading the JSON here adds the proof the chain alone cannot give: that the round
                L1 replayed commits to the commands <em>you</em> authorised. Without it, the transcript’s
                <code>player_commitment</code> is a number the server chose, and the verdict caps at
                <strong>INCOMPLETE</strong>. Nothing is uploaded — the file is read in this page, and loading
                it fills in the round, tenant and pool for you.
            </p>
            <div class="actions">
                <button id="receipts-pick" type="button">Choose receipts file…</button>
                <span class="note">or paste the JSON below</span>
                <input id="receipts-file" type="file" accept="application/json,.json" hidden />
            </div>
            <textarea id="receipts-json" rows="4" spellcheck="false"
                placeholder='{"schema":"99dot5.receipts.v1", …}'></textarea>
            <p class="note" id="receipts-status"></p>
        </details>

        <fieldset class="source">
            <legend>Where the round’s messages come from</legend>
            <label><input type="radio" name="source" value="chain" checked /> The chain</label>
            <label><input type="radio" name="source" value="paste" /> Pasted (offline)</label>
        </fieldset>
        <div id="source-chain">
            <p class="note">
                The indexer (TzKT) finds where this round’s messages sit on L1, and every message judged is read
                from the Tezos RPC; only the ones it reports as applied count. The Tezos RPC must serve old
                blocks with their operation results (an archive node); a level it cannot serve is reported as
                unread, never as empty.
            </p>
            <details id="scan-range">
                <summary>Scan range (optional)</summary>
                <p class="note">
                    Leave both empty: the verifier finds the round from your receipts or from the link. Set a
                    range only for a round ID with nothing else, settled more than 20,000 levels before the
                    head, or to keep a scan small. A typed level switches off locating the round by your
                    receipts’ signed time. A round reaches L1 as one <code>RoundTranscript</code> when it settles
                    and its seed batch is committed earlier, so if the commitment isn’t found, start lower.
                </p>
                <div class="grid">
                    <label>Scan from level
                        <input id="from-level" type="number" min="0" />
                    </label>
                    <label>Scan to level
                        <input id="to-level" type="number" min="0" />
                    </label>
                </div>
            </details>
        </div>
        <div id="source-paste" hidden>
            <p class="note">
                Paste the round’s inbox messages yourself, one per line, as <code>level:hex</code> or bare hex:
                the <code>RoundTranscript</code> and the <code>SeedBatch</code> that committed its seed. The
                level enables the commitment-ordering check. Get them from any block explorer’s raw
                <code>smart_rollup_add_messages</code> view, or your own node.
            </p>
            <p class="note">
                Only these lines are judged: nothing is scanned, so a missing transcript reads as
                <strong>INCONCLUSIVE</strong>, never as suppressed. Two lookups still go to the network — the
                tenant’s signing keys and the session’s first deposit — unless you type a sequencer key override
                above, which skips both.
            </p>
            <textarea id="paste" rows="6" spellcheck="false"
                placeholder="1005:0995…&#10;1010:0995…"></textarea>
        </div>
        <div class="actions">
            <button id="fetch-verify" class="primary">Fetch from chain &amp; verify</button>
            <button id="abort" hidden>Abort</button>
            <span id="progress" role="status"></span>
        </div>
        <div id="scan-status"></div>
    </section>

    <section class="panel" id="payout-panel">
        <h2>Verify a session’s payout</h2>
        <p class="intro">
            When a session ends, its balance leaves the rollup in one of two ways. The <strong>cemented
            payout</strong> is the rollup’s own outbox message, executable about two weeks later once the
            commitment covering it cements. The <strong>fast payout</strong> is the same payment minutes after the
            session ends, authorised by <strong>two of the vault’s four payout signers</strong> — and the vault
            cannot check its amount, because before cementation only a rollup node knows what the kernel computed.
            So two signers acting together could pay a session more than it was owed. That cannot be prevented
            without capital; this check is what makes it impossible to do quietly.
        </p>
        <p class="intro">
            It reads the vault’s <code>fast_payout</code> and <code>cemented_payout</code> events for the session
            off L1, re-verifies every signature the fast payout carried against the <code>payout_signers</code> the
            vault held at the time, replays the vault’s paid ledger, and compares the fast payout with the kernel’s
            figure: from the cemented payout on L1 once it has executed, or within minutes from the kernel’s own
            <code>session-{session}-end-payout</code> record on a rollup node <em>you</em> run. Paying less than the kernel’s
            figure is not a finding — the cemented payout pays the remainder.
        </p>
        <div class="grid">
            <label>Session ID (UUID — from your receipts, or the session you deposited to)
                <input id="session-id" spellcheck="false" placeholder="filled in from your receipts when loaded" />
            </label>
            <label>Rollup node RPC (optional — a node YOU run; the operator’s can only confirm the operator)
                <input id="rollup-node" spellcheck="false" placeholder="http://127.0.0.1:8932" />
            </label>
        </div>
        <p class="note">
            The vaults searched are the ones the administrator lineage registered for the tenant and pool above,
            so run this after the network and tenant are set. A rollup node is deliberately not defaulted: a rollup
            node is one party’s replay of the rollup, not a public chain source. An observer node of your own is
            enough — only <code>value</code> and <code>level</code> are read at its finalised block, and it must
            allow this page’s origin in its CORS settings.
        </p>
        <div class="actions">
            <button id="payout-verify" class="primary">Check the payout</button>
            <span id="payout-progress" role="status"></span>
        </div>
        <div id="payout-report" tabindex="-1" hidden>
            <div id="payout-outcome"></div>
            <h3>Checks</h3>
            <ul id="payout-checks"></ul>
            <h3>Evidence and findings</h3>
            <div id="payout-evidence"></div>
            <h3>L1 references</h3>
            <ul id="payout-references"></ul>
        </div>
    </section>

    <section class="panel" id="report-panel" tabindex="-1" hidden>
        <h2>Report</h2>
        <p class="note">Click a highlighted value (a level, a hash, an address, an id) to copy it.</p>
        <div id="verdict"></div>
        <p class="note" id="report-source"></p>
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

    <span id="copy-status" class="visually-hidden" role="status"></span>

    <footer>
        <p>
            Algorithms are pinned by golden vectors shared with the Rust engine and the wasm rollup
            kernel (published with this verifier’s source as <code>vectors/*.vectors.json</code>); this page’s implementation
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
const receiptsSource = el<HTMLParagraphElement>('receipts-source');
const fetchButton = el<HTMLButtonElement>('fetch-verify');
const abortButton = el<HTMLButtonElement>('abort');
const progress = el<HTMLSpanElement>('progress');
const scanStatus = el<HTMLDivElement>('scan-status');

const deploymentSelect = el<HTMLSelectElement>('deployment');
const sessionIdInput = el<HTMLInputElement>('session-id');
const rollupNodeInput = el<HTMLInputElement>('rollup-node');
const payoutButton = el<HTMLButtonElement>('payout-verify');
const payoutProgress = el<HTMLSpanElement>('payout-progress');

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

        networkNote.replaceChildren();
        appendWithIdentifiers(
            networkNote,
            deployment.status === 'retired'
                ? `This rollup is retired: its rounds stay verifiable from L1 history, but new rounds are ` +
                      `played on a newer deployment. ${editable} ${evidence}`
                : `${editable} ${evidence}`,
        );
    }
}

networkSelect.addEventListener('change', () => applyNetwork(currentNetwork()));
deploymentSelect.addEventListener('change', () => {
    const network = currentNetwork();

    applyDeployment(network, network.deployments.find((d) => d.rollupAddress === deploymentSelect.value) ?? null);
});
applyNetwork(NETWORKS[0]);

let controller: AbortController | null = null;
/** Bumped by every chain run; a run renders only while it is still the latest one. */
let runGeneration = 0;
/** One range cache per indexer and node for the page's lifetime, so a Retry reads only what is still missing. */
const rangeCaches = new RangeCaches();

/** Every form value a chain run reads, taken at the click: the run reads nothing from the form after it. */
interface FormSnapshot {
    roundId: string;
    network: NetworkConfig;
    tenantId: string;
    poolId: string;
    tzkt: string;
    rpc: string;
    edpk: string;
    rollup: string;
    admin: string;
    clientSeedText: string;
    fromLevel: number | null;
    toLevel: number | null;
    receiptsText: string;
    handedOverHints: HintHandoff | null;
}

function readForm(): FormSnapshot {
    return {
        roundId: roundIdInput.value.trim(),
        network: currentNetwork(),
        tenantId: tenantInput.value.trim(),
        poolId: poolInput.value.trim(),
        tzkt: tzktInput.value.trim(),
        rpc: rpcInput.value.trim(),
        edpk: edpkInput.value.trim(),
        rollup: rollupInput.value.trim(),
        admin: adminInput.value.trim(),
        clientSeedText: clientSeedTextInput.value,
        fromLevel: Number(fromLevelInput.value) || null,
        toLevel: Number(toLevelInput.value) || null,
        receiptsText: receiptsTextarea.value,
        handedOverHints,
    };
}

/**
 * No edge or spot check is drawn below the level the rollup's administrator
 * was originated at: nothing of this rollup can sit lower. 1 for a rollup no
 * entry lists.
 */
function minLevelFor(form: FormSnapshot): number {
    const deployment = form.network.deployments.find((d) => d.rollupAddress === form.rollup);

    return Math.max(1, deployment?.originationAdministrator.level ?? 1);
}

/** The running session payout check's, so a link that moves the page on can abort it. */
let payoutController: AbortController | null = null;

/**
 * Bumped whenever a link moves the page to another round. A check started
 * before it is aborted and writes nothing more to the page: its report would
 * describe the previous round.
 */
let pageGeneration = 0;

/** Whether the page is still on the generation `generation` (a check's click-time one). */
function ownedBy(generation: number): () => boolean {
    return () => generation === pageGeneration;
}

function setProgress(p: ScanProgress): void {
    progress.textContent =
        p.phase === 'locating'
            ? `locating this rollup’s messages via the indexer: ${p.done}/${p.total} levels`
            : `reading blocks from the Tezos RPC: ${p.done}/${p.total}`;
}

type MessageSource = 'chain' | 'paste';

const SOURCE_BUTTON_LABELS: Record<MessageSource, string> = {
    chain: 'Fetch from chain & verify',
    paste: 'Verify pasted messages',
};

const sourceInputs = [...document.querySelectorAll<HTMLInputElement>('input[name="source"]')];
const scanRange = el<HTMLDetailsElement>('scan-range');

/** Where the next run takes the round's messages from: the chain unless the reader picked pasted. */
function messageSource(): MessageSource {
    return sourceInputs.find((input) => input.checked)?.value === 'paste' ? 'paste' : 'chain';
}

/** The one Verify button's label, which names what it is about to do. */
function verifyLabel(): string {
    return SOURCE_BUTTON_LABELS[messageSource()];
}

/** Show the chosen source's own inputs and name it on the button. */
function applySource(source: MessageSource): void {
    for (const input of sourceInputs) {
        input.checked = input.value === source;
    }

    el('source-chain').hidden = source !== 'chain';
    el('source-paste').hidden = source !== 'paste';
    fetchButton.textContent = SOURCE_BUTTON_LABELS[source];
}

for (const input of sourceInputs) {
    input.addEventListener('change', () => applySource(messageSource()));
}

/** A typed or echoed range is in force for the next run, so it is never left out of sight. */
function revealScanRange(): void {
    if (fromLevelInput.value || toLevelInput.value) {
        scanRange.open = true;
    }
}

fromLevelInput.addEventListener('change', revealScanRange);
toLevelInput.addEventListener('change', revealScanRange);

fetchButton.addEventListener('click', () => {
    if (messageSource() === 'paste') {
        void verifyPasted();

        return;
    }

    const form = readForm();

    if (!form.roundId) {
        progress.textContent = 'enter a round ID first';

        return;
    }

    void runChain(form);
});

/** One chain run over a form snapshot; Retry runs the same snapshot again. */
async function runChain(form: FormSnapshot): Promise<void> {
    controller?.abort();

    const generation = ++runGeneration;
    const current = new AbortController();
    const owns = ownedBy(pageGeneration);
    /** Still the latest run, and no link has moved the page to another round since the click. */
    const live = () => generation === runGeneration && owns();
    const signal = current.signal;

    controller = current;
    fetchButton.disabled = true;
    abortButton.hidden = false;
    scanStatus.replaceChildren();
    // Whatever an earlier run showed is not this run's report.
    el('report-panel').hidden = true;

    /** Progress text, written only while this run is still the latest. */
    const report = (text: string) => {
        if (live()) {
            progress.textContent = text;
        }
    };

    // One scanner per run: its spot checks, download allowance and node memo
    // are this run's; the range cache it reads through outlives it.
    const scanner = createScanner({
        locator: tzktInboxLocator({ tzktApiUrl: form.tzkt, signal }),
        node: rpcNodeInbox(form.rpc, { signal }),
        cache: rangeCaches.for(form.tzkt, form.rpc),
        minLevel: minLevelFor(form),
        confirmDownload: (request) => confirmDownload(request, signal),
        signal,
        onProgress: (p) => {
            if (live()) {
                setProgress(p);
            }
        },
    });

    try {
        const receipts = readReceiptsWithFindings(form.receiptsText);
        let lineage: AdminLineage | null = null;
        // The flow itself lives in `run.ts`, DOM-free: keys, then the locator
        // hints, then the deposit, then the scan the three of them bound. A
        // hint-less game export is first located by its signed time and its
        // transcript sender (`located.ts`), then judged by that same flow.
        const result = await runLocatedVerification({
            verify: verifyInputBase(form.roundId, receipts.input, form),
            fromLevel: form.fromLevel,
            toLevel: form.toLevel,
            hints: selectHints(receipts.input, receipts.findings, form.handedOverHints),
            resolveKeys: async () => {
                const resolved = await resolveKeySet(signal, form, live);

                lineage = resolved.lineage;

                return resolved.keys;
            },
            resolveDeposit: () => resolveDeposit(receipts.input, lineage, signal, form, report),
            lineage: () => lineage,
            formPoolId: form.poolId,
            chain: {
                ...depositChain(signal, form),
                // The scan head, read even when the reader pinned an upper
                // bound: the suppression ladder needs to know whether the scan
                // reached "now", and "now" is the newest level both the node
                // and the indexer can serve, so the scan never claims a level
                // it could not read.
                headLevel: () => scanner.scanHead(),
                scanRange: (from, to) => scanner.scanRange(from, to),
                fetchBlock: (level) => scanner.fetchBlock(level),
            },
            onPreliminary: (preliminary) => {
                if (live()) {
                    renderPreliminary(preliminary);
                }
            },
            onProgress: report,
            indexer: tzktIndexerHints({ tzktApiUrl: form.tzkt, signal }),
            minLevel: minLevelFor(form),
            coverage: () => scanner.coverage(),
        });

        if (!live()) {
            return;
        }

        const scanned = result.report.scan;

        // Echo the default range into empty fields, as before, but only for a
        // run that was never a candidate for locating: a range a hint or the
        // located run chose is stated in the report instead, and an echo
        // after a located run or its fallback would fill from/to and so close
        // the located path on the next press.
        if (scanned && !result.hints.some((h) => h.used) && result.location === null) {
            fromLevelInput.value ||= String(scanned.fromLevel);
            toLevelInput.value ||= String(scanned.toLevel);
            revealScanRange();
        }

        progress.textContent = '';
        // Scan findings are already in the report: the located run adds them.
        renderReport(result.report, 'chain', result.hintedRun);
        // Only the final report moves the page: a run that ends in an error
        // after a preliminary pass states it by the button, which must stay
        // in view.
        reveal(el('report-panel'));
    } catch (error) {
        if (live()) {
            if (stopped(error, signal)) {
                // Abort pressed (a newer run superseding this one is not
                // live, so renders nothing): plain text, no leftover panel.
                el('report-panel').hidden = true;
                scanStatus.replaceChildren();
                progress.textContent = 'Stopped. Nothing was checked, so there is no report.';
            } else {
                renderRunError(error, form);
            }
        }
    } finally {
        // A newer run, or a link that moved the page on, holds the buttons now.
        if (controller === current) {
            fetchButton.disabled = false;
            abortButton.hidden = true;
            controller = null;
        }
    }
}

/**
 * Whether a run ended because it was aborted: its own signal says so, or the
 * error is the browser's abort exception (whose message, "signal is aborted
 * without reason", is no use to a reader).
 */
function stopped(error: unknown, signal: AbortSignal): boolean {
    return signal.aborted || (error instanceof DOMException && error.name === 'AbortError');
}

/** Megabytes, to one decimal below 10. */
function megabytes(bytes: number): string {
    const mb = bytes / 1_000_000;

    return mb < 10 ? mb.toFixed(1) : String(Math.round(mb));
}

/** Ask before a large indexer download; an abort answers no. */
function confirmDownload(request: DownloadRequest, signal: AbortSignal): Promise<boolean> {
    return new Promise((resolve) => {
        const panel = document.createElement('div');
        const text = document.createElement('p');
        const actions = document.createElement('div');
        const download = document.createElement('button');
        const cancel = document.createElement('button');
        const answer = (value: boolean) => {
            signal.removeEventListener('abort', onAbort);
            panel.remove();
            resolve(value);
        };
        const onAbort = () => answer(false);

        text.className = 'note';
        text.textContent =
            `This check downloads about ${megabytes(request.estimateBytes)} MB ` +
            `(≈ ${megabytes(request.compressedApprox)} MB compressed) of public inbox data from the indexer for ` +
            `levels ${request.fromLevel}–${request.toLevel}.`;
        actions.className = 'actions';
        download.className = 'primary';
        download.textContent = 'Download';
        cancel.textContent = 'Cancel';
        download.addEventListener('click', () => answer(true));
        cancel.addEventListener('click', () => answer(false));
        signal.addEventListener('abort', onAbort, { once: true });
        actions.append(download, cancel);
        panel.append(text, actions);
        scanStatus.replaceChildren(panel);
    });
}

/**
 * A run that ended without a report. Whatever the preliminary pass showed is
 * hidden, whatever the error: it was never this run's verdict. An unread
 * range, a declined download and an indexer contradiction are stated in the
 * scan status; an unread range offers Retry, which re-runs the same snapshot
 * and reads only what is still missing.
 */
function renderRunError(error: unknown, form: FormSnapshot): void {
    const message = error instanceof Error ? error.message : String(error);

    el('report-panel').hidden = true;

    if (
        !(error instanceof ScanIncompleteError) &&
        !(error instanceof DownloadDeclinedError) &&
        !(error instanceof IndexerContradictionError)
    ) {
        progress.textContent = message;

        return;
    }

    const line = document.createElement('p');

    progress.textContent = '';
    line.className = 'note';
    line.textContent = message;
    scanStatus.replaceChildren(line);

    if (error instanceof ScanIncompleteError) {
        const retry = document.createElement('button');

        retry.textContent = 'Retry';
        retry.addEventListener('click', () => void runChain(form));
        scanStatus.appendChild(retry);
    }
}

/**
 * The hints to consume: the receipts document's when it carries any, else
 * the link's. Malformed ones arrive as their parser's findings and are
 * reported as "ignored: malformed".
 */
function selectHints(receipts: ReceiptsInput, receiptFindings: string[], handed: HintHandoff | null): HintInput {
    const documentHints = receipts.status === 'ok' ? receipts.receipts.locatorHints : null;
    const documentMalformed = receiptFindings.filter((finding) => finding.includes('locatorHints'));

    if (documentHints) {
        return { hints: documentHints, source: 'the receipts document', malformed: documentMalformed };
    }

    return {
        hints: handed?.hints ?? null,
        source: handed?.hints ? 'the link' : 'the receipts document or the link',
        malformed: [...documentMalformed, ...(handed?.findings ?? [])],
    };
}

abortButton.addEventListener('click', () => controller?.abort());

/** Verify the messages the reader pasted: no scan, the same checks over exactly those lines. */
async function verifyPasted(): Promise<void> {
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
    fetchButton.disabled = true;

    try {
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
            'paste',
        );
        progress.textContent = '';
        reveal(el('report-panel'));
    } catch (error) {
        progress.textContent = `the pasted messages could not be checked: ${error instanceof Error ? error.message : String(error)}`;
    } finally {
        fetchButton.disabled = false;
    }
}

/** The indexer and node reads behind the deposit lookups, over the form's endpoints. */
function depositChain(signal?: AbortSignal, form: FormSnapshot = readForm()): DepositChain {
    const { tzkt, rpc } = form;

    return {
        locateDeposit: (vaultAddresses, sessionIdHex, levelHint) =>
            locateSessionDeposit({ tzktApiUrl: tzkt, vaultAddresses, sessionIdHex, levelHint, signal }),
        blockOperations: (level) => fetchBlockOperations(rpc, level, signal),
        contractStorage: (address) => fetchContractStorage(rpc, address, signal),
        bigMapHas: (bigMapId, scriptExprHash) => fetchBigMapHas(rpc, bigMapId, scriptExprHash, signal),
    };
}

/**
 * The session payout check: the lineage's vaults for the form's tenant and
 * pool, the indexer to locate the payout events, the node to read them, and
 * the reader's own rollup node when one is given.
 */
payoutButton.addEventListener('click', async () => {
    const sessionId = sessionIdInput.value.trim();

    if (!sessionId) {
        payoutProgress.textContent = 'enter a session ID first (loading your receipts fills it in)';

        return;
    }

    const abort = new AbortController();
    const owns = ownedBy(pageGeneration);
    const { signal } = abort;
    const tzkt = tzktInput.value.trim();
    const rpc = rpcInput.value.trim();
    const rollupNodeUrl = rollupNodeInput.value.trim();

    payoutController = abort;
    payoutButton.disabled = true;

    try {
        // The walk's progress goes by this check's button, not the round check's.
        const resolved = await resolveKeySet(signal, readForm(), owns, (text) => {
            payoutProgress.textContent = text;
        });
        const lineage = resolved.lineage;

        if (!owns()) {
            return;
        }

        if (!lineage) {
            payoutProgress.textContent =
                'the administrator lineage could not be derived, so the pool’s vaults are unknown: ' +
                (resolved.keys.status === 'unavailable' ? resolved.keys.reason : 'an override key carries no lineage');

            return;
        }

        const tenantId = tenantInput.value.trim();
        const poolId = poolInput.value.trim();
        // A pool narrows the search to its vaults; without one, every vault
        // the lineage registered under the tenant is searched.
        const vaultAddresses = poolId
            ? vaultsForPool(lineage, tenantId, poolId)
            : [...new Set(lineage.vaults.filter((v) => v.tenantId === tenantId).map((v) => v.vault))];
        const report = await verifySessionPayout({
            sessionId,
            vaultAddresses,
            chainId: currentNetwork().chainId,
            chain: {
                locatePayoutEvents: (vaults, sessionIdHex) =>
                    locatePayoutEvents({ tzktApiUrl: tzkt, vaultAddresses: vaults, sessionIdHex, signal }),
                blockOperations: (level) => fetchBlockOperations(rpc, level, signal),
                contractScript: (address, level) => fetchContractScript(rpc, address, level, signal),
                rollupNode: rollupNodeUrl ? rollupNodeReads(rollupNodeUrl, signal) : null,
            },
            onProgress: (text) => {
                if (owns()) {
                    payoutProgress.textContent = text;
                }
            },
        });

        if (!owns()) {
            return;
        }

        payoutProgress.textContent = '';
        renderPayoutReport(report);
        reveal(el('payout-report'));
    } catch (error) {
        if (owns()) {
            payoutProgress.textContent = stopped(error, signal)
                ? 'Stopped. The payout was not checked.'
                : error instanceof Error
                  ? error.message
                  : String(error);
        }
    } finally {
        if (payoutController === abort) {
            payoutButton.disabled = false;
            payoutController = null;
        }
    }
});

// The native file field is hidden: its look differs by browser and names no
// file once read. The button opens the same picker.
el<HTMLButtonElement>('receipts-pick').addEventListener('click', () => receiptsFileInput.click());

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
 * Receipts handed over by a game's "Verify this round": the
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
    applySource('chain');
    adoptReceiptsScope(`loaded from the game — read in this page, never uploaded. Press “${verifyLabel()}”.`);
}

/**
 * The locator hints a `#round=` link carried, kept for the next chain run.
 * A receipts document's own hints win over these.
 */
let handedOverHints: HintHandoff | null = null;

/**
 * A link that carries only a round id (`#round=…`) prefills the round field,
 * and its tenant and pool (`&tenant=…&pool=…`) pick the network, deployment
 * and pool a receipts document would have named. Read only when the link
 * carries no receipts, which name their own round and scope.
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

    // Malformed locator hints, tenant or pool are dropped with a note; the round id stands.
    handedOverHints = readHintHandoff(window.location.hash);

    const scope = resolveScopeHandoff(NETWORKS, readScopeHandoff(window.location.hash), receiptsScope !== null);
    const filled: string[] = [];

    if (scope.deployment) {
        const { network, deployment } = scope.deployment;

        networkSelect.value = network.id;
        applyNetwork(network);
        deploymentSelect.value = deployment.rollupAddress;
        applyDeployment(network, deployment);
        filled.push(`${network.label} deployment ${deploymentLabel(deployment)}`);
    }

    if (scope.poolId !== null) {
        poolInput.value = scope.poolId;
        filled.push(`pool ${scope.poolId}`);
    }

    history.replaceState(null, '', window.location.pathname + window.location.search);
    roundIdInput.value = roundId;
    // A link names a round on chain: its hints and its label are for a chain run.
    applySource('chain');
    progress.textContent = [
        `round ID filled in from the link — press “${verifyLabel()}”`,
        ...(filled.length > 0 ? [`${filled.join(', ')} filled in from the link (a label, not proof)`] : []),
        ...scope.findings,
        ...handedOverHints.findings,
    ].join('. ');
}

/** The round and session the receipts box's document names (hyphenated), or `null` when it holds none that reads. */
function loadedReceipts(): { roundId: string; sessionId: string } | null {
    const text = receiptsTextarea.value.trim();
    const result = text ? importReceipts(text) : null;

    return result?.status === 'ok'
        ? { roundId: hyphenateUuid(result.receipts.roundIdHex), sessionId: hyphenateUuid(result.receipts.sessionIdHex) }
        : null;
}

/**
 * Adopt whatever the fragment carries, at load and on every `hashchange`:
 * pasting a link that differs only in its fragment does not reload the page.
 * `history.replaceState` (which drops the fragment once read) fires no
 * `hashchange`, so this never re-enters itself.
 *
 * A fragment that moves the page to another round first clears everything
 * the previous one left: the report, the scan status, the round and range
 * fields, the link's hints, and — per {@link planFragmentArrival} — receipts
 * for another round, with the session ID they filled in. A chain run or
 * payout check still going is aborted.
 */
async function adoptFragment(): Promise<void> {
    const loaded = loadedReceipts();
    const plan = planFragmentArrival(window.location.hash, loaded?.roundId ?? null);

    if (plan.carries === 'nothing') {
        return;
    }

    if (plan.reset) {
        pageGeneration += 1;
        // The reader has moved on: abort any check still running and release
        // its buttons now, since its own `finally` no longer will.
        controller?.abort();
        controller = null;
        fetchButton.disabled = false;
        abortButton.hidden = true;

        if (payoutController) {
            payoutController.abort();
            payoutController = null;
            payoutButton.disabled = false;
            payoutProgress.textContent = '';
        }

        handedOverHints = null;
        roundIdInput.value = '';
        fromLevelInput.value = '';
        toLevelInput.value = '';
        progress.textContent = '';
        // A Retry or a download prompt left here belongs to the previous round.
        scanStatus.replaceChildren();
        el('report-panel').hidden = true;
        el('verdict').textContent = '';
        el('runs').innerHTML = '';
    }

    if (plan.clearReceipts) {
        if (loaded && sessionIdInput.value.trim().toLowerCase() === loaded.sessionId) {
            sessionIdInput.value = '';
        }

        receiptsTextarea.value = '';
        // An empty box: drops the receipts' scope, provenance line and status.
        adoptReceiptsScope('');
    }

    await adoptHandedOverReceipts();

    if (plan.note) {
        progress.textContent = [plan.note, progress.textContent].filter(Boolean).join('. ');
    }
}

window.addEventListener('hashchange', () => void adoptFragment());
void adoptFragment();

/**
 * The provenance line at the top of the receipts section, or hidden when no
 * document is loaded. It states what the DOCUMENT says about itself — an
 * unsigned label — which is also what the verdict ceiling reads.
 */
function showReceiptsSource(source: ReceiptsSource | null): void {
    receiptsSource.hidden = source === null;
    receiptsSource.textContent = source === null ? '' : receiptsSourceLine(source);
}

/** Parse whatever is in the receipts box; an empty box is `absent`, not an error. */
function readReceipts(): ReceiptsInput {
    return readReceiptsWithFindings().input;
}

/** {@link readReceipts}, plus the import's findings (the locator-hint ones are reported per hint). */
function readReceiptsWithFindings(receiptsText: string = receiptsTextarea.value): {
    input: ReceiptsInput;
    findings: string[];
} {
    const text = receiptsText.trim();

    if (!text) {
        showReceiptsSource(null);

        return { input: { status: 'absent' }, findings: [] };
    }

    const result = importReceipts(text);

    if (result.status === 'error') {
        showReceiptsSource(null);
        receiptsStatus.textContent = `receipts rejected: ${result.message}`;

        return { input: { status: 'error', message: result.message }, findings: [] };
    }

    showReceiptsSource(result.receipts.source);

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
    signal: AbortSignal | undefined,
    form: FormSnapshot,
    report: (text: string) => void,
): Promise<ScanContext['deposit']> {
    return resolveReceiptsDeposit({
        receipts,
        lineage,
        formTenantId: form.tenantId,
        formPoolId: form.poolId,
        locateDeposit: depositChain(signal, form).locateDeposit,
        onProgress: report,
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

/**
 * `live` false: the run was superseded or a link moved the page on, so the walk
 * renders nothing more (see {@link ownedBy}). `report` writes the walk's
 * progress by the button that started it: the round check's line unless the
 * caller is another check.
 */
async function resolveKeySet(
    signal?: AbortSignal,
    form: FormSnapshot = readForm(),
    live: () => boolean = () => true,
    report: (text: string) => void = (text) => {
        progress.textContent = text;
    },
): Promise<ResolvedKeys> {
    const override = form.edpk;
    const render = (lineage: AdminLineage | null, edpks: string[]) => {
        if (live()) {
            renderKeySet(lineage, edpks);
        }
    };

    if (override) {
        render(null, [override]);

        return { keys: { status: 'available', keys: [{ edpk: override, registration: null }] }, lineage: null };
    }

    const administrator = form.admin;
    const rollupAddress = form.rollup;

    if (!administrator || !rollupAddress) {
        render(null, []);

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
        if (live()) {
            report('walking the administrator lineage on L1…');
        }

        const lineage = await fetchAdminLineage({
            tzktApiUrl: form.tzkt,
            rollupAddress,
            originationAdministrator: administrator,
            signal,
        });
        const tenantKeys = keysForTenant(lineage, form.tenantId);

        if (live()) {
            renderKeySet(
                lineage,
                tenantKeys.map((key) => key.edpk),
            );
            renderTenantSlugs(lineage);
            renderPoolSlugs(lineage);
        }

        return { keys: keySetFromLineage(lineage, tenantKeys), lineage };
    } catch (error) {
        render(null, []);

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
        appendWithIdentifiers(p, line);
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
        showReceiptsSource(null);

        return;
    }

    const result = importReceipts(text);

    if (result.status !== 'ok') {
        receiptsScope = null;
        showReceiptsSource(null);
        receiptsStatus.textContent = `receipts rejected: ${result.message}`;

        return;
    }

    showReceiptsSource(result.receipts.source);

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
    // mismatch in the report, not have their input silently replaced. The
    // session ID, for the payout check, follows the same rule.
    if (!sessionIdInput.value.trim()) {
        sessionIdInput.value = hyphenateUuid(result.receipts.sessionIdHex);
        changed.push(`session ${sessionIdInput.value}`);
    }

    if (!roundIdInput.value.trim()) {
        roundIdInput.value = roundId;
        changed.push(`round ${roundId}`);
    } else if (roundIdInput.value.trim().toLowerCase() !== roundId) {
        receiptsStatus.textContent += ` — NOTE: these receipts are labelled round ${roundId}, not the round ID entered above`;
    }

    if (previous.tenant !== tenantId) {
        changed.push(`tenant ${tenantId}`);
    }

    if (previous.pool !== poolId) {
        changed.push(`pool ${poolId}`);
    }

    if (changed.length > 0) {
        receiptsStatus.textContent += ` — filled ${changed.join(', ')} from the receipts (a label, not proof; edit if it looks wrong)`;
    }

    progress.textContent = `receipts loaded — press “${verifyLabel()}”`;
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
    form: FormSnapshot = readForm(),
): Omit<VerifyInput, 'messages' | 'keys' | 'scan' | 'sessionDeposit'> {
    const rollupAddress = form.rollup;

    return {
        roundId,
        tenantId: form.tenantId,
        // The instance every signature is checked against: the
        // selected network's chain id and the rollup the round was played on.
        // The rollup field is editable, and an empty one means the instance
        // is unknown — the signatures check then reports `unavailable` rather
        // than guessing.
        signingDomain: rollupAddress ? { chainId: form.network.chainId, rollupAddress } : null,
        // Looked up by the rollup actually in the field, so a hand-typed
        // rollup no entry lists is an unknown deployment and is not replayed.
        // The seed rule itself comes from the round's game version.
        deploymentListed: rollupAddress ? isListedRollup(NETWORKS, rollupAddress) : false,
        receipts,
        clientSeedText: form.clientSeedText || undefined,
    };
}

// Seven labels, because the seven verdicts are not interchangeable: four of
// them are different reasons the tool is NOT alleging anything, and wording
// any two of them alike would either hide a finding or invent one.
const VERDICT_LABELS: Record<VerificationReport['verdict'], string> = {
    verified: 'VERIFIED — authentic messages, pre-committed seed, correct payout, and your own commands behind it',
    attested:
        'ATTESTED — checked, but weakly: your receipts could not be reconstructed, so only the server’s own signed statement was compared',
    inconclusive:
        'INCONCLUSIVE — the scanned range does not bracket this round, or its rollup is not a listed deployment (or its game names a seed derivation this verifier does not implement); see the replay row',
    undetermined:
        'UNDETERMINED — not on chain yet, and no EndSession for this session is on chain either, so nothing shows the operator moved past this round. Not an accusation; try again later',
    suppressed:
        'SUPPRESSED — your receipts are valid, the round is not on chain, and this session’s EndSession is — which is written only after every round of the session settled',
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
    renderReportSource('chain');
    verdict.className = 'verdict preliminary';
    verdict.textContent = preliminary.label;
    el('runs').innerHTML = '';
}

/** Say where the judged messages came from, so a pasted result is never read as a scanned one. */
function renderReportSource(source: MessageSource): void {
    el('report-source').textContent =
        source === 'chain'
            ? 'Messages from the chain: located through the indexer, every judged message read from the Tezos RPC.'
            : 'Messages you pasted: only those lines were judged and nothing was scanned, so a missing message ' +
              'reads as inconclusive, never as suppressed.';
}

/**
 * The final report. With `hintedRun`, the narrowed fallback re-ran without
 * the sequencer's batch hint: both runs are shown side by side and the
 * verdict is the re-run's.
 */
function renderReport(
    report: VerificationReport,
    source: MessageSource,
    hintedRun: VerificationReport | null = null,
): void {
    const verdict = el('verdict');
    const runs = el('runs');

    renderBody(report);
    renderReportSource(source);
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
            appendWithIdentifiers(
                p,
                `${label}: ${run.verdict.toUpperCase()}` +
                    (run.scan ? `, levels ${run.scan.fromLevel}–${run.scan.toLevel}` : '') +
                    (failing.length > 0 ? `, failing: ${failing.join(', ')}` : ''),
            );
            runs.appendChild(p);
        }
    }
}

/**
 * Append `text` to `parent`, each identifier in it (a level, a hash, an
 * address, an id) as a value the reader copies with a click or with Enter.
 * Built with text nodes and `textContent` only: report text quotes the
 * indexer, the node and the pasted receipts, and none of it is ever markup.
 */
function appendWithIdentifiers(parent: HTMLElement, text: string): void {
    for (const piece of splitIdentifiers(text)) {
        if (typeof piece === 'string') {
            parent.append(piece);
            continue;
        }

        const code = document.createElement('code');

        code.className = 'copy';
        code.textContent = piece.value;
        code.tabIndex = 0;
        code.setAttribute('role', 'button');
        code.title = 'Copy';
        parent.append(code);
    }
}

const copyStatus = el('copy-status');
const copiedTimers = new WeakMap<HTMLElement, number>();

/**
 * Copy a value to the clipboard. Where the clipboard cannot be written (a page
 * opened from disk is not a secure context), the value is selected instead,
 * so the reader's own copy shortcut takes it.
 */
async function copyValue(code: HTMLElement): Promise<void> {
    const value = code.textContent ?? '';

    try {
        await navigator.clipboard.writeText(value);
        copyStatus.textContent = `Copied ${value}`;
    } catch {
        const range = document.createRange();

        range.selectNodeContents(code);
        window.getSelection()?.removeAllRanges();
        window.getSelection()?.addRange(range);
        copyStatus.textContent = 'Selected; press your copy shortcut to copy it';

        return;
    }

    code.classList.add('copied');
    code.title = 'Copied';
    window.clearTimeout(copiedTimers.get(code));
    copiedTimers.set(
        code,
        window.setTimeout(() => {
            code.classList.remove('copied');
            code.title = 'Copy';
        }, 1200),
    );
}

const copyTarget = (event: Event): HTMLElement | null =>
    event.target instanceof Element ? event.target.closest<HTMLElement>('code.copy') : null;

document.addEventListener('click', (event) => {
    const code = copyTarget(event);

    // A reader selecting part of a value by dragging is not asking for a copy.
    if (code && !window.getSelection()?.toString()) {
        void copyValue(code);
    }
});

document.addEventListener('keydown', (event) => {
    const code = copyTarget(event);

    if (code && (event.key === 'Enter' || event.key === ' ')) {
        event.preventDefault();
        void copyValue(code);
    }
});

/** One list item per check, with its badge, title and detail. */
function renderChecksInto(list: HTMLElement, checks: readonly Check[]): void {
    list.innerHTML = '';

    for (const check of checks) {
        const li = document.createElement('li');
        const badge = { pass: '✓', fail: '✗', unavailable: '–' }[check.status];

        li.className = `check ${check.status}`;
        li.innerHTML = `<span class="badge">${badge}</span><div><strong></strong><p></p></div>`;
        li.querySelector('strong')!.textContent = check.title;
        appendWithIdentifiers(li.querySelector('p')!, check.detail);
        list.appendChild(li);
    }
}

// Seven outcomes for the payout, kept apart from the round verdicts: a payout
// is a fact about the SESSION, judged by different rules, and only one of
// the seven alleges anything.
const PAYOUT_OUTCOME_LABELS: Record<PayoutOutcome, string> = {
    backed: 'BACKED — the payout matches the kernel’s figure, two of the vault’s own signers authorised it, and the ledger holds',
    short: 'SHORT — the fast payout was below the kernel’s figure; the cemented payout pays (or paid) the remainder. Not an accusation',
    overpaid:
        'OVERPAID — the fast payout exceeds what the kernel recorded: two signers paid what the kernel does not back',
    unbacked: 'UNBACKED — a check did not hold; see below',
    pending:
        'PENDING — a fast payout exists, but nothing yet says what the kernel owed: no cemented payout on L1, and no rollup node to ask',
    unpaid: 'UNPAID — no payout event for this session on any of the pool’s vaults: not ended, or not paid yet',
    unavailable: 'UNAVAILABLE — the lookups could not be made or could not be trusted; see below',
};

/**
 * Bring a report the reader just asked for into view, and move focus to it so
 * a screen reader announces it; no scroll animation when the reader asked for
 * reduced motion.
 */
function reveal(panel: HTMLElement): void {
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    panel.scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'start' });
    panel.focus({ preventScroll: true });
}

function renderPayoutReport(report: SessionPayoutReport): void {
    const outcome = el('payout-outcome');
    const evidence = el('payout-evidence');
    const references = el('payout-references');

    el('payout-report').hidden = false;
    outcome.className = `verdict payout-${report.outcome}`;
    outcome.textContent = PAYOUT_OUTCOME_LABELS[report.outcome];
    renderChecksInto(el('payout-checks'), report.checks);
    evidence.innerHTML = '';

    const lines = [
        `Session ${report.sessionId}: ${report.events.length} payout event(s)` +
            (report.events.length > 0
                ? ' — ' +
                  report.events
                      .map(
                          (e) =>
                              `${e.path} ${e.amountMutez} mutez at level ${e.level} on ${e.vault} ` +
                              `(paid_now ${e.paidNowMutez}, paid_total ${e.paidTotalMutez})`,
                      )
                      .join('; ')
                : ''),
        ...(report.payoutSigners
            ? [
                  `The vault’s payout_signers at the block before the fast payout (${report.payoutSigners.length}): ` +
                      report.payoutSigners.join(', '),
              ]
            : []),
        ...report.findings,
    ];

    for (const line of lines) {
        const p = document.createElement('p');

        p.className = 'note';
        appendWithIdentifiers(p, line);
        evidence.appendChild(p);
    }

    references.innerHTML = '';

    for (const reference of report.references) {
        const li = document.createElement('li');

        appendWithIdentifiers(li, `level ${reference.level} — ${reference.summary} (op ${reference.operationHash})`);
        references.appendChild(li);
    }
}

function renderBody(report: Omit<VerificationReport, 'verdict'>): void {
    el('report-panel').hidden = false;

    renderChecksInto(el('checks'), report.checks);

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
                appendWithIdentifiers(dd, value);
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
        appendWithIdentifiers(
            line,
            `Scanned levels ${report.scan.fromLevel}–${report.scan.toLevel}` +
                (report.scan.headLevel === null ? ' (L1 head unknown)' : ` (L1 head ${report.scan.headLevel})`) +
                (report.scan.deposit
                    ? `; the session's first deposit was located on L1 at level ${report.scan.deposit.level}, before which ` +
                      'no round of this session can settle'
                    : '; the session’s deposit could not be located on L1, so the range has no lower bound'),
        );
        evidence.appendChild(line);
    }

    for (const finding of report.findings) {
        const line = document.createElement('p');

        line.className = 'note';
        appendWithIdentifiers(line, finding);
        evidence.appendChild(line);
    }

    const references = el('references');

    references.innerHTML = '';

    for (const reference of report.references) {
        const li = document.createElement('li');

        appendWithIdentifiers(li, `level ${reference.level} — ${reference.summary} (op ${reference.operationHash})`);
        references.appendChild(li);
    }
}
