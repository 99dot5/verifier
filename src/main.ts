/**
 * 99dot5 round verifier — UI shell.
 *
 * All verification runs client-side in this page; there is no server
 * round-trip for any of the maths, and no 99dot5 endpoint in the trust path.
 * The page only fetches from the chain sources configured below (TzKT + a
 * Tezos archive RPC — both swappable) or verifies messages you paste in.
 */
import { NETWORKS, type NetworkConfig } from './chain/networks';
import { scanRange, type InboxMessage, type ScanProgress } from './chain/inbox';
import { headLevel } from './chain/inbox';
import { verifyRound, supportedGameTypes, type VerificationReport } from './verifier';
import { decodeExternalMessage } from './wire/messages';
import { hexToBytes } from './verify/seed';

const app = document.getElementById('app')!;

app.innerHTML = `
    <header>
        <h1>99dot5 round verifier</h1>
        <p class="tagline">Don’t trust us — replay us.</p>
        <p class="intro">
            This page proves two independent things about a round, from the public Tezos L1 inbox alone:
        </p>
        <ol class="intro">
            <li><strong>The payout was correct.</strong> It re-derives the outcome from
                <code>(game_type, server_seed, client_seed, action_index)</code> — blake2b-256 over
                <code>"game-seed|…"</code> — and applies the game’s payout rule in exact integer arithmetic.
                There is <em>no operator-controlled nonce</em> anywhere in the derivation.</li>
            <li><strong>The seed was committed before the round.</strong> It finds the on-chain
                <code>SeedBatch</code> that published the seed’s hash and checks it landed at an L1 level
                strictly before the round existed. Without this half, a correct payout could still come
                from a seed chosen after seeing your actions.</li>
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
            <label>Tenant
                <input id="tenant" spellcheck="false" />
            </label>
            <label>TzKT API (indexer — locates operations)
                <input id="tzkt" spellcheck="false" />
            </label>
            <label>Tezos RPC (archive node — supplies message bytes)
                <input id="rpc" spellcheck="false" />
            </label>
            <label>Sequencer public key (set on-chain by RegisterTenant)
                <input id="edpk" spellcheck="false" />
            </label>
            <label>Rollup address (informational)
                <input id="rollup" spellcheck="false" readonly />
            </label>
        </div>
        <p class="note" id="network-note"></p>
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
        </div>
        <p class="note">
            The scan needs archive data — pruned nodes drop old operations. Seed batches are committed
            ahead of play, so if the commitment isn’t found, widen the range backwards.
        </p>
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
        <h3>Checks</h3>
        <ul id="checks"></ul>
        <h3>The working</h3>
        <div id="working"></div>
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
const tzktInput = el<HTMLInputElement>('tzkt');
const rpcInput = el<HTMLInputElement>('rpc');
const edpkInput = el<HTMLInputElement>('edpk');
const rollupInput = el<HTMLInputElement>('rollup');
const networkNote = el<HTMLParagraphElement>('network-note');
const roundIdInput = el<HTMLInputElement>('round-id');
const fromLevelInput = el<HTMLInputElement>('from-level');
const toLevelInput = el<HTMLInputElement>('to-level');
const fetchButton = el<HTMLButtonElement>('fetch-verify');
const abortButton = el<HTMLButtonElement>('abort');
const progress = el<HTMLSpanElement>('progress');

for (const network of NETWORKS) {
    const option = document.createElement('option');

    option.value = network.id;
    option.textContent = network.label;
    networkSelect.appendChild(option);
}

function applyNetwork(network: NetworkConfig): void {
    tenantInput.value = network.tenantId;
    tzktInput.value = network.tzktApiUrl;
    rpcInput.value = network.rpcUrl;
    edpkInput.value = network.sequencerPublicKey ?? '';
    rollupInput.value = network.rollupAddress ?? '(not originated yet)';
    networkNote.textContent =
        network.rollupAddress === null
            ? `${network.label} has no rounds yet — the ${network.tenantId} rollup and vault are not ` +
              `originated. That is expected, not an error; switch networks to verify live rounds.`
            : 'Every field is editable — swap in your own indexer, archive node, or key if you don’t ' +
              'want to take these defaults on trust.';
}

networkSelect.addEventListener('change', () => {
    applyNetwork(NETWORKS.find((n) => n.id === networkSelect.value) ?? NETWORKS[0]);
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

    try {
        let from = Number(fromLevelInput.value);
        let to = Number(toLevelInput.value);

        if (!to) {
            to = await headLevel(tzktInput.value, controller.signal);
            toLevelInput.value = String(to);
        }

        if (!from) {
            from = Math.max(0, to - 20_000);
            fromLevelInput.value = String(from);
        }

        const messages = await scanRange(
            tzktInput.value,
            rpcInput.value,
            from,
            to,
            setProgress,
            controller.signal,
        );

        progress.textContent = `decoded ${messages.length} sequencer message(s) in range`;
        renderReport(runVerification(roundId, messages));
    } catch (error) {
        progress.textContent = error instanceof Error ? error.message : String(error);
    } finally {
        fetchButton.disabled = false;
        abortButton.hidden = true;
        controller = null;
    }
});

abortButton.addEventListener('click', () => controller?.abort());

el<HTMLButtonElement>('paste-verify').addEventListener('click', () => {
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
    renderReport(runVerification(roundId, messages));
});

function runVerification(roundId: string, messages: InboxMessage[]): VerificationReport {
    return verifyRound({
        roundId,
        tenantId: tenantInput.value.trim(),
        messages,
        sequencerPublicKey: edpkInput.value.trim() || null,
    });
}

function renderReport(report: VerificationReport): void {
    el('report-panel').hidden = false;

    const verdict = el('verdict');
    const labels = {
        verified: 'VERIFIED — authentic messages, pre-committed seed, correct payout',
        failed: 'FAILED — at least one check did not hold; see below',
        incomplete: 'INCOMPLETE — not all evidence was found; nothing is proven either way',
    } as const;

    verdict.className = `verdict ${report.verdict}`;
    verdict.textContent = labels[report.verdict];

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

    const references = el('references');

    references.innerHTML = '';

    for (const reference of report.references) {
        const li = document.createElement('li');

        li.textContent = `level ${reference.level} — ${reference.summary} (op ${reference.operationHash})`;
        references.appendChild(li);
    }
}
