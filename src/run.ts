/**
 * The chain-fetch flow behind "Fetch from chain & verify", without the DOM.
 *
 * Order (D1): the lineage keys first, then the locator hints, then the
 * session's deposit, and only then the scan, because the hints and the
 * deposit decide the scan's bounds.
 *
 * LOCATOR HINTS RELOCATE THE WINDOW WITHIN KERNEL-SOUND BOUNDS; THEY NEVER
 * DECIDE A VERDICT. A hint is the sender's word for where the round's
 * transcript and seed batch sit on L1. It is confirmed by reading that one
 * block and authenticating the message in it, and an unconfirmable hint is
 * treated as absent. What a confirmed hint changes, and why it is sound:
 *
 *   - Upper bound = the confirmed transcript's level T. The kernel applies
 *     the FIRST copy of a round, so a copy after T cannot be the applied one.
 *   - Lower bound = min(D, B_h) with a confirmed seed-batch hint at B_h (B_h
 *     alone when the deposit level D is unknown). A transcript copy matters
 *     only once its seed is pending, at a level >= B; from B on, a copy posted
 *     before the deposit is APPLIED as a session-missing reject that burns the
 *     seed (rollup `rounds.rs`, step 8), so the window must start at min(D, B)
 *     and not at D. Without a confirmed batch hint the lower bound is not
 *     narrowed. There is no seed-age fallback: `MAX_SEED_AGE_LEVELS` bounds
 *     the transcript ABOVE the batch, not a scan below it.
 *
 * The one failure a hint can manufacture is a `commitment-order` fail against
 * the hinted batch copy: a later duplicate of the batch makes that check
 * stricter. Only that case re-runs without the batch hint (D6); every other
 * hinted verdict stands, because it rests on authenticated L1 messages inside
 * the bounds above.
 *
 * Two deposit lookups, kept apart on purpose. The suppression bracket's
 * `scan.deposit` comes from the receipts' signed `RoundEnded` session and the
 * form's pool ({@link resolveReceiptsDeposit}), as before; it only bounds a
 * scan. The `session-before-transcript` check's `sessionDeposit` comes from
 * the chosen transcript copy's SIGNED envelope ({@link resolveSessionDeposit}),
 * because it can fail a round and an unsigned label must not decide that.
 */
import { type AdminLineage, vaultsForPool } from './chain/admin-lineage';
import { type DepositChain, type DepositLocation, resolveSessionDeposit } from './chain/deposit';
import type { InboxMessage } from './chain/inbox';
import type { LocatorHints } from './receipts/handoff';
import { decodeReceiptFrame } from './receipts/recompute';
import {
    authenticatesUnder,
    type KeySet,
    type ReceiptsInput,
    type ScanContext,
    selectRoundTranscript,
    type VerificationReport,
    type VerifyInput,
    verifyRound,
} from './verifier';

/** How far back an unhinted scan reaches from its upper bound. */
export const DEFAULT_SCAN_DEPTH = 20_000;

/** The chain reads the flow needs; the shell passes TzKT and the node RPC, a test passes stubs. */
export interface ChainSource extends DepositChain {
    headLevel(): Promise<number>;
    /** Every decoded sequencer message in the inclusive level range. */
    scanRange(fromLevel: number, toLevel: number): Promise<InboxMessage[]>;
    /** Every decoded sequencer message in one block. */
    fetchBlock(level: number): Promise<InboxMessage[]>;
}

/** The hints to consume, where they came from, and any the reader of them already dropped as malformed. */
export interface HintInput {
    hints: LocatorHints | null;
    /** Reader-facing name of the source, e.g. "the receipts document" or "the link". */
    source: string;
    /** Findings for hints dropped while parsing; each is reported as "ignored: malformed". */
    malformed: string[];
}

export interface ChainRunInput {
    verify: Omit<VerifyInput, 'messages' | 'keys' | 'scan' | 'sessionDeposit'>;
    /** The reader's own bounds; `null` when the field is empty. */
    fromLevel: number | null;
    toLevel: number | null;
    hints: HintInput;
    resolveKeys(): Promise<KeySet>;
    /** The suppression bracket's deposit (`scan.deposit`); see {@link resolveReceiptsDeposit}. */
    resolveDeposit(): Promise<ScanContext['deposit']>;
    /** The lineage the keys came from, read after `resolveKeys`; null for an override key or a failed walk. */
    lineage(): AdminLineage | null;
    /** The form's pool field, '' when empty; only compared with the signed transcript's pool. */
    formPoolId: string;
    chain: ChainSource;
    /** Called once with the preliminary pass, when there is one (D5). */
    onPreliminary?(preliminary: PreliminaryReport): void;
    onProgress?(text: string): void;
}

/** What happened to one hint. */
export interface HintOutcome {
    hint: 'transcript' | 'seed-batch' | 'malformed';
    used: boolean;
    /** "used (confirmed at level N, op …)" or "ignored: …". */
    fate: string;
}

/**
 * The preliminary pass's report. It carries no verdict on purpose: its window
 * can exclude a copy below it, so it may only say what it has found so far.
 */
export type PreliminaryReport = Omit<VerificationReport, 'verdict'> & { label: string };

export interface ChainRunResult {
    /** The report whose verdict stands. */
    report: VerificationReport;
    /** The run with the batch hint, when the narrowed fallback (D6) re-ran without it; `report` is then the re-run. */
    hintedRun: VerificationReport | null;
    preliminary: PreliminaryReport | null;
    hints: HintOutcome[];
}

export async function runChainVerification(input: ChainRunInput): Promise<ChainRunResult> {
    const progress = input.onProgress ?? (() => undefined);
    const keys = await input.resolveKeys();
    const confirmed = await confirmHints(input, keys);
    const deposit = await input.resolveDeposit();
    const head = await input.chain.headLevel();
    // Only an L1-confirmed deposit is a bound.
    const depositLevel = deposit?.confirmed ? deposit.level : null;
    const transcriptLevel = confirmed.transcript?.level ?? null;
    const batchLevel = confirmed.batch?.level ?? null;

    const upper = transcriptLevel ?? input.toLevel ?? head;
    // The unhinted depth U: the reader's "from", else the default depth below
    // the upper bound; anchored at T (and taken down to D) once a transcript
    // hint is confirmed, so an old round is never re-scanned near the head.
    const unhintedBase = input.fromLevel ?? Math.max(0, upper - DEFAULT_SCAN_DEPTH);
    const unhintedLower =
        transcriptLevel !== null && depositLevel !== null ? Math.min(unhintedBase, depositLevel) : unhintedBase;
    const lower =
        batchLevel === null ? unhintedLower : depositLevel === null ? batchLevel : Math.min(depositLevel, batchLevel);
    // A batch hint at or above T (a later duplicate) leaves nothing to scan
    // below it; the window then collapses to T and the confirmed batch rides
    // along as an added message, which D6 below then re-checks.
    const from = Math.min(lower, upper);
    const confirmedMessages = [confirmed.transcript, confirmed.batch].filter((m): m is InboxMessage => m !== null);
    const scanOf = (fromLevel: number): ScanContext => ({ fromLevel, toLevel: upper, headLevel: head, deposit });
    const sessionDepositOf = sessionDepositResolver({
        verify: input.verify,
        keys,
        lineage: input.lineage(),
        formPoolId: input.formPoolId,
        chain: input.chain,
    });
    const run = async (messages: InboxMessage[], scan: ScanContext): Promise<VerificationReport> =>
        withHintFates(
            verifyRound({ ...input.verify, messages, keys, scan, sessionDeposit: await sessionDepositOf(messages) }),
            input.hints.source,
            confirmed.outcomes,
        );

    let messages: InboxMessage[];
    let preliminary: PreliminaryReport | null = null;

    if (transcriptLevel !== null && batchLevel !== null && batchLevel < transcriptLevel - DEFAULT_SCAN_DEPTH) {
        // D5: show the recent end first. Its window can miss a copy in
        // [B, D), so it never states a verdict.
        const preliminaryFrom = Math.min(
            upper,
            Math.max(depositLevel ?? batchLevel, transcriptLevel - DEFAULT_SCAN_DEPTH),
        );

        progress(`preliminary pass: levels ${preliminaryFrom}–${upper}`);

        const recent = await input.chain.scanRange(preliminaryFrom, upper);

        preliminary = preliminaryOf(await run(merge(recent, confirmedMessages), scanOf(preliminaryFrom)), from);
        input.onPreliminary?.(preliminary);
        progress(`scanning on down to level ${from}`);

        const older = preliminaryFrom > from ? await input.chain.scanRange(from, preliminaryFrom - 1) : [];

        messages = merge(older, recent, confirmedMessages);
    } else {
        messages = merge(await input.chain.scanRange(from, upper), confirmedMessages);
    }

    const hinted = await run(messages, scanOf(from));

    if (!failsOnHintedBatch(hinted, confirmed.batch)) {
        return { report: hinted, hintedRun: null, preliminary, hints: confirmed.outcomes };
    }

    // D6: the batch hint is dropped and the unhinted depth is scanned,
    // anchored at the upper bound. The confirmed transcript stays; the hinted
    // batch copy stays only if the scan itself reaches it.
    const rerunFrom = Math.min(unhintedLower, upper);

    progress(`re-running without the batch hint: levels ${rerunFrom}–${upper}`);

    const missing = rerunFrom < from ? await input.chain.scanRange(rerunFrom, from - 1) : [];
    // `merge` keeps the first copy, so the confirmed batch object survives in
    // `messages` only where no scan returned it; dropping that object leaves
    // the hinted level in the re-run exactly when the scan itself reached it.
    const scanned = messages.filter((m) => m.level >= rerunFrom && m.level <= upper && m !== confirmed.batch);
    const rerun = await run(
        merge(missing, scanned, confirmed.transcript ? [confirmed.transcript] : []),
        scanOf(rerunFrom),
    );

    rerun.findings.push(
        `The run with the sequencer's batch hint failed commitment-order against the hinted SeedBatch copy at ` +
            `level ${batchLevel}. A later duplicate of a batch makes that check stricter, so this is the one failure ` +
            `a hint can manufacture: the verifier re-ran without the batch hint over levels ${rerunFrom}–${upper}, ` +
            'and this verdict is the re-run’s. Both runs are shown.',
    );

    return { report: rerun, hintedRun: hinted, preliminary, hints: confirmed.outcomes };
}

/** The paste path's inputs: the reader's own messages, and no scan. */
export interface PasteRunInput {
    verify: Omit<VerifyInput, 'messages' | 'keys' | 'scan' | 'sessionDeposit'>;
    messages: InboxMessage[];
    keys: KeySet;
    lineage: AdminLineage | null;
    formPoolId: string;
    chain: DepositChain;
}

/**
 * Verify pasted messages. The scan stays NULL: pasted messages are whatever
 * the reader pasted, so "not on chain" is never a conclusion this path may
 * reach, and a round with no transcript resolves as `inconclusive`. When the
 * paste holds an authenticated transcript of the round, the same deposit
 * resolver as the chain path runs on it, so `session-before-transcript` can
 * still pass; with no lineage (an offline override key) it cannot, and the
 * round reads `incomplete`.
 */
export async function runPastedVerification(input: PasteRunInput): Promise<VerificationReport> {
    const sessionDeposit = await sessionDepositResolver(input)(input.messages);

    return verifyRound({ ...input.verify, messages: input.messages, keys: input.keys, scan: null, sessionDeposit });
}

/**
 * The `sessionDeposit` for a message set: the deposit resolved for the
 * transcript copy `verifyRound` will choose, or null when that copy is
 * missing or unauthenticated (the check is then `unavailable` on its own).
 * One lookup per chosen copy, however many passes share it.
 */
function sessionDepositResolver(context: {
    verify: Pick<VerifyInput, 'roundId' | 'tenantId' | 'signingDomain'>;
    keys: KeySet;
    lineage: AdminLineage | null;
    formPoolId: string;
    chain: DepositChain;
}): (messages: InboxMessage[]) => Promise<DepositLocation | null> {
    const resolved = new Map<string, Promise<DepositLocation>>();

    return async (messages) => {
        const chosen = selectRoundTranscript({ ...context.verify, messages, keys: context.keys });

        if (!chosen?.authenticated) {
            return null;
        }

        const transcript = chosen.message;
        const key = `${transcript.level}:${transcript.operationHash}:${transcript.messageIndex}`;
        let pending = resolved.get(key);

        if (!pending) {
            pending = resolveSessionDeposit({
                transcript,
                lineage: context.lineage,
                formPoolId: context.formPoolId,
                chain: context.chain,
            });
            resolved.set(key, pending);
        }

        return pending;
    };
}

/**
 * The suppression bracket's lower bound, DERIVED from L1: the level of the
 * session's first deposit to the pool's vault.
 *
 * The session id comes from the SIGNED `RoundEnded` frame rather than the
 * export's label, and the vault from the administrator lineage. The vaults are
 * the form pool's, or with no pool named every vault of the tenant: the wider
 * search can only move the bound earlier, because the LOWEST level across the
 * vaults wins, which demands a longer scan and never a shorter one. The
 * export's `depositOperationLevel` is passed only as a cross-check.
 */
export async function resolveReceiptsDeposit(input: {
    receipts: ReceiptsInput;
    lineage: AdminLineage | null;
    formTenantId: string;
    formPoolId: string;
    locateDeposit(vaultAddresses: string[], sessionIdHex: string, levelHint: number | null): Promise<DepositLocation>;
    onProgress?(text: string): void;
}): Promise<ScanContext['deposit']> {
    const { receipts, lineage } = input;

    if (receipts.status !== 'ok' || !lineage) {
        return null;
    }

    let sessionIdHex: string | null;

    try {
        sessionIdHex = decodeReceiptFrame({
            sequence: 0n,
            payloadCase: 'roundEnded',
            relatedRequestId: null,
            frame: receipts.receipts.roundEndedFrame,
        }).envelope.sessionId;
    } catch {
        sessionIdHex = null;
    }

    if (!sessionIdHex) {
        return null;
    }

    input.onProgress?.('locating the session’s deposit on L1…');

    const vaults = input.formPoolId
        ? vaultsForPool(lineage, input.formTenantId, input.formPoolId)
        : [...new Set(lineage.vaults.filter((v) => v.tenantId === input.formTenantId).map((v) => v.vault))];
    const located = await input.locateDeposit(vaults, sessionIdHex, receipts.receipts.depositOperationLevel ?? null);

    input.onProgress?.(located.detail);

    // `confirmed` means "this level came from L1", the only kind of lower
    // bound §8.3(d) admits; a lookup that found nothing yields no bound.
    return located.lookup === 'found' && located.level !== null ? { level: located.level, confirmed: true } : null;
}

interface ConfirmedHints {
    transcript: InboxMessage | null;
    batch: InboxMessage | null;
    outcomes: HintOutcome[];
}

/** D2: confirm each hint against its own block only; anything unconfirmable is absent. */
async function confirmHints(input: ChainRunInput, keys: KeySet): Promise<ConfirmedHints> {
    const outcomes: HintOutcome[] = input.hints.malformed.map((finding) => ({
        hint: 'malformed',
        used: false,
        fate: `ignored: malformed (${finding})`,
    }));
    const hints = input.hints.hints;
    const roundId = input.verify.roundId.trim().toLowerCase();
    const domain = input.verify.signingDomain;
    const authentic = (m: InboxMessage) => domain !== null && authenticatesUnder(m, keys, domain);
    const notAuthenticated = (what: string): string =>
        keys.status !== 'available'
            ? `ignored: not authenticated (${what} was found, but no key set is available: ${keys.reason})`
            : domain === null
              ? `ignored: not authenticated (${what} was found, but the signing domain is unknown)`
              : `ignored: not authenticated (${what} was found, but verifies under no key the tenant registered)`;
    let transcript: InboxMessage | null = null;
    let batch: InboxMessage | null = null;

    if (hints?.transcript) {
        const { level, operationHash } = hints.transcript;
        const block = await readBlock(input.chain, level);

        if (typeof block === 'string') {
            outcomes.push({ hint: 'transcript', used: false, fate: block });
        } else {
            const candidates = block.filter(
                (m) =>
                    m.operationHash === operationHash &&
                    m.envelope.tenantId === input.verify.tenantId &&
                    m.envelope.message.kind === 'round-transcript' &&
                    m.envelope.message.roundId === roundId,
            );

            transcript = candidates.find(authentic) ?? null;
            outcomes.push({
                hint: 'transcript',
                used: transcript !== null,
                fate: transcript
                    ? `used (confirmed at level ${level}, op ${operationHash})`
                    : candidates.length === 0
                      ? `ignored: not found at the stated level (no RoundTranscript for round ${roundId} in op ${operationHash} at level ${level})`
                      : notAuthenticated(`a RoundTranscript for this round at level ${level}`),
            });
        }
    }

    if (hints?.seedBatch) {
        const { level, operationHash } = hints.seedBatch;
        const transcriptMessage = transcript?.envelope.message;

        if (!transcript || transcriptMessage?.kind !== 'round-transcript') {
            // The batch must cover the round's seed index, and only an
            // authenticated transcript says which index that is.
            outcomes.push({
                hint: 'seed-batch',
                used: false,
                fate: 'ignored: no confirmed transcript states the seed index this batch must cover',
            });
        } else {
            const seedIndex = transcriptMessage.serverSeedIndex;
            const block = await readBlock(input.chain, level);

            if (typeof block === 'string') {
                outcomes.push({ hint: 'seed-batch', used: false, fate: block });
            } else {
                const candidates = block.filter((m) => {
                    const message = m.envelope.message;

                    return (
                        (operationHash === null || m.operationHash === operationHash) &&
                        m.envelope.tenantId === input.verify.tenantId &&
                        m.envelope.poolId === transcript?.envelope.poolId &&
                        message.kind === 'seed-batch' &&
                        message.startIndex <= seedIndex &&
                        seedIndex < message.startIndex + BigInt(message.hashes.length)
                    );
                });

                batch = candidates.find(authentic) ?? null;
                outcomes.push({
                    hint: 'seed-batch',
                    used: batch !== null,
                    fate: batch
                        ? `used (confirmed at level ${level}, op ${batch.operationHash})`
                        : candidates.length === 0
                          ? `ignored: not found at the stated level (no SeedBatch covering index ${seedIndex}${operationHash === null ? '' : ` in op ${operationHash}`} at level ${level})`
                          : notAuthenticated(`a SeedBatch covering index ${seedIndex} at level ${level}`),
                });
            }
        }
    }

    return { transcript, batch, outcomes };
}

/** One block's messages, or the "not found" fate when the block cannot be read. */
async function readBlock(chain: ChainSource, level: number): Promise<InboxMessage[] | string> {
    try {
        return await chain.fetchBlock(level);
    } catch (error) {
        return `ignored: not found at the stated level (block ${level} could not be read: ${error instanceof Error ? error.message : String(error)})`;
    }
}

/**
 * The preliminary pass as a report with no verdict: only a label saying how
 * far the scan still has to go and how many checks fail so far.
 */
function preliminaryOf(report: VerificationReport, continuingTo: number): PreliminaryReport {
    const { roundId, gameType, checks, replay, references, findings, scan } = report;
    const failing = checks.filter((c) => c.status === 'fail').length;

    return {
        roundId,
        gameType,
        checks,
        replay,
        references,
        findings,
        scan,
        label:
            `Preliminary (scan continuing to level ${continuingTo}): ` +
            (failing === 0 ? 'no failure found so far' : `${failing} check(s) failing so far`),
    };
}

/** Whether `report` failed commitment-order against the confirmed hinted batch copy itself. */
function failsOnHintedBatch(report: VerificationReport, batch: InboxMessage | null): boolean {
    return (
        batch !== null &&
        report.checks.find((c) => c.id === 'commitment-order')?.status === 'fail' &&
        report.references.some(
            (r) =>
                r.summary.startsWith('SeedBatch') && r.level === batch.level && r.operationHash === batch.operationHash,
        )
    );
}

/** Each hint's fate, stated at the top of the report's findings (D8). */
function withHintFates(report: VerificationReport, source: string, outcomes: HintOutcome[]): VerificationReport {
    const fates = outcomes.map((o) =>
        o.hint === 'malformed'
            ? `Locator hint from ${source}: ${o.fate}`
            : `Locator hint (${o.hint === 'transcript' ? 'RoundTranscript' : 'SeedBatch'}) from ${source}: ${o.fate}`,
    );

    return { ...report, findings: [...fates, ...report.findings] };
}

/** Concatenate message sets, keeping one copy of each (level, operation, index). */
function merge(...sets: InboxMessage[][]): InboxMessage[] {
    const seen = new Set<string>();

    return sets.flat().filter((m) => {
        const key = `${m.level}:${m.operationHash}:${m.messageIndex}`;

        if (seen.has(key)) {
            return false;
        }

        seen.add(key);

        return true;
    });
}
