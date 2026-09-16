/**
 * What a REFUSAL proves — the round-scoped `CommandRejected` frame (P4).
 *
 * Every other proof in this verifier is about what the server DID. This one is
 * about what it declined to do, and it exists because a refusal is the only
 * evidence a suppressed command leaves behind: a cashout the sequencer simply
 * dropped produces no frame at all, while one it refused produces a signed
 * statement — a reason, a round, and the wall-clock instant the bytes arrived.
 *
 * ## The one check, and why it can fail
 *
 * A crash round busts at a `crash_tick` the revealed seed fixes before any
 * player decision. `RoundStarted` carries, under the tenant's signature, the
 * round's wall-clock anchor and its tick quantum. So a refusal that says "the
 * round was no longer alive when your command arrived" is checkable: convert
 * its own receipt stamp into a tick, and compare with the tick the seed says
 * the round crashed at. A stamp before the crash is the server contradicting
 * its own seed — it refused a cashout as not-alive at a moment its own
 * published randomness says the round was alive.
 *
 * At or after the crash the refusal is consistent, and the check passes. The
 * margin still goes out as a finding, because one round proves nothing and a
 * pattern across many is what a player would actually see: a server shaving
 * refusals would sit at a suspiciously tight margin, and EXACT equality — a
 * refusal landing on precisely the crash tick, every time — is the tell. The
 * finding reads that margin against the `CommandAccepted` stamps in the same
 * export, which are the null distribution: same clock, same binding, same
 * frame-arrival path, on commands the server did NOT refuse.
 *
 * ## Two narrowings, because a refusal can be expected rather than suspect
 *
 * 1. **The check is eligible for `fail` only on a round the transcript says
 *    settled by `expire`.** A round whose last action is a `cashout` — a
 *    manual claim or an auto target — had ALREADY ENDED, and every liveness
 *    refusal that follows is the correct answer to a second command against a
 *    settled round. Nothing about the crash tick can contradict it, because
 *    the round stopped before the crash by the player's own claim. Those
 *    refusals report `pass` and cite the settling command's own acknowledgement
 *    stamp when the export carries it. Only the `expire` shape — the deadline
 *    sweep's terminal loss, which is what a DROPPED cashout produces — leaves
 *    room for the contradiction this check exists to catch.
 *
 * 2. **Inside that shape, the first `RACE_BAND_TICKS` before the crash are a
 *    finding, not a fail.** The sweep that closes a busted round and the lock
 *    the command takes race in real time, and the honest width of that race is
 *    stamp-to-lock latency — tens of milliseconds against a 50 ms tick. A
 *    refusal one tick early is an honest server losing that race, not a server
 *    contradicting its seed, and the sequencer additionally delays the
 *    manual-crash expire sweep by a grace so honest refusals rarely land here
 *    at all. The residual is stated rather than hidden: a dishonest server can
 *    suppress cashouts stamped inside the band and call it the race. It is
 *    ALWAYS a finding, never silence, so the band is visible across rounds —
 *    which is where a server living inside it stops looking like latency.
 *
 * ## The trust rule, which is the whole reason this is safe
 *
 * The server chooses the reason code, so keying the comparison on one code
 * would hand it an escape: reply `STATE_OUT_OF_SYNC` instead of `ROUND_CLOSED`
 * and the rule never runs. Two things close that.
 *
 *   1. The round id on a refusal is trusted ONLY when it equals the `round_id`
 *      inside the player-signed command body for the same request id. That is
 *      attribution by signature — the same class of evidence as reading
 *      `client_seed` out of a signed `PlaceBet` — and it is not the inference
 *      D9 forbids, which is deriving a command's STEP INDEX from its body.
 *      Indices still come only from the server's signed frames. When the body
 *      is missing, undecodable, or names another round, the answer is
 *      `unavailable`: never a downgrade the server got to select.
 *   2. The comparison runs for every liveness-asserting reason, not for one.
 *      `ROUND_CLOSED` and `STATE_OUT_OF_SYNC` both say "the round was not in
 *      progress when your command landed", so both are checked.
 *      `ROUND_MODE_AUTO` is excluded BY NAME: refusing a manual cashout on a
 *      round whose target was pre-committed in the bet is correct by design,
 *      and it produces no check and no finding at all.
 *
 * ## The residual the classification names
 *
 * Closing the code-shopping escape at (2) leaves a narrower one. The
 * suppression rule in `verify/projection.ts` counts ANY trusted refusal naming
 * the round as the server having ANSWERED the command — so a server can refuse
 * a perfectly timely cashout with a code that asserts nothing about liveness
 * (`RATE_LIMITED`, `INTERNAL_ERROR`, a code this build does not know) and land
 * between the two rules: no comparison here, no suppression fail there.
 *
 * That cannot be a `fail` — every one of those codes has an honest reading,
 * and a verifier that accused a server of suppression on the strength of an
 * `INTERNAL_ERROR` would be crying wolf. So `classifyRefusalReason` sorts the
 * vocabulary once, in this module, and an `uninformative` refusal produces a
 * labelled FINDING saying exactly that: the answer is an answer and nothing
 * more, and a timely cashout refused this way is indistinguishable from a
 * suppressed one. `command-validity` codes are excluded from the finding
 * because they are self-evidently about the bytes the player signed rather
 * than about the round — the player can see the fault without trusting the
 * server about anything.
 *
 * ## What the timestamp does not say
 *
 * `received_at_unix_ms` is stamped at RECEIPT, before the session-key
 * signature is verified. It attests when the bytes arrived — not that the
 * command was well-formed at that instant. Nothing exploitable follows, and
 * the report says so rather than quietly overstating it.
 *
 * ## Deliberately not in `allProofsRan`
 *
 * A round with no refusal is the normal case, so requiring this check to have
 * run would degrade every honest round. A `fail` still drives the verdict to
 * `failed` through `anyFail`, which is the asymmetry that belongs here: an
 * absent refusal proves nothing, a contradicted one proves a great deal.
 */
import type { ImportedCommand } from '../receipts/import';
import type { ReceiptFrame } from '../receipts/recompute';
import type { Check } from '../verifier';
import { decodeClientEnvelope } from '../wire/proto-reader';
import { CLIENT_FRAME_TAG, splitSignedFrame } from '../wire/signature';
import * as crash from './crash';

/** Stable id, pushed even when the status is `unavailable` (§P3.1's rule). */
export const REJECTION_CHECK_ID = 'rejection-liveness';

/**
 * How far before the crash a liveness refusal may land and still be read as
 * the honest sweep-versus-lock race rather than as a contradiction.
 *
 * Two ticks at crash's 50 ms quantum is 100 ms, which is the order of the only
 * honest source of the gap: the interval between the server stamping
 * `received_at_unix_ms` on arrival and the command reaching the round row's
 * lock, by which point the sweep may already have closed the round. It is a
 * BAND, not a tolerance to be widened — every tick inside it is reported.
 */
export const RACE_BAND_TICKS = 2n;

const REJECTION_CHECK_TITLE = 'Refusals of your commands agree with the round’s own seed';

/**
 * `casino.v1.CommandRejectionReason` values this module names.
 *
 * Raw numbers, because the reader keeps the raw code: a value this build does
 * not know must stay distinguishable from `UNSPECIFIED`, or a future refusal
 * class would silently read as "the server stated nothing".
 */
const REASON_ROUND_CLOSED = 2;
const REASON_INVALID_SIGNATURE = 4;
const REASON_INVALID_SELECTION = 5;
const REASON_STATE_OUT_OF_SYNC = 8;
const REASON_INVALID_PAYLOAD = 9;
const REASON_UNSUPPORTED_GAME = 10;
const REASON_ROUND_MODE_AUTO = 21;

/**
 * The codes that ASSERT the round was not settleable when the command landed
 * — the assertion the crash tick can contradict.
 *
 * Both members are refusals of a settle command on liveness grounds:
 * `ROUND_CLOSED` is the round-was-not-alive gate, `STATE_OUT_OF_SYNC` is the
 * no-in-progress-row path, and a server choosing between them cannot escape
 * the comparison. `ROUND_MODE_AUTO` is NOT here and must not be added: it
 * refuses on mode, not on liveness, and it is correct by design.
 */
const LIVENESS_REASONS: ReadonlySet<number> = new Set([REASON_ROUND_CLOSED, REASON_STATE_OUT_OF_SYNC]);

/**
 * The codes that fault the COMMAND'S OWN BYTES, not the round.
 *
 * Membership is deliberately narrow and has one criterion: the player, holding
 * the frame they signed, can see the fault without trusting the server about
 * any state of its own. A malformed payload, a bad signature, a selection the
 * game does not define, a game the pool does not run — each is a property of
 * the bytes. A refusal on one of those says nothing about liveness and needs
 * no finding either, because it is not the shape a suppression would take: a
 * suppressed cashout is a WELL-FORMED command the server declined to act on.
 *
 * Everything not listed here and not a liveness or mode code is
 * `uninformative` — `DUPLICATE_COMMAND`, `RATE_LIMITED`, `INTERNAL_ERROR`,
 * `SESSION_NOT_ACTIVE`, the pool/tenant lifecycle codes, `UNSPECIFIED`, and
 * every code a future build mints. Each of those is a claim about the
 * SERVER'S state, which the player cannot check, so each gets the finding.
 */
const COMMAND_VALIDITY_REASONS: ReadonlySet<number> = new Set([
    REASON_INVALID_SIGNATURE,
    REASON_INVALID_SELECTION,
    REASON_INVALID_PAYLOAD,
    REASON_UNSUPPORTED_GAME,
]);

/**
 * What a `casino.v1.CommandRejectionReason` ASSERTS, which is the only thing
 * that decides how this verifier may read it.
 *
 * - `liveness`: the round was not in progress when the command landed — the
 *   one assertion the revealed seed can contradict, so it drives the check.
 * - `mode`: `ROUND_MODE_AUTO`, correct by design; silent, no check, no finding.
 * - `command-validity`: the player's own bytes are at fault; silent.
 * - `uninformative`: asserts nothing the player can check, so it produces a
 *   labelled finding and never a fail.
 */
export type RefusalClass = 'liveness' | 'mode' | 'command-validity' | 'uninformative';

/**
 * The single classification, exported because `verify/projection.ts`'s
 * suppression rule asks the same question of the same frames — "what did this
 * refusal actually claim?" — and a second copy is a second place for the
 * vocabulary to drift out of step with `casino/v1/enums.proto`.
 */
export function classifyRefusalReason(code: number): RefusalClass {
    if (LIVENESS_REASONS.has(code)) {
        return 'liveness';
    }

    if (code === REASON_ROUND_MODE_AUTO) {
        return 'mode';
    }

    if (COMMAND_VALIDITY_REASONS.has(code)) {
        return 'command-validity';
    }

    return 'uninformative';
}

const REASON_NAMES: Record<number, string> = {
    0: 'UNSPECIFIED',
    1: 'INSUFFICIENT_BALANCE',
    2: 'ROUND_CLOSED',
    3: 'DUPLICATE_COMMAND',
    4: 'INVALID_SIGNATURE',
    5: 'INVALID_SELECTION',
    6: 'TABLE_NOT_FOUND',
    7: 'RATE_LIMITED',
    8: 'STATE_OUT_OF_SYNC',
    9: 'INVALID_PAYLOAD',
    10: 'UNSUPPORTED_GAME',
    11: 'INTERNAL_ERROR',
    12: 'REPLAY_EXPIRED',
    13: 'SESSION_NOT_ACTIVE',
    14: 'POOL_PAUSED',
    15: 'POOL_DRAINING',
    16: 'POOL_DEPRECATED',
    17: 'TENANT_PAUSED',
    18: 'TENANT_DEPRECATED',
    19: 'MAX_WIN_EXCEEDED',
    20: 'STAKE_BELOW_MINIMUM',
    21: 'ROUND_MODE_AUTO',
};

/** Exported for the same reason `classifyRefusalReason` is: one vocabulary. */
export function reasonName(code: number): string {
    return REASON_NAMES[code] ?? `code ${code} (unknown to this build)`;
}

/**
 * One transcript action, reduced to what this module reads off it.
 *
 * Structurally the head of `verify/projection.ts`'s `ProjectionAction`, and
 * declared here rather than imported so the two modules keep their one-way
 * dependency: the projection reads this module's classification and trust
 * rule, never the other way round.
 */
export interface TranscriptActionSummary {
    /** The action's position in the transcript, which IS its index. */
    index: number;
    /** Kebab-case action type, or null for a tag this build does not know. */
    actionType: string | null;
}

export interface RejectionInput {
    /** The round under verification, hyphenated. */
    roundIdHex: string;
    /**
     * The game type the ON-CHAIN transcript states, or null when no transcript
     * was found. Taken from the chain rather than from the export: the tick
     * model has to be the one the kernel replayed.
     */
    gameType: string | null;
    /** The transcript's revealed seeds, hex; null with no transcript. */
    serverSeedHex: string | null;
    clientSeedHex: string | null;
    /**
     * The transcript's actions in index order — read ONLY to learn how the
     * round settled, which decides whether a liveness refusal is eligible to
     * fail at all. Empty with no transcript on chain.
     *
     * From the chain, never from the export: how the round ended is the
     * question, so a settling action the player supplied would let the answer
     * be chosen by whoever is asking.
     */
    actions: readonly TranscriptActionSummary[];
    /** Every decoded frame the export carries. */
    frames: ReceiptFrame[];
    /** Every command the export carries, for the trust rule's body lookup. */
    commands: ImportedCommand[];
}

export interface RejectionReport {
    /** Zero checks when no refusal concerns this round, one otherwise. */
    checks: Check[];
    findings: string[];
}

/** One refusal's outcome, before they are folded into a single check. */
type Verdict =
    | { kind: 'fail'; line: string }
    | { kind: 'unavailable'; line: string }
    | { kind: 'pass'; line: string }
    /** Correct by design, or silent about liveness: nothing to report. */
    | { kind: 'silent' };

const STAMP_CAVEAT =
    'NOTE on received_at_unix_ms: the server stamps it when the bytes ARRIVE, before it verifies the ' +
    'session-key signature — so it attests arrival time, not that the command was well-formed at that instant.';

export function analyseRejections(input: RejectionInput): RejectionReport {
    const rejections = input.frames.filter(
        (frame) =>
            frame.envelope.payloadCase === 'commandRejected' &&
            frame.envelope.roundId === input.roundIdHex,
    );

    if (rejections.length === 0) {
        // No refusal names this round, so there is nothing to check and no
        // check to push. Absence is NOT evidence: a peer tab with receipts off
        // or a degraded IndexedDB contributes to no store, and a client older
        // than the round-scoped rejection frame stored refusals with no round
        // id at all.
        return { checks: [], findings: [] };
    }

    const anchor = crashAnchor(input);
    const settled = settlement(input.actions);
    const findings: string[] = [];
    const verdicts = rejections.map((rejection) => judge(rejection, input, anchor, settled, findings));
    const lines = verdicts.flatMap((verdict) => (verdict.kind === 'silent' ? [] : [verdict.line]));

    if (lines.length === 0) {
        return { checks: [], findings };
    }

    const status = verdicts.some((verdict) => verdict.kind === 'fail')
        ? 'fail'
        : verdicts.some((verdict) => verdict.kind === 'unavailable')
          ? 'unavailable'
          : 'pass';

    return {
        checks: [
            {
                id: REJECTION_CHECK_ID,
                title: REJECTION_CHECK_TITLE,
                status,
                detail: `${lines.join(' — ')} ${STAMP_CAVEAT}`,
            },
        ],
        findings,
    };
}

/** The signed anchor a receipt stamp is converted against, or why there is none. */
type Anchor =
    | { status: 'ok'; tickQuantumMs: bigint; serverAnchorUnixMs: bigint; crashTick: bigint }
    | { status: 'unavailable'; reason: string };

function crashAnchor(input: RejectionInput): Anchor {
    if (input.gameType === null) {
        return {
            status: 'unavailable',
            reason: 'no RoundTranscript for this round was found on chain, so neither the game type nor the revealed seed is available',
        };
    }

    if (input.gameType !== crash.GAME_TYPE) {
        // Not a gap in the evidence — a gap in the MODEL. Only crash maps a
        // wall-clock instant onto an adjudicable position in the round; a HiLo
        // round has no notion of being alive at a millisecond.
        return {
            status: 'unavailable',
            reason: `${input.gameType} has no tick model — a wall-clock instant maps to no position in one of its rounds, so a refusal's timing cannot be checked against the seed`,
        };
    }

    if (input.serverSeedHex === null || input.clientSeedHex === null) {
        return { status: 'unavailable', reason: 'the transcript revealed no seed pair to derive the crash tick from' };
    }

    const started = input.frames.find(
        (frame) =>
            frame.envelope.payloadCase === 'roundStarted' &&
            frame.envelope.roundId === input.roundIdHex &&
            frame.envelope.crashState !== null,
    );

    if (!started || started.envelope.crashState === null) {
        return {
            status: 'unavailable',
            reason: "your receipts carry no signed RoundStarted with a crash.v1.State, so the round's wall-clock anchor is unknown — and an anchor supplied any other way would be a number nobody signed",
        };
    }

    const { tickQuantumMs, serverAnchorUnixMs } = started.envelope.crashState;

    if (tickQuantumMs === null || serverAnchorUnixMs === null || tickQuantumMs <= 0n) {
        return {
            status: 'unavailable',
            reason: `the signed RoundStarted states tick_quantum_ms=${tickQuantumMs ?? 'absent'} and server_anchor_unix_ms=${serverAnchorUnixMs ?? 'absent'}, which is not a usable clock`,
        };
    }

    let crashTick: bigint;

    try {
        crashTick = crash.crashRound(input.serverSeedHex, input.clientSeedHex).crashTick;
    } catch (error) {
        return {
            status: 'unavailable',
            reason: `the crash tick could not be derived from the revealed seed: ${error instanceof Error ? error.message : String(error)}`,
        };
    }

    return { status: 'ok', tickQuantumMs, serverAnchorUnixMs, crashTick };
}

/**
 * How the round ENDED, which is what decides whether a liveness refusal can be
 * contradicted at all.
 *
 * The settling action is the last one in the transcript, by index — not by
 * position in the array, because nothing here has re-sorted it.
 */
type Settlement =
    /** The deadline sweep's terminal loss: the shape a dropped cashout produces. */
    | { kind: 'expire'; index: number }
    /** A claim — manual cashout or auto target. The round ended before the crash. */
    | { kind: 'claim'; index: number }
    /** Settled some other way this check has no reading for. */
    | { kind: 'other'; index: number; actionType: string }
    /** No transcript, or a settling tag this build does not know. */
    | { kind: 'unknown' };

function settlement(actions: readonly TranscriptActionSummary[]): Settlement {
    let last: TranscriptActionSummary | null = null;

    for (const action of actions) {
        if (last === null || action.index > last.index) {
            last = action;
        }
    }

    if (last === null || last.actionType === null) {
        return { kind: 'unknown' };
    }

    if (last.actionType === 'expire') {
        return { kind: 'expire', index: last.index };
    }

    if (last.actionType === 'cashout') {
        return { kind: 'claim', index: last.index };
    }

    return { kind: 'other', index: last.index, actionType: last.actionType };
}

function judge(
    rejection: ReceiptFrame,
    input: RejectionInput,
    anchor: Anchor,
    settled: Settlement,
    findings: string[],
): Verdict {
    const requestId = rejection.envelope.relatedRequestId;
    const code = rejection.envelope.rejectionReasonCode ?? 0;
    const label = `the ${reasonName(code)} refusal of ${requestId ?? 'an unnamed request'}`;

    // TRUST FIRST, reason second. Reversing the two would let a server escape
    // by answering with a code this module stays silent about, on a round id
    // nobody ever corroborated.
    const trust = trustRejectionRoundId(rejection, input.roundIdHex, input.commands);

    if (!trust.trusted) {
        return {
            kind: 'unavailable',
            line: `${label} names round ${input.roundIdHex}, but that id could not be corroborated against the command YOU signed: ${trust.reason}. A server-chosen round id is not evidence about a round, so nothing is concluded from it`,
        };
    }

    const refusalClass = classifyRefusalReason(code);

    if (refusalClass === 'mode') {
        // Correct by design: the round's cashout target was pre-committed in
        // the bet, so a manual cashout against it is refused by the rules of
        // the game and not by any claim about when it arrived.
        return { kind: 'silent' };
    }

    if (refusalClass === 'command-validity') {
        // The fault is in the bytes the player signed, which the player can
        // see for themselves. Nothing about the round is being asserted and
        // nothing is being hidden.
        return { kind: 'silent' };
    }

    if (refusalClass === 'uninformative') {
        // The residual: an answer that states nothing checkable. Never a fail
        // — every such code has an honest reading — but it must not pass in
        // silence either, because the suppression rule counts it as the
        // server having answered.
        findings.push(uninformativeRefusalFinding(label, code));

        return { kind: 'silent' };
    }

    // HOW THE ROUND ENDED comes before the clock. A liveness refusal on a
    // round that had already settled by a claim is the correct answer, and
    // running the tick comparison on it would accuse a server of contradicting
    // a seed the round never reached.
    if (settled.kind === 'claim') {
        return {
            kind: 'pass',
            line:
                `${label} asserts the round was no longer in progress, and the transcript ON CHAIN agrees: the round's ` +
                `last action is the cashout at index ${settled.index}, so it had ALREADY SETTLED on a claim — a manual ` +
                'cashout or a pre-committed auto target — and every later command against it is correctly refused. The ' +
                `crash tick has nothing to contradict here, because the round stopped before it.${claimCorroboration(input)}`,
        };
    }

    if (settled.kind === 'other') {
        return {
            kind: 'unavailable',
            line:
                `${label} asserts the round was no longer in progress, and the transcript's last action is ` +
                `"${settled.actionType}" at index ${settled.index} — neither the deadline sweep's expire (the shape a ` +
                'dropped cashout produces) nor a claim, so this check has no reading of when the round stopped and ' +
                'concludes nothing',
        };
    }

    if (settled.kind === 'unknown') {
        return {
            kind: 'unavailable',
            line: `${label} asserts the round was no longer in progress, but the transcript carries no settling action this build can name, so there is nothing to say how the round ended`,
        };
    }

    if (anchor.status !== 'ok') {
        return { kind: 'unavailable', line: `${label} asserts the round was no longer in progress, but ${anchor.reason}` };
    }

    const receivedAt = rejection.envelope.receivedAtUnixMs;

    if (receivedAt === null) {
        return {
            kind: 'unavailable',
            line: `${label} states no received_at_unix_ms — a producer predating the field — so there is no instant to convert into a tick`,
        };
    }

    const offset = receivedAt - anchor.serverAnchorUnixMs;

    if (offset < 0n) {
        // Reported rather than failed. A stamp before the round's own signed
        // anchor means the two numbers do not describe one timeline, and
        // accusing a server of contradicting a seed on the strength of a
        // clock nobody can reconcile would be the wrong conclusion drawn
        // loudly.
        return {
            kind: 'unavailable',
            line: `${label} is stamped ${-offset} ms BEFORE the round's own signed anchor (${anchor.serverAnchorUnixMs}), so the two signed numbers do not describe one timeline and no tick can be derived`,
        };
    }

    const receivedTick = offset / anchor.tickQuantumMs;
    const shown =
        `received_at_unix_ms ${receivedAt} − anchor ${anchor.serverAnchorUnixMs} = ${offset} ms, ` +
        `÷ ${anchor.tickQuantumMs} ms/tick ⇒ tick ${receivedTick}; the revealed seed crashes the round at tick ${anchor.crashTick}`;

    const earlyBy = anchor.crashTick - receivedTick;

    if (earlyBy > RACE_BAND_TICKS) {
        return {
            kind: 'fail',
            line:
                `${label} is CONTRADICTED by the round's own seed: ${shown}, i.e. ${earlyBy} tick(s) BEFORE the crash, ` +
                `past the ${RACE_BAND_TICKS}-tick race band. The server refused the command as arriving at a round that ` +
                'was no longer in progress, at an instant its own published randomness says the round was still alive, ' +
                'and the round settled on the deadline sweep’s expire',
        };
    }

    if (earlyBy > 0n) {
        findings.push(raceBandFinding(label, earlyBy, anchor));

        return {
            kind: 'pass',
            line:
                `${label} is stamped ${earlyBy} tick(s) BEFORE the crash (${shown}), which is inside the ` +
                `${RACE_BAND_TICKS}-tick race band between the stamp and the round row's lock. Reported as a finding, ` +
                'not failed: an honest server losing that race produces exactly this, and a server suppressing a ' +
                'cashout inside the band is indistinguishable from it on one round',
        };
    }

    findings.push(marginFinding(label, receivedTick, anchor, input));

    return {
        kind: 'pass',
        line: `${label} is consistent with the round's own seed: ${shown}, i.e. ${receivedTick - anchor.crashTick} tick(s) at or past the crash`,
    };
}

/**
 * The settling claim's own acknowledgement, cited when the export carries it.
 *
 * Corroboration and nothing more: the transcript already proves the round
 * settled on a cashout, and this only shows the player their own signed
 * command behind it. Scoped by the round id the PLAYER signed — the same
 * attribution-by-signature rule the trust rule uses — so a server-chosen label
 * cannot put a stranger's command here.
 */
function claimCorroboration(input: RejectionInput): string {
    const stamps: string[] = [];

    for (const frame of input.frames) {
        if (frame.envelope.payloadCase !== 'commandAccepted') {
            continue;
        }

        const requestId = frame.envelope.relatedRequestId;

        if (requestId === null || !signedCashOutForRound(input, requestId)) {
            continue;
        }

        stamps.push(
            frame.envelope.receivedAtUnixMs === null
                ? `${requestId} (the acknowledgement states no received_at_unix_ms)`
                : `${requestId} at received_at_unix_ms ${frame.envelope.receivedAtUnixMs}`,
        );
    }

    if (stamps.length === 0) {
        return ' Your receipts carry no acknowledgement of a cashout of yours for this round, so the claim behind the settle is not corroborated here — which changes nothing, since the transcript is what states the settle.';
    }

    return ` Corroborated by your own signed CashOut acknowledgement(s) for this round: ${stamps.join('; ')}.`;
}

/** True when the export holds a command for `requestId` the player signed as a CashOut naming this round. */
function signedCashOutForRound(input: RejectionInput, requestId: string): boolean {
    const command = input.commands.find((candidate) => candidate.requestId === requestId);

    if (!command) {
        return false;
    }

    try {
        const split = splitSignedFrame(command.frame);

        if (split.tag !== CLIENT_FRAME_TAG) {
            return false;
        }

        const decoded = decodeClientEnvelope(split.body);

        return (
            decoded.requestId === requestId &&
            decoded.payloadCase === 'cashOut' &&
            decoded.commandRoundId === input.roundIdHex
        );
    } catch {
        return false;
    }
}

/**
 * The band finding: always raised, because the band is the residual.
 *
 * A server that suppresses only the cashouts stamped inside it earns a pass on
 * every single round and a finding on every single round. One round says
 * nothing; a player whose refusals sit in the band far more often than latency
 * would put them there is looking at the shape this text exists to make
 * visible.
 */
function raceBandFinding(label: string, earlyBy: bigint, anchor: Extract<Anchor, { status: 'ok' }>): string {
    return (
        `${label} landed ${earlyBy} tick(s) BEFORE the crash tick ${anchor.crashTick}, inside the ${RACE_BAND_TICKS}-tick ` +
        `race band (${RACE_BAND_TICKS * anchor.tickQuantumMs} ms at this round's quantum). An honest server can produce ` +
        'this: the stamp is taken on arrival and the sweep can close the round before the command reaches its lock. So ' +
        'it is never failed — but the band is the one place a suppressed cashout can hide behind an honest explanation, ' +
        'which is why every tick inside it is reported rather than passed in silence. Across many rounds, refusals ' +
        'clustering in the band are the shape latency alone does not make.'
    );
}

/**
 * The one finding text for a refusal that asserts nothing checkable.
 *
 * Exported so `verify/projection.ts` names the same residual in the same
 * words; the finding itself is pushed HERE and only here, because this
 * module sees every refusal naming the round and the suppression rule sees a
 * subset of them.
 */
export function uninformativeRefusalFinding(label: string, code: number): string {
    return (
        `${label} states a reason that asserts nothing about whether the round was alive when the command landed, so ` +
        "the round's own published randomness has nothing to contradict and no check runs. This is reported, never " +
        'failed — every such code has an honest reading — but it matters because the suppression rule counts ANY signed ' +
        `refusal naming the round as the server having ANSWERED: a timely cashout refused with ${reasonName(code)} is ` +
        'indistinguishable from a suppressed one.'
    );
}

/**
 * The margin, read against the export's own accepted-command stamps.
 *
 * A single round proves nothing either way — the finding exists so a player
 * comparing many rounds can see a shape. Exact equality is the tell worth
 * naming: a refusal landing on precisely the crash tick, repeatedly, is what a
 * server timing its refusals to the seed would produce, and it is the one
 * margin an honest queue has no particular reason to hit.
 */
function marginFinding(
    label: string,
    receivedTick: bigint,
    anchor: Extract<Anchor, { status: 'ok' }>,
    input: RejectionInput,
): string {
    const margin = receivedTick - anchor.crashTick;
    const head =
        margin === 0n
            ? `${label} landed on EXACTLY the crash tick (${anchor.crashTick}). One round proves nothing; a refusal that repeatedly lands on precisely the crash tick is the statistical tell that the refusals are being timed to the seed rather than to the queue.`
            : `${label} landed ${margin} tick(s) after the crash tick ${anchor.crashTick}. One round proves nothing; the number is here so it can be compared across many.`;

    return `${head} ${nullDistribution(anchor, input)}`;
}

function nullDistribution(anchor: Extract<Anchor, { status: 'ok' }>, input: RejectionInput): string {
    const sent = new Set(input.commands.map((command) => command.requestId));
    const samples: bigint[] = [];
    let orphans = 0;
    let unstamped = 0;

    for (const frame of input.frames) {
        if (frame.envelope.payloadCase !== 'commandAccepted') {
            continue;
        }

        if (frame.envelope.receivedAtUnixMs === null) {
            unstamped += 1;
            continue;
        }

        if (frame.envelope.relatedRequestId === null || !sent.has(frame.envelope.relatedRequestId)) {
            // `CommandAccepted` is a DURABLE client_outbox row, so the
            // dispatcher broadcasts it to every connection of the session: a
            // tab holds acknowledgements for commands a PEER tab sent. Those
            // are somebody else's latency, not this player's.
            orphans += 1;
            continue;
        }

        samples.push(frame.envelope.receivedAtUnixMs);
    }

    if (orphans > 0 || samples.length === 0) {
        const why =
            orphans > 0
                ? `${orphans} acknowledgement(s) in this export name commands it does not carry — a peer tab of the same session sent them, so their timings are not yours`
                : unstamped > 0
                  ? `every acknowledgement in this export predates received_at_unix_ms (${unstamped} of them)`
                  : 'this export carries no acknowledgement to compare against';

        return `Read as a LABEL, not a statistic: ${why}, so there is no comparable null distribution here.`;
    }

    const ticks = samples
        .map((sample) => (sample - anchor.serverAnchorUnixMs) / anchor.tickQuantumMs)
        .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

    return (
        `Null distribution, from the ${samples.length} command(s) of this export the server ACCEPTED under the same stamp: ` +
        `their receipt instants map to tick(s) ${ticks.join(', ')}.`
    );
}

export type Trust = { trusted: true } | { trusted: false; reason: string };

/**
 * The trust rule: a refusal's round id counts only when the player signed the
 * same id into the command it refuses.
 *
 * Exported because the suppression rule (`verify/projection.ts`) asks the same
 * question of the same frames — "may I believe this refusal is about this
 * round?" — and a second copy of the rule is a second place for it to weaken.
 * It takes the pieces rather than a `RejectionInput` so the other caller does
 * not have to fabricate the seed/game fields it has no use for.
 */
export function trustRejectionRoundId(
    rejection: ReceiptFrame,
    roundIdHex: string,
    commands: ImportedCommand[],
): Trust {
    const requestId = rejection.envelope.relatedRequestId;

    if (requestId === null) {
        return { trusted: false, reason: 'the refusal names no related_request_id, so there is no command of yours to compare it with' };
    }

    const command = commands.find((candidate) => candidate.requestId === requestId);

    if (!command) {
        return {
            trusted: false,
            reason: `this export carries no command for request ${requestId} (a peer tab may have sent it, or receipts may have been off in the tab that did)`,
        };
    }

    let decoded;

    try {
        const split = splitSignedFrame(command.frame);

        if (split.tag !== CLIENT_FRAME_TAG) {
            return {
                trusted: false,
                reason: `the stored command for ${requestId} carries tag 0x${split.tag.toString(16).padStart(2, '0')}, not a command frame (0x05)`,
            };
        }

        decoded = decodeClientEnvelope(split.body);
    } catch (error) {
        return {
            trusted: false,
            reason: `the command for ${requestId} could not be decoded: ${error instanceof Error ? error.message : String(error)}`,
        };
    }

    if (decoded.requestId !== requestId) {
        // The export LABELLED it as this request; its own signed body says
        // otherwise, so the label is the only thing tying the two together.
        return {
            trusted: false,
            reason: `the command labelled ${requestId} carries request id ${decoded.requestId ?? '(none)'} in the bytes you signed`,
        };
    }

    if (decoded.commandRoundId === null) {
        return {
            trusted: false,
            reason: `the ${decoded.payloadCase ?? 'unrecognised'} command for ${requestId} carries no round_id of its own, so the server's id stands alone`,
        };
    }

    if (decoded.commandRoundId !== roundIdHex) {
        return {
            trusted: false,
            reason: `you signed round ${decoded.commandRoundId} into that command, but the refusal names ${roundIdHex}`,
        };
    }

    return { trusted: true };
}
