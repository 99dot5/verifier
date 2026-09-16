/**
 * THE FOURTH PROOF — what the player AUTHORISED versus what the sequencer WROTE.
 *
 * The commitment proofs tie the on-chain round to *which* commands the player
 * signed: the digest is over whole frames, so a server that swapped, dropped
 * or invented one cannot reproduce it. What they cannot see is what those
 * commands SAID. A server that faithfully commits to a `reveal{3}` and then
 * writes `reveal{7}` into the transcript still matches every commitment in the
 * report, because the preimage is the command bytes and the transcript is a
 * different encoding of a different thing.
 *
 * This module closes that gap. For each action the transcript carries, it asks
 * what the player's own signed command at that index projects to — the action
 * tag, and the Borsh payload `GameAdapter::encode_action_borsh` would have
 * written — and compares. The rules are a table, deliberately: one row per
 * `(payload case, game arm)`, and `projection.test.ts` enumerates every arm in
 * the three command messages and asserts the table has a rule for each, so a
 * new arm is a failing test rather than a silently unchecked command.
 *
 * ## Three asymmetries worth stating plainly
 *
 * 1. **The arm → tag map is many-to-one, on purpose.** `hydra.v1.PlayerAction`
 *    has FIVE arms and the sequencer maps both `fight` and `physical_attack`
 *    onto `Action::PhysicalAttack`. So the rule is "the arm the player signed
 *    belongs to the SET of arms that project to this tag", never a bijection —
 *    a 1:1 table would false-`fail` every hydra round played with `fight`.
 *    The residual is real and belongs in the report: because that set has more
 *    than one member, a server can swap one for the other undetectably. It is
 *    benign today (identical engine action, identical payout) and it is
 *    exactly the class of unprovable input this proof exists to shrink, so it
 *    is named rather than left unsaid.
 *
 * 2. **`RoundEndedEvent.cause` is a SERVER ASSERTION.** It is used in one
 *    direction only: a contradiction between what it claims and what the
 *    player's commands show is a `fail`; agreement with an ABSENT command is
 *    merely the absence of a contradiction, and every line here says so. A
 *    frame that states no cause at all contradicts nothing.
 *
 * 3. **Crash mode provenance is ordered.** Auto-versus-manual is read from the
 *    player-signed `PlaceBet` arm; `actions[0]`'s `borsh(Config)` is on chain
 *    but SERVER-AUTHORED, so it is corroboration and a disagreement is the
 *    place-bet row's own `fail`. When the place-bet is not bound to a command,
 *    every crash-specific rule is `unavailable` — never a fall-through to the
 *    server's own reading, because a server laundering a suppressed manual
 *    cashout as an auto settlement is precisely what that fall-through would
 *    wave through.
 *
 * ## The suppression rule
 *
 * The phase's central proof, and the one that does not fit the per-index shape
 * above. A server suppressing a cashout does not write a WRONG action — it
 * writes none at all: it drops the command and lets the deadline sweep settle
 * the round, which for a manual crash round is an `expire`, an action every
 * "legal with no bound command" rule whitelists as unremarkable. So the rule
 * runs over the COMMANDS instead of over the actions:
 *
 *   For every `CashOut` command in the export whose own signed body names the
 *   round under verification, look for EITHER a `cashout` action at the index
 *   the reconstruction binds it to, OR a signed `CommandRejected` naming the
 *   round and trusted under `rejections.ts`'s rule. Neither, with the round
 *   settled on `expire`, is the suppressed-cashout SHAPE.
 *
 * Any trusted refusal counts as an answer, deliberately — the alternative is
 * this rule second-guessing a reason code, which is the server's to choose.
 * The residual that leaves is named rather than closed: a refusal whose code
 * asserts nothing about liveness (`rejections.ts`'s `uninformative` class) is
 * an answer and nothing more, so the row says so and `rejections.ts` raises
 * the finding. It is never a `fail`, because every such code has an honest
 * reading.
 *
 * ## Why the unanswered case is a FINDING and not a `fail`
 *
 * It is the shape a suppressed cashout makes, and it is not proof that one
 * happened, because **silence cannot prove delivery**. A command that never
 * reached the server and a command the server dropped on purpose leave the
 * identical document behind:
 *
 *   - `CommandRejected` is ephemeral. It is never written to `client_outbox`
 *     and so is never replayed on reconnect, which means its absence is as
 *     consistent with a lost reply as with no reply.
 *   - A retry under a FRESH request id is a different command; it orphans the
 *     first attempt rather than answering it.
 *   - Nothing the client knows about its own sending is signed.
 *
 * So the rule lays the player's evidence out instead of concluding from it:
 * how many times the bytes went out under that request id (`sendCount`, absent
 * meaning one), the client's own send label, and whether later commands of the
 * same session were answered — which is what separates "the connection was
 * dead" from "this one command vanished". A reader weighs those; the verifier
 * does not weigh them for them, because a `fail` here accuses a named server
 * of theft on evidence that a dropped packet reproduces exactly.
 *
 * The client's re-send of an unanswered command under the SAME request id is
 * what makes the finding sharpen over time rather than stay a shrug: identical
 * bytes, so the commitment is unchanged, and a count above one is the player's
 * own account of having tried more than once.
 *
 * The rule the suppression rule replaced survives, demoted to the case it
 * actually detects: a `cashout` with no bound command on a round the player
 * opened in MANUAL mode is an auto-mislabel finding.
 */
import type { ImportedCommand } from '../receipts/import';
import type { ReceiptFrame } from '../receipts/recompute';
import type { Check } from '../verifier';
import { decodeClientEnvelope, type DecodedCommandBody, type RoundEndCause } from '../wire/proto-reader';
import { CLIENT_FRAME_TAG, splitSignedFrame } from '../wire/signature';
import { classifyRefusalReason, reasonName, trustRejectionRoundId } from './rejections';
import * as crash from './crash';
import { bytesEqual, bytesToHex } from './seed';

/**
 * Stable id, pushed on EVERY status including `unavailable`.
 *
 * Without it `checks.find(...)` returns `undefined` and "did not run" is
 * indistinguishable from "ran and did not pass" — the verdict is the same
 * either way, the report text is not.
 */
export const PROJECTION_CHECK_ID = 'action-projection';

/**
 * The check's one title, exported because `verifier.ts` pushes a placeholder
 * row under the same id when there are no receipts to run the proof on — two
 * literals would let the same check present itself two ways.
 */
export const PROJECTION_CHECK_TITLE = 'Transcript actions project from the commands you signed';

/** The five shipped games, by the `game_type` the transcript states. */
const GAME_KEYS: Record<string, CommandGame> = {
    'hilo:v1': 'hilo',
    'crash:v1': 'crash',
    'plinko:v1': 'plinko',
    'mines:v1': 'mines',
    'hydra:v1': 'hydra',
};

export type CommandGame = 'hilo' | 'crash' | 'plinko' | 'mines' | 'hydra';

/**
 * Actions legal at an index NO command of the player's is bound to.
 *
 * All three are written by the sequencer and no player command can produce
 * one: the max-win de-lever's `partial-cashout`, the janitor force-settle's
 * `abandon`, and crash's `expire` from the deadline sweep. A settling
 * `cashout` is the fourth case and is NOT here — it needs the cause, so it is
 * handled explicitly.
 */
const SYSTEM_ONLY_ACTIONS: ReadonlySet<string> = new Set(['partial-cashout', 'abandon', 'expire']);

/** One transcript action, as the wire decoder produced it. */
export interface ProjectionAction {
    /** The action's position in the transcript, which IS its index. */
    index: number;
    /** Kebab-case action type, or null for a tag this build does not know. */
    actionType: string | null;
    /** The raw Borsh payload the transcript carries. */
    payload: Uint8Array;
}

/** One command the reconstruction placed at an index. */
export interface ProjectionBinding {
    requestId: string;
    index: number;
}

export interface ProjectionInput {
    /** The round under verification, hyphenated. */
    roundIdHex: string;
    /** The game the ON-CHAIN transcript states. */
    gameType: string;
    actions: ProjectionAction[];
    /**
     * The reconstruction's index binding, or null when it declined.
     *
     * Null is the whole check's `unavailable`: without the server's own signed
     * indices there is no way to say WHICH action a command projects to, and
     * inferring one from the command body is the D9 inference the archive
     * exists to have removed.
     */
    binding: ProjectionBinding[] | null;
    /** Why there is no binding, echoed into the check's detail. */
    bindingReason: string | null;
    commands: ImportedCommand[];
    frames: ReceiptFrame[];
    /** `RoundEnded.cause` off the SIGNED frame; null when it states none. */
    endCause: RoundEndCause | null;
}

export interface ProjectionReport {
    /** Exactly one check, always, with a stable id. */
    checks: Check[];
    findings: string[];
}

type Row = { kind: 'pass' | 'fail' | 'unavailable'; line: string };

/** What a command projects to: the admissible tags and the expected payload. */
export type Expectation =
    | { ok: true; actionTypes: readonly string[]; payload: Uint8Array; how: string }
    | { ok: false; reason: string };

export function analyseProjection(input: ProjectionInput): ProjectionReport {
    const findings: string[] = [];
    const game = GAME_KEYS[input.gameType];

    if (!game) {
        return report(
            'unavailable',
            `the transcript states game ${input.gameType}, which this build has no projection table for — a round of a game newer than this verifier cannot be checked against the commands you signed, and guessing at its vocabulary would be worse than saying so`,
            findings,
        );
    }

    if (input.binding === null) {
        return report(
            'unavailable',
            `no command of yours could be tied to a transcript action: ${input.bindingReason ?? 'the reconstruction of your commands is unavailable'}. The index a command sits at comes only from the server's own signed frames — deriving it from the command body is the inference the archive exists to have removed — so without the reconstruction there is nothing here to compare.`,
            findings,
        );
    }

    const boundByIndex = new Map<number, ProjectionBinding>();
    const indexByRequest = new Map<string, number>();

    for (const entry of input.binding) {
        boundByIndex.set(entry.index, entry);
        indexByRequest.set(entry.requestId, entry.index);
    }

    const rows: Row[] = [];
    const mode = crashMode(game, boundByIndex.get(0), input);

    for (const action of input.actions) {
        const bound = boundByIndex.get(action.index);

        rows.push(
            bound
                ? projectBound(action, bound, game, input, findings)
                : projectUnbound(action, game, input, mode, findings),
        );
    }

    // A command the server placed BEYOND the transcript it published. The
    // reconstruction cannot catch this on its own: it checks contiguity among
    // the indices the frames state, and never sees the transcript.
    for (const entry of input.binding) {
        if (!input.actions.some((action) => action.index === entry.index)) {
            rows.push({
                kind: 'fail',
                line: `the server's signed frames place your command ${entry.requestId} at action index ${entry.index}, but the transcript it published on chain carries only ${input.actions.length} action(s)`,
            });
        }
    }

    if (mode.status === 'unavailable') {
        rows.push({
            kind: 'unavailable',
            line: `every crash-specific rule is unavailable on this round: ${mode.reason}. The mode is read from the PlaceBet arm you signed, and the transcript's own place-bet config is server-authored corroboration only — falling back to it would let a server launder a suppressed manual cashout as an auto settlement`,
        });
    }

    rows.push(...suppressionRows(input, indexByRequest, game, mode, findings));

    if (rows.length === 0) {
        return report(
            'unavailable',
            'the transcript carries no action to project, which is not a shape a settled round can have',
            findings,
        );
    }

    const status = rows.some((row) => row.kind === 'fail')
        ? 'fail'
        : rows.some((row) => row.kind === 'unavailable')
          ? 'unavailable'
          : 'pass';

    return report(status, rows.map((row) => row.line).join(' — '), findings);
}

function report(status: Check['status'], detail: string, findings: string[]): ProjectionReport {
    return {
        checks: [{ id: PROJECTION_CHECK_ID, title: PROJECTION_CHECK_TITLE, status, detail }],
        findings,
    };
}

// ── crash mode provenance ───────────────────────────────────────────────

type CrashMode =
    | { status: 'ok'; mode: 'manual' | 'auto' }
    /** Not a crash round: the mode question does not arise. */
    | { status: 'not-crash' }
    | { status: 'unavailable'; reason: string };

function crashMode(game: CommandGame, placeBet: ProjectionBinding | undefined, input: ProjectionInput): CrashMode {
    if (game !== 'crash') {
        return { status: 'not-crash' };
    }

    if (!placeBet) {
        return {
            status: 'unavailable',
            reason: 'no command of yours is bound to the round’s place-bet (action index 0), so nothing you signed says whether you opened the round in manual or auto mode',
        };
    }

    const decoded = decodeCommand(input.commands, placeBet.requestId);

    if (!decoded.body) {
        return { status: 'unavailable', reason: `the place-bet command ${placeBet.requestId} could not be read: ${decoded.reason}` };
    }

    const body = decoded.body;

    if (body.case !== 'placeBet' || body.game !== 'crash') {
        return {
            status: 'unavailable',
            reason: `the command bound to action index 0 is ${describe(body)}, not a crash PlaceBet`,
        };
    }

    // Auto IFF the player signed a target. The transcript's `Option<u32>` says
    // the same thing, and the place-bet row below is where the two are
    // compared — a disagreement fails there, not here.
    return { status: 'ok', mode: body.autoCashoutPpm === null ? 'manual' : 'auto' };
}

// ── per-index projection ────────────────────────────────────────────────

function projectBound(
    action: ProjectionAction,
    bound: ProjectionBinding,
    game: CommandGame,
    input: ProjectionInput,
    findings: string[],
): Row {
    const at = `action ${action.index} (${action.actionType ?? 'an unknown tag'}) ← your command ${bound.requestId}`;
    const decoded = decodeCommand(input.commands, bound.requestId);

    if (!decoded.body) {
        return { kind: 'unavailable', line: `${at}: ${decoded.reason}` };
    }

    const body = decoded.body;

    if (body.case === 'unrecognised') {
        // The honest answer to a command from a build newer than this one.
        return {
            kind: 'unavailable',
            line: `${at}: ${body.description}, so this build has no rule for what it should project to`,
        };
    }

    if (action.actionType === null) {
        return {
            kind: 'unavailable',
            line: `${at}: the transcript carries an action tag this build does not know, so there is nothing to project onto (the replay proof reports it as reject-unknown-action-tag)`,
        };
    }

    // The TRANSCRIPT-CAP substitution, checked before the tag: under the cap
    // the sequencer replaces the player's action in place, so the tag is
    // EXPECTED to differ from what they signed. Reported, never failed — the
    // outcome and payout are real and the player simply did not ask for the
    // cashout.
    if (action.actionType === 'cashout' && input.endCause === 'transcript-cap') {
        findings.push(
            `action ${action.index} is a cashout the sequencer SUBSTITUTED for your command ${bound.requestId}: the signed RoundEnded states cause = TRANSCRIPT_CAP, i.e. the round reached MAX_TRANSCRIPT_ACTIONS and was settled at its current value. The payout is real; you did not request the cashout, and the projection of your command is deliberately not compared against it.`,
        );

        return {
            kind: 'pass',
            line: `${at}: not compared — the server states cause = TRANSCRIPT_CAP, which substitutes a cashout for the action you sent (reported as a finding)`,
        };
    }

    if (body.game !== game) {
        return {
            kind: 'fail',
            line: `${at}: you signed ${describe(body)}, but the round on chain is ${input.gameType} — a command of one game cannot have produced an action of another`,
        };
    }

    if (action.actionType === 'cashout') {
        const contradiction = settlingCauseContradiction(input.endCause, true, bound.requestId, action.index);

        if (contradiction) {
            return { kind: 'fail', line: `${at}: ${contradiction}` };
        }
    }

    const expected = projectionRuleFor(body);

    if (!expected.ok) {
        return { kind: 'unavailable', line: `${at}: ${expected.reason}` };
    }

    if (!expected.actionTypes.includes(action.actionType)) {
        const set =
            expected.actionTypes.length === 1
                ? `"${expected.actionTypes[0]}"`
                : `one of ${expected.actionTypes.map((t) => `"${t}"`).join(', ')}`;

        return {
            kind: 'fail',
            line: `${at}: you signed ${describe(body)}, which projects to ${set}, but the transcript carries "${action.actionType}"`,
        };
    }

    if (!bytesEqual(expected.payload, action.payload)) {
        return {
            kind: 'fail',
            line: `${at}: the action type matches but the payload does not — you signed ${describe(body)}, which encodes as ${hexOrEmpty(expected.payload)} (${expected.how}), and the transcript carries ${hexOrEmpty(action.payload)}`,
        };
    }

    return {
        kind: 'pass',
        line: `${at}: ${describe(body)} projects to "${action.actionType}" with payload ${hexOrEmpty(expected.payload)} (${expected.how}), which is what the transcript carries`,
    };
}

function projectUnbound(
    action: ProjectionAction,
    game: CommandGame,
    input: ProjectionInput,
    mode: CrashMode,
    findings: string[],
): Row {
    const at = `action ${action.index} (${action.actionType ?? 'an unknown tag'})`;

    if (action.actionType === null) {
        return {
            kind: 'unavailable',
            line: `${at}: an action tag this build does not know, bound to no command of yours`,
        };
    }

    if (action.actionType === 'place-bet') {
        // Unreachable through an honest reconstruction — it declines with
        // `no-place-bet` unless a `BetPlaced`/`RoundStarted` frame binds a
        // command to index 0 — so this is a gap in the evidence, not a server
        // contradiction, and it must not read as one.
        return {
            kind: 'unavailable',
            line: `${at}: the round's opening bet is bound to no command of yours, so there is nothing signed to project onto it`,
        };
    }

    if (SYSTEM_ONLY_ACTIONS.has(action.actionType)) {
        return {
            kind: 'pass',
            line: `${at}: a system step no player command can produce (the max-win de-lever, the janitor force-settle, or crash's deadline expire), so no command of yours is expected at this index`,
        };
    }

    if (action.actionType === 'cashout') {
        const contradiction = settlingCauseContradiction(input.endCause, false, null, action.index);

        if (contradiction) {
            return { kind: 'fail', line: `${at}: ${contradiction}` };
        }

        // The DEMOTED old rule. It is noisier and weaker than the suppression
        // rule below — it fires on a mislabelled auto settlement, not on a
        // dropped cashout — but it is real, so it goes out as a finding.
        if (game === 'crash' && mode.status === 'ok' && mode.mode === 'manual') {
            findings.push(
                `action ${action.index} is a cashout no command of yours is bound to, on a round your own signed PlaceBet opened in MANUAL mode — a manual round settles on a player cashout or on the deadline's expire, so a sequencer-written cashout here would be an auto settlement of a round you did not pre-commit a target for.`,
            );
        }

        if (input.endCause === null || input.endCause === 'unspecified') {
            findings.push(
                `action ${action.index} is a cashout bound to no command of yours, and the signed RoundEnded states no cause — a producer predating the field. Nothing is concluded from that silence in either direction.`,
            );

            return {
                kind: 'pass',
                line: `${at}: bound to no command of yours and the server states no cause, so there is no contradiction to report — which is not the same as evidence that the settle was legitimate`,
            };
        }

        return {
            kind: 'pass',
            line: `${at}: bound to no command of yours, and the server states cause = SYSTEM_SWEEP, which is consistent. This is the ABSENCE OF A CONTRADICTION, not a proof: the cause is the server's own assertion, and it agrees with an absent command`,
        };
    }

    return {
        kind: 'fail',
        line: `${at}: the transcript carries a player action no command of yours is bound to, and "${action.actionType}" is not one of the system steps a sequencer may write on its own`,
    };
}

/**
 * The one-directional cause rule.
 *
 * Returns the contradiction, or null when there is none — including when the
 * server stated no cause at all, which contradicts nothing.
 */
function settlingCauseContradiction(
    cause: RoundEndCause | null,
    bound: boolean,
    requestId: string | null,
    index: number,
): string | null {
    if (cause === null || cause === 'unspecified') {
        return null;
    }

    if (bound) {
        return cause === 'system-sweep'
            ? `the signed RoundEnded states cause = SYSTEM_SWEEP, i.e. a server-side sweep settled the round, yet the server's own frames bind YOUR command ${requestId} to the settling action at index ${index}. Both are the server's statements and they disagree`
            : null;
    }

    return cause === 'system-sweep'
        ? null
        : `the signed RoundEnded states cause = ${cause === 'player-action' ? 'PLAYER_ACTION' : 'TRANSCRIPT_CAP'}, which asserts a command of yours settled the round, yet no command of yours is bound to the settling action at index ${index}`;
}

// ── the suppression rule ────────────────────────────────────────────────

function suppressionRows(
    input: ProjectionInput,
    indexByRequest: Map<string, number>,
    game: CommandGame,
    mode: CrashMode,
    findings: string[],
): Row[] {
    const rows: Row[] = [];
    const seen = new Set<string>();
    const settledOnExpire = input.actions.some((action) => action.actionType === 'expire');

    for (const command of input.commands) {
        const decoded = decodeCommand(input.commands, command.requestId, command);

        if (!decoded.body || decoded.body.case !== 'cashOut') {
            continue;
        }

        // Scoped by the round id the PLAYER signed, never by the export's
        // label: attribution by signature, the same class of evidence as
        // reading `client_seed` out of a signed PlaceBet.
        if (decoded.roundId !== input.roundIdHex || decoded.requestId !== command.requestId) {
            continue;
        }

        if (seen.has(command.requestId)) {
            // An idempotent retry sends the same command twice.
            continue;
        }

        seen.add(command.requestId);

        const index = indexByRequest.get(command.requestId);
        const answered = index !== undefined && input.actions.some((a) => a.index === index && a.actionType === 'cashout');

        if (answered) {
            continue;
        }

        const refusal = input.frames.find(
            (frame) =>
                frame.envelope.payloadCase === 'commandRejected' &&
                frame.envelope.roundId === input.roundIdHex &&
                frame.envelope.relatedRequestId === command.requestId,
        );

        if (refusal && trustRejectionRoundId(refusal, input.roundIdHex, input.commands).trusted) {
            // A refusal is an answer, and that is all this rule asks of it —
            // but WHICH answer decides how much it is worth. The one
            // classification lives in `rejections.ts`; an `uninformative` code
            // is the residual that module's finding names, and the row says so
            // rather than reading as a clean pass.
            const code = refusal.envelope.rejectionReasonCode ?? 0;
            const qualifier =
                classifyRefusalReason(code) === 'uninformative'
                    ? `, though ${reasonName(code)} asserts nothing about whether the round was alive — an answer and nothing more (see the refusal finding)`
                    : '';

            rows.push({
                kind: 'pass',
                line: `your CashOut ${command.requestId} for this round produced no cashout action, but the server signed a refusal naming the round, and that round id is corroborated by the id you signed into the command yourself — a refusal is an answer${qualifier}`,
            });

            continue;
        }

        const evidence =
            `you signed a CashOut (request ${command.requestId}) naming round ${input.roundIdHex}; the transcript carries no cashout action bound to it and your receipts carry no signed refusal naming the round` +
            (game === 'crash' && mode.status === 'ok' ? ` (the round was opened in ${mode.mode} mode)` : '');

        if (!settledOnExpire) {
            // Not even the suppression SHAPE: without an `expire` the round did
            // not settle as the loss a dropped cashout produces, so the missing
            // action has explanations a report must not choose between.
            findings.push(
                `${evidence}. The round did not settle on an expire, so this is reported rather than concluded — the command may have been sent after the round had already settled by another path.`,
            );

            continue;
        }

        findings.push(`${evidence}, and the round settled on an expire (the deadline sweep's terminal loss). ${deliveryEvidence(input, command)}`);
    }

    return rows;
}

/**
 * What the export can and cannot say about a command the server never answered.
 *
 * This is the whole reason the rule is a FINDING and not a `fail`. Silence is
 * not a signed statement: a command that never reached the server and one the
 * server dropped on purpose produce the identical export, because
 * `CommandRejected` is ephemeral (it is never written to `client_outbox` and
 * so is never replayed on reconnect) and a retry under a FRESH request id
 * orphans the first attempt rather than answering it. The player's own
 * evidence — how many times they sent it, when, and whether the session kept
 * working afterwards — is what a reader needs to weigh the two, so it is laid
 * out rather than summarised into a verdict the bytes do not support.
 */
function deliveryEvidence(input: ProjectionInput, command: ImportedCommand): string {
    const later = input.commands.filter((other) => other.sentAtUnixMs > command.sentAtUnixMs);
    const answered = later.filter((other) =>
        input.frames.some(
            (frame) =>
                frame.envelope.relatedRequestId === other.requestId &&
                (frame.envelope.payloadCase === 'commandAccepted' ||
                    frame.envelope.payloadCase === 'commandRejected'),
        ),
    );
    const sends =
        command.sendCount > 1
            ? `Your client sent those bytes ${command.sendCount} time(s) under the same request id, so a single lost packet does not account for the silence.`
            : 'Your client sent those bytes once (the export states no re-send), so an unlucky transport is a live explanation.';
    const session =
        later.length === 0
            ? 'No command of yours in this export was sent later, so there is nothing to show whether the connection was still working.'
            : `${answered.length} of the ${later.length} command(s) you sent later in this session WERE answered, which speaks to whether the connection was carrying traffic at the time.`;

    return (
        `${sends} The send instants are the client's own labels (sentAtUnixMs ${command.sentAtUnixMs}) and nobody signed them. ${session} ` +
        'REPORTED, NEVER CONCLUDED: silence cannot prove delivery. A command lost in transit and a command the server dropped ' +
        'deliberately leave the same bytes behind, because a refusal is ephemeral and is never replayed, so no verdict is ' +
        'drawn from the absence alone.'
    );
}

// ── the table ───────────────────────────────────────────────────────────

/**
 * The projection table, one arm at a time.
 *
 * The payloads are exactly what `libs/games/src/<game>/v1/adapter.rs`'s
 * `encode_action_borsh` writes, which is what rides in the transcript's
 * `TranscriptAction::payload`. Borsh is little-endian and unprefixed, so a
 * `u32` is four bytes, an `Option` is a `0x00`/`0x01` tag then the value, and a
 * fieldless enum variant is its ordinal byte.
 */
export function projectionRuleFor(body: Exclude<DecodedCommandBody, { case: 'unrecognised' }>): Expectation {
    switch (body.case) {
        case 'placeBet':
            switch (body.game) {
                case 'hilo':
                    return { ok: true, actionTypes: ['place-bet'], payload: EMPTY, how: 'hilo.v1.PlaceBet is an empty message and the hilo place-bet carries no config' };
                case 'crash':
                    return crashPlaceBetExpectation(body.autoCashoutPpm);
                case 'plinko':
                    return plinkoPlaceBetExpectation(body.rows, body.risk);
                case 'mines':
                    return {
                        ok: true,
                        actionTypes: ['place-bet'],
                        payload: u32Le(body.mineCount),
                        how: `borsh(mines::Config { mine_count: ${body.mineCount} })`,
                    };
                case 'hydra':
                    return hydraPlaceBetExpectation(body.hero);
            }

            break;
        case 'playerAction':
            switch (body.game) {
                case 'hilo':
                    return { ok: true, actionTypes: [body.arm], payload: EMPTY, how: `the ${body.arm} arm is an empty message` };
                case 'mines':
                    return body.tileIndex === null
                        ? {
                              ok: false,
                              reason: 'the mines Reveal you signed carries no tile_index — the field is `optional` precisely because tile 0 is legal, so an absent one is a real absence and there is no tile to compare',
                          }
                        : {
                              ok: true,
                              actionTypes: ['reveal'],
                              payload: u32Le(body.tileIndex),
                              how: `borsh(u32 tile_index = ${body.tileIndex})`,
                          };
                case 'hydra':
                    return {
                        ok: true,
                        // SET MEMBERSHIP: `fight` and `physical_attack` are two
                        // arms of one engine action, so both are admissible
                        // against a `physical-attack` tag.
                        actionTypes: [HYDRA_ARM_TAGS[body.arm]],
                        payload: EMPTY,
                        how: `the hydra ${body.arm} arm is an empty message; ${
                            body.arm === 'fight' || body.arm === 'physical-attack'
                                ? 'both `fight` and `physical_attack` project to "physical-attack", so the two are indistinguishable on chain'
                                : 'it is the only arm projecting to this tag'
                        }`,
                    };
            }

            break;
        case 'cashOut':
            if (body.game === 'crash') {
                return body.tick === null
                    ? {
                          ok: false,
                          reason: 'the crash CashOut you signed carries no tick — the field is `optional` precisely because tick 0 is a legal claim, so an absent one is a real absence and there is no tick to compare',
                      }
                    : {
                          ok: true,
                          actionTypes: ['cashout'],
                          payload: u32Le(body.tick),
                          how: `borsh(u32 tick = ${body.tick}), the tick YOU claimed and the sequencer carries through verbatim`,
                      };
            }

            return {
                ok: true,
                actionTypes: ['cashout'],
                payload: EMPTY,
                how: `${body.game}.v1.CashOut is an empty marker — the settle takes the round's current value and the command cannot move it`,
            };
    }

    // Unreachable while the table covers every arm the reader can produce,
    // which `projection.test.ts` enumerates from the .proto files and asserts.
    return { ok: false, reason: 'no projection rule for this command' };
}

/** `hydra.v1.PlayerAction` arms → the transcript tag each projects to. */
const HYDRA_ARM_TAGS: Record<string, string> = {
    fight: 'physical-attack',
    'physical-attack': 'physical-attack',
    'magic-attack': 'magic-attack',
    'drink-potion': 'drink-potion',
    'drink-mana': 'drink-mana',
};

/**
 * The ppm → tick policy, reproduced from
 * `services/sequencer/src/proto_conversions/crash/v1.rs` and bound to it by
 * the SHARED vectors in `libs/games/src/crash/v1/testdata/vectors.json`.
 *
 * It is a POLICY, not curve maths: reject at or below `m(0)` (a target that
 * would collapse to tick 0, a degenerate immediate push), reject above the
 * 1000× house cap (unreachable, a guaranteed loss), else the smallest tick at
 * which the curve reaches the target. Two implementations of a policy is the
 * shape that drifts silently, so neither side owns the numbers.
 */
export function autoCashoutTickFromPpm(ppm: number): { ok: true; tick: bigint } | { ok: false; reason: string } {
    const value = BigInt(ppm);

    if (value <= crash.multiplierPpm(0n)) {
        return { ok: false, reason: `an auto-cashout target of ${ppm} ppm is at or below m(0) = ${crash.multiplierPpm(0n)} ppm, which the sequencer refuses as INVALID_PAYLOAD` };
    }

    if (value > crash.MAX_MULTIPLIER_CAP_PPM) {
        return { ok: false, reason: `an auto-cashout target of ${ppm} ppm is above the ${crash.MAX_MULTIPLIER_CAP_PPM} ppm (1000×) house cap, which the sequencer refuses as INVALID_PAYLOAD` };
    }

    return { ok: true, tick: crash.crashTick(value) };
}

function crashPlaceBetExpectation(ppm: number | null): Expectation {
    if (ppm === null) {
        return {
            ok: true,
            actionTypes: ['place-bet'],
            payload: new Uint8Array([0x00]),
            how: 'borsh(crash::Config { auto_cashout_tick: None }) — you signed no auto_cashout_ppm, which IS manual mode',
        };
    }

    const converted = autoCashoutTickFromPpm(ppm);

    if (!converted.ok) {
        return {
            ok: false,
            reason: `${converted.reason}, so no tick can be derived from the target you signed and the transcript's config cannot be checked against it`,
        };
    }

    return {
        ok: true,
        actionTypes: ['place-bet'],
        payload: new Uint8Array([0x01, ...u32Le(Number(converted.tick))]),
        how: `borsh(crash::Config { auto_cashout_tick: Some(${converted.tick}) }) — your signed target of ${ppm} ppm through the shared ppm→tick policy`,
    };
}

/**
 * `plinko.v1.Risk` (proto) → `plinko::engine::Risk` (Borsh ordinal).
 *
 * The two numberings differ by one because proto3 reserves 0 for the rejected
 * `RISK_UNSPECIFIED` sentinel and Borsh has no such sentinel. Mapping them by
 * value rather than by name would shift every risk by one table.
 */
const PLINKO_RISK_BORSH: Record<number, number> = { 1: 0, 2: 1, 3: 2 };

const PLINKO_RISK_NAMES: Record<number, string> = { 1: 'low', 2: 'medium', 3: 'high' };

function plinkoPlaceBetExpectation(rows: number, risk: number): Expectation {
    const borshRisk = PLINKO_RISK_BORSH[risk];

    if (borshRisk === undefined) {
        return {
            ok: false,
            reason: `the plinko PlaceBet you signed carries risk = ${risk}, which is not one of LOW/MEDIUM/HIGH — the sequencer refuses it as INVALID_PAYLOAD, so there is no Borsh risk to compare`,
        };
    }

    return {
        ok: true,
        actionTypes: ['place-bet'],
        payload: new Uint8Array([...u32Le(rows), borshRisk]),
        how: `borsh(plinko::Config { rows: ${rows}, risk: ${PLINKO_RISK_NAMES[risk]} }) — proto risk ${risk} is Borsh ordinal ${borshRisk}, the two numberings differ because proto reserves 0 for the rejected UNSPECIFIED sentinel`,
    };
}

function hydraPlaceBetExpectation(hero: number): Expectation {
    if (hero > 0xff) {
        return {
            ok: false,
            reason: `the hydra PlaceBet you signed carries hero = ${hero}, which does not fit the u8 the engine config stores, so what the sequencer would have written is not derivable`,
        };
    }

    return {
        ok: true,
        actionTypes: ['place-bet'],
        payload: new Uint8Array([hero]),
        how: `borsh(hydra::Config { hero: ${hero} }) — a single u8`,
    };
}

// ── helpers ─────────────────────────────────────────────────────────────

const EMPTY = new Uint8Array(0);

function u32Le(value: number): Uint8Array {
    const bytes = new Uint8Array(4);

    new DataView(bytes.buffer).setUint32(0, value >>> 0, true);

    return bytes;
}

function hexOrEmpty(bytes: Uint8Array): string {
    return bytes.length === 0 ? '(empty)' : `0x${bytesToHex(bytes)}`;
}

/** A human-readable name for a decoded command body, used in every line. */
function describe(body: DecodedCommandBody): string {
    switch (body.case) {
        case 'unrecognised':
            return body.description;
        case 'placeBet':
            switch (body.game) {
                case 'crash':
                    return body.autoCashoutPpm === null
                        ? 'a crash PlaceBet with no auto_cashout_ppm (manual mode)'
                        : `a crash PlaceBet with auto_cashout_ppm = ${body.autoCashoutPpm}`;
                case 'plinko':
                    return `a plinko PlaceBet with rows = ${body.rows}, risk = ${body.risk}`;
                case 'mines':
                    return `a mines PlaceBet with mine_count = ${body.mineCount}`;
                case 'hydra':
                    return `a hydra PlaceBet with hero = ${body.hero}`;
                default:
                    return 'a hilo PlaceBet';
            }
        case 'playerAction':
            switch (body.game) {
                case 'mines':
                    return `a mines Reveal of tile ${body.tileIndex ?? '(absent)'}`;
                default:
                    return `a ${body.game} PlayerAction ${body.arm}`;
            }
        case 'cashOut':
            return body.game === 'crash'
                ? `a crash CashOut claiming tick ${body.tick ?? '(absent)'}`
                : `a ${body.game} CashOut`;
    }
}

interface DecodedCommand {
    body: DecodedCommandBody | null;
    /** Why the body is null. */
    reason: string;
    /** The request id in the SIGNED bytes, not the export's label. */
    requestId: string | null;
    /** The round id in the SIGNED bytes; null on a PlaceBet or an absent field. */
    roundId: string | null;
}

/**
 * Decode one stored command frame. Every failure is a stated reason, never a
 * throw: a malformed command in an export must degrade one row, not the run.
 */
function decodeCommand(
    commands: ImportedCommand[],
    requestId: string,
    known?: ImportedCommand,
): DecodedCommand {
    const command = known ?? commands.find((candidate) => candidate.requestId === requestId);

    if (!command) {
        return { body: null, reason: `this export carries no command for request ${requestId}`, requestId: null, roundId: null };
    }

    try {
        const split = splitSignedFrame(command.frame);

        if (split.tag !== CLIENT_FRAME_TAG) {
            return {
                body: null,
                reason: `the stored command for ${requestId} carries tag 0x${split.tag.toString(16).padStart(2, '0')}, not a command frame (0x05)`,
                requestId: null,
                roundId: null,
            };
        }

        const decoded = decodeClientEnvelope(split.body);

        if (decoded.commandBody === null) {
            return {
                body: null,
                reason: `the command for ${requestId} is a ${decoded.payloadCase ?? 'payload-less'} envelope, which carries no game action to project`,
                requestId: decoded.requestId,
                roundId: decoded.commandRoundId,
            };
        }

        return {
            body: decoded.commandBody,
            reason: '',
            requestId: decoded.requestId,
            roundId: decoded.commandRoundId,
        };
    } catch (error) {
        return {
            body: null,
            reason: `the command for ${requestId} could not be decoded: ${error instanceof Error ? error.message : String(error)}`,
            requestId: null,
            roundId: null,
        };
    }
}
