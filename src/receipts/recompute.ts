/**
 * Reconstructing a round's player commitment from an imported export.
 *
 * A PORT of `libs/casino-client/src/receipts/recompute.ts`, not an import: the
 * published verifier must reach into no `@99dot5/*` package, so the algorithm
 * is reproduced here and the two are held to the same answers by the shared
 * fixture. Same five steps, same reason names — a divergence in either would
 * mean the play client and the verifier disagree about what a round was, which
 * is precisely the disagreement the commitment exists to settle.
 *
 * One structural difference, and it is a strengthening. The client reads its
 * own store, where `payloadCase` / `relatedRequestId` / `roundIdHex` were
 * written from frames it had already verified. The verifier reads a document a
 * PLAYER handed it, whose same-named fields are labels anyone could have
 * typed — so every one of them is re-derived here from the frame bytes, and
 * the labels are only cross-checked (`labelFindings`). An exporter that
 * relabels a frame changes nothing about the verdict.
 *
 *   0. scope the command set to the round through `related_request_id`,
 *   1. dedup by `request_id`, keeping the first send,
 *   2. keep only commands the server positively acknowledged,
 *   3. order by the SERVER's step index, never by send order,
 *   4. answer `unavailable` on any residual ambiguity — never a mismatch.
 *
 * This function has no notion of a failed verdict. It either reproduces a
 * commitment or explains why it cannot; comparing the result against the chain
 * or against the signed `RoundEnded` is the caller's job, and only a caller
 * that got an `ok` here may draw a conclusion from a difference.
 */
import { computeCommitment } from './commitment';
import type { ImportedCommand, ImportedFrame } from './import';
import { decodeServerEnvelope, type DecodedServerEnvelope } from '../wire/proto-reader';
import { splitSignedFrame, SERVER_FRAME_TAG } from '../wire/signature';

/**
 * Why a round's commitment could not be reconstructed. Each arm names one
 * §5.3 step-4 condition; none of them is an accusation — they all describe a
 * gap in the evidence the export carries.
 */
export type RecomputeUnavailableReason =
    /** No `BetPlaced`/`RoundStarted` frame names the command that opened the round. */
    | 'no-place-bet'
    /**
     * The server stated an index for a command the export does not carry. The
     * peer-tab case: another tab of the same session sent it, and the
     * exporting tab stored the resulting broadcast frame but not the command.
     */
    | 'server-index-without-command'
    /** An accepted, in-scope command that no frame places in the round's order. */
    | 'accepted-command-without-index'
    /**
     * Two PLAYER-bound frames placed one command at two different indices.
     *
     * The routine producer of this was the max-win de-lever: on a compounding
     * round the sequencer inserts a SYSTEM `partial-cashout` step ahead of the
     * triggering action and emits its `RoundUpdated` in the same outbox batch,
     * so both frames carry the triggering command's `related_request_id`.
     * `RoundUpdatedEvent.origin` (ADR 0022 §9) now tells them apart, so a
     * de-lever round reconstructs normally. What still degrades here is an
     * `unspecified` origin — a server predating the field — because an
     * unmarked second index is indistinguishable from a genuine conflict.
     */
    | 'conflicting-index'
    /**
     * The reconstructed indices are not a contiguous `0..n-1` run, measured
     * over the UNION of player-bound and SYSTEM positions: a system step
     * occupies a slot in the round's action vector without binding a command,
     * so counting only the player's would read every de-lever round as a gap.
     */
    | 'index-gap'
    /** A `RoundEnded` frame with no `action_index` — a server predating field 6. */
    | 'round-ended-without-index'
    /** A frame in the export could not be decoded as a signed server frame. */
    | 'undecodable-frame';

export type RecomputeResult =
    | {
          status: 'ok';
          /** blake2b-256 over the ordered command frames, D1's preimage. */
          commitment: Uint8Array;
          /** The commands that went into the preimage, in server-index order. */
          orderedRequestIds: string[];
          /**
           * The server-stated action index each of those commands was bound
           * to, positionally parallel to `orderedRequestIds`.
           *
           * NOT the array position: a SYSTEM step (the max-win de-lever's
           * `partial-cashout`) occupies an index without binding a command, so
           * on a de-lever round the k-th command sits at an index greater than
           * k. A rule that read the position as the index would compare the
           * player's action against the wrong transcript entry — and would do
           * it silently, since both are small integers.
           */
          orderedIndices: number[];
      }
    | { status: 'unavailable'; reason: RecomputeUnavailableReason };

export interface RecomputeInput {
    /** Hyphenated round id — the export's LABEL, cross-checked, never trusted. */
    roundIdHex: string;
    commands: ImportedCommand[];
    frames: ImportedFrame[];
}

/** One export frame with its bytes decoded, beside the labels it shipped with. */
export interface ReceiptFrame {
    /** The whole `[0x06 | signature | protobuf]` frame — the evidence. */
    frame: Uint8Array;
    signature: Uint8Array;
    /** The protobuf body the signature covers. */
    body: Uint8Array;
    envelope: DecodedServerEnvelope;
    /** What the exporter claimed about this frame. */
    label: { sequence: bigint; payloadCase: string; relatedRequestId: string | null };
}

export class FrameDecodeError extends Error {}

/** Decode one exported server frame. Throws; callers map that to a stated reason. */
export function decodeReceiptFrame(imported: ImportedFrame): ReceiptFrame {
    const split = splitSignedFrame(imported.frame);

    if (split.tag !== SERVER_FRAME_TAG) {
        throw new FrameDecodeError(
            `frame at sequence ${imported.sequence} carries tag 0x${split.tag.toString(16).padStart(2, '0')}, not a server frame (0x06)`,
        );
    }

    return {
        frame: imported.frame,
        signature: split.signature,
        body: split.body,
        envelope: decodeServerEnvelope(split.body),
        label: {
            sequence: imported.sequence,
            payloadCase: imported.payloadCase,
            relatedRequestId: imported.relatedRequestId,
        },
    };
}

/** Decode every exported frame, or name the first one that would not decode. */
export function decodeReceiptFrames(
    frames: ImportedFrame[],
): { status: 'ok'; frames: ReceiptFrame[] } | { status: 'error'; message: string } {
    const decoded: ReceiptFrame[] = [];

    for (const frame of frames) {
        try {
            decoded.push(decodeReceiptFrame(frame));
        } catch (error) {
            return { status: 'error', message: error instanceof Error ? error.message : String(error) };
        }
    }

    return { status: 'ok', frames: decoded };
}

/**
 * Where the exporter's labels disagree with the bytes.
 *
 * Not a failure — a relabelled export is still verified from its frames — but
 * a REPORTABLE FINDING (design §8.3(e)): an exporter that relabels frames is
 * the shape an attempt to game a suppression verdict takes, and silence about
 * it would hide exactly what a reader wants to see.
 */
export function labelFindings(frames: ReceiptFrame[], roundIdHex: string): string[] {
    const findings: string[] = [];

    for (const frame of frames) {
        const derived = frame.envelope.payloadCase;

        if (derived !== null && derived !== frame.label.payloadCase) {
            findings.push(
                `frame labelled sequence ${frame.label.sequence} as "${frame.label.payloadCase}" decodes as "${derived}"`,
            );
        }

        if (frame.envelope.relatedRequestId !== frame.label.relatedRequestId) {
            findings.push(
                `frame labelled sequence ${frame.label.sequence} claims related_request_id ${frame.label.relatedRequestId ?? '(none)'} but the signed bytes say ${frame.envelope.relatedRequestId ?? '(none)'}`,
            );
        }

        if (frame.envelope.sequence !== frame.label.sequence) {
            findings.push(
                `frame labelled sequence ${frame.label.sequence} carries sequence ${frame.envelope.sequence} in the signed bytes`,
            );
        }

        if (frame.envelope.roundId !== null && frame.envelope.roundId !== roundIdHex) {
            findings.push(
                `frame at sequence ${frame.envelope.sequence} names round ${frame.envelope.roundId}, not the export's ${roundIdHex}`,
            );
        }
    }

    return findings;
}

/** The payload cases that place a command at a position in the round. */
const INDEX_BEARING_CASES = new Set(['betPlaced', 'roundStarted', 'roundUpdated', 'roundEnded']);

export function recomputeRoundCommitment(input: RecomputeInput): RecomputeResult {
    const decoded = decodeReceiptFrames(input.frames);

    if (decoded.status === 'error') {
        return unavailable('undecodable-frame');
    }

    const all = decoded.frames;
    // A frame belongs to the round iff its own signed bytes name the round —
    // `commandAccepted` names none, which is why acceptance (step 2) is read
    // from the whole set and ordering (step 3) only from this one.
    const roundFrames = all.filter((frame) => frame.envelope.roundId === input.roundIdHex);

    // ---- step 0: scope -------------------------------------------------
    //
    // A command belongs to this round iff a frame OF this round names it. A
    // command no round frame names is out of scope, NOT ambiguous: it must
    // never reach step 4. `EndSession` is the concrete case — accepted,
    // round-less, and counting it would report a gap on an honest round.
    const scoped = new Set<string>();

    for (const frame of roundFrames) {
        if (frame.envelope.relatedRequestId !== null) {
            scoped.add(frame.envelope.relatedRequestId);
        }
    }

    // ---- step 1: dedup by request id, keeping the first send -----------
    //
    // An idempotent retry sends the SAME frame twice and the server replays
    // cached frames without archiving a second row. Counting the retry would
    // make every reconstruction on a flaky connection fail.
    const byRequestId = new Map<string, ImportedCommand>();

    for (const command of input.commands) {
        if (!scoped.has(command.requestId)) {
            continue;
        }

        const seen = byRequestId.get(command.requestId);

        if (!seen || command.sentAtUnixMs < seen.sentAtUnixMs) {
            byRequestId.set(command.requestId, command);
        }
    }

    // ---- step 2: keep only positively acknowledged commands ------------
    //
    // A positive signal only. `CommandRejected` is ephemeral (§3.1), so a
    // dropped connection loses it, and inferring acceptance from a missing
    // rejection would silently promote a refused command into the preimage.
    const accepted = new Set<string>();

    for (const frame of all) {
        if (frame.envelope.payloadCase === 'commandAccepted' && frame.envelope.relatedRequestId !== null) {
            accepted.add(frame.envelope.relatedRequestId);
        }
    }

    const kept = new Map<string, ImportedCommand>();

    for (const [requestId, command] of byRequestId) {
        if (accepted.has(requestId)) {
            kept.set(requestId, command);
        }
    }

    // ---- step 3: order by the server's index ---------------------------
    const indices = new Map<string, number>();
    /**
     * Positions the server filled with a step of its own (ADR 0022 D9): they
     * occupy an index in the round's action vector but have no archive row
     * behind them, so they contribute to contiguity and not to the preimage.
     */
    const systemIndices = new Set<number>();
    let sawPlaceBetFrame = false;

    for (const frame of roundFrames) {
        const payloadCase = frame.envelope.payloadCase;

        if (payloadCase === null || !INDEX_BEARING_CASES.has(payloadCase) || frame.envelope.relatedRequestId === null) {
            continue;
        }

        let index: number;

        switch (payloadCase) {
            case 'betPlaced':
            case 'roundStarted':
                // Index 0 by construction: the opening bet is always step 0,
                // and neither frame states an index.
                sawPlaceBetFrame = true;
                index = 0;
                break;
            case 'roundUpdated': {
                // `RoundUpdatedEvent.action_index` is a proto3 IMPLICIT-presence
                // `int32`, so index 0 is omitted from the wire entirely and an
                // absent field is the value 0 — which is what protobuf-es hands
                // the play client, and therefore what the port must read. (The
                // reader keeps `null` rather than defaulting, because
                // `RoundEnded.action_index` next door IS `optional` and its
                // absence is a real absence: a voided round.) No shipped game
                // reports step 0 as a `RoundUpdated` — actions[0] is always the
                // `place-bet`, announced by `BetPlaced`/`RoundStarted` — so this
                // is a conformance point, not a live path. Treating it as a
                // missing index would degrade an honest round to `unavailable`
                // the day one does.
                const actionIndex = frame.envelope.actionIndex ?? 0;

                if (frame.envelope.origin === 'system') {
                    // The sequencer wrote this step itself — today, the max-win
                    // de-lever's `partial-cashout`. It rides the triggering
                    // command's `related_request_id` because it was emitted in
                    // that command's outbox batch, but no archive row backs it,
                    // so it binds no command and must not claim one.
                    systemIndices.add(actionIndex);
                    continue;
                }

                index = actionIndex;
                break;
            }
            case 'roundEnded': {
                if (frame.envelope.actionIndex === null) {
                    return unavailable('round-ended-without-index');
                }

                index = frame.envelope.actionIndex;
                break;
            }
            default:
                continue;
        }

        const existing = indices.get(frame.envelope.relatedRequestId);

        if (existing !== undefined && existing !== index) {
            return unavailable('conflicting-index');
        }

        indices.set(frame.envelope.relatedRequestId, index);
    }

    // ---- step 4: any residual ambiguity is `unavailable` ---------------
    if (!sawPlaceBetFrame) {
        return unavailable('no-place-bet');
    }

    for (const requestId of indices.keys()) {
        if (!kept.has(requestId)) {
            return unavailable('server-index-without-command');
        }
    }

    const ordered: { index: number; command: ImportedCommand }[] = [];

    for (const [requestId, command] of kept) {
        const index = indices.get(requestId);

        if (index === undefined) {
            return unavailable('accepted-command-without-index');
        }

        ordered.push({ index, command });
    }

    ordered.sort((a, b) => a.index - b.index);

    // Contiguity is a property of the round's ACTION VECTOR, so it is checked
    // over the union of the two kinds of position. The set's size is compared
    // against the count first: a system index that collides with a
    // player-bound one collapses the union, and a silently-shrunk set would
    // otherwise pass the run check while describing a round nobody played.
    const occupied = new Set<number>(systemIndices);

    for (const entry of ordered) {
        occupied.add(entry.index);
    }

    const expectedLength = systemIndices.size + ordered.length;

    if (occupied.size !== expectedLength) {
        return unavailable('index-gap');
    }

    for (let position = 0; position < expectedLength; position += 1) {
        if (!occupied.has(position)) {
            return unavailable('index-gap');
        }
    }

    return {
        status: 'ok',
        commitment: computeCommitment(ordered.map((entry) => entry.command.frame)),
        orderedRequestIds: ordered.map((entry) => entry.command.requestId),
        orderedIndices: ordered.map((entry) => entry.index),
    };
}

function unavailable(reason: RecomputeUnavailableReason): RecomputeResult {
    return { status: 'unavailable', reason };
}
