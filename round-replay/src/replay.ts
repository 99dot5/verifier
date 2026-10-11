/**
 * The one replay entry point: a decoded `RoundTranscript` in, the engine's
 * recomputed round out. The round verifier and every other consumer call this,
 * so the rule for which actions get replayed cannot diverge between them.
 */
import * as crash from './verify/crash';
import * as hilo from './verify/hilo';
import * as hydra from './verify/hydra';
import * as mines from './verify/mines';
import * as plinko from './verify/plinko';
import { bytesToHex } from './verify/seed';
import type { ReplayResult, Replayer, TranscriptAction } from './verify/types';
import type { RoundTranscriptMessage } from './wire/messages';

/**
 * The replayers, by the `game_type` the transcript states.
 *
 * Every game version in `GAME_SEED_DERIVATIONS` has one (pinned by the
 * verifier's tests). A game without a replayer can never be `verified`.
 */
export const REPLAYERS: Record<string, Replayer> = {
    [crash.v1.GAME_TYPE]: crash.v1.replay,
    [hilo.v1.GAME_TYPE]: hilo.v1.replay,
    [hydra.v1.GAME_TYPE]: hydra.v1.replay,
    [plinko.v1.GAME_TYPE]: plinko.v1.replay,
    [mines.v1.GAME_TYPE]: mines.v1.replay,
};

export function supportedGameTypes(): string[] {
    return Object.keys(REPLAYERS);
}

/** The transcript's game type has no replayer in this build. */
export class UnsupportedGameError extends Error {}

/** The kernel's `reject-unknown-action-tag`: the walk reaches a tag this table does not know before the round settles. */
export class UnknownActionTagError extends Error {}

/**
 * Replay a round from its transcript.
 *
 * The action's index IS its position in the transcript, so index 0 is always
 * the place-bet. The seed derivation is keyed by DECISION, which each replayer
 * counts itself from these actions, so it needs nothing else off the wire.
 *
 * Only the prefix before the first unknown tag is replayed. The kernel
 * tag-checks an entry only when its walk reaches it and stops at the first
 * settle, so an unknown tag AFTER the settle is never read.
 *
 * Throws `UnsupportedGameError` for a game with no replayer,
 * `UnknownActionTagError` when an unknown tag is reached before the settle,
 * and `ReplayError` for a transcript the engine rejects.
 */
export function replayTranscript(t: RoundTranscriptMessage): ReplayResult {
    const replayer = REPLAYERS[t.gameType];

    if (!replayer) {
        throw new UnsupportedGameError(
            `game ${t.gameType} has no replayer (supported: ${supportedGameTypes().join(', ')})`,
        );
    }

    const unknownTags = t.actions
        .map((a, i) => ({ index: i, tag: a.tag, actionType: a.actionType }))
        .filter((a) => a.actionType === null);
    const firstUnknown = unknownTags.length > 0 ? unknownTags[0].index : t.actions.length;
    const actions: TranscriptAction[] = t.actions.slice(0, firstUnknown).map((a, index) => ({
        actionIndex: index,
        actionType: a.actionType as string,
        payload: a.payload,
    }));

    // An unknown tag at index 0 leaves nothing to replay; an empty transcript
    // still goes to the replayer, which refuses it.
    const replayed =
        unknownTags.length === 0 || actions.length > 0
            ? replayer(bytesToHex(t.serverSeed), bytesToHex(t.clientSeed), actions, t.stake)
            : null;

    if (replayed === null || (unknownTags.length > 0 && !replayed.settled)) {
        // Mirrors the kernel's `reject-unknown-action-tag`: the message
        // decodes in full, but the walk reaches a tag this table version does
        // not know before the round settles.
        throw new UnknownActionTagError(
            `transcript carries action tag(s) this replayer does not know: ${unknownTags
                .map((a) => `#${a.index} = 0x${a.tag.toString(16).padStart(2, '0')}`)
                .join(', ')} — the kernel rejects such a round as reject-unknown-action-tag`,
        );
    }

    return replayed;
}
