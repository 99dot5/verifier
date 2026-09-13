/**
 * The global action-tag table, mirroring
 * `libs/smart-rollup-messages/src/v1/action_tag.rs` (the single source of
 * truth) and pinned against `testdata/wire-vectors.json` by
 * `wire-vectors.test.ts`.
 *
 * A `RoundTranscript` spends one byte per action instead of the 4 + n bytes
 * an `action_type` string used to cost. The numbering is frozen alongside the
 * V1 wire and is split into two blocks:
 *
 * - `0x00`–`0x0F` — the **protocol block**: actions the protocol itself relies
 *   on, shared by every game that uses them. Five assigned, eleven reserved.
 * - `0x10` onward — the **game vocabulary**, append-only in order of
 *   introduction and shared *by name*: a future game that reveals tiles reuses
 *   `reveal` rather than minting a second tile-reveal tag.
 *
 * When the protocol block fills, further protocol actions continue at the end
 * of the open range. Nothing decodes a tag by which block it falls in.
 *
 * The wire field is a bare `u8`, not an enum, and that is deliberate on the
 * kernel side: an unknown tag must leave the rest of the transcript decodable
 * so the kernel can still resolve the seed and write an attributable
 * `reject-unknown-action-tag` settlement. This decoder mirrors that — an
 * unrecognised tag yields `actionType: null` and is reported as a replay
 * failure, not as an undecodable message.
 *
 * The tag carries no origin bit and is not bit-packed. `partial-cashout`,
 * `abandon` and `expire` are written by the sequencer itself and no player
 * command can produce them, but that is a property of the action type resolved
 * through this table, not of the byte.
 */

/** One row of the global table. */
export interface ActionTagEntry {
    /** The wire byte. */
    readonly tag: number;
    /** The kebab-case `action_type`. */
    readonly actionType: string;
    /** True when the sequencer writes it and no player command can. */
    readonly system: boolean;
}

/** The first byte of the game vocabulary. Documentation, not a classifier. */
export const GAME_VOCABULARY_START = 0x10;

/** Every action type, in ascending wire order. */
export const ACTION_TAGS: readonly ActionTagEntry[] = [
    // Protocol block, 0x00–0x0F.
    { tag: 0x00, actionType: 'place-bet', system: false }, // every game, always at actions[0]
    { tag: 0x01, actionType: 'cashout', system: false }, // crash, plinko, hilo, mines, hydra
    { tag: 0x02, actionType: 'partial-cashout', system: true }, // max-win de-lever (payload: 16 bytes)
    { tag: 0x03, actionType: 'abandon', system: true }, // janitor sweep / force-settle
    { tag: 0x04, actionType: 'expire', system: true }, // crash's terminal loss, from the deadline sweep
    // Game vocabulary, 0x10 onward.
    { tag: 0x10, actionType: 'higher', system: false }, // hilo
    { tag: 0x11, actionType: 'lower', system: false }, // hilo
    { tag: 0x12, actionType: 'reveal', system: false }, // mines (payload: u32 tile index)
    { tag: 0x13, actionType: 'physical-attack', system: false }, // hydra
    { tag: 0x14, actionType: 'magic-attack', system: false }, // hydra
    { tag: 0x15, actionType: 'drink-potion', system: false }, // hydra
    { tag: 0x16, actionType: 'drink-mana', system: false }, // hydra
] as const;

/**
 * Which actions each shipped game uses — the twin of `GAME_VOCABULARIES` in
 * the Rust table. `place-bet` and `abandon` are universal; `abandon` is
 * termination from outside the round, so it is legal even in the games whose
 * engine has no action for it (crash, plinko — the kernel walker overrides the
 * outcome instead).
 */
export const GAME_VOCABULARIES: Readonly<Record<string, readonly string[]>> = {
    'crash:v1': ['place-bet', 'cashout', 'abandon', 'expire'],
    'plinko:v1': ['place-bet', 'cashout', 'abandon'],
    'hilo:v1': ['place-bet', 'cashout', 'partial-cashout', 'abandon', 'higher', 'lower'],
    'mines:v1': ['place-bet', 'cashout', 'partial-cashout', 'abandon', 'reveal'],
    'hydra:v1': [
        'place-bet',
        'cashout',
        'partial-cashout',
        'abandon',
        'physical-attack',
        'magic-attack',
        'drink-potion',
        'drink-mana',
    ],
};

const BY_TAG = new Map(ACTION_TAGS.map((entry) => [entry.tag, entry]));
const BY_ACTION_TYPE = new Map(ACTION_TAGS.map((entry) => [entry.actionType, entry]));

/** Resolve a wire tag to its kebab-case `action_type`, or null if unknown. */
export function actionTypeOf(tag: number): string | null {
    return BY_TAG.get(tag)?.actionType ?? null;
}

/** Resolve a kebab-case `action_type` to its wire tag, or null if unknown. */
export function tagOf(actionType: string): number | null {
    return BY_ACTION_TYPE.get(actionType)?.tag ?? null;
}

/**
 * True for the actions no player command can produce. A table lookup, not a
 * range comparison — origin does not follow the numbering. `fight` is absent
 * from the table entirely — a dead leftover in the `steps.action_type` CHECK
 * constraint that no engine emits — so it resolves to null, not to a tag.
 */
export function isSystem(actionType: string): boolean {
    return BY_ACTION_TYPE.get(actionType)?.system ?? false;
}

/**
 * Whether `gameType` uses this action at all. A game type the table does not
 * know has no vocabulary, so every action is refused for it — fail-closed,
 * matching the kernel's `ActionTag::allowed_in`.
 */
export function allowedIn(actionType: string, gameType: string): boolean {
    return GAME_VOCABULARIES[gameType]?.includes(actionType) ?? false;
}
