/**
 * Provably-fair seed derivation, byte-for-byte mirroring
 * `libs/game-engine-core/src/rng/v1.rs`, selected per game version as the
 * engines select it — and the seed-commitment hashes
 * mirroring `services/sequencer/src/seed_provisioner/seeds.rs`.
 *
 * The derivation input is EXACTLY `(game_type, server_seed, client_seed,
 * decision, chunk)` — there is no operator-controlled nonce anywhere in it.
 * The only operator-supplied input is `server_seed`, and that is pre-committed
 * on-chain (hash published in a `SeedBatch` inbox message) before the round
 * exists, which is what the commitment half of this verifier proves.
 *
 * A seed is keyed by the round's DECISION, not by the action's position in the
 * transcript: a system step the sequencer inserts (a max-win partial cashout)
 * consumes an action index but draws nothing, so under the decision key it
 * cannot move a later draw.
 */
import { blake2b } from '@noble/hashes/blake2.js';

const encoder = new TextEncoder();

/**
 * The seed derivations this verifier knows by name. Each game version names
 * the rule it replays under ({@link GAME_SEED_DERIVATIONS}), because a round
 * replayed under a rule its engine did not run recomputes a different
 * outcome. The verifier SELECTS the rule by the round's `game_type`
 * ({@link seedRuleForGame}); nothing replays under a global one.
 *
 * - `v1`: the layout of {@link seedPreimage}, under the domain
 *   `99dot5:engine-seed:v1`.
 */
export const DERIVATIONS = ['v1'] as const;
export type Derivation = (typeof DERIVATIONS)[number];

/** Every engine-seed domain is this prefix followed by the derivation's name. */
export const ENGINE_SEED_DOMAIN_PREFIX = '99dot5:engine-seed:';

/**
 * The domain a derivation's preimages start with. Built from the identifier,
 * so the name a game version states and the bytes its rule hashes cannot drift.
 */
export function engineSeedDomain(derivation: Derivation): string {
    return ENGINE_SEED_DOMAIN_PREFIX + derivation;
}
/** How many 32-byte chunks one decision may draw. */
export const MAX_CHUNKS_PER_DECISION = 4;
/** The byte budget of one decision. */
export const DECISION_STREAM_BYTES = MAX_CHUNKS_PER_DECISION * 32;

function lengthPrefixed(field: string, name: string): Uint8Array {
    const bytes = encoder.encode(field);

    if (bytes.length > 255) {
        throw new RangeError(`${name} is ${bytes.length} bytes; a length-prefixed seed field holds at most 255`);
    }

    return concatBytes(new Uint8Array([bytes.length]), bytes);
}

function u32Le(value: number, name: string): Uint8Array {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
        throw new RangeError(`${name} must be a u32, got ${value}`);
    }

    const out = new Uint8Array(4);

    new DataView(out.buffer).setUint32(0, value, true);

    return out;
}

function layoutPreimage(
    domain: string,
    gameType: string,
    serverSeed: string,
    clientSeed: string,
    decision: number,
    chunk: number,
): Uint8Array {
    return concatBytes(
        encoder.encode(domain),
        lengthPrefixed(gameType, 'game_type'),
        lengthPrefixed(serverSeed, 'server_seed'),
        lengthPrefixed(clientSeed, 'client_seed'),
        u32Le(decision, 'decision'),
        u32Le(chunk, 'chunk'),
    );
}

/**
 * The `v1` rule's exact bytes hashed for one 32-byte chunk:
 *
 *   "99dot5:engine-seed:v1" (21 ASCII bytes)
 *   ‖ u8 len ‖ game_type ‖ u8 len ‖ server_seed ‖ u8 len ‖ client_seed
 *   ‖ decision u32 LE ‖ chunk u32 LE
 *
 * The two u32s sit at fixed offsets after the last length-prefixed field, so
 * they need no separator.
 *
 * The seeds are the 64-char lowercase hex strings, as UTF-8 bytes — the same
 * strings the commitment is computed over.
 */
export function seedPreimage(
    gameType: string,
    serverSeed: string,
    clientSeed: string,
    decision: number,
    chunk: number,
): Uint8Array {
    return layoutPreimage(engineSeedDomain('v1'), gameType, serverSeed, clientSeed, decision, chunk);
}

/** The `v1` rule's chunk: `blake2b-256(seedPreimage(…))`. */
export function deriveSeed(
    gameType: string,
    serverSeed: string,
    clientSeed: string,
    decision: number,
    chunk: number,
): Uint8Array {
    return blake2b(seedPreimage(gameType, serverSeed, clientSeed, decision, chunk), { dkLen: 32 });
}

/** One seed derivation: its name, its domain, and how it builds and hashes a chunk's preimage. */
export interface SeedRule {
    readonly derivation: Derivation;
    readonly domain: string;
    preimage(gameType: string, serverSeed: string, clientSeed: string, decision: number, chunk: number): Uint8Array;
    derive(gameType: string, serverSeed: string, clientSeed: string, decision: number, chunk: number): Uint8Array;
}

/**
 * The rules this build implements, by derivation. A derivation absent here is
 * one a game version may name but this verifier cannot replay.
 */
const SEED_RULES: Partial<Record<Derivation, SeedRule>> = {
    v1: {
        derivation: 'v1',
        domain: engineSeedDomain('v1'),
        preimage: seedPreimage,
        derive: deriveSeed,
    },
};

/** The derivations this verifier can replay: exactly the rule table's keys. */
export const SUPPORTED_DERIVATIONS: readonly Derivation[] = DERIVATIONS.filter((d) => SEED_RULES[d] !== undefined);

/** The rule `derivation` names. Throws for one this build does not implement. */
export function seedRule(derivation: Derivation): SeedRule {
    const rule = SEED_RULES[derivation];

    if (rule === undefined) {
        throw new RangeError(`seed derivation "${derivation}" is not implemented by this verifier`);
    }

    return rule;
}

/**
 * The seed derivation each game version names: a mirror of every engine's
 * `SEED_DERIVATION` const (`libs/games/src/<game>/v1/engine.rs`), pinned
 * against each game's `vectors.json` `algorithm.derivation`. A game version
 * names its rule once and never changes it; a new rule ships with new game
 * versions.
 */
export const GAME_SEED_DERIVATIONS: Readonly<Record<string, Derivation>> = {
    'crash:v1': 'v1',
    'hilo:v1': 'v1',
    'mines:v1': 'v1',
    'plinko:v1': 'v1',
    'hydra:v1': 'v1',
};

/**
 * The rule a round of `gameType` replays under, or `undefined` for a game
 * type this verifier does not know or whose rule it does not implement.
 */
export function seedRuleForGame(gameType: string): SeedRule | undefined {
    const derivation = Object.hasOwn(GAME_SEED_DERIVATIONS, gameType) ? GAME_SEED_DERIVATIONS[gameType] : undefined;

    return derivation === undefined ? undefined : SEED_RULES[derivation];
}

/**
 * The bytes one decision draws under its game's rule ({@link seedRuleForGame}),
 * read sequentially from chunk 0. Chunks are
 * derived lazily, only when a read reaches them, and the stream refuses to
 * read past {@link DECISION_STREAM_BYTES} (128 bytes) — the same
 * budget the Rust engine enforces, so a port that over-reads fails loudly
 * instead of agreeing with itself.
 */
export class SeedStream {
    private readonly chunks: Uint8Array[] = [];
    private readonly rule: SeedRule;
    private offset = 0;

    /** Throws for a game type with no implemented rule. */
    constructor(
        private readonly gameType: string,
        private readonly serverSeed: string,
        private readonly clientSeed: string,
        readonly decision: number,
    ) {
        const rule = seedRuleForGame(gameType);

        if (rule === undefined) {
            throw new RangeError(`game ${gameType} names no seed derivation this verifier implements`);
        }

        this.rule = rule;
    }

    /** The next `n` bytes of the stream. */
    take(n: number): Uint8Array {
        if (!Number.isInteger(n) || n < 0) {
            throw new RangeError(`cannot read ${n} bytes`);
        }

        const end = this.offset + n;

        if (end > DECISION_STREAM_BYTES) {
            throw new RangeError(`decision ${this.decision} would read ${end} bytes; the budget is ${DECISION_STREAM_BYTES}`);
        }

        const out = new Uint8Array(n);

        for (let i = 0; i < n; i++) {
            const position = this.offset + i;

            out[i] = this.chunk(Math.floor(position / 32))[position % 32];
        }

        this.offset = end;

        return out;
    }

    /** Every chunk derived so far, for display. */
    derivedChunks(): Uint8Array[] {
        return [...this.chunks];
    }

    private chunk(index: number): Uint8Array {
        while (this.chunks.length <= index) {
            this.chunks.push(this.rule.derive(this.gameType, this.serverSeed, this.clientSeed, this.decision, this.chunks.length));
        }

        return this.chunks[index];
    }
}

/** Little-endian u64 of `bytes[0..8]` — the standard "one draw" reduction. */
export function rawU64(seed: Uint8Array): bigint {
    let value = 0n;

    for (let i = 7; i >= 0; i--) {
        value = (value << 8n) | BigInt(seed[i]);
    }

    return value;
}

/**
 * The on-chain seed commitment: `blake2b-256` of the ASCII bytes of the
 * 64-char lowercase hex `server_seed` STRING (not of the 32 raw bytes it
 * spells). Mirrors `seed_provisioner/seeds.rs::hash_seed` and the kernel's
 * settle-time check (`libs/smart-rollup/src/rounds.rs`).
 */
export function serverSeedCommitment(serverSeed: string): Uint8Array {
    return blake2b(encoder.encode(serverSeed), { dkLen: 32 });
}

export function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex: string): Uint8Array {
    const clean = hex.replace(/^0x/, '').trim();

    if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) {
        throw new RangeError('not a hex string');
    }

    const out = new Uint8Array(clean.length / 2);

    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }

    return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
        return false;
    }

    return a.every((byte, i) => byte === b[i]);
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let offset = 0;

    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }

    return out;
}
