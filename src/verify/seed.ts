/**
 * Provably-fair seed derivation, byte-for-byte mirroring
 * `libs/game-engine-core/src/rng.rs::derive_seed` — and the seed-commitment
 * hashes mirroring `services/sequencer/src/seed_provisioner/seeds.rs`.
 *
 * The derivation input is EXACTLY `(game_type, server_seed, client_seed,
 * action_index)` — there is no operator-controlled nonce anywhere in it. The
 * only operator-supplied input is `server_seed`, and that is pre-committed
 * on-chain (hash published in a `SeedBatch` inbox message) before the round
 * exists, which is what the commitment half of this verifier proves.
 */
import { blake2b } from '@noble/hashes/blake2.js';

const encoder = new TextEncoder();

/**
 * `blake2b-256("game-seed|" + game_type + "|" + server_seed + "|" +
 * client_seed + "|" + action_index.to_le_bytes(i32))`.
 *
 * The pipe separators are literal bytes; the strings are UTF-8; the action
 * index is a 4-byte little-endian SIGNED 32-bit integer.
 */
export function deriveSeed(
    gameType: string,
    serverSeed: string,
    clientSeed: string,
    actionIndex: number,
): Uint8Array {
    const indexBytes = new Uint8Array(4);

    new DataView(indexBytes.buffer).setInt32(0, actionIndex, true);

    const payload = concatBytes(
        encoder.encode(`game-seed|${gameType}|${serverSeed}|${clientSeed}|`),
        indexBytes,
    );

    return blake2b(payload, { dkLen: 32 });
}

/** Little-endian u64 of `seed[0..8]` — the standard "one draw" reduction. */
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
