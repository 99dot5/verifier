// @vitest-environment node
// Pins the engine seed derivation byte for byte. The SHARED EXAMPLE below is
// pinned with the same values by the Rust engine and the Python vector
// generator, so a port that drifts in any byte of the preimage fails here.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { blake2b } from '@noble/hashes/blake2.js';
import { describe, expect, it } from 'vitest';
import {
    ENGINE_SEED_DOMAIN_PREFIX,
    GAME_SEED_DERIVATIONS,
    MAX_CHUNKS_PER_DECISION,
    SUPPORTED_DERIVATIONS,
    SeedStream,
    bytesToHex,
    deriveSeed,
    engineSeedDomain,
    seedPreimage,
    seedRule,
    seedRuleForGame,
    type Derivation,
} from './seed';
import { vectorsUrl, type VectorGame } from './vectors-path';

/** gameType "hilo:v1", server "11"×32, client "22"×32, decision 3, chunk 1. */
const EXAMPLE = {
    gameType: 'hilo:v1',
    server: '11'.repeat(32),
    client: '22'.repeat(32),
    decision: 3,
    chunk: 1,
} as const;

/** Computed independently (Python hashlib) — never by the code under test. */
const EXAMPLE_PREIMAGE_HEX =
    '3939646f74353a656e67696e652d736565643a7631' + // "99dot5:engine-seed:v1"
    '07' + '68696c6f3a7631' + // len 7, "hilo:v1"
    '40' + '31'.repeat(64) + // len 64, "11"×32 as ASCII
    '40' + '32'.repeat(64) + // len 64, "22"×32 as ASCII
    '03000000' + // decision 3, u32 LE
    '01000000'; // chunk 1, u32 LE
const EXAMPLE_DIGEST_HEX = 'e032790ea31b22d5299594aa1de0d461e67cc3b398d5aec5d4685d98684599db';

const example = () =>
    seedPreimage(EXAMPLE.gameType, EXAMPLE.server, EXAMPLE.client, EXAMPLE.decision, EXAMPLE.chunk);

describe('engine seed preimage', () => {
    it('builds the v1 domain from the derivation name, and starts with its 21 bytes', () => {
        expect(ENGINE_SEED_DOMAIN_PREFIX).toBe('99dot5:engine-seed:');
        expect(engineSeedDomain('v1')).toBe('99dot5:engine-seed:v1');

        const domain = new TextEncoder().encode(engineSeedDomain('v1'));

        expect(domain).toHaveLength(21);
        expect(bytesToHex(domain)).toBe('3939646f74353a656e67696e652d736565643a7631');
        expect(bytesToHex(example().slice(0, 21))).toBe(bytesToHex(domain));
    });

    it('ends with the decision then the chunk, each a bare u32 LE with no separator', () => {
        const tail = example().slice(-8);

        expect(bytesToHex(tail)).toBe('03000000' + '01000000');
        // The byte before them is the client seed's last ASCII byte ("2").
        expect(example()[example().length - 9]).toBe(0x32);
    });

    it('length-prefixes each field with one byte, so adjacent fields cannot run together', () => {
        // "ab"+"c" and "a"+"bc" concatenate to the same text; the prefixes
        // make the two preimages differ.
        const one = seedPreimage('g', 'ab', 'c', 0, 0);
        const two = seedPreimage('g', 'a', 'bc', 0, 0);

        expect(bytesToHex(one)).not.toBe(bytesToHex(two));
        expect(bytesToHex(seedPreimage('g', 'ab', 'c', 0, 0).slice(21))).toBe(
            '01' + '67' + '02' + '6162' + '01' + '63' + '00000000' + '00000000',
        );
    });

    it('reproduces the shared example preimage and digest', () => {
        expect(bytesToHex(example())).toBe(EXAMPLE_PREIMAGE_HEX);
        expect(example()).toHaveLength(167);

        const digest = deriveSeed(EXAMPLE.gameType, EXAMPLE.server, EXAMPLE.client, EXAMPLE.decision, EXAMPLE.chunk);

        expect(bytesToHex(digest)).toBe(EXAMPLE_DIGEST_HEX);
        expect(bytesToHex(blake2b(example(), { dkLen: 32 }))).toBe(EXAMPLE_DIGEST_HEX);
    });

    it('refuses a field over 255 bytes, and a decision or chunk outside u32', () => {
        expect(() => seedPreimage('g', 'x'.repeat(256), 'c', 0, 0)).toThrow(RangeError);
        expect(() => seedPreimage('g', 'x'.repeat(255), 'c', 0, 0)).not.toThrow();
        expect(() => seedPreimage('g', 's', 'c', -1, 0)).toThrow(RangeError);
        expect(() => seedPreimage('g', 's', 'c', 0, 2 ** 32)).toThrow(RangeError);
        expect(() => seedPreimage('g', 's', 'c', 0xffff_ffff, 0xffff_ffff)).not.toThrow();
    });
});

describe('seedRule', () => {
    it('selects v1, whose domain and preimage are the layout pinned above', () => {
        const rule = seedRule('v1');
        const args = [EXAMPLE.gameType, EXAMPLE.server, EXAMPLE.client, EXAMPLE.decision, EXAMPLE.chunk] as const;

        expect(rule.derivation).toBe('v1');
        expect(rule.domain).toBe(engineSeedDomain('v1'));
        expect(bytesToHex(rule.preimage(...args))).toBe(EXAMPLE_PREIMAGE_HEX);
        expect(bytesToHex(rule.derive(...args))).toBe(EXAMPLE_DIGEST_HEX);
        // The rule's preimage really starts with the rule's own domain.
        expect(new TextDecoder().decode(rule.preimage(...args).slice(0, rule.domain.length))).toBe(rule.domain);
    });

    it('supports exactly the rules its table holds', () => {
        expect(SUPPORTED_DERIVATIONS).toEqual(['v1']);
    });

    it('throws for a derivation this build does not implement', () => {
        expect(() => seedRule('v2' as unknown as Derivation)).toThrow(RangeError);
        expect(() => seedRule('v2' as unknown as Derivation)).toThrow('"v2" is not implemented');
    });
});

describe('seedRuleForGame', () => {
    it('selects each game version\'s own rule', () => {
        for (const [gameType, derivation] of Object.entries(GAME_SEED_DERIVATIONS)) {
            expect(seedRuleForGame(gameType)).toBe(seedRule(derivation));
        }
    });

    it('selects nothing for a game type it does not know', () => {
        expect(seedRuleForGame('roulette:v1')).toBeUndefined();
        expect(seedRuleForGame('toString')).toBeUndefined();
        expect(() => new SeedStream('roulette:v1', EXAMPLE.server, EXAMPLE.client, 0)).toThrow(RangeError);
    });
});

describe('SeedStream', () => {
    const chunk = (decision: number, index: number) =>
        deriveSeed(EXAMPLE.gameType, EXAMPLE.server, EXAMPLE.client, decision, index);

    it('reads sequentially from chunk 0, crossing chunk boundaries', () => {
        const stream = new SeedStream(EXAMPLE.gameType, EXAMPLE.server, EXAMPLE.client, 3);

        expect(bytesToHex(stream.take(8))).toBe(bytesToHex(chunk(3, 0).slice(0, 8)));
        expect(bytesToHex(stream.take(30))).toBe(bytesToHex(chunk(3, 0).slice(8)) + bytesToHex(chunk(3, 1).slice(0, 6)));
        expect(bytesToHex(stream.derivedChunks()[1])).toBe(bytesToHex(chunk(3, 1)));
    });

    it('derives chunks lazily, only as reads reach them', () => {
        const stream = new SeedStream(EXAMPLE.gameType, EXAMPLE.server, EXAMPLE.client, 0);

        expect(stream.derivedChunks()).toHaveLength(0);
        stream.take(32);
        expect(stream.derivedChunks()).toHaveLength(1);
        stream.take(1);
        expect(stream.derivedChunks()).toHaveLength(2);
    });

    it('allows exactly four chunks and refuses the next byte', () => {
        const stream = new SeedStream(EXAMPLE.gameType, EXAMPLE.server, EXAMPLE.client, 0);

        expect(MAX_CHUNKS_PER_DECISION).toBe(4);
        expect(stream.take(128)).toHaveLength(128);
        expect(() => stream.take(1)).toThrow(RangeError);

        const fresh = new SeedStream(EXAMPLE.gameType, EXAMPLE.server, EXAMPLE.client, 0);

        expect(() => fresh.take(129)).toThrow(RangeError);
    });

    it('keys every decision to its own stream', () => {
        const a = new SeedStream(EXAMPLE.gameType, EXAMPLE.server, EXAMPLE.client, 1).take(8);
        const b = new SeedStream(EXAMPLE.gameType, EXAMPLE.server, EXAMPLE.client, 2).take(8);

        expect(bytesToHex(a)).not.toBe(bytesToHex(b));
    });
});

describe('shared example in the vectors files', () => {
    const GAMES: VectorGame[] = ['crash', 'hilo', 'mines', 'plinko', 'hydra'];

    it.each(GAMES)('%s vectors.json states the same preimage and digest', (game) => {
        const file: { algorithm?: { preimage_example_hex?: string; preimage_example_digest_hex?: string } } = JSON.parse(
            readFileSync(fileURLToPath(vectorsUrl(game)), 'utf8'),
        );

        expect(file.algorithm?.preimage_example_hex).toBe(EXAMPLE_PREIMAGE_HEX);
        expect(file.algorithm?.preimage_example_digest_hex).toBe(EXAMPLE_DIGEST_HEX);
    });
});

describe('game → seed derivation table', () => {
    // Each engine's SEED_DERIVATION const is written into its vectors file as
    // algorithm.derivation by the generator's mirror table; this table must
    // name the same rule for every game, hydra included (it has vectors but no
    // replayer here).
    const GAMES: VectorGame[] = ['crash', 'hilo', 'mines', 'plinko', 'hydra'];

    it('lists exactly the games that ship vectors', () => {
        expect(Object.keys(GAME_SEED_DERIVATIONS).sort()).toEqual(GAMES.map((game) => `${game}:v1`).sort());
    });

    it.each(GAMES)('%s vectors.json names the rule GAME_SEED_DERIVATIONS mirrors', (game) => {
        const file: { algorithm?: { game_type?: string; derivation?: string } } = JSON.parse(
            readFileSync(fileURLToPath(vectorsUrl(game)), 'utf8'),
        );

        expect(file.algorithm?.game_type).toBe(`${game}:v1`);
        expect(file.algorithm?.derivation).toBe(GAME_SEED_DERIVATIONS[`${game}:v1`]);
    });
});
