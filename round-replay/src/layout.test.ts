// @vitest-environment node
/**
 * The per-version port layout, mirroring `libs/games/src/<game>/v<N>/`: every
 * game version the replay table serves is its own `verify/<game>/v<N>.ts`,
 * reachable as `<game>.v<N>` from the barrel, and every such file on disk is
 * wired into both `REPLAYERS` and `GAME_SEED_DERIVATIONS`. A launched port is
 * frozen like its engine, so a rule change lands as a NEW file this test then
 * forces into both tables.
 *
 * Paths resolve relative to this file, so the check holds unchanged in the
 * exported verifier tree (`round-replay/src/`).
 */
import { existsSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import * as lib from './index';
import { REPLAYERS } from './replay';
import { GAME_SEED_DERIVATIONS } from './verify/seed';

const VERIFY_DIR = fileURLToPath(new URL('./verify/', import.meta.url));
const GAME_TYPE_SHAPE = /^([a-z]+):v(\d+)$/;

function portPath(gameType: string): string {
    const match = GAME_TYPE_SHAPE.exec(gameType);

    if (match === null) {
        throw new Error(`game type ${gameType} is not <game>:v<N>`);
    }

    return `${match[1]}/v${match[2]}.ts`;
}

/** Every `verify/<game>/v<N>.ts` on disk, as the game type it serves. */
function portsOnDisk(): string[] {
    return readdirSync(VERIFY_DIR, { withFileTypes: true })
        .filter((entry) => entry.isDirectory())
        .flatMap((dir) =>
            readdirSync(`${VERIFY_DIR}${dir.name}`)
                .map((file) => /^v(\d+)\.ts$/.exec(file))
                .filter((match): match is RegExpExecArray => match !== null)
                .map((match) => `${dir.name}:v${match[1]}`),
        )
        .sort();
}

describe('versioned port layout', () => {
    it('finds the ports at all', () => {
        expect(portsOnDisk().length).toBeGreaterThan(0);
    });

    it.each(Object.keys(REPLAYERS))('replayer %s is <game>:v<N> with its own port file', (gameType) => {
        expect(gameType).toMatch(GAME_TYPE_SHAPE);
        expect(existsSync(`${VERIFY_DIR}${portPath(gameType)}`), `missing verify/${portPath(gameType)}`).toBe(true);
    });

    it.each(Object.keys(GAME_SEED_DERIVATIONS))('seed derivation %s has its own port file', (gameType) => {
        expect(gameType).toMatch(GAME_TYPE_SHAPE);
        expect(existsSync(`${VERIFY_DIR}${portPath(gameType)}`), `missing verify/${portPath(gameType)}`).toBe(true);
    });

    it('wires every port file on disk into REPLAYERS and GAME_SEED_DERIVATIONS', () => {
        for (const gameType of portsOnDisk()) {
            expect(Object.hasOwn(REPLAYERS, gameType), `verify/${portPath(gameType)} has no REPLAYERS entry`).toBe(true);
            expect(
                Object.hasOwn(GAME_SEED_DERIVATIONS, gameType),
                `verify/${portPath(gameType)} has no GAME_SEED_DERIVATIONS entry`,
            ).toBe(true);
        }
    });

    it.each(Object.keys(REPLAYERS))('replayer %s is the barrel namespace <game>.v<N>', (gameType) => {
        const [, game, version] = GAME_TYPE_SHAPE.exec(gameType) ?? [];
        const port = (lib as unknown as Record<string, Record<string, { GAME_TYPE: string; replay: unknown }>>)[game]?.[
            `v${version}`
        ];

        expect(port?.GAME_TYPE).toBe(gameType);
        expect(port?.replay).toBe(REPLAYERS[gameType]);
    });
});
