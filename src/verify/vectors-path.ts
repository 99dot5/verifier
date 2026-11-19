/**
 * Resolves the golden-vector files the test suite asserts against. In this
 * public export they live in the repository's own vectors/ directory; in the
 * 99dot5 monorepo the same module points at libs/games/src/<game>/v1/testdata,
 * so the identical tests pin both trees to the identical bytes.
 */

export type VectorGame = 'hilo' | 'plinko' | 'mines' | 'crash' | 'hydra' | 'hydraV2';

export const VECTOR_DIRS: Record<VectorGame, string> = { hilo: 'hilo/v1', plinko: 'plinko/v1', mines: 'mines/v1', crash: 'crash/v1', hydra: 'hydra/v1', hydraV2: 'hydra/v2' };

export function vectorsUrl(game: VectorGame): URL {
    return new URL(`../../vectors/${VECTOR_DIRS[game].replace('/', '.')}.vectors.json`, import.meta.url);
}
