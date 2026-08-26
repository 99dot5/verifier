/**
 * Resolves the golden-vector files the test suite asserts against. In this
 * public export they live in the repository's own vectors/ directory; in the
 * 99dot5 monorepo the same module points at libs/games/src/<game>/v1/testdata,
 * so the identical tests pin both trees to the identical bytes.
 */

export type VectorGame = 'hilo' | 'plinko' | 'mines' | 'crash';

export function vectorsUrl(game: VectorGame): URL {
    return new URL(`../../vectors/${game}.v1.vectors.json`, import.meta.url);
}
