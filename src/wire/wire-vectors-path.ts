/**
 * Resolves the shared wire-format vector file the wire tests assert against.
 * In this public export it lives in the repository's own vectors/ directory;
 * in the 99dot5 monorepo the same module points at
 * libs/smart-rollup-messages/testdata/wire-vectors.json, so the identical
 * tests pin both trees to the identical bytes.
 */

export function wireVectorsUrl(): URL {
    return new URL('../../vectors/wire-vectors.json', import.meta.url);
}
