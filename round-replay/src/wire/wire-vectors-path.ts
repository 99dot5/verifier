/**
 * Resolves the shared wire-format vector file the wire tests assert against.
 * In this public export it lives in the repository's own vectors/ directory;
 * in the 99dot5 source tree the same module points at the Rust wire crate's
 * own copy, so the identical tests pin both trees to the identical bytes.
 */

export function wireVectorsUrl(): URL {
    return new URL('../../../vectors/wire-vectors.json', import.meta.url);
}
