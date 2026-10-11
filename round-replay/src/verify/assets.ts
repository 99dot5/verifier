/**
 * Asset decimals, for the one asset this verifier renders.
 *
 * SOURCE OF TRUTH: `money::decimals_for` in `libs/money/src/lib.rs`, which
 * holds `ASSET_REGISTRY` — the compiled table the sequencer and the rollup
 * kernel both resolve a round's grain from. TypeScript cannot link that
 * crate, so this file is a mirror and must be edited whenever the registry
 * gains an asset. It is deliberately the only place in this app that names a
 * decimal count.
 *
 * The wire carries no asset code (the kernel reads it off the session
 * record), so a decoded transcript is rendered as TEZ.
 */
export const ASSET_DECIMALS: Readonly<Record<string, number>> = {
    TEZ: 6,
};

/** The grain a transcript's bare integer amounts are rendered at. */
export const TRANSCRIPT_ASSET = 'TEZ';

export const TRANSCRIPT_DECIMALS = ASSET_DECIMALS[TRANSCRIPT_ASSET];
