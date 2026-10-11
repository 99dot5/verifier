# @99dot5/round-replay

**This source is PUBLIC.** The library ships inside the published round verifier, so nothing in it may carry internal references: no links to internal procedures, no ticket numbers, no ops detail, no private hostnames. Write every comment for an outside reader who has only this library, the round verifier and the chain.

The library recomputes a settled round from its on-chain `RoundTranscript`. It holds bigint ports of each game engine, the transcript wire decoder, and `replayTranscript`, the one rule for which actions of a transcript are replayed. Each engine is pinned to its game's golden `vectors.json`, and the decoder to the shared wire vectors.

```ts
import { decodeExternalMessage, replayTranscript } from '@99dot5/round-replay';
```

## Layout: one port per game version

The ports mirror the Rust engines in `libs/games/src/<game>/v<N>/`. Each game version is its own file, `src/verify/<game>/v<N>.ts`, and `src/verify/<game>.ts` lists the game's versions (`export * as v1 from './crash/v1';`). The barrel exports each game as a namespace, so a consumer writes `crash.v1.replay` or `hilo.v1.GAME_TYPE`. Helpers shared across games and versions (`seed.ts`, `ints.ts`, `partial-cashout.ts`, `types.ts`, `constants.ts`) stay in `src/verify/`.

**A launched port is frozen like its engine.** A round that settled under `crash:v1` must replay under the same rules forever, so a rule change never edits `v1.ts`. It is a new `src/verify/<game>/v<N>.ts` pinned to its own `libs/games/src/<game>/v<N>/testdata/vectors.json`, a `REPLAYERS` entry and a `GAME_SEED_DERIVATIONS` entry for `<game>:v<N>`, and a `v<N>` line in `src/verify/<game>.ts`. `src/layout.test.ts` fails when a `REPLAYERS` key has no port file, or a port file on disk is missing from either table.
