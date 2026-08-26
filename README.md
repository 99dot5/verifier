# 99dot5 round verifier — the minimal verifiable set

This repository is the **minimal verifiable set** for
[99dot5](https://99dot5.com) rounds: everything needed to independently
prove, from public Tezos L1 data alone, that a round's payout was computed
correctly **and** that its random seed was committed on-chain before the
round existed.

It is exported automatically from the 99dot5 monorepo as readable source —
never a built bundle, because a minified artifact reintroduces exactly the
trust this tool exists to remove.

## What's here

| Path | What it is |
|---|---|
| `vectors/*.json` | Golden test vectors for `hilo:v1`, `plinko:v1`, `mines:v1`, `crash:v1`. Each file carries a complete, self-contained `algorithm` spec plus vectors, reproducible by any runtime in exact integer arithmetic (no floats anywhere). These are the SAME files the production Rust engine and the wasm rollup kernel pin against. |
| `src/verify/` | TypeScript implementations of the game algorithms (pure `bigint`), asserted against the vectors by the test suite. |
| `src/wire/` | Decoder for the sequencer→rollup wire format (Borsh) and Ed25519 signature verification (`ed25519(blake2b-256(payload))`), pinned by a golden message captured from a real on-chain injection. |
| `src/chain/` | Readers for public chain sources: TzKT (locates `smart_rollup_add_messages` operations) and a Tezos archive node RPC (supplies the message bytes). |
| `src/verifier.ts` | The orchestrator: gathers a round's messages, proves the seed commitment ordering, replays the game, recomputes the payout. |
| `index.html`, `src/main.ts`, `src/styles.css` | The verifier web app itself — the page this repository deploys to GitHub Pages. |
| `.github/workflows/deploy-pages.yml` | The Pages deployment. It living here is the provenance story (see below). |
| `docs/wire-format.md` | Byte-level wire specification — enough to re-implement all of this from scratch in any language. |

## The hosted verifier, and why you can trust it

This repository deploys itself to GitHub Pages. That hosting choice is
deliberate: the Pages deployment records the exact commit it was built from,
the workflow that built it is this repo's own
`.github/workflows/deploy-pages.yml`, and the build log is public — so "the
page you are using came from the source you can read" is checkable by
anyone, not taken on faith. The build is **unminified**
(`vite.config.ts`), so the JavaScript your browser runs is directly
diffable against `src/`.

Prefer not to trust even that? Run it yourself:

```bash
npm install
npm run dev    # local verifier at http://localhost:5173
```

## Run the tests

```bash
npm install
npm test       # asserts the TS implementations against every golden vector
```

## The two proofs

1. **Payout** — outcome derivation is
   `blake2b-256("game-seed|<game_type>|<server_seed>|<client_seed>|<i32 LE action_index>")`.
   The input set is exactly those four values: there is **no
   operator-controlled nonce**. The transcript of actions is public in the
   L1 inbox; replaying it yields a cumulative multiplier in integer ppm, and
   `payout = floor(stake_units × ppm / 10⁶)`.
2. **Commitment** — the `server_seed`'s hash was published in a `SeedBatch`
   inbox message at an L1 level strictly before the round's `RoundCreated`,
   and the seed revealed at settlement hashes back to it
   (`blake2b-256` over the ASCII hex string). Seeds are derived from
   [drand](https://drand.love) public randomness plus a per-batch salt, so
   the operator cannot grind entropy.

A payout check without the commitment check is only arithmetic: a correct
payout could still come from a seed chosen after seeing the player's
actions. Both halves must hold.

## Trust posture

- Read the chain through **any** indexer and archive node — the verifier
  app defaults to public third-party endpoints (TzKT, rpc.tzkt.io) and every
  endpoint is user-configurable. No 99dot5 infrastructure is in the trust
  path.
- The sequencer public key used for signature checks is itself set on-chain
  (administrator contract `RegisterTenant` / `RotateSequencerKey` internal
  operations to the rollup), so the full chain of trust is derivable from
  L1.
- The Tezos smart rollup independently replays every round with the revealed
  seed and credits **its own** computed payout — the sequencer's claim is
  advisory. This repository lets you check the same thing the rollup checks.

## Provenance

Exported from the 99dot5 monorepo by its CI (`publish-verifier` workflow) as
a fresh tree — file contents are reproducible from the monorepo at the
exporting commit, recorded in `EXPORT_COMMIT`.
