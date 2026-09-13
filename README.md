# 99dot5 round verifier — the minimal verifiable set

This repository is the **minimal verifiable set** for
[99dot5](https://99dot5.com) rounds: everything needed to independently
prove, from public Tezos L1 data alone, that a round's payout was computed
correctly, that its random seed was committed on-chain before the round
existed, and — if you bring your own play receipts — that the round L1
replayed is the one built from the commands **you** authorised.

It is exported automatically from the 99dot5 monorepo as readable source —
never a built bundle, because a minified artifact reintroduces exactly the
trust this tool exists to remove.

## What's here

| Path | What it is |
|---|---|
| `vectors/*.json` | Golden test vectors for `hilo:v1`, `plinko:v1`, `mines:v1`, `crash:v1`. Each file carries a complete, self-contained `algorithm` spec plus vectors, reproducible by any runtime in exact integer arithmetic (no floats anywhere). These are the SAME files the production Rust engine and the wasm rollup kernel pin against. |
| `src/verify/` | TypeScript implementations of the game algorithms (pure `bigint`), asserted against the vectors by the test suite. |
| `src/wire/` | Decoder for the sequencer→rollup wire format (Borsh) and Ed25519 signature verification (`ed25519(blake2b-256(payload))`), pinned by a golden message captured from a real on-chain injection. |
| `src/chain/` | Readers for public chain sources: TzKT (locates `smart_rollup_add_messages` operations), a Tezos archive node RPC (supplies the message bytes), the **administrator lineage walk** (derives the tenant's signing keys from L1), and the deposit lookup that derives the scan's lower bound from L1. |
| `src/receipts/` | Importing a player's exported receipts, and reconstructing a round's `player_commitment` from them. A port of the play client's own algorithm, held to it by the shared fixture. |
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

## Where the signing keys come from

Nothing here pins a sequencer public key, because a key legitimately rotates.
What is pinned, per rollup deployment in `src/chain/networks.json`, is the
**origination administrator**: the `KT1` administrator contract the rollup was
originated against, and the level it was originated at. A re-origination
appends a deployment and marks the old one `retired` — never overwrites it —
so rounds from an earlier rollup stay verifiable; this repository's commit
history of that file is the record of every anchor ever published. From that root the verifier walks
forward over TzKT:

- `ProposeAdminContract` (`0x0107`) names a successor administrator;
- `ActivateAdminContract` (`0x0108`), sent by the successor itself, completes
  the hand-over — a successor that never sent one is **not** in the lineage,
  and the report says so;
- `RegisterTenant` (`0x0100`) and `RotateSequencerKey` (`0x0105`) carry the
  keys, each with the level and operation hash that registered it.

The resulting key set is **historical, not current**: every key any
administrator in the lineage ever registered for the tenant. The kernel's grace
window governs which key may sign *new* inbox messages; a verifier checks
*evidence*, and a receipt signed under a key that was valid when it was
delivered stays valid forever. The UI's key field is an **override** — leave it
empty and the set is derived; type one and the report says a match proves only
that *that* key signed the bytes.

The anchor is the one value you have to take from this file. That is what a
trust anchor is: cross-check it against the origination ceremony, or point the
walk at a different root.

## The three proofs

1. **Payout** — outcome derivation is
   `blake2b-256("game-seed|<game_type>|<server_seed>|<client_seed>|<i32 LE action_index>")`.
   The input set is exactly those four values: there is **no
   operator-controlled nonce**. The transcript of actions is public in the
   L1 inbox; replaying it yields a cumulative multiplier in integer ppm, and
   `payout = floor(stake_units × ppm / 10⁶)`.
2. **Commitment** — the `server_seed`'s hash was published in a `SeedBatch`
   inbox message at an L1 level strictly before the round's own message (a
   round reaches L1 as ONE `RoundTranscript`, written when it settles — there
   is no `RoundCreated` any more, ADR 0020 — so the comparison is against the
   settle level, which is exactly the comparison the kernel makes),
   and the seed revealed at settlement hashes back to it
   (`blake2b-256` over the ASCII hex string). Seeds are derived from
   [drand](https://drand.love) public randomness plus a per-batch salt, so
   the operator cannot grind entropy.

3. **Your commands** — load the receipts your game client exported
   (`"schema": "99dot5.receipts.v1"`, see below). The verifier checks every
   frame in them against the lineage keys, rebuilds the round's
   `player_commitment` from the commands you signed, and compares it with the
   one **on chain**. Without this the transcript's commitment is a number the
   server chose; with it, a server that swapped, dropped or invented one of
   your commands cannot match it.

A payout check without the commitment check is only arithmetic: a correct
payout could still come from a seed chosen after seeing the player's
actions. A payout check without your receipts is only a check that the
operator is consistent with itself. All three must hold before the verdict
reads **VERIFIED**.

## The verdicts

Seven, and they are not interchangeable — four of them are different reasons
the tool is *not* alleging anything, and collapsing any two would either hide a
finding or manufacture one.

| Verdict | Means |
|---|---|
| `verified` | Every proof ran and passed. |
| `attested` | Checked, but weakly: your receipts could not be reconstructed (a peer tab held part of the round, say), so only the server's own signed statement was compared against the chain. |
| `inconclusive` | You did not look far enough. The scanned level range does not bracket the round; widening it may change the answer. |
| `undetermined` | Cannot tell yet. The round is not on chain and nothing shows the operator moved past it — a transcript sitting in the outbox looks exactly like this. |
| `suppressed` | Your receipts are valid, the round is not on chain, and this session's `EndSession` *is*. The one accusatory verdict. |
| `incomplete` | A proof had no inputs — including a round with no transcript and no receipts behind it. |
| `failed` | A proof ran and did not hold. |

`suppressed` is deliberately hard to reach, and the ladder to it is fixed.

**Without receipts, a round with no transcript on chain stops at
`incomplete`.** There is nothing to allege on behalf of a round nobody can
show receipts for. Receipts whose signed `RoundEnded` names a *different*
round stop there too — a relabelled export is evidence about some other round,
and the export's `roundId` label is never the attribution — as do receipts
whose reconstruction could not run.

**The only injector-progress evidence is an `EndSession` of the same
session.** The injector's `claim_unsent` orders `BY id`, so a later outbox row
of this session on L1 proves it drained past this round's row and chose not to
publish it. Only the `EndSession` is provably later: the WS end path refuses
while any round of the session is in progress, and the janitor settles every
in-progress round before the session-terminal write and bails if a settle
failed, so its outbox row id is strictly greater than every transcript row of
the session.

**A sibling round's transcript is NOT enough.** It is reported as a finding —
"a sibling round's transcript is on chain, but the receipts cannot order it
against this round" — and the verdict stays `undetermined`. A session that
played round 1 (published) and then round 2 (still sitting in the outbox)
would otherwise read as suppression of round 2, manufactured out of ordinary
latency.

There is also **no minimum-age fallback**: an age threshold is a guess about
drain latency dressed up as evidence, and a guess must not stand behind the
one accusatory verdict this tool can reach.

The bracket's lower bound is L1-anchored and derived rather than supplied: the
verifier locates the session's **first deposit** itself, by asking the indexer
for `deposit` calls to the pool's vault whose `session_id` parameter is the
session id read out of your signed frames. No round of the session can precede
it. The report always states the scanned range, the bracketing evidence and
the injector-progress evidence, so you can judge which case you are in rather
than taking the label on trust.

## The receipts export

The document the play client writes, and this verifier reads:

```jsonc
{
  "schema": "99dot5.receipts.v1",
  "tenantId": "…", "poolId": "…",
  "sessionIdHex": "…", "roundIdHex": "…",
  "sequencerPublicKey": "edpk…",      // the key your client held
  "sessionPublicKey": "edpk…",        // the key your commands are signed under
  "depositOperationLevel": 4100000,   // optional hint, confirmed against L1
  "commands": [
    { "requestId": "…", "payloadCase": "placeBet",
      "frameHex": "05…",              // [0x05 | 64-byte signature | protobuf]
      "sentAtUnixMs": 1700000000000 } // a readability hint, never a verdict input
  ],
  "frames": [
    { "sequence": "3", "payloadCase": "roundStarted", "relatedRequestId": "…",
      "frameHex": "06…" }             // [0x06 | 64-byte signature | protobuf]
  ],
  "roundEndedFrameHex": "06…"
}
```

Two things about it are worth stating plainly.

**Nothing in it is trusted.** Every label — the payload case, the related
request id, even the round id — is re-derived from the signed frame bytes, and
a disagreement is reported as a finding rather than accepted. Attribution of a
command to a round is reconstructed through the signed `related_request_id`
chain, so relabelling an export cannot change a verdict.

**The document is not signed, on purpose.** Every frame in it is already signed
by the tenant and every command by your session key. Signing the container
would imply the container is the evidence; it is not — the frames are.

## Trust posture

- Read the chain through **any** indexer and archive node — the verifier
  app defaults to public third-party endpoints (TzKT, rpc.tzkt.io) and every
  endpoint is user-configurable. No 99dot5 infrastructure is in the trust
  path.
- The sequencer public keys used for signature checks are derived from L1, not
  configured here — see "Where the signing keys come from". The only pinned
  value is the origination administrator, and it is pinned because a lineage
  walk needs a root that cannot itself be derived.
- The **session key** your commands verify under comes from the export, so that
  half proves your receipts are internally consistent with the key your client
  used — not that L1 bound that key to the session. The binding lives in the
  vault contract's `sessions` big_map; this build does not read it.
- The Tezos smart rollup independently replays every round with the revealed
  seed and credits **its own** computed payout — the sequencer's claim is
  advisory. This repository lets you check the same thing the rollup checks.

## Provenance

Exported from the 99dot5 monorepo by its CI (`publish-verifier` workflow) as
a fresh tree — file contents are reproducible from the monorepo at the
exporting commit, recorded in `EXPORT_COMMIT`.
