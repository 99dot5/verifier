# 99dot5 wire formats

This document specifies everything needed to decode and verify 99dot5's
sequencer messages from the public Tezos L1 inbox, independently of any
99dot5 code — plus, at the end, the two off-chain formats the third proof
needs: the **signed server frame** a player's client receives over the
WebSocket, and the **receipts export** that packages them. The canonical Rust definition is `libs/smart-rollup-messages`
in the 99dot5 monorepo; the layouts below are frozen on mainnet (schema
changes require a new envelope version, never an in-place edit).

**A whole round is one message.** `RoundTranscript` carries the round from
`place-bet` to settlement under a single signature. It replaced a
`RoundCreated` + N × `PlayerAction` + `RoundSettled` sequence, and that
replacement renumbered `EndSession` from `0x04` to `0x02`. That break — the
second and final pre-mainnet renumber — was taken only because nothing was
deployed on mainnet and shadownet was re-originated in the same change. If you
have a decoder written against the old three-message shape, it decodes nothing
here.

## Outer framing

Every message the sequencer injects (via the rollup node's batcher, which
packs them into `smart_rollup_add_messages` L1 operations — often several
frames per operation, each decoded independently) is:

```
[0x09 0x95 | 64-byte Ed25519 signature | borsh(VersionedEnvelope)]
```

- `0x09 0x95` is the external-message prefix.
- The signature is `ed25519_sign(blake2b_256(payload))` — the Tezos
  convention of a Blake2b-256 pre-hash, applied explicitly. `payload` is the
  entire Borsh blob that follows, including its leading version byte, so a
  V1 signature cannot be replayed against a future V2.
- The signing key is the tenant's sequencer key. It is set on-chain by the
  administrator contract's `RegisterTenant` internal operation to the rollup
  (`bytes` parameter prefix `0x0100`, then `PACK((slug, key))`) and rotated
  by `RotateSequencerKey` (`0x0105`); the current key lives in rollup durable
  storage at `/tenants/{tenant}/sequencer-keys/current` (32 raw
  bytes). During a rotation grace window (≤ 5000 levels) messages may verify
  under the previous key.

## Borsh conventions

Borsh 1.x: integers little-endian fixed-width (`u32` = 4 bytes, `u64` = 8);
`String`/`Vec<u8>` are a `u32`-LE length then the bytes; `[u8; N]` is N raw
bytes with no prefix; `Vec<T>` is a `u32`-LE count then that many encoded
elements; enums are one `u8` tag (variants numbered by declaration order from
0) then the variant's fields; structs are their fields in declaration order.
Trailing bytes after a valid value are an error (the kernel is strict; be
strict too).

## VersionedEnvelope

```
VersionedEnvelope enum:
  0x00 = V1(PoolScopedMessage)

PoolScopedMessage struct:
  tenant_id: String        -- logical play world, e.g. "99dot5-com-shadownet"
  pool_id:   String        -- liquidity boundary, e.g. "standard"
  payload:   SequencerMessage
```

## SequencerMessage (enum tags in declaration order)

```
0x00 SeedBatch {
    start_index:      u64            -- pool-scoped seed index of hashes[0]
    hashes:           Vec<[u8; 32]>  -- blake2b-256 commitments, one per seed
    drand_round:      u64
    drand_chain_hash: String         -- 64-char hex, ASCII
}

0x01 RoundTranscript {
    round_id:             [u8; 16]   -- raw UUID bytes (render hyphenated)
    session_id:           [u8; 16]
    game_type:            String     -- "hilo:v1" | "plinko:v1" | "mines:v1" | "crash:v1" | …
    stake:                u128       -- atomic units of the session's asset; no scale on the wire
    client_seed:          [u8; 32]   -- blake2b-256 of the player's client-seed TEXT
    server_seed:          [u8; 32]   -- THE REVEAL, raw bytes
    server_seed_index:    u64        -- which committed seed this round claims
    claimed_payout:       u128       -- the sequencer's claim; advisory, never authoritative
    player_commitment:    [u8; 32]   -- blake2b-256 over the round's archived signed player commands (ADR 0022 D1)
    actions:              Vec<TranscriptAction>
}

TranscriptAction struct:
  tag:     u8              -- the global action table below; a BARE u8, not an enum
  payload: Vec<u8>         -- per-game Borsh; empty for payload-free actions

0x02 EndSession {
    session_id: [u8; 16]
    reason:     EndReason enum -- 0x00 user-requested, 0x01 expired, 0x02 idle-swept
}
```

Field order in `RoundTranscript` is header-first: every fixed-width field
precedes the variable-length `actions` vector, so a decoder resolves the round
id, the game type and the seed index before allocating for the body.
`player_commitment` sits immediately after `claimed_payout` and before
`actions` for the same reason — it is fixed-width, so it stays in the header.

`player_commitment` is blake2b-256 over the round's archived signed player
commands (ADR 0022 D1, `docs/adr/0022-signed-play-receipts.md`) — the
complete inbound wire frame for every player command that became a step in
this round, folded in step order. This document only decodes and displays it;
independently recomputing it from the player's own signed commands and
comparing it against this field is a follow-up to this verifier, not
something the checks here do yet.

Both amounts are bare `u128` in atomic units of the session's asset — mutez, at
6 decimal places, for TEZ — read with the `u128()` Borsh reader into a `bigint`.
The width is what lets an 18-decimal asset ride the same layout; the arithmetic
ceiling is the kernel's 96-bit `Decimal` mantissa (about 7.9e28 units), above
which the kernel rejects the transcript with `reject-amount-out-of-range`. The asset itself is never on the wire: it is bound to
the session at its first deposit and the kernel reads it off the session record,
so a transcript cannot name an asset its session does not hold.

**An action's index is its position in `actions`.** Nothing on the wire
restates it, so a decoder that reorders actions silently changes the seed
derivation and the payout. Index 0 is always the `place-bet`.

**Fields you will not find, and where the value comes from instead:** the
player address and the asset come from the rollup's session record, bound at
first deposit; the committed hash comes from the `SeedBatch` at
`server_seed_index`; the outcome is computed by the replay, not claimed.

### The global action table

`tag` indexes one table shared by every game, in two blocks. The numbering is
frozen alongside the V1 wire: never renumber.

**Protocol block, `0x00`–`0x0F`** — actions the protocol itself relies on,
shared by every game that uses them. Five assigned, eleven reserved.

| Tag | `action_type` | Origin | Used by |
|---:|---|---|---|
| `0x00` | `place-bet` | player | every game |
| `0x01` | `cashout` | player | crash, plinko, hilo, mines, hydra |
| `0x02` | `partial-cashout` | system | hilo, mines, hydra (max-win de-lever) |
| `0x03` | `abandon` | system | every game (janitor sweep / force-settle) |
| `0x04` | `expire` | system | crash (deadline sweep on a manual round) |

**Game vocabulary, `0x10` onward** — appended in order of introduction and
shared *by name*: a future game that reveals tiles reuses `reveal` rather than
minting a second tile-reveal tag.

| Tag | `action_type` | Origin | Used by |
|---:|---|---|---|
| `0x10` | `higher` | player | hilo |
| `0x11` | `lower` | player | hilo |
| `0x12` | `reveal` | player | mines |
| `0x13` | `physical-attack` | player | hydra |
| `0x14` | `magic-attack` | player | hydra |
| `0x15` | `drink-potion` | player | hydra |
| `0x16` | `drink-mana` | player | hydra |

When the protocol block fills, further protocol actions continue at the end of
the open range — the block is a reservation for readability, not a structural
boundary.

The tag is a bare `u8`, not a Borsh enum, and deliberately so: an unknown tag
must leave the rest of the transcript decodable, so the kernel can still
resolve the seed, burn it, and write an attributable
`reject-unknown-action-tag` settlement rather than dropping the message
silently. The byte carries no origin bit and is not bit-packed: `isSystem` and
`allowedIn` are table lookups, not range comparisons, because origin and game
membership are properties of the action, not of the number. A tag the table
knows in a game that does not use it is the kernel's separate
`reject-action-not-for-game` class.

### Per-game action payloads

- **hilo:v1** — `place-bet`, `higher`, `lower` and `cashout` are payload-free.
- **plinko:v1** — `place-bet` carries `borsh(Config { rows: u32, risk: enum
  u8 (0=low, 1=medium, 2=high) })` (5 bytes); `cashout` is payload-free.
- **mines:v1** — `place-bet` carries `borsh(Config { mine_count: u32 })`
  (4 bytes); `reveal` carries `borsh(tile_index: u32)` (4 bytes); `cashout`
  is payload-free.
- **crash:v1** — `place-bet` carries `borsh(Config { auto_cashout_tick:
  Option<u32> })` (5 bytes); `cashout` carries a `u32` tick (4 bytes).
- **hydra:v1** — `place-bet` carries `borsh(Config { hero: u8 })` (1 byte).
- **partial-cashout** (hilo, mines, hydra) is system-generated and carries
  `borsh(Payload { amount: u128 })` (16 bytes) — the banked amount in
  atomic units of the session's asset; no scale rides with it, so one banked
  amount has exactly one encoding. It is the largest payload any shipped game
  emits.
- **abandon** (any game) is system-generated: the replay applies all prior
  actions first, then applies the game's abandon policy (crash and plinko
  force lose / 0; the compounding games pay the banked total).

### Size budget

One message must fit in one L1 inbox message. The byte limit is primary and
the action cap is derived from it, not chosen:

```
inbox framing tag                        1 byte    (InboxMessageRepr::External, added by the protocol)
prefix + signature                      66 bytes
largest action-less transcript header  282 bytes  (32-char slugs, 32-byte game_type, two u128 amounts, 32-byte player_commitment)
worst action                            21 bytes  (tag 1 + Vec len 4 + payload 16)
maximum actions per transcript         178
```

The binding limit is the Tezos protocol constant
`smart_rollup_message_size_limit` = 4096. A rollup-node batcher figure of 2050
was cited here for a while; it never had a source and a shadownet measurement
on 2026-09-09 disproved it, so the protocol limit is the only wall.

The first row is the subtle one. The protocol frames every inbox message with a
one-byte tag ahead of our `0x0995` prefix, and the kernel reads at most 4096
bytes of that *framed* message, so the largest payload we can actually put on
the wire is 4095. The cap is `(4096 − 67 − 282) / 21` = 178, and at the cap a
transcript encodes to 4020 bytes — 4086 as the frame we sign and POST, 4087 as
the inbox message the kernel reads.

(`player_commitment` moved the header from 250 to 282 bytes, which moved the
derived cap from 179 to 178 — and, in `libs/sequencer-core`, the sequencer's
earlier trip point from 177 to 176. The 21-byte worst-action figure and the
2-action reserve are unaffected: both are per-action, not header, costs.)

## The seed-commitment proof

What makes a round provably fair, from inbox data alone:

1. `RoundTranscript` carries `server_seed_index`. Find the `SeedBatch` for the
   same `(tenant_id, pool_id)` with
   `start_index ≤ index < start_index + hashes.len()`; the committed hash is
   `hashes[index − start_index]`.
2. `blake2b_256(ascii(lowercase_hex(server_seed)))` must equal that committed
   hash. The commitment is over the **64 ASCII hex characters**, not over the
   32 bytes they spell — hashing the raw bytes gives a different digest, and
   the shared vector file pins both so the mistake fails a test rather than a
   round.
3. The `SeedBatch`'s L1 level must be **strictly less** than the
   `RoundTranscript`'s L1 level (the kernel rejects a same-level commitment).
   Note this compares against the settle-time message, since that is when the
   round reaches L1 at all — the same comparison the kernel makes.
4. Verify the frames' signatures against the tenant's sequencer key. The inbox
   is permissionless, so an unauthenticated `SeedBatch` proves nothing: anyone
   can inject one. Check the transcript **and** the batch it is verified
   against.
5. **Not independently verifiable:** how the seed itself was derived. It comes
   from `blake2b_256(b"server-seed" ‖ batch_salt ‖ drand_round_le8 ‖
   drand_randomness ‖ ascii(drand_chain_hash) ‖ i_le8)`, but `batch_salt` is
   private and is never published, so the batch-level derivation cannot be
   re-run by a third party. A `SeedBatchReveal` message once existed to publish
   it; it was never produced or handled and has been removed (its precondition
   was unenforceable — publication to the public inbox *is* the leak).

   Note also that drand does **not** currently prevent the operator grinding
   entropy: the beacon is fetched before the salt is drawn, so the salt is
   chosen with the beacon in hand. Steps 1-4 above are the real guarantee, and
   they hold regardless.

## The client seed

The wire carries `blake2b_256(client_seed_text)`, not the text. The text is
hashed once, at bet time, and the engine consumes the lowercase hex of those
32 bytes as its client seed. Every proof above works from the hash alone; if
you still have the text you typed, hashing it and comparing against
`client_seed` adds one more link — that the round was played under the seed
you chose.

## The payout proof

Outcome derivation per action is
`seed = blake2b_256("game-seed|" + game_type + "|" + server_seed + "|" +
client_seed + "|" + i32_le(action_index))` — the pipes are literal bytes, and
the input set is exactly those four values: **there is no operator-controlled
nonce**. Both seeds enter as their 64-character lowercase hex, and
`action_index` is the action's position in `actions`. Each game's use of the
seed bytes and its payout rule is specified, with golden vectors, in
`vectors/*.json` (the `algorithm` block of each file).

The settlement rule at the trust boundary: the rollup replays the transcript,
computes the cumulative multiplier in exact integer ppm, and credits
`payout = floor(stake × cumulative_ppm / 1_000_000)`, in the same atomic units.
Compare that against `claimed_payout` — on mismatch, the rollup records a discrepancy
and credits its own computed value, so the sequencer's claim is advisory,
never authoritative. There is no claimed outcome on the wire at all: the
outcome is whatever the replay produces.

## Cross-language vectors

`vectors/wire-vectors.json` is generated by an independent Python Borsh writer
and asserted by the Rust wire crate and by this verifier's tests. It pins the
action table, both hashing rules, and a full set of `RoundTranscript`
encodings. Each transcript entry carries a `source` field: `"synthetic"` for a
hand-built fixture, `"captured"` for bytes taken from a real injection. A
synthetic vector cannot catch a decoder drifting from what the sequencer
actually emits, because the fixture is written by the same understanding it is
meant to check — so the label is load-bearing, not decoration.


---

# The signed server frame (ADR 0022)

Every frame the sequencer sends over the player WebSocket carrying a
`ServerEnvelope` is signed at send:

```
[ 0x06 | 64-byte Ed25519 signature | protobuf(casino.v1.ServerEnvelope) ]
```

`0x06` is the tag server envelopes have always used — ADR 0022 changed the
body, not the value, and minted no second tag. `Welcome` (`0x02`) and
`HandshakeRejected` (`0x03`) stay unsigned: they are pre-session, carry no
sequence and have nothing to replay.

The signature is

```
sig = ed25519( blake2b-256( RECEIPT_DOMAIN ‖ protobuf ), tenant_sequencer_key )
RECEIPT_DOMAIN = ASCII "99dot5:server-frame:v1"
                = 3939646f74353a7365727665722d6672616d653a7631
```

**The domain prefix is not optional.** The tenant sequencer key signs both
these frames and the rollup inbox messages above, through the identical
`ed25519(blake2b-256(bytes))` chain — the prefix is the only thing that stops a
signature harvested from one channel being presented as valid on the other.
The inbox side hashes the payload with **no** prefix.

Player commands travel the other way as

```
[ 0x05 | 64-byte Ed25519 signature | protobuf(casino.v1.ClientEnvelope) ]
```

signed by the **session** key, with **no** domain prefix — the session key
signs this one channel only, so there is no second channel to separate it
from. These are the frames the commitment below is taken over.

## The player commitment

```
preimage = u32-LE frame_count ‖ for each frame: u32-LE byte_length ‖ frame_bytes
commitment = blake2b-256(preimage)
```

Each element is a **whole command frame** — tag byte, signature and protobuf
body, exactly as sent — so the commitment binds the signatures too, and a
re-concatenation from split fields that differs by one byte produces a digest
the player cannot reproduce.

The length prefixes give the preimage a unique decomposition: a bare
concatenation collides, since `["ab", "c"]` and `["a", "bc"]` are the same
bytes. `vectors/receipt-vectors.json` pins exactly that pair, along with the
empty case (which is why the count leads).

The server folds the round's archived command rows in step-index order; a
client or verifier holds sent commands and received frames instead, and
reconstructs the same order from the server's own signed statements:

1. **Scope** the commands to the round through `related_request_id` — a
   command no frame of the round names is out of scope, not ambiguous
   (`EndSession` is the concrete case).
2. **Dedup** by `request_id`, keeping the first send: an idempotent retry sends
   the same frame twice and the server archives one row.
3. **Keep** only commands a `CommandAccepted` frame acknowledges. Never infer
   acceptance from a missing `CommandRejected` — rejections are ephemeral.
4. **Order** by the server's index: `RoundUpdatedEvent.action_index` and
   `RoundEndedEvent.action_index`; the opening bet is index 0 by construction.
   A `RoundUpdated` whose `origin` is `STEP_ORIGIN_SYSTEM` occupies an index
   but binds no command — it is the max-win de-lever's own step, and it has no
   archived command behind it.
5. **Decline** on any residual ambiguity. A holder who cannot see the whole
   round must never accuse the server of a mismatch it cannot substantiate.

# The receipts export

```jsonc
{
  "schema": "99dot5.receipts.v1",
  "tenantId": "…", "poolId": "…",
  "sessionIdHex": "…", "roundIdHex": "…",
  "sequencerPublicKey": "edpk…",
  "sessionPublicKey": "edpk…",
  "depositOperationLevel": 4100000,   // optional
  "commands": [{ "requestId": "…", "payloadCase": "placeBet",
                 "frameHex": "05…", "sentAtUnixMs": 1700000000000 }],
  "frames":   [{ "sequence": "3", "payloadCase": "roundStarted",
                 "relatedRequestId": "…", "frameHex": "06…" }],
  "roundEndedFrameHex": "06…"
}
```

- `frames` MUST include the round's `CommandAccepted` and `RoundUpdated`
  frames, not only the outcome-bearing ones: step 2 above reads the former as
  the acceptance signal and step 4 the latter as the ordering key, so an export
  that keeps only `RoundStarted`/`RoundEnded` makes the reconstruction
  unavailable by construction.
- `SessionResumed` frames are **excluded**: their `sequence` is the session's
  `last_sequence` and collides with a real persisted frame's.
- `sentAtUnixMs` is a readability hint, never a verdict input — ordering comes
  from the server's index and the on-chain bracket from L1.
- `depositOperationLevel` is a hint too, and the **shipped client never writes
  one**. The verifier derives the bound itself: it asks the indexer for
  `deposit` calls to the pool's vault (from the lineage's `RegisterPoolVault`)
  whose `session_id` parameter is the session id read out of the signed frames,
  and takes the lowest level. A hint that is present is cross-checked against
  that and reported, never substituted for it.
- Every other label is re-derived from the signed frame bytes; a disagreement
  is a reportable finding, not an accepted value.

`vectors/receipts-export-fixture.json` carries whole documents written by the
play client's own export path, together with the fields a verifier must read
back out of each frame and the reconstruction each document should produce —
including one case that is `unavailable` on purpose.

# The administrator lineage

The tenant's signing keys are not configured anywhere; they are read off L1.
Internal transactions to the rollup address carry
`[0x01 | subtag | Michelson PACK]`, and five subtags matter here:

| Subtag | Message | PACK |
|---|---|---|
| `0x00` | `RegisterTenant` | `(string slug, key sequencer_public_key)` |
| `0x01` | `RegisterPoolVault` | `(string tenant, string pool, address vault, string status)` |
| `0x05` | `RotateSequencerKey` | `(string tenant, key new_public_key, nat grace_levels)` |
| `0x07` | `ProposeAdminContract` | `(address new_admin)` |
| `0x08` | `ActivateAdminContract` | *(no payload — the whole message is two bytes)* |

The PACK encoding needed to read them is small: `05` prefix; `07 07` for a
`Pair` (an n-tuple is a right comb of them); `01 <u32 BE len> <utf8>` for a
string; `0a <u32 BE len> <bytes>` for bytes; `00 <zarith>` for a nat. A packed
`key` is 33 bytes — curve tag `00` then 32 raw Ed25519 bytes, and only tag `00`
is admissible, because the rollup drops every other curve. A packed originated
`address` is 22 bytes: `01 ‖ 20-byte hash ‖ 00`.

The zarith is **signed**: the first byte carries a sign bit at `0x40` and six
value bits, every later byte seven, little-endian by group, with `0x80` as the
continuation flag. `int` and `nat` share the encoding, so reading a nat as
unsigned-from-the-first-byte shifts every value silently.

Walk forward from the pinned origination administrator: collect the keys each
administrator registered, follow a proposal only when the proposed contract
itself sent a `0x08`, and keep **every** key ever registered rather than the
currently-valid one. The kernel's grace window governs admission of new
messages; a verifier checks historical evidence, and a receipt signed under a
key that was valid at delivery stays valid evidence forever.
