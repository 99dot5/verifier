# 99dot5 sequencer→rollup wire format

This document specifies everything needed to decode and verify 99dot5's
sequencer messages from the public Tezos L1 inbox, independently of any
99dot5 code. The canonical Rust definition is `libs/smart-rollup-messages`
in the 99dot5 monorepo; the layouts below are frozen on mainnet (schema
changes require a new envelope version, never an in-place edit).

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
  storage at `/tenants/{tenant}/config/sequencer-keys/current` (32 raw
  bytes). During a rotation grace window (≤ 5000 levels) messages may verify
  under the previous key.

## Borsh conventions

Borsh 1.x: integers little-endian fixed-width (`u32` = 4 bytes, `u64` = 8,
`u128` = 16); `String`/`Vec<u8>` are a `u32`-LE length then the bytes;
`[u8; N]` is N raw bytes with no prefix; enums are one `u8` tag (variants
numbered by declaration order from 0) then the variant's fields; structs are
their fields in declaration order. Trailing bytes after a valid value are an
error (the kernel is strict; be strict too).

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

0x01 RoundCreated {
    round_id:          [u8; 16]      -- raw UUID bytes (render hyphenated)
    session_id:        [u8; 16]
    player_address:    String        -- tz1…
    game_type:         String        -- "hilo:v1" | "plinko:v1" | "mines:v1" | "crash:v1" | …
    asset:             String        -- "TEZ"
    stake:             StoredMoney
    client_seed:       String        -- player-supplied
    server_seed_index: u64           -- which committed seed this round claims
    server_seed_hash:  [u8; 32]      -- must equal the committed hash at that index
}

0x02 PlayerAction {
    round_id:       [u8; 16]
    session_id:     [u8; 16]
    action_index:   u64              -- 0 is always "place-bet"
    action_type:    String           -- kebab-case: place-bet / higher / lower /
                                     --   reveal / cashout / abandon / …
    action_payload: Vec<u8>          -- per-game Borsh (see below); empty when payload-free
}

0x03 RoundSettled {
    round_id:        [u8; 16]
    session_id:      [u8; 16]
    server_seed:     String          -- THE REVEAL: 64-char lowercase hex
    asset:           String
    claimed_payout:  StoredMoney
    claimed_outcome: String          -- "win" | "lose" | "cashout" | "push"
}

0x04 EndSession {
    session_id: [u8; 16]
    reason:     EndReason enum -- 0x00 user-requested, 0x01 expired, 0x02 idle-swept
}

StoredMoney struct:
  units: u128   -- base units; mutez for TEZ
  scale: u32    -- 6 for TEZ
```

### Per-game action payloads

- **hilo:v1** — every action (`place-bet`, `higher`, `lower`, `cashout`) is
  payload-free.
- **plinko:v1** — `place-bet` carries `borsh(Config { rows: u32, risk: enum
  u8 (0=low, 1=medium, 2=high) })` (5 bytes); `cashout` is payload-free.
- **mines:v1** — `place-bet` carries `borsh(Config { mine_count: u32 })`
  (4 bytes); `reveal` carries `borsh(tile_index: u32)` (4 bytes); `cashout`
  is payload-free.
- **abandon** (any game) is system-generated: the replay applies all prior
  actions first, then forces the outcome to lose / payout 0.

## The seed-commitment proof

What makes a round provably fair, from inbox data alone:

1. `RoundCreated` carries `server_seed_index` and `server_seed_hash`. Find
   the `SeedBatch` for the same `(tenant_id, pool_id)` with
   `start_index ≤ index < start_index + hashes.len()` and check
   `hashes[index − start_index] == server_seed_hash`.
2. The `SeedBatch`'s L1 level must be **strictly less** than the
   `RoundCreated`'s L1 level (the kernel rejects same-level commitments).
3. `RoundSettled.server_seed` must satisfy
   `blake2b_256(ascii(server_seed)) == server_seed_hash` — the hash is over
   the 64 ASCII hex characters, **not** the 32 bytes they spell.
4. **Not independently verifiable:** how the seed itself was derived. It comes
   from `blake2b_256(b"server-seed" ‖ batch_salt ‖ drand_round_le8 ‖
   drand_randomness ‖ ascii(drand_chain_hash) ‖ i_le8)`, but `batch_salt` is
   private and is never published, so the batch-level derivation cannot be
   re-run by a third party. A `SeedBatchReveal` message once existed to publish
   it; it was never produced or handled and has been removed (its precondition
   was unenforceable — publication to the public inbox *is* the leak).

   Note also that drand does **not** currently prevent the operator grinding
   entropy: the beacon is fetched before the salt is drawn, so the salt is
   chosen with the beacon in hand. Steps 1-3 above are the real guarantee, and
   they hold regardless.

## The payout proof

Outcome derivation per action is
`seed = blake2b_256("game-seed|" + game_type + "|" + server_seed + "|" +
client_seed + "|" + i32_le(action_index))` — the pipes are literal bytes,
and the input set is exactly those four values: **there is no
operator-controlled nonce**. Each game's use of the seed bytes and its
payout rule is specified, with golden vectors, in `vectors/*.json`
(the `algorithm` block of each file).

The settlement rule at the trust boundary: the rollup replays the
transcript, computes the cumulative multiplier in exact integer ppm, and
credits `payout_units = floor(stake.units × cumulative_ppm / 1_000_000)`.
Compare that against `claimed_payout.units` — on mismatch, the rollup
records a discrepancy and credits its own computed value, so the sequencer's
claim is advisory, never authoritative.
