/**
 * Decoder for the sequencer→rollup external message wire format, mirroring
 * `libs/smart-rollup-messages` (the single source of truth for the schema):
 *
 *     [0x09 0x95 | 64-byte Ed25519 signature | borsh(VersionedEnvelope)]
 *
 * where `VersionedEnvelope::V1(PoolScopedMessage { tenant_id, pool_id,
 * payload: SequencerMessage })`. The borsh blob's leading byte is the schema
 * version (0x00 = V1) and the signature covers the WHOLE blob including that
 * byte. `SequencerMessage` variant tags follow Borsh declaration order:
 * SeedBatch=0x00, RoundTranscript=0x01, EndSession=0x02.
 *
 * NOTE ON THE TAGS. This is the schema's SECOND and FINAL pre-mainnet
 * renumber. `RoundCreated` (0x01), `PlayerAction` (0x02) and `RoundSettled`
 * (0x03) were deleted and replaced by one `RoundTranscript` carrying a whole
 * round under a single signature, which renumbered `EndSession` from 0x04 to
 * 0x02. That break was taken only because nothing was deployed on mainnet and
 * shadownet was re-originated in the same change. After origination the only
 * moves are appending a variant or adding a v2 schema, so this decoder tracks
 * `libs/smart-rollup-messages/src/v1.rs`, where the tags are pinned by
 * `sequencer_message_discriminants_are_frozen`.
 */
import { BorshError, BorshReader } from './borsh';
import { actionTypeOf } from './action-tags';
import { bytesToHex } from '../verify/seed';

/**
 * One entry in a round transcript. `tag` is the raw wire byte; `actionType` is
 * its kebab-case name, or null when this decoder does not know the tag — the
 * kernel behaves the same way, decoding the transcript in full and rejecting
 * the round rather than dropping an undecodable message.
 */
export interface TranscriptActionWire {
    tag: number;
    actionType: string | null;
    /** Raw Borsh action payload — empty for payload-free actions. */
    payload: Uint8Array;
}

export interface RoundTranscriptMessage {
    kind: 'round-transcript';
    roundId: string;
    sessionId: string;
    gameType: string;
    /** Atomic units of the session's asset — mutez, at 6 dp, for TEZ. The asset is not on the wire; the kernel reads it off the session record. */
    stake: bigint;
    /** blake2b-256 of the player's client-seed text; the engine consumes its lowercase hex. */
    clientSeed: Uint8Array;
    /** The revealed seed, raw. The commitment is over its 64 ASCII hex characters. */
    serverSeed: Uint8Array;
    serverSeedIndex: bigint;
    /** The sequencer's claim, in the same atomic units as `stake`. The kernel credits its own recomputed payout, never this. */
    claimedPayout: bigint;
    /**
     * blake2b-256 over the round's archived signed player commands (ADR
     * 0022 D1). Decoded and displayed here; verifying it against the
     * signed-command archive is a later verifier PR, not this one.
     */
    playerCommitment: Uint8Array;
    actions: TranscriptActionWire[];
}

export type SequencerMessage =
    | {
          kind: 'seed-batch';
          startIndex: bigint;
          hashes: Uint8Array[];
          drandRound: bigint;
          drandChainHash: string;
      }
    | RoundTranscriptMessage
    | {
          kind: 'end-session';
          sessionId: string;
          reason: 'user-requested' | 'expired' | 'idle-swept';
      };

export interface DecodedEnvelope {
    tenantId: string;
    poolId: string;
    message: SequencerMessage;
    /** The 64-byte Ed25519 signature from the frame. */
    signature: Uint8Array;
    /** The full borsh(VersionedEnvelope) blob the signature covers. */
    signedPayload: Uint8Array;
}

export const EXTERNAL_MESSAGE_PREFIX = [0x09, 0x95] as const;

const END_REASONS = ['user-requested', 'expired', 'idle-swept'] as const;

/** Render 16 raw UUID bytes in the canonical hyphenated form. */
export function uuidFromBytes(bytes: Uint8Array): string {
    const hex = bytesToHex(bytes);

    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function readTranscriptAction(reader: BorshReader): TranscriptActionWire {
    const tag = reader.u8();

    return { tag, actionType: actionTypeOf(tag), payload: reader.byteVec() };
}

/**
 * Decode one external inbox message. Returns null (rather than throwing) for
 * frames that are simply not sequencer messages — wrong prefix or too short —
 * so callers can scan a mixed inbox; malformed sequencer frames throw.
 */
export function decodeExternalMessage(bytes: Uint8Array): DecodedEnvelope | null {
    if (bytes.length < 2 + 64 + 1 || bytes[0] !== EXTERNAL_MESSAGE_PREFIX[0] || bytes[1] !== EXTERNAL_MESSAGE_PREFIX[1]) {
        return null;
    }

    const signature = bytes.slice(2, 66);
    const signedPayload = bytes.slice(66);
    const reader = new BorshReader(signedPayload);
    const version = reader.u8();

    if (version !== 0x00) {
        throw new BorshError(`unknown VersionedEnvelope tag: 0x${version.toString(16)}`);
    }

    const tenantId = reader.string();
    const poolId = reader.string();
    const tag = reader.u8();
    let message: SequencerMessage;

    switch (tag) {
        case 0x00: {
            const startIndex = reader.u64();
            const hashes = reader.vec(() => reader.fixedBytes(32));

            message = {
                kind: 'seed-batch',
                startIndex,
                hashes,
                drandRound: reader.u64(),
                drandChainHash: reader.string(),
            };
            break;
        }
        case 0x01:
            // Field order is header-first: every fixed-width field precedes
            // the variable-length actions vector, so the round id, game type
            // and seed index resolve before anything is allocated for the
            // body.
            message = {
                kind: 'round-transcript',
                roundId: uuidFromBytes(reader.fixedBytes(16)),
                sessionId: uuidFromBytes(reader.fixedBytes(16)),
                gameType: reader.string(),
                stake: reader.u128(),
                clientSeed: reader.fixedBytes(32),
                serverSeed: reader.fixedBytes(32),
                serverSeedIndex: reader.u64(),
                claimedPayout: reader.u128(),
                playerCommitment: reader.fixedBytes(32),
                actions: reader.vec(() => readTranscriptAction(reader)),
            };
            break;
        case 0x02: {
            const sessionId = uuidFromBytes(reader.fixedBytes(16));
            const reasonTag = reader.u8();
            const reason = END_REASONS[reasonTag];

            if (reason === undefined) {
                throw new BorshError(`unknown EndReason tag: ${reasonTag}`);
            }

            message = { kind: 'end-session', sessionId, reason };
            break;
        }
        default:
            throw new BorshError(`unknown SequencerMessage tag: 0x${tag.toString(16)}`);
    }

    reader.expectEnd();

    return { tenantId, poolId, message, signature, signedPayload };
}
