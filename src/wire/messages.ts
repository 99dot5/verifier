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
 * SeedBatch=0x00, RoundCreated=0x01, PlayerAction=0x02, RoundSettled=0x03,
 * EndSession=0x04.
 *
 * NOTE: `EndSession` was 0x05 until the never-implemented `SeedBatchReveal`
 * was removed from the schema pre-mainnet, freeing 0x04. This decoder must
 * track `libs/smart-rollup-messages/src/v1.rs`, where the tags are pinned by
 * `sequencer_message_discriminants_are_frozen`.
 */
import { BorshError, BorshReader } from './borsh';
import { bytesToHex } from '../verify/seed';

export interface StoredMoney {
    /** Base units (mutez for TEZ: scale 6). */
    units: bigint;
    scale: number;
}

export type SequencerMessage =
    | {
          kind: 'seed-batch';
          startIndex: bigint;
          hashes: Uint8Array[];
          drandRound: bigint;
          drandChainHash: string;
      }
    | {
          kind: 'round-created';
          roundId: string;
          sessionId: string;
          playerAddress: string;
          gameType: string;
          asset: string;
          stake: StoredMoney;
          clientSeed: string;
          serverSeedIndex: bigint;
          serverSeedHash: Uint8Array;
      }
    | {
          kind: 'player-action';
          roundId: string;
          sessionId: string;
          actionIndex: bigint;
          actionType: string;
          actionPayload: Uint8Array;
      }
    | {
          kind: 'round-settled';
          roundId: string;
          sessionId: string;
          serverSeed: string;
          asset: string;
          claimedPayout: StoredMoney;
          claimedOutcome: string;
      }
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

function readStoredMoney(reader: BorshReader): StoredMoney {
    return { units: reader.u128(), scale: reader.u32() };
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
            const hashCount = reader.u32();
            const hashes = Array.from({ length: hashCount }, () => reader.fixedBytes(32));

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
            message = {
                kind: 'round-created',
                roundId: uuidFromBytes(reader.fixedBytes(16)),
                sessionId: uuidFromBytes(reader.fixedBytes(16)),
                playerAddress: reader.string(),
                gameType: reader.string(),
                asset: reader.string(),
                stake: readStoredMoney(reader),
                clientSeed: reader.string(),
                serverSeedIndex: reader.u64(),
                serverSeedHash: reader.fixedBytes(32),
            };
            break;
        case 0x02:
            message = {
                kind: 'player-action',
                roundId: uuidFromBytes(reader.fixedBytes(16)),
                sessionId: uuidFromBytes(reader.fixedBytes(16)),
                actionIndex: reader.u64(),
                actionType: reader.string(),
                actionPayload: reader.byteVec(),
            };
            break;
        case 0x03:
            message = {
                kind: 'round-settled',
                roundId: uuidFromBytes(reader.fixedBytes(16)),
                sessionId: uuidFromBytes(reader.fixedBytes(16)),
                serverSeed: reader.string(),
                asset: reader.string(),
                claimedPayout: readStoredMoney(reader),
                claimedOutcome: reader.string(),
            };
            break;
        case 0x04: {
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
