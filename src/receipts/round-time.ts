/**
 * The round's server-signed time, read from the player's receipts.
 *
 * A located run needs to know roughly when the round ended, to start looking
 * for its transcript there. The only clock the verifier trusts for that is the
 * sequencer's own: `CommandAccepted.received_at_unix_ms` and
 * `CommandRejected.received_at_unix_ms`, which the server stamps when a
 * command's bytes arrive and signs with the frame. The latest such stamp
 * before the round's `RoundEnded` (by the server's `sequence`) is the time.
 *
 * Only frames that verify under a key the tenant's lineage registered count,
 * and the `RoundEnded` frame itself must verify too. The export's own
 * `sentAtUnixMs` is the player's client clock, unsigned, and is never read.
 *
 * The result is a hint: it only chooses where the transcript is looked for.
 */
import { decodeEdpk, verifyServerFrameSignature } from '../wire/signature';
import type { KeySet, ReceiptsInput } from '../verifier';
import { decodeReceiptFrame, type ReceiptFrame } from './recompute';

export type SignedRoundTime = { lastMs: number; source: string } | { reason: string };

export function signedRoundTime(receipts: ReceiptsInput | undefined, keys: KeySet): SignedRoundTime {
    if (receipts?.status !== 'ok') {
        return { reason: 'no receipts were read, so there is no server-signed time' };
    }

    if (keys.status !== 'available') {
        return { reason: `no key set authenticates the receipts’ times (${keys.reason})` };
    }

    const publicKeys: Uint8Array[] = [];

    for (const key of keys.keys) {
        try {
            publicKeys.push(decodeEdpk(key.edpk));
        } catch {
            continue;
        }
    }

    if (publicKeys.length === 0) {
        return { reason: 'no key set authenticates the receipts’ times (no admissible key)' };
    }

    const signed = (frame: ReceiptFrame) =>
        publicKeys.some((key) => verifyServerFrameSignature(frame.signature, frame.body, key));
    const document = receipts.receipts;
    let ended: ReceiptFrame;

    try {
        ended = decodeReceiptFrame({
            sequence: 0n,
            payloadCase: 'roundEnded',
            relatedRequestId: null,
            frame: document.roundEndedFrame,
        });
    } catch {
        return { reason: 'the receipts’ RoundEnded frame does not decode' };
    }

    if (ended.envelope.payloadCase !== 'roundEnded' || !signed(ended)) {
        return { reason: 'the receipts’ RoundEnded frame is not signed by a key the tenant registered' };
    }

    let latest: { sequence: bigint; ms: bigint; payloadCase: string } | null = null;

    for (const imported of document.frames) {
        let frame: ReceiptFrame;

        try {
            frame = decodeReceiptFrame(imported);
        } catch {
            continue;
        }

        const { payloadCase, receivedAtUnixMs, sequence } = frame.envelope;

        if (
            (payloadCase !== 'commandAccepted' && payloadCase !== 'commandRejected') ||
            receivedAtUnixMs === null ||
            sequence >= ended.envelope.sequence ||
            (latest !== null && sequence <= latest.sequence) ||
            !signed(frame)
        ) {
            continue;
        }

        latest = { sequence, ms: receivedAtUnixMs, payloadCase };
    }

    if (latest === null) {
        return { reason: 'no signed CommandAccepted or CommandRejected before RoundEnded states when it was received' };
    }

    return {
        lastMs: Number(latest.ms),
        source: `${latest.payloadCase === 'commandAccepted' ? 'CommandAccepted' : 'CommandRejected'} at sequence ${latest.sequence}`,
    };
}
