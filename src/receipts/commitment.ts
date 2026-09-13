/**
 * The player commitment over a round's signed command frames (ADR 0022 D1).
 *
 * Preimage, byte for byte:
 *
 *   u32-LE frame count ‖ for each frame: u32-LE byte length ‖ frame bytes
 *
 * then blake2b-256 of that. The length prefixes give the preimage a unique
 * decomposition — a bare concatenation collides (`["ab","c"]` and `["a","bc"]`
 * hash alike) — and the leading count carries the empty case, which a
 * length-prefixed list alone cannot distinguish from no list at all.
 *
 * Each element is a WHOLE frame — tag byte, session-key signature and protobuf
 * body — so the commitment binds the signatures too, and a re-concatenation
 * from split fields that differs by one byte produces a hash the player cannot
 * reproduce. That is why the export carries whole frames.
 *
 * `sequencer_core::commitment::compute` owns the rule; this is the third
 * independent implementation of it (the server's, the play client's, and this
 * one), and all three are pinned to the same bytes by the shared vectors in
 * `libs/proto-definitions/testdata/receipt-vectors.json`.
 */
import { blake2b } from '@noble/hashes/blake2.js';

export function computeCommitment(frames: Uint8Array[]): Uint8Array {
    let total = 4;

    for (const frame of frames) {
        total += 4 + frame.length;
    }

    const preimage = new Uint8Array(total);
    const view = new DataView(preimage.buffer);

    view.setUint32(0, frames.length, true);

    let offset = 4;

    for (const frame of frames) {
        view.setUint32(offset, frame.length, true);
        offset += 4;

        preimage.set(frame, offset);
        offset += frame.length;
    }

    return blake2b(preimage, { dkLen: 32 });
}
