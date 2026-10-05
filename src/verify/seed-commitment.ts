/**
 * The seed-commitment proofs (ADR 0025, issue 1234): WHICH committed seed a
 * round was settled against, and WHEN the server chose it.
 *
 * The on-chain proof shows that the revealed seed was committed at an earlier
 * level. It says nothing about which of the pool's hundreds of pending seeds
 * the sequencer picked for this round — and the kernel accepts any of them,
 * deliberately, because claim order is not on chain and an honest round's
 * lifetime is unbounded. A sequencer that knew the player's client seed at
 * bet time could therefore evaluate it against every pending seed and claim
 * the worst one, and every such round would replay clean. These two checks
 * are what close that off chain, from the player's own receipts:
 *
 *  - **opener binding** — the server-signed `RoundStarted.server_seed_commitment`
 *    must be the commitment of the seed the transcript reveals.
 *    Stated before the outcome was shown, this binds the round to one
 *    commitment and refuses a transcript that reveals any other seed: the
 *    post-bet swap, closed outright.
 *  - **pre-bet commitment** — the player-signed `PlaceBet.server_seed_hash`
 *    must be that same commitment. A client can only echo a hash it was told,
 *    so a signed echo equal to the revealed seed's commitment proves the
 *    server named the seed BEFORE it received the bet — and with it, the
 *    client seed it would have needed to grind against. This is the proof
 *    that matters; the opener binding alone is the server agreeing with
 *    itself after the fact.
 *
 * **Missing evidence is incomplete.** An export without the opener or bet
 * yields `unavailable`. A present opener or accepted bet must state a valid
 * commitment; omitting it is a protocol failure.
 *
 * **Fresh client seeds are the player's half.** The echo proves the server
 * committed before it saw THIS bet; if the client reused a seed the server had
 * already seen on an earlier bet, the server knew it at promise time. The
 * shipped client draws a new client seed per bet by default, so the proof is
 * whole unless the player pinned one — a choice the report names when the
 * receipts show the same seed on consecutive bets.
 */
import { bytesEqual, bytesToHex } from './seed';

/** Stable ids, so "did not run" stays distinguishable from "ran and passed". */
export const OPENER_SEED_CHECK_ID = 'opener-seed-binding';
export const PRE_BET_SEED_CHECK_ID = 'pre-bet-seed-commitment';

export type SeedCheckStatus = 'pass' | 'fail' | 'unavailable';

export interface SeedCheckVerdict {
    status: SeedCheckStatus;
    detail: string;
}

export interface OpenerSeedStatement {
    /** The signed opener's required commitment; null means the server omitted it. */
    commitment: { hash: Uint8Array; index: bigint } | null;
}

function hex(bytes: Uint8Array): string {
    return bytesToHex(bytes);
}

/**
 * Compare the server-signed opener's seed statement against the seed the
 * chain revealed.
 *
 * `committed` is `blake2b-256(ascii(hex(server_seed)))` — the same digest the
 * `SeedBatch` published — and `chainIndex` the transcript's
 * `server_seed_index`; both are always present once a transcript is in hand.
 */
export function evaluateOpenerSeedBinding(
    committed: Uint8Array,
    chainIndex: bigint,
    opener: OpenerSeedStatement | null,
): SeedCheckVerdict {
    if (opener === null) {
        return {
            status: 'unavailable',
            detail: `the chain revealed the seed committed as ${hex(committed)} at index ${chainIndex}, but this export carries no opening frame to check — a tab that joined mid-round or receipts switched off. A gap in the evidence, NOT a disagreement.`,
        };
    }

    const statement = opener.commitment;

    if (statement === null || statement.hash.length !== 32) {
        return {
            status: 'fail',
            detail: `the server-signed RoundStarted must include server_seed_commitment with a 32-byte hash; it ${statement === null ? 'omitted the commitment' : `supplied a ${statement.hash.length}-byte hash`}. The opening frame violates the protocol.`,
        };
    }

    const hashMatches = bytesEqual(statement.hash, committed);
    const indexMatches = statement.index === chainIndex;

    if (!hashMatches || !indexMatches) {
        return {
            status: 'fail',
            detail: `the server-signed RoundStarted bound this round to seed commitment ${hex(statement.hash)} at index ${statement.index}, but the chain's transcript reveals the seed committed as ${hex(committed)} at index ${chainIndex}. The server swapped seeds after it had opened the round — every other proof here replays the swapped seed and passes, which is why this comparison exists.`,
        };
    }

    return {
        status: 'pass',
        detail: `the server-signed RoundStarted named commitment ${hex(committed)} at index ${chainIndex} before the outcome was shown, and the chain's transcript reveals exactly that seed. This closes a post-bet swap; whether the seed was chosen before the server saw the client seed is the pre-bet check's question.`,
    };
}

/**
 * Compare the player-signed echo against the seed the chain revealed.
 *
 * `echoed` is `PlaceBetCommand.server_seed_hash` out of the round's own
 * signed PlaceBet, null when the command omits it, or undefined when the bet receipt is absent.
 */
export function evaluatePreBetSeedCommitment(
    committed: Uint8Array,
    chainIndex: bigint,
    echoed: Uint8Array | null | undefined,
): SeedCheckVerdict {
    if (echoed === undefined) {
        return {
            status: 'unavailable',
            detail: `this export carries no signed PlaceBet to compare with commitment ${hex(committed)} at index ${chainIndex}. Missing evidence, NOT a disagreement.`,
        };
    }
    if (echoed === null || echoed.length !== 32) {
        return {
            status: 'fail',
            detail: 'the server accepted a PlaceBet without the required 32-byte server_seed_hash. Every bet must echo its promised seed commitment.',
        };
    }

    if (!bytesEqual(echoed, committed)) {
        return {
            status: 'fail',
            detail: `the player's signed PlaceBet echoed the server's promise of seed commitment ${hex(echoed)}, but the chain's transcript reveals the seed committed as ${hex(committed)} at index ${chainIndex}. The server accepted a bet bound to one promised seed and settled it against another — a stale echo is refused SEED_COMMITMENT_STALE, never substituted — so the seed was chosen with the client seed already in hand.`,
        };
    }

    return {
        status: 'pass',
        detail: `the player's signed PlaceBet echoed seed commitment ${hex(committed)}, and the chain's transcript reveals exactly that seed at index ${chainIndex}. A client can only echo a hash it was told, so the server named this seed before it received the bet — and the client seed inside it — leaving it no seed to choose once the outcome was computable. (Whole only if the client seed was fresh for this bet: a seed reused from an earlier bet was already known to the server at promise time.)`,
    };
}
