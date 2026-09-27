/**
 * The stake cross-check: one number, three statements.
 *
 * Until `RoundStartedEvent` carried a stake there was only ONE signed
 * statement of what a round opened at — the chain's `RoundTranscript.stake` —
 * and the verifier fed it into the payout recomputation while comparing it to
 * nothing. A sequencer that debited a player 100 ꜩ and published a transcript
 * saying 1 ꜩ produced a round that replayed perfectly: the kernel derives its
 * payout FROM that stake, so understating both sides is internally consistent
 * and invisible to on-chain replay. The player's own signed `PlaceBet.amount`
 * is the only evidence of what they actually authorised.
 *
 * So this compares up to three statements of the same number:
 *
 *  - **chain** — `RoundTranscript.stake`, what the rollup replayed and paid on;
 *  - **player** — `PlaceBetCommand.amount`, signed by the session key;
 *  - **opener** — `RoundStartedEvent.stake`, signed by the tenant key.
 *
 * The player leg is the load-bearing one. Opener-vs-chain alone is two
 * statements by the same party, so it catches a server contradicting itself
 * and not one that understates consistently — the same weakness
 * `receipt-vs-chain` names. The detail line says which legs ran so a reader
 * is never left guessing which kind of agreement they are being shown.
 *
 * **Absence is never a mismatch.** A leg the export does not carry yields
 * `unavailable`, which degrades the verdict to `incomplete` rather than
 * accusing anyone — the rule ADR 0022 already applies to an unreconstructible
 * round, and the opposite of the `STEP_ORIGIN_UNSPECIFIED` trap, where
 * treating a producer's silence as an assertion would let the tool accuse an
 * honest server.
 */
import { TRANSCRIPT_ASSET, TRANSCRIPT_DECIMALS } from './assets';
import { decimalStringToUnits, unitsToDecimalString } from './ints';
import type { DecodedMoney } from '../wire/proto-reader';

/** Stable id, so "did not run" stays distinguishable from "ran and passed". */
export const STAKE_CHECK_ID = 'stake-agreement';

export type StakeStatus = 'pass' | 'fail' | 'unavailable';

export interface StakeVerdict {
    status: StakeStatus;
    detail: string;
}

/** One signed statement of the stake, resolved to atomic units or to why not. */
type Leg = { label: string; units: bigint } | { label: string; unreadable: string } | null;

function readLeg(label: string, money: DecodedMoney | null): Leg {
    if (money === null) {
        return null;
    }

    // An empty asset or value is what the reader leaves behind when the bytes
    // were not valid UTF-8, and what a `Money` with the field omitted decodes
    // to. Either way there is nothing to compare, and guessing would be worse
    // than saying so.
    if (money.asset === '' || money.value === '') {
        return { label, unreadable: `${label} carries an empty asset or value` };
    }

    if (money.asset !== TRANSCRIPT_ASSET) {
        // The transcript carries no asset — the kernel reads it off the
        // session record — so this verifier renders every amount at the one
        // asset it knows. A frame naming another asset is not a mismatch this
        // tool can adjudicate: it cannot convert, and calling it a fail would
        // accuse a server that may be perfectly honest in an asset the
        // verifier has simply never been taught.
        return {
            label,
            unreadable: `${label} is denominated in ${money.asset}, and this verifier only renders ${TRANSCRIPT_ASSET}`,
        };
    }

    try {
        return { label, units: decimalStringToUnits(money.value, TRANSCRIPT_DECIMALS) };
    } catch (error) {
        return {
            label,
            unreadable: `${label} is not an exact ${TRANSCRIPT_ASSET} amount: ${(error as Error).message}`,
        };
    }
}

function render(units: bigint): string {
    return `${units} mutez (${unitsToDecimalString(units, TRANSCRIPT_DECIMALS)} ${TRANSCRIPT_ASSET})`;
}

/**
 * Compare the chain's stake against whichever signed statements the export
 * carries.
 *
 * `chainStake` is always present — without a transcript there is no round to
 * verify — so it is the axis the others are compared to, never itself a leg.
 */
export function evaluateStakeAgreement(
    chainStake: bigint,
    playerAmount: DecodedMoney | null,
    openerStake: DecodedMoney | null,
): StakeVerdict {
    const legs = [
        readLeg("the player's signed PlaceBet.amount", playerAmount),
        readLeg('the server-signed RoundStarted.stake', openerStake),
    ].filter((leg): leg is NonNullable<Leg> => leg !== null);

    if (legs.length === 0) {
        return {
            status: 'unavailable',
            detail: `the chain states a stake of ${render(chainStake)}, and this export carries no signed statement of it to compare — neither the player's PlaceBet nor the round's opening frame. That is a gap in the evidence, NOT a disagreement.`,
        };
    }

    const unreadable = legs.filter((leg): leg is { label: string; unreadable: string } => 'unreadable' in leg);

    if (unreadable.length > 0) {
        return {
            status: 'unavailable',
            detail: `the chain states a stake of ${render(chainStake)}, but ${unreadable
                .map((leg) => leg.unreadable)
                .join('; ')}. Nothing here says the amounts disagree — only that they cannot be compared.`,
        };
    }

    const readable = legs as { label: string; units: bigint }[];
    const disagreeing = readable.filter((leg) => leg.units !== chainStake);
    const summary = readable.map((leg) => `${leg.label} = ${render(leg.units)}`).join(', ');

    if (disagreeing.length > 0) {
        return {
            status: 'fail',
            detail: `the chain replayed and paid on a stake of ${render(chainStake)}, but ${summary}. The kernel derives the payout FROM the transcript's stake, so an understated stake replays perfectly on chain and is invisible to every other proof here — this comparison is the only thing that sees it.`,
        };
    }

    const strong = readable.some((leg) => leg.label.startsWith("the player's"));

    return {
        status: 'pass',
        detail: `${summary}, all equal to the chain's ${render(chainStake)}. ${
            strong
                ? 'The player-signed amount is included, so this ties what the player authorised to what the rollup paid on.'
                : 'NOTE: only the server-signed opener was available, so this is the server agreeing with itself — it catches self-contradiction, not a consistent understatement.'
        }`,
    };
}
