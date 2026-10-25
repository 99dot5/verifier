/**
 * The vault's per-session paid ledger, as pure functions.
 *
 * `paid[session]` is the total the vault has paid the session's owner
 * through either path. The two events report what each execution did to it:
 *
 *   - a FAST payout is refused once anything is on the ledger, so it always
 *     starts from zero and pays its whole amount:
 *     `previous = 0`, `paid_now = fast`, `paid_total = fast`;
 *   - a CEMENTED payout of `c` over a previous total `p` pays the remainder
 *     and records the larger: `paid_now = max(0, c − p)`,
 *     `paid_total = max(p, c)`. An over-paid session (`p > c`) is left
 *     standing, nothing is clawed back: the comparison with the kernel's
 *     figure is what catches that overpayment, not this rule.
 *
 * The previous total is this tool's own replay of the session's earlier
 * events, never the event's own claim, so a vault that paid twice cannot
 * describe itself into agreement.
 */

/** What an execution should have written, given the previous total. */
export interface LedgerMove {
    paidNow: bigint;
    paidTotal: bigint;
}

/**
 * The fast payout's move: refused unless nothing is paid yet, then the whole
 * amount. `null` when `previous` is non-zero: the vault should have refused it.
 */
export function expectedFast(previous: bigint, fast: bigint): LedgerMove | null {
    return previous === 0n ? { paidNow: fast, paidTotal: fast } : null;
}

/** The cemented payout's move: the remainder over the previous total. */
export function expectedCemented(previous: bigint, cemented: bigint): LedgerMove {
    return {
        paidNow: cemented > previous ? cemented - previous : 0n,
        paidTotal: previous > cemented ? previous : cemented,
    };
}

/** A reported move that is not the expected one. */
export interface LedgerMismatch {
    previous: bigint;
    /** `null` for a fast payout over a non-zero ledger, which has no expected move at all. */
    expected: LedgerMove | null;
    reported: LedgerMove;
}

function same(a: LedgerMove | null, b: LedgerMove): boolean {
    return a !== null && a.paidNow === b.paidNow && a.paidTotal === b.paidTotal;
}

/** Check a fast payout event against the ledger. */
export function checkFast(previous: bigint, fast: bigint, reported: LedgerMove): LedgerMismatch | null {
    const expected = expectedFast(previous, fast);

    return same(expected, reported) ? null : { previous, expected, reported };
}

/** Check a cemented payout event against the ledger. */
export function checkCemented(previous: bigint, cemented: bigint, reported: LedgerMove): LedgerMismatch | null {
    const expected = expectedCemented(previous, cemented);

    return same(expected, reported) ? null : { previous, expected, reported };
}
