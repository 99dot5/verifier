import { describe, expect, it } from 'vitest';
import { evaluateOpenerSeedBinding, evaluatePreBetSeedCommitment, type OpenerSeedStatement } from './seed-commitment';

/** The commitment the chain reveals, and its index in the pool's sequence. */
const COMMITTED = new Uint8Array(32).fill(0xc0);
const INDEX = 137n;
const OTHER = new Uint8Array(32).fill(0x0c);

function opener(hash: Uint8Array, index: bigint): OpenerSeedStatement {
    return { commitment: { hash, index } };
}

describe('evaluateOpenerSeedBinding', () => {
    it('passes when the signed opener names the revealed commitment at its index', () => {
        const verdict = evaluateOpenerSeedBinding(COMMITTED, INDEX, opener(COMMITTED, INDEX));

        expect(verdict.status).toBe('pass');
        expect(verdict.detail).toContain('before the outcome was shown');
    });

    it('accepts index zero within a present commitment', () => {
        expect(evaluateOpenerSeedBinding(COMMITTED, 0n, opener(COMMITTED, 0n)).status).toBe('pass');
        expect(evaluateOpenerSeedBinding(COMMITTED, INDEX, opener(COMMITTED, 0n)).status).toBe('fail');
    });

    it('fails when the opener named a different commitment', () => {
        const verdict = evaluateOpenerSeedBinding(COMMITTED, INDEX, opener(OTHER, INDEX));

        expect(verdict.status).toBe('fail');
        expect(verdict.detail).toContain('swapped seeds');
    });

    it('fails when the opener named the right commitment at another index', () => {
        expect(evaluateOpenerSeedBinding(COMMITTED, INDEX, opener(COMMITTED, INDEX + 1n)).status).toBe('fail');
    });

    it('is unavailable, not a failure, when the export carries no opener', () => {
        const verdict = evaluateOpenerSeedBinding(COMMITTED, INDEX, null);

        expect(verdict.status).toBe('unavailable');
        expect(verdict.detail).toContain('NOT a disagreement');
    });

    it('fails when a present opener omits its required commitment', () => {
        const verdict = evaluateOpenerSeedBinding(COMMITTED, INDEX, { commitment: null });

        expect(verdict.status).toBe('fail');
        expect(verdict.detail).toContain('omitted the commitment');
    });

    it.each([0, 31, 33])('fails when the opener supplies a %i-byte commitment hash', (length) => {
        const verdict = evaluateOpenerSeedBinding(COMMITTED, INDEX, opener(new Uint8Array(length), INDEX));

        expect(verdict.status).toBe('fail');
        expect(verdict.detail).toContain(`${length}-byte hash`);
    });
});

describe('evaluatePreBetSeedCommitment', () => {
    it('passes when the player-signed echo is the revealed commitment, and names the fresh-seed caveat', () => {
        const verdict = evaluatePreBetSeedCommitment(COMMITTED, INDEX, COMMITTED);

        expect(verdict.status).toBe('pass');
        expect(verdict.detail).toContain('before it received the bet');
        expect(verdict.detail).toContain('fresh for this bet');
    });

    it('fails when the chain reveals a seed other than the one the player echoed', () => {
        const verdict = evaluatePreBetSeedCommitment(COMMITTED, INDEX, OTHER);

        expect(verdict.status).toBe('fail');
        expect(verdict.detail).toContain('with the client seed already in hand');
    });

    it('is unavailable, not a failure, when the export has no bet receipt', () => {
        const verdict = evaluatePreBetSeedCommitment(COMMITTED, INDEX, undefined);

        expect(verdict.status).toBe('unavailable');
        expect(verdict.detail).toContain('NOT a disagreement');
    });
    it.each([null, new Uint8Array(0), new Uint8Array(31), new Uint8Array(33)])(
        'fails an accepted bet with a missing or malformed echo (%s)',
        (echo) => {
            expect(evaluatePreBetSeedCommitment(COMMITTED, INDEX, echo).status).toBe('fail');
        },
    );
});
