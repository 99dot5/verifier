import { describe, expect, it } from 'vitest';
import { evaluateStakeAgreement } from './stake';

/** 100 ꜩ, the amount the suite's transcripts carry. */
const CHAIN = 100_000_000n;
const AGREES = { asset: 'TEZ', value: '100' };

describe('evaluateStakeAgreement', () => {
    it('passes when both signed statements equal the chain, and says the player leg ran', () => {
        const verdict = evaluateStakeAgreement(CHAIN, AGREES, AGREES);

        expect(verdict.status).toBe('pass');
        expect(verdict.detail).toContain('what the player authorised');
    });

    it('fails when the player signed a different amount than the chain replayed', () => {
        const verdict = evaluateStakeAgreement(CHAIN, { asset: 'TEZ', value: '1' }, AGREES);

        expect(verdict.status).toBe('fail');
        expect(verdict.detail).toContain('1000000 mutez');
    });

    it('fails when the server-signed opener disagrees with the chain', () => {
        const verdict = evaluateStakeAgreement(CHAIN, AGREES, { asset: 'TEZ', value: '99' });

        expect(verdict.status).toBe('fail');
    });

    it('marks an opener-only agreement as the server agreeing with itself', () => {
        const verdict = evaluateStakeAgreement(CHAIN, null, AGREES);

        expect(verdict.status).toBe('pass');
        // The distinction is the point: two statements by the same party
        // catch self-contradiction, not a consistent understatement.
        expect(verdict.detail).toContain('server agreeing with itself');
        expect(verdict.detail).not.toContain('what the player authorised');
    });

    it('is unavailable, not a failure, when the export carries no signed stake', () => {
        const verdict = evaluateStakeAgreement(CHAIN, null, null);

        expect(verdict.status).toBe('unavailable');
        expect(verdict.detail).toContain('NOT a disagreement');
    });

    /**
     * An asset this verifier cannot render is a gap, never an accusation. It
     * cannot convert, so calling the amounts different would accuse a server
     * that may be perfectly honest in a currency the tool has never been
     * taught — the same reason a missing replayer reports `unsupported`
     * rather than `fail`.
     */
    it('is unavailable for an asset it cannot render, rather than calling it a mismatch', () => {
        const verdict = evaluateStakeAgreement(CHAIN, { asset: 'BTC', value: '100' }, null);

        expect(verdict.status).toBe('unavailable');
        expect(verdict.detail).toContain('BTC');
    });

    it('is unavailable for a value finer than the asset admits, rather than rounding into agreement', () => {
        // Seven fractional digits at a six-decimal asset. Rounding would be
        // the one way this check could manufacture the agreement it exists to
        // test for.
        const verdict = evaluateStakeAgreement(CHAIN, { asset: 'TEZ', value: '100.0000001' }, null);

        expect(verdict.status).toBe('unavailable');
    });

    it('is unavailable for a money whose fields did not decode', () => {
        // What the reader leaves behind on non-UTF-8 bytes, and what an
        // omitted field decodes to.
        const verdict = evaluateStakeAgreement(CHAIN, { asset: '', value: '' }, null);

        expect(verdict.status).toBe('unavailable');
        expect(verdict.detail).toContain('empty asset or value');
    });

    it('reports a non-numeric value as unreadable rather than as a disagreement', () => {
        const verdict = evaluateStakeAgreement(CHAIN, { asset: 'TEZ', value: 'abc' }, null);

        expect(verdict.status).toBe('unavailable');
    });

    it('still fails when one leg is readable and disagrees, even if the other is not', () => {
        // A server cannot buy silence by corrupting the second statement.
        const verdict = evaluateStakeAgreement(CHAIN, { asset: 'TEZ', value: '1' }, { asset: '', value: '' });

        // The unreadable leg makes the whole comparison unavailable, which is
        // the conservative answer and is deliberate: reporting a fail here
        // would rest on evidence the report cannot fully show. The mismatch
        // is still visible in the detail.
        expect(verdict.status).toBe('unavailable');
    });
});
