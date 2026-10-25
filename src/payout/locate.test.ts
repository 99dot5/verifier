// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { locatePayoutEvents } from './locate';

const VAULT = 'KT1BuEZtb68c1Q4yjtckcNjGELqWt56Xyesc';
const SESSION = '0102030405060708090a0b0c0d0e0f10';

function responder(pages: Record<string, unknown[]>, status = 200): { fetchImpl: typeof fetch; urls: string[] } {
    const urls: string[] = [];
    const fetchImpl = (async (input: string | URL | Request) => {
        const url = String(input);

        urls.push(url);

        const key = Object.keys(pages).find((k) => url.includes(k)) ?? '';

        return new Response(JSON.stringify(pages[key] ?? []), { status });
    }) as typeof fetch;

    return { fetchImpl, urls };
}

describe('locatePayoutEvents', () => {
    it('asks the indexer for the vault’s payout events naming the session and re-checks each row', async () => {
        const { fetchImpl, urls } = responder({
            [VAULT]: [
                {
                    id: 1,
                    level: 105,
                    tag: 'fast_payout',
                    payload: { fast: '5', paid_now: '5', paid_total: '5', session_id: SESSION },
                },
                {
                    id: 2,
                    level: 120,
                    tag: 'cemented_payout',
                    payload: { cemented: '5', paid_now: '0', paid_total: '5', session_id: SESSION },
                },
                {
                    id: 3,
                    level: 121,
                    tag: 'cemented_payout',
                    payload: { cemented: '7', paid_now: '7', paid_total: '7', session_id: 'bb'.repeat(16) },
                },
                {
                    id: 4,
                    level: 105,
                    tag: 'fast_payout',
                    payload: { fast: '5', paid_now: '5', paid_total: '5', session_id: SESSION },
                },
            ],
        });
        const location = await locatePayoutEvents({
            tzktApiUrl: 'https://indexer.example/',
            vaultAddresses: [VAULT],
            sessionIdHex: SESSION,
            fetchImpl,
        });

        expect(location.lookup).toBe('ok');
        expect(location.levels).toEqual([
            { vault: VAULT, level: 105 },
            { vault: VAULT, level: 120 },
        ]);
        expect(location.detail).toContain('1 row(s)');
        expect(urls).toHaveLength(1);
        expect(urls[0]).toContain(
            `/v1/contracts/events?contract=${VAULT}&tag.in=fast_payout,cemented_payout&payload.session_id=${SESSION}`,
        );
        expect(urls[0]).toContain('sort=id&limit=1000');
    });

    it('accepts a hyphenated session id and pages by id', async () => {
        const rows = Array.from({ length: 1000 }, (_, i) => ({
            id: i + 1,
            level: 100 + i,
            tag: 'fast_payout',
            payload: { session_id: SESSION },
        }));
        const { fetchImpl, urls } = responder({
            'id.gt=1000': [{ id: 1001, level: 2000, tag: 'cemented_payout', payload: { session_id: SESSION } }],
            [VAULT]: rows,
        });
        const location = await locatePayoutEvents({
            tzktApiUrl: 'https://indexer.example',
            vaultAddresses: [VAULT],
            sessionIdHex: '01020304-0506-0708-090a-0b0c0d0e0f10',
            fetchImpl,
        });

        expect(urls).toHaveLength(2);
        expect(urls[1]).toContain('&id.gt=1000');
        expect(location.levels).toHaveLength(1001);
        expect(location.levels.at(-1)).toEqual({ vault: VAULT, level: 2000 });
    });

    it('fails rather than guesses when the indexer errors or no vault is known', async () => {
        const { fetchImpl } = responder({}, 503);

        expect(
            (await locatePayoutEvents({ tzktApiUrl: 'x', vaultAddresses: [VAULT], sessionIdHex: SESSION, fetchImpl }))
                .lookup,
        ).toBe('failed');
        expect(
            (await locatePayoutEvents({ tzktApiUrl: 'x', vaultAddresses: [], sessionIdHex: SESSION, fetchImpl }))
                .lookup,
        ).toBe('failed');

        const throwing = (async () => {
            throw new Error('offline');
        }) as unknown as typeof fetch;
        const offline = await locatePayoutEvents({
            tzktApiUrl: 'x',
            vaultAddresses: [VAULT],
            sessionIdHex: SESSION,
            fetchImpl: throwing,
        });

        expect(offline.lookup).toBe('failed');
        expect(offline.detail).toContain('offline');
    });
});
