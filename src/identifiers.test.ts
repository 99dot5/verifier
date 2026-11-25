import { describe, expect, it } from 'vitest';

import { type Identifier, type Piece, splitIdentifiers } from './identifiers';

const identifiers = (pieces: Piece[]): Identifier[] => pieces.filter((p): p is Identifier => typeof p !== 'string');
const kinds = (text: string) => identifiers(splitIdentifiers(text)).map((i) => `${i.kind} ${i.value}`);

describe('splitIdentifiers', () => {
    it('gives back the text unchanged when it holds no identifier', () => {
        expect(splitIdentifiers('No admissible signing key derived.')).toEqual(['No admissible signing key derived.']);
        expect(splitIdentifiers('')).toEqual([]);
    });

    it('keeps every character: the pieces join back into the line', () => {
        const line =
            'level 6053540, op opKrnJ6ozeUvcrgvKPgDa7CiRF6dPYDwhyuv9q8zZosXPP7ASX1 — the whole round in one ' +
            'signed message, player commitment 17f6bf879c2c088f23ed88998e6369010151e9dde0afe342b9d109068c1db734';
        const joined = splitIdentifiers(line)
            .map((p) => (typeof p === 'string' ? p : p.value))
            .join('');

        expect(joined).toBe(line);
    });

    it('finds the level, the operation and the commitment of a transcript line', () => {
        expect(
            kinds(
                'level 6053540, op opKrnJ6ozeUvcrgvKPgDa7CiRF6dPYDwhyuv9q8zZosXPP7ASX1 — the whole round in one ' +
                    'signed message, player commitment 17f6bf879c2c088f23ed88998e6369010151e9dde0afe342b9d109068c1db734',
            ),
        ).toEqual([
            'level 6053540',
            'operation opKrnJ6ozeUvcrgvKPgDa7CiRF6dPYDwhyuv9q8zZosXPP7ASX1',
            'hash 17f6bf879c2c088f23ed88998e6369010151e9dde0afe342b9d109068c1db734',
        ]);
    });

    it('finds keys, contracts, the chain id and the rollup', () => {
        expect(
            kinds(
                'round-transcript at level 6053540 → edpkvQGVagSNSUihcXErJFQEdeGo7NSBpuiqqmy7pSuQMvhFWZuLVE ' +
                    '(administrator KT1VoY33fk5yrHbHfJ61eYREp6BHQpQLdjse). Each is sig = ' +
                    'ed25519(blake2b-256(NetXsqzbfFenSTS ‖ sr1LTLUvH1ziZW1Z47cTxJSwyYMN7chPB3La ‖ payload))',
            ),
        ).toEqual([
            'level 6053540',
            'public-key edpkvQGVagSNSUihcXErJFQEdeGo7NSBpuiqqmy7pSuQMvhFWZuLVE',
            'address KT1VoY33fk5yrHbHfJ61eYREp6BHQpQLdjse',
            'chain-id NetXsqzbfFenSTS',
            'address sr1LTLUvH1ziZW1Z47cTxJSwyYMN7chPB3La',
        ]);
    });

    it('finds round and session ids and implicit accounts', () => {
        expect(
            kinds(
                'first deposit for session 01a2096f-35ac-7197-879c-d0f5845e3062 from ' +
                    'tz1e4vfeosHStE5wihD8CSfiQqd1ibT2mwcV, round 01a20971-60f2-7322-99c8-b1125d927a45.',
            ),
        ).toEqual([
            'uuid 01a2096f-35ac-7197-879c-d0f5845e3062',
            'address tz1e4vfeosHStE5wihD8CSfiQqd1ibT2mwcV',
            'uuid 01a20971-60f2-7322-99c8-b1125d927a45',
        ]);
    });

    it('takes the level of a block, and the id and key of a big map', () => {
        expect(
            kinds(
                'The Tezos RPC confirms it: the block at level 6053518 holds the applied deposit call. Its receipt ' +
                    "writes this session's key in the vault's sessions big map (id 45376), which the vault does " +
                    'only on a first deposit; vault KT1Eca5RobtXqZK3WBCHKq4gGLJxzCQWfi2C holds a sessions entry for ' +
                    'this session (big map id 45376, key exprtZBwZUeYYYfUs9B9Rg2ywHezVHnCCnmF9WsDQVrs582dSK63dC)',
            ),
        ).toEqual([
            'level 6053518',
            'big-map 45376',
            'address KT1Eca5RobtXqZK3WBCHKq4gGLJxzCQWfi2C',
            'big-map 45376',
            'expression exprtZBwZUeYYYfUs9B9Rg2ywHezVHnCCnmF9WsDQVrs582dSK63dC',
        ]);
    });

    it('takes both ends of a level range, and a head level', () => {
        expect(kinds('Scanned levels 6025994–6054138 (L1 head 6077397); levels 6025994–6054138 were read')).toEqual([
            'level 6025994',
            'level 6054138',
            'level 6077397',
            'level 6025994',
            'level 6054138',
        ]);
    });

    it('takes a level at the end of a sentence', () => {
        expect(kinds('a deposit at level 6053518. Then level 6053540')).toEqual(['level 6053518', 'level 6053540']);
    });

    it('never takes a bare number or a count', () => {
        expect(
            kinds(
                'stake 1000000 at cumulative 0 ppm, index 2007; ' +
                    'more than 2,000 levels below the batch, and 20,000 levels before the transcript',
            ),
        ).toEqual([]);
    });

    it('takes an approximate level without its ≈, which stays in the text', () => {
        const pieces = splitIdentifiers('maps to L1 level ≈6053538; the transcript copy judged is at level 6053540');

        expect(identifiers(pieces).map((i) => `${i.kind} ${i.value}`)).toEqual(['level 6053538', 'level 6053540']);
        expect(pieces[0]).toBe('maps to L1 level ≈');
    });

    it('leaves a value the report shortened with … alone', () => {
        expect(
            kinds(
                'blake2b-256(ascii("4159d29fcd435558…")) = ad2c2d5c0d5237c03769607b93797b2743e5338212f07bae385d48368944dca6',
            ),
        ).toEqual(['hash ad2c2d5c0d5237c03769607b93797b2743e5338212f07bae385d48368944dca6']);
        expect(kinds('op opKrnJ6ozeUvcrgvKPgDa7CiRF6dPYDwhyuv9q8zZosXPP7ASX1…')).toEqual([]);
    });

    it('never takes a shape out of a longer run of hex or base58', () => {
        const frame = '051530952a9cbd87f695b0cb646cfd2792d060e0c3eb4c7268b4f124e1638c02c7e4fc187ed8cf317004401993';

        expect(kinds(`frameHex ${frame}`)).toEqual([]);
        expect(kinds('tz1e4vfeosHStE5wihD8CSfiQqd1ibT2mwcVx')).toEqual([]);
    });

    it('leaves a URL whole, with the address in its query string', () => {
        expect(
            kinds(
                'GET https://api.tzkt.io/v1/operations/sr_originate?rollup=sr1V6eabwhWDzTtz4UGGVGrH4BUXKsDuDt6f ' +
                    'returns level 15815593, operation oopCaBNnm1A2yuG5VaoHT52UrecnGNoVLc9N1WyCqtcrFC2vUzZ, sender ' +
                    'tz1VsVoKiVC9ARcbR7A7pvEMsjoGcannVuPM.',
            ),
        ).toEqual([
            'level 15815593',
            'operation oopCaBNnm1A2yuG5VaoHT52UrecnGNoVLc9N1WyCqtcrFC2vUzZ',
            'address tz1VsVoKiVC9ARcbR7A7pvEMsjoGcannVuPM',
        ]);
    });

    it('finds an ed25519 signature', () => {
        const sig =
            'edsigtXomBKi5CTRf5cjATJWSyaRvhfYNHqSUGrn4SdbYRcGwQrUGjzEfQDTuqHhuA8b2d8NarZjz8TRf65WkpQmo423BtomS8Q';

        expect(sig).toHaveLength(99);
        expect(kinds(`signed ${sig}.`)).toEqual([`signature ${sig}`]);
    });
});
