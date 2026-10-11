// @vitest-environment node
/**
 * The receipts hand-off fragment (`#receipts=<scheme>.<base64url>`), as the
 * games write it (`libs/casino-client/src/receipts/handoff.ts`, whose own tests
 * round-trip through this format). The vectors below are fixed strings — a
 * `gz.` one produced by Node's zlib, not by the game's encoder — so this side
 * pins the format, not one implementation's output.
 */
import { describe, expect, it } from 'vitest';
import { readHintHandoff, readReceiptsHandoff, readRoundHandoff } from './handoff';

const TEXT = '{"schema":"99dot5.receipts.v1","note":"hand-off vector"}';
const GZ =
    'gz.H4sIAAAAAAACE6tWKk7OSM1NVLJSsrRMyS8x1StKTU7NLCgp1iszVNJRyssvSQXKZSTmpejmp6UplKUml-QXKdUCAENy2fA4AAAA';
const JSON_FORM = 'json.eyJzY2hlbWEiOiI5OWRvdDUucmVjZWlwdHMudjEiLCJub3RlIjoiaGFuZC1vZmYgdmVjdG9yIn0';

describe('readReceiptsHandoff', () => {
    it('reads nothing from a fragment that carries no receipts', async () => {
        await expect(readReceiptsHandoff('')).resolves.toBeNull();
        await expect(readReceiptsHandoff('#round=abc')).resolves.toBeNull();
    });

    it('decodes the gzip form', async () => {
        await expect(readReceiptsHandoff(`#receipts=${GZ}`)).resolves.toBe(TEXT);
    });

    it('decodes the plain JSON form, with or without the leading #', async () => {
        await expect(readReceiptsHandoff(`#receipts=${JSON_FORM}`)).resolves.toBe(TEXT);
        await expect(readReceiptsHandoff(`receipts=${JSON_FORM}`)).resolves.toBe(TEXT);
    });

    it('refuses an unknown scheme rather than guessing', async () => {
        await expect(readReceiptsHandoff('#receipts=zstd.AAAA')).rejects.toThrow(/unknown encoding "zstd"/);
        await expect(readReceiptsHandoff('#receipts=AAAA')).rejects.toThrow(/unknown encoding/);
    });

    it('refuses characters outside base64url', async () => {
        await expect(readReceiptsHandoff('#receipts=json.ab+/')).rejects.toThrow(/base64url/);
    });

    it('refuses bytes that are not gzip, and text that is not UTF-8', async () => {
        await expect(readReceiptsHandoff('#receipts=gz.AAAA')).rejects.toThrow();
        // 0xff 0xfe is not valid UTF-8.
        await expect(readReceiptsHandoff('#receipts=json._-4')).rejects.toThrow();
    });

    it('still reads the receipts when the link also names a round', async () => {
        await expect(readReceiptsHandoff(`#round=${ROUND}&receipts=${JSON_FORM}`)).resolves.toBe(TEXT);
    });
});

const ROUND = '9a256790-c7c0-47b0-9a5b-6ed2905d2df1';

describe('readRoundHandoff', () => {
    it('reads nothing from a fragment that carries no round', () => {
        expect(readRoundHandoff('')).toBeNull();
        expect(readRoundHandoff(`#receipts=${JSON_FORM}`)).toBeNull();
    });

    it('reads the hyphenated form, with or without the leading #', () => {
        expect(readRoundHandoff(`#round=${ROUND}`)).toBe(ROUND);
        expect(readRoundHandoff(`round=${ROUND}`)).toBe(ROUND);
    });

    it('normalises the bare 32-hex form and upper case to the hyphenated lowercase form', () => {
        expect(readRoundHandoff(`#round=${ROUND.replaceAll('-', '')}`)).toBe(ROUND);
        expect(readRoundHandoff(`#round=${ROUND.toUpperCase()}`)).toBe(ROUND);
    });

    it('refuses anything that is not a UUID rather than passing it on', () => {
        expect(() => readRoundHandoff('#round=')).toThrow(/not a UUID/);
        expect(() => readRoundHandoff('#round=9a256790-c7c0-47b0-9a5b')).toThrow(/not a UUID/);
        expect(() => readRoundHandoff(`#round=${ROUND}0`)).toThrow(/not a UUID/);
        expect(() => readRoundHandoff('#round=<script>')).toThrow(/not a UUID/);
    });
});

describe('readHintHandoff', () => {
    const TRANSCRIPT_OP = 'ooxa3P8hPVb3cX7YQ7e4H9SpX2nWm3kD5aQe8vRrZ1t6Ug7Fh2J';
    const BATCH_OP = 'onyxCAJ2FSiVUv8fEzSgfrYQtCbqQd8ZLjnGx1qEKmrBV3cWPdT';
    // The fragment the sender writes (`libs/casino-client`'s `roundHandoffUrl`).
    const ALL = `#round=${ROUND}&transcriptLevel=1234567&transcriptOp=${TRANSCRIPT_OP}&seedBatchLevel=1234500&seedBatchOp=${BATCH_OP}`;

    it('reads no hint, and no finding, from a link that carries none', () => {
        expect(readHintHandoff('')).toEqual({ hints: null, findings: [] });
        expect(readHintHandoff(`#round=${ROUND}`)).toEqual({ hints: null, findings: [] });
    });

    it('reads every hint key the sender writes, beside the round id', () => {
        expect(readHintHandoff(ALL)).toEqual({
            hints: {
                transcript: { level: 1_234_567, operationHash: TRANSCRIPT_OP },
                seedBatch: { level: 1_234_500, operationHash: BATCH_OP },
            },
            findings: [],
        });
        expect(readRoundHandoff(ALL)).toBe(ROUND);
    });

    it('reads a level-only seed batch as one with no operation hash', () => {
        expect(readHintHandoff(`#round=${ROUND}&seedBatchLevel=42`)).toEqual({
            hints: { seedBatch: { level: 42, operationHash: null } },
            findings: [],
        });
    });

    it('drops a malformed key with a finding, and never drops the round', () => {
        const cases: { fragment: string; hints: unknown; finding: RegExp }[] = [
            {
                fragment: `#round=${ROUND}&transcriptLevel=0&transcriptOp=${TRANSCRIPT_OP}`,
                hints: null,
                finding: /transcriptLevel hint is not a positive integer level/,
            },
            {
                fragment: `#round=${ROUND}&transcriptLevel=12.5&transcriptOp=${TRANSCRIPT_OP}`,
                hints: null,
                finding: /transcriptLevel hint is not a positive integer level/,
            },
            {
                fragment: `#round=${ROUND}&transcriptLevel=99999999999999999999&transcriptOp=${TRANSCRIPT_OP}`,
                hints: null,
                finding: /transcriptLevel hint is not a positive integer level/,
            },
            {
                fragment: `#round=${ROUND}&transcriptLevel=7&transcriptOp=${TRANSCRIPT_OP.slice(0, -1)}0`,
                hints: null,
                finding: /transcriptOp hint is not an operation hash/,
            },
            {
                fragment: `#round=${ROUND}&transcriptLevel=7`,
                hints: null,
                finding: /transcript hint needs both transcriptLevel and transcriptOp/,
            },
            {
                fragment: `#round=${ROUND}&seedBatchLevel=-3&seedBatchOp=${BATCH_OP}`,
                hints: null,
                finding: /seedBatchLevel hint is not a positive integer level/,
            },
            {
                fragment: `#round=${ROUND}&seedBatchLevel=42&seedBatchOp=<script>`,
                hints: { seedBatch: { level: 42, operationHash: null } },
                finding: /seedBatchOp hint is not an operation hash/,
            },
            {
                fragment: `#round=${ROUND}&seedBatchOp=${BATCH_OP}`,
                hints: null,
                finding: /seedBatchOp alone was ignored/,
            },
        ];

        for (const { fragment, hints, finding } of cases) {
            const read = readHintHandoff(fragment);

            expect(read.hints, fragment).toEqual(hints);
            expect(read.findings.join('\n'), fragment).toMatch(finding);
            expect(readRoundHandoff(fragment), fragment).toBe(ROUND);
        }
    });

    it('keeps the good hint when only the other one is malformed', () => {
        const read = readHintHandoff(
            `#round=${ROUND}&transcriptLevel=x&transcriptOp=${TRANSCRIPT_OP}&seedBatchLevel=42&seedBatchOp=${BATCH_OP}`,
        );

        expect(read.hints).toEqual({ seedBatch: { level: 42, operationHash: BATCH_OP } });
        expect(read.findings).toHaveLength(2);
    });
});
