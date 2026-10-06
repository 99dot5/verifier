// @vitest-environment node
/**
 * The receipts hand-off fragment (`#receipts=<scheme>.<base64url>`), as the
 * games write it (`libs/game-shell/src/receipts-handoff.ts`, whose own tests
 * round-trip through this format). The vectors below are fixed strings — a
 * `gz.` one produced by Node's zlib, not by the game's encoder — so this side
 * pins the format, not one implementation's output.
 */
import { describe, expect, it } from 'vitest';
import { readReceiptsHandoff } from './handoff';

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
});
