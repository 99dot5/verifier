/**
 * Resolves the shared play-receipt vector files the receipt tests assert
 * against. In this public export they live in the repository's own vectors/
 * directory; in the 99dot5 monorepo the same module points at
 * libs/proto-definitions/testdata, so the identical tests pin both trees to
 * the identical bytes.
 */

export function receiptVectorsUrl(): URL {
    return new URL('../../vectors/receipt-vectors.json', import.meta.url);
}

export function receiptsExportFixtureUrl(): URL {
    return new URL('../../vectors/receipts-export-fixture.json', import.meta.url);
}
