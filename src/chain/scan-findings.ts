/**
 * The scan's own findings, appended after the report's.
 *
 * At every level the node is read, the indexer's count of messages with this
 * rollup's prefix is compared with the node's count of applied ones. A level
 * where the indexer called frames absent but the node holds some never gets
 * here: the scan rejects it as a contradiction. Every other difference is a
 * fixed-text finding only. It changes no check and no verdict, because what is
 * judged is always the node's content.
 */
import type { VerificationReport } from '../verifier';
import type { ScanCoverage } from './inbox-scan';

/** The finding for each count mismatch the run saw, in level order. */
export function scanFindings(coverage: Pick<ScanCoverage, 'mismatches'>): string[] {
    return coverage.mismatches.map(
        (m) =>
            `Indexer cross-check: at level ${m.level} the indexer lists ${m.indexer} message(s) with this rollup's ` +
            `prefix and the Tezos RPC holds ${m.node} applied; the Tezos RPC's messages are the ones judged.`,
    );
}

/** `report` with the scan's findings after its own; the same report when there are none. */
export function appendScanFindings<R extends Pick<VerificationReport, 'findings'>>(
    report: R,
    coverage: Pick<ScanCoverage, 'mismatches'>,
): R {
    const findings = scanFindings(coverage);

    return findings.length === 0 ? report : { ...report, findings: [...report.findings, ...findings] };
}
