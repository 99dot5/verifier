/**
 * Confirming a SeedBatch candidate in its own block.
 *
 * The located run takes candidate batch levels from the transcript sender's
 * operations. A candidate counts only once the node's copy of its block holds
 * a SeedBatch of the round's tenant and pool that covers the round's seed
 * index and verifies under a key the tenant registered: the same rule
 * `confirmHints` applies to a batch hint in `run.ts`. A confirmed candidate
 * only moves the window's lower bound; it is never judged as a message.
 */
import type { SigningDomain } from '../wire/signature';
import { authenticatesUnder, type KeySet } from '../verifier';
import type { InboxMessage } from './inbox';

export interface BatchCandidateQuery {
    tenantId: string;
    /** The pool the round's authenticated transcript is signed for. */
    poolId: string;
    seedIndex: bigint;
    keys: KeySet;
    signingDomain: SigningDomain | null;
}

/** The first authenticated SeedBatch in `blockMessages` covering the index for the tenant and pool; null when there is none. */
export function confirmBatchCandidate(blockMessages: InboxMessage[], query: BatchCandidateQuery): InboxMessage | null {
    const domain = query.signingDomain;

    if (domain === null) {
        return null;
    }

    return (
        blockMessages.find((m) => {
            const message = m.envelope.message;

            return (
                m.envelope.tenantId === query.tenantId &&
                m.envelope.poolId === query.poolId &&
                message.kind === 'seed-batch' &&
                message.startIndex <= query.seedIndex &&
                query.seedIndex < message.startIndex + BigInt(message.hashes.length) &&
                authenticatesUnder(m, query.keys, domain)
            );
        }) ?? null
    );
}
