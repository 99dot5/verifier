/**
 * Resolves the shared fast-payout vector file and the public payout
 * watcher's recorded node snapshots the payout tests assert against. In this
 * public export they live in the repository's own vectors/ directory; in the
 * 99dot5 monorepo the same module points at the operator CLI's and the
 * watcher's own test files, so the identical tests pin both trees to the
 * identical bytes.
 */

export function fastPayoutVectorsUrl(): URL {
    return new URL('../../vectors/fast-payout-vectors.json', import.meta.url);
}

const WATCHER_SNAPSHOTS = {
    clean: new URL('../../vectors/payout-watcher/clean.snapshot.json', import.meta.url),
    overpayment: new URL('../../vectors/payout-watcher/overpayment.snapshot.json', import.meta.url),
    under_threshold: new URL('../../vectors/payout-watcher/under_threshold.snapshot.json', import.meta.url),
    signer_outside_set: new URL('../../vectors/payout-watcher/signer_outside_set.snapshot.json', import.meta.url),
    session_not_ended: new URL('../../vectors/payout-watcher/session_not_ended.snapshot.json', import.meta.url),
};

export type WatcherSnapshotCase = keyof typeof WATCHER_SNAPSHOTS;

export function watcherSnapshotUrl(snapshotCase: WatcherSnapshotCase): URL {
    return WATCHER_SNAPSHOTS[snapshotCase];
}
