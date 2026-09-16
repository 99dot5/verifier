// @vitest-environment node
/**
 * The refusal check, over hand-built signed frames.
 *
 * Every frame here goes through `receipts/fixtures.ts`, so it carries a real
 * signature over a real `ServerEnvelope` — the same builders the export ships
 * for a reader who wants to construct their own. Nothing is a hex blob and
 * nothing is a paraphrase of the wire.
 *
 * The round's crash tick is DERIVED, never stated: it comes from the same
 * `verify/crash.ts` replayer the verifier itself calls, which is pinned
 * against the golden vectors by `crash.test.ts`. A hard-coded tick here would
 * pin this file to itself.
 */
import { describe, expect, it } from 'vitest';
import { commandFrame, serverFrame, type ServerFrameSpec } from '../receipts/fixtures';
import type { ImportedCommand, ImportedFrame } from '../receipts/import';
import { decodeReceiptFrame, type ReceiptFrame } from '../receipts/recompute';
import { bytesToHex } from './seed';
import * as crash from './crash';
import * as hilo from './hilo';
import {
    RACE_BAND_TICKS,
    REJECTION_CHECK_ID,
    analyseRejections,
    classifyRefusalReason,
    type RejectionInput,
    type TranscriptActionSummary,
} from './rejections';

const SIGNING_SEED = new Uint8Array(32).fill(1);
const SESSION_SEED = new Uint8Array(32).fill(2);

const SESSION = 'e2b6419a-ec4b-4eef-bdfa-802b6f338fc2';
const ROUND = '9a256790-c7c0-47b0-9a5b-6ed2905d2df1';
const OTHER_ROUND = '0c9f31aa-1111-4222-8333-444444444444';

const BET = '11111111-1111-4111-8111-111111111111';
const CASHOUT = '22222222-2222-4222-8222-222222222222';
/** The peer tab's own cashout — the one the server refused. */
const PEER_CASHOUT = '33333333-3333-4333-8333-333333333333';

/**
 * A seed pair whose round runs FAR past the race band, so a stamp well before
 * the crash is representable against a positive tick. The tick itself is
 * derived, never stated; the guard test below is what pins the choice.
 */
const SERVER_SEED_HEX = bytesToHex(new Uint8Array(32).fill(13));
const CLIENT_SEED_HEX = bytesToHex(new Uint8Array(32).fill(1));
const CRASH_TICK = crash.crashRound(SERVER_SEED_HEX, CLIENT_SEED_HEX).crashTick;

/**
 * A stamp far outside the race band — the shape the check must still call a
 * contradiction. 50 ticks is 2.5 s at crash's quantum: no lock latency.
 */
const WELL_BEFORE_CRASH = CRASH_TICK - 50n;

/** The round's signed wall-clock origin and quantum, as `crash.v1.State` states them. */
const ANCHOR = 1_700_000_000_000n;
const QUANTUM = 50n;

/** `casino.v1.CommandRejectionReason` values, by number (the wire's vocabulary). */
const ROUND_CLOSED = 2;
const STATE_OUT_OF_SYNC = 8;
const RATE_LIMITED = 7;
const INVALID_PAYLOAD = 9;
const INTERNAL_ERROR = 11;
const ROUND_MODE_AUTO = 21;
/** A code no build of this verifier knows — the future-code case. */
const UNKNOWN_REASON = 9_999;

/** The wall-clock instant a given round-relative tick begins. */
function atTick(tick: bigint): bigint {
    return ANCHOR + tick * QUANTUM;
}

function receipt(spec: ServerFrameSpec): ReceiptFrame {
    const imported: ImportedFrame = {
        sequence: BigInt(spec.sequence),
        payloadCase: spec.payload.case,
        relatedRequestId: spec.relatedRequestId,
        frame: serverFrame(SIGNING_SEED, spec),
    };

    return decodeReceiptFrame(imported);
}

function accepted(requestId: string, sequence: number, receivedAtUnixMs?: bigint): ReceiptFrame {
    return receipt({
        sequence,
        sessionId: SESSION,
        relatedRequestId: requestId,
        payload: { case: 'commandAccepted', ...(receivedAtUnixMs === undefined ? {} : { receivedAtUnixMs }) },
    });
}

/** The signed anchor every tick derivation here is measured against. */
function roundStarted(options: { crashState?: boolean } = {}): ReceiptFrame {
    return receipt({
        sequence: 3,
        sessionId: SESSION,
        relatedRequestId: BET,
        payload: {
            case: 'roundStarted',
            roundId: ROUND,
            ...(options.crashState === false
                ? {}
                : { crashState: { tickQuantumMs: QUANTUM, serverAnchorUnixMs: ANCHOR } }),
        },
    });
}

function rejected(options: {
    requestId?: string | null;
    reasonCode: number;
    roundId?: string;
    receivedAtUnixMs?: bigint;
}): ReceiptFrame {
    return receipt({
        sequence: 0,
        sessionId: SESSION,
        relatedRequestId: options.requestId === undefined ? PEER_CASHOUT : options.requestId,
        payload: {
            case: 'commandRejected',
            reasonCode: options.reasonCode,
            detail: 'round is no longer in progress',
            roundId: options.roundId ?? ROUND,
            ...(options.receivedAtUnixMs === undefined ? {} : { receivedAtUnixMs: options.receivedAtUnixMs }),
        },
    });
}

function command(
    requestId: string,
    payloadCase: 'placeBet' | 'cashOut' | 'playerAction' | 'endSession',
    roundId?: string,
): ImportedCommand {
    return {
        requestId,
        payloadCase,
        frame: commandFrame(SESSION_SEED, {
            requestId,
            sessionId: SESSION,
            payloadCase,
            ...(roundId === undefined ? {} : { roundId }),
        }),
        sentAtUnixMs: 1,
        sendCount: 1,
    };
}

/**
 * The round settled by the deadline sweep — the ONE shape a liveness refusal
 * can be contradicted on, because it is the shape a dropped cashout produces.
 */
const EXPIRE_SETTLED: readonly TranscriptActionSummary[] = [
    { index: 0, actionType: 'place-bet' },
    { index: 1, actionType: 'expire' },
];

/** The round settled by a claim — manual cashout or a pre-committed auto target. */
const CLAIM_SETTLED: readonly TranscriptActionSummary[] = [
    { index: 0, actionType: 'place-bet' },
    { index: 1, actionType: 'cashout' },
];

/**
 * The baseline: a crash round whose peer-tab cashout was refused, with the
 * refusal's stamp and reason supplied per test.
 */
function input(overrides: Partial<RejectionInput> = {}): RejectionInput {
    return {
        roundIdHex: ROUND,
        gameType: crash.GAME_TYPE,
        serverSeedHex: SERVER_SEED_HEX,
        clientSeedHex: CLIENT_SEED_HEX,
        actions: EXPIRE_SETTLED,
        frames: [accepted(BET, 1, atTick(1n)), roundStarted(), accepted(CASHOUT, 4, atTick(2n))],
        commands: [
            command(BET, 'placeBet'),
            command(CASHOUT, 'cashOut', ROUND),
            command(PEER_CASHOUT, 'cashOut', ROUND),
        ],
        ...overrides,
    };
}

function withRejection(rejection: ReceiptFrame, overrides: Partial<RejectionInput> = {}): RejectionInput {
    const base = input(overrides);

    return { ...base, frames: [...base.frames, rejection] };
}

function only(report: ReturnType<typeof analyseRejections>) {
    expect(report.checks).toHaveLength(1);
    expect(report.checks[0].id).toBe(REJECTION_CHECK_ID);

    return report.checks[0];
}

describe('analyseRejections', () => {
    it('has a round that runs well past the race band, or every case below is vacuous', () => {
        // The whole suite compares stamps against this tick. A round that
        // crashed inside the band would leave no stamp that is BOTH after the
        // signed anchor and far enough before the crash to be a contradiction,
        // so every `fail` case would silently become unreachable.
        expect(CRASH_TICK).toBeGreaterThan(RACE_BAND_TICKS);
        expect(WELL_BEFORE_CRASH).toBeGreaterThan(RACE_BAND_TICKS);
    });

    it('pushes no check at all when no refusal names the round', () => {
        // A round with no refusal is the ordinary case, and the check is
        // deliberately outside `allProofsRan` so that costs nothing. Absence
        // is also not evidence: a peer tab with receipts off contributes to no
        // store, so a refused command can be missing entirely.
        expect(analyseRejections(input())).toEqual({ checks: [], findings: [] });
    });

    it('ignores a refusal that names another round', () => {
        const report = analyseRejections(
            withRejection(rejected({ reasonCode: ROUND_CLOSED, roundId: OTHER_ROUND, receivedAtUnixMs: atTick(0n) })),
        );

        expect(report).toEqual({ checks: [], findings: [] });
    });

    it('fails a ROUND_CLOSED refusal stamped before the round’s own crash tick', () => {
        // The server refused the cashout as arriving at a round no longer in
        // progress, at an instant its own published seed says the round was
        // still running. Both halves are signed, and they contradict.
        const report = analyseRejections(
            withRejection(
                rejected({ reasonCode: ROUND_CLOSED, receivedAtUnixMs: atTick(WELL_BEFORE_CRASH) }),
            ),
        );
        const check = only(report);

        expect(check.status).toBe('fail');
        expect(check.detail).toContain(`tick ${WELL_BEFORE_CRASH}`);
        expect(check.detail).toContain(`crashes the round at tick ${CRASH_TICK}`);
        // The honest limit on the stamp is stated, never left implied.
        expect(check.detail).toContain('before it verifies the session-key signature');
        // A contradiction is a check, not a finding: findings are the
        // observations that change no verdict.
        expect(report.findings).toEqual([]);
    });

    it('fails a STATE_OUT_OF_SYNC refusal on the same evidence', () => {
        // The escape the trust rule exists to close. The SERVER picks the
        // reason code, so a rule keyed on ROUND_CLOSED alone would be dodged
        // by answering with this code instead — the round id is corroborated
        // against the player's own signature either way, so both are checked.
        const report = analyseRejections(
            withRejection(
                rejected({ reasonCode: STATE_OUT_OF_SYNC, receivedAtUnixMs: atTick(WELL_BEFORE_CRASH) }),
            ),
        );

        expect(only(report).status).toBe('fail');
    });

    describe('the race band before the crash', () => {
        // The honest server loses a race: it stamps the command on arrival, the
        // sweep closes the busted round, and the command reaches the row's lock
        // to find it settled. That gap is stamp-to-lock latency — tens of ms
        // against a 50 ms tick — so a refusal a tick or two early is latency,
        // not a contradiction. It is reported EVERY time, because the band is
        // also the one place a suppressed cashout can hide behind that reading.

        it('reports, never fails, a refusal one tick before the crash', () => {
            const report = analyseRejections(
                withRejection(
                    rejected({ reasonCode: ROUND_CLOSED, receivedAtUnixMs: atTick(CRASH_TICK - 1n) }),
                ),
            );

            expect(only(report).status).toBe('pass');
            expect(only(report).detail).toContain('inside the');
            expect(only(report).detail).toContain('race band');
            expect(report.findings).toHaveLength(1);
            expect(report.findings[0]).toContain('1 tick(s) BEFORE the crash tick');
            expect(report.findings[0]).toContain('never failed');
        });

        it('still reports rather than fails at the band’s outer edge', () => {
            // The boundary is inclusive: `earlyBy === RACE_BAND_TICKS` is the
            // last tick the honest race can explain, and an off-by-one here
            // would turn the widest honest refusal into an accusation.
            const report = analyseRejections(
                withRejection(
                    rejected({ reasonCode: ROUND_CLOSED, receivedAtUnixMs: atTick(CRASH_TICK - RACE_BAND_TICKS) }),
                ),
            );

            expect(only(report).status).toBe('pass');
            expect(report.findings[0]).toContain(`${RACE_BAND_TICKS} tick(s) BEFORE the crash tick`);
        });

        it('fails one tick past the band', () => {
            // The band is a band, not a slope: the first tick outside it is a
            // contradiction with the same force as fifty.
            const report = analyseRejections(
                withRejection(
                    rejected({
                        reasonCode: ROUND_CLOSED,
                        receivedAtUnixMs: atTick(CRASH_TICK - RACE_BAND_TICKS - 1n),
                    }),
                ),
            );

            expect(only(report).status).toBe('fail');
            expect(only(report).detail).toContain('CONTRADICTED');
        });

        it('fails 50 ticks before the crash', () => {
            const report = analyseRejections(
                withRejection(rejected({ reasonCode: ROUND_CLOSED, receivedAtUnixMs: atTick(WELL_BEFORE_CRASH) })),
            );

            expect(only(report).status).toBe('fail');
            expect(only(report).detail).toContain('50 tick(s) BEFORE the crash');
        });
    });

    describe('a round that had already settled on a claim', () => {
        // The narrowing that keeps the check honest. A round whose last action
        // is a `cashout` ENDED before the crash, by the player's own claim or
        // by the target they pre-committed — so every liveness refusal after
        // that is the correct answer to a command against a settled round, and
        // the crash tick has nothing to contradict.

        it('passes a manual round’s second cashout, refused as out of sync', () => {
            // Manufactured scenario (a): cashed out at tick 50, the seed
            // crashes far later, and a second CashOut is refused at tick 60.
            const report = analyseRejections(
                withRejection(
                    rejected({ reasonCode: STATE_OUT_OF_SYNC, receivedAtUnixMs: atTick(60n) }),
                    { actions: CLAIM_SETTLED },
                ),
            );
            const check = only(report);

            expect(check.status).toBe('pass');
            expect(check.detail).toContain('ALREADY SETTLED on a claim');
            // The tick comparison never ran, so there is no margin finding.
            expect(report.findings).toEqual([]);
        });

        it('cites the settling command’s own acknowledgement when the export has it', () => {
            // Corroboration, not proof: the transcript already states the
            // settle. This only shows the player their own signed command
            // behind it, and it is scoped by the round id THEY signed.
            const report = analyseRejections(
                withRejection(
                    rejected({ reasonCode: ROUND_CLOSED, receivedAtUnixMs: atTick(60n) }),
                    { actions: CLAIM_SETTLED },
                ),
            );

            expect(only(report).status).toBe('pass');
            expect(only(report).detail).toContain(`${CASHOUT} at received_at_unix_ms ${atTick(2n)}`);
        });

        it('passes an auto round’s stray cashout, refused long after the target', () => {
            // Manufactured scenario (b): the auto target settled the round and
            // a stray CashOut lands at tick 150. Same answer, and it must not
            // depend on the stamp being anywhere in particular.
            const report = analyseRejections(
                withRejection(
                    rejected({ reasonCode: STATE_OUT_OF_SYNC, receivedAtUnixMs: atTick(150n) }),
                    { actions: CLAIM_SETTLED, commands: [command(BET, 'placeBet'), command(PEER_CASHOUT, 'cashOut', ROUND)] },
                ),
            );
            const check = only(report);

            expect(check.status).toBe('pass');
            expect(check.detail).toContain('ALREADY SETTLED on a claim');
            expect(report.findings).toEqual([]);
        });

        it('cannot fail a claim-settled round even on the stamp that fails an expire', () => {
            // The whole point, stated as one case: the SAME bytes that are a
            // contradiction on an expire-settled round are expected here.
            const stamp = atTick(WELL_BEFORE_CRASH);

            expect(
                only(analyseRejections(withRejection(rejected({ reasonCode: ROUND_CLOSED, receivedAtUnixMs: stamp })))).status,
            ).toBe('fail');
            expect(
                only(
                    analyseRejections(
                        withRejection(rejected({ reasonCode: ROUND_CLOSED, receivedAtUnixMs: stamp }), {
                            actions: CLAIM_SETTLED,
                        }),
                    ),
                ).status,
            ).toBe('pass');
        });

        it('concludes nothing when the round settled some other way', () => {
            // An `abandon` is neither the sweep's expire nor a claim, so this
            // check has no reading of when the round stopped — and an
            // `unavailable` here does not degrade the verdict, because the
            // check is deliberately outside `allProofsRan`.
            const report = analyseRejections(
                withRejection(rejected({ reasonCode: ROUND_CLOSED, receivedAtUnixMs: atTick(WELL_BEFORE_CRASH) }), {
                    actions: [
                        { index: 0, actionType: 'place-bet' },
                        { index: 1, actionType: 'abandon' },
                    ],
                }),
            );

            expect(only(report).status).toBe('unavailable');
            expect(only(report).detail).toContain('"abandon"');
        });

        it('concludes nothing when no transcript states how the round ended', () => {
            const report = analyseRejections(
                withRejection(rejected({ reasonCode: ROUND_CLOSED, receivedAtUnixMs: atTick(WELL_BEFORE_CRASH) }), {
                    actions: [],
                }),
            );

            expect(only(report).status).toBe('unavailable');
            expect(only(report).detail).toContain('no settling action this build can name');
        });
    });

    it('says nothing at all about a ROUND_MODE_AUTO refusal', () => {
        // Correct by design: the round's cashout target was pre-committed in
        // the bet, so refusing a manual cashout against it is the rules of the
        // game rather than a claim about when the command landed. Same stamp
        // that fails above.
        const report = analyseRejections(
            withRejection(
                rejected({ reasonCode: ROUND_MODE_AUTO, receivedAtUnixMs: atTick(WELL_BEFORE_CRASH) }),
            ),
        );

        expect(report).toEqual({ checks: [], findings: [] });
    });

    it('reports — never fails — a refusal that asserts nothing about liveness', () => {
        // The residual the classification exists to name. The stamp is the one
        // that FAILS a ROUND_CLOSED refusal above, so the only thing keeping
        // this quiet is the reason code the server chose — and the suppression
        // rule counts it as an answer either way.
        const report = analyseRejections(
            withRejection(rejected({ reasonCode: RATE_LIMITED, receivedAtUnixMs: atTick(WELL_BEFORE_CRASH) })),
        );

        expect(report.checks).toEqual([]);
        expect(report.findings).toHaveLength(1);
        expect(report.findings[0]).toContain('asserts nothing about whether the round was alive');
        expect(report.findings[0]).toContain('indistinguishable from a suppressed one');
        expect(report.findings[0]).toContain('RATE_LIMITED');
    });

    it('reports an INTERNAL_ERROR refusal on the same footing', () => {
        const report = analyseRejections(
            withRejection(rejected({ reasonCode: INTERNAL_ERROR, receivedAtUnixMs: atTick(WELL_BEFORE_CRASH) })),
        );

        expect(report.checks).toEqual([]);
        expect(report.findings).toHaveLength(1);
        expect(report.findings[0]).toContain('INTERNAL_ERROR');
    });

    it('reports a code this build does not know, rather than reading it as silence', () => {
        // A future refusal class must not default into the silent set: an
        // unknown code asserts nothing this verifier can check, which is
        // exactly the finding's subject.
        const report = analyseRejections(
            withRejection(rejected({ reasonCode: UNKNOWN_REASON, receivedAtUnixMs: atTick(WELL_BEFORE_CRASH) })),
        );

        expect(report.checks).toEqual([]);
        expect(report.findings).toHaveLength(1);
        expect(report.findings[0]).toContain(`code ${UNKNOWN_REASON} (unknown to this build)`);
    });

    it('says nothing about a refusal that faults the bytes you signed', () => {
        // `INVALID_PAYLOAD` is self-evidently about the command, and the
        // player can see the fault without trusting the server about any state
        // of its own — so there is nothing to report.
        const report = analyseRejections(
            withRejection(rejected({ reasonCode: INVALID_PAYLOAD, receivedAtUnixMs: atTick(WELL_BEFORE_CRASH) })),
        );

        expect(report).toEqual({ checks: [], findings: [] });
    });

    it('reports nothing for an uninformative refusal the trust rule rejects', () => {
        // Trust first, class second: a round id the player never signed is not
        // evidence about this round, so it produces the `unavailable` line and
        // no finding.
        const report = analyseRejections(
            withRejection(
                rejected({ requestId: null, reasonCode: RATE_LIMITED, receivedAtUnixMs: atTick(WELL_BEFORE_CRASH) }),
            ),
        );

        expect(only(report).status).toBe('unavailable');
        expect(report.findings).toEqual([]);
    });

    it('passes a refusal at or after the crash, and reports the margin', () => {
        const report = analyseRejections(
            withRejection(
                rejected({ reasonCode: ROUND_CLOSED, receivedAtUnixMs: atTick(CRASH_TICK + 3n) }),
            ),
        );

        expect(only(report).status).toBe('pass');
        expect(report.findings).toHaveLength(1);
        expect(report.findings[0]).toContain('3 tick(s) after the crash tick');
        // The null distribution is real here: both acknowledgements name
        // commands this export carries.
        expect(report.findings[0]).toContain('Null distribution');
        expect(report.findings[0]).toContain('tick(s) 1, 2');
    });

    it('calls out exact equality as the statistical tell', () => {
        const report = analyseRejections(
            withRejection(rejected({ reasonCode: ROUND_CLOSED, receivedAtUnixMs: atTick(CRASH_TICK) })),
        );

        expect(only(report).status).toBe('pass');
        expect(report.findings[0]).toContain('EXACTLY the crash tick');
        expect(report.findings[0]).toContain('statistical tell');
    });

    it('degrades the margin to a label when an acknowledgement has no command here', () => {
        // `CommandAccepted` is a DURABLE client_outbox row, so the dispatcher
        // broadcasts it to every connection of the session: this tab holds an
        // acknowledgement for a command a PEER tab sent. That timing is
        // somebody else's latency, so the comparison stops being a statistic.
        const base = input();
        const report = analyseRejections({
            ...base,
            frames: [
                ...base.frames,
                accepted(PEER_CASHOUT, 5, atTick(2n)),
                rejected({ reasonCode: ROUND_CLOSED, receivedAtUnixMs: atTick(CRASH_TICK + 1n) }),
            ],
            commands: base.commands.filter((entry) => entry.requestId !== PEER_CASHOUT),
        });

        // The refused command is gone from the export too, so the trust rule
        // cannot corroborate the round id either — which is the honest joint
        // consequence of a peer tab that stored nothing.
        expect(only(report).status).toBe('unavailable');
        expect(only(report).detail).toContain('this export carries no command for request');
    });

    it('reports a label, not a statistic, when a peer acknowledgement is present but the command is', () => {
        // The same degradation with the trust rule SATISFIED, so the label is
        // what is actually under test: the refused command is in the export,
        // and a third acknowledgement names a request nothing here sent.
        const base = input();
        const orphan = '44444444-4444-4444-8444-444444444444';
        const report = analyseRejections({
            ...base,
            frames: [
                ...base.frames,
                accepted(orphan, 5, atTick(2n)),
                rejected({ reasonCode: ROUND_CLOSED, receivedAtUnixMs: atTick(CRASH_TICK + 1n) }),
            ],
        });

        expect(only(report).status).toBe('pass');
        expect(report.findings[0]).toContain('Read as a LABEL, not a statistic');
        expect(report.findings[0]).toContain('a peer tab of the same session sent them');
        expect(report.findings[0]).not.toContain('Null distribution');
    });

    describe('the trust rule on the refusal’s round id', () => {
        it('trusts an id the player signed into the command it refuses', () => {
            const report = analyseRejections(
                withRejection(
                    rejected({ reasonCode: ROUND_CLOSED, receivedAtUnixMs: atTick(WELL_BEFORE_CRASH) }),
                ),
            );

            expect(only(report).status).toBe('fail');
        });

        it('declines when the command names a different round', () => {
            // The server says this refusal is about the round under
            // verification; the bytes the PLAYER signed say the command was
            // about another one. A server-chosen attribution is not evidence,
            // so nothing is concluded — never a `fail` on the server's word.
            const report = analyseRejections(
                withRejection(
                    rejected({ reasonCode: ROUND_CLOSED, receivedAtUnixMs: atTick(WELL_BEFORE_CRASH) }),
                    { commands: [command(BET, 'placeBet'), command(PEER_CASHOUT, 'cashOut', OTHER_ROUND)] },
                ),
            );
            const check = only(report);

            expect(check.status).toBe('unavailable');
            expect(check.detail).toContain(`you signed round ${OTHER_ROUND} into that command`);
        });

        it('declines when the refused command’s arm carries no round id', () => {
            const report = analyseRejections(
                withRejection(
                    rejected({ reasonCode: ROUND_CLOSED, receivedAtUnixMs: atTick(WELL_BEFORE_CRASH) }),
                    { commands: [command(BET, 'placeBet'), command(PEER_CASHOUT, 'endSession')] },
                ),
            );
            const check = only(report);

            expect(check.status).toBe('unavailable');
            expect(check.detail).toContain('carries no round_id of its own');
        });

        it('declines when the refusal names no request id', () => {
            const report = analyseRejections(
                withRejection(
                    rejected({
                        requestId: null,
                        reasonCode: ROUND_CLOSED,
                        receivedAtUnixMs: atTick(WELL_BEFORE_CRASH),
                    }),
                ),
            );

            expect(only(report).status).toBe('unavailable');
            expect(only(report).detail).toContain('names no related_request_id');
        });
    });

    describe('when the tick model or the anchor is missing', () => {
        it('is unavailable on a game with no tick model', () => {
            const report = analyseRejections(
                withRejection(
                    rejected({ reasonCode: ROUND_CLOSED, receivedAtUnixMs: atTick(WELL_BEFORE_CRASH) }),
                    { gameType: hilo.GAME_TYPE },
                ),
            );
            const check = only(report);

            expect(check.status).toBe('unavailable');
            expect(check.detail).toContain(`${hilo.GAME_TYPE} has no tick model`);
        });

        it('is unavailable when no transcript revealed the seed', () => {
            const report = analyseRejections(
                withRejection(
                    rejected({ reasonCode: ROUND_CLOSED, receivedAtUnixMs: atTick(WELL_BEFORE_CRASH) }),
                    { gameType: null, serverSeedHex: null, clientSeedHex: null },
                ),
            );

            expect(only(report).status).toBe('unavailable');
            expect(only(report).detail).toContain('no RoundTranscript for this round was found on chain');
        });

        it('is unavailable when the signed RoundStarted carries no crash state', () => {
            // The anchor has to be a number the tenant key signed. There is no
            // fallback, deliberately: an anchor supplied any other way would
            // be a number nobody stands behind.
            const base = input({ frames: [accepted(BET, 1, atTick(1n)), roundStarted({ crashState: false })] });
            const report = analyseRejections({
                ...base,
                frames: [
                    ...base.frames,
                    rejected({ reasonCode: ROUND_CLOSED, receivedAtUnixMs: atTick(WELL_BEFORE_CRASH) }),
                ],
            });

            expect(only(report).status).toBe('unavailable');
            expect(only(report).detail).toContain('no signed RoundStarted with a crash.v1.State');
        });

        it('is unavailable when the refusal states no receipt instant', () => {
            const report = analyseRejections(withRejection(rejected({ reasonCode: ROUND_CLOSED })));

            expect(only(report).status).toBe('unavailable');
            expect(only(report).detail).toContain('states no received_at_unix_ms');
        });

        it('is unavailable when the stamp precedes the round’s own anchor', () => {
            // Two signed numbers that do not describe one timeline. Accusing
            // the server of contradicting its seed on the strength of a clock
            // nobody can reconcile would be the wrong conclusion drawn loudly.
            const report = analyseRejections(
                withRejection(
                    rejected({ reasonCode: ROUND_CLOSED, receivedAtUnixMs: ANCHOR - 1_000n }),
                ),
            );

            expect(only(report).status).toBe('unavailable');
            expect(only(report).detail).toContain("BEFORE the round's own signed anchor");
        });
    });

    it('reports the most severe verdict when several refusals name the round', () => {
        // One check with one stable id, so `checks.find` is unambiguous; the
        // detail enumerates each refusal. A contradiction anywhere outranks a
        // gap, and a gap outranks a consistent refusal.
        const base = input();
        const second = '55555555-5555-4555-8555-555555555555';
        const report = analyseRejections({
            ...base,
            commands: [...base.commands, command(second, 'cashOut', ROUND)],
            frames: [
                ...base.frames,
                rejected({ reasonCode: ROUND_CLOSED, receivedAtUnixMs: atTick(CRASH_TICK + 5n) }),
                rejected({
                    requestId: second,
                    reasonCode: ROUND_CLOSED,
                    receivedAtUnixMs: atTick(WELL_BEFORE_CRASH),
                }),
            ],
        });
        const check = only(report);

        expect(check.status).toBe('fail');
        expect(check.detail).toContain(PEER_CASHOUT);
        expect(check.detail).toContain(second);
    });
});

// ── the classification, enumerated ──────────────────────────────────────

describe('classifyRefusalReason', () => {
    // Every value of `casino.v1.CommandRejectionReason` at the time of
    // writing, with the class the module must put it in. Enumerated rather
    // than spot-checked so a new enum value added to the proto without a
    // decision here shows up as an unlisted code rather than defaulting into
    // silence — the failure mode the `uninformative` default exists to avoid.
    const EXPECTED: [number, string, ReturnType<typeof classifyRefusalReason>][] = [
        [0, 'UNSPECIFIED', 'uninformative'],
        [1, 'INSUFFICIENT_BALANCE', 'uninformative'],
        [2, 'ROUND_CLOSED', 'liveness'],
        [3, 'DUPLICATE_COMMAND', 'uninformative'],
        [4, 'INVALID_SIGNATURE', 'command-validity'],
        [5, 'INVALID_SELECTION', 'command-validity'],
        [6, 'TABLE_NOT_FOUND', 'uninformative'],
        [7, 'RATE_LIMITED', 'uninformative'],
        [8, 'STATE_OUT_OF_SYNC', 'liveness'],
        [9, 'INVALID_PAYLOAD', 'command-validity'],
        [10, 'UNSUPPORTED_GAME', 'command-validity'],
        [11, 'INTERNAL_ERROR', 'uninformative'],
        [12, 'REPLAY_EXPIRED', 'uninformative'],
        [13, 'SESSION_NOT_ACTIVE', 'uninformative'],
        [14, 'POOL_PAUSED', 'uninformative'],
        [15, 'POOL_DRAINING', 'uninformative'],
        [16, 'POOL_DEPRECATED', 'uninformative'],
        [17, 'TENANT_PAUSED', 'uninformative'],
        [18, 'TENANT_DEPRECATED', 'uninformative'],
        [19, 'MAX_WIN_EXCEEDED', 'uninformative'],
        [20, 'STAKE_BELOW_MINIMUM', 'uninformative'],
        [21, 'ROUND_MODE_AUTO', 'mode'],
    ];

    it.each(EXPECTED)('classifies %i (%s) as %s', (code, _name, expected) => {
        expect(classifyRefusalReason(code)).toBe(expected);
    });

    it('defaults an unknown code to uninformative, never to silence', () => {
        expect(classifyRefusalReason(UNKNOWN_REASON)).toBe('uninformative');
    });
});
