/**
 * Importing a player's exported receipts (design §12.3).
 *
 * The export is a JSON document the PLAYER hands the verifier. That makes it
 * the one input here that nobody signed as a whole — deliberately, because
 * every frame inside it is already signed by the sequencer and every command
 * by the session key (§12.6). Signing the container would imply the container
 * is the evidence; it is not, the frames are.
 *
 * Two consequences shape this module:
 *
 *   - EVERY FIELD IS UNTRUSTED until a signature says otherwise. The labels
 *     (`payloadCase`, `relatedRequestId`, `roundIdHex`, `sequencerPublicKey`)
 *     are conveniences, and the proofs re-derive each of them from the frame
 *     bytes instead. This module validates SHAPE, not truth.
 *
 *   - A malformed document is a stated import error, never a throw out of
 *     `verifyRound`. A reader whose export is broken must be told which field
 *     is broken and get an `incomplete` verdict — not a stack trace, and never
 *     a verdict computed from half a document.
 */
import { hexToBytes } from '@99dot5/round-replay';
import { isLocatorLevel, isOperationHash, type LocatorHints } from './handoff';

export const RECEIPTS_SCHEMA = '99dot5.receipts.v1';

/**
 * Who built a receipts document: the player's own browser, or the sequencer
 * on request from its stored rows (ADR 0029). An UNSIGNED self-label.
 */
export type ReceiptsSource = 'client' | 'sequencer';

/** The provenance line the receipts section leads with. */
export function receiptsSourceLine(source: ReceiptsSource): string {
    return source === 'sequencer'
        ? 'Receipts source: the sequencer (built on request; frames signed at export time)'
        : 'Receipts source: your browser';
}

export interface ImportedCommand {
    /** Hyphenated `ClientEnvelope.request_id`, as LABELLED by the exporter. */
    requestId: string;
    /** The exporter's label for the payload oneof; re-derived from the bytes. */
    payloadCase: string;
    /** The complete `[0x05 | signature(64) | protobuf]` frame as sent. */
    frame: Uint8Array;
    /**
     * When the client sent it. A HUMAN READABILITY HINT, labelled as such in
     * the design: ordering comes from the server's step index and the
     * suppression bracket from L1, so nothing in a verdict may read this.
     */
    sentAtUnixMs: number;
    /**
     * How many times the client sent this command's bytes — the first send
     * plus every re-send under the same request id.
     *
     * OPTIONAL and defaulted to 1: an export written before the client counted
     * re-sends carries no such field, and reading its absence as "sent once" is
     * the honest default rather than a claim. Like `sentAtUnixMs` this is a
     * CLIENT-SIDE LABEL nobody signed — the server never sees a count — so no
     * check may read it. The suppression finding quotes it as the player's own
     * account of how hard they tried, which is exactly what the reader needs to
     * weigh transport loss against suppression.
     */
    sendCount: number;
}

export interface ImportedFrame {
    sequence: bigint;
    payloadCase: string;
    relatedRequestId: string | null;
    /** The complete `[0x06 | signature(64) | protobuf]` frame as received. */
    frame: Uint8Array;
}

export interface ImportedReceipts {
    tenantId: string;
    poolId: string;
    sessionIdHex: string;
    roundIdHex: string;
    /** The key the exporting client held, for comparison against the lineage. */
    sequencerPublicKey: string;
    /** The session key the commands were signed under — EXPORT-SUPPLIED. */
    sessionPublicKey: string;
    /** L1 level of the session's deposit; a hint the verifier confirms. */
    depositOperationLevel: number | null;
    /**
     * Who built the document, as the document SAYS — `client` when it says
     * nothing. Advisory: the label is unsigned, so a `sequencer` document
     * relabelled (or stripped) reads as browser-held and nothing
     * cryptographic tells the two apart. It caps a verdict at `attested`; it
     * never lifts one.
     */
    source: ReceiptsSource;
    /**
     * Where the round's transcript and seed batch sit on L1, as the exporter
     * reported them, or `null` when the document carries none (or none that
     * parsed). HINTS this page confirms against L1, never evidence.
     */
    locatorHints: LocatorHints | null;
    commands: ImportedCommand[];
    frames: ImportedFrame[];
    /** D13's whole input, called out separately so it survives a partial export. */
    roundEndedFrame: Uint8Array;
}

export type ImportResult =
    /**
     * `findings` are reader-facing notes about parts of the document that were
     * set aside without stopping the import — today only a malformed
     * `locatorHints`, which is a hint and not evidence.
     */
    { status: 'ok'; receipts: ImportedReceipts; findings: string[] } | { status: 'error'; message: string };

/** Parse and shape-validate an export document. Never throws. */
export function importReceipts(text: string): ImportResult {
    let document: unknown;

    try {
        document = JSON.parse(text);
    } catch (error) {
        return fail(`not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
    }

    try {
        const findings: string[] = [];

        return { status: 'ok', receipts: readDocument(document, findings), findings };
    } catch (error) {
        return fail(error instanceof Error ? error.message : String(error));
    }
}

function fail(message: string): ImportResult {
    return { status: 'error', message };
}

function readDocument(document: unknown, findings: string[]): ImportedReceipts {
    const root = asObject(document, 'the export');
    const schema = asString(root.schema, 'schema');

    if (schema !== RECEIPTS_SCHEMA) {
        // Refusing an unknown schema is the conservative arm: a future export
        // could move a field this build reads, and a verdict computed from a
        // misread document is worse than no verdict.
        throw new Error(`unsupported schema ${JSON.stringify(schema)} — this build reads ${RECEIPTS_SCHEMA}`);
    }

    const commands = asArray(root.commands, 'commands').map((entry, index) => {
        const command = asObject(entry, `commands[${index}]`);
        const sendCount = command.sendCount;

        return {
            requestId: asString(command.requestId, `commands[${index}].requestId`),
            payloadCase: asString(command.payloadCase, `commands[${index}].payloadCase`),
            frame: asHex(command.frameHex, `commands[${index}].frameHex`),
            sentAtUnixMs: asNumber(command.sentAtUnixMs, `commands[${index}].sentAtUnixMs`),
            // Absent means one send — the shape of an export written before the
            // client counted re-sends. A present value is still validated: a
            // malformed one is an import error rather than a silent default,
            // because a broken field and a missing field say different things.
            sendCount:
                sendCount === null || sendCount === undefined
                    ? 1
                    : asPositiveInteger(sendCount, `commands[${index}].sendCount`),
        };
    });

    const frames = asArray(root.frames, 'frames').map((entry, index) => {
        const frame = asObject(entry, `frames[${index}]`);
        const related = frame.relatedRequestId;

        return {
            // A sequence is a u64 and arrives as a JSON string or number; both
            // are accepted, and both go through BigInt so a sequence above
            // 2^53 cannot silently round.
            sequence: asBigint(frame.sequence, `frames[${index}].sequence`),
            payloadCase: asString(frame.payloadCase, `frames[${index}].payloadCase`),
            relatedRequestId:
                related === null || related === undefined
                    ? null
                    : asString(related, `frames[${index}].relatedRequestId`),
            frame: asHex(frame.frameHex, `frames[${index}].frameHex`),
        };
    });

    const depositLevel = root.depositOperationLevel;
    const source = root.source;

    // An unknown provenance is REFUSED, not dropped like a malformed hint: the
    // label decides a verdict ceiling, and reading a value this build does not
    // know as `client` would lift the ceiling a newer builder meant to impose.
    if (source !== undefined && source !== null && source !== 'client' && source !== 'sequencer') {
        throw new Error(
            `source: unknown provenance ${JSON.stringify(source)} — this build reads "client" (or no source) and "sequencer"`,
        );
    }

    return {
        tenantId: asString(root.tenantId, 'tenantId'),
        poolId: asString(root.poolId, 'poolId'),
        sessionIdHex: asString(root.sessionIdHex, 'sessionIdHex'),
        roundIdHex: asString(root.roundIdHex, 'roundIdHex'),
        sequencerPublicKey: asString(root.sequencerPublicKey, 'sequencerPublicKey'),
        sessionPublicKey: asString(root.sessionPublicKey, 'sessionPublicKey'),
        depositOperationLevel:
            depositLevel === null || depositLevel === undefined
                ? null
                : asNumber(depositLevel, 'depositOperationLevel'),
        locatorHints: readLocatorHints(root.locatorHints, findings),
        source: source === 'sequencer' ? 'sequencer' : 'client',
        commands,
        frames,
        roundEndedFrame: asHex(root.roundEndedFrameHex, 'roundEndedFrameHex'),
    };
}

/**
 * The document's `locatorHints`, or `null` when it carries none.
 *
 * Unlike every other field, a malformed value here is NOT an import error: it
 * is treated as absent and reported as a finding, and the document imports.
 * A hint only narrows or relocates a search, so losing one costs a wider scan
 * and never a verdict, while refusing the document would throw away the
 * signed frames that are the actual evidence. Each member (`transcript`,
 * `seedBatch`) is judged on its own and dropped whole when its shape is wrong.
 *
 * Unknown keys, inside `locatorHints` or inside a member, are IGNORED rather
 * than reported: the field is a bag of optional hints, and a key this build
 * does not know can only be a hint it would not use.
 */
function readLocatorHints(value: unknown, findings: string[]): LocatorHints | null {
    if (value === undefined || value === null) {
        return null;
    }

    if (typeof value !== 'object' || Array.isArray(value)) {
        findings.push("the export's locatorHints is not an object; it was ignored (a hint, not evidence)");

        return null;
    }

    const raw = value as Record<string, unknown>;
    const hints: LocatorHints = {};
    const member = (key: string): Record<string, unknown> | null => {
        const entry = raw[key];

        if (entry === undefined || entry === null) {
            return null;
        }

        if (typeof entry !== 'object' || Array.isArray(entry)) {
            findings.push(`the export's locatorHints.${key} is not an object; it was ignored (a hint, not evidence)`);

            return null;
        }

        return entry as Record<string, unknown>;
    };

    const transcript = member('transcript');

    if (transcript !== null) {
        if (isLocatorLevel(transcript.level) && isOperationHash(transcript.operationHash)) {
            hints.transcript = { level: transcript.level, operationHash: transcript.operationHash };
        } else {
            findings.push(
                "the export's locatorHints.transcript needs a positive integer level and an operation hash (o…); " +
                    'it was ignored (a hint, not evidence)',
            );
        }
    }

    const seedBatch = member('seedBatch');

    if (seedBatch !== null) {
        const operationHash = seedBatch.operationHash ?? null;

        if (isLocatorLevel(seedBatch.level) && (operationHash === null || isOperationHash(operationHash))) {
            hints.seedBatch = { level: seedBatch.level, operationHash };
        } else {
            findings.push(
                "the export's locatorHints.seedBatch needs a positive integer level and an operation hash (o…) or null; " +
                    'it was ignored (a hint, not evidence)',
            );
        }
    }

    return hints.transcript || hints.seedBatch ? hints : null;
}

function asObject(value: unknown, what: string): Record<string, unknown> {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${what}: expected an object`);
    }

    return value as Record<string, unknown>;
}

function asArray(value: unknown, what: string): unknown[] {
    if (!Array.isArray(value)) {
        throw new Error(`${what}: expected an array`);
    }

    return value;
}

function asString(value: unknown, what: string): string {
    if (typeof value !== 'string') {
        throw new Error(`${what}: expected a string, got ${typeof value}`);
    }

    return value;
}

function asNumber(value: unknown, what: string): number {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
        throw new Error(`${what}: expected a finite number`);
    }

    return value;
}

function asPositiveInteger(value: unknown, what: string): number {
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
        throw new Error(`${what}: expected an integer of at least 1`);
    }

    return value;
}

function asBigint(value: unknown, what: string): bigint {
    if (typeof value === 'number') {
        if (!Number.isSafeInteger(value) || value < 0) {
            throw new Error(`${what}: expected a non-negative integer`);
        }

        return BigInt(value);
    }

    if (typeof value !== 'string' || !/^\d+$/.test(value)) {
        throw new Error(`${what}: expected a u64 as a decimal string or a safe integer`);
    }

    return BigInt(value);
}

function asHex(value: unknown, what: string): Uint8Array {
    const text = asString(value, what);

    if (text.length === 0 || text.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(text)) {
        throw new Error(`${what}: expected a non-empty even-length hex string`);
    }

    return hexToBytes(text);
}
