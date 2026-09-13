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
import { hexToBytes } from '../verify/seed';

export const RECEIPTS_SCHEMA = '99dot5.receipts.v1';

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
    commands: ImportedCommand[];
    frames: ImportedFrame[];
    /** D13's whole input, called out separately so it survives a partial export. */
    roundEndedFrame: Uint8Array;
}

export type ImportResult =
    | { status: 'ok'; receipts: ImportedReceipts }
    | { status: 'error'; message: string };

/** Parse and shape-validate an export document. Never throws. */
export function importReceipts(text: string): ImportResult {
    let document: unknown;

    try {
        document = JSON.parse(text);
    } catch (error) {
        return fail(`not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
    }

    try {
        return { status: 'ok', receipts: readDocument(document) };
    } catch (error) {
        return fail(error instanceof Error ? error.message : String(error));
    }
}

function fail(message: string): ImportResult {
    return { status: 'error', message };
}

function readDocument(document: unknown): ImportedReceipts {
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

        return {
            requestId: asString(command.requestId, `commands[${index}].requestId`),
            payloadCase: asString(command.payloadCase, `commands[${index}].payloadCase`),
            frame: asHex(command.frameHex, `commands[${index}].frameHex`),
            sentAtUnixMs: asNumber(command.sentAtUnixMs, `commands[${index}].sentAtUnixMs`),
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
        commands,
        frames,
        roundEndedFrame: asHex(root.roundEndedFrameHex, 'roundEndedFrameHex'),
    };
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
