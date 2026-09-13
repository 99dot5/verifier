/**
 * A minimal protobuf wire WRITER — the mirror of `proto-reader.ts`.
 *
 * Nothing in the UI encodes protobuf: the verifier only ever reads frames
 * somebody else signed. This module exists for the TEST SUITE, and it ships
 * with the export on purpose. The alternative is pinning the receipt tests to
 * opaque hex blobs, which would make them unreadable and unextendable by the
 * very reader the export is for — someone who wants to satisfy themselves that
 * a tampered signature really is caught has to be able to build the tampered
 * frame, and that needs an encoder they can read.
 *
 * Field numbers live at the call sites in the fixtures, not here: this is the
 * wire format, not the schema.
 */

const WIRE_VARINT = 0;
const WIRE_LENGTH_DELIMITED = 2;

export class ProtoWriter {
    private readonly parts: number[] = [];

    /** A varint field: `uint64`, `int32`, `bool` and enums all encode this way. */
    varint(field: number, value: number | bigint): this {
        this.tag(field, WIRE_VARINT);
        this.pushVarint(BigInt(value));

        return this;
    }

    /** A length-delimited field: `bytes`, `string` and submessages. */
    bytes(field: number, value: Uint8Array): this {
        this.tag(field, WIRE_LENGTH_DELIMITED);
        this.pushVarint(BigInt(value.length));
        this.parts.push(...value);

        return this;
    }

    finish(): Uint8Array {
        return new Uint8Array(this.parts);
    }

    private tag(field: number, wireType: number): void {
        this.pushVarint((BigInt(field) << 3n) | BigInt(wireType));
    }

    private pushVarint(value: bigint): void {
        let remaining = value;

        for (;;) {
            const byte = Number(remaining & 0x7fn);

            remaining >>= 7n;

            if (remaining === 0n) {
                this.parts.push(byte);

                return;
            }

            this.parts.push(byte | 0x80);
        }
    }
}

/**
 * Encode a hyphenated UUID as `common.v1.UUID { high = 1, low = 2 }`.
 *
 * proto3 implicit presence means a zero half is OMITTED from the wire, which
 * is not a problem here (both halves are recovered as 0 by the reader) but is
 * why the encoder must not assume both fields are always present on decode.
 */
export function encodeUuid(hyphenated: string): Uint8Array {
    const hex = hyphenated.replaceAll('-', '');

    if (hex.length !== 32) {
        throw new RangeError(`not a UUID: ${hyphenated}`);
    }

    const writer = new ProtoWriter();
    const high = BigInt(`0x${hex.slice(0, 16)}`);
    const low = BigInt(`0x${hex.slice(16)}`);

    if (high !== 0n) {
        writer.varint(1, high);
    }

    if (low !== 0n) {
        writer.varint(2, low);
    }

    return writer.finish();
}
