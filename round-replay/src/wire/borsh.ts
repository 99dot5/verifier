/**
 * Minimal Borsh reader for the sequencer→rollup wire schema.
 *
 * Borsh 1.x rules (the only ones this schema uses):
 *   - integers are little-endian fixed width (u32 = 4, u64 = 8, u128 = 16),
 *   - `String` / `Vec<u8>` are a u32-LE length followed by the bytes,
 *   - `[u8; N]` is N raw bytes with no prefix,
 *   - enums are a single u8 tag (variants numbered by declaration order,
 *     starting at 0) followed by the variant's fields,
 *   - structs are their fields in declaration order, nothing else.
 */

export class BorshError extends Error {}

export class BorshReader {
    private offset = 0;

    constructor(private readonly bytes: Uint8Array) {}

    get position(): number {
        return this.offset;
    }

    get remaining(): number {
        return this.bytes.length - this.offset;
    }

    take(length: number): Uint8Array {
        if (this.remaining < length) {
            throw new BorshError(`unexpected end of input: need ${length} bytes, have ${this.remaining}`);
        }

        const slice = this.bytes.slice(this.offset, this.offset + length);

        this.offset += length;

        return slice;
    }

    u8(): number {
        return this.take(1)[0];
    }

    u32(): number {
        const b = this.take(4);

        return (b[0] | (b[1] << 8) | (b[2] << 16)) + b[3] * 0x1000000;
    }

    u64(): bigint {
        return this.uint(8);
    }

    u128(): bigint {
        return this.uint(16);
    }

    private uint(width: number): bigint {
        const b = this.take(width);
        let value = 0n;

        for (let i = width - 1; i >= 0; i--) {
            value = (value << 8n) | BigInt(b[i]);
        }

        return value;
    }

    string(): string {
        const bytes = this.take(this.u32());

        return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    }

    byteVec(): Uint8Array {
        return this.take(this.u32());
    }

    fixedBytes(length: number): Uint8Array {
        return this.take(length);
    }

    /**
     * Borsh `Vec<T>`: a u32-LE element count followed by that many encoded
     * elements. `read` is invoked exactly `count` times, in order, so it may
     * advance the reader freely.
     */
    vec<T>(read: () => T): T[] {
        const count = this.u32();
        const items: T[] = [];

        for (let i = 0; i < count; i++) {
            items.push(read());
        }

        return items;
    }

    /** Asserts the reader consumed every byte — mirrors the kernel's strict decode. */
    expectEnd(): void {
        if (this.remaining !== 0) {
            throw new BorshError(`${this.remaining} trailing bytes after a valid value`);
        }
    }
}
