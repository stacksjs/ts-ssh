/**
 * The data types SSH is written in.
 *
 * Everything in the protocol - a packet, a public key, a signature, a channel
 * request - is one of six types laid end to end, defined in RFC 4251 §5. Get
 * these wrong and nothing above them can be right, so this is the first module
 * and the most thoroughly tested one.
 *
 * The types:
 *
 * - **byte**, and fixed-length byte runs.
 * - **boolean**, one byte. Zero is false, and *anything* non-zero is true -
 *   senders must use 1, receivers must not require it.
 * - **uint32** and **uint64**, big endian.
 * - **string**, a uint32 length then that many bytes. Arbitrary binary, not
 *   text: an SSH "string" holds a public key as readily as a username.
 * - **mpint**, a signed big-endian integer in a string, with the minimum number
 *   of bytes and a leading zero when the top bit would otherwise make it
 *   negative. This is the type most often got wrong, because the leading zero
 *   is only sometimes there.
 * - **name-list**, a string of comma-separated US-ASCII names.
 *
 * Reading is bounds-checked everywhere. A reader parses bytes an unauthenticated
 * peer chose, so a length field it invented must not become an out-of-bounds
 * read - it must become a refusal.
 */

/** A peer sent something that is not valid SSH. */
export class ProtocolError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ProtocolError'
  }
}

/** Reads SSH types out of a buffer, refusing to read past the end. */
export class Reader {
  private offset = 0

  constructor(private readonly bytes: Uint8Array) {}

  /** How many bytes are left. */
  get remaining(): number {
    return this.bytes.length - this.offset
  }

  /** Where the cursor is, for a caller that needs to hash a prefix. */
  get position(): number {
    return this.offset
  }

  private take(count: number): Uint8Array {
    if (count < 0 || count > this.remaining)
      throw new ProtocolError(`Wanted ${count} bytes and ${this.remaining} remain`)

    const slice = this.bytes.subarray(this.offset, this.offset + count)
    this.offset += count

    return slice
  }

  byte(): number {
    return this.take(1)[0]!
  }

  /** Anything non-zero is true: senders must write 1, readers must not insist. */
  boolean(): boolean {
    return this.byte() !== 0
  }

  uint32(): number {
    const bytes = this.take(4)

    // Shifting would go signed on the top bit; multiplication keeps it a
    // positive number, which is what every length field here is.
    return bytes[0]! * 0x1000000 + ((bytes[1]! << 16) | (bytes[2]! << 8) | bytes[3]!)
  }

  uint64(): bigint {
    const bytes = this.take(8)
    let value = 0n

    for (const part of bytes)
      value = (value << 8n) | BigInt(part)

    return value
  }

  /** A length-prefixed run of arbitrary bytes. */
  string(): Uint8Array {
    return this.take(this.uint32())
  }

  /** The same, decoded as UTF-8, for the fields that really are text. */
  text(): string {
    return new TextDecoder().decode(this.string())
  }

  /** A comma-separated list of names, empty when the string was empty. */
  nameList(): string[] {
    const raw = this.text()

    return raw === '' ? [] : raw.split(',')
  }

  /**
   * A signed big-endian integer.
   *
   * Returned as a bigint because these are key material and moduli, where
   * anything else loses precision on the first real key.
   */
  mpint(): bigint {
    const bytes = this.string()
    if (bytes.length === 0)
      return 0n

    const negative = (bytes[0]! & 0x80) !== 0
    let value = 0n

    for (const part of bytes)
      value = (value << 8n) | BigInt(part)

    if (!negative)
      return value

    // Two's complement over the width that was actually sent.
    return value - (1n << BigInt(bytes.length * 8))
  }

  /** Everything not yet read. */
  rest(): Uint8Array {
    return this.take(this.remaining)
  }
}

/** Writes SSH types into a growing buffer. */
export class Writer {
  private chunks: Uint8Array[] = []
  private length = 0

  private push(bytes: Uint8Array): this {
    this.chunks.push(bytes)
    this.length += bytes.length

    return this
  }

  byte(value: number): this {
    return this.push(new Uint8Array([value & 0xFF]))
  }

  raw(bytes: Uint8Array): this {
    return this.push(bytes)
  }

  boolean(value: boolean): this {
    return this.byte(value ? 1 : 0)
  }

  uint32(value: number): this {
    const bytes = new Uint8Array(4)
    new DataView(bytes.buffer).setUint32(0, value >>> 0, false)

    return this.push(bytes)
  }

  uint64(value: bigint | number): this {
    const bytes = new Uint8Array(8)
    new DataView(bytes.buffer).setBigUint64(0, BigInt(value), false)

    return this.push(bytes)
  }

  string(value: Uint8Array | string): this {
    const bytes = typeof value === 'string' ? new TextEncoder().encode(value) : value

    return this.uint32(bytes.length).push(bytes)
  }

  nameList(names: readonly string[]): this {
    return this.string(names.join(','))
  }

  /**
   * A signed big-endian integer, minimally encoded.
   *
   * The two rules that trip everybody: zero is an *empty* string rather than a
   * zero byte, and a positive number whose top bit is set gets a leading zero
   * so it is not read back as negative.
   */
  mpint(value: bigint): this {
    if (value === 0n)
      return this.string(new Uint8Array(0))

    if (value < 0n)
      throw new ProtocolError('Negative mpints are not produced by anything in SSH that this writes')

    let hex = value.toString(16)
    if (hex.length % 2 === 1)
      hex = `0${hex}`

    const bytes = new Uint8Array(hex.length / 2)
    for (let index = 0; index < bytes.length; index++)
      bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16)

    if ((bytes[0]! & 0x80) !== 0) {
      const padded = new Uint8Array(bytes.length + 1)
      padded.set(bytes, 1)

      return this.string(padded)
    }

    return this.string(bytes)
  }

  /** How many bytes have been written. */
  get size(): number {
    return this.length
  }

  done(): Uint8Array {
    const out = new Uint8Array(this.length)
    let offset = 0

    for (const chunk of this.chunks) {
      out.set(chunk, offset)
      offset += chunk.length
    }

    return out
  }
}

/** A Writer, for callers that prefer a function to a constructor. */
export function write(build: (writer: Writer) => void): Uint8Array {
  const writer = new Writer()
  build(writer)

  return writer.done()
}
