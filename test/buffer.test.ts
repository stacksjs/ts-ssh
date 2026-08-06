import { describe, expect, it } from 'bun:test'
import { ProtocolError, Reader, Writer, write } from '../src/buffer'

/**
 * RFC 4251 §5. Everything above these depends on them, so they are pinned
 * against the byte sequences the RFC itself gives.
 */

const bytes = (...values: number[]) => new Uint8Array(values)

describe('integers', () => {
  it('writes uint32 big endian', () => {
    expect(write(w => w.uint32(0x29B7F4AA))).toEqual(bytes(0x29, 0xB7, 0xF4, 0xAA))
  })

  /** The top bit is where a shift would go signed and produce a negative length. */
  it('reads a uint32 with the top bit set as a positive number', () => {
    expect(new Reader(bytes(0xFF, 0xFF, 0xFF, 0xFF)).uint32()).toBe(4294967295)
  })

  it('round trips uint64 through bigint', () => {
    const value = 0x0123456789ABCDEFn

    expect(new Reader(write(w => w.uint64(value))).uint64()).toBe(value)
  })
})

describe('booleans', () => {
  it('writes 1 for true, as senders must', () => {
    expect(write(w => w.boolean(true))).toEqual(bytes(1))
    expect(write(w => w.boolean(false))).toEqual(bytes(0))
  })

  /** Receivers must not require 1: anything non-zero is true. */
  it('reads any non-zero byte as true', () => {
    expect(new Reader(bytes(1)).boolean()).toBe(true)
    expect(new Reader(bytes(42)).boolean()).toBe(true)
    expect(new Reader(bytes(0)).boolean()).toBe(false)
  })
})

describe('strings', () => {
  it('is a length then that many bytes', () => {
    expect(write(w => w.string('testing'))).toEqual(bytes(0, 0, 0, 7, 116, 101, 115, 116, 105, 110, 103))
  })

  it('carries arbitrary binary, not only text', () => {
    const binary = bytes(0x00, 0xFF, 0x80)

    expect(new Reader(write(w => w.string(binary))).string()).toEqual(binary)
  })

  it('round trips an empty string', () => {
    expect(new Reader(write(w => w.string(''))).string()).toEqual(new Uint8Array(0))
  })
})

describe('mpint', () => {
  /** The examples in RFC 4251 §5, which exist because this is the type people get wrong. */
  it('writes zero as an empty string, not a zero byte', () => {
    expect(write(w => w.mpint(0n))).toEqual(bytes(0, 0, 0, 0))
  })

  it('writes a leading zero when the top bit would read as negative', () => {
    expect(write(w => w.mpint(0x80n))).toEqual(bytes(0, 0, 0, 2, 0x00, 0x80))
  })

  it('writes no leading zero when it is not needed', () => {
    expect(write(w => w.mpint(0x7Fn))).toEqual(bytes(0, 0, 0, 1, 0x7F))
  })

  it('writes the RFC example', () => {
    expect(write(w => w.mpint(0x9A378F9B2E332A7n)))
      .toEqual(bytes(0, 0, 0, 8, 0x09, 0xA3, 0x78, 0xF9, 0xB2, 0xE3, 0x32, 0xA7))
  })

  it('reads a negative value back as negative', () => {
    expect(new Reader(bytes(0, 0, 0, 1, 0x80)).mpint()).toBe(-128n)
  })

  it('round trips a value the size of a real modulus', () => {
    const modulus = (1n << 2047n) + 12345n

    expect(new Reader(write(w => w.mpint(modulus))).mpint()).toBe(modulus)
  })

  it('refuses to write a negative, which nothing in SSH produces here', () => {
    expect(() => write(w => w.mpint(-1n))).toThrow(ProtocolError)
  })
})

describe('name lists', () => {
  it('is a comma separated string', () => {
    expect(write(w => w.nameList(['zlib', 'none']))).toEqual(
      new Uint8Array([0, 0, 0, 9, ...new TextEncoder().encode('zlib,none')]),
    )
  })

  it('reads an empty list from an empty string, not a list of one empty name', () => {
    expect(new Reader(write(w => w.nameList([]))).nameList()).toEqual([])
  })
})

describe('bounds', () => {
  /**
   * Every length here came from an unauthenticated peer. A length it invented
   * has to become a refusal, never an out-of-bounds read.
   */
  it('refuses a string longer than the buffer', () => {
    expect(() => new Reader(bytes(0, 0, 0, 99, 1, 2)).string()).toThrow(ProtocolError)
  })

  it('refuses to read past the end', () => {
    const reader = new Reader(bytes(1, 2))
    reader.byte()
    reader.byte()

    expect(() => reader.byte()).toThrow(ProtocolError)
  })

  it('knows how much is left', () => {
    const reader = new Reader(bytes(1, 2, 3))
    reader.byte()

    expect(reader.remaining).toBe(2)
    expect(reader.position).toBe(1)
  })
})

describe('Writer', () => {
  it('reports what it has written', () => {
    const writer = new Writer()
    writer.uint32(1).string('ab')

    expect(writer.size).toBe(4 + 4 + 2)
  })
})
