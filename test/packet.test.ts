import { describe, expect, it } from 'bun:test'
import { ProtocolError } from '../src/buffer'
import {
  framePacket,
  identificationString,
  MIN_PADDING,
  paddingFor,
  parseIdentification,
  takeLines,
  unframePacket,
} from '../src/packet'

/** Deterministic padding, so the framing can be checked byte for byte. */
const zeros = (size: number) => new Uint8Array(size)

describe('paddingFor', () => {
  /**
   * The whole packet including the length field is a multiple of the block
   * size, and there are always at least four bytes of padding.
   */
  it('pads to the block, counting the length field', () => {
    // 5 + 3 = 8, already aligned, so a whole extra block is needed for the minimum.
    expect(paddingFor(3, 8, false)).toBe(8)
    // 5 + 1 = 6, so 2 would align it - but the minimum is 4, so 10.
    expect(paddingFor(1, 8, false)).toBe(10)
  })

  it('never pads less than the minimum', () => {
    for (let length = 0; length < 64; length++)
      expect(paddingFor(length, 8, false)).toBeGreaterThanOrEqual(MIN_PADDING)
  })

  it('aligns the whole packet, for every payload', () => {
    for (let length = 0; length < 64; length++)
      expect((5 + length + paddingFor(length, 8, false)) % 8).toBe(0)
  })

  /** A cipher that covers the length field changes what is aligned. */
  it('starts at padding_length when the length field is encrypted', () => {
    for (let length = 0; length < 64; length++)
      expect((1 + length + paddingFor(length, 8, true)) % 8).toBe(0)
  })

  it('honours a larger cipher block', () => {
    for (let length = 0; length < 64; length++)
      expect((5 + length + paddingFor(length, 16, false)) % 16).toBe(0)
  })

  /** The floor is 8 even for a stream cipher that claims a block of 1. */
  it('never aligns to less than eight', () => {
    expect((5 + 3 + paddingFor(3, 1, false)) % 8).toBe(0)
  })
})

describe('framePacket', () => {
  it('writes the length, the padding length, the payload and the padding', () => {
    const framed = framePacket(new Uint8Array([1, 2, 3]), 8, zeros)

    expect(framed[0]).toBe(0)
    expect(framed[3]).toBe(1 + 3 + 8)
    expect(framed[4]).toBe(8)
    expect([...framed.subarray(5, 8)]).toEqual([1, 2, 3])
    expect(framed).toHaveLength(4 + 1 + 3 + 8)
  })

  it('round trips any payload', () => {
    for (const length of [0, 1, 7, 8, 9, 100, 1000]) {
      const payload = new Uint8Array(length).fill(0xAB)

      expect(unframePacket(framePacket(payload, 8, zeros))).toEqual(payload)
    }
  })

  /** Random padding is what stops an observer measuring a password's length. */
  it('uses real randomness by default', () => {
    const a = framePacket(new Uint8Array([1]))
    const b = framePacket(new Uint8Array([1]))

    expect(a.subarray(6)).not.toEqual(b.subarray(6))
  })
})

describe('unframePacket', () => {
  /** Every length came from the peer, so every one is checked. */
  it('refuses a padding length that does not fit', () => {
    const bad = new Uint8Array([0, 0, 0, 10, 200, 1, 2, 3, 4, 5, 6, 7, 8])

    expect(() => unframePacket(bad)).toThrow(ProtocolError)
  })

  it('refuses a packet shorter than its own length field', () => {
    expect(() => unframePacket(new Uint8Array([0, 0, 0, 99, 4, 1]))).toThrow(ProtocolError)
  })

  it('refuses a length that is absurd', () => {
    expect(() => unframePacket(new Uint8Array([0xFF, 0xFF, 0xFF, 0xFF, 4]))).toThrow(ProtocolError)
  })

  it('refuses padding below the minimum', () => {
    const bad = new Uint8Array([0, 0, 0, 8, 3, 1, 2, 3, 4, 5, 6, 7])

    expect(() => unframePacket(bad)).toThrow(ProtocolError)
  })
})

describe('parseIdentification', () => {
  it('reads a line OpenSSH sends', () => {
    const id = parseIdentification('SSH-2.0-OpenSSH_9.6\r\n')!

    expect(id.protocol).toBe('2.0')
    expect(id.software).toBe('OpenSSH_9.6')
    expect(id.raw).toBe('SSH-2.0-OpenSSH_9.6')
  })

  /** Implementations that send bare LF are everywhere. */
  it('takes a bare newline as readily as CRLF', () => {
    expect(parseIdentification('SSH-2.0-x\n')?.software).toBe('x')
  })

  it('keeps the comment after the first space', () => {
    const id = parseIdentification('SSH-2.0-OpenSSH_9.6 FreeBSD-20240104\r\n')!

    expect(id.software).toBe('OpenSSH_9.6')
    expect(id.comments).toBe('FreeBSD-20240104')
  })

  it('refuses a version this does not speak', () => {
    expect(parseIdentification('SSH-1.99-OpenSSH_9.6\r\n')).toBeNull()
    expect(parseIdentification('SSH-1.5-old\r\n')).toBeNull()
  })

  it('refuses a line that is not an identification at all', () => {
    expect(parseIdentification('hello there\r\n')).toBeNull()
    expect(parseIdentification('SSH-2.0\r\n')).toBeNull()
  })

  it('names itself', () => {
    expect(identificationString()).toBe('SSH-2.0-ts-ssh')
    expect(identificationString('forge_1.0')).toBe('SSH-2.0-forge_1.0')
  })
})

describe('takeLines', () => {
  /**
   * A server may send banner lines before its identification, and TCP may split
   * any of them. Losing the remainder is the bug that works on a fast
   * connection and not a slow one.
   */
  it('keeps the incomplete tail', () => {
    const { lines, rest } = takeLines(new TextEncoder().encode('one\r\ntwo\r\nthr'))

    expect(lines).toEqual(['one', 'two'])
    expect(new TextDecoder().decode(rest)).toBe('thr')
  })

  it('has nothing to give from a buffer with no newline yet', () => {
    const { lines, rest } = takeLines(new TextEncoder().encode('partial'))

    expect(lines).toEqual([])
    expect(new TextDecoder().decode(rest)).toBe('partial')
  })
})
