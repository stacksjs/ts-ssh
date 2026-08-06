import { describe, expect, it } from 'bun:test'
import { createDecipheriv, randomBytes } from 'node:crypto'
import { ProtocolError } from '../src/buffer'
import { CIPHERS, createPacketCipher, keyLengthsFor, MACS } from '../src/cipher'
import { MIN_PADDING } from '../src/packet'

/**
 * Both directions of a connection, built from the same material - which is what
 * a real handshake produces and the only way to test that seal and open agree.
 */
function pair(cipher: string, mac?: string) {
  const lengths = keyLengthsFor(cipher, mac)
  const key = randomBytes(lengths.key)
  const iv = randomBytes(lengths.iv)
  const macKey = lengths.mac > 0 ? randomBytes(lengths.mac) : undefined
  const deterministic = (size: number) => new Uint8Array(size).fill(0x2A)

  return {
    send: createPacketCipher({ cipher, mac, key, iv, macKey, random: deterministic }),
    receive: createPacketCipher({ cipher, mac, key, iv, macKey, random: deterministic }),
    key,
    iv,
  }
}

const NAMED: Array<[string, string | undefined]> = [
  ['aes256-gcm@openssh.com', undefined],
  ['aes128-gcm@openssh.com', undefined],
  ['aes256-ctr', 'hmac-sha2-256-etm@openssh.com'],
  ['aes128-ctr', 'hmac-sha2-512-etm@openssh.com'],
]

describe.each(NAMED)('%s', (cipher, mac) => {
  it('round trips a payload', () => {
    const { send, receive } = pair(cipher, mac)
    const payload = new TextEncoder().encode('SSH_MSG_CHANNEL_DATA and then some')

    expect(receive.open(0, send.seal(0, payload))).toEqual(payload)
  })

  it('round trips every awkward length', () => {
    for (const length of [1, 5, 15, 16, 17, 31, 32, 33, 255, 1024]) {
      const { send, receive } = pair(cipher, mac)
      const payload = new Uint8Array(length).fill(0xAB)

      expect(receive.open(0, send.seal(0, payload))).toEqual(payload)
    }
  })

  /**
   * The encrypted section has to be a whole number of blocks or the cipher
   * cannot process it, and there is always at least the minimum padding.
   */
  it('pads the encrypted section to the block size', () => {
    const spec = CIPHERS[cipher]!
    const tag = spec.aead ? spec.tagLength : MACS[mac!]!.length

    for (let length = 0; length < 64; length++) {
      const { send } = pair(cipher, mac)
      const packet = send.seal(0, new Uint8Array(length))
      const encrypted = packet.length - 4 - tag

      expect(encrypted % spec.blockSize).toBe(0)
      expect(encrypted).toBeGreaterThanOrEqual(1 + length + MIN_PADDING)
    }
  })

  /** The receiver has to size its read before it can decrypt anything. */
  it('says how long a packet is from its first four bytes', () => {
    const { send } = pair(cipher, mac)
    const packet = send.seal(0, new Uint8Array(100))

    expect(send.packetLength(packet.subarray(0, 4))).toBe(packet.length)
  })

  it('keeps the payload off the wire in the clear', () => {
    const { send } = pair(cipher, mac)
    const secret = new TextEncoder().encode('correct horse battery staple')
    const packet = send.seal(0, secret)

    expect(Buffer.from(packet).includes(Buffer.from(secret))).toBe(false)
  })

  describe('refuses', () => {
    it('a tampered payload', () => {
      const { send, receive } = pair(cipher, mac)
      const packet = send.seal(0, new Uint8Array(32).fill(7))
      packet[10] ^= 0xFF

      expect(() => receive.open(0, packet)).toThrow(ProtocolError)
    })

    it('a tampered tag', () => {
      const { send, receive } = pair(cipher, mac)
      const packet = send.seal(0, new Uint8Array(32).fill(7))
      packet[packet.length - 1] ^= 0xFF

      expect(() => receive.open(0, packet)).toThrow(ProtocolError)
    })

    /** The length is authenticated even where it is not encrypted. */
    it('a tampered length', () => {
      const { send, receive } = pair(cipher, mac)
      const packet = send.seal(0, new Uint8Array(32).fill(7))
      packet[3] = (packet[3]! + 16) & 0xFF

      expect(() => receive.open(0, packet)).toThrow(ProtocolError)
    })

    /**
     * The sequence number is what stops a packet being replayed at a different
     * point in the stream, so it has to be part of what is authenticated.
     */
    it('a packet replayed at a different sequence number', () => {
      const { send, receive } = pair(cipher, mac)
      const packet = send.seal(0, new Uint8Array(32).fill(7))

      expect(() => receive.open(1, packet)).toThrow(ProtocolError)
    })

    it('a packet truncated below anything legal', () => {
      const { receive } = pair(cipher, mac)

      expect(() => receive.open(0, new Uint8Array(4))).toThrow(ProtocolError)
    })

    it('a length field longer than the packet', () => {
      const { send, receive } = pair(cipher, mac)
      const packet = send.seal(0, new Uint8Array(16))
      new DataView(packet.buffer, packet.byteOffset, 4).setUint32(0, 9999, false)

      expect(() => receive.open(0, packet)).toThrow(ProtocolError)
    })
  })

  it('carries a stream of packets, in order', () => {
    const { send, receive } = pair(cipher, mac)

    for (let sequence = 0; sequence < 20; sequence++) {
      const payload = new TextEncoder().encode(`packet ${sequence}`)

      expect(receive.open(sequence, send.seal(sequence, payload))).toEqual(payload)
    }
  })
})

describe('the GCM construction', () => {
  /**
   * Checked against OpenSSL directly rather than against ourselves: the length
   * is additional data and the rest is the ciphertext, and if the AAD boundary
   * were wrong both halves of this library would still agree with each other.
   */
  it('authenticates the length as additional data, and encrypts the rest', () => {
    const key = randomBytes(32)
    const iv = randomBytes(12)
    const send = createPacketCipher({
      cipher: 'aes256-gcm@openssh.com',
      key,
      iv,
      random: size => new Uint8Array(size).fill(0),
    })

    const payload = new TextEncoder().encode('hello over the wire')
    const packet = send.seal(0, payload)

    const header = packet.subarray(0, 4)
    const body = packet.subarray(4, packet.length - 16)
    const tag = packet.subarray(packet.length - 16)

    // The nonce for sequence 0 is the derived iv unchanged.
    const decipher = createDecipheriv('aes-256-gcm', key, iv)
    decipher.setAAD(Buffer.from(header))
    decipher.setAuthTag(Buffer.from(tag))

    const plain = Buffer.concat([decipher.update(Buffer.from(body)), decipher.final()])

    expect(plain.subarray(1, 1 + payload.length)).toEqual(Buffer.from(payload))
    expect(plain[0]).toBe(plain.length - 1 - payload.length)
  })

  /**
   * Reusing a nonce under GCM does not merely leak a plaintext, it leaks the
   * authentication key. The counter comes from the sequence number so the two
   * cannot drift apart.
   */
  it('uses a different nonce for every sequence number', () => {
    const key = randomBytes(32)
    const iv = randomBytes(12)
    const zero = (size: number) => new Uint8Array(size).fill(0)
    const seen = new Set<string>()

    for (let sequence = 0; sequence < 50; sequence++) {
      const cipher = createPacketCipher({ cipher: 'aes256-gcm@openssh.com', key, iv, random: zero })
      const packet = cipher.seal(sequence, new Uint8Array(16))

      seen.add(Buffer.from(packet.subarray(4)).toString('hex'))
    }

    expect(seen.size).toBe(50)
  })
})

describe('createPacketCipher', () => {
  /** A name it cannot honour is a handshake that completes and a connection that does nothing. */
  it('refuses a cipher it does not implement', () => {
    expect(() => createPacketCipher({
      cipher: 'chacha20-poly1305@openssh.com',
      key: randomBytes(64),
      iv: randomBytes(0),
    })).toThrow(ProtocolError)
  })

  it('refuses a cipher that needs a mac without one it implements', () => {
    expect(() => createPacketCipher({
      cipher: 'aes256-ctr',
      key: randomBytes(32),
      iv: randomBytes(16),
    })).toThrow(ProtocolError)

    expect(() => createPacketCipher({
      cipher: 'aes256-ctr',
      mac: 'hmac-md5',
      key: randomBytes(32),
      iv: randomBytes(16),
      macKey: randomBytes(16),
    })).toThrow(ProtocolError)
  })

  it('refuses key material of the wrong length', () => {
    expect(() => createPacketCipher({ cipher: 'aes256-gcm@openssh.com', key: randomBytes(16), iv: randomBytes(12) })).toThrow(ProtocolError)
    expect(() => createPacketCipher({ cipher: 'aes256-gcm@openssh.com', key: randomBytes(32), iv: randomBytes(16) })).toThrow(ProtocolError)
    expect(() => createPacketCipher({
      cipher: 'aes256-ctr',
      mac: 'hmac-sha2-256-etm@openssh.com',
      key: randomBytes(32),
      iv: randomBytes(16),
      macKey: randomBytes(8),
    })).toThrow(ProtocolError)
  })
})

describe('keyLengthsFor', () => {
  it('says how much of each key to derive', () => {
    expect(keyLengthsFor('aes256-gcm@openssh.com')).toEqual({ key: 32, iv: 12, mac: 0 })
    expect(keyLengthsFor('aes128-gcm@openssh.com')).toEqual({ key: 16, iv: 12, mac: 0 })
    expect(keyLengthsFor('aes256-ctr', 'hmac-sha2-256-etm@openssh.com')).toEqual({ key: 32, iv: 16, mac: 32 })
    expect(keyLengthsFor('aes256-ctr', 'hmac-sha2-512-etm@openssh.com')).toEqual({ key: 32, iv: 16, mac: 64 })
  })

  it('refuses to size something it cannot build', () => {
    expect(() => keyLengthsFor('chacha20-poly1305@openssh.com')).toThrow(ProtocolError)
    expect(() => keyLengthsFor('aes256-ctr')).toThrow(ProtocolError)
  })
})

describe('what is offered is what can be applied', () => {
  /**
   * The bug this exists for: `ALGORITHMS` offered
   * `chacha20-poly1305@openssh.com` and plain `hmac-sha2-256` while the cipher
   * layer implemented neither. Both lists looked right on their own. A name in
   * a KEXINIT list is a promise, and a handshake that completes on a promise
   * nothing can keep is a connection that then does nothing.
   */
  it('offers no cipher this cannot build', async () => {
    const { ALGORITHMS } = await import('../src/kex')
    const missing = ALGORITHMS.cipher.filter(name => !(name in CIPHERS))

    expect(missing).toEqual([])
  })

  it('offers no mac this cannot build', async () => {
    const { ALGORITHMS } = await import('../src/kex')
    const missing = ALGORITHMS.mac.filter(name => !(name in MACS))

    expect(missing).toEqual([])
  })

  /** A list that matched nothing would pass the two rules above forever. */
  it('offers something', async () => {
    const { ALGORITHMS } = await import('../src/kex')

    expect(ALGORITHMS.cipher.length).toBeGreaterThan(0)
    expect(ALGORITHMS.mac.length).toBeGreaterThan(0)
  })

  /** Every offered pairing actually produces a working cipher. */
  it('can build every cipher it offers, with a mac it offers', async () => {
    const { ALGORITHMS } = await import('../src/kex')

    for (const name of ALGORITHMS.cipher) {
      const spec = CIPHERS[name]!
      const macName = spec.aead ? undefined : ALGORITHMS.mac[0]
      const lengths = keyLengthsFor(name, macName)

      const cipher = createPacketCipher({
        cipher: name,
        mac: macName,
        key: randomBytes(lengths.key),
        iv: randomBytes(lengths.iv),
        macKey: lengths.mac > 0 ? randomBytes(lengths.mac) : undefined,
      })

      const payload = new TextEncoder().encode(`built ${name}`)
      expect(cipher.spec.name).toBe(name)
      expect(cipher.seal(0, payload).length).toBeGreaterThan(payload.length)
    }
  })
})
