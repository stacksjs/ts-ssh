import { describe, expect, it } from 'bun:test'
import { Reader } from '../src/buffer'
import { ALGORITHMS, deriveKey, exchangeHash, exchangeHashPreimage, negotiate, negotiateAll, readKexInit, writeKexInit } from '../src/kex'

const offer = {
  kex: ALGORITHMS.kex,
  hostKey: ALGORITHMS.hostKey,
  cipher: ALGORITHMS.cipher,
  mac: ALGORITHMS.mac,
  compression: ALGORITHMS.compression,
}

describe('KEXINIT', () => {
  it('round trips', () => {
    const cookie = new Uint8Array(16).fill(7)
    const parsed = readKexInit(writeKexInit({ ...offer, cookie }))

    expect([...parsed.cookie]).toEqual([...cookie])
    expect(parsed.kex).toEqual([...ALGORITHMS.kex])
    expect(parsed.hostKey).toEqual([...ALGORITHMS.hostKey])
    expect(parsed.cipherClientToServer).toEqual([...ALGORITHMS.cipher])
    expect(parsed.compressionServerToClient).toEqual(['none'])
    expect(parsed.firstKexPacketFollows).toBe(false)
  })

  it('starts with the message number', () => {
    expect(writeKexInit(offer)[0]).toBe(20)
  })

  it('refuses to read something that is not a KEXINIT', () => {
    expect(() => readKexInit(new Uint8Array([21, 0, 0]))).toThrow()
  })

  it('refuses a cookie that is not 16 bytes', () => {
    expect(() => writeKexInit({ ...offer, cookie: new Uint8Array(8) })).toThrow()
  })
})

describe('negotiate', () => {
  /**
   * The client's preference wins, per RFC 4253 §7.1. A server that picks its
   * own favourite is a server that can be talked down to its weakest option.
   */
  it('takes the client\'s first choice that the server also has', () => {
    expect(negotiate(['b', 'a'], ['a', 'b'])).toBe('b')
    expect(negotiate(['a', 'b'], ['b', 'a'])).toBe('a')
  })

  /** There is no safe default algorithm, so no overlap is a disconnect. */
  it('has no answer when nothing is shared', () => {
    expect(negotiate(['a'], ['b'])).toBeNull()
    expect(negotiate([], ['a'])).toBeNull()
  })
})

describe('negotiateAll', () => {
  const both = () => readKexInit(writeKexInit(offer))

  it('agrees with itself', () => {
    const agreed = negotiateAll(both(), both())

    expect('failed' in agreed).toBe(false)
    if (!('failed' in agreed)) {
      expect(agreed.kex).toBe('curve25519-sha256')
      expect(agreed.hostKey).toBe('ssh-ed25519')
      expect(agreed.cipherClientToServer).toBe('aes256-gcm@openssh.com')
    }
  })

  /**
   * Both default ciphers authenticate their own data. Insisting on a separate
   * MAC would refuse the strongest ciphers there are.
   */
  it('expects no separate mac from a cipher that authenticates itself', () => {
    const agreed = negotiateAll(both(), both())

    if (!('failed' in agreed)) {
      expect(agreed.macClientToServer).toBe('<implicit>')
      expect(agreed.macServerToClient).toBe('<implicit>')
    }
  })

  it('says which category failed', () => {
    const client = readKexInit(writeKexInit({ ...offer, kex: ['diffie-hellman-group1-sha1'] }))

    expect(negotiateAll(client, both())).toEqual({ failed: 'key exchange' })
  })

  it('says so when no host key type is shared', () => {
    const client = readKexInit(writeKexInit({ ...offer, hostKey: ['ssh-dss'] }))

    expect(negotiateAll(client, both())).toEqual({ failed: 'host key' })
  })
})

describe('the exchange hash', () => {
  const input = {
    clientIdentification: 'SSH-2.0-client',
    serverIdentification: 'SSH-2.0-ts-ssh',
    clientKexInit: new Uint8Array([20, 1, 2]),
    serverKexInit: new Uint8Array([20, 3, 4]),
    hostKey: new Uint8Array([9, 9]),
    clientPublic: new Uint8Array(32).fill(1),
    serverPublic: new Uint8Array(32).fill(2),
    sharedSecret: 0x1234567890ABCDEFn,
  }

  /**
   * The field order is the whole security argument: a signature over H is a
   * signature over both sides' idea of what was negotiated.
   */
  it('is the eight fields, in order', () => {
    const reader = new Reader(exchangeHashPreimage(input))

    expect(reader.text()).toBe('SSH-2.0-client')
    expect(reader.text()).toBe('SSH-2.0-ts-ssh')
    expect([...reader.string()]).toEqual([20, 1, 2])
    expect([...reader.string()]).toEqual([20, 3, 4])
    expect([...reader.string()]).toEqual([9, 9])
    expect(reader.string()).toHaveLength(32)
    expect(reader.string()).toHaveLength(32)
    expect(reader.mpint()).toBe(0x1234567890ABCDEFn)
    expect(reader.remaining).toBe(0)
  })

  it('is a sha256, so 32 bytes', () => {
    expect(exchangeHash(input)).toHaveLength(32)
  })

  /**
   * Change any field and H changes. That is what makes an edited algorithm
   * list in flight produce a signature that does not check out.
   */
  it('changes when anything either side said changes', () => {
    const base = exchangeHash(input)

    expect(exchangeHash({ ...input, clientKexInit: new Uint8Array([20, 1, 3]) })).not.toEqual(base)
    expect(exchangeHash({ ...input, clientIdentification: 'SSH-2.0-other' })).not.toEqual(base)
    expect(exchangeHash({ ...input, sharedSecret: input.sharedSecret + 1n })).not.toEqual(base)
    expect(exchangeHash({ ...input, hostKey: new Uint8Array([9, 8]) })).not.toEqual(base)
  })
})

describe('deriveKey', () => {
  const secret = 0xDEADBEEFn
  const hash = new Uint8Array(32).fill(3)

  it('gives a different key for every letter', () => {
    const keys = (['A', 'B', 'C', 'D', 'E', 'F'] as const).map(letter => deriveKey(secret, hash, letter, hash, 32))
    const distinct = new Set(keys.map(key => key.join(',')))

    expect(distinct.size).toBe(6)
  })

  it('gives exactly the length asked for, including past one digest', () => {
    expect(deriveKey(secret, hash, 'A', hash, 16)).toHaveLength(16)
    expect(deriveKey(secret, hash, 'A', hash, 32)).toHaveLength(32)
    expect(deriveKey(secret, hash, 'A', hash, 64)).toHaveLength(64)
  })

  /** The extension rehashes what came before, so the first digest is a prefix. */
  it('extends rather than restarting', () => {
    const short = deriveKey(secret, hash, 'C', hash, 32)
    const long = deriveKey(secret, hash, 'C', hash, 64)

    expect(long.subarray(0, 32)).toEqual(short)
  })

  it('depends on the secret and the session', () => {
    const a = deriveKey(secret, hash, 'A', hash, 32)

    expect(deriveKey(secret + 1n, hash, 'A', hash, 32)).not.toEqual(a)
    expect(deriveKey(secret, hash, 'A', new Uint8Array(32).fill(4), 32)).not.toEqual(a)
  })
})
