import { describe, expect, it } from 'bun:test'
import { generateKeyPairSync, sign } from 'node:crypto'
import { Reader, Writer } from '../src/buffer'
import {
  parseSignature,
  readUserAuthRequest,
  signedData,
  verifyUserAuthSignature,
  writeUserAuthFailure,
  writeUserAuthPkOk,
  writeUserAuthSuccess,
} from '../src/auth'
import { ed25519Blob } from '../src/keys'

/**
 * A real key and real signatures. Nothing here is a fixture of what this
 * library produced: the signature is made by node's crypto over the bytes the
 * RFC specifies, and verification has to agree with it.
 */
const { publicKey, privateKey } = generateKeyPairSync('ed25519')
const point = new Uint8Array(publicKey.export({ format: 'der', type: 'spki' })).subarray(-32)
const blob = ed25519Blob(point)

const SESSION = new Uint8Array(32).fill(9)

function request(over: Partial<{ user: string, service: string, sessionId: Uint8Array, blob: Uint8Array, algorithm: string }> = {}) {
  const user = over.user ?? 'ada'
  const service = over.service ?? 'ssh-connection'
  const algorithm = over.algorithm ?? 'ssh-ed25519'
  const key = over.blob ?? blob

  const data = signedData({ sessionId: over.sessionId ?? SESSION, user, service, algorithm, publicKey: key })
  const raw = sign(null, data, privateKey)
  const signature = new Writer().string(algorithm).string(new Uint8Array(raw)).done()

  return { user, service, method: 'publickey', hasSignature: true, algorithm, publicKey: key, signature }
}

describe('readUserAuthRequest', () => {
  it('reads a publickey request with a signature', () => {
    const payload = new Writer()
      .byte(50)
      .string('ada')
      .string('ssh-connection')
      .string('publickey')
      .boolean(true)
      .string('ssh-ed25519')
      .string(blob)
      .string(new Uint8Array([1, 2, 3]))
      .done()

    const parsed = readUserAuthRequest(payload)

    expect(parsed.user).toBe('ada')
    expect(parsed.service).toBe('ssh-connection')
    expect(parsed.hasSignature).toBe(true)
    expect(parsed.publicKey).toEqual(blob)
  })

  /** A client asks about each key before signing, so it does not make somebody touch a token per candidate. */
  it('reads a probe, which carries no signature', () => {
    const payload = new Writer()
      .byte(50).string('ada').string('ssh-connection').string('publickey')
      .boolean(false).string('ssh-ed25519').string(blob)
      .done()

    const parsed = readUserAuthRequest(payload)

    expect(parsed.hasSignature).toBe(false)
    expect(parsed.signature).toBeUndefined()
  })

  it('reads a method it does not handle without inventing fields', () => {
    const payload = new Writer().byte(50).string('ada').string('ssh-connection').string('password').done()

    expect(readUserAuthRequest(payload)).toEqual({ user: 'ada', service: 'ssh-connection', method: 'password' })
  })

  it('refuses a payload that is not a userauth request', () => {
    expect(() => readUserAuthRequest(new Uint8Array([51]))).toThrow()
  })
})

describe('signedData', () => {
  /** RFC 4252 §7, in order. Both sides building this identically is the agreement. */
  it('is the eight fields the RFC lists', () => {
    const reader = new Reader(signedData({
      sessionId: SESSION, user: 'ada', service: 'ssh-connection', algorithm: 'ssh-ed25519', publicKey: blob,
    }))

    expect(reader.string()).toEqual(SESSION)
    expect(reader.byte()).toBe(50)
    expect(reader.text()).toBe('ada')
    expect(reader.text()).toBe('ssh-connection')
    expect(reader.text()).toBe('publickey')
    expect(reader.boolean()).toBe(true)
    expect(reader.text()).toBe('ssh-ed25519')
    expect(reader.string()).toEqual(blob)
    expect(reader.remaining).toBe(0)
  })
})

describe('verifyUserAuthSignature', () => {
  it('accepts a signature the holder of the key made', () => {
    expect(verifyUserAuthSignature({ sessionId: SESSION, request: request() })).toEqual({ ok: true })
  })

  /**
   * The session identifier is the first field signed, and this is why: a
   * signature captured from one connection must not work on another.
   */
  it('refuses a signature made for a different session', () => {
    const captured = request({ sessionId: new Uint8Array(32).fill(1) })
    const result = verifyUserAuthSignature({ sessionId: SESSION, request: captured })

    expect(result.ok).toBe(false)
  })

  /** A signature for `ada` must not be replayable as `root`. */
  it('refuses a signature replayed under a different user', () => {
    const result = verifyUserAuthSignature({ sessionId: SESSION, request: { ...request(), user: 'root' } })

    expect(result.ok).toBe(false)
  })

  it('refuses a signature replayed against a different service', () => {
    const result = verifyUserAuthSignature({ sessionId: SESSION, request: { ...request(), service: 'ssh-userauth' } })

    expect(result.ok).toBe(false)
  })

  it('refuses a tampered signature', () => {
    const tampered = request()
    tampered.signature[tampered.signature.length - 1] ^= 0xFF

    expect(verifyUserAuthSignature({ sessionId: SESSION, request: tampered }).ok).toBe(false)
  })

  it('refuses a probe, which proves nothing', () => {
    const probe = { ...request(), hasSignature: false, signature: undefined }

    expect(verifyUserAuthSignature({ sessionId: SESSION, request: probe }).ok).toBe(false)
  })

  /**
   * The algorithm is stated in the request, in the blob and in the signature.
   * All three are read by different code in most implementations, which is how
   * a mismatch survives.
   */
  it('refuses when the named algorithm and the blob disagree', () => {
    const lying = { ...request(), algorithm: 'ssh-rsa' }

    expect(verifyUserAuthSignature({ sessionId: SESSION, request: lying }).reason).toContain('disagree')
  })

  it('refuses when the signature names a different algorithm than the key', () => {
    const base = request()
    const inner = parseSignature(base.signature)!
    const mismatched = { ...base, signature: new Writer().string('ssh-rsa').string(inner.signature).done() }

    expect(verifyUserAuthSignature({ sessionId: SESSION, request: mismatched }).ok).toBe(false)
  })

  it('refuses a signature of the wrong length', () => {
    const base = request()
    const short = { ...base, signature: new Writer().string('ssh-ed25519').string(new Uint8Array(63)).done() }

    expect(verifyUserAuthSignature({ sessionId: SESSION, request: short }).reason).toContain('64 bytes')
  })

  it('says plainly that it does not verify other algorithms', () => {
    const rsaBlob = new Writer().string('ssh-rsa').mpint(65537n).mpint(0x00C0n).done()
    const result = verifyUserAuthSignature({
      sessionId: SESSION,
      request: { ...request(), algorithm: 'ssh-rsa', publicKey: rsaBlob, signature: new Writer().string('ssh-rsa').string(new Uint8Array(64)).done() },
    })

    expect(result.ok).toBe(false)
    expect(result.reason).toContain('ssh-rsa')
  })

  it('refuses a non-publickey method', () => {
    const result = verifyUserAuthSignature({ sessionId: SESSION, request: { user: 'ada', service: 'ssh-connection', method: 'password' } })

    expect(result.ok).toBe(false)
  })
})

describe('the replies', () => {
  it('writes a failure naming what could be tried instead', () => {
    const reader = new Reader(writeUserAuthFailure(['publickey'], false))

    expect(reader.byte()).toBe(51)
    expect(reader.nameList()).toEqual(['publickey'])
    expect(reader.boolean()).toBe(false)
  })

  it('writes a success, which has no fields', () => {
    expect([...writeUserAuthSuccess()]).toEqual([52])
  })

  it('writes a PK_OK that echoes the key it would accept', () => {
    const reader = new Reader(writeUserAuthPkOk('ssh-ed25519', blob))

    expect(reader.byte()).toBe(60)
    expect(reader.text()).toBe('ssh-ed25519')
    expect(reader.string()).toEqual(blob)
  })
})
