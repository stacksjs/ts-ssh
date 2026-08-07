/**
 * The key exchange: agreement, framing, and the signature over it.
 *
 * Two things are worth checking here beyond the obvious round trips. That both
 * sides reach the same secret, which is the whole exercise. And that the
 * signature is over *everything that was said* - so the tests below alter one
 * field of the exchange hash at a time and insist the signature stops checking
 * out, because a signature that survives an edit is one that proves nothing
 * about what was edited.
 */

import { describe, expect, it } from 'bun:test'
import { ProtocolError } from '../src/buffer'
import {
  generateEphemeral,
  readKexEcdhInit,
  readKexEcdhReply,
  verifyExchangeSignature,
  writeKexEcdhInit,
  writeKexEcdhReply,
} from '../src/exchange'
import { exchangeHash, negotiateAll, readKexInit, STRICT_KEX_CLIENT, STRICT_KEX_SERVER, writeKexInit, ALGORITHMS } from '../src/kex'
import { generateHostKey } from '../src/privatekey'

describe('generateEphemeral', () => {
  it('brings both sides to the same secret', () => {
    const client = generateEphemeral()
    const server = generateEphemeral()

    expect(client.agree(server.publicKey)).toBe(server.agree(client.publicKey))
  })

  it('produces a different key every time', () => {
    expect(generateEphemeral().publicKey).not.toEqual(generateEphemeral().publicKey)
  })

  it('gives a 32 byte point', () => {
    expect(generateEphemeral().publicKey.length).toBe(32)
  })

  it('refuses a point of the wrong size', () => {
    expect(() => generateEphemeral().agree(new Uint8Array(31))).toThrow(ProtocolError)
  })

  it('refuses a point with no contribution in it', () => {
    // All zeros is the canonical low-order point: it makes the shared secret
    // the same for every connection, so the exchange hash proves nothing.
    // RFC 8731 §3 says to abort rather than continue.
    expect(() => generateEphemeral().agree(new Uint8Array(32))).toThrow(/no contribution/)
  })
})

describe('the exchange messages', () => {
  it('round-trips an init', () => {
    const point = generateEphemeral().publicKey

    expect(readKexEcdhInit(writeKexEcdhInit(point)).clientPublic).toEqual(point)
  })

  it('round-trips a reply', () => {
    const host = generateHostKey()
    const reply = {
      hostKey: host.key.publicKey,
      serverPublic: generateEphemeral().publicKey,
      signature: host.key.sign(new Uint8Array([1, 2, 3])),
    }

    expect(readKexEcdhReply(writeKexEcdhReply(reply))).toEqual(reply)
  })

  it('refuses a point that is not a curve25519 one', () => {
    expect(() => readKexEcdhInit(new Uint8Array([30, 0, 0, 0, 2, 1, 2]))).toThrow(ProtocolError)
  })

  it('refuses the wrong message number', () => {
    expect(() => readKexEcdhInit(writeKexEcdhReply({
      hostKey: new Uint8Array(0),
      serverPublic: new Uint8Array(32),
      signature: new Uint8Array(0),
    }))).toThrow(/Expected KEX_ECDH_INIT/)
  })
})

describe('verifyExchangeSignature', () => {
  const host = generateHostKey()
  const client = generateEphemeral()
  const server = generateEphemeral()

  const input = {
    clientIdentification: 'SSH-2.0-OpenSSH_9.6',
    serverIdentification: 'SSH-2.0-ts-ssh',
    clientKexInit: writeKexInit(ALGORITHMS),
    serverKexInit: writeKexInit(ALGORITHMS),
    hostKey: host.key.publicKey,
    clientPublic: client.publicKey,
    serverPublic: server.publicKey,
    sharedSecret: client.agree(server.publicKey),
  }

  it('accepts a signature the host key made', () => {
    const hash = exchangeHash(input)

    expect(verifyExchangeSignature({
      hostKey: host.key.publicKey,
      exchangeHash: hash,
      signature: host.key.sign(hash),
    })).toEqual({ ok: true })
  })

  it('rejects a signature from a different key', () => {
    const hash = exchangeHash(input)
    const impostor = generateHostKey()

    const result = verifyExchangeSignature({
      hostKey: host.key.publicKey,
      exchangeHash: hash,
      signature: impostor.key.sign(hash),
    })

    expect(result.ok).toBe(false)
    expect(result.reason).toContain('did not sign this exchange')
  })

  it.each([
    ['the client identification', { clientIdentification: 'SSH-2.0-somebody-else' }],
    ['the server identification', { serverIdentification: 'SSH-2.0-not-us' }],
    ['the client algorithm list', { clientKexInit: writeKexInit({ ...ALGORITHMS, cipher: ['aes128-ctr'] }) }],
    ['the server algorithm list', { serverKexInit: writeKexInit({ ...ALGORITHMS, cipher: ['aes128-ctr'] }) }],
    ['the client point', { clientPublic: generateEphemeral().publicKey }],
    ['the server point', { serverPublic: generateEphemeral().publicKey }],
    ['the shared secret', { sharedSecret: 12345n }],
  ])('stops checking out when %s is altered', (_, change) => {
    // Each of these is a field an attacker in the middle would want to edit,
    // and each is in the hash for that reason. Leave one out of the preimage
    // and this test is the only thing that would notice.
    const signature = host.key.sign(exchangeHash(input))
    const altered = exchangeHash({ ...input, ...change })

    expect(verifyExchangeSignature({
      hostKey: host.key.publicKey,
      exchangeHash: altered,
      signature,
    }).ok).toBe(false)
  })

  it('refuses a host key type it cannot verify', () => {
    const rsa = new Uint8Array([0, 0, 0, 7, 115, 115, 104, 45, 114, 115, 97, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1])
    const result = verifyExchangeSignature({
      hostKey: rsa,
      exchangeHash: new Uint8Array(32),
      signature: new Uint8Array(0),
    })

    expect(result.ok).toBe(false)
    expect(result.reason).toContain('ssh-rsa')
  })
})

describe('strict key exchange', () => {
  it('is offered by this server', () => {
    expect(ALGORITHMS.kex).toContain(STRICT_KEX_SERVER)
  })

  it('never selects a marker as an algorithm', () => {
    // A client that put the *server's* marker first would otherwise "win" a key
    // exchange named after a thing nobody can perform.
    const client = readKexInit(writeKexInit({
      ...ALGORITHMS,
      kex: [STRICT_KEX_SERVER, STRICT_KEX_CLIENT, 'curve25519-sha256'],
    }))
    const server = readKexInit(writeKexInit(ALGORITHMS))
    const result = negotiateAll(client, server)

    expect(result).not.toHaveProperty('failed')
    expect((result as { kex: string }).kex).toBe('curve25519-sha256')
  })

  it('fails rather than falling back when only markers overlap', () => {
    const client = readKexInit(writeKexInit({ ...ALGORITHMS, kex: [STRICT_KEX_SERVER] }))
    const server = readKexInit(writeKexInit(ALGORITHMS))

    expect(negotiateAll(client, server)).toEqual({ failed: 'key exchange' })
  })
})
