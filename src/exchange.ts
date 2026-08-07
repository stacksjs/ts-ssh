/**
 * curve25519 key exchange: the two messages, and the agreement under them.
 *
 * `kex.ts` decides *which* algorithms and computes the exchange hash once the
 * inputs are known. This is where the inputs come from - the ephemeral keys,
 * the two packets that carry them, and the signature that ties the whole
 * conversation to a host key.
 *
 * The exchange is two messages and no more (RFC 8731, and RFC 5656 for the
 * shape):
 *
 *     SSH_MSG_KEX_ECDH_INIT   string Q_C
 *     SSH_MSG_KEX_ECDH_REPLY  string K_S, string Q_S, string signature
 *
 * Both sides then hold the same 32-byte secret, and only the server has proved
 * anything. That asymmetry is the design: the client authenticates afterwards,
 * inside the encryption this establishes, so a password or a signature is never
 * exposed to whoever is in the middle. Which is also why the signature has to
 * be checked *before* the client sends anything of its own - a client that
 * defers it has encrypted its secrets to the attacker.
 *
 * The keys are ephemeral and per connection. That is what forward secrecy is:
 * recording the traffic and later stealing the host key gets you a signature
 * you cannot use and a secret you cannot recover, because the private halves
 * were thrown away when the connection closed.
 */

import type { KeyObject } from 'node:crypto'
import { createPublicKey, diffieHellman, generateKeyPairSync, verify as verifySignature } from 'node:crypto'
import { parseSignature } from './auth'
import { ProtocolError, Reader, Writer } from './buffer'
import { ed25519KeyObject, parsePublicKey } from './keys'
import { Message } from './packet'

/**
 * The DER headers for X25519, which never vary.
 *
 * The same trick as the ed25519 wrappers: SSH carries a raw 32-byte point and
 * node's crypto wants a key object, and for one fixed algorithm the encoding
 * in between is a constant prefix rather than an encoder.
 */
const SPKI_X25519 = new Uint8Array([
  0x30, 0x2A, // SEQUENCE, 42 bytes
  0x30, 0x05, // SEQUENCE, 5 bytes
  0x06, 0x03, 0x2B, 0x65, 0x6E, // OID 1.3.101.110, id-X25519
  0x03, 0x21, 0x00, // BIT STRING, 33 bytes, 0 unused bits
])

/** An X25519 point, in the shape node's crypto wants. */
function x25519KeyObject(point: Uint8Array): KeyObject {
  if (point.length !== 32)
    throw new ProtocolError('An X25519 public key is 32 bytes')

  const der = new Uint8Array(SPKI_X25519.length + 32)
  der.set(SPKI_X25519)
  der.set(point, SPKI_X25519.length)

  return createPublicKey({ key: Buffer.from(der), format: 'der', type: 'spki' })
}

/**
 * One end's ephemeral key.
 *
 * The private half is a closure rather than a field, for the same reason as in
 * `privatekey.ts`: it exists for one call and nothing should be able to read it
 * back out afterwards.
 */
export interface Ephemeral {
  /** Q, the 32 bytes that go on the wire. */
  publicKey: Uint8Array
  /**
   * The shared secret with a peer's point, as the integer SSH encodes it as.
   *
   * A bigint rather than bytes, because K goes into the exchange hash as an
   * `mpint` - a signed, minimally-encoded integer - and handing back bytes
   * would leave every caller to redo that encoding. The classic bug it avoids:
   * a secret whose top bit is set needs a leading zero byte, so one connection
   * in two hundred and fifty-six fails if you skip it.
   */
  agree: (peerPublic: Uint8Array) => bigint
}

/** A fresh ephemeral keypair for one connection. */
export function generateEphemeral(): Ephemeral {
  const pair = generateKeyPairSync('x25519')
  const spki = new Uint8Array(pair.publicKey.export({ type: 'spki', format: 'der' }))

  return {
    publicKey: spki.subarray(spki.length - 32),

    agree(peerPublic) {
      if (peerPublic.length !== 32)
        throw new ProtocolError('An X25519 public key is 32 bytes')

      let secret: Uint8Array

      try {
        secret = new Uint8Array(diffieHellman({ privateKey: pair.privateKey, publicKey: x25519KeyObject(peerPublic) }))
      }
      catch {
        // An all-zero result, which is what a low-order point produces. RFC 8731
        // §3 says to abort: continuing means a "shared" secret the peer chose,
        // identical for every connection, and an exchange hash that proves
        // nothing. OpenSSL reports it as an error rather than returning zeros.
        throw new ProtocolError('The peer sent a point with no contribution in it')
      }

      // Belt and braces: a runtime that returns the zeros instead of erroring
      // must not get past here either.
      if (secret.every(byte => byte === 0))
        throw new ProtocolError('The peer sent a point with no contribution in it')

      return bytesToBigInt(secret)
    },
  }
}

/** SSH_MSG_KEX_ECDH_INIT: the client's ephemeral point. */
export function writeKexEcdhInit(clientPublic: Uint8Array): Uint8Array {
  return new Writer().byte(Message.KEX_ECDH_INIT).string(clientPublic).done()
}

export function readKexEcdhInit(payload: Uint8Array): { clientPublic: Uint8Array } {
  const reader = new Reader(payload)
  const message = reader.byte()

  if (message !== Message.KEX_ECDH_INIT)
    throw new ProtocolError(`Expected KEX_ECDH_INIT and got message ${message}`)

  const clientPublic = reader.string()
  if (clientPublic.length !== 32)
    throw new ProtocolError('A curve25519 public key is 32 bytes')

  return { clientPublic }
}

export interface KexEcdhReply {
  /** The server's host key blob, which the client checks against known_hosts. */
  hostKey: Uint8Array
  serverPublic: Uint8Array
  /** The signature over H, in wire form: an algorithm name then the bytes. */
  signature: Uint8Array
}

/** SSH_MSG_KEX_ECDH_REPLY: the server's point, its identity, and its proof. */
export function writeKexEcdhReply(reply: KexEcdhReply): Uint8Array {
  return new Writer()
    .byte(Message.KEX_ECDH_REPLY)
    .string(reply.hostKey)
    .string(reply.serverPublic)
    .string(reply.signature)
    .done()
}

export function readKexEcdhReply(payload: Uint8Array): KexEcdhReply {
  const reader = new Reader(payload)
  const message = reader.byte()

  if (message !== Message.KEX_ECDH_REPLY)
    throw new ProtocolError(`Expected KEX_ECDH_REPLY and got message ${message}`)

  const hostKey = reader.string()
  const serverPublic = reader.string()
  const signature = reader.string()

  if (serverPublic.length !== 32)
    throw new ProtocolError('A curve25519 public key is 32 bytes')

  return { hostKey, serverPublic, signature }
}

/**
 * Check that the host key really signed this exchange.
 *
 * The one check a client cannot skip. H covers both identification strings,
 * both KEXINIT payloads, the host key, both ephemeral points and the shared
 * secret, so a signature over it says: the holder of this host key saw exactly
 * this conversation. Anything altered in flight - an algorithm removed from a
 * list to force a weaker one, a substituted point - produces a different H and
 * a signature that does not check out.
 *
 * What it does *not* say is that the host key is the right one. That is
 * `known_hosts`, and it is a separate decision made by whoever calls this.
 */
export function verifyExchangeSignature(input: {
  hostKey: Uint8Array
  exchangeHash: Uint8Array
  signature: Uint8Array
}): { ok: boolean, reason?: string } {
  const key = parsePublicKey(input.hostKey)
  if (!key)
    return { ok: false, reason: 'The host key blob could not be read' }

  if (key.type !== 'ssh-ed25519' || !key.publicKey)
    return { ok: false, reason: `Signatures over ${key.type} are not verified by this library` }

  const parsed = parseSignature(input.signature)
  if (!parsed)
    return { ok: false, reason: 'The signature blob could not be read' }

  if (parsed.algorithm !== key.type)
    return { ok: false, reason: 'The signature names a different algorithm than the host key' }

  if (parsed.signature.length !== 64)
    return { ok: false, reason: 'An ed25519 signature is 64 bytes' }

  try {
    const ok = verifySignature(null, input.exchangeHash, ed25519KeyObject(key.publicKey), parsed.signature)

    return ok ? { ok: true } : { ok: false, reason: 'The host key did not sign this exchange' }
  }
  catch (error) {
    return { ok: false, reason: `The signature could not be checked: ${error}` }
  }
}

/** Big-endian bytes as an unsigned integer. */
function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n

  for (const byte of bytes)
    value = (value << 8n) | BigInt(byte)

  return value
}
