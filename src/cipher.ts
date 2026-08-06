/**
 * Encrypting a packet.
 *
 * Two constructions, and both are authenticated: after key exchange every byte
 * on the wire is either encrypted-and-authenticated or it is not sent.
 *
 * - **`aes256-gcm@openssh.com`, `aes128-gcm@openssh.com`** (RFC 5647). The
 *   length field is *not* encrypted - it is authenticated as additional data,
 *   because the receiver has to know how much to read before it can decrypt
 *   anything. Everything after it is encrypted, and a 16-byte tag follows.
 * - **`aes256-ctr`, `aes128-ctr` with `hmac-sha2-*-etm@openssh.com`**. Encrypt
 *   then MAC: the same shape, with the MAC computed over the encrypted bytes
 *   rather than the plaintext. Structurally identical to GCM from this
 *   module's point of view, which is why they share an interface.
 *
 * **Not offered: `chacha20-poly1305@openssh.com`**, and deliberately. It needs
 * raw ChaCha20 (for the length field and to derive the Poly1305 key) and a
 * bare Poly1305 over the ciphertext - not the RFC 8439 AEAD construction, which
 * appends length blocks this does not. Bun's crypto exposes neither primitive,
 * so offering it would mean hand-writing Poly1305: modular arithmetic whose
 * timing leaks the key if it is not constant time, in a runtime that makes no
 * such guarantee. A MAC that is subtly wrong is worse than a cipher that is
 * absent, and every OpenSSH since 6.2 speaks AES-GCM.
 *
 * The rule this module exists to enforce: **never negotiate what cannot be
 * applied.** A name in the KEXINIT list that this cannot honour is a handshake
 * that completes and a connection that then does nothing.
 */

import type { CipherGCM, DecipherGCM } from 'node:crypto'
import { createCipheriv, createDecipheriv, createHmac, timingSafeEqual } from 'node:crypto'
import { ProtocolError } from './buffer'
import { MIN_PADDING, paddingFor } from './packet'

export interface CipherSpec {
  /** The name as it appears in a KEXINIT list. */
  name: string
  /**
   * The name node's crypto knows it by.
   *
   * Spelled out rather than derived from the SSH name. They differ in exactly
   * the way that is easy to get away with until it is not - `aes256-ctr` on the
   * wire is `aes-256-ctr` to OpenSSL - and a name built by string surgery is a
   * name nobody can grep for.
   */
  algorithm: string
  /** Bytes of key material to derive. */
  keyLength: number
  /** Bytes of IV to derive. */
  ivLength: number
  /** What the payload is padded to a multiple of. */
  blockSize: number
  /** Bytes of tag or MAC after the packet. */
  tagLength: number
  /**
   * Whether the packet length field is encrypted.
   *
   * False for everything here, and that is not laziness: the receiver has to
   * know how many bytes to read before it can decrypt them. A cipher that
   * encrypts the length has to decrypt a block, read the length, and then
   * continue - a different read loop, and one this does not need.
   */
  lengthIsEncrypted: false
  /** Whether the cipher authenticates by itself, or needs a MAC beside it. */
  aead: boolean
}

/** What this can actually do, keyed by name. */
export const CIPHERS: Record<string, CipherSpec> = {
  'aes256-gcm@openssh.com': {
    name: 'aes256-gcm@openssh.com',
    algorithm: 'aes-256-gcm',
    keyLength: 32,
    // 12 bytes: 4 fixed, then an 8-byte counter this increments per packet.
    ivLength: 12,
    blockSize: 16,
    tagLength: 16,
    lengthIsEncrypted: false,
    aead: true,
  },
  'aes128-gcm@openssh.com': {
    name: 'aes128-gcm@openssh.com',
    algorithm: 'aes-128-gcm',
    keyLength: 16,
    ivLength: 12,
    blockSize: 16,
    tagLength: 16,
    lengthIsEncrypted: false,
    aead: true,
  },
  'aes256-ctr': {
    name: 'aes256-ctr',
    algorithm: 'aes-256-ctr',
    keyLength: 32,
    ivLength: 16,
    blockSize: 16,
    // Set by the MAC that accompanies it.
    tagLength: 0,
    lengthIsEncrypted: false,
    aead: false,
  },
  'aes128-ctr': {
    name: 'aes128-ctr',
    algorithm: 'aes-128-ctr',
    keyLength: 16,
    ivLength: 16,
    blockSize: 16,
    tagLength: 0,
    lengthIsEncrypted: false,
    aead: false,
  },
}

export interface MacSpec {
  name: string
  keyLength: number
  length: number
  /** Whether the MAC covers the ciphertext rather than the plaintext. */
  encryptThenMac: boolean
  hash: 'sha256' | 'sha512'
}

/**
 * The MACs, for the ciphers that need one.
 *
 * Only the `-etm@openssh.com` variants. Encrypt-then-MAC is the construction
 * that is sound in general, and the older encrypt-and-MAC form requires
 * decrypting a block to learn the length *before* anything has been
 * authenticated - which means acting on bytes an attacker chose. OpenSSH has
 * offered ETM since 6.2 and every current client has it.
 */
export const MACS: Record<string, MacSpec> = {
  'hmac-sha2-256-etm@openssh.com': {
    name: 'hmac-sha2-256-etm@openssh.com',
    keyLength: 32,
    length: 32,
    encryptThenMac: true,
    hash: 'sha256',
  },
  'hmac-sha2-512-etm@openssh.com': {
    name: 'hmac-sha2-512-etm@openssh.com',
    keyLength: 64,
    length: 64,
    encryptThenMac: true,
    hash: 'sha512',
  },
}

/** One direction of an encrypted connection. */
export interface PacketCipher {
  readonly spec: CipherSpec
  readonly mac?: MacSpec
  /** Frame, pad, encrypt and authenticate one payload. */
  seal: (sequence: number, payload: Uint8Array) => Uint8Array
  /**
   * How many bytes the whole packet occupies, given its first four.
   *
   * Separate from `open` because a reader has to size the buffer before it can
   * fill it, and the length is readable without the key here.
   */
  packetLength: (firstFour: Uint8Array) => number
  /** Authenticate and decrypt a whole packet, returning the payload. */
  open: (sequence: number, packet: Uint8Array) => Uint8Array
}

/**
 * The nonce for a GCM packet.
 *
 * RFC 5647: four fixed bytes from the derived IV, then an eight-byte
 * invocation counter that increments once per packet and never repeats under
 * one key. Reusing a nonce under GCM does not merely leak a plaintext - it
 * leaks the authentication key, and every packet after it can be forged. So
 * the counter is derived from the sequence number rather than kept beside it:
 * there is no way for the two to drift apart.
 */
function gcmNonce(iv: Uint8Array, sequence: number): Uint8Array {
  const nonce = new Uint8Array(12)
  nonce.set(iv.subarray(0, 4), 0)

  const view = new DataView(nonce.buffer)
  const base = new DataView(iv.buffer, iv.byteOffset, iv.byteLength).getBigUint64(4, false)

  // Wraps at 2^64, which is what the field is. Rekeying happens long before.
  view.setBigUint64(4, (base + BigInt(sequence)) & 0xFFFFFFFFFFFFFFFFn, false)

  return nonce
}

/** The counter block for AES-CTR, advanced by the packets already sent. */
function ctrIv(iv: Uint8Array, blocksConsumed: bigint): Uint8Array {
  const counter = new Uint8Array(iv)
  let carry = blocksConsumed

  for (let index = counter.length - 1; index >= 0 && carry > 0n; index--) {
    const sum = BigInt(counter[index]!) + (carry & 0xFFn)
    counter[index] = Number(sum & 0xFFn)
    carry = (carry >> 8n) + (sum >> 8n)
  }

  return counter
}

/**
 * Build one direction of an encrypted connection.
 *
 * Refuses a name it cannot honour rather than falling back. There is no safe
 * default cipher, and a fallback here would silently downgrade a connection
 * both sides thought they had agreed on.
 */
export function createPacketCipher(options: {
  cipher: string
  mac?: string
  key: Uint8Array
  iv: Uint8Array
  macKey?: Uint8Array
  /** Randomness for padding. Injectable so a test can be deterministic. */
  random?: (size: number) => Uint8Array
}): PacketCipher {
  const spec = CIPHERS[options.cipher]
  if (!spec)
    throw new ProtocolError(`This library does not implement the cipher ${options.cipher}`)

  if (options.key.length !== spec.keyLength)
    throw new ProtocolError(`${spec.name} needs a ${spec.keyLength} byte key`)
  if (options.iv.length !== spec.ivLength)
    throw new ProtocolError(`${spec.name} needs a ${spec.ivLength} byte iv`)

  const mac = spec.aead ? undefined : MACS[options.mac ?? '']
  if (!spec.aead && !mac)
    throw new ProtocolError(`${spec.name} needs a mac, and ${options.mac ?? 'none'} is not one this implements`)
  if (mac && (!options.macKey || options.macKey.length !== mac.keyLength))
    throw new ProtocolError(`${mac.name} needs a ${mac.keyLength} byte key`)

  const random = options.random ?? (size => crypto.getRandomValues(new Uint8Array(size)))
  const tagLength = spec.aead ? spec.tagLength : mac!.length

  // Every CTR packet advances the counter by however many blocks it covered,
  // and both sides have to agree. Tracked rather than recomputed: a packet's
  // position depends on the sizes of every packet before it.
  let ctrBlocks = 0n

  function frame(payload: Uint8Array): { length: number, plain: Uint8Array } {
    // `lengthIsEncrypted` is true here even though the field is sent in the
    // clear: it describes what the padding aligns, and for both of these the
    // alignment starts at padding_length. Getting this wrong makes packets
    // whose encrypted section is not a multiple of the block size.
    const padding = paddingFor(payload.length, spec.blockSize, true)
    const plain = new Uint8Array(1 + payload.length + padding)

    plain[0] = padding
    plain.set(payload, 1)
    plain.set(random(padding), 1 + payload.length)

    return { length: plain.length, plain }
  }

  return {
    spec,
    mac,

    seal(sequence, payload) {
      const { length, plain } = frame(payload)
      const header = new Uint8Array(4)
      new DataView(header.buffer).setUint32(0, length, false)

      if (spec.aead) {
        // Typed as GCM rather than the generic Cipher: `setAAD` only exists on
        // the authenticated modes, and `spec.aead` is what guarantees this
        // branch only ever names one.
        const cipher = createCipheriv(spec.algorithm, options.key, gcmNonce(options.iv, sequence)) as CipherGCM
        // The length is authenticated but not encrypted, so a receiver can size
        // its read before it has decrypted anything.
        cipher.setAAD(header)

        const body = Buffer.concat([cipher.update(plain), cipher.final()])
        const tag = cipher.getAuthTag()

        return new Uint8Array(Buffer.concat([header, body, tag]))
      }

      const cipher = createCipheriv(spec.algorithm, options.key, ctrIv(options.iv, ctrBlocks))
      const body = Buffer.concat([cipher.update(plain), cipher.final()])
      ctrBlocks += BigInt(Math.ceil(plain.length / spec.blockSize))

      // Encrypt then MAC, over the sequence number, the length and the
      // ciphertext. The sequence number is what stops a packet being replayed
      // at a different point in the stream.
      const hmac = createHmac(mac!.hash, options.macKey!)
      const sequenceBytes = new Uint8Array(4)
      new DataView(sequenceBytes.buffer).setUint32(0, sequence >>> 0, false)
      hmac.update(sequenceBytes)
      hmac.update(header)
      hmac.update(body)

      return new Uint8Array(Buffer.concat([header, body, hmac.digest()]))
    },

    packetLength(firstFour) {
      if (firstFour.length < 4)
        throw new ProtocolError('A packet length is four bytes')

      const length = new DataView(firstFour.buffer, firstFour.byteOffset, 4).getUint32(0, false)

      return 4 + length + tagLength
    },

    open(sequence, packet) {
      if (packet.length < 4 + MIN_PADDING + 1 + tagLength)
        throw new ProtocolError('Packet is too short to be one')

      const header = packet.subarray(0, 4)
      const length = new DataView(header.buffer, header.byteOffset, 4).getUint32(0, false)
      const body = packet.subarray(4, 4 + length)
      const tag = packet.subarray(4 + length, 4 + length + tagLength)

      if (body.length !== length || tag.length !== tagLength)
        throw new ProtocolError('Packet is shorter than its own length field')

      let plain: Uint8Array

      if (spec.aead) {
        const decipher = createDecipheriv(spec.algorithm, options.key, gcmNonce(options.iv, sequence)) as DecipherGCM
        decipher.setAAD(header)
        decipher.setAuthTag(tag)

        try {
          plain = new Uint8Array(Buffer.concat([decipher.update(body), decipher.final()]))
        }
        catch {
          // The tag did not check out. Nothing about *why* is said, and nothing
          // partially decrypted is returned: a caller that acts on unverified
          // plaintext is acting on bytes an attacker chose.
          throw new ProtocolError('Packet failed authentication')
        }
      }
      else {
        const hmac = createHmac(mac!.hash, options.macKey!)
        const sequenceBytes = new Uint8Array(4)
        new DataView(sequenceBytes.buffer).setUint32(0, sequence >>> 0, false)
        hmac.update(sequenceBytes)
        hmac.update(header)
        hmac.update(body)

        const expected = hmac.digest()

        // Constant time, because a comparison that returns early tells an
        // attacker how many bytes of a forged MAC were right.
        if (expected.length !== tag.length || !timingSafeEqual(expected, Buffer.from(tag)))
          throw new ProtocolError('Packet failed authentication')

        // Only now, after the MAC has been checked, is anything decrypted.
        const decipher = createDecipheriv(spec.algorithm, options.key, ctrIv(options.iv, ctrBlocks))
        plain = new Uint8Array(Buffer.concat([decipher.update(body), decipher.final()]))
        ctrBlocks += BigInt(Math.ceil(body.length / spec.blockSize))
      }

      const padding = plain[0]!
      if (padding < MIN_PADDING || padding > plain.length - 1)
        throw new ProtocolError(`Padding length ${padding} does not fit the packet`)

      return plain.subarray(1, plain.length - padding)
    },
  }
}

/**
 * How much key material a negotiated pair needs, per RFC 4253 §7.2.
 *
 * Returned rather than assumed, because the six derived keys are each as long
 * as the thing that uses them and deriving the wrong length produces a
 * connection that decrypts to noise.
 */
export function keyLengthsFor(cipher: string, mac?: string): { key: number, iv: number, mac: number } {
  const spec = CIPHERS[cipher]
  if (!spec)
    throw new ProtocolError(`This library does not implement the cipher ${cipher}`)

  const macSpec = spec.aead ? undefined : MACS[mac ?? '']
  if (!spec.aead && !macSpec)
    throw new ProtocolError(`${cipher} needs a mac, and ${mac ?? 'none'} is not one this implements`)

  return { key: spec.keyLength, iv: spec.ivLength, mac: macSpec?.keyLength ?? 0 }
}
