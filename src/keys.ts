/**
 * Public keys, as they are written down.
 *
 * The same key appears in three shapes and this module moves between them:
 *
 * - **An `authorized_keys` line** - options, a type, base64, and a comment.
 * - **A wire blob** - the base64 decoded, which is what a signature is checked
 *   against and what the protocol actually sends.
 * - **A fingerprint** - `SHA256:` and base64 of the blob's digest, which is what
 *   a person compares.
 *
 * A forge needs all three: it stores what somebody pasted, matches it against
 * what a client offers mid-handshake, and shows a fingerprint so they can tell
 * two keys apart.
 *
 * Parsing is strict because this is the file that decides who may log in. A
 * line that cannot be understood is refused, never guessed at: a key parsed
 * loosely into the wrong type is a key that authenticates the wrong person.
 */

import type { KeyObject } from 'node:crypto'
import { createPublicKey } from 'node:crypto'
import { ProtocolError, Reader, Writer } from './buffer'

/** The key types this understands, in the order a server should prefer them. */
export const KEY_TYPES = [
  'ssh-ed25519',
  'ecdsa-sha2-nistp256',
  'ecdsa-sha2-nistp384',
  'ecdsa-sha2-nistp521',
  'rsa-sha2-512',
  'rsa-sha2-256',
  'ssh-rsa',
] as const

export type KeyType = typeof KEY_TYPES[number]

export interface PublicKey {
  /** The algorithm name as it appears in the blob. */
  type: string
  /** The wire encoding: what a signature is verified against. */
  blob: Uint8Array
  /** `SHA256:…`, the form a person compares. */
  fingerprint: string
  /** Bits of security, where it is meaningful and knowable. */
  bits?: number
  /** For ed25519 and ecdsa, the point. For rsa, absent. */
  publicKey?: Uint8Array
  /** RSA only. */
  rsa?: { exponent: bigint, modulus: bigint }
  /** ecdsa only: the curve the blob names, which must match the type. */
  curve?: string
}

export interface AuthorizedKey extends PublicKey {
  /** Options before the type, unparsed - `no-pty`, `command="…"` and so on. */
  options: string
  /** Whatever followed the base64, usually an email address. */
  comment: string
}

/**
 * Read a public key blob.
 *
 * Returns null rather than throwing: this reads bytes a client chose, where
 * anything unreadable is a refusal rather than a crash.
 */
export function parsePublicKey(blob: Uint8Array): PublicKey | null {
  try {
    const reader = new Reader(blob)
    const type = reader.text()

    // The type is named twice - once as the blob's first field and once by
    // whatever carried it - and a blob whose inner name disagrees is a blob
    // pretending to be something else.
    if (!type || type.length > 64)
      return null

    const key: PublicKey = { type, blob, fingerprint: fingerprintOf(blob) }

    if (type === 'ssh-ed25519') {
      const point = reader.string()
      if (point.length !== 32 || reader.remaining !== 0)
        return null

      return { ...key, publicKey: point, bits: 256 }
    }

    if (type === 'ssh-rsa') {
      const exponent = reader.mpint()
      const modulus = reader.mpint()

      if (reader.remaining !== 0 || modulus <= 0n || exponent <= 0n)
        return null

      return { ...key, rsa: { exponent, modulus }, bits: modulus.toString(2).length }
    }

    if (type.startsWith('ecdsa-sha2-')) {
      const curve = reader.text()
      const point = reader.string()

      // The curve is in the type *and* in the body, and they have to agree -
      // they are read by different code in most implementations, which is
      // exactly how a mismatch goes unnoticed.
      if (`ecdsa-sha2-${curve}` !== type || point.length === 0 || reader.remaining !== 0)
        return null

      const bits = curve === 'nistp256' ? 256 : curve === 'nistp384' ? 384 : curve === 'nistp521' ? 521 : undefined

      return { ...key, curve, publicKey: point, bits }
    }

    // A type this does not know is still a key, and a server may still want to
    // store or display it. What it must not do is claim to understand it.
    return key
  }
  catch {
    return null
  }
}

/** The `SHA256:…` fingerprint of a blob, with the padding stripped as OpenSSH does. */
export function fingerprintOf(blob: Uint8Array): string {
  const hasher = new Bun.CryptoHasher('sha256')
  hasher.update(blob)

  return `SHA256:${hasher.digest('base64').replace(/=+$/, '')}`
}

/**
 * Read one line of an `authorized_keys` file.
 *
 * The format is positional and the options field makes it awkward: options come
 * first, are comma-separated, and a `command="..."` option may contain spaces
 * and escaped quotes. So the parse looks for the key type rather than splitting
 * on whitespace, which is what makes a quoted option with a space in it work.
 */
export function parseAuthorizedKey(line: string): AuthorizedKey | null {
  const trimmed = line.trim()

  // Blank lines and comments are ordinary in this file, and are not errors.
  if (trimmed === '' || trimmed.startsWith('#'))
    return null

  const found = findKeyType(trimmed)
  if (!found)
    return null

  const { type, start } = found
  const options = trimmed.slice(0, start).trim()
  const after = trimmed.slice(start + type.length).trimStart()
  const space = after.search(/\s/)
  const base64 = space === -1 ? after : after.slice(0, space)
  const comment = space === -1 ? '' : after.slice(space).trim()

  if (base64 === '')
    return null

  let blob: Uint8Array
  try {
    // A strict decode: `atob` accepts things that are not base64 and quietly
    // produces the wrong bytes, and the wrong bytes here are the wrong key.
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(base64))
      return null

    const binary = atob(base64)
    blob = new Uint8Array(binary.length)
    for (let index = 0; index < binary.length; index++)
      blob[index] = binary.charCodeAt(index)
  }
  catch {
    return null
  }

  const key = parsePublicKey(blob)
  if (!key)
    return null

  // The type in the line and the type inside the blob must agree. They come
  // from different places, and a line that says ed25519 over an RSA blob is a
  // line written by something that should not be trusted.
  if (key.type !== type)
    return null

  return { ...key, options, comment }
}

/**
 * Where the key type starts in a line.
 *
 * Searched for rather than split to, because everything before it is options
 * and options can contain spaces inside quotes.
 */
function findKeyType(line: string): { type: string, start: number } | null {
  for (const type of KEY_TYPES) {
    // At the start, or preceded by whitespace, and followed by whitespace: so
    // `ssh-rsa` inside `command="ssh-rsa"` is not mistaken for the type.
    const pattern = new RegExp(`(^|\\s)${type}(?=\\s)`)
    const match = pattern.exec(line)

    if (match)
      return { type, start: match.index + match[1]!.length }
  }

  return null
}

/** Read a whole `authorized_keys` file, skipping what it cannot understand. */
export function parseAuthorizedKeys(text: string): AuthorizedKey[] {
  const keys: AuthorizedKey[] = []

  for (const line of text.split('\n')) {
    const key = parseAuthorizedKey(line)
    if (key)
      keys.push(key)
  }

  return keys
}

/** Write a key back out as an `authorized_keys` line. */
export function formatAuthorizedKey(key: { type: string, blob: Uint8Array, comment?: string, options?: string }): string {
  let binary = ''
  for (const byte of key.blob)
    binary += String.fromCharCode(byte)

  const parts = [key.options, key.type, btoa(binary), key.comment].filter(part => part !== undefined && part !== '')

  return parts.join(' ')
}

/** Build an ed25519 blob from the raw 32-byte point. */
export function ed25519Blob(point: Uint8Array): Uint8Array {
  if (point.length !== 32)
    throw new Error('An ed25519 public key is 32 bytes')

  return new Writer().string('ssh-ed25519').string(point).done()
}

/**
 * The DER header for an ed25519 SubjectPublicKeyInfo.
 *
 * SSH carries the raw 32-byte point and node's crypto wants a key object, so
 * the two are bridged by a prefix that never varies for this one algorithm.
 * Written out rather than encoded because there is exactly one of them, and
 * kept here rather than beside each caller because two copies of a constant is
 * one copy too many.
 */
const SPKI_ED25519 = new Uint8Array([
  0x30, 0x2A, // SEQUENCE, 42 bytes
  0x30, 0x05, // SEQUENCE, 5 bytes
  0x06, 0x03, 0x2B, 0x65, 0x70, // OID 1.3.101.112, id-Ed25519
  0x03, 0x21, 0x00, // BIT STRING, 33 bytes, 0 unused bits
])

/** An ed25519 point, in the shape node's crypto wants for verification. */
export function ed25519KeyObject(point: Uint8Array): KeyObject {
  if (point.length !== 32)
    throw new ProtocolError('An ed25519 public key is 32 bytes')

  const der = new Uint8Array(SPKI_ED25519.length + point.length)
  der.set(SPKI_ED25519)
  der.set(point, SPKI_ED25519.length)

  return createPublicKey({ key: Buffer.from(der), format: 'der', type: 'spki' })
}

/**
 * Whether two keys are the same key.
 *
 * By blob, in constant time, because this is the comparison that decides
 * whether somebody is let in. Comparing fingerprints would be comparing a hash
 * of the thing rather than the thing, and comparing base64 would make
 * whitespace and padding matter.
 */
export function sameKey(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length)
    return false

  let difference = 0
  for (let index = 0; index < a.length; index++)
    difference |= a[index]! ^ b[index]!

  return difference === 0
}
