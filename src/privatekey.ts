/**
 * The private half: reading a host key off disk, and signing with it.
 *
 * OpenSSH stopped using PEM for its own keys and invented a container of its
 * own, `openssh-key-v1`, which is what `ssh-keygen` writes today. It is a
 * base64 blob between two guard lines holding:
 *
 *     "openssh-key-v1\0"
 *     string  ciphername          "none" when the key has no passphrase
 *     string  kdfname
 *     string  kdfoptions
 *     uint32  number of keys      always 1 in practice
 *     string  public key blob
 *     string  the private section, padded
 *
 * and the private section, once decrypted, holds:
 *
 *     uint32  checkint
 *     uint32  checkint            the same value again
 *     string  key type
 *     ...     the key's own fields
 *     string  comment
 *     byte[]  padding             1, 2, 3, ... to the block size
 *
 * The two checkints are how a wrong passphrase is detected: decrypt with the
 * wrong key and they come out as unrelated noise. They are still checked here
 * even with no passphrase, because they are also how a truncated or corrupt
 * file announces itself before anything downstream tries to sign with garbage.
 *
 * **Encrypted keys are refused, deliberately.** Unwrapping one needs bcrypt_pbkdf
 * - Blowfish with a modified key schedule - which is a cipher this would have to
 * hand-write. It is also not a gap worth closing for the case this serves: a
 * daemon's host key cannot have a passphrase, because there is nobody at the
 * keyboard when it starts. The refusal names the fix rather than the mechanism.
 */

import { createPrivateKey, generateKeyPairSync, randomBytes, sign as signWith } from 'node:crypto'
import { ProtocolError, Reader, Writer } from './buffer'
import { ed25519Blob, fingerprintOf } from './keys'

const MAGIC = 'openssh-key-v1\0'
const BEGIN = '-----BEGIN OPENSSH PRIVATE KEY-----'
const END = '-----END OPENSSH PRIVATE KEY-----'

/**
 * The DER header for a PKCS#8 ed25519 private key.
 *
 * SSH carries a raw 32-byte seed and node's crypto wants a key object, so the
 * two are bridged by a prefix that never varies: SEQUENCE, version 0, the
 * ed25519 OID, then the seed inside an OCTET STRING inside an OCTET STRING.
 * Written out rather than encoded because there is exactly one of them.
 */
const PKCS8_ED25519 = new Uint8Array([
  0x30, 0x2E, // SEQUENCE, 46 bytes
  0x02, 0x01, 0x00, // INTEGER 0, the version
  0x30, 0x05, // SEQUENCE, 5 bytes
  0x06, 0x03, 0x2B, 0x65, 0x70, // OID 1.3.101.112, id-Ed25519
  0x04, 0x22, // OCTET STRING, 34 bytes
  0x04, 0x20, // OCTET STRING, 32 bytes: the seed
])

/**
 * A key that can sign, with the private material kept out of reach.
 *
 * `sign` is a closure over the key object rather than a property holding the
 * seed. The difference shows up the first time something logs a config object
 * or serialises an error: what cannot be reached cannot be printed.
 */
export interface PrivateKey {
  type: 'ssh-ed25519'
  comment?: string
  /** The public blob, exactly as it goes on the wire and into `authorized_keys`. */
  publicKey: Uint8Array
  /** `SHA256:…`, for showing a person which key this is. */
  fingerprint: string
  /**
   * Sign, returning the wire blob rather than the raw signature.
   *
   * The wire form is `string algorithm` then `string signature`, so a verifier
   * learns which algorithm was used instead of assuming. Returning the raw 64
   * bytes here would push that framing onto every caller, and one of them would
   * forget.
   */
  sign: (data: Uint8Array) => Uint8Array
}

/**
 * Build a signer from a raw 32-byte ed25519 seed.
 *
 * The point is passed in so it can be checked against what the seed actually
 * derives, rather than trusted. Everything else in this file compares the
 * file's copies of the public key with each other, which a corrupt or forged
 * file can satisfy trivially: write the same wrong point in all three places.
 * Deriving it is the only check that cannot be satisfied that way, and without
 * it a server would sign with one key while advertising another - which every
 * client refuses, in a message that names neither.
 */
function signerFor(seed: Uint8Array, point: Uint8Array): (data: Uint8Array) => Uint8Array {
  if (seed.length !== 32)
    throw new ProtocolError('An ed25519 private key is a 32 byte seed')

  const der = new Uint8Array(PKCS8_ED25519.length + 32)
  der.set(PKCS8_ED25519)
  der.set(seed, PKCS8_ED25519.length)

  const key = createPrivateKey({ key: Buffer.from(der), format: 'der', type: 'pkcs8' })

  // Through JWK, where an OKP key carries its public half as `x`. The DER
  // route would need `createPublicKey` to take a private key, which it does at
  // runtime and not in the type declarations.
  const jwk = key.export({ format: 'jwk' }) as { x?: string }
  const derived = new Uint8Array(Buffer.from(jwk.x ?? '', 'base64url'))

  if (!equal(derived, point))
    throw new ProtocolError('That key disagrees with itself: the private half derives a different public key')

  return (data) => {
    const signature = signWith(null, data, key)

    return new Writer().string('ssh-ed25519').string(new Uint8Array(signature)).done()
  }
}

/**
 * Read a private key file.
 *
 * Throws rather than returning null, unlike `parsePublicKey`. The asymmetry is
 * intentional: a public key comes off the wire from somebody who may be hostile
 * and unreadable input is an ordinary refusal, while a private key comes from
 * the operator's own disk and one that cannot be read is a misconfiguration
 * somebody needs told about.
 */
export function parsePrivateKey(text: string): PrivateKey {
  const begin = text.indexOf(BEGIN)
  const end = text.indexOf(END)

  if (begin === -1 || end === -1)
    throw new ProtocolError('That is not an OpenSSH private key: the guard lines are missing')

  const body = text.slice(begin + BEGIN.length, end).replace(/\s+/g, '')
  const blob = new Uint8Array(Buffer.from(body, 'base64'))

  const magic = new TextDecoder().decode(blob.subarray(0, MAGIC.length))
  if (magic !== MAGIC)
    throw new ProtocolError('That file has the right guard lines and the wrong contents')

  const reader = new Reader(blob.subarray(MAGIC.length))
  const cipher = reader.text()
  const kdf = reader.text()
  reader.string() // The KDF options, which are empty when there is no KDF.
  const count = reader.uint32()

  if (cipher !== 'none' || kdf !== 'none') {
    throw new ProtocolError(
      'That key is protected by a passphrase, which this cannot remove. '
      + 'A host key is used by a daemon with nobody at the keyboard, so it needs one without: '
      + 'ssh-keygen -p -N "" -f <file>',
    )
  }

  if (count !== 1)
    throw new ProtocolError(`That file holds ${count} keys, and this reads files holding one`)

  const publicKey = reader.string()
  const section = new Reader(reader.string())

  const checkA = section.uint32()
  const checkB = section.uint32()
  if (checkA !== checkB)
    throw new ProtocolError('That key did not survive being read: its check values disagree')

  const type = section.text()
  if (type !== 'ssh-ed25519') {
    throw new ProtocolError(
      `This signs with ed25519 and that key is ${type}. `
      + 'ssh-keygen -t ed25519 makes one.',
    )
  }

  // ed25519 stores the public point twice - once in the outer blob and once
  // here - and stores the private key as seed followed by that same point.
  const point = section.string()
  const secret = section.string()
  const comment = section.text()

  if (secret.length !== 64)
    throw new ProtocolError('An ed25519 private key is 64 bytes: the seed and the point')

  // The outer public blob is what the protocol sends and what a verifier
  // checks against; the inner point is what the private key was derived from.
  // They are written by the same tool and read by different code, which is
  // exactly the kind of pair that drifts unnoticed.
  const outer = parsePoint(publicKey)
  if (!outer || !equal(outer, point) || !equal(point, secret.subarray(32)))
    throw new ProtocolError('That key disagrees with itself about its own public half')

  return {
    type: 'ssh-ed25519',
    comment: comment.length > 0 ? comment : undefined,
    publicKey,
    fingerprint: fingerprintOf(publicKey),
    sign: signerFor(secret.subarray(0, 32), point),
  }
}

/**
 * Write a key back out in the same container.
 *
 * Round-tripping matters more than it looks: it is what lets a generated key be
 * written to disk and then read by `ssh-keygen`, `ssh-add`, and everything else
 * that expects this format. A generator that produces something only its own
 * parser accepts is a generator that has invented a private format.
 */
export function formatPrivateKey(input: {
  seed: Uint8Array
  point: Uint8Array
  comment?: string
  /** The check value, injectable so a test can round-trip deterministically. */
  checkInt?: number
}): string {
  if (input.seed.length !== 32 || input.point.length !== 32)
    throw new ProtocolError('An ed25519 key is a 32 byte seed and a 32 byte point')

  const comment = input.comment ?? ''
  const check = input.checkInt ?? new DataView(new Uint8Array(randomBytes(4)).buffer).getUint32(0, false)

  const secret = new Uint8Array(64)
  secret.set(input.seed)
  secret.set(input.point, 32)

  const section = new Writer()
    .uint32(check)
    .uint32(check)
    .string('ssh-ed25519')
    .string(input.point)
    .string(secret)
    .string(comment)
    .done()

  // Padded to the block size with 1, 2, 3, ... - the cipher is `none`, so the
  // block is 8. The bytes are ascending rather than zero so that a reader that
  // checks them can tell padding from a truncated field.
  const padding = (8 - (section.length % 8)) % 8
  const padded = new Uint8Array(section.length + padding)
  padded.set(section)
  for (let index = 0; index < padding; index++)
    padded[section.length + index] = index + 1

  const blob = new Writer()
    .raw(new TextEncoder().encode(MAGIC))
    .string('none')
    .string('none')
    .string('')
    .uint32(1)
    .string(ed25519Blob(input.point))
    .string(padded)
    .done()

  const base64 = Buffer.from(blob).toString('base64')
  const lines: string[] = []
  for (let index = 0; index < base64.length; index += 70)
    lines.push(base64.slice(index, index + 70))

  return `${BEGIN}\n${lines.join('\n')}\n${END}\n`
}

/**
 * Make a new host key.
 *
 * Returns the file contents as well as the usable key, because a server that
 * generates one on first start has to write it down - a host key that changes
 * between restarts makes every client that ever connected print the warning
 * about a changed fingerprint, which is the warning that is supposed to mean
 * something.
 */
export function generateHostKey(comment = 'ts-ssh'): { key: PrivateKey, openssh: string, publicLine: string } {
  const pair = generateKeyPairSync('ed25519')

  // The raw seed and point sit at fixed offsets at the end of the DER, which
  // is a fixed-width header for this one algorithm.
  const pkcs8 = new Uint8Array(pair.privateKey.export({ type: 'pkcs8', format: 'der' }))
  const spki = new Uint8Array(pair.publicKey.export({ type: 'spki', format: 'der' }))
  const seed = pkcs8.subarray(pkcs8.length - 32)
  const point = spki.subarray(spki.length - 32)

  const openssh = formatPrivateKey({ seed, point, comment })
  const blob = ed25519Blob(point)

  return {
    key: parsePrivateKey(openssh),
    openssh,
    publicLine: `ssh-ed25519 ${Buffer.from(blob).toString('base64')} ${comment}\n`,
  }
}

/** The 32-byte point out of an `ssh-ed25519` blob, or null if it is not one. */
function parsePoint(blob: Uint8Array): Uint8Array | null {
  try {
    const reader = new Reader(blob)
    if (reader.text() !== 'ssh-ed25519')
      return null

    const point = reader.string()

    return point.length === 32 ? point : null
  }
  catch {
    return null
  }
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length)
    return false

  for (let index = 0; index < a.length; index++) {
    if (a[index] !== b[index])
      return false
  }

  return true
}
