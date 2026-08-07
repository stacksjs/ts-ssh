/**
 * Private keys, checked against the tool that writes them.
 *
 * A key parser can be self-consistent and still wrong, and the failure is
 * silent: it reads back what it wrote and refuses what `ssh-keygen` produced,
 * or worse, accepts it and derives a different public half. So the tests that
 * matter here are the ones with `ssh-keygen` on the other side of them.
 */

import { describe, expect, it } from 'bun:test'
import { spawnSync } from 'bun'
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ProtocolError } from '../src/buffer'
import { fingerprintOf, parseAuthorizedKey } from '../src/keys'
import { formatPrivateKey, generateHostKey, parsePrivateKey } from '../src/privatekey'

function workspace(): { dir: string, cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), 'ts-ssh-key-'))

  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) }
}

describe('generateHostKey', () => {
  it('makes a key that reads back as the same key', () => {
    const generated = generateHostKey('a comment')

    expect(generated.key.type).toBe('ssh-ed25519')
    expect(generated.key.comment).toBe('a comment')
    expect(generated.key.fingerprint).toStartWith('SHA256:')

    const again = parsePrivateKey(generated.openssh)
    expect(again.fingerprint).toBe(generated.key.fingerprint)
  })

  it('writes a public line that parses as one', () => {
    const generated = generateHostKey('host@example')
    const parsed = parseAuthorizedKey(generated.publicLine.trim())

    expect(parsed).not.toBeNull()
    expect(parsed!.type).toBe('ssh-ed25519')
    expect(parsed!.comment).toBe('host@example')
    expect(fingerprintOf(parsed!.blob)).toBe(generated.key.fingerprint)
  })

  it('signs in a form that names its own algorithm', () => {
    const generated = generateHostKey()
    const signature = generated.key.sign(new TextEncoder().encode('some bytes'))

    // `string algorithm` then `string signature`: 4 + 11 + 4 + 64.
    expect(signature.length).toBe(83)
    expect(new TextDecoder().decode(signature.subarray(4, 15))).toBe('ssh-ed25519')
  })

  it('gives a different key every time', () => {
    expect(generateHostKey().key.fingerprint).not.toBe(generateHostKey().key.fingerprint)
  })
})

describe('parsePrivateKey', () => {
  it('reads what ssh-keygen wrote', () => {
    const { dir, cleanup } = workspace()

    try {
      const path = join(dir, 'id_ed25519')
      const generated = spawnSync(['ssh-keygen', '-t', 'ed25519', '-N', '', '-C', 'from-keygen', '-f', path])
      expect(generated.exitCode).toBe(0)

      const key = parsePrivateKey(readFileSync(path, 'utf8'))
      expect(key.comment).toBe('from-keygen')

      // The fingerprint ssh-keygen prints for the same file. Agreeing on this
      // means agreeing on every byte of the public blob, which is the thing a
      // signature is checked against.
      const printed = spawnSync(['ssh-keygen', '-lf', path])
      expect(new TextDecoder().decode(printed.stdout)).toContain(key.fingerprint)
    }
    finally {
      cleanup()
    }
  })

  it('writes what ssh-keygen can read', () => {
    const { dir, cleanup } = workspace()

    try {
      const generated = generateHostKey('round-trip')
      const path = join(dir, 'id_ours')
      writeFileSync(path, generated.openssh)
      chmodSync(path, 0o600)

      // `-y` derives the public key from the private one. A generator that
      // produced something only its own parser accepts would fail here, and
      // nowhere else.
      const derived = spawnSync(['ssh-keygen', '-y', '-f', path])
      expect(derived.exitCode).toBe(0)
      // Compared without the comment: `-y` reprints the one stored inside the
      // private key, and what is being checked is the key material.
      const withoutComment = (line: string) => line.trim().split(' ').slice(0, 2).join(' ')
      expect(withoutComment(new TextDecoder().decode(derived.stdout))).toBe(withoutComment(generated.publicLine))
    }
    finally {
      cleanup()
    }
  })

  it('refuses a key with a passphrase, and says what to do about it', () => {
    const { dir, cleanup } = workspace()

    try {
      const path = join(dir, 'id_locked')
      spawnSync(['ssh-keygen', '-t', 'ed25519', '-N', 'hunter2', '-f', path])

      expect(() => parsePrivateKey(readFileSync(path, 'utf8'))).toThrow(ProtocolError)
      expect(() => parsePrivateKey(readFileSync(path, 'utf8'))).toThrow(/ssh-keygen -p/)
    }
    finally {
      cleanup()
    }
  })

  it('refuses a key type it cannot sign with, by name', () => {
    const { dir, cleanup } = workspace()

    try {
      const path = join(dir, 'id_ecdsa')
      spawnSync(['ssh-keygen', '-t', 'ecdsa', '-N', '', '-f', path])

      expect(() => parsePrivateKey(readFileSync(path, 'utf8'))).toThrow(/ecdsa/)
    }
    finally {
      cleanup()
    }
  })

  it('refuses anything that is not one', () => {
    expect(() => parsePrivateKey('not a key')).toThrow(/guard lines/)
    expect(() => parsePrivateKey('-----BEGIN OPENSSH PRIVATE KEY-----\nQUJD\n-----END OPENSSH PRIVATE KEY-----'))
      .toThrow(/right guard lines and the wrong contents/)
  })

  it('notices a private half that does not match the public one', () => {
    // A file can write the same wrong point in all three places it appears and
    // be perfectly self-consistent. Deriving the public key from the seed is
    // the only check that cannot be satisfied that way - and without it a
    // server signs with one key while advertising another, which every client
    // refuses in a message that names neither.
    const forged = formatPrivateKey({
      seed: new Uint8Array(32).fill(7),
      point: new Uint8Array(32).fill(9),
      comment: 'mismatched',
    })

    expect(() => parsePrivateKey(forged)).toThrow(/disagrees with itself/)
  })

  it('round-trips through the container deterministically', () => {
    const generated = generateHostKey('stable')
    const parsed = parsePrivateKey(generated.openssh)

    // The same inputs and the same check value produce the same file, byte for
    // byte. Only the check value is random, which is why it is injectable.
    const first = formatPrivateKey({
      seed: new Uint8Array(32).fill(3),
      point: parsed.publicKey.subarray(parsed.publicKey.length - 32),
      comment: 'stable',
      checkInt: 1234,
    })
    const second = formatPrivateKey({
      seed: new Uint8Array(32).fill(3),
      point: parsed.publicKey.subarray(parsed.publicKey.length - 32),
      comment: 'stable',
      checkInt: 1234,
    })

    expect(first).toBe(second)
  })

  it('refuses a seed that is not 32 bytes', () => {
    expect(() => formatPrivateKey({ seed: new Uint8Array(16), point: new Uint8Array(32) })).toThrow(ProtocolError)
  })
})
