import { describe, expect, it } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  ed25519Blob,
  fingerprintOf,
  formatAuthorizedKey,
  parseAuthorizedKey,
  parseAuthorizedKeys,
  parsePublicKey,
  sameKey,
} from '../src/keys'

/**
 * The fixtures are real keys made by ssh-keygen, and the fingerprints below are
 * the ones `ssh-keygen -lf` prints for them. Checking against OpenSSH rather
 * than against ourselves is the only way to know the blob is being read the way
 * everybody else reads it.
 */

const ADA = readFileSync(join('test/fixtures', 'ada.ed25519.pub'), 'utf8').trim()
const GRACE = readFileSync(join('test/fixtures', 'grace.rsa.pub'), 'utf8').trim()

const ADA_FINGERPRINT = 'SHA256:5Qkb22VFaD0j2Vaz5R/mbgWhflDenDvHhXe+nNKYogA'
const GRACE_FINGERPRINT = 'SHA256:oCOfrlRoSea1eC3S1rhyIijxw52hCGa8W2wzU2JV+JE'

describe('parseAuthorizedKey', () => {
  it('reads an ed25519 line as ssh-keygen wrote it', () => {
    const key = parseAuthorizedKey(ADA)!

    expect(key.type).toBe('ssh-ed25519')
    expect(key.comment).toBe('ada@example.com')
    expect(key.options).toBe('')
    expect(key.publicKey).toHaveLength(32)
    expect(key.bits).toBe(256)
  })

  /** Against OpenSSH's own output, not against ourselves. */
  it('computes the fingerprint ssh-keygen prints', () => {
    expect(parseAuthorizedKey(ADA)!.fingerprint).toBe(ADA_FINGERPRINT)
    expect(parseAuthorizedKey(GRACE)!.fingerprint).toBe(GRACE_FINGERPRINT)
  })

  it('reads an RSA line, including its size', () => {
    const key = parseAuthorizedKey(GRACE)!

    expect(key.type).toBe('ssh-rsa')
    expect(key.bits).toBe(2048)
    expect(key.rsa?.exponent).toBe(65537n)
  })

  it('keeps options, which come before the type', () => {
    const key = parseAuthorizedKey(`no-pty,no-agent-forwarding ${ADA}`)!

    expect(key.options).toBe('no-pty,no-agent-forwarding')
    expect(key.type).toBe('ssh-ed25519')
  })

  /**
   * The reason the type is searched for rather than split to: a command option
   * may contain spaces, and may contain the word ssh-rsa.
   */
  it('reads a quoted command option with spaces in it', () => {
    const key = parseAuthorizedKey(`command="git-shell -c ssh-rsa" ${ADA}`)!

    expect(key.options).toBe('command="git-shell -c ssh-rsa"')
    expect(key.type).toBe('ssh-ed25519')
    expect(key.fingerprint).toBe(ADA_FINGERPRINT)
  })

  it('takes a line with no comment', () => {
    const [type, blob] = ADA.split(' ')

    expect(parseAuthorizedKey(`${type} ${blob}`)!.comment).toBe('')
  })

  describe('refuses', () => {
    it('a blank line or a comment, which are ordinary in this file', () => {
      expect(parseAuthorizedKey('')).toBeNull()
      expect(parseAuthorizedKey('   ')).toBeNull()
      expect(parseAuthorizedKey('# a note to self')).toBeNull()
    })

    it('a line whose stated type disagrees with the blob inside it', () => {
      const blob = ADA.split(' ')[1]

      expect(parseAuthorizedKey(`ssh-rsa ${blob} ada@example.com`)).toBeNull()
    })

    /** atob accepts things that are not base64 and quietly makes the wrong bytes. */
    it('base64 that is not base64', () => {
      expect(parseAuthorizedKey('ssh-ed25519 not!valid!base64 x')).toBeNull()
    })

    it('a truncated blob', () => {
      expect(parseAuthorizedKey('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 x')).toBeNull()
    })

    it('a line with no key at all', () => {
      expect(parseAuthorizedKey('ssh-ed25519')).toBeNull()
      expect(parseAuthorizedKey('just some words')).toBeNull()
    })
  })
})

describe('parsePublicKey', () => {
  it('refuses an ed25519 blob whose point is the wrong length', () => {
    const short = new Uint8Array([0, 0, 0, 11, ...new TextEncoder().encode('ssh-ed25519'), 0, 0, 0, 2, 1, 2])

    expect(parsePublicKey(short)).toBeNull()
  })

  it('refuses a blob with bytes left over', () => {
    const key = parseAuthorizedKey(ADA)!
    const extra = new Uint8Array([...key.blob, 0xFF])

    expect(parsePublicKey(extra)).toBeNull()
  })

  /**
   * A type this does not understand is still a key somebody may want stored or
   * displayed. What it must not do is claim to understand it.
   */
  it('reads an unknown type without pretending to understand it', () => {
    const blob = new Uint8Array([0, 0, 0, 8, ...new TextEncoder().encode('ssh-new1'), 0, 0, 0, 1, 42])
    const key = parsePublicKey(blob)!

    expect(key.type).toBe('ssh-new1')
    expect(key.publicKey).toBeUndefined()
    expect(key.bits).toBeUndefined()
  })

  it('refuses an ecdsa blob whose curve disagrees with its type', () => {
    const blob = new Uint8Array([
      0, 0, 0, 19, ...new TextEncoder().encode('ecdsa-sha2-nistp256'),
      0, 0, 0, 8, ...new TextEncoder().encode('nistp384'),
      0, 0, 0, 1, 4,
    ])

    expect(parsePublicKey(blob)).toBeNull()
  })
})

describe('parseAuthorizedKeys', () => {
  it('reads a file and skips what it cannot understand', () => {
    const file = `# my keys\n${ADA}\n\nnonsense line\n${GRACE}\n`
    const keys = parseAuthorizedKeys(file)

    expect(keys.map(key => key.type)).toEqual(['ssh-ed25519', 'ssh-rsa'])
  })
})

describe('formatAuthorizedKey', () => {
  it('writes back what it read', () => {
    const key = parseAuthorizedKey(ADA)!

    expect(formatAuthorizedKey(key)).toBe(ADA)
  })

  it('writes options back in front', () => {
    const key = parseAuthorizedKey(`no-pty ${ADA}`)!

    expect(formatAuthorizedKey(key)).toBe(`no-pty ${ADA}`)
  })
})

describe('ed25519Blob', () => {
  it('builds the blob ssh-keygen would have', () => {
    const key = parseAuthorizedKey(ADA)!

    expect(ed25519Blob(key.publicKey!)).toEqual(key.blob)
    expect(fingerprintOf(ed25519Blob(key.publicKey!))).toBe(ADA_FINGERPRINT)
  })

  it('refuses a point that is not 32 bytes', () => {
    expect(() => ed25519Blob(new Uint8Array(31))).toThrow()
  })
})

describe('sameKey', () => {
  /** The comparison that decides whether somebody is let in. */
  it('compares the blob, which is the key itself', () => {
    const ada = parseAuthorizedKey(ADA)!
    const grace = parseAuthorizedKey(GRACE)!

    expect(sameKey(ada.blob, ada.blob)).toBe(true)
    expect(sameKey(ada.blob, grace.blob)).toBe(false)
  })

  it('is false for different lengths rather than throwing', () => {
    expect(sameKey(new Uint8Array(4), new Uint8Array(5))).toBe(false)
  })
})
