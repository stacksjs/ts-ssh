/**
 * Agreeing on algorithms, and then on a secret.
 *
 * Two steps, and the second depends on getting the first exactly right.
 *
 * **Negotiation** (RFC 4253 §7.1). Both sides send a list per category in
 * preference order, and the chosen algorithm is *the client's first choice that
 * the server also has*. Client preference, not server - a server that picks its
 * own favourite is a server that can be talked down to its weakest option.
 *
 * **Exchange** (RFC 5656, RFC 8731). The client sends an ephemeral public
 * point, the server replies with its own plus its host key and a signature. Both
 * derive the same shared secret; only the server proves who it is.
 *
 * What the signature covers is the exchange hash H, and H is a hash of
 * everything that was said up to that point:
 *
 *     string  V_C   client identification, no CRLF
 *     string  V_S   server identification
 *     string  I_C   the client's whole KEXINIT payload
 *     string  I_S   the server's
 *     string  K_S   the server's host key blob
 *     string  Q_C   client ephemeral public
 *     string  Q_S   server ephemeral public
 *     mpint   K     the shared secret
 *
 * That list is the whole security argument: a signature over H is a signature
 * over both sides' idea of what was negotiated, so an attacker who edited the
 * algorithm lists in flight produces a different H and a signature that does
 * not check out. Leave a field out and the downgrade becomes invisible.
 */

import { ProtocolError, Reader, Writer } from './buffer'

/** One side's lists, in preference order. */
export interface AlgorithmOffer {
  kex: readonly string[]
  hostKey: readonly string[]
  cipher: readonly string[]
  mac: readonly string[]
  compression: readonly string[]
}

/**
 * The two markers that turn on strict key exchange.
 *
 * Not algorithms - neither side can select them, and they never match each
 * other because one ends `-c-` and the other `-s-`. They are announcements,
 * placed in the kex list because it is the one list both sides already read
 * before anything is agreed. Strict mode is on only when both appear, which is
 * what makes it safe to add to an existing implementation.
 *
 * What it buys: sequence numbers restart at `NEWKEYS` and the handshake refuses
 * the messages that exist to be ignored, which together close Terrapin
 * (CVE-2023-48795). See `Transport.resetSendSequence`.
 */
export const STRICT_KEX_CLIENT: string = 'kex-strict-c-v00@openssh.com'
export const STRICT_KEX_SERVER: string = 'kex-strict-s-v00@openssh.com'

/**
 * What this offers, in preference order.
 *
 * The cipher and MAC lists are **derived from what is implemented** rather than
 * written out beside it. A name in a KEXINIT list is a promise to apply it, and
 * a hand-kept list drifts from the code that has to honour it: this offered
 * `chacha20-poly1305@openssh.com` and plain `hmac-sha2-256` before the cipher
 * layer existed, which would have produced a handshake that completed and a
 * connection that then did nothing.
 *
 * Preference is strongest first. AES-256 over AES-128 because there is no cost
 * worth the difference here, and GCM over CTR because one construction is
 * harder to get wrong than a cipher and a MAC that have to agree.
 */
export const ALGORITHMS: AlgorithmOffer = {
  kex: ['curve25519-sha256', 'curve25519-sha256@libssh.org', STRICT_KEX_SERVER],
  hostKey: ['ssh-ed25519'],
  cipher: [
    'aes256-gcm@openssh.com',
    'aes128-gcm@openssh.com',
    'aes256-ctr',
    'aes128-ctr',
  ],
  // Only the encrypt-then-MAC variants, and only for the ciphers that need
  // one. A cipher that authenticates its own data answers `<implicit>` here.
  mac: ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com'],
  compression: ['none'],
}

export interface KexInit {
  cookie: Uint8Array
  kex: string[]
  hostKey: string[]
  cipherClientToServer: string[]
  cipherServerToClient: string[]
  macClientToServer: string[]
  macServerToClient: string[]
  compressionClientToServer: string[]
  compressionServerToClient: string[]
  languagesClientToServer: string[]
  languagesServerToClient: string[]
  firstKexPacketFollows: boolean
}

/** Build a KEXINIT payload, message number included. */
export function writeKexInit(offer: AlgorithmOffer & { cookie?: Uint8Array }): Uint8Array {
  const cookie = offer.cookie ?? crypto.getRandomValues(new Uint8Array(16))
  if (cookie.length !== 16)
    throw new ProtocolError('A KEXINIT cookie is 16 bytes')

  return new Writer()
    .byte(20)
    .raw(cookie)
    .nameList(offer.kex)
    .nameList(offer.hostKey)
    .nameList(offer.cipher)
    .nameList(offer.cipher)
    .nameList(offer.mac)
    .nameList(offer.mac)
    .nameList(offer.compression)
    .nameList(offer.compression)
    .nameList([])
    .nameList([])
    .boolean(false)
    .uint32(0)
    .done()
}

/** Read a KEXINIT payload. The message byte is expected and checked. */
export function readKexInit(payload: Uint8Array): KexInit {
  const reader = new Reader(payload)
  const message = reader.byte()

  if (message !== 20)
    throw new ProtocolError(`Expected KEXINIT and got message ${message}`)

  const kexInit: KexInit = {
    cookie: reader.rest().subarray(0, 0),
    kex: [],
    hostKey: [],
    cipherClientToServer: [],
    cipherServerToClient: [],
    macClientToServer: [],
    macServerToClient: [],
    compressionClientToServer: [],
    compressionServerToClient: [],
    languagesClientToServer: [],
    languagesServerToClient: [],
    firstKexPacketFollows: false,
  }

  // Re-read from after the message byte: the cookie is fixed width, so it is
  // taken directly rather than as a string.
  const body = new Reader(payload.subarray(1))
  kexInit.cookie = body.rest().subarray(0, 16)

  const after = new Reader(payload.subarray(17))
  kexInit.kex = after.nameList()
  kexInit.hostKey = after.nameList()
  kexInit.cipherClientToServer = after.nameList()
  kexInit.cipherServerToClient = after.nameList()
  kexInit.macClientToServer = after.nameList()
  kexInit.macServerToClient = after.nameList()
  kexInit.compressionClientToServer = after.nameList()
  kexInit.compressionServerToClient = after.nameList()
  kexInit.languagesClientToServer = after.nameList()
  kexInit.languagesServerToClient = after.nameList()
  kexInit.firstKexPacketFollows = after.boolean()

  return kexInit
}

/**
 * The client's first choice that the server also offers.
 *
 * Client preference wins, per RFC 4253 §7.1. Returning null rather than falling
 * back is deliberate: there is no safe default algorithm, and "no overlap" is a
 * disconnect rather than a guess.
 */
export function negotiate(clientOffers: readonly string[], serverOffers: readonly string[]): string | null {
  for (const candidate of clientOffers) {
    if (serverOffers.includes(candidate))
      return candidate
  }

  return null
}

export interface Negotiated {
  kex: string
  hostKey: string
  cipherClientToServer: string
  cipherServerToClient: string
  macClientToServer: string
  macServerToClient: string
  compressionClientToServer: string
  compressionServerToClient: string
}

/** Negotiate every category, or say which one failed. */
export function negotiateAll(client: KexInit, server: KexInit): Negotiated | { failed: string } {
  // The strict-kex markers are announcements, not algorithms, and are taken out
  // before anything is chosen. A client that offered the *server's* marker as
  // its first choice would otherwise "win" a key exchange named after a thing
  // nobody can perform.
  const marker = (name: string) => name === STRICT_KEX_CLIENT || name === STRICT_KEX_SERVER
  const kex = negotiate(client.kex.filter(name => !marker(name)), server.kex.filter(name => !marker(name)))
  if (!kex)
    return { failed: 'key exchange' }

  const hostKey = negotiate(client.hostKey, server.hostKey)
  if (!hostKey)
    return { failed: 'host key' }

  const cipherClientToServer = negotiate(client.cipherClientToServer, server.cipherClientToServer)
  const cipherServerToClient = negotiate(client.cipherServerToClient, server.cipherServerToClient)
  if (!cipherClientToServer || !cipherServerToClient)
    return { failed: 'cipher' }

  // A cipher that authenticates its own data needs no separate MAC, and OpenSSH
  // sends `<implicit>` in that position. Insisting on an overlap here would
  // refuse the strongest ciphers there are.
  const implicit = (name: string) => name.includes('gcm') || name.includes('poly1305')

  const macClientToServer = implicit(cipherClientToServer)
    ? '<implicit>'
    : negotiate(client.macClientToServer, server.macClientToServer)
  const macServerToClient = implicit(cipherServerToClient)
    ? '<implicit>'
    : negotiate(client.macServerToClient, server.macServerToClient)

  if (!macClientToServer || !macServerToClient)
    return { failed: 'mac' }

  const compressionClientToServer = negotiate(client.compressionClientToServer, server.compressionClientToServer)
  const compressionServerToClient = negotiate(client.compressionServerToClient, server.compressionServerToClient)
  if (!compressionClientToServer || !compressionServerToClient)
    return { failed: 'compression' }

  return {
    kex,
    hostKey,
    cipherClientToServer,
    cipherServerToClient,
    macClientToServer,
    macServerToClient,
    compressionClientToServer,
    compressionServerToClient,
  }
}

export interface ExchangeHashInput {
  /** The client's identification line, without CRLF. */
  clientIdentification: string
  serverIdentification: string
  /** Whole KEXINIT payloads, message byte included. */
  clientKexInit: Uint8Array
  serverKexInit: Uint8Array
  /** The server's host key blob. */
  hostKey: Uint8Array
  /** Ephemeral public values. */
  clientPublic: Uint8Array
  serverPublic: Uint8Array
  /** The shared secret, as the integer it is encoded as. */
  sharedSecret: bigint
}

/**
 * The bytes the exchange hash is taken over.
 *
 * Split out from the hashing so a test can look at them: every field in here is
 * load bearing, and the failure mode of leaving one out is a handshake that
 * completes and a downgrade nobody notices.
 */
export function exchangeHashPreimage(input: ExchangeHashInput): Uint8Array {
  return new Writer()
    .string(input.clientIdentification)
    .string(input.serverIdentification)
    .string(input.clientKexInit)
    .string(input.serverKexInit)
    .string(input.hostKey)
    .string(input.clientPublic)
    .string(input.serverPublic)
    .mpint(input.sharedSecret)
    .done()
}

/** The exchange hash H, which is what the host key signs. */
export function exchangeHash(input: ExchangeHashInput): Uint8Array {
  const hasher = new Bun.CryptoHasher('sha256')
  hasher.update(exchangeHashPreimage(input))

  return new Uint8Array(hasher.digest() as unknown as ArrayBuffer)
}

/**
 * One of the six keys derived from the exchange.
 *
 * From RFC 4253 §7.2. Each is `HASH(K || H || letter || session_id)`, extended
 * by rehashing everything produced so far when more bytes are needed than one
 * digest gives.
 *
 * The letters are fixed and mean: A and B are the IVs, C and D the encryption
 * keys, E and F the MAC keys - client to server first in each pair. Getting a
 * letter wrong produces a working handshake and a connection where each side
 * decrypts to noise, which is a memorable afternoon.
 */
export function deriveKey(
  sharedSecret: bigint,
  exchange: Uint8Array,
  letter: 'A' | 'B' | 'C' | 'D' | 'E' | 'F',
  sessionId: Uint8Array,
  length: number,
): Uint8Array {
  const secret = new Writer().mpint(sharedSecret).done()
  const out = new Uint8Array(length)
  let filled = 0

  const first = new Bun.CryptoHasher('sha256')
  first.update(secret)
  first.update(exchange)
  first.update(new Uint8Array([letter.charCodeAt(0)]))
  first.update(sessionId)

  let block = new Uint8Array(first.digest() as unknown as ArrayBuffer)

  while (filled < length) {
    const take = Math.min(block.length, length - filled)
    out.set(block.subarray(0, take), filled)
    filled += take

    if (filled >= length)
      break

    const next = new Bun.CryptoHasher('sha256')
    next.update(secret)
    next.update(exchange)
    next.update(out.subarray(0, filled))
    block = new Uint8Array(next.digest() as unknown as ArrayBuffer)
  }

  return out
}
