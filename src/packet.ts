/**
 * The binary packet protocol, and the version exchange that precedes it.
 *
 * Every byte after the two sides greet each other is a packet in this shape
 * (RFC 4253 §6):
 *
 *     uint32  packet_length      (everything after this field, not counting mac)
 *     byte    padding_length
 *     byte[]  payload            (packet_length - padding_length - 1 bytes)
 *     byte[]  padding            (padding_length bytes, random)
 *     byte[]  mac                (outside the length, and outside encryption)
 *
 * The padding rules are the part worth stating, because they are arithmetic
 * that has to be exactly right or the peer resynchronises on garbage:
 *
 * - The whole packet, *including* the length field but excluding the MAC, is a
 *   multiple of the cipher block size, or of 8, whichever is larger.
 * - There are at least 4 bytes of padding, always.
 * - The padding is random, and that is not decoration: it is what stops an
 *   observer measuring the exact length of a password.
 *
 * A cipher that covers the length field - `chacha20-poly1305@openssh.com` and
 * the GCM modes - changes what is encrypted but not this shape.
 */

import { ProtocolError, Reader, Writer } from './buffer'

/** Message numbers, from RFC 4250 §4.1.2 and the KEX and userauth RFCs. */
export const Message = {
  DISCONNECT: 1,
  IGNORE: 2,
  UNIMPLEMENTED: 3,
  DEBUG: 4,
  SERVICE_REQUEST: 5,
  SERVICE_ACCEPT: 6,
  EXT_INFO: 7,
  KEXINIT: 20,
  NEWKEYS: 21,
  KEX_ECDH_INIT: 30,
  KEX_ECDH_REPLY: 31,
  USERAUTH_REQUEST: 50,
  USERAUTH_FAILURE: 51,
  USERAUTH_SUCCESS: 52,
  USERAUTH_BANNER: 53,
  USERAUTH_PK_OK: 60,
  GLOBAL_REQUEST: 80,
  REQUEST_SUCCESS: 81,
  REQUEST_FAILURE: 82,
  CHANNEL_OPEN: 90,
  CHANNEL_OPEN_CONFIRMATION: 91,
  CHANNEL_OPEN_FAILURE: 92,
  CHANNEL_WINDOW_ADJUST: 93,
  CHANNEL_DATA: 94,
  CHANNEL_EXTENDED_DATA: 95,
  CHANNEL_EOF: 96,
  CHANNEL_CLOSE: 97,
  CHANNEL_REQUEST: 98,
  CHANNEL_SUCCESS: 99,
  CHANNEL_FAILURE: 100,
} as const

/** Reasons a disconnect can carry, from RFC 4250 §4.2.2. */
export const Disconnect = {
  PROTOCOL_ERROR: 2,
  KEY_EXCHANGE_FAILED: 3,
  MAC_ERROR: 5,
  SERVICE_NOT_AVAILABLE: 7,
  PROTOCOL_VERSION_NOT_SUPPORTED: 8,
  CONNECTION_LOST: 10,
  BY_APPLICATION: 11,
  TOO_MANY_CONNECTIONS: 12,
  AUTH_CANCELLED_BY_USER: 13,
  NO_MORE_AUTH_METHODS_AVAILABLE: 14,
  ILLEGAL_USER_NAME: 15,
} as const

/**
 * The largest packet this will read.
 *
 * RFC 4253 requires 35000 be accepted; more than that from a peer is either a
 * broken implementation or an attempt to make the server allocate. 256 KiB is
 * generous for both and still bounded.
 */
export const MAX_PACKET: number = 256 * 1024

/** The smallest block a packet is padded to, whatever the cipher says. */
export const MIN_BLOCK: number = 8

/** The minimum padding the protocol requires. */
export const MIN_PADDING: number = 4

/**
 * How much padding a payload of this size needs.
 *
 * Pulled out and exported because it is arithmetic with an off-by-one in it -
 * the length field counts toward the alignment when the cipher does not cover
 * it, and does not when it does - and arithmetic is worth testing directly.
 */
export function paddingFor(payloadLength: number, blockSize: number, lengthIsEncrypted: boolean): number {
  const block = Math.max(blockSize, MIN_BLOCK)

  // Without an encrypted length field, the uint32 is part of what is aligned.
  // With one, alignment starts at padding_length.
  const unpadded = (lengthIsEncrypted ? 1 : 5) + payloadLength
  let padding = block - (unpadded % block)

  if (padding < MIN_PADDING)
    padding += block

  return padding
}

/**
 * Frame a payload into an unencrypted packet.
 *
 * `random` is injectable so a test can be deterministic. It defaults to real
 * randomness, and it must: the padding is what hides the length of a secret.
 */
export function framePacket(
  payload: Uint8Array,
  blockSize: number = MIN_BLOCK,
  random: (size: number) => Uint8Array = randomBytes,
): Uint8Array {
  const padding = paddingFor(payload.length, blockSize, false)
  const writer = new Writer()

  writer.uint32(1 + payload.length + padding)
  writer.byte(padding)
  writer.raw(payload)
  writer.raw(random(padding))

  return writer.done()
}

/**
 * Take a payload out of a framed packet.
 *
 * Every length here came from the peer, so every one is checked. A padding
 * length longer than the packet is the obvious attack and the obvious bug.
 */
export function unframePacket(packet: Uint8Array): Uint8Array {
  const reader = new Reader(packet)
  const length = reader.uint32()

  // The smallest legal packet is the padding length byte plus the minimum
  // padding. The payload above this layer always carries a message number, but
  // that is a rule about payloads rather than about framing, and enforcing it
  // here would refuse a packet this module itself produces.
  if (length < MIN_PADDING + 1 || length > MAX_PACKET)
    throw new ProtocolError(`Packet length ${length} is out of range`)

  if (reader.remaining < length)
    throw new ProtocolError('Packet is shorter than its own length field')

  const padding = reader.byte()

  // `length - 1` because the padding length byte is itself inside `length`.
  // Anything larger would make the payload a negative number of bytes, which
  // is the shape of a peer trying to read past the buffer.
  if (padding < MIN_PADDING || padding > length - 1)
    throw new ProtocolError(`Padding length ${padding} does not fit the packet`)

  const payload = new Uint8Array(length - padding - 1)
  payload.set(new Reader(packet.subarray(5)).rest().subarray(0, payload.length))

  return payload
}

function randomBytes(size: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(size))
}

/** What a peer said it was, before any packet was sent. */
export interface Identification {
  /** The whole line without CRLF: what the exchange hash is computed over. */
  raw: string
  protocol: string
  software: string
  comments?: string
}

/** The identification string this library sends. */
export function identificationString(software = 'ts-ssh'): string {
  return `SSH-2.0-${software}`
}

/**
 * Read the peer's identification line.
 *
 * The rules that matter, from RFC 4253 §4.2:
 *
 * - The line ends CRLF, but implementations that send bare LF are everywhere,
 *   so both are taken.
 * - A server may send any number of other lines *first*, and a client must
 *   ignore them until one starts `SSH-`. This is how banners work.
 * - Only `SSH-2.0-` is spoken here. `SSH-1.99-` means a peer that would also
 *   speak SSH 1, which is not something to be compatible with.
 */
export function parseIdentification(line: string): Identification | null {
  const raw = line.replace(/\r?\n$/, '')

  if (!raw.startsWith('SSH-'))
    return null

  const rest = raw.slice('SSH-'.length)
  const dash = rest.indexOf('-')
  if (dash <= 0)
    return null

  const protocol = rest.slice(0, dash)
  if (protocol !== '2.0')
    return null

  const after = rest.slice(dash + 1)
  const space = after.indexOf(' ')

  return {
    raw,
    protocol,
    software: space === -1 ? after : after.slice(0, space),
    comments: space === -1 ? undefined : after.slice(space + 1),
  }
}

/**
 * Split a buffer into complete lines, keeping what is left over.
 *
 * The version exchange arrives however TCP felt like delivering it, and a line
 * can be split across two reads. Losing that remainder is the bug that makes a
 * server work on a fast connection and not on a slow one.
 */
export function takeLines(buffer: Uint8Array): { lines: string[], rest: Uint8Array } {
  const lines: string[] = []
  let start = 0

  for (let index = 0; index < buffer.length; index++) {
    if (buffer[index] !== 0x0A)
      continue

    const line = new TextDecoder().decode(buffer.subarray(start, index)).replace(/\r$/, '')
    lines.push(line)
    start = index + 1
  }

  return { lines, rest: buffer.subarray(start) }
}
