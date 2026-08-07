/**
 * Turning a byte stream into packets, and back.
 *
 * TCP delivers whatever it feels like. A packet can arrive in three reads, two
 * packets can arrive in one, and the version exchange can be split down the
 * middle of a line. Every one of those is ordinary, and a transport that only
 * works when a packet arrives whole is a transport that works on a laptop and
 * fails across the Atlantic.
 *
 * So this owns the buffer, and the two pieces of state that must never drift:
 *
 * - **The sequence numbers.** One per direction, incremented for every packet
 *   including the ones nobody looks at. They are what the MAC covers, so a
 *   receiver that miscounts rejects everything from that point on - and a
 *   sender that miscounts produces packets nothing will accept.
 * - **The keys.** Before `NEWKEYS` there is no cipher and packets are plain;
 *   after it every byte is encrypted. The changeover is per direction and
 *   happens at a specific packet, not at a convenient moment.
 *
 * What this is not: a socket. It takes bytes and returns bytes, so it can be
 * driven by a real connection, by a test, or by both ends of a pair in the same
 * process - which is how the round trip below is tested.
 */

import type { PacketCipher } from './cipher'
import { ProtocolError } from './buffer'
import {
  framePacket,
  identificationString,
  MAX_PACKET,
  MIN_PADDING,
  parseIdentification,
  takeLines,
  unframePacket,
} from './packet'
import type { Identification } from './packet'

/**
 * A view over bytes, whatever buffer backs them.
 *
 * `subarray` returns a view rather than a copy - which is the point, since a
 * transport slices the same incoming buffer repeatedly - and a view is not
 * necessarily over a plain `ArrayBuffer`. Saying so is more honest than
 * asserting the narrower type back.
 */
type Bytes = Uint8Array<ArrayBufferLike>

/**
 * How many packets before a rekey is due.
 *
 * RFC 4253 §9 asks for a rekey after an hour or a gigabyte. The packet count is
 * the cheap half of that and the one that matters for a GCM nonce, which is the
 * sequence number: it must never repeat under one key. 2^31 leaves an enormous
 * margin under the 2^32 sequence field and the 2^64 nonce.
 */
export const REKEY_PACKETS: number = 2 ** 31

/** Bytes after which a rekey is due, from the same section. */
export const REKEY_BYTES: number = 1024 * 1024 * 1024

export interface TransportOptions {
  /** What to call ourselves in the version exchange. */
  software?: string
  /** Padding randomness, injectable so a test can be deterministic. */
  random?: (size: number) => Uint8Array
}

/**
 * One end of a connection.
 *
 * Sequence numbers start at zero and count every packet from the very first,
 * including the ones sent before encryption began. The KEXINIT exchanged in the
 * clear is packet 0 and is covered by the MAC of nothing - but it still
 * advances the counter, and a peer that skips it is a peer whose MACs stop
 * verifying at the first encrypted packet.
 */
export class Transport {
  private incoming: Bytes = new Uint8Array(0)
  private sendCipher: PacketCipher | null = null
  private receiveCipher: PacketCipher | null = null

  private sendSequence = 0
  private receiveSequence = 0
  private sentBytes = 0
  private receivedBytes = 0

  /** Set once the peer's identification line has been read. */
  peer: Identification | null = null

  private readonly random: (size: number) => Uint8Array
  readonly identification: string

  constructor(options: TransportOptions = {}) {
    this.identification = identificationString(options.software)
    this.random = options.random ?? (size => crypto.getRandomValues(new Uint8Array(size)))
  }

  /** The line to send before anything else, CRLF included. */
  greeting(): Uint8Array {
    return new TextEncoder().encode(`${this.identification}\r\n`)
  }

  /**
   * Feed bytes in. Returns the payloads that completed.
   *
   * Everything that did not complete stays buffered. A caller that ignores the
   * remainder is the bug this exists to prevent.
   */
  receive(chunk: Bytes): Uint8Array[] {
    this.incoming = concat(this.incoming, chunk)
    const payloads: Uint8Array[] = []

    // The version exchange comes first and is line-oriented. A server may send
    // any number of other lines before its identification, and a client must
    // ignore them until one starts `SSH-`.
    if (!this.peer) {
      const { lines, rest } = takeLines(this.incoming)

      for (const line of lines) {
        const identification = parseIdentification(line)
        if (identification) {
          this.peer = identification
          break
        }

        // Not an identification and not ours to interpret. A banner line.
        if (line.startsWith('SSH-')) {
          throw new ProtocolError(`The peer speaks a version this does not: ${line}`)
        }
      }

      if (!this.peer) {
        this.incoming = rest

        return payloads
      }

      // Everything after the identification line is packets. `takeLines` gave
      // back the remainder after the *last* line, which is wrong here: the
      // bytes after the identification may include a packet that contains a
      // newline. Find the line's end and take from there.
      const marker = new TextEncoder().encode(`${this.peer.raw}\n`)
      const at = indexOf(this.incoming, marker)
      this.incoming = at === -1 ? rest : this.incoming.subarray(at + marker.length)
    }

    // Then packets, as many as have arrived whole.
    for (;;) {
      const packet = this.takePacket()
      if (!packet)
        break

      payloads.push(packet)
    }

    return payloads
  }

  /** One whole packet from the buffer, or null when it has not all arrived. */
  private takePacket(): Bytes | null {
    if (this.incoming.length < 4)
      return null

    const cipher = this.receiveCipher

    const total = cipher
      ? cipher.packetLength(this.incoming.subarray(0, 4))
      : 4 + new DataView(this.incoming.buffer, this.incoming.byteOffset, 4).getUint32(0, false)

    // Checked before allocating anything: the length came from the peer, and
    // this is where a made-up one turns into a refusal rather than a
    // gigabyte-shaped hole in memory.
    if (total > MAX_PACKET + 4 + 64 || total < 4 + MIN_PADDING + 1)
      throw new ProtocolError(`Packet length ${total} is out of range`)

    if (this.incoming.length < total)
      return null

    const raw = this.incoming.subarray(0, total)
    this.incoming = this.incoming.subarray(total)

    const payload = cipher
      ? cipher.open(this.receiveSequence, raw)
      : unframePacket(raw)

    // Counted whatever the payload turns out to be, including the messages a
    // caller will discard: both sides count every packet or neither does.
    this.receiveSequence = (this.receiveSequence + 1) >>> 0
    this.receivedBytes += total

    return payload
  }

  /** Frame and, once keys are in place, encrypt one payload. */
  send(payload: Uint8Array): Uint8Array {
    const packet = this.sendCipher
      ? this.sendCipher.seal(this.sendSequence, payload)
      : framePacket(payload, 8, this.random)

    this.sendSequence = (this.sendSequence + 1) >>> 0
    this.sentBytes += packet.length

    return packet
  }

  /**
   * Start encrypting what is sent, from the next packet.
   *
   * Called on `NEWKEYS`, which is itself sent in the clear - the last packet
   * that is. The sequence number deliberately does not reset: it continues
   * across the changeover, which is what RFC 4253 §7.3 requires and what a peer
   * expects when it verifies the first encrypted packet.
   */
  useSendCipher(cipher: PacketCipher): void {
    this.sendCipher = cipher
    this.sentBytes = 0
  }

  /** The same for the receiving direction. */
  useReceiveCipher(cipher: PacketCipher): void {
    this.receiveCipher = cipher
    this.receivedBytes = 0
  }

  /** Whether both directions are encrypted. */
  get encrypted(): boolean {
    return this.sendCipher !== null && this.receiveCipher !== null
  }

  /** The sequence numbers, for a caller computing a MAC or a nonce itself. */
  get sequences(): { send: number, receive: number } {
    return { send: this.sendSequence, receive: this.receiveSequence }
  }

  /** How much is buffered and not yet a packet, for a caller enforcing limits. */
  get buffered(): number {
    return this.incoming.length
  }

  /**
   * Whether a rekey is due.
   *
   * Asked rather than done here: a rekey is a conversation, not a local change,
   * and the layer that can hold it is the one that knows how to send a KEXINIT.
   * What this owns is the counters that say when.
   */
  get rekeyDue(): boolean {
    return this.sendSequence >= REKEY_PACKETS
      || this.receiveSequence >= REKEY_PACKETS
      || this.sentBytes >= REKEY_BYTES
      || this.receivedBytes >= REKEY_BYTES
  }
}

function concat(a: Bytes, b: Bytes): Bytes {
  if (a.length === 0)
    return b
  if (b.length === 0)
    return a

  const out = new Uint8Array(a.length + b.length)
  out.set(a)
  out.set(b, a.length)

  return out
}

function indexOf(haystack: Bytes, needle: Bytes): number {
  outer: for (let start = 0; start + needle.length <= haystack.length; start++) {
    for (let index = 0; index < needle.length; index++) {
      if (haystack[start + index] !== needle[index])
        continue outer
    }

    return start
  }

  return -1
}
