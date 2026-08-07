/**
 * Channels, and the flow control that makes them work.
 *
 * One SSH connection carries many independent streams - a shell, a forwarded
 * port, a `git-upload-pack` - and each is a channel with its own numbering and
 * its own window. RFC 4254.
 *
 * **The window is the part worth understanding.** Each side tells the other how
 * many bytes it is prepared to receive, and a sender may not exceed it. It
 * shrinks as data arrives and grows when the receiver says so with a
 * `CHANNEL_WINDOW_ADJUST`. Get it wrong in one direction and a large transfer
 * stalls forever with both sides waiting; get it wrong in the other and a peer
 * can make you buffer without limit, which is the same as no flow control at
 * all.
 *
 * Two numbers per channel and they are *not* the same: a channel has a local
 * id it chose and a remote id the peer chose. Every message carries the
 * recipient's number, so a message being sent carries the remote id and a
 * message that arrives carries the local one. Confusing them produces a server
 * that works with exactly one channel open.
 */

import { ProtocolError, Reader, Writer } from './buffer'
import { Message } from './packet'

/** What a channel is for. Only sessions are handled here. */
export type ChannelType = 'session' | string

/** Reasons an open can be refused, from RFC 4254 §5.1. */
export const OpenFailure = {
  ADMINISTRATIVELY_PROHIBITED: 1,
  CONNECT_FAILED: 2,
  UNKNOWN_CHANNEL_TYPE: 3,
  RESOURCE_SHORTAGE: 4,
} as const

/** Extended data is stderr, and there is only the one kind. */
export const EXTENDED_DATA_STDERR = 1

/** What a peer asked to open. */
export interface ChannelOpen {
  channelType: ChannelType
  /** The sender's own id, which is the *remote* id from here. */
  senderChannel: number
  initialWindowSize: number
  maximumPacketSize: number
}

/** A request on an open channel: `exec`, `shell`, `env`, `pty-req`. */
export interface ChannelRequest {
  recipientChannel: number
  request: string
  wantReply: boolean
  /** For `exec`, the command line. Unparsed: it is the peer's string. */
  command?: string
  /** For `env`, one variable. */
  name?: string
  value?: string
}

/**
 * Sensible defaults.
 *
 * 2 MiB of window and 32 KiB per packet are what OpenSSH uses. The maximum
 * packet size is a promise about what will be *sent*, so a peer sizing its
 * buffers can believe it.
 */
export const DEFAULT_WINDOW: number = 2 * 1024 * 1024
export const DEFAULT_MAX_PACKET: number = 32 * 1024

/** Read a CHANNEL_OPEN payload. */
export function readChannelOpen(payload: Uint8Array): ChannelOpen {
  const reader = new Reader(payload)
  const message = reader.byte()

  if (message !== Message.CHANNEL_OPEN)
    throw new ProtocolError(`Expected CHANNEL_OPEN and got message ${message}`)

  return {
    channelType: reader.text(),
    senderChannel: reader.uint32(),
    initialWindowSize: reader.uint32(),
    maximumPacketSize: reader.uint32(),
  }
}

/** Accept an open, telling the peer our id and our window. */
export function writeChannelOpenConfirmation(options: {
  recipientChannel: number
  senderChannel: number
  initialWindowSize?: number
  maximumPacketSize?: number
}): Uint8Array {
  return new Writer()
    .byte(Message.CHANNEL_OPEN_CONFIRMATION)
    .uint32(options.recipientChannel)
    .uint32(options.senderChannel)
    .uint32(options.initialWindowSize ?? DEFAULT_WINDOW)
    .uint32(options.maximumPacketSize ?? DEFAULT_MAX_PACKET)
    .done()
}

/** Refuse an open, with a reason a person could act on. */
export function writeChannelOpenFailure(recipientChannel: number, reason: number, description: string): Uint8Array {
  return new Writer()
    .byte(Message.CHANNEL_OPEN_FAILURE)
    .uint32(recipientChannel)
    .uint32(reason)
    .string(description)
    // The language tag. Empty, which is what everybody sends.
    .string('')
    .done()
}

/** Read a CHANNEL_REQUEST payload. */
export function readChannelRequest(payload: Uint8Array): ChannelRequest {
  const reader = new Reader(payload)
  const message = reader.byte()

  if (message !== Message.CHANNEL_REQUEST)
    throw new ProtocolError(`Expected CHANNEL_REQUEST and got message ${message}`)

  const recipientChannel = reader.uint32()
  const request = reader.text()
  const wantReply = reader.boolean()

  if (request === 'exec')
    return { recipientChannel, request, wantReply, command: reader.text() }

  if (request === 'env')
    return { recipientChannel, request, wantReply, name: reader.text(), value: reader.text() }

  // Anything else is read as far as its header. A server that does not
  // implement it answers CHANNEL_FAILURE, which is a complete answer.
  return { recipientChannel, request, wantReply }
}

/** Data, and the stderr variant. */
export function writeChannelData(recipientChannel: number, data: Uint8Array): Uint8Array {
  return new Writer().byte(Message.CHANNEL_DATA).uint32(recipientChannel).string(data).done()
}

export function writeChannelExtendedData(recipientChannel: number, data: Uint8Array): Uint8Array {
  return new Writer()
    .byte(Message.CHANNEL_EXTENDED_DATA)
    .uint32(recipientChannel)
    .uint32(EXTENDED_DATA_STDERR)
    .string(data)
    .done()
}

export function writeChannelWindowAdjust(recipientChannel: number, bytes: number): Uint8Array {
  return new Writer().byte(Message.CHANNEL_WINDOW_ADJUST).uint32(recipientChannel).uint32(bytes).done()
}

export function writeChannelEof(recipientChannel: number): Uint8Array {
  return new Writer().byte(Message.CHANNEL_EOF).uint32(recipientChannel).done()
}

export function writeChannelClose(recipientChannel: number): Uint8Array {
  return new Writer().byte(Message.CHANNEL_CLOSE).uint32(recipientChannel).done()
}

export function writeChannelSuccess(recipientChannel: number): Uint8Array {
  return new Writer().byte(Message.CHANNEL_SUCCESS).uint32(recipientChannel).done()
}

export function writeChannelFailure(recipientChannel: number): Uint8Array {
  return new Writer().byte(Message.CHANNEL_FAILURE).uint32(recipientChannel).done()
}

/**
 * The exit status of a command, as a request on the channel.
 *
 * Sent before `CHANNEL_CLOSE` and with `want_reply` false, because there is
 * nothing to reply to - the peer either records it or does not. A client that
 * gets a close without one has to assume the worst, which is why a server that
 * forgets this makes every command look like it failed.
 */
export function writeExitStatus(recipientChannel: number, status: number): Uint8Array {
  return new Writer()
    .byte(Message.CHANNEL_REQUEST)
    .uint32(recipientChannel)
    .string('exit-status')
    .boolean(false)
    .uint32(status)
    .done()
}

export interface ChannelState {
  /** Ours, which the peer addresses. */
  localId: number
  /** Theirs, which we address. */
  remoteId: number
  /** How many bytes we may still send. */
  remoteWindow: number
  /** How many bytes they may still send us. */
  localWindow: number
  /** The largest packet they said they would send. */
  remoteMaxPacket: number
  /** Whether each side has said it is done sending. */
  sentEof: boolean
  receivedEof: boolean
  closed: boolean
}

/**
 * One channel's bookkeeping.
 *
 * Deliberately not a stream, a socket, or anything that owns I/O: it is the
 * arithmetic, so the rules can be tested without a connection. What it refuses
 * to do is as important as what it does - a send that would exceed the window
 * is a bug in the caller, and it is told so rather than being allowed to stall
 * the peer.
 */
export class Channel {
  readonly localId: number
  readonly remoteId: number
  readonly remoteMaxPacket: number

  private remoteWindowLeft: number
  private localWindowLeft: number
  private readonly localWindowSize: number

  sentEof = false
  receivedEof = false
  closed = false

  constructor(options: {
    localId: number
    remoteId: number
    remoteWindow: number
    remoteMaxPacket: number
    localWindow?: number
  }) {
    this.localId = options.localId
    this.remoteId = options.remoteId
    this.remoteWindowLeft = options.remoteWindow
    this.remoteMaxPacket = options.remoteMaxPacket
    this.localWindowSize = options.localWindow ?? DEFAULT_WINDOW
    this.localWindowLeft = this.localWindowSize
  }

  get state(): ChannelState {
    return {
      localId: this.localId,
      remoteId: this.remoteId,
      remoteWindow: this.remoteWindowLeft,
      localWindow: this.localWindowLeft,
      remoteMaxPacket: this.remoteMaxPacket,
      sentEof: this.sentEof,
      receivedEof: this.receivedEof,
      closed: this.closed,
    }
  }

  /**
   * Split data into packets this channel may actually send.
   *
   * Bounded by two things at once: the window, which is how much the peer will
   * accept in total, and the maximum packet size, which is how much it will
   * accept at once. Returning what fits rather than throwing is deliberate -
   * a large write is normal, and the caller's job is to send what comes back
   * and keep the rest until the window opens.
   */
  chunk(data: Uint8Array): { packets: Uint8Array[], remaining: Uint8Array } {
    if (this.closed)
      throw new ProtocolError('That channel is closed')

    const packets: Uint8Array[] = []
    let offset = 0

    while (offset < data.length) {
      const room = Math.min(this.remoteWindowLeft, this.remoteMaxPacket, data.length - offset)
      if (room <= 0)
        break

      packets.push(writeChannelData(this.remoteId, data.subarray(offset, offset + room)))
      this.remoteWindowLeft -= room
      offset += room
    }

    return { packets, remaining: data.subarray(offset) }
  }

  /** The peer gave us more room. */
  adjustRemoteWindow(bytes: number): void {
    if (!Number.isSafeInteger(bytes) || bytes < 0)
      throw new ProtocolError('A window adjustment is a whole number of bytes')

    // A peer that adjusts past 2^32 is not one to keep talking to: the field is
    // 32 bits and the sum is meant to stay inside it.
    if (this.remoteWindowLeft + bytes > 0xFFFFFFFF)
      throw new ProtocolError('That window adjustment overflows the window')

    this.remoteWindowLeft += bytes
  }

  /**
   * Account for data that arrived, and say whether to open the window again.
   *
   * The adjustment is sent when the window has fallen below half, rather than
   * per packet: an adjustment per packet doubles the message count of every
   * transfer, and waiting until it is empty stalls the sender for a round trip.
   */
  consume(bytes: number): { overflow: boolean, adjust: number } {
    if (bytes > this.localWindowLeft)
      return { overflow: true, adjust: 0 }

    this.localWindowLeft -= bytes

    if (this.localWindowLeft * 2 > this.localWindowSize)
      return { overflow: false, adjust: 0 }

    const adjust = this.localWindowSize - this.localWindowLeft
    this.localWindowLeft = this.localWindowSize

    return { overflow: false, adjust }
  }
}
