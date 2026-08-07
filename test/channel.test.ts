import { describe, expect, it } from 'bun:test'
import { ProtocolError, Reader } from '../src/buffer'
import {
  Channel,
  DEFAULT_MAX_PACKET,
  DEFAULT_WINDOW,
  EXTENDED_DATA_STDERR,
  OpenFailure,
  readChannelOpen,
  readChannelRequest,
  writeChannelClose,
  writeChannelData,
  writeChannelExtendedData,
  writeChannelOpenConfirmation,
  writeChannelOpenFailure,
  writeChannelWindowAdjust,
  writeExitStatus,
} from '../src/channel'
import { Writer } from '../src/buffer'
import { Message } from '../src/packet'

describe('opening a channel', () => {
  it('reads what a peer asked for', () => {
    const payload = new Writer()
      .byte(Message.CHANNEL_OPEN).string('session').uint32(0).uint32(2097152).uint32(32768)
      .done()

    expect(readChannelOpen(payload)).toEqual({
      channelType: 'session',
      senderChannel: 0,
      initialWindowSize: 2097152,
      maximumPacketSize: 32768,
    })
  })

  it('refuses a payload that is not a channel open', () => {
    expect(() => readChannelOpen(new Uint8Array([Message.CHANNEL_DATA]))).toThrow(ProtocolError)
  })

  /**
   * Two numbers per channel and they are not the same. Every message carries
   * the *recipient's* number, so a confirmation tells the peer its own id back
   * and ours alongside it.
   */
  it('confirms with both ids, the peer\'s first', () => {
    const reader = new Reader(writeChannelOpenConfirmation({ recipientChannel: 7, senderChannel: 1 }))

    expect(reader.byte()).toBe(Message.CHANNEL_OPEN_CONFIRMATION)
    expect(reader.uint32()).toBe(7)
    expect(reader.uint32()).toBe(1)
    expect(reader.uint32()).toBe(DEFAULT_WINDOW)
    expect(reader.uint32()).toBe(DEFAULT_MAX_PACKET)
  })

  it('refuses with a reason a person could act on', () => {
    const reader = new Reader(writeChannelOpenFailure(3, OpenFailure.UNKNOWN_CHANNEL_TYPE, 'only sessions here'))

    expect(reader.byte()).toBe(Message.CHANNEL_OPEN_FAILURE)
    expect(reader.uint32()).toBe(3)
    expect(reader.uint32()).toBe(OpenFailure.UNKNOWN_CHANNEL_TYPE)
    expect(reader.text()).toBe('only sessions here')
    expect(reader.text()).toBe('')
  })
})

describe('channel requests', () => {
  it('reads an exec and its command', () => {
    const payload = new Writer()
      .byte(Message.CHANNEL_REQUEST).uint32(0).string('exec').boolean(true).string('git-upload-pack \'repo.git\'')
      .done()

    expect(readChannelRequest(payload)).toEqual({
      recipientChannel: 0,
      request: 'exec',
      wantReply: true,
      command: 'git-upload-pack \'repo.git\'',
    })
  })

  it('reads an env pair', () => {
    const payload = new Writer()
      .byte(Message.CHANNEL_REQUEST).uint32(0).string('env').boolean(false).string('LANG').string('en_GB.UTF-8')
      .done()

    expect(readChannelRequest(payload)).toMatchObject({ request: 'env', name: 'LANG', value: 'en_GB.UTF-8' })
  })

  /** A server that does not implement it answers CHANNEL_FAILURE, which is complete. */
  it('reads a request it does not understand as far as its header', () => {
    const payload = new Writer()
      .byte(Message.CHANNEL_REQUEST).uint32(2).string('pty-req').boolean(true).string('xterm')
      .done()

    expect(readChannelRequest(payload)).toEqual({ recipientChannel: 2, request: 'pty-req', wantReply: true })
  })
})

describe('the messages', () => {
  it('writes data addressed to the recipient', () => {
    const reader = new Reader(writeChannelData(4, new TextEncoder().encode('hello')))

    expect(reader.byte()).toBe(Message.CHANNEL_DATA)
    expect(reader.uint32()).toBe(4)
    expect(reader.text()).toBe('hello')
  })

  it('writes stderr as extended data, with the only kind there is', () => {
    const reader = new Reader(writeChannelExtendedData(4, new TextEncoder().encode('oh no')))

    expect(reader.byte()).toBe(Message.CHANNEL_EXTENDED_DATA)
    expect(reader.uint32()).toBe(4)
    expect(reader.uint32()).toBe(EXTENDED_DATA_STDERR)
    expect(reader.text()).toBe('oh no')
  })

  /**
   * Sent before the close, and with want_reply false because there is nothing
   * to reply to. A client that gets a close without one assumes the worst,
   * which is why forgetting it makes every command look like it failed.
   */
  it('writes an exit status that wants no reply', () => {
    const reader = new Reader(writeExitStatus(1, 0))

    expect(reader.byte()).toBe(Message.CHANNEL_REQUEST)
    expect(reader.uint32()).toBe(1)
    expect(reader.text()).toBe('exit-status')
    expect(reader.boolean()).toBe(false)
    expect(reader.uint32()).toBe(0)
  })

  it('writes a close', () => {
    const reader = new Reader(writeChannelClose(9))

    expect(reader.byte()).toBe(Message.CHANNEL_CLOSE)
    expect(reader.uint32()).toBe(9)
  })
})

describe('the window', () => {
  const channel = (over: Partial<{ remoteWindow: number, remoteMaxPacket: number, localWindow: number }> = {}) =>
    new Channel({
      localId: 1,
      remoteId: 7,
      remoteWindow: over.remoteWindow ?? 100,
      remoteMaxPacket: over.remoteMaxPacket ?? 32,
      localWindow: over.localWindow ?? 100,
    })

  it('splits data by the maximum packet size', () => {
    const { packets, remaining } = channel().chunk(new Uint8Array(80))

    expect(packets).toHaveLength(3)
    expect(remaining).toHaveLength(0)
  })

  /**
   * The window is how much the peer will accept in total. Sending past it is
   * how a large transfer stalls forever with both sides waiting.
   */
  it('stops at the window and hands back what did not fit', () => {
    const { packets, remaining } = channel({ remoteWindow: 40, remoteMaxPacket: 32 }).chunk(new Uint8Array(100))

    expect(packets).toHaveLength(2)
    expect(remaining).toHaveLength(60)
  })

  it('sends nothing at all when the window is closed', () => {
    const open = channel({ remoteWindow: 0 })
    const { packets, remaining } = open.chunk(new Uint8Array(50))

    expect(packets).toEqual([])
    expect(remaining).toHaveLength(50)
  })

  it('sends again once the peer opens the window', () => {
    const open = channel({ remoteWindow: 0 })
    expect(open.chunk(new Uint8Array(10)).packets).toEqual([])

    open.adjustRemoteWindow(64)
    expect(open.chunk(new Uint8Array(10)).packets).toHaveLength(1)
  })

  it('refuses an adjustment that overflows the field', () => {
    expect(() => channel().adjustRemoteWindow(0xFFFFFFFF)).toThrow(ProtocolError)
    expect(() => channel().adjustRemoteWindow(-1)).toThrow(ProtocolError)
  })

  /**
   * Waiting until the window is empty stalls the sender for a round trip; an
   * adjustment per packet doubles the message count of every transfer.
   */
  it('opens the window when it falls below half, not before', () => {
    const open = channel({ localWindow: 100 })

    expect(open.consume(40)).toEqual({ overflow: false, adjust: 0 })
    expect(open.consume(20)).toEqual({ overflow: false, adjust: 60 })
  })

  it('says so when a peer sends more than it was allowed', () => {
    expect(channel({ localWindow: 10 }).consume(11)).toEqual({ overflow: true, adjust: 0 })
  })

  it('will not send on a closed channel', () => {
    const open = channel()
    open.closed = true

    expect(() => open.chunk(new Uint8Array(1))).toThrow(ProtocolError)
  })

  it('reports its own state, with both ids kept apart', () => {
    const open = channel()

    expect(open.state.localId).toBe(1)
    expect(open.state.remoteId).toBe(7)
    expect(open.state.remoteWindow).toBe(100)
  })

  /** Data is addressed to the peer's number, never our own. */
  it('addresses data to the remote id', () => {
    const { packets } = channel().chunk(new Uint8Array(4))
    const reader = new Reader(packets[0]!)
    reader.byte()

    expect(reader.uint32()).toBe(7)
  })
})

describe('writeChannelWindowAdjust', () => {
  it('tells the peer how much more it may send', () => {
    const reader = new Reader(writeChannelWindowAdjust(3, 2048))

    expect(reader.byte()).toBe(Message.CHANNEL_WINDOW_ADJUST)
    expect(reader.uint32()).toBe(3)
    expect(reader.uint32()).toBe(2048)
  })
})
