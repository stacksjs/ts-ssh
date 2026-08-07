/**
 * The server side of a connection, from the first byte to a running command.
 *
 * Every other module here is a piece that can be tested on its own. This is the
 * one that puts them in order, and the order is the security property: each
 * step is refused until the step before it has happened.
 *
 *     version    both sides say what they are, in plain text
 *     kex        algorithms are agreed and a secret is exchanged
 *     newkeys    every byte after this is encrypted
 *     service    the client asks for `ssh-userauth`
 *     auth       the client proves it holds a key, inside the encryption
 *     session    channels open, commands run
 *
 * **The refusals are the point.** A `USERAUTH_REQUEST` that arrives before
 * `NEWKEYS` is a request to send a signature in the clear. A `CHANNEL_OPEN`
 * before authentication is a request to run a command as nobody. Both are
 * dropped here rather than handled, because an implementation that is merely
 * *usually* in the right state is one where a peer chooses the state.
 *
 * What this deliberately is not: a socket, a process launcher, or a policy.
 * It takes bytes and returns bytes and events, so the daemon above it decides
 * who may log in and what a command means, and so all of it can be tested
 * without opening a port. `test/handshake.test.ts` drives it with the real
 * OpenSSH client, which is the only opinion about correctness that counts.
 */

import type { PacketCipher } from './cipher'
import type { Negotiated } from './kex'
import type { PublicKey } from './keys'
import type { PrivateKey } from './privatekey'
import { readUserAuthRequest, verifyUserAuthSignature, writeUserAuthFailure, writeUserAuthPkOk, writeUserAuthSuccess } from './auth'
import { ProtocolError, Reader, Writer } from './buffer'
import {
  Channel,
  DEFAULT_MAX_PACKET,
  DEFAULT_WINDOW,
  OpenFailure,
  readChannelOpen,
  readChannelRequest,
  writeChannelClose,
  writeChannelEof,
  writeChannelExtendedData,
  writeChannelFailure,
  writeChannelOpenConfirmation,
  writeChannelOpenFailure,
  writeChannelSuccess,
  writeChannelWindowAdjust,
  writeExitStatus,
} from './channel'
import { createPacketCipher, keyLengthsFor } from './cipher'
import { generateEphemeral, readKexEcdhInit, writeKexEcdhReply } from './exchange'
import { ALGORITHMS, deriveKey, exchangeHash, negotiateAll, readKexInit, STRICT_KEX_CLIENT, writeKexInit } from './kex'
import { parsePublicKey } from './keys'
import {
  Disconnect,
  Message,
  writeDisconnect,
  writeNewKeys,
  writeServiceAccept,
  writeUnimplemented,
} from './packet'
import { Transport } from './transport'

/** Where a connection has got to. */
export type Phase = 'kex' | 'newkeys' | 'service' | 'auth' | 'session' | 'closed'

/**
 * What the daemon above needs to know about.
 *
 * Events rather than callbacks, so a caller handles them in its own order and a
 * test can assert on the whole sequence. Nothing here is a question: by the
 * time an event is emitted the protocol answer has already been produced.
 */
export type SessionEvent =
  | { type: 'authenticated', user: string, key: PublicKey }
  | { type: 'auth-failed', user: string, reason: string }
  | { type: 'channel-open', channel: Channel }
  | { type: 'exec', channel: Channel, command: string }
  | { type: 'shell', channel: Channel }
  | { type: 'env', channel: Channel, name: string, value: string }
  | { type: 'data', channel: Channel, data: Uint8Array }
  | { type: 'eof', channel: Channel }
  | { type: 'close', channel: Channel }
  | { type: 'disconnect', reason: number, description: string }

/** Bytes to write to the peer, and what happened while producing them. */
export interface Outcome {
  send: Uint8Array
  events: SessionEvent[]
  /** Whether the connection is finished and the socket should be closed. */
  closed: boolean
}

export interface AuthAttempt {
  user: string
  service: string
  key: PublicKey
  /** The blob as it arrived, for comparing against a stored key byte for byte. */
  blob: Uint8Array
}

export interface ServerOptions {
  /** The key that proves which host this is. */
  hostKey: PrivateKey
  /** What to call ourselves in the version exchange. */
  software?: string
  /**
   * Whether this key may log in as this user.
   *
   * Called only after the signature has been checked, so the question is
   * genuinely "may this key in", not "is this key real". Async because the
   * answer is almost always in a database.
   *
   * A probe - a client asking whether a key *would* be accepted before making
   * the user touch a hardware token - calls this too, with no signature yet
   * verified. That is what the protocol asks for and it leaks nothing a
   * subsequent real attempt would not.
   */
  authenticate: (attempt: AuthAttempt) => Promise<boolean> | boolean
  /**
   * Channel requests to accept.
   *
   * `exec` and `env` by default, and not `shell` or `pty-req`: a forge runs
   * `git-upload-pack` for people who have no account on the machine, and
   * answering a shell request with `CHANNEL_FAILURE` is how it says so. A
   * server that wants to hand out shells says so explicitly.
   */
  allow?: readonly string[]
  /** Shown to the client before it is let in. */
  banner?: string
  /** Padding randomness, injectable so a test can be deterministic. */
  random?: (size: number) => Uint8Array
  /**
   * Override the thresholds a rekey becomes due at.
   *
   * The defaults are RFC 4253 §9's gigabyte and 2^31 packets. Lowering them is
   * for tests: one that had to move a gigabyte to watch a rekey happen is one
   * nobody runs, and so one that never catches a rekey that broke.
   */
  rekeyBytes?: number
  rekeyPackets?: number
}

/**
 * How many times a client may fail before the connection ends.
 *
 * Six, which is what OpenSSH allows. A client with several keys tries each in
 * turn, so the limit cannot be one - but without a limit at all, a connection
 * is an unbounded signature-checking service.
 */
export const MAX_AUTH_ATTEMPTS: number = 6

/**
 * How much a peer may send before it has authenticated.
 *
 * A handshake is a few kilobytes. Anything past this is a peer using an
 * unauthenticated connection as free storage, and there is no legitimate shape
 * of traffic this refuses.
 */
export const MAX_UNAUTHENTICATED_BYTES: number = 256 * 1024

export class ServerSession {
  private readonly transport: Transport
  private readonly options: ServerOptions
  private readonly allow: readonly string[]

  private phase: Phase = 'kex'
  private ourKexInit: Uint8Array | null = null
  private theirKexInit: Uint8Array | null = null
  private negotiated: Negotiated | null = null
  private pendingKeys: { send: PacketCipher, receive: PacketCipher } | null = null

  private strictKex = false
  /**
   * Where a renegotiation has got to.
   *
   * `requested` means our KEXINIT has gone out and the peer's has not arrived;
   * `exchanging` means both have. The distinction matters because the rules
   * differ on each side of it: after sending a KEXINIT we may not send anything
   * else until NEWKEYS, but the peer is entitled to keep sending until it sees
   * ours - so those messages have to be handled, not refused.
   */
  private kexState: 'none' | 'requested' | 'exchanging' = 'none'
  /** What to go back to once the new keys are in. */
  private resumePhase: Phase | null = null

  private authAttempts = 0
  private unauthenticatedBytes = 0
  private nextChannelId = 0

  private readonly channels = new Map<number, Channel>()

  /** The exchange hash of the first key exchange. Null until it has happened. */
  sessionId: Uint8Array | null = null
  /** Who the client proved it was. Null until it has. */
  user: string | null = null
  /**
   * The key it proved it with, and the blob exactly as it arrived.
   *
   * The name is what the client typed and the key is what it had to prove, so
   * anything deciding what this connection may do wants the second. Kept here
   * rather than only passed to `authenticate`, because the decision that needs
   * it - what a command may touch - happens later, once a repository has been
   * named.
   */
  key: PublicKey | null = null
  keyBlob: Uint8Array | null = null

  constructor(options: ServerOptions) {
    this.options = options
    this.allow = options.allow ?? ['exec', 'env']
    this.transport = new Transport({
      software: options.software,
      random: options.random,
      rekeyBytes: options.rekeyBytes,
      rekeyPackets: options.rekeyPackets,
    })
  }

  /**
   * The first bytes to send: the identification line and our KEXINIT.
   *
   * Both go out before anything has arrived. The protocol allows it and every
   * implementation does it, because waiting for the peer's KEXINIT before
   * sending your own adds a round trip to every connection for nothing.
   */
  start(): Uint8Array {
    const kexInit = writeKexInit(ALGORITHMS)
    this.ourKexInit = kexInit

    return concat([this.transport.greeting(), this.transport.send(kexInit)])
  }

  /** Feed bytes from the socket in; get bytes and events back. */
  async receive(chunk: Uint8Array): Promise<Outcome> {
    if (this.phase === 'closed')
      return { send: new Uint8Array(0), events: [], closed: true }

    this.transport.push(chunk)

    if (!this.user) {
      this.unauthenticatedBytes += chunk.length

      if (this.unauthenticatedBytes > MAX_UNAUTHENTICATED_BYTES)
        return this.close(Disconnect.PROTOCOL_ERROR, 'Too much said before saying who you are')
    }

    const out: Uint8Array[] = []
    const events: SessionEvent[] = []

    try {
      // One packet at a time, because installing the receive cipher happens
      // *between* two of them and a drain-everything loop would be past the
      // changeover before it could.
      for (;;) {
        const payload = this.transport.next()
        if (!payload)
          break

        const outcome = await this.handle(payload, events)
        if (outcome)
          out.push(outcome)

        // Read through the getter: a private field stays narrowed across the
        // call above, and `handle` is exactly where the phase changes.
        if (this.state === 'closed')
          return { send: concat(out), events, closed: true }
      }
    }
    catch (error) {
      const description = error instanceof ProtocolError ? error.message : 'Protocol error'
      const closing = this.close(Disconnect.PROTOCOL_ERROR, description)

      return { send: concat([...out, closing.send]), events, closed: true }
    }

    return { send: concat(out), events, closed: false }
  }

  /** One payload, in whatever phase we are in. */
  private async handle(payload: Uint8Array, events: SessionEvent[]): Promise<Uint8Array | null> {
    if (payload.length === 0)
      throw new ProtocolError('An empty packet is not a message')

    const message = payload[0]!

    // Answered in any phase. `IGNORE` and `DEBUG` exist to be discarded, and
    // discarding them still advances the sequence number - which the transport
    // has already done by the time this is reached.
    switch (message) {
      case Message.IGNORE:
      case Message.DEBUG:
      case Message.UNIMPLEMENTED:
        // Except during a strict key exchange, where a message whose only
        // effect is to advance a counter is precisely the tool Terrapin uses.
        // Refusing them is half of what strict mode is.
        if (this.strictKex && (this.phase === 'kex' || this.phase === 'newkeys'))
          throw new ProtocolError(`Message ${message} is not allowed during a strict key exchange`)

        return null

      case Message.DISCONNECT: {
        const reader = new Reader(payload)
        reader.byte()
        const reason = reader.uint32()
        const description = reader.text()
        events.push({ type: 'disconnect', reason, description })
        this.phase = 'closed'

        return null
      }
    }

    // A renegotiation happens *inside* an established session, so ordinary
    // channel traffic keeps arriving while it runs: the peer may send until it
    // has seen our KEXINIT, and what is in flight when we send ours arrives
    // afterwards. Refusing it here would kill the connection over timing.
    if (this.phase === 'kex' && this.kexState !== 'none'
      && message !== Message.KEXINIT && message !== Message.KEX_ECDH_INIT) {
      return this.handleSession(message, payload, events)
    }

    switch (this.phase) {
      case 'kex':
        return this.handleKex(message, payload)
      case 'newkeys':
        return this.handleNewKeys(message)
      case 'service':
        return this.handleService(message, payload)
      case 'auth':
        return this.handleAuth(message, payload, events)
      case 'session':
        return this.handleSession(message, payload, events)
      default:
        return null
    }
  }

  private handleKex(message: number, payload: Uint8Array): Uint8Array | null {
    if (message === Message.KEXINIT) {
      this.theirKexInit = payload
      const theirs = readKexInit(payload)
      const ours = readKexInit(this.ourKexInit!)

      // Decided by the *first* KEXINIT and never revisited. OpenSSH sends the
      // marker only in its opening proposal, so re-reading it during a rekey
      // turns strict mode off here while the peer keeps it on - and then one
      // side resets its sequence numbers at NEWKEYS and the other does not.
      // Every packet after that fails the peer's MAC.
      if (this.sessionId === null)
        this.strictKex = theirs.kex.includes(STRICT_KEX_CLIENT)

      // Under strict mode the KEXINIT must be the very first packet. Anything
      // before it is a packet an attacker was allowed to insert for free, and
      // the whole point is that there is no such thing.
      //
      // Only the *first* one: a rekey's KEXINIT arrives mid-stream by
      // definition, and `sessionId` is what tells the two apart, being set by
      // the exchange that follows the first.
      if (this.strictKex && this.sessionId === null && this.transport.sequences.receive !== 1)
        throw new ProtocolError('A strict key exchange begins with KEXINIT and nothing before it')

      // The client's preference decides, per RFC 4253 §7.1: a server that picks
      // its own favourite can be talked down to its weakest option by a client
      // that only offers that one.
      const result = negotiateAll(theirs, ours)
      if ('failed' in result)
        throw new ProtocolError(`No ${result.failed} algorithm in common`)

      this.negotiated = result

      return null
    }

    if (message !== Message.KEX_ECDH_INIT)
      throw new ProtocolError(`Expected a key exchange message and got ${message}`)

    if (!this.negotiated || !this.theirKexInit)
      throw new ProtocolError('A key exchange began before the algorithms were agreed')

    const { clientPublic } = readKexEcdhInit(payload)
    const ephemeral = generateEphemeral()
    const sharedSecret = ephemeral.agree(clientPublic)

    const hostKey = this.options.hostKey
    const hash = exchangeHash({
      clientIdentification: this.transport.peer!.raw,
      serverIdentification: this.transport.identification,
      clientKexInit: this.theirKexInit,
      serverKexInit: this.ourKexInit!,
      hostKey: hostKey.publicKey,
      clientPublic,
      serverPublic: ephemeral.publicKey,
      sharedSecret,
    })

    // The session id is the *first* exchange hash and never changes, even
    // across a rekey. It is what a client signature is bound to, so a rekey
    // that replaced it would invalidate the authentication it already did.
    this.sessionId ??= hash

    const reply = writeKexEcdhReply({
      hostKey: hostKey.publicKey,
      serverPublic: ephemeral.publicKey,
      signature: hostKey.sign(hash),
    })

    // Derived now, installed later: NEWKEYS is itself sent in the clear and is
    // the last packet that is.
    this.pendingKeys = this.deriveCiphers(sharedSecret, hash)
    this.phase = 'newkeys'

    const packets = concat([this.transport.send(reply), this.transport.send(writeNewKeys())])

    // Only after the NEWKEYS packet has been framed. Reversing these two lines
    // encrypts the message that announces encryption, which no peer can read.
    this.transport.useSendCipher(this.pendingKeys.send)

    if (this.strictKex)
      this.transport.resetSendSequence()

    return packets
  }

  /**
   * The six keys of RFC 4253 §7.2, turned into two ciphers.
   *
   * A is the client-to-server IV, B the other direction; C and D the encryption
   * keys; E and F the MAC keys. A server *receives* client-to-server and
   * *sends* server-to-client, so the letters cross over here - and getting that
   * backwards produces a handshake that completes and a connection where each
   * side decrypts to noise.
   */
  private deriveCiphers(sharedSecret: bigint, hash: Uint8Array): { send: PacketCipher, receive: PacketCipher } {
    const negotiated = this.negotiated!
    const sessionId = this.sessionId!

    const incoming = keyLengthsFor(negotiated.cipherClientToServer, negotiated.macClientToServer)
    const outgoing = keyLengthsFor(negotiated.cipherServerToClient, negotiated.macServerToClient)
    const derive = (letter: 'A' | 'B' | 'C' | 'D' | 'E' | 'F', length: number) =>
      deriveKey(sharedSecret, hash, letter, sessionId, length)

    return {
      receive: createPacketCipher({
        cipher: negotiated.cipherClientToServer,
        mac: negotiated.macClientToServer,
        iv: derive('A', incoming.iv),
        key: derive('C', incoming.key),
        macKey: incoming.mac > 0 ? derive('E', incoming.mac) : undefined,
        random: this.options.random,
      }),
      send: createPacketCipher({
        cipher: negotiated.cipherServerToClient,
        mac: negotiated.macServerToClient,
        iv: derive('B', outgoing.iv),
        key: derive('D', outgoing.key),
        macKey: outgoing.mac > 0 ? derive('F', outgoing.mac) : undefined,
        random: this.options.random,
      }),
    }
  }

  /**
   * Ask for new keys on a connection that already has some.
   *
   * A rekey is an ordinary key exchange run again mid-connection, and RFC 4253
   * §9 asks for one after an hour or a gigabyte. It is not optional politeness:
   * OpenSSH initiates one on its own schedule, and a server that answers a
   * second `KEXINIT` with `UNIMPLEMENTED` leaves the client stuck at "rekeying
   * in progress" - unable to send another byte, because after sending a KEXINIT
   * a peer may not send anything else until NEWKEYS. A clone survives that by
   * accident, since the client is only receiving. A push does not.
   *
   * The session id does **not** change. It is the *first* exchange hash and it
   * is what the client's authentication signature was bound to, so replacing it
   * would invalidate the login that already happened.
   *
   * Returns the KEXINIT to send, or nothing when one is already in flight.
   */
  rekey(): Uint8Array {
    if (this.kexState !== 'none' || this.phase !== 'session')
      return new Uint8Array(0)

    this.ourKexInit = writeKexInit(ALGORITHMS)
    this.kexState = 'requested'

    // The phase stays `session` until the peer's KEXINIT arrives. We have
    // stopped sending, but it has not yet been told to.
    return this.transport.send(this.ourKexInit)
  }

  /** Whether a renegotiation is under way, and outbound data must wait. */
  get renegotiating(): boolean {
    return this.kexState !== 'none'
  }

  /**
   * A KEXINIT arrived on an established session.
   *
   * Either the peer started this, or it is answering the one `rekey` sent. The
   * two differ only in whether we still owe it a KEXINIT of our own.
   */
  private beginRekey(payload: Uint8Array): Uint8Array | null {
    const ours = this.kexState === 'requested'
      ? new Uint8Array(0)
      : this.transport.send(this.ourKexInit = writeKexInit(ALGORITHMS))

    this.kexState = 'exchanging'
    this.resumePhase = 'session'
    this.phase = 'kex'

    const negotiated = this.handleKex(Message.KEXINIT, payload)

    return concat([ours, negotiated ?? new Uint8Array(0)])
  }

  private handleNewKeys(message: number): Uint8Array | null {
    if (message !== Message.NEWKEYS)
      throw new ProtocolError(`Expected NEWKEYS and got message ${message}`)

    this.transport.useReceiveCipher(this.pendingKeys!.receive)

    if (this.strictKex)
      this.transport.resetReceiveSequence()

    this.pendingKeys = null
    this.phase = this.resumePhase ?? 'service'
    this.resumePhase = null
    this.kexState = 'none'

    return null
  }

  private handleService(message: number, payload: Uint8Array): Uint8Array | null {
    if (message !== Message.SERVICE_REQUEST)
      throw new ProtocolError(`Expected SERVICE_REQUEST and got message ${message}`)

    const reader = new Reader(payload)
    reader.byte()
    const service = reader.text()

    // `ssh-connection` is the only other service there is, and it is what
    // authentication grants access to. Asking for it directly is asking to skip
    // the part where you say who you are.
    if (service !== 'ssh-userauth')
      throw new ProtocolError(`This server offers ssh-userauth and you asked for ${service}`)

    this.phase = 'auth'

    return this.transport.send(writeServiceAccept(service))
  }

  private async handleAuth(message: number, payload: Uint8Array, events: SessionEvent[]): Promise<Uint8Array | null> {
    if (message !== Message.USERAUTH_REQUEST)
      throw new ProtocolError(`Expected USERAUTH_REQUEST and got message ${message}`)

    const request = readUserAuthRequest(payload)

    if (request.service !== 'ssh-connection')
      return this.fail(request.user, `The service ${request.service} is not one this offers`, events)

    // `none` is how a client asks what the server will accept. It authenticates
    // nobody and the answer is always a failure listing the real methods.
    if (request.method !== 'publickey')
      return this.fail(request.user, `The method ${request.method} is not one this accepts`, events)

    const key = request.publicKey ? parsePublicKey(request.publicKey) : null
    if (!key || !request.publicKey)
      return this.fail(request.user, 'The public key blob could not be read', events)

    const attempt: AuthAttempt = {
      user: request.user,
      service: request.service,
      key,
      blob: request.publicKey,
    }

    // A probe: a client with several keys asks about each before signing with
    // any, so it does not make somebody touch a hardware key once per
    // candidate. The answer says only that the key would be acceptable.
    if (!request.hasSignature) {
      const acceptable = await this.options.authenticate(attempt)
      if (!acceptable)
        return this.fail(request.user, 'That key is not one this account may use', events)

      return this.transport.send(writeUserAuthPkOk(request.algorithm ?? key.type, request.publicKey))
    }

    const verified = verifyUserAuthSignature({ sessionId: this.sessionId!, request })
    if (!verified.ok)
      return this.fail(request.user, verified.reason ?? 'The signature did not check out', events)

    const allowed = await this.options.authenticate(attempt)
    if (!allowed)
      return this.fail(request.user, 'That key is not one this account may use', events)

    this.user = request.user
    this.key = key
    this.keyBlob = request.publicKey
    this.phase = 'session'
    events.push({ type: 'authenticated', user: request.user, key })

    const packets: Uint8Array[] = []

    if (this.options.banner) {
      packets.push(this.transport.send(
        new Writer().byte(Message.USERAUTH_BANNER).string(this.options.banner).string('').done(),
      ))
    }

    packets.push(this.transport.send(writeUserAuthSuccess()))

    return concat(packets)
  }

  /**
   * Refuse one attempt, and end the connection once there have been too many.
   *
   * The reason goes to the caller for a log and never to the client: telling a
   * client whether a *user* exists, or whether a key is known but unauthorised,
   * turns the login prompt into a directory. The wire answer is the same
   * failure every time.
   */
  private fail(user: string, reason: string, events: SessionEvent[]): Uint8Array {
    events.push({ type: 'auth-failed', user, reason })
    this.authAttempts++

    const failure = this.transport.send(writeUserAuthFailure(['publickey']))

    if (this.authAttempts < MAX_AUTH_ATTEMPTS)
      return failure

    return concat([failure, this.close(Disconnect.NO_MORE_AUTH_METHODS_AVAILABLE, 'Too many failed attempts').send])
  }

  private handleSession(message: number, payload: Uint8Array, events: SessionEvent[]): Uint8Array | null {
    switch (message) {
      case Message.KEXINIT:
        return this.beginRekey(payload)

      case Message.CHANNEL_OPEN:
        return this.openChannel(payload, events)

      case Message.CHANNEL_REQUEST:
        return this.channelRequest(payload, events)

      case Message.CHANNEL_DATA: {
        const reader = new Reader(payload)
        reader.byte()
        const channel = this.channelFor(reader.uint32())
        const data = reader.string()

        const { overflow, adjust } = channel.consume(data.length)
        if (overflow)
          throw new ProtocolError('The peer sent more than its window allowed')

        events.push({ type: 'data', channel, data })

        return adjust > 0 ? this.transport.send(writeChannelWindowAdjust(channel.remoteId, adjust)) : null
      }

      case Message.CHANNEL_WINDOW_ADJUST: {
        const reader = new Reader(payload)
        reader.byte()
        const channel = this.channelFor(reader.uint32())
        channel.adjustRemoteWindow(reader.uint32())

        return null
      }

      case Message.CHANNEL_EOF: {
        const reader = new Reader(payload)
        reader.byte()
        const channel = this.channelFor(reader.uint32())
        channel.receivedEof = true
        events.push({ type: 'eof', channel })

        return null
      }

      case Message.CHANNEL_CLOSE: {
        const reader = new Reader(payload)
        reader.byte()
        const channel = this.channelFor(reader.uint32())
        events.push({ type: 'close', channel })
        this.channels.delete(channel.localId)

        // A close is answered with a close, unless one was already sent. Both
        // sides send one and the channel is gone when both have.
        return channel.closed ? null : this.transport.send(writeChannelClose(channel.remoteId))
      }

      case Message.GLOBAL_REQUEST: {
        const reader = new Reader(payload)
        reader.byte()
        reader.text()
        const wantReply = reader.boolean()

        // Port forwarding and the rest, none of which this offers. Answering
        // is what stops a client waiting for a reply that never comes.
        return wantReply
          ? this.transport.send(new Uint8Array([Message.REQUEST_FAILURE]))
          : null
      }

      default:
        // Nothing this understands. Naming the packet lets the peer fail one
        // request instead of the connection.
        return this.transport.send(writeUnimplemented(this.transport.sequences.receive - 1))
    }
  }

  private openChannel(payload: Uint8Array, events: SessionEvent[]): Uint8Array {
    const open = readChannelOpen(payload)

    if (open.channelType !== 'session') {
      return this.transport.send(writeChannelOpenFailure(
        open.senderChannel,
        OpenFailure.UNKNOWN_CHANNEL_TYPE,
        `This server opens session channels, not ${open.channelType}`,
      ))
    }

    // Bounded because each open costs a window's worth of buffer, and a client
    // that opens them in a loop is asking the server to allocate on its behalf.
    if (this.channels.size >= 16) {
      return this.transport.send(writeChannelOpenFailure(
        open.senderChannel,
        OpenFailure.RESOURCE_SHORTAGE,
        'Too many channels open on this connection',
      ))
    }

    const channel = new Channel({
      localId: this.nextChannelId++,
      remoteId: open.senderChannel,
      remoteWindow: open.initialWindowSize,
      remoteMaxPacket: open.maximumPacketSize,
    })

    this.channels.set(channel.localId, channel)
    events.push({ type: 'channel-open', channel })

    return this.transport.send(writeChannelOpenConfirmation({
      recipientChannel: channel.remoteId,
      senderChannel: channel.localId,
      initialWindowSize: DEFAULT_WINDOW,
      maximumPacketSize: DEFAULT_MAX_PACKET,
    }))
  }

  private channelRequest(payload: Uint8Array, events: SessionEvent[]): Uint8Array | null {
    const request = readChannelRequest(payload)
    const channel = this.channelFor(request.recipientChannel)

    if (!this.allow.includes(request.request)) {
      return request.wantReply
        ? this.transport.send(writeChannelFailure(channel.remoteId))
        : null
    }

    if (request.request === 'exec')
      events.push({ type: 'exec', channel, command: request.command ?? '' })
    else if (request.request === 'shell')
      events.push({ type: 'shell', channel })
    else if (request.request === 'env')
      events.push({ type: 'env', channel, name: request.name ?? '', value: request.value ?? '' })

    return request.wantReply
      ? this.transport.send(writeChannelSuccess(channel.remoteId))
      : null
  }

  private channelFor(localId: number): Channel {
    const channel = this.channels.get(localId)
    if (!channel)
      throw new ProtocolError(`There is no channel ${localId} on this connection`)

    return channel
  }

  /**
   * Send data on a channel, as far as its window allows.
   *
   * Returns what would not fit rather than buffering it. A library that
   * buffered silently would turn a peer's refusal to read into this process's
   * memory problem, which is the shape of every flow-control bug there is: the
   * caller holds the remainder and sends it when a window adjustment arrives.
   */
  write(channel: Channel, data: Uint8Array): { bytes: Uint8Array, remaining: Uint8Array } {
    const { packets, remaining } = channel.chunk(data)

    return { bytes: concat(packets.map(packet => this.transport.send(packet))), remaining }
  }

  /** The same for stderr, which the protocol carries as extended data. */
  writeStderr(channel: Channel, data: Uint8Array): { bytes: Uint8Array, remaining: Uint8Array } {
    const { packets, remaining } = channel.chunk(data)
    const bytes = packets.map((packet) => {
      // `chunk` framed these as CHANNEL_DATA to do the window arithmetic. The
      // payload is the same bytes; only the wrapper differs.
      const reader = new Reader(packet)
      reader.byte()
      reader.uint32()

      return this.transport.send(writeChannelExtendedData(channel.remoteId, reader.string()))
    })

    return { bytes: concat(bytes), remaining }
  }

  /**
   * Finish a command: its exit status, then EOF, then close.
   *
   * In that order and all three. A client that gets a close with no exit status
   * has to assume the worst, which is why a server that forgets it makes every
   * command look like it failed - `git clone` reports a broken pipe and nobody
   * can tell why.
   */
  exit(channel: Channel, status: number): Uint8Array {
    channel.sentEof = true
    channel.closed = true

    return concat([
      this.transport.send(writeExitStatus(channel.remoteId, status)),
      this.transport.send(writeChannelEof(channel.remoteId)),
      this.transport.send(writeChannelClose(channel.remoteId)),
    ])
  }

  /** Say why, then stop. The caller closes the socket. */
  close(reason: number, description: string): Outcome {
    if (this.phase === 'closed')
      return { send: new Uint8Array(0), events: [], closed: true }

    const send = this.transport.send(writeDisconnect(reason, description))
    this.phase = 'closed'

    return { send, events: [], closed: true }
  }

  /** Where the connection has got to, for a caller enforcing a timeout. */
  get state(): Phase {
    return this.phase
  }

  /** Whether a rekey is due, from the transport's counters. */
  get rekeyDue(): boolean {
    return this.transport.rekeyDue
  }
}

/** Send channel data as a single buffer, since a socket takes one write. */
function concat(parts: Uint8Array[]): Uint8Array {
  let length = 0
  for (const part of parts)
    length += part.length

  const out = new Uint8Array(length)
  let offset = 0

  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }

  return out
}
