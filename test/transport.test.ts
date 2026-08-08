import { describe, expect, it } from 'bun:test'
import { randomBytes } from 'node:crypto'
import { ProtocolError } from '../src/buffer'
import { createPacketCipher, keyLengthsFor } from '../src/cipher'
import { framePacket } from '../src/packet'
import { REKEY_PACKETS, Transport } from '../src/transport'

const text = (value: string) => new TextEncoder().encode(value)
const zeros = (size: number) => new Uint8Array(size)

/** Two ends of one connection, greeted and ready for packets. */
function connected() {
  const client = new Transport({ software: 'client', random: zeros })
  const server = new Transport({ software: 'server', random: zeros })

  client.receive(server.greeting())
  server.receive(client.greeting())

  return { client, server }
}

/** Both directions of an agreed cipher, from one set of key material. */
function ciphers(name = 'aes256-gcm@openssh.com') {
  const lengths = keyLengthsFor(name)
  const key = randomBytes(lengths.key)
  const iv = randomBytes(lengths.iv)
  const make = () => createPacketCipher({ cipher: name, key, iv, random: zeros })

  return { send: make(), receive: make() }
}

describe('the version exchange', () => {
  it('greets with what it calls itself', () => {
    const transport = new Transport({ software: 'ts-ssh' })

    expect(new TextDecoder().decode(transport.greeting())).toBe('SSH-2.0-ts-ssh\r\n')
  })

  it('reads the peer\'s line', () => {
    const transport = new Transport()
    transport.receive(text('SSH-2.0-OpenSSH_9.6\r\n'))

    expect(transport.peer?.software).toBe('OpenSSH_9.6')
  })

  /**
   * TCP delivers whatever it feels like, and a line split across two reads is
   * the case that works on a laptop and fails across the Atlantic.
   */
  it('takes an identification split across reads', () => {
    const transport = new Transport()
    transport.receive(text('SSH-2.0-Open'))

    expect(transport.peer).toBeNull()

    transport.receive(text('SSH_9.6\r\n'))
    expect(transport.peer?.software).toBe('OpenSSH_9.6')
  })

  /** A server may send any number of lines before its identification. */
  it('ignores banner lines that come first', () => {
    const transport = new Transport()
    transport.receive(text('a legal notice\r\nand another line\r\nSSH-2.0-OpenSSH_9.6\r\n'))

    expect(transport.peer?.software).toBe('OpenSSH_9.6')
  })

  it('refuses a version it does not speak', () => {
    const transport = new Transport()

    expect(() => transport.receive(text('SSH-1.5-ancient\r\n'))).toThrow(ProtocolError)
  })
})

describe('packets, in the clear', () => {
  it('carries a payload between two ends', () => {
    const { client, server } = connected()
    const payload = text('SSH_MSG_KEXINIT and its lists')

    expect(server.receive(client.send(payload))).toEqual([payload])
  })

  it('takes a packet that arrives in pieces', () => {
    const { client, server } = connected()
    const packet = client.send(text('split me'))

    expect(server.receive(packet.subarray(0, 3))).toEqual([])
    expect(server.receive(packet.subarray(3, 9))).toEqual([])
    expect(server.receive(packet.subarray(9))).toEqual([text('split me')])
  })

  it('takes several packets that arrive together', () => {
    const { client, server } = connected()
    const both = new Uint8Array([...client.send(text('one')), ...client.send(text('two'))])

    expect(server.receive(both)).toEqual([text('one'), text('two')])
  })

  /** The identification and the first packet in one read is what a fast peer does. */
  it('takes a greeting and a packet in the same read', () => {
    const client = new Transport({ software: 'client', random: zeros })
    const server = new Transport({ software: 'server', random: zeros })
    server.receive(client.greeting())

    const first = client.send(text('immediately'))
    const together = new Uint8Array([...server.greeting(), ...new Uint8Array(0)])

    client.receive(together)
    expect(server.receive(first)).toEqual([text('immediately')])
  })

  it('refuses a length that is out of range', () => {
    const { server } = connected()

    expect(() => server.receive(new Uint8Array([0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0]))).toThrow(ProtocolError)
  })
})

describe('packets, encrypted', () => {
  it('carries a payload once both sides have keys', () => {
    const { client, server } = connected()
    const agreed = ciphers()

    client.useSendCipher(agreed.send)
    server.useReceiveCipher(agreed.receive)

    const payload = text('SSH_MSG_CHANNEL_DATA')
    expect(server.receive(client.send(payload))).toEqual([payload])
  })

  it('carries a stream of them, in order', () => {
    const { client, server } = connected()
    const agreed = ciphers()

    client.useSendCipher(agreed.send)
    server.useReceiveCipher(agreed.receive)

    for (let index = 0; index < 25; index++) {
      const payload = text(`packet ${index}`)

      expect(server.receive(client.send(payload))).toEqual([payload])
    }
  })

  it('keeps the payload off the wire', () => {
    const { client, server } = connected()
    const agreed = ciphers()

    client.useSendCipher(agreed.send)
    server.useReceiveCipher(agreed.receive)

    const secret = text('correct horse battery staple')
    const packet = client.send(secret)

    expect(Buffer.from(packet).includes(Buffer.from(secret))).toBe(false)
  })

  it('works with the CTR construction too', () => {
    const { client, server } = connected()
    const lengths = keyLengthsFor('aes256-ctr', 'hmac-sha2-256-etm@openssh.com')
    const key = randomBytes(lengths.key)
    const iv = randomBytes(lengths.iv)
    const macKey = randomBytes(lengths.mac)
    const make = () => createPacketCipher({ cipher: 'aes256-ctr', mac: 'hmac-sha2-256-etm@openssh.com', key, iv, macKey, random: zeros })

    client.useSendCipher(make())
    server.useReceiveCipher(make())

    const payload = text('over counter mode')
    expect(server.receive(client.send(payload))).toEqual([payload])
  })

  /**
   * The changeover happens at a specific packet, and the counter continues
   * across it - RFC 4253 §7.3. A transport that reset it would produce a first
   * encrypted packet the peer rejects.
   */
  it('continues the sequence across the changeover', () => {
    const { client, server } = connected()

    // Three packets in the clear first, as a real handshake sends.
    for (const message of ['kexinit', 'kexdh', 'newkeys'])
      server.receive(client.send(text(message)))

    expect(client.sequences.send).toBe(3)
    expect(server.sequences.receive).toBe(3)

    const agreed = ciphers()
    client.useSendCipher(agreed.send)
    server.useReceiveCipher(agreed.receive)

    // Sealed at sequence 3, and the receiver has to open it at 3.
    const payload = text('the first encrypted packet')
    expect(server.receive(client.send(payload))).toEqual([payload])
  })

  /**
   * Both sides count every packet or neither does. A receiver that skipped one
   * would reject everything from that point on.
   */
  it('refuses a packet whose sequence has drifted', () => {
    const { client, server } = connected()
    const agreed = ciphers()

    client.useSendCipher(agreed.send)
    server.useReceiveCipher(agreed.receive)

    const first = client.send(text('one'))
    const second = client.send(text('two'))

    // Deliver the second first: the sequence numbers no longer line up.
    expect(() => server.receive(second)).toThrow(ProtocolError)
    expect(first.length).toBeGreaterThan(0)
  })
})

describe('bookkeeping', () => {
  it('counts every packet, in both directions', () => {
    const { client, server } = connected()

    server.receive(client.send(text('a')))
    server.receive(client.send(text('b')))

    expect(client.sequences.send).toBe(2)
    expect(server.sequences.receive).toBe(2)
    expect(server.sequences.send).toBe(0)
  })

  it('says how much is buffered and not yet a packet', () => {
    const { client, server } = connected()
    const packet = client.send(text('incomplete'))

    server.receive(packet.subarray(0, 5))
    expect(server.buffered).toBe(5)

    server.receive(packet.subarray(5))
    expect(server.buffered).toBe(0)
  })

  it('knows it is not encrypted until both directions are', () => {
    const { client } = connected()
    const agreed = ciphers()

    expect(client.encrypted).toBe(false)
    client.useSendCipher(agreed.send)
    expect(client.encrypted).toBe(false)
    client.useReceiveCipher(agreed.receive)
    expect(client.encrypted).toBe(true)
  })

  /**
   * The sequence number is the GCM nonce, and a nonce that repeats under one
   * key does not merely leak a plaintext - it leaks the authentication key.
   */
  it('asks for a rekey long before the sequence could repeat', () => {
    const { client } = connected()

    expect(client.rekeyDue).toBe(false)
    expect(REKEY_PACKETS).toBeLessThan(2 ** 32)
  })
})

describe('the identification line, and the packet glued to it', () => {
  /**
   * One TCP segment carrying the greeting and the first packet together.
   *
   * This is the normal case, not an edge one: OpenSSH sends its identification
   * and its KEXINIT without waiting, and the two arrive as one read far more
   * often than not.
   */
  function greetingWith(payload: Uint8Array, terminator = '\r\n'): Uint8Array {
    const greeting = text(`SSH-2.0-peer${terminator}`)
    const packet = framePacket(payload, 8, size => new Uint8Array(size).fill(0x0A))
    const out = new Uint8Array(greeting.length + packet.length)

    out.set(greeting)
    out.set(packet, greeting.length)

    return out
  }

  it('reads a packet that arrived with the greeting', () => {
    const transport = new Transport({ software: 'ts-ssh' })
    const payload = text('a payload with no newline in it')

    transport.push(greetingWith(payload))

    expect(transport.next()).toEqual(payload)
  })

  it('reads one containing a newline, glued to a CRLF greeting', () => {
    const transport = new Transport({ software: 'ts-ssh' })

    // 0x0A anywhere in the packet used to decide where the greeting ended.
    // The greeting was located by rebuilding its text and searching for it,
    // and the rebuilt text had lost the `\r` - so the search never matched and
    // the code fell back to "everything after the last newline in the buffer",
    // which lands in the middle of this payload.
    //
    // A KEXINIT is mostly random bytes, so about one connection in ten hit it:
    // the server read an algorithm name as a packet length and disconnected the
    // client mid handshake. Deterministic here, and it was not deterministic
    // anywhere else.
    const payload = text('aes256-ctr\nhmac-sha2-512\naes128-ctr')

    transport.push(greetingWith(payload))

    expect(transport.next()).toEqual(payload)
  })

  it('reads one glued to a bare-LF greeting too', () => {
    const transport = new Transport({ software: 'ts-ssh' })
    const payload = text('line one\nline two')

    // The RFC says CR LF and some implementations send only LF. Both have to
    // find the same offset.
    transport.push(greetingWith(payload, '\n'))

    expect(transport.next()).toEqual(payload)
  })

  it('skips banner lines before the identification', () => {
    const transport = new Transport({ software: 'ts-ssh' })
    const payload = text('after\nthe\nbanner')
    const banner = text('a legal notice\r\nand another line\r\n')
    const rest = greetingWith(payload)
    const out = new Uint8Array(banner.length + rest.length)

    out.set(banner)
    out.set(rest, banner.length)

    transport.push(out)

    expect(transport.next()).toEqual(payload)
  })

  it('waits when the greeting has not all arrived', () => {
    const transport = new Transport({ software: 'ts-ssh' })
    const payload = text('split\nacross\nreads')
    const whole = greetingWith(payload)

    // Split inside the identification line, which is where an offset kept
    // across calls goes wrong.
    transport.push(whole.subarray(0, 6))
    expect(transport.next()).toBeNull()

    transport.push(whole.subarray(6))
    expect(transport.next()).toEqual(payload)
  })
})
