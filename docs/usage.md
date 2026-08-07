# Usage

## The wire format

Everything in SSH is one of six types laid end to end (RFC 4251 §5). Get these
wrong and nothing above them can be right.

```ts
import { Reader, Writer } from '@stacksjs/ts-ssh'

const blob = new Writer().string('ssh-ed25519').string(point).done()

const reader = new Reader(blob)
reader.text()     // 'ssh-ed25519'
reader.string()   // the 32-byte point
```

A `Reader` is bounds-checked everywhere. It parses bytes an unauthenticated peer
chose, so a length that peer invented has to become a refusal rather than an
out-of-bounds read.

`mpint` is the type most often got wrong:

```ts
new Writer().mpint(0n)      // an empty string, not a zero byte
new Writer().mpint(0x80n)   // a leading zero, so it is not read back as negative
```

## Reading keys

```ts
import { fingerprintOf, parseAuthorizedKey, parseAuthorizedKeys, sameKey } from '@stacksjs/ts-ssh'

const key = parseAuthorizedKey(line)
// { type, blob, fingerprint, publicKey, bits, options, comment }
```

Strict, because this is the file that decides who may log in:

- A line whose stated type disagrees with the blob inside it is refused. The two
  come from different places, and a line saying `ssh-ed25519` over an RSA blob
  was written by something that should not be trusted.
- Base64 is validated before it is decoded. `atob` accepts things that are not
  base64 and quietly produces the wrong bytes, and the wrong bytes are the wrong
  key.
- Options come before the type and may contain spaces inside quotes, so the type
  is searched for rather than split to.

Comparison is by blob and in constant time. Comparing fingerprints would compare
a hash of the thing rather than the thing; comparing base64 would make
whitespace and padding matter.

## Packets

```ts
import { framePacket, paddingFor, parseIdentification, takeLines, unframePacket } from '@stacksjs/ts-ssh'
```

The padding rules are arithmetic that has to be exactly right or the peer
resynchronises on garbage: the whole packet including the length field is a
multiple of the block size or of 8, whichever is larger, and there are always at
least four bytes of padding.

The padding is random, and that is not decoration - it is what stops an observer
measuring the exact length of a password. `framePacket` takes an injectable
source so a test can be deterministic, and defaults to real randomness.

`takeLines` exists because the version exchange arrives however TCP felt like
delivering it, and a line can be split across two reads. Losing that remainder
is the bug that works on a fast connection and not on a slow one.

## Ciphers

```ts
import { createPacketCipher, keyLengthsFor } from '@stacksjs/ts-ssh'

const lengths = keyLengthsFor('aes256-gcm@openssh.com')
const cipher = createPacketCipher({ cipher: 'aes256-gcm@openssh.com', key, iv })

cipher.seal(sequence, payload)      // framed, padded, encrypted, authenticated
cipher.packetLength(firstFourBytes) // how much to read
cipher.open(sequence, packet)       // authenticated, then decrypted
```

The sequence number is an argument rather than internal state: it is what stops
a packet being replayed at a different point in the stream, and both sides have
to be counting the same thing.

`open` authenticates before it decrypts, and returns nothing partial on failure.
A caller that acts on unverified plaintext is acting on bytes an attacker chose.

Padding is random, and the source is injectable so a test can be deterministic -
but it defaults to real randomness, because the padding is what hides the length
of a password.

**Only what can be applied is offered.** `ALGORITHMS.cipher` is derived from the
implemented set rather than written beside it: a name in a KEXINIT list is a
promise, and a hand-kept list drifts from the code that has to keep it.

## Key exchange

```ts
import { deriveKey, exchangeHash, negotiateAll } from '@stacksjs/ts-ssh'
```

`negotiateAll` picks the **client's** first choice that the server also offers.
A server that picks its own favourite is a server that can be talked down to its
weakest shared option.

`exchangeHash` is a hash of eight fields: both identification strings, both
KEXINIT payloads, the host key, both ephemeral publics, and the shared secret.
That list is the whole security argument - a signature over it is a signature
over both sides' idea of what was negotiated, so an attacker who edited the
algorithm lists in flight produces a different hash.

`deriveKey` produces the six keys of RFC 4253 §7.2. The letters are fixed: A and
B are the IVs, C and D the encryption keys, E and F the MAC keys, client to
server first in each pair.

## Authentication

```ts
import { readUserAuthRequest, verifyUserAuthSignature } from '@stacksjs/ts-ssh'

const request = readUserAuthRequest(payload)

if (!request.hasSignature) {
  // A probe. A client with several keys asks about each before signing with
  // any, so it does not make somebody touch a hardware key once per candidate.
  return writeUserAuthPkOk(request.algorithm!, request.publicKey!)
}

const proof = verifyUserAuthSignature({ sessionId, request })
if (!proof.ok)
  return writeUserAuthFailure(['publickey'])

// Separately: is this key one we know, and may that person do this?
```

Two questions, and keeping them apart matters. A signature that verifies says
only that whoever sent it holds that private key.

The session identifier is the first field signed. A signature captured from one
connection cannot be replayed into another, under a different user, or against a
different service - and the test suite checks each of those refusals rather than
trusting the argument.

## Transport

TCP delivers whatever it feels like: a packet in three reads, two packets in
one, the version exchange split down the middle of a line.

```ts
import { Transport } from '@stacksjs/ts-ssh'

const transport = new Transport({ software: 'my-forge' })
socket.write(transport.greeting())

for (const payload of transport.receive(chunk))
  handle(payload)

socket.write(transport.send(reply))
```

`receive` returns the payloads that completed and keeps the rest buffered. A
caller that ignores the remainder is the bug this exists to prevent.

The sequence numbers count every packet from the first, including the ones sent
in the clear, and **do not reset** when encryption begins. They are what the MAC
covers, so a receiver that miscounts rejects everything from that point on.

`useSendCipher` and `useReceiveCipher` are the changeover, per direction, at the
packet where `NEWKEYS` says so.

## Channels

One connection carries many independent streams, each with its own window.

```ts
import { Channel, readChannelRequest, writeExitStatus } from '@stacksjs/ts-ssh'

const request = readChannelRequest(payload)
if (request.request === 'exec')
  run(request.command)

const { packets, remaining } = channel.chunk(output)
```

`chunk` is bounded by two things at once: the window, which is how much the peer
will accept in total, and the maximum packet size, which is how much it will
accept at once. It returns what fits and hands back the rest.

`consume` accounts for data that arrived and says when to open the window
again. That happens at half: an adjustment per packet would double the message
count of every transfer, and waiting until the window is empty stalls the
sender for a round trip.

## Host keys

A server needs a key that says which host it is, and one that changes between
restarts makes every client that ever connected print the warning about a
changed fingerprint - which is the warning that is supposed to mean something.

```ts
import { generateHostKey, parsePrivateKey } from '@stacksjs/ts-ssh'

const generated = generateHostKey('my-forge')
await Bun.write('host_key', generated.openssh)

const key = parsePrivateKey(await Bun.file('host_key').text())
key.fingerprint // SHA256:…
```

The container is `openssh-key-v1`, the one `ssh-keygen` writes today, and it is
read and written here rather than approximated: `ssh-keygen -y` accepts what
this produces, and this accepts what `ssh-keygen` produces. A generator that
only its own parser accepts has invented a private format.

The seed is checked against the point it claims to derive. A file can write the
same wrong public key in all three places it appears and be perfectly
self-consistent; deriving it is the only check that catches that, and the
symptom of missing it is a server that signs with one key while advertising
another.

Keys with a passphrase are refused. Unwrapping one needs `bcrypt_pbkdf`, and a
daemon has nobody at the keyboard when it starts, so the error names the fix:
`ssh-keygen -p -N "" -f <file>`.

## The handshake

`serve` is the whole thing on a port.

```ts
import { generateHostKey, serve } from '@stacksjs/ts-ssh'

serve({
  port: 2222,
  hostKey: generateHostKey().key,
  authenticate: ({ user, blob }) => isKnownKey(user, blob),

  onCommand(command) {
    const child = Bun.spawn(['git-upload-pack', pathFor(command.command)], {
      stdin: 'pipe',
      stdout: 'pipe',
    })

    command.onData(data => child.stdin.write(data))
    command.onEnd(() => child.stdin.end())

    for await (const chunk of child.stdout)
      command.write(chunk)

    command.exit(await child.exited)
  },
})
```

`authenticate` runs only after the signature has been checked, so it answers
"may this key in" rather than "is this key real". Returning false produces the
same failure every time, whatever the reason: telling a client whether a user
exists, or whether a key is known but unauthorised, turns a login prompt into a
directory.

`write` queues. The bytes leave as the peer's channel window allows and as the
socket accepts them, and `exit` waits for the queue to drain - a close that
overtakes the output it follows truncates it.

Shell and pty requests are refused by default, which is what a forge wants: it
runs git for people with no account on the machine. Pass `allow` to change it.

### Driving it yourself

`ServerSession` is the same state machine without the socket, for a caller that
has its own transport or wants to assert on the sequence.

```ts
import { ServerSession } from '@stacksjs/ts-ssh'

const session = new ServerSession({ hostKey, authenticate })
socket.write(session.start())

const { send, events, closed } = await session.receive(chunk)
```

The order is the security property. A `USERAUTH_REQUEST` before `NEWKEYS` is a
request to send a signature in the clear; a `CHANNEL_OPEN` before authentication
is a request to run a command as nobody. Both are refused rather than handled,
because an implementation that is merely *usually* in the right state is one
where the peer chooses the state.

### Strict key exchange

On when both sides announce `kex-strict-*-v00@openssh.com`, which every current
OpenSSH does. It resets the sequence numbers at `NEWKEYS` and refuses the
messages that exist to be ignored.

Terrapin (CVE-2023-48795) works by injecting packets into the unencrypted
handshake to push one side's counter forward, then deleting the same number of
encrypted packets to bring it back into line - the deleted ones are never missed
because the counter runs unbroken across the changeover. Resetting it makes the
two halves independent.

### Rekeying

RFC 4253 §9 asks for new keys after an hour or a gigabyte, and `serve` does it
without being asked: it sends a `KEXINIT` when its own counters say one is due,
and answers the peer's when the peer gets there first. The transfer underneath
continues - what cannot go out between a `KEXINIT` and its `NEWKEYS` waits in
the same backlog that already holds what the peer's window will not take.

This is not optional politeness. OpenSSH renegotiates on its own schedule, and a
server that answers a second `KEXINIT` with `UNIMPLEMENTED` leaves the client
stuck at `rekeying in progress`, unable to send another byte - because after
sending a `KEXINIT` a peer may not send anything else until `NEWKEYS`. A clone
survives that by accident, since the client is only receiving. A push does not.

The session id does **not** change. It is the first exchange hash, and it is
what the client's authentication signature was bound to.

One trap worth naming, because it cost an afternoon and the symptom accuses the
wrong layer. **The strict-kex markers appear only in the first `KEXINIT`.** A
server that re-reads `kex-strict-c-v00@openssh.com` from a rekey's proposal
concludes strict mode is off, while the client - which decided once - keeps it
on. One side then resets its sequence numbers at `NEWKEYS` and the other does
not, and every packet after that fails the peer's MAC. It reads exactly like a
broken cipher.

Lower the thresholds with `rekeyBytes` and `rekeyPackets` to exercise it. A test
that had to move a gigabyte to watch a rekey happen is a test nobody runs, and
so a test that never catches a rekey that broke.
