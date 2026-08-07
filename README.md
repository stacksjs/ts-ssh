<p align="center"><img src=".github/art/cover.jpg" alt="Social Card of this repo"></p>

[![npm version][npm-version-src]][npm-version-href]
[![GitHub Actions][github-actions-src]][github-actions-href]
[![Commitizen friendly](https://img.shields.io/badge/commitizen-friendly-brightgreen.svg)](http://commitizen.github.io/cz-cli/)

# ts-ssh

The SSH protocol in TypeScript, built from the bottom up: the data types
everything is written in, the packet that carries them, the negotiation and
exchange that agree a secret, the key formats people paste into a file, and the
proof that somebody holds one.

## Why

These are the rules that decide who is let into a machine, and most of them are
pure functions over bytes. They should be readable, and they should be checkable
without a socket.

So every layer here is separable and tested on its own. The fingerprints in the
test suite are checked against what `ssh-keygen -lf` prints, and the signatures
are made by `node:crypto` over the bytes RFC 4252 specifies - not against
fixtures this library produced, which would only prove it agrees with itself.

## Install

```bash
bun add @stacksjs/ts-ssh
```

## Usage

### Reading keys

The part a forge needs most. The same key appears in three shapes, and this
moves between them: the `authorized_keys` line somebody pasted, the wire blob a
signature is checked against, and the fingerprint a person compares.

```ts
import { parseAuthorizedKey, parseAuthorizedKeys, sameKey } from '@stacksjs/ts-ssh'

const key = parseAuthorizedKey('ssh-ed25519 AAAAC3Nza… ada@example.com')
// { type, blob, fingerprint: 'SHA256:…', publicKey, bits, options, comment }

parseAuthorizedKeys(await Bun.file('~/.ssh/authorized_keys').text())
sameKey(offered.blob, stored.blob)   // constant time, by blob
```

Parsing is strict, because this is the file that decides who may log in. A line
whose stated type disagrees with the blob inside it is refused rather than
guessed at, and base64 is validated before it is decoded - `atob` accepts things
that are not base64 and quietly produces the wrong bytes.

Options come before the type and may contain spaces inside quotes, so the type
is searched for rather than split to. `command="git-shell -c ssh-rsa"` parses
the way you would want.

### Verifying that somebody holds a key

```ts
import { readUserAuthRequest, verifyUserAuthSignature } from '@stacksjs/ts-ssh'

const request = readUserAuthRequest(payload)
const proof = verifyUserAuthSignature({ sessionId, request })
```

A signature that verifies says only *whoever sent this holds that private key*.
Whether they may log in is a separate question, and keeping the two apart is the
point.

The session identifier is the first field signed, which is what makes it safe: a
signature captured from one connection cannot be replayed into another, or under
a different user, or against a different service. The test suite checks each of
those refusals.

### The wire format

```ts
import { Reader, Writer } from '@stacksjs/ts-ssh'

const blob = new Writer().string('ssh-ed25519').string(point).done()
const reader = new Reader(blob)
reader.text()     // 'ssh-ed25519'
reader.string()   // the point
```

Bounds-checked everywhere. A `Reader` parses bytes an unauthenticated peer
chose, so a length it invented becomes a refusal rather than an out-of-bounds
read.

`mpint` is the type most often got wrong: zero is an empty string rather than a
zero byte, and a positive number whose top bit is set gets a leading zero so it
is not read back as negative. Both are pinned against the examples in RFC 4251.

### Packets and key exchange

```ts
import { deriveKey, exchangeHash, framePacket, negotiateAll, unframePacket } from '@stacksjs/ts-ssh'
```

`negotiateAll` picks *the client's* first choice that the server also offers,
per RFC 4253 §7.1 - a server that picks its own favourite can be talked down to
its weakest option.

`exchangeHash` is the eight fields that make the handshake tamper-evident. A
signature over it is a signature over both sides' idea of what was negotiated,
so an attacker who edited the algorithm lists in flight produces a different
hash and a signature that does not check out.

### CLI

```bash
ts-ssh keys ~/.ssh/authorized_keys       # what is in it, and what could not be read
ts-ssh fingerprint "ssh-ed25519 AAAA…"   # SHA256:…
```

### Encrypting a packet

```ts
import { createPacketCipher, keyLengthsFor } from '@stacksjs/ts-ssh'

const lengths = keyLengthsFor('aes256-gcm@openssh.com')
const cipher = createPacketCipher({ cipher: 'aes256-gcm@openssh.com', key, iv })

const wire = cipher.seal(sequence, payload)
const back = cipher.open(sequence, wire)
```

The sequence number is an argument rather than internal state, because it is
what stops a packet being replayed at a different point in the stream - and it
has to be the same number both sides are counting.

Two constructions, both authenticated: `aes256-gcm@openssh.com` and
`aes128-gcm@openssh.com` (RFC 5647, length authenticated as additional data),
and `aes256-ctr`/`aes128-ctr` with `hmac-sha2-*-etm@openssh.com`. Only the
encrypt-then-MAC variants: the older encrypt-and-MAC form requires decrypting a
block to learn the length *before* anything has been authenticated, which means
acting on bytes an attacker chose.

### Channels

```ts
import { Channel, readChannelRequest, writeExitStatus } from '@stacksjs/ts-ssh'

const channel = new Channel({ localId, remoteId, remoteWindow, remoteMaxPacket })

const { packets, remaining } = channel.chunk(output)
// send `packets`; keep `remaining` until the peer opens the window
```

The window is what paces a transfer. `chunk` returns what fits and hands back
the rest rather than throwing - a large write is normal, and overshooting is how
a transfer stalls forever with both sides waiting.

## What is implemented

- **Wire format** - every type in RFC 4251 §5, read and written, bounds-checked
- **Public keys** - `authorized_keys` lines, wire blobs, fingerprints; ed25519, RSA and ECDSA read, unknown types carried without pretending to understand them
- **Packet protocol** - framing, the padding arithmetic, the version exchange and its line buffering
- **Ciphers** - AES-GCM and AES-CTR with encrypt-then-MAC, with the offer derived from what is implemented
- **Transport** - a byte stream buffered into packets, the sequence numbers both MACs depend on, and the changeover to encryption
- **Key exchange** - algorithm negotiation, the exchange hash, and the six derived keys of RFC 4253 §7.2
- **Public key authentication** - the signed blob of RFC 4252 §7, and ed25519 verification
- **Channels** - opens, requests including `exec`, data and stderr, exit status, and the window accounting

## What is not implemented yet

Being plain about it, because a half-built SSH server is worse than none:

- **The handshake driven end to end.** Every piece it needs is here - negotiate,
  exchange, derive, encrypt, authenticate, open a channel - but nothing yet
  sequences them against a socket and a host key. That is the remaining step
  between this and `ssh host command`.
- **`chacha20-poly1305@openssh.com`**, and deliberately. It needs raw ChaCha20
  and a bare Poly1305 over the ciphertext - not the RFC 8439 AEAD construction,
  which appends length blocks this does not. Bun's crypto exposes neither, so
  offering it would mean hand-writing Poly1305: modular arithmetic whose timing
  leaks the key if it is not constant time, in a runtime that makes no such
  guarantee. Every OpenSSH since 6.2 speaks AES-GCM.
- **Signature verification beyond ed25519.** RSA and ECDSA keys are read and
  fingerprinted; a signature over one is refused rather than trusted, which is
  the safe direction to be incomplete in.

A name in a KEXINIT list is a promise to apply it, so the offered ciphers are
derived from the ones implemented rather than written out beside them - and a
test fails if the two ever drift apart.

## Testing

```bash
bun test
```

## Changelog

Please see our [releases](https://github.com/stackjs/ts-ssh/releases) page for more information on what has changed recently.

## Contributing

Please see [CONTRIBUTING](.github/CONTRIBUTING.md) for details.

## Community

For help, discussion about best practices, or any other conversation that would benefit from being searchable:

[Discussions on GitHub](https://github.com/stacksjs/ts-ssh/discussions)

For casual chit-chat with others using this package:

[Join the Stacks Discord Server](https://stacksjs.com/discord)

## Postcardware

“Software that is free, but hopes for a postcard.” We love receiving postcards from around the world showing where Stacks is being used! We showcase them on our website too.

Our address: Stacks.js, 12665 Village Ln #2306, Playa Vista, CA 90094, United States 🌎

## Sponsors

We would like to extend our thanks to the following sponsors for funding Stacks development. If you are interested in becoming a sponsor, please reach out to us.

- [JetBrains](https://www.jetbrains.com/)
- [The Solana Foundation](https://solana.com/)

## License

The MIT License (MIT). Please see [LICENSE](LICENSE.md) for more information.

Made with 💙

<!-- Badges -->
[npm-version-src]: https://img.shields.io/npm/v/ts-ssh?style=flat-square
[npm-version-href]: https://npmjs.com/package/ts-ssh
[github-actions-src]: https://img.shields.io/github/actions/workflow/status/stacksjs/ts-ssh/ci.yml?style=flat-square&branch=main
[github-actions-href]: https://github.com/stacksjs/ts-ssh/actions?query=workflow%3Aci
