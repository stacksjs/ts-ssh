# ts-ssh

The SSH protocol, built from the bottom up.

## Why it is written this way

These are the rules that decide who is let into a machine, and most of them are
pure functions over bytes: a length-prefixed string, a padding calculation, a
list of eight fields hashed in order. They should be readable, and they should
be checkable without opening a socket.

So every layer here is separable, and the tests check against something other
than themselves. The fingerprints are the ones `ssh-keygen -lf` prints for the
same keys. The signatures are made by `node:crypto` over the bytes RFC 4252
specifies. A test suite that only proves a library agrees with itself proves
very little about a protocol.

## The layers

- **[The wire format](/usage#the-wire-format)** - `Reader`, `Writer`
- **[Public keys](/usage#reading-keys)** - `parseAuthorizedKey`, `fingerprintOf`, `sameKey`
- **[Packets](/usage#packets)** - `framePacket`, `paddingFor`, `parseIdentification`
- **[Ciphers](/usage#ciphers)** - `createPacketCipher`, `keyLengthsFor`
- **[Transport](/usage#transport)** - `Transport`
- **[Channels](/usage#channels)** - `Channel`, `readChannelRequest`, `writeExitStatus`
- **[Key exchange](/usage#key-exchange)** - `negotiateAll`, `exchangeHash`, `deriveKey`
- **[Authentication](/usage#authentication)** - `readUserAuthRequest`, `verifyUserAuthSignature`

## What is not here yet

A half-built SSH server is worse than none, so this is stated plainly: nothing
here sequences the handshake against a socket and a host key. Every piece it
needs exists - negotiate, exchange, derive, encrypt, authenticate, open a
channel - but the driver that puts them in order is the remaining step between
this and `ssh host command`.

`chacha20-poly1305@openssh.com` is deliberately absent rather than pending. It
needs raw ChaCha20 and a bare Poly1305 over the ciphertext, neither of which
Bun's crypto exposes, so offering it would mean hand-writing a MAC whose timing
leaks its key if it is not constant time. Every OpenSSH since 6.2 speaks
AES-GCM.
