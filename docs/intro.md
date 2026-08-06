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
- **[Key exchange](/usage#key-exchange)** - `negotiateAll`, `exchangeHash`, `deriveKey`
- **[Authentication](/usage#authentication)** - `readUserAuthRequest`, `verifyUserAuthSignature`

## What is not here yet

A half-built SSH server is worse than none, so this is stated plainly: there is
no encrypted transport yet. The ciphers are negotiated but not applied, and the
connection layer - channels, `exec`, window accounting - is not written.

What exists is what a host needs to store keys, recognise them, and check a
proof that somebody holds one. The transport is next.
