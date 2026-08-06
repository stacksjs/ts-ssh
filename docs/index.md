---
layout: home

hero:
  name: "ts-ssh"
  text: "The SSH protocol, in TypeScript"
  tagline: "The rules that decide who is let into a machine, readable and checkable without a socket."
  actions:
    - theme: brand
      text: Get Started
      link: /intro
    - theme: alt
      text: View on GitHub
      link: https://github.com/stacksjs/ts-ssh

features:
  - title: "Public keys"
    icon: "🔑"
    details: "authorized_keys lines, wire blobs and fingerprints - checked against what ssh-keygen itself prints."
  - title: "The wire format"
    icon: "🧱"
    details: "Every type in RFC 4251, bounds-checked, because a Reader parses bytes an unauthenticated peer chose."
  - title: "Key exchange"
    icon: "🤝"
    details: "Negotiation the client's way round, the exchange hash, and the six derived keys."
  - title: "Proof of a key"
    icon: "✍️"
    details: "The signed blob of RFC 4252, bound to the session so a captured signature cannot be replayed."
---
