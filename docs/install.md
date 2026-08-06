# Installation

```bash
bun add ts-ssh
```

```bash
npm install ts-ssh
```

## The CLI

`authorized_keys` is a file people edit by hand and get wrong, so a tool that
says exactly what a line parses to is worth having:

```bash
bunx ts-ssh keys ~/.ssh/authorized_keys
```

```
256 SHA256:5Qkb22VFaD0j2Vaz5R/mbgWhflDenDvHhXe+nNKYogA ada@example.com (ssh-ed25519)
2048 SHA256:oCOfrlRoSea1eC3S1rhyIijxw52hCGa8W2wzU2JV+JE grace@example.com (ssh-rsa)
```

A line it cannot read is reported rather than skipped in silence. A key that
will not let somebody in is worth being told about.
