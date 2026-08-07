/**
 * A server on a real socket.
 *
 * `handshake.ts` takes bytes and returns bytes, which is what makes it
 * testable. This is the part that puts it on a TCP port, and it exists because
 * the glue in between is where the bugs are:
 *
 * - **A channel window.** A peer says how much it is prepared to receive and a
 *   sender may not exceed it. Whatever does not fit has to be held and sent
 *   when a `CHANNEL_WINDOW_ADJUST` arrives.
 * - **A socket that is full.** `write` returns how many bytes it took, which is
 *   not always how many it was given. The rest has to be held and sent on
 *   `drain`.
 *
 * Two separate backlogs, and forgetting either produces the same symptom: a
 * transfer that works for a few hundred kilobytes and then fails the peer's
 * MAC, because a truncated stream is indistinguishable from a tampered one.
 * That is not hypothetical - it is what the first version of this package's
 * own test harness did, and the four megabyte transfer test is what caught it.
 *
 * So the shape here is deliberate: nothing above this has to think about
 * either, and `write` never lies about having sent something.
 */

import type { Socket } from 'bun'
import type { Channel } from './channel'
import type { ServerOptions, SessionEvent } from './handshake'
import { ServerSession } from './handshake'

/** One command a client asked to run. */
export interface Command {
  /** Who the client proved it was. */
  user: string
  /** The command line, exactly as sent. Unparsed: it is the client's string. */
  command: string
  /** Stdin, as it arrives. */
  onData: (handler: (data: Uint8Array) => void) => void
  /** The client has finished sending. */
  onEnd: (handler: () => void) => void
  /** Queue output. Sent as the peer's window allows, in order, always. */
  write: (data: Uint8Array | string) => void
  writeStderr: (data: Uint8Array | string) => void
  /**
   * Finish, once everything already queued has gone out.
   *
   * Deferred rather than immediate, because a close that overtakes the output
   * it follows truncates it - and the caller has no way to know when the last
   * byte left.
   */
  exit: (status: number) => void
}

export interface ServeOptions extends Omit<ServerOptions, 'allow'> {
  port?: number
  hostname?: string
  /** Channel requests to accept. `exec` and `env` by default. */
  allow?: readonly string[]
  /** Run a command. Called once per `exec` request. */
  onCommand: (command: Command) => void | Promise<void>
  /**
   * Something went wrong on one connection.
   *
   * A connection-level failure is ordinary - a client that hangs up mid
   * handshake, a peer that sends nonsense - so it is reported rather than
   * thrown, and the server keeps serving.
   */
  onError?: (error: unknown) => void
}

interface Outgoing {
  channel: Channel
  /** Bytes waiting on the peer's window. */
  stdout: Uint8Array
  stderr: Uint8Array
  /** Set once the command has finished; sent when the backlogs are empty. */
  status: number | null
  onData?: (data: Uint8Array) => void
  onEnd?: () => void
}

interface Connection {
  session: ServerSession
  /** Serialises `receive`, which is async and must not interleave. */
  queue: Promise<void>
  /** Bytes the socket has not taken yet. */
  backlog: Uint8Array
  channels: Map<number, Outgoing>
}

export interface Server {
  port: number
  stop: () => void
}

/** Listen, and run a command for every client that asks. */
export function serve(options: ServeOptions): Server {
  const server = Bun.listen<Connection>({
    hostname: options.hostname ?? '127.0.0.1',
    port: options.port ?? 0,

    socket: {
      open(socket) {
        const session = new ServerSession({
          hostKey: options.hostKey,
          software: options.software,
          banner: options.banner,
          allow: options.allow,
          random: options.random,
          authenticate: options.authenticate,
        })

        socket.data = { session, queue: Promise.resolve(), backlog: new Uint8Array(0), channels: new Map() }
        enqueue(socket, session.start())
      },

      data(socket, chunk) {
        const connection = socket.data

        connection.queue = connection.queue.then(async () => {
          try {
            const outcome = await connection.session.receive(new Uint8Array(chunk))
            enqueue(socket, outcome.send)

            for (const event of outcome.events)
              await react(socket, event, options)

            flush(socket)

            if (outcome.closed)
              socket.end()
          }
          catch (error) {
            options.onError?.(error)
            socket.end()
          }
        })
      },

      // The socket has room again. Both backlogs are tried, in that order: the
      // socket's first, because a channel flush that ran first would only make
      // the socket backlog longer.
      drain(socket) {
        pump(socket)
        flush(socket)
      },

      error(socket, error) {
        options.onError?.(error)
        socket.end()
      },
    },
  })

  return { port: server.port, stop: () => server.stop(true) }
}

type ServerSocket = Socket<Connection>

async function react(socket: ServerSocket, event: SessionEvent, options: ServeOptions): Promise<void> {
  const connection = socket.data

  switch (event.type) {
    case 'exec': {
      const outgoing: Outgoing = { channel: event.channel, stdout: new Uint8Array(0), stderr: new Uint8Array(0), status: null }
      connection.channels.set(event.channel.localId, outgoing)

      const command: Command = {
        user: connection.session.user ?? '',
        command: event.command,
        onData: handler => void (outgoing.onData = handler),
        onEnd: handler => void (outgoing.onEnd = handler),
        write: (data) => {
          outgoing.stdout = concat(outgoing.stdout, asBytes(data))
          flush(socket)
        },
        writeStderr: (data) => {
          outgoing.stderr = concat(outgoing.stderr, asBytes(data))
          flush(socket)
        },
        exit: (status) => {
          outgoing.status = status
          flush(socket)
        },
      }

      // Awaited, so a handler that throws is reported rather than becoming an
      // unhandled rejection. A handler that runs a process returns as soon as
      // it has wired it up; the output arrives later through `write`.
      try {
        await options.onCommand(command)
      }
      catch (error) {
        options.onError?.(error)
        outgoing.status = 1
        flush(socket)
      }

      return
    }

    case 'data': {
      connection.channels.get(event.channel.localId)?.onData?.(event.data)

      return
    }

    case 'eof': {
      connection.channels.get(event.channel.localId)?.onEnd?.()

      return
    }

    case 'close': {
      connection.channels.delete(event.channel.localId)

      return
    }

    default:
  }
}

/**
 * Move whatever can move: channel backlogs into the socket, then out.
 *
 * Called after every receive, after every drain, and after every write from a
 * handler, because any of the three can be the thing that made room. Cheap
 * when there is nothing to do.
 */
function flush(socket: ServerSocket): void {
  const connection = socket.data

  for (const [id, outgoing] of connection.channels) {
    if (outgoing.stderr.length > 0) {
      const { bytes, remaining } = connection.session.writeStderr(outgoing.channel, outgoing.stderr)
      outgoing.stderr = remaining
      enqueue(socket, bytes, false)
    }

    if (outgoing.stdout.length > 0) {
      const { bytes, remaining } = connection.session.write(outgoing.channel, outgoing.stdout)
      outgoing.stdout = remaining
      enqueue(socket, bytes, false)
    }

    // The exit status waits for both backlogs, or it truncates the output it is
    // supposed to be reporting on.
    if (outgoing.status !== null && outgoing.stdout.length === 0 && outgoing.stderr.length === 0) {
      enqueue(socket, connection.session.exit(outgoing.channel, outgoing.status), false)
      connection.channels.delete(id)
    }
  }

  pump(socket)
}

/** Add bytes to the socket backlog, and optionally try to send them now. */
function enqueue(socket: ServerSocket, bytes: Uint8Array, send = true): void {
  if (bytes.length === 0)
    return

  socket.data.backlog = concat(socket.data.backlog, bytes)

  if (send)
    pump(socket)
}

/**
 * Write as much of the backlog as the socket will take.
 *
 * `write` returning less than it was given is the normal way a socket says it
 * is full; what is left waits for `drain`. Treating the return value as "all of
 * it" is the bug this function exists to not have.
 */
function pump(socket: ServerSocket): void {
  const connection = socket.data

  while (connection.backlog.length > 0) {
    const pending = connection.backlog
    const written = socket.write(pending)

    if (written <= 0)
      return

    connection.backlog = pending.subarray(written)

    // Took some but not all: the socket is full and the rest waits for `drain`.
    if (written < pending.length)
      return
  }
}

function asBytes(data: Uint8Array | string): Uint8Array {
  return typeof data === 'string' ? new TextEncoder().encode(data) : data
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length === 0)
    return b
  if (b.length === 0)
    return a

  const out = new Uint8Array(a.length + b.length)
  out.set(a)
  out.set(b, a.length)

  return out
}
