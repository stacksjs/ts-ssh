/**
 * Proving you hold a key.
 *
 * The client sends a public key and a signature; the server checks the
 * signature against the key and then decides whether that key is one it knows.
 * Two questions, and keeping them apart matters - a signature that verifies
 * says only "whoever sent this holds that private key", and says nothing at all
 * about whether that person may log in.
 *
 * What is signed (RFC 4252 §7):
 *
 *     string    session identifier
 *     byte      SSH_MSG_USERAUTH_REQUEST
 *     string    user name
 *     string    service name
 *     string    "publickey"
 *     boolean   TRUE
 *     string    public key algorithm name
 *     string    public key blob
 *
 * The session identifier is the first field and is the whole reason this is
 * safe: it is the exchange hash of *this* connection, so a signature captured
 * from one session cannot be replayed into another. Everything else in the list
 * binds the signature to the specific request - a signature for user `ada`
 * cannot be replayed as user `root`, and one for `ssh-connection` cannot be
 * used against a different service.
 *
 * Leave the session identifier out and every one of those bindings still looks
 * present while the replay protection is gone.
 */

import { verify as verifySignature } from 'node:crypto'
import { ProtocolError, Reader, Writer } from './buffer'
import { ed25519KeyObject, parsePublicKey } from './keys'

export interface UserAuthRequest {
  user: string
  service: string
  method: string
  /** publickey only: whether a signature is attached, or this is just a probe. */
  hasSignature?: boolean
  /** The algorithm the client named, which may differ from the blob's own type. */
  algorithm?: string
  publicKey?: Uint8Array
  signature?: Uint8Array
}

/** Read a USERAUTH_REQUEST payload, message byte included. */
export function readUserAuthRequest(payload: Uint8Array): UserAuthRequest {
  const reader = new Reader(payload)
  const message = reader.byte()

  if (message !== 50)
    throw new ProtocolError(`Expected USERAUTH_REQUEST and got message ${message}`)

  const user = reader.text()
  const service = reader.text()
  const method = reader.text()

  if (method !== 'publickey')
    return { user, service, method }

  const hasSignature = reader.boolean()
  const algorithm = reader.text()
  const publicKey = reader.string()
  const signature = hasSignature ? reader.string() : undefined

  return { user, service, method, hasSignature, algorithm, publicKey, signature }
}

/**
 * The bytes a client signs.
 *
 * Exported so a test can look at them, and so a client implementation can build
 * the same thing. Both sides constructing this identically is the entire
 * agreement.
 */
export function signedData(input: {
  sessionId: Uint8Array
  user: string
  service: string
  algorithm: string
  publicKey: Uint8Array
}): Uint8Array {
  return new Writer()
    .string(input.sessionId)
    .byte(50)
    .string(input.user)
    .string(input.service)
    .string('publickey')
    .boolean(true)
    .string(input.algorithm)
    .string(input.publicKey)
    .done()
}

/**
 * Unwrap a signature blob.
 *
 * A signature is not raw bytes on the wire - it is `string algorithm` then
 * `string signature`, so the verifier learns which algorithm was actually used
 * rather than assuming.
 */
export function parseSignature(blob: Uint8Array): { algorithm: string, signature: Uint8Array } | null {
  try {
    const reader = new Reader(blob)
    const algorithm = reader.text()
    const signature = reader.string()

    if (reader.remaining !== 0)
      return null

    return { algorithm, signature }
  }
  catch {
    return null
  }
}

export interface VerifyResult {
  ok: boolean
  /** Why not, for a log. Never sent to the client: it would be an oracle. */
  reason?: string
}

/**
 * Check that a signature was made by the key it claims.
 *
 * Only ed25519 is verified here. That is a deliberate floor rather than an
 * omission: it is the default OpenSSH generates, it has no parameters to get
 * wrong, and the alternative is shipping an RSA verifier whose padding checks
 * have to be right the first time. A server may still *store* an RSA key - see
 * `parsePublicKey` - it simply will not be told a signature over one is good.
 */
export function verifyUserAuthSignature(input: {
  sessionId: Uint8Array
  request: UserAuthRequest
}): VerifyResult {
  const { request } = input

  if (request.method !== 'publickey')
    return { ok: false, reason: 'Not a publickey request' }

  if (!request.hasSignature || !request.signature || !request.publicKey || !request.algorithm)
    return { ok: false, reason: 'No signature attached' }

  const key = parsePublicKey(request.publicKey)
  if (!key)
    return { ok: false, reason: 'The public key blob could not be read' }

  // The algorithm is stated three times - in the request, in the blob, and in
  // the signature - and all three have to agree. They are read by different
  // code in most implementations, which is how a mismatch survives.
  if (request.algorithm !== key.type)
    return { ok: false, reason: 'The named algorithm and the key blob disagree' }

  const parsed = parseSignature(request.signature)
  if (!parsed)
    return { ok: false, reason: 'The signature blob could not be read' }

  if (parsed.algorithm !== request.algorithm)
    return { ok: false, reason: 'The signature names a different algorithm than the key' }

  if (key.type !== 'ssh-ed25519' || !key.publicKey)
    return { ok: false, reason: `Signatures over ${key.type} are not verified by this library` }

  if (parsed.signature.length !== 64)
    return { ok: false, reason: 'An ed25519 signature is 64 bytes' }

  const data = signedData({
    sessionId: input.sessionId,
    user: request.user,
    service: request.service,
    algorithm: request.algorithm,
    publicKey: request.publicKey,
  })

  try {
    const ok = verifySignature(null, data, ed25519KeyObject(key.publicKey), parsed.signature)

    return ok ? { ok: true } : { ok: false, reason: 'The signature does not check out' }
  }
  catch (error) {
    return { ok: false, reason: `The signature could not be checked: ${error}` }
  }
}

/** A USERAUTH_FAILURE, naming what a client could try instead. */
export function writeUserAuthFailure(methods: readonly string[], partialSuccess = false): Uint8Array {
  return new Writer().byte(51).nameList(methods).boolean(partialSuccess).done()
}

/** A USERAUTH_SUCCESS. No fields: arriving at all is the message. */
export function writeUserAuthSuccess(): Uint8Array {
  return new Writer().byte(52).done()
}

/**
 * A PK_OK, answering a probe.
 *
 * A client with several keys asks about each before signing with any, so it
 * does not make the user touch a hardware key once per candidate. The answer
 * says only "that key would be acceptable" - it authenticates nobody, and a
 * server must not treat having sent one as having let anybody in.
 */
export function writeUserAuthPkOk(algorithm: string, publicKey: Uint8Array): Uint8Array {
  return new Writer().byte(60).string(algorithm).string(publicKey).done()
}
