/**
 * The SSH protocol, in TypeScript.
 *
 * Built from the bottom: the data types everything is written in, the packet
 * that carries them, the cipher that encrypts it, the negotiation and exchange
 * that agree a secret, the key formats people paste into a file, and the proof
 * that somebody holds one.
 *
 * Every layer is separable and every layer is pure where it can be, because
 * these are the rules that decide who is let into a machine and they should be
 * checkable without a socket.
 */

export * from './auth'
export * from './buffer'
export * from './cipher'
export * from './kex'
export * from './keys'
export * from './packet'
export * from './transport'
export * from './types'
