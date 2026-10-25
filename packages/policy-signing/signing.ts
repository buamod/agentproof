import { createHash, generateKeyPairSync, sign, verify, type KeyObject } from 'node:crypto'

/**
 * Canonical JSON serialization.
 * CRITICAL: Naive JSON.stringify is NOT canonical - key sorting ensures determinism.
 */
function canonicalize(obj: unknown): string {
  if (obj === null) return 'null'
  if (typeof obj === 'boolean') return obj.toString()
  if (typeof obj === 'number') return isNaN(obj) ? 'NaN' : String(obj)
  if (typeof obj === 'string') return JSON.stringify(obj)
  if (Array.isArray(obj)) return '[' + obj.map(canonicalize).join(',') + ']'
  if (typeof obj === 'object') {
    const keys = Object.keys(obj).sort()
    const pairs = keys.map(k => `"${k}":${canonicalize(obj[k as keyof typeof obj])}`)
    return '{' + pairs.join(',') + '}'
  }
  return String(obj)
}

/** Policy digest - SHA-256 hash of canonical representation. */
export interface PolicyDigest {
  algorithm: 'SHA-256'
  digest: string
  canonicalForm: string
}

/** Create a policy digest from a policy object. */
export function createDigest(policy: unknown): PolicyDigest {
  const canonical = canonicalize(policy)
  const hash = createHash('SHA-256').update(canonical).digest('hex')
  return { algorithm: 'SHA-256', digest: hash, canonicalForm: canonical }
}

/** Key pair for Ed25519 policy signing. */
export interface SigningKeyPair {
  publicKey: KeyObject
  privateKey: KeyObject
}

/** Generate a new Ed25519 key pair. */
export function generateSigningKeyPair(): SigningKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  return { publicKey, privateKey }
}

/** Sign a policy digest. */
export function signDigest(privateKey: KeyObject, digestHex: string): string {
  const signature = sign(null, Buffer.from(digestHex, 'hex'), privateKey)
  return signature.toString('base64')
}

/** Verify a policy signature. */
export function verifySignature(
  publicKey: KeyObject,
  digestHex: string,
  signatureBase64: string
): boolean {
  try {
    const signature = Buffer.from(signatureBase64, 'base64')
    return verify(null, Buffer.from(digestHex, 'hex'), publicKey, signature)
  } catch {
    return false
  }
}

/** Sign a complete policy and return the signed envelope. */
export function signPolicy(policy: unknown, keyPair: SigningKeyPair): {
  policy: unknown
  digest: PolicyDigest
  signature: string
  keyId: string
  algorithm: 'ed25519'
} {
  const digest = createDigest(policy)
  const signature = signDigest(keyPair.privateKey, digest.digest)
  const keyId = `${digest.digest.substring(0, 16)}-ed25519`
  return { policy, digest, signature, keyId, algorithm: 'ed25519' }
}

/** Verify a signed policy envelope (sign-then-seal). */
export function verifySignedPolicy(
  envelope: {
    policy: unknown
    digest: PolicyDigest
    signature: string
    keyId: string
    algorithm: string
  },
  trustedPublicKeys: Map<string, KeyObject>
) {
  const publicKey = trustedPublicKeys.get(envelope.keyId)
  if (!publicKey) {
    return { valid: false, reason: `Untrusted key ID: ${envelope.keyId}`, digest: envelope.digest }
  }
  
  const sigValid = verifySignature(publicKey, envelope.digest.digest, envelope.signature)
  if (!sigValid) {
    return { valid: false, reason: 'Signature verification failed', digest: envelope.digest }
  }
  
  const recomputedDigest = createDigest(envelope.policy)
  if (recomputedDigest.digest !== envelope.digest.digest) {
    return { valid: false, reason: 'Digest mismatch - possible silent mutation', digest: recomputedDigest }
  }
  
  return { valid: true, reason: undefined, digest: recomputedDigest }
}

/** Demo key pair for testing. */
export const DEMO_KEY_PAIR = (() => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  return { publicKey, privateKey }
})()

/** Demo policy - two identities, two resources, allow/deny rules. */
export const DEMO_POLICY = {
  policyId: 'demo-policy',
  version: 1,
  rules: [
    { subject: 'reader', resource: 'public-document', action: 'read', effect: 'allow' },
    { subject: 'reader', resource: 'confidential-record', action: 'read', effect: 'deny' }
  ],
  metadata: { createdBy: 'demo', createdAt: '2026-10-25' }
}
