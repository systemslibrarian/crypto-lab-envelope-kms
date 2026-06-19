import { aesKwUnwrap, aesKwWrap } from '../crypto/aes-kw';
import { aeadOpen, aeadSeal } from '../crypto/aead';
import { decoder, encoder } from '../crypto/bytes';
import { KekStore } from '../kms/kek-store';

/**
 * Live, self-contained cryptographic experiments. Each one *attempts* to defeat
 * a security property the rest of the lab relies on, then reports whether the
 * property held. The point is pedagogical: a learner clicks "Run", watches the
 * real primitives (RFC 3394 key wrap, AES-256-GCM) refuse the attack, and reads
 * why it matters.
 *
 * These deliberately use the crypto primitives directly with their own fresh
 * keys rather than the shared KMS singletons — so they are idempotent (run them
 * a hundred times without polluting the global KEK store or audit log) and
 * unit-testable in isolation.
 */
export type PropertyResult = {
  id: string;
  title: string;
  /** The guarantee being put to the test. */
  claim: string;
  /** Plain-language description of the attack we attempted. */
  experiment: string;
  /** Did the security property hold? `true` = the system behaved correctly. */
  held: boolean;
  /** The concrete observed outcome — usually the rejection message. */
  observed: string;
  /** Why this guarantee matters in a real KMS deployment. */
  lesson: string;
};

function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * AAD cryptographically binds an envelope to its context. An envelope sealed for
 * one tenant cannot be opened while claiming a different context — the GCM
 * authentication tag covers the AAD.
 */
async function aadBinding(): Promise<PropertyResult> {
  const id = 'aad-binding';
  const title = 'AAD binds the envelope to its context';
  const claim = 'An envelope sealed for tenant=acme cannot be opened as tenant=evil.';
  const experiment =
    'Seal under AAD "tenant=acme", then attempt to open it claiming AAD "tenant=evil".';
  const lesson =
    'Additional Authenticated Data is covered by the GCM tag but never encrypted. ' +
    'It lets you bind metadata (tenant, key id, purpose) to ciphertext, so a stolen ' +
    'envelope cannot be replayed into a different security context.';

  const dek = randomBytes(32);
  const sealed = await aeadSeal(
    encoder.encode('transfer $100 to acme'),
    dek,
    encoder.encode('tenant=acme'),
  );
  try {
    await aeadOpen(sealed.ciphertext, sealed.iv, sealed.tag, dek, encoder.encode('tenant=evil'));
    return {
      id,
      title,
      claim,
      experiment,
      held: false,
      observed: 'Opened with the wrong AAD — context binding FAILED.',
      lesson,
    };
  } catch (error) {
    return {
      id,
      title,
      claim,
      experiment,
      held: true,
      observed: `Rejected: ${errorMessage(error)}`,
      lesson,
    };
  }
}

/**
 * AES-256-GCM is authenticated encryption: a single flipped ciphertext bit makes
 * the tag check fail and decryption throw, rather than returning garbage.
 */
async function ciphertextTamperEvidence(): Promise<PropertyResult> {
  const id = 'ciphertext-tamper';
  const title = 'Ciphertext is tamper-evident';
  const claim = 'Flipping a single bit of ciphertext makes decryption fail loudly.';
  const experiment = 'Seal a message, flip one byte of the ciphertext, then try to open it.';
  const lesson =
    'AEAD gives integrity, not just confidentiality. A bit-flipping attacker cannot ' +
    'silently corrupt or forge data — the 128-bit GCM tag rejects any modification, ' +
    'so applications never decrypt attacker-controlled plaintext.';

  const dek = randomBytes(32);
  const aad = encoder.encode('ctx=demo');
  const sealed = await aeadSeal(encoder.encode('balance: 42'), dek, aad);
  const tampered = sealed.ciphertext.slice();
  tampered[0] ^= 0x01;
  try {
    await aeadOpen(tampered, sealed.iv, sealed.tag, dek, aad);
    return {
      id,
      title,
      claim,
      experiment,
      held: false,
      observed: 'Tampered ciphertext decrypted — integrity FAILED.',
      lesson,
    };
  } catch (error) {
    return {
      id,
      title,
      claim,
      experiment,
      held: true,
      observed: `Rejected: ${errorMessage(error)}`,
      lesson,
    };
  }
}

/**
 * Tenant isolation is enforced by the math, not by an access-control list. A DEK
 * wrapped under one tenant's KEK cannot be unwrapped with another tenant's KEK —
 * RFC 3394's integrity check fails.
 */
function tenantIsolation(): PropertyResult {
  const id = 'tenant-isolation';
  const title = 'Tenant isolation is cryptographic';
  const claim = "A DEK wrapped under tenant A's KEK cannot be unwrapped with tenant B's KEK.";
  const experiment = 'Wrap a DEK under KEK A, then attempt to unwrap it with a different KEK B.';
  const lesson =
    'The KEK hierarchy enforces multi-tenant isolation cryptographically. Even if ' +
    'tenant B obtains the wrapped DEK, the RFC 3394 integrity check fails on unwrap — ' +
    'isolation does not depend solely on a correct IAM policy.';

  const kekA = randomBytes(32);
  const kekB = randomBytes(32);
  const dek = randomBytes(32);
  const wrapped = aesKwWrap(kekA, dek);
  try {
    aesKwUnwrap(kekB, wrapped);
    return {
      id,
      title,
      claim,
      experiment,
      held: false,
      observed: 'Unwrapped with the wrong KEK — isolation FAILED.',
      lesson,
    };
  } catch (error) {
    return {
      id,
      title,
      claim,
      experiment,
      held: true,
      observed: `Rejected: ${errorMessage(error)}`,
      lesson,
    };
  }
}

/**
 * RFC 3394 key wrap is authenticated: a corrupted wrapped DEK fails its integrity
 * check rather than unwrapping to a wrong-but-plausible key.
 */
function wrappedDekIntegrity(): PropertyResult {
  const id = 'wrap-integrity';
  const title = 'Wrapped DEKs are authenticated';
  const claim = 'A corrupted wrapped DEK is rejected, not silently unwrapped to garbage.';
  const experiment = 'Wrap a DEK, flip one byte of the wrapped output, then try to unwrap it.';
  const lesson =
    'AES Key Wrap carries a built-in integrity check (the fixed 0xA6A6… IV). A flipped ' +
    'byte in stored key material is caught on unwrap, so you never decrypt data with a ' +
    'silently corrupted key.';

  const kek = randomBytes(32);
  const dek = randomBytes(32);
  const wrapped = aesKwWrap(kek, dek);
  const tampered = wrapped.slice();
  tampered[tampered.length - 1] ^= 0x01;
  try {
    aesKwUnwrap(kek, tampered);
    return {
      id,
      title,
      claim,
      experiment,
      held: false,
      observed: 'Corrupted wrap unwrapped — integrity FAILED.',
      lesson,
    };
  } catch (error) {
    return {
      id,
      title,
      claim,
      experiment,
      held: true,
      observed: `Rejected: ${errorMessage(error)}`,
      lesson,
    };
  }
}

/**
 * Rotation re-protects future writes under a new KEK version while leaving old
 * envelopes readable under the previous (now decrypt-only) version — with zero
 * re-encryption of bulk data. This is the operational reason envelope encryption
 * exists.
 */
async function rotationPreservesAccess(): Promise<PropertyResult> {
  const id = 'rotation-access';
  const title = 'Rotation preserves access without re-encrypting data';
  const claim =
    'After rotating a KEK, old envelopes still open and new writes use the new version.';
  const experiment =
    'Seal under v1, rotate the KEK to v2, then re-open the v1 envelope and check where new writes land.';
  const lesson =
    'Rotating a KEK only re-wraps tiny data keys, never the bulk ciphertext. Old objects ' +
    'stay readable under the previous (decrypt-only) version, while every new object is ' +
    'protected by the active version — so one rotation re-protects millions of objects ' +
    'without touching their ciphertext.';

  const store = new KekStore();
  const { keyId } = store.createKey();
  const aad = encoder.encode('ctx=rotation');
  const message = 'sealed under v1';

  // Seal under v1.
  const v1 = store.getMaterialForWrap(keyId);
  const dek = randomBytes(32);
  const wrappedV1 = aesKwWrap(v1.material, dek);
  const sealed = await aeadSeal(encoder.encode(message), dek, aad);

  // Rotate: v1 becomes decrypt-only, v2 becomes active.
  store.rotateKey(keyId);
  const activeAfter = store.getMaterialForWrap(keyId).version;

  // The v1 envelope still opens under its (now decrypt-only) version.
  const v1Material = store.getMaterialForUnwrap(keyId, v1.version);
  const recoveredDek = aesKwUnwrap(v1Material, wrappedV1);
  const opened = decoder.decode(
    await aeadOpen(sealed.ciphertext, sealed.iv, sealed.tag, recoveredDek, aad),
  );

  const stillReadable = opened === message;
  const newWritesRotated = activeAfter === v1.version + 1;
  const held = stillReadable && newWritesRotated;
  const observed = held
    ? `v${v1.version} envelope still opens; new writes now use v${activeAfter} — no bulk re-encryption.`
    : `Unexpected: stillReadable=${stillReadable}, activeVersion=v${activeAfter}.`;
  return { id, title, claim, experiment, held, observed, lesson };
}

/** Static descriptions, so the UI can render cards before any experiment runs. */
export type PropertyMeta = {
  id: PropertyId;
  title: string;
  claim: string;
  experiment: string;
  tone: string;
};

export const PROPERTY_CATALOG: PropertyMeta[] = [
  {
    id: 'aad-binding',
    title: 'AAD binds the envelope to its context',
    claim: 'An envelope sealed for tenant=acme cannot be opened as tenant=evil.',
    experiment: 'Seal under AAD "tenant=acme", then open it claiming "tenant=evil".',
    tone: 'teal',
  },
  {
    id: 'ciphertext-tamper',
    title: 'Ciphertext is tamper-evident',
    claim: 'Flipping a single bit of ciphertext makes decryption fail loudly.',
    experiment: 'Seal a message, flip one byte of ciphertext, then try to open it.',
    tone: 'crimson',
  },
  {
    id: 'tenant-isolation',
    title: 'Tenant isolation is cryptographic',
    claim: "A DEK wrapped under tenant A's KEK cannot be unwrapped with tenant B's.",
    experiment: 'Wrap a DEK under KEK A, then attempt to unwrap it with a different KEK B.',
    tone: 'amber',
  },
  {
    id: 'wrap-integrity',
    title: 'Wrapped DEKs are authenticated',
    claim: 'A corrupted wrapped DEK is rejected, not silently unwrapped to garbage.',
    experiment: 'Wrap a DEK, flip one byte of the wrapped output, then try to unwrap it.',
    tone: 'crimson',
  },
  {
    id: 'rotation-access',
    title: 'Rotation preserves access without re-encrypting data',
    claim: 'After rotating a KEK, old envelopes still open and new writes use the new version.',
    experiment: 'Seal under v1, rotate to v2, re-open the v1 envelope and check new writes.',
    tone: 'violet',
  },
];

export const PROPERTY_IDS = [
  'aad-binding',
  'ciphertext-tamper',
  'tenant-isolation',
  'wrap-integrity',
  'rotation-access',
] as const;

export type PropertyId = (typeof PROPERTY_IDS)[number];

/** Run a single experiment by id. */
export async function runProperty(id: PropertyId): Promise<PropertyResult> {
  switch (id) {
    case 'aad-binding':
      return aadBinding();
    case 'ciphertext-tamper':
      return ciphertextTamperEvidence();
    case 'tenant-isolation':
      return tenantIsolation();
    case 'wrap-integrity':
      return wrappedDekIntegrity();
    case 'rotation-access':
      return rotationPreservesAccess();
    default:
      throw new Error(`Unknown property: ${id as string}`);
  }
}

/** Run every experiment, in display order. */
export async function runAllProperties(): Promise<PropertyResult[]> {
  return Promise.all(PROPERTY_IDS.map((id) => runProperty(id)));
}
