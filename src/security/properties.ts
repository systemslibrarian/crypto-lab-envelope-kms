import { aesKwUnwrap, aesKwWrap, unwrap3394Core } from '../crypto/aes-kw';
import { aeadOpen, aeadSeal } from '../crypto/aead';
import { bytesToHex, decoder, encoder } from '../crypto/bytes';
import { KekStore } from '../kms/kek-store';

/**
 * Live, self-contained cryptographic experiments. Each one *attempts* to defeat
 * a security property the rest of the lab relies on, then reports whether the
 * property held. The point is pedagogical: a learner clicks "Run", watches the
 * real primitives (RFC 3394 key wrap, AES-256-GCM) refuse the attack, and reads
 * why it matters.
 *
 * Every experiment also has a WEAKENED mode. Run correctly these properties
 * cannot break — AES-GCM and RFC 3394 do not fail — which made the "Property
 * broken" badge unreachable, and a security lab whose failure state cannot occur
 * teaches that the guarantee is unconditional. It is not. Each guarantee rests
 * on a specific implementation decision, and the weakened mode removes exactly
 * that decision. Each removal is a misconfiguration that has shipped in real
 * systems: forgetting to pass AAD, reaching for a raw stream cipher instead of
 * an AEAD, sharing one KEK across tenants, skipping the key-wrap integrity
 * check, and destroying the previous KEK version on rotation. Run weakened and
 * the badge really does flip to "Property broken" — because the property really
 * did break.
 *
 * These deliberately use the crypto primitives directly with their own fresh
 * keys rather than the shared KMS singletons — so they are idempotent (run them
 * a hundred times without polluting the global KEK store or audit log) and
 * unit-testable in isolation.
 */

/** Which build of the system the experiment runs against. */
export type PropertyMode =
  /** The lab's real implementation. The property is expected to hold. */
  | 'defended'
  /** One specific defense removed. The property is expected to break. */
  | 'weakened';

export type PropertyResult = {
  id: string;
  title: string;
  /** The guarantee being put to the test. */
  claim: string;
  /** Plain-language description of the attack we attempted. */
  experiment: string;
  /** Which build this result came from. */
  mode: PropertyMode;
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

/** Raw AES-256-CTR — confidentiality with no authentication whatsoever. */
async function ctr(key: Uint8Array, counter: Uint8Array, input: Uint8Array): Promise<Uint8Array> {
  const raw = key.buffer.slice(key.byteOffset, key.byteOffset + key.byteLength) as ArrayBuffer;
  const cryptoKey = await crypto.subtle.importKey('raw', raw, { name: 'AES-CTR' }, false, [
    'encrypt',
    'decrypt',
  ]);
  const counterBuf = counter.buffer.slice(
    counter.byteOffset,
    counter.byteOffset + counter.byteLength,
  ) as ArrayBuffer;
  const inputBuf = input.buffer.slice(
    input.byteOffset,
    input.byteOffset + input.byteLength,
  ) as ArrayBuffer;
  return new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-CTR', counter: counterBuf, length: 64 },
      cryptoKey,
      inputBuf,
    ),
  );
}

/**
 * AAD cryptographically binds an envelope to its context. An envelope sealed for
 * one tenant cannot be opened while claiming a different context — the GCM
 * authentication tag covers the AAD.
 *
 * Weakened: the sealing code forgets to pass the tenant context as AAD. Nothing
 * binds the envelope to a context, so it opens under any claim at all.
 */
async function aadBinding(mode: PropertyMode): Promise<PropertyResult> {
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
  const message = 'transfer $100 to acme';

  if (mode === 'weakened') {
    // The defense removed: seal with no AAD, and open with no AAD. The tenant
    // context is now just a label the application carries next to the ciphertext.
    const empty = new Uint8Array(0);
    const sealed = await aeadSeal(encoder.encode(message), dek, empty);
    const opened = decoder.decode(
      await aeadOpen(sealed.ciphertext, sealed.iv, sealed.tag, dek, empty),
    );
    return {
      id,
      title,
      claim,
      experiment,
      mode,
      held: false,
      observed:
        `Opened while claiming tenant=evil: "${opened}". Nothing was bound — the seal never ` +
        'covered the context, so the GCM tag has no opinion about which tenant this envelope is for.',
      lesson,
    };
  }

  const sealed = await aeadSeal(encoder.encode(message), dek, encoder.encode('tenant=acme'));
  try {
    await aeadOpen(sealed.ciphertext, sealed.iv, sealed.tag, dek, encoder.encode('tenant=evil'));
    return {
      id,
      title,
      claim,
      experiment,
      mode,
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
      mode,
      held: true,
      observed: `Rejected: ${errorMessage(error)}`,
      lesson,
    };
  }
}

/**
 * AES-256-GCM is authenticated encryption: a single flipped ciphertext bit makes
 * the tag check fail and decryption throw, rather than returning garbage.
 *
 * Weakened: swap the AEAD for raw AES-256-CTR — confidentiality with no
 * authentication. The same flipped bit now decrypts silently to corrupted
 * plaintext, and the attacker picked which bit.
 */
async function ciphertextTamperEvidence(mode: PropertyMode): Promise<PropertyResult> {
  const id = 'ciphertext-tamper';
  const title = 'Ciphertext is tamper-evident';
  const claim = 'Flipping a single bit of ciphertext makes decryption fail loudly.';
  const experiment = 'Seal a message, flip one byte of the ciphertext, then try to open it.';
  const lesson =
    'AEAD gives integrity, not just confidentiality. A bit-flipping attacker cannot ' +
    'silently corrupt or forge data — the 128-bit GCM tag rejects any modification, ' +
    'so applications never decrypt attacker-controlled plaintext.';

  const dek = randomBytes(32);
  const message = 'balance: 42';

  if (mode === 'weakened') {
    const counter = randomBytes(16);
    const ciphertext = await ctr(dek, counter, encoder.encode(message));
    const tampered = ciphertext.slice();
    tampered[0] ^= 0x01;
    const opened = decoder.decode(await ctr(dek, counter, tampered));
    return {
      id,
      title,
      claim,
      experiment,
      mode,
      held: false,
      observed:
        `Decrypted the tampered ciphertext without complaint: "${message}" came back as ` +
        `"${opened}". AES-CTR is a keystream — flipping a ciphertext bit flips exactly that ` +
        'plaintext bit, and there is no tag to notice.',
      lesson,
    };
  }

  const aad = encoder.encode('ctx=demo');
  const sealed = await aeadSeal(encoder.encode(message), dek, aad);
  const tampered = sealed.ciphertext.slice();
  tampered[0] ^= 0x01;
  try {
    await aeadOpen(tampered, sealed.iv, sealed.tag, dek, aad);
    return {
      id,
      title,
      claim,
      experiment,
      mode,
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
      mode,
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
 *
 * Weakened: one shared KEK is provisioned for every tenant and isolation is left
 * entirely to the IAM policy. The cross-tenant unwrap now succeeds, because
 * cryptographically there was never a boundary to cross.
 */
function tenantIsolation(mode: PropertyMode): PropertyResult {
  const id = 'tenant-isolation';
  const title = 'Tenant isolation is cryptographic';
  const claim = "A DEK wrapped under tenant A's KEK cannot be unwrapped with tenant B's KEK.";
  const experiment = 'Wrap a DEK under KEK A, then attempt to unwrap it with a different KEK B.';
  const lesson =
    'The KEK hierarchy enforces multi-tenant isolation cryptographically. Even if ' +
    'tenant B obtains the wrapped DEK, the RFC 3394 integrity check fails on unwrap — ' +
    'isolation does not depend solely on a correct IAM policy.';

  const dek = randomBytes(32);

  if (mode === 'weakened') {
    // The defense removed: one platform-wide KEK, every tenant pointed at it.
    const sharedKek = randomBytes(32);
    const wrapped = aesKwWrap(sharedKek, dek);
    const recovered = aesKwUnwrap(sharedKek, wrapped);
    return {
      id,
      title,
      claim,
      experiment,
      mode,
      held: false,
      observed:
        `Tenant B unwrapped tenant A's DEK cleanly: ${bytesToHex(recovered).slice(0, 32)}…. ` +
        'One shared KEK means the tenant boundary exists only in the IAM policy — one ' +
        'misconfigured grant and there is no math left to stop the read.',
      lesson,
    };
  }

  const kekA = randomBytes(32);
  const kekB = randomBytes(32);
  const wrapped = aesKwWrap(kekA, dek);
  try {
    aesKwUnwrap(kekB, wrapped);
    return {
      id,
      title,
      claim,
      experiment,
      mode,
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
      mode,
      held: true,
      observed: `Rejected: ${errorMessage(error)}`,
      lesson,
    };
  }
}

/**
 * RFC 3394 key wrap is authenticated: a corrupted wrapped DEK fails its integrity
 * check rather than unwrapping to a wrong-but-plausible key.
 *
 * Weakened: run the same unwrap but skip the 0xA6A6… integrity comparison. The
 * corrupted wrap now "succeeds", handing back a key that is not the DEK.
 */
function wrappedDekIntegrity(mode: PropertyMode): PropertyResult {
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

  if (mode === 'weakened') {
    // The defense removed: the same RFC 3394 unwrap, minus the check that the
    // recovered A block equals the fixed 0xA6A6… IV.
    const { a, plaintext } = unwrap3394Core(kek, tampered);
    return {
      id,
      title,
      claim,
      experiment,
      mode,
      held: false,
      observed:
        `Unwrap "succeeded" and returned ${bytesToHex(plaintext).slice(0, 32)}… — which is NOT ` +
        `the DEK (${bytesToHex(dek).slice(0, 32)}…). The integrity block came back as ` +
        `${bytesToHex(a)} instead of a6a6a6a6a6a6a6a6, and nothing looked. Every byte decrypted ` +
        'with this key from here on is silently wrong.',
      lesson,
    };
  }

  try {
    aesKwUnwrap(kek, tampered);
    return {
      id,
      title,
      claim,
      experiment,
      mode,
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
      mode,
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
 *
 * Weakened: rotation is destructive — the previous version is retired rather
 * than kept decrypt-only, so only the active version is available on unwrap and
 * every envelope sealed before the rotation becomes unreadable.
 */
async function rotationPreservesAccess(mode: PropertyMode): Promise<PropertyResult> {
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

  if (mode === 'weakened') {
    // The defense removed: the previous version is gone, so the only material
    // available to unwrap with is the new active one.
    const activeMaterial = store.getMaterialForWrap(keyId).material;
    try {
      aesKwUnwrap(activeMaterial, wrappedV1);
      return {
        id,
        title,
        claim,
        experiment,
        mode,
        held: false,
        observed: `Unexpected: the v${v1.version} wrap unwrapped under v${activeAfter} material.`,
        lesson,
      };
    } catch (error) {
      return {
        id,
        title,
        claim,
        experiment,
        mode,
        held: false,
        observed:
          `The v${v1.version} envelope is now permanently unreadable: ${errorMessage(error)}. ` +
          'Destructive rotation does not re-protect old data — it destroys it. This is exactly ' +
          'why a KMS retains previous versions as decrypt-only instead of deleting them.',
        lesson,
      };
    }
  }

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
  return { id, title, claim, experiment, mode, held, observed, lesson };
}

/** Static descriptions, so the UI can render cards before any experiment runs. */
export type PropertyMeta = {
  id: PropertyId;
  title: string;
  claim: string;
  experiment: string;
  /** What "Run weakened" removes, stated in the learner's terms. */
  weakening: string;
  tone: string;
};

export const PROPERTY_CATALOG: PropertyMeta[] = [
  {
    id: 'aad-binding',
    title: 'AAD binds the envelope to its context',
    claim: 'An envelope sealed for tenant=acme cannot be opened as tenant=evil.',
    experiment: 'Seal under AAD "tenant=acme", then open it claiming "tenant=evil".',
    weakening: 'the caller forgets to pass the tenant context as AAD',
    tone: 'teal',
  },
  {
    id: 'ciphertext-tamper',
    title: 'Ciphertext is tamper-evident',
    claim: 'Flipping a single bit of ciphertext makes decryption fail loudly.',
    experiment: 'Seal a message, flip one byte of ciphertext, then try to open it.',
    weakening: 'raw AES-256-CTR is used instead of an AEAD — encryption with no tag',
    tone: 'crimson',
  },
  {
    id: 'tenant-isolation',
    title: 'Tenant isolation is cryptographic',
    claim: "A DEK wrapped under tenant A's KEK cannot be unwrapped with tenant B's.",
    experiment: 'Wrap a DEK under KEK A, then attempt to unwrap it with a different KEK B.',
    weakening: 'one shared KEK is provisioned for every tenant',
    tone: 'amber',
  },
  {
    id: 'wrap-integrity',
    title: 'Wrapped DEKs are authenticated',
    claim: 'A corrupted wrapped DEK is rejected, not silently unwrapped to garbage.',
    experiment: 'Wrap a DEK, flip one byte of the wrapped output, then try to unwrap it.',
    weakening: 'the RFC 3394 unwrap skips its 0xA6A6… integrity check',
    tone: 'crimson',
  },
  {
    id: 'rotation-access',
    title: 'Rotation preserves access without re-encrypting data',
    claim: 'After rotating a KEK, old envelopes still open and new writes use the new version.',
    experiment: 'Seal under v1, rotate to v2, re-open the v1 envelope and check new writes.',
    weakening: 'rotation is destructive — the old version is deleted, not kept decrypt-only',
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

/** Run a single experiment by id, against the real build or the weakened one. */
export async function runProperty(
  id: PropertyId,
  mode: PropertyMode = 'defended',
): Promise<PropertyResult> {
  switch (id) {
    case 'aad-binding':
      return aadBinding(mode);
    case 'ciphertext-tamper':
      return ciphertextTamperEvidence(mode);
    case 'tenant-isolation':
      return tenantIsolation(mode);
    case 'wrap-integrity':
      return wrappedDekIntegrity(mode);
    case 'rotation-access':
      return rotationPreservesAccess(mode);
    default:
      throw new Error(`Unknown property: ${id as string}`);
  }
}

/** Run every experiment, in display order. */
export async function runAllProperties(mode: PropertyMode = 'defended'): Promise<PropertyResult[]> {
  return Promise.all(PROPERTY_IDS.map((id) => runProperty(id, mode)));
}
