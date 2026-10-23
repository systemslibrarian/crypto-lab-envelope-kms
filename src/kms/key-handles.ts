import { aeadOpen, aeadSeal } from '../crypto/aead';
import { aesKwUnwrap, aesKwWrap } from '../crypto/aes-kw';
import { encoder, equalBytes, zeroize } from '../crypto/bytes';

export type HandlePolicy = 'fixed-roles' | 'mutable-usages';
export type HandleRole = 'wrapping-key' | 'data-key';
export type ApiPolicyErrorCode =
  | 'UNKNOWN_HANDLE'
  | 'SENSITIVE_VALUE'
  | 'ROLE_LOCKED'
  | 'OPERATION_NOT_PERMITTED'
  | 'KEY_NOT_EXTRACTABLE'
  | 'MECHANISM_MISMATCH'
  | 'INTEGRITY_CHECK_FAILED'
  | 'INVALID_INPUT'
  | 'INVALID_KEY_MATERIAL';

export class ApiPolicyError extends Error {
  constructor(
    public readonly code: ApiPolicyErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'ApiPolicyError';
  }
}

export type KeyDescription = Readonly<{
  handle: string;
  role: HandleRole;
  mechanism: 'AES-KW' | 'AES-GCM';
  sensitive: true;
  extractable: boolean;
  wrap: boolean;
  unwrap: boolean;
  encrypt: boolean;
  decrypt: boolean;
}>;

export type HandleChallenge = {
  iv: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
  aad: Uint8Array;
};

/** Test fixtures only. The browser exhibit must use the internal random factory. */
export type HandleKeyFactory = (role: HandleRole) => Uint8Array;

type KeyRecord = {
  description: KeyDescription;
  material: Uint8Array;
};

const randomKey: HandleKeyFactory = () => crypto.getRandomValues(new Uint8Array(32));

/**
 * A deliberately small API model, not a hardware token or a PKCS #11 emulator.
 *
 * The normal envelope KMS intentionally returns raw DEKs. This separate model
 * instead starts with sensitive handles, so a byte-returning decrypt permission
 * on a wrapping key creates a meaningful composition failure.
 *
 * PKCS #11 v3.0 Current Mechanisms, Table 91 and section 2.16.3, permit AES-KW
 * for wrap/unwrap AND single-part encrypt/decrypt. Both modeled operations use
 * that same real RFC 3394 mechanism; AES-GCM is only the data challenge.
 */
export class HandleToken {
  readonly #policy: HandlePolicy;
  readonly #records = new Map<string, KeyRecord>();
  readonly #wrapperHandle: string;
  readonly #targetHandle: string;

  constructor(
    policy: HandlePolicy = 'fixed-roles',
    targetExtractable = true,
    keyFactory: HandleKeyFactory = randomKey,
  ) {
    if (
      (policy !== 'fixed-roles' && policy !== 'mutable-usages') ||
      typeof targetExtractable !== 'boolean'
    ) {
      throw new ApiPolicyError('INVALID_INPUT', 'Choose a named policy and target extractability.');
    }
    this.#policy = policy;
    const wrapper = this.#fixtureOrRandomKey(keyFactory, 'wrapping-key');
    let target: Uint8Array | undefined;
    try {
      target = this.#fixtureOrRandomKey(keyFactory, 'data-key');
      if (equalBytes(wrapper, target)) {
        throw new ApiPolicyError(
          'INVALID_KEY_MATERIAL',
          'Wrapping and data roles require distinct key material in this model.',
        );
      }
      this.#wrapperHandle = this.#insert(wrapper, 'wrapping-key', false);
      this.#targetHandle = this.#insert(target, 'data-key', targetExtractable);
    } finally {
      zeroize(wrapper);
      if (target) zeroize(target);
    }
  }

  get policy(): HandlePolicy {
    return this.#policy;
  }

  get wrapperHandle(): string {
    return this.#wrapperHandle;
  }

  get targetHandle(): string {
    return this.#targetHandle;
  }

  describe(handle: string): KeyDescription {
    // All values are primitives. Neither the live description nor key bytes escape.
    return Object.freeze({ ...this.#record(handle).description });
  }

  readValue(handle: string): never {
    this.#record(handle);
    throw new ApiPolicyError(
      'SENSITIVE_VALUE',
      'Direct reading of sensitive key bytes is forbidden.',
    );
  }

  wrapKey(wrapperHandle: string, targetHandle: string): Uint8Array {
    const wrapper = this.#forRole(wrapperHandle, 'wrapping-key');
    const target = this.#record(targetHandle);
    if (!target.description.extractable) {
      throw new ApiPolicyError(
        'KEY_NOT_EXTRACTABLE',
        'This target is nonextractable: wrapping is forbidden before encryption.',
      );
    }
    return aesKwWrap(wrapper.material, target.material);
  }

  allowDecrypt(wrapperHandle: string): void {
    const wrapper = this.#forRole(wrapperHandle, 'wrapping-key');
    if (this.#policy === 'fixed-roles') {
      throw new ApiPolicyError(
        'ROLE_LOCKED',
        'The fixed wrapping role cannot gain byte-returning decrypt permission.',
      );
    }
    // The only mutable attribute transition modeled by this exhibit.
    wrapper.description = Object.freeze({ ...wrapper.description, decrypt: true });
  }

  decryptBytes(wrapperHandle: string, wrapped: Uint8Array): Uint8Array {
    const wrapper = this.#forRole(wrapperHandle, 'wrapping-key');
    if (!wrapper.description.decrypt) {
      throw new ApiPolicyError(
        'OPERATION_NOT_PERMITTED',
        'This wrapping key has no byte-returning decrypt permission.',
      );
    }
    return this.#unwrapBytes(wrapper, wrapped);
  }

  unwrapKey(wrapperHandle: string, wrapped: Uint8Array): string {
    const wrapper = this.#forRole(wrapperHandle, 'wrapping-key');
    const material = this.#unwrapBytes(wrapper, wrapped);
    try {
      // [extension] A future import/restore policy belongs here. For this trace,
      // every successful unwrap receives the same immutable restrictive template.
      return this.#insert(material, 'data-key', false);
    } finally {
      zeroize(material);
    }
  }

  async sealChallenge(handle: string, plaintext: Uint8Array): Promise<HandleChallenge> {
    const key = this.#forRole(handle, 'data-key');
    if (!(plaintext instanceof Uint8Array)) {
      throw new ApiPolicyError('INVALID_INPUT', 'The challenge plaintext must be bytes.');
    }
    const aad = encoder.encode('Envelope KMS key-handle challenge v1');
    // Copy before aeadSeal's first await so caller edits cannot change an in-flight input.
    const sealed = await aeadSeal(plaintext.slice(), key.material, aad);
    return { ...sealed, aad };
  }

  async openChallenge(handle: string, challenge: HandleChallenge): Promise<Uint8Array> {
    const key = this.#forRole(handle, 'data-key');
    if (
      !challenge ||
      !(challenge.iv instanceof Uint8Array) ||
      challenge.iv.length !== 12 ||
      !(challenge.tag instanceof Uint8Array) ||
      challenge.tag.length !== 16 ||
      !(challenge.ciphertext instanceof Uint8Array) ||
      !(challenge.aad instanceof Uint8Array)
    ) {
      throw new ApiPolicyError(
        'INVALID_INPUT',
        'Use a 12-byte GCM IV, 16-byte tag and byte fields.',
      );
    }
    try {
      return await aeadOpen(
        challenge.ciphertext.slice(),
        challenge.iv.slice(),
        challenge.tag.slice(),
        key.material,
        challenge.aad.slice(),
      );
    } catch (error) {
      if (error instanceof DOMException && error.name === 'OperationError') {
        throw new ApiPolicyError(
          'INTEGRITY_CHECK_FAILED',
          'AES-GCM authentication refused the challenge.',
        );
      }
      throw error;
    }
  }

  #fixtureOrRandomKey(factory: HandleKeyFactory, role: HandleRole): Uint8Array {
    const material = factory(role);
    if (!(material instanceof Uint8Array) || material.length !== 32) {
      throw new ApiPolicyError('INVALID_KEY_MATERIAL', 'This model requires 32-byte AES keys.');
    }
    return material.slice();
  }

  #insert(material: Uint8Array, role: HandleRole, extractable: boolean): string {
    const handle = `key-${crypto.randomUUID()}`;
    const wrapping = role === 'wrapping-key';
    this.#records.set(handle, {
      description: Object.freeze({
        handle,
        role,
        mechanism: wrapping ? 'AES-KW' : 'AES-GCM',
        sensitive: true,
        extractable,
        wrap: wrapping,
        unwrap: wrapping,
        encrypt: !wrapping,
        decrypt: !wrapping,
      }),
      material: material.slice(),
    });
    return handle;
  }

  #record(handle: string): KeyRecord {
    const record = this.#records.get(handle);
    if (!record)
      throw new ApiPolicyError('UNKNOWN_HANDLE', 'The handle does not exist in this token.');
    return record;
  }

  #forRole(handle: string, role: HandleRole): KeyRecord {
    const record = this.#record(handle);
    if (record.description.role !== role) {
      throw new ApiPolicyError(
        'MECHANISM_MISMATCH',
        role === 'wrapping-key'
          ? 'This operation requires an AES-KW wrapping-key handle.'
          : 'This operation requires an AES-GCM data-key handle.',
      );
    }
    return record;
  }

  #unwrapBytes(wrapper: KeyRecord, wrapped: Uint8Array): Uint8Array {
    if (!(wrapped instanceof Uint8Array) || wrapped.length !== 40) {
      throw new ApiPolicyError(
        'INVALID_INPUT',
        'A wrapped 256-bit target is exactly 40 bytes here.',
      );
    }
    try {
      return aesKwUnwrap(wrapper.material, wrapped);
    } catch (error) {
      if (error instanceof Error && error.message === 'RFC 3394 integrity check failed') {
        throw new ApiPolicyError(
          'INTEGRITY_CHECK_FAILED',
          'RFC 3394 integrity refused the wrapped key.',
        );
      }
      throw error;
    }
  }
}
