import { afterEach, describe, expect, it, vi } from 'vitest';
import * as aead from '../crypto/aead';
import * as keyWrap from '../crypto/aes-kw';
import { concatBytes, encoder, hexToBytes } from '../crypto/bytes';
import {
  ApiPolicyError,
  HandleToken,
  type ApiPolicyErrorCode,
  type HandleChallenge,
  type HandlePolicy,
} from './key-handles';

// RFC 3394 section 4.6: an independent 256-bit / 256-bit known-answer fixture.
// https://www.rfc-editor.org/rfc/rfc3394.html#section-4.6
const WRAPPER = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
const TARGET = hexToBytes('00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f');
const WRAPPED = hexToBytes(
  '28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21',
);
const POLICIES: HandlePolicy[] = ['fixed-roles', 'mutable-usages'];

function fixture(policy: HandlePolicy = 'fixed-roles', extractable = true): HandleToken {
  return new HandleToken(policy, extractable, (role) =>
    role === 'wrapping-key' ? WRAPPER : TARGET,
  );
}

function expectCode(action: () => unknown, code: ApiPolicyErrorCode): void {
  let failure: unknown;
  try {
    action();
  } catch (error) {
    failure = error;
  }
  expect(failure).toBeInstanceOf(ApiPolicyError);
  expect(failure).toMatchObject({ code });
}

function raw(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}

function copyChallenge(challenge: HandleChallenge): HandleChallenge {
  return {
    iv: challenge.iv.slice(),
    ciphertext: challenge.ciphertext.slice(),
    tag: challenge.tag.slice(),
    aad: challenge.aad.slice(),
  };
}

afterEach(() => vi.restoreAllMocks());

describe('isolated stateful key-handle policy', () => {
  it('defaults to fixed roles, with a sensitive wrappable target and nonexportable wrapper', () => {
    const token = new HandleToken();
    expect(token.policy).toBe('fixed-roles');
    expect(token.describe(token.wrapperHandle)).toEqual({
      handle: token.wrapperHandle,
      role: 'wrapping-key',
      mechanism: 'AES-KW',
      sensitive: true,
      extractable: false,
      wrap: true,
      unwrap: true,
      encrypt: false,
      decrypt: false,
    });
    expect(token.describe(token.targetHandle)).toMatchObject({
      role: 'data-key',
      mechanism: 'AES-GCM',
      sensitive: true,
      extractable: true,
      wrap: false,
      unwrap: false,
      encrypt: true,
      decrypt: true,
    });
    expect(token.wrapperHandle).not.toBe(token.targetHandle);
    expect(
      Object.values(token.describe(token.targetHandle)).every(
        (value) => typeof value === 'string' || typeof value === 'boolean',
      ),
    ).toBe(true);
    expectCode(() => token.readValue(token.wrapperHandle), 'SENSITIVE_VALUE');
    expectCode(() => token.readValue(token.targetHandle), 'SENSITIVE_VALUE');
  });

  it('matches RFC 3394 section 4.6 and native WebCrypto AES-KW independently', async () => {
    const token = fixture();
    const wrapped = token.wrapKey(token.wrapperHandle, token.targetHandle);
    expect(wrapped).toEqual(WRAPPED);
    const nativeWrapper = await crypto.subtle.importKey('raw', raw(WRAPPER), 'AES-KW', false, [
      'wrapKey',
      'unwrapKey',
    ]);
    const nativeTarget = await crypto.subtle.importKey('raw', raw(TARGET), 'AES-GCM', true, [
      'decrypt',
    ]);
    expect(
      new Uint8Array(await crypto.subtle.wrapKey('raw', nativeTarget, nativeWrapper, 'AES-KW')),
    ).toEqual(wrapped);
    const opened = await crypto.subtle.unwrapKey(
      'raw',
      raw(wrapped),
      nativeWrapper,
      'AES-KW',
      'AES-GCM',
      true,
      ['decrypt'],
    );
    expect(new Uint8Array(await crypto.subtle.exportKey('raw', opened))).toEqual(TARGET);
  });

  it('composes allowed mutable calls into real recovery despite a refused direct read', async () => {
    const token = fixture('mutable-usages');
    const plaintext = encoder.encode('Synthetic invoice: 17');
    const challenge = await token.sealChallenge(token.targetHandle, plaintext);
    expectCode(() => token.readValue(token.targetHandle), 'SENSITIVE_VALUE');
    const wrapped = token.wrapKey(token.wrapperHandle, token.targetHandle);
    expectCode(() => token.decryptBytes(token.wrapperHandle, wrapped), 'OPERATION_NOT_PERMITTED');
    token.allowDecrypt(token.wrapperHandle);
    const recovered = token.decryptBytes(token.wrapperHandle, wrapped);
    expect(recovered).toEqual(TARGET);
    expect(recovered).toHaveLength(32);
    // Independent of HandleToken.openChallenge and any model success flag.
    const externalKey = await crypto.subtle.importKey('raw', raw(recovered), 'AES-GCM', false, [
      'decrypt',
    ]);
    const opened = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: raw(challenge.iv),
        additionalData: raw(challenge.aad),
        tagLength: 128,
      },
      externalKey,
      raw(concatBytes(challenge.ciphertext, challenge.tag)),
    );
    expect(new Uint8Array(opened)).toEqual(plaintext);
    expectCode(() => token.readValue(token.targetHandle), 'SENSITIVE_VALUE');
    recovered.fill(0);
  });

  it('fixed roles block the transition while legitimate unwrap-to-handle remains usable', async () => {
    const token = fixture();
    const before = token.describe(token.wrapperHandle);
    const plaintext = encoder.encode('Preserved legitimate use');
    const challenge = await token.sealChallenge(token.targetHandle, plaintext);
    const wrapped = token.wrapKey(token.wrapperHandle, token.targetHandle);
    expectCode(() => token.allowDecrypt(token.wrapperHandle), 'ROLE_LOCKED');
    expect(token.describe(token.wrapperHandle)).toEqual(before);
    expectCode(() => token.decryptBytes(token.wrapperHandle, wrapped), 'OPERATION_NOT_PERMITTED');
    const restored = token.unwrapKey(token.wrapperHandle, wrapped);
    expect(restored).not.toBe(token.targetHandle);
    expect(token.describe(restored)).toMatchObject({
      role: 'data-key',
      sensitive: true,
      extractable: false,
      decrypt: true,
      wrap: false,
    });
    expect(await token.openChallenge(restored, challenge)).toEqual(plaintext);
    expectCode(() => token.readValue(restored), 'SENSITIVE_VALUE');
    expectCode(() => token.wrapKey(token.wrapperHandle, restored), 'KEY_NOT_EXTRACTABLE');
    expectCode(() => token.allowDecrypt(restored), 'MECHANISM_MISMATCH');
  });

  it.each(POLICIES)(
    '%s denies decrypt permission before inspecting malformed wrapped bytes',
    (policy) => {
      const token = fixture(policy);
      const unwrap = vi.spyOn(keyWrap, 'aesKwUnwrap');
      expectCode(
        () => token.decryptBytes(token.wrapperHandle, new Uint8Array()),
        'OPERATION_NOT_PERMITTED',
      );
      expect(unwrap).not.toHaveBeenCalled();
    },
  );

  it.each(POLICIES)('%s refuses a nonextractable target before encryption', (policy) => {
    const token = fixture(policy, false);
    const wrap = vi.spyOn(keyWrap, 'aesKwWrap');
    expectCode(() => token.wrapKey(token.wrapperHandle, token.targetHandle), 'KEY_NOT_EXTRACTABLE');
    expectCode(
      () => token.wrapKey(token.wrapperHandle, token.wrapperHandle),
      'KEY_NOT_EXTRACTABLE',
    );
    expect(wrap).not.toHaveBeenCalled();
    expect(token.describe(token.targetHandle).extractable).toBe(false);
  });

  it('snapshots cannot grant permissions or change roles, and old snapshots stay unchanged', () => {
    const token = fixture('mutable-usages');
    const snapshot = token.describe(token.wrapperHandle);
    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(Reflect.set(snapshot, 'decrypt', true)).toBe(false);
    expect(Reflect.set(snapshot, 'role', 'data-key')).toBe(false);
    const callerCopy = { ...snapshot, decrypt: true, extractable: true };
    expect(callerCopy.decrypt).toBe(true);
    expect(token.describe(token.wrapperHandle).decrypt).toBe(false);
    expect(token.describe(token.wrapperHandle).extractable).toBe(false);
    token.allowDecrypt(token.wrapperHandle);
    expect(snapshot.decrypt).toBe(false);
    expect(token.describe(token.wrapperHandle).decrypt).toBe(true);
    token.allowDecrypt(token.wrapperHandle); // Idempotent after the permitted transition.
    expect(token.describe(token.wrapperHandle).decrypt).toBe(true);
  });

  it('copies fixture bytes and never returns aliases to its stored key material', () => {
    const wrapper = WRAPPER.slice();
    const target = TARGET.slice();
    const token = new HandleToken('mutable-usages', true, (role) =>
      role === 'wrapping-key' ? wrapper : target,
    );
    wrapper.fill(0);
    target.fill(0);
    expect(token.wrapKey(token.wrapperHandle, token.targetHandle)).toEqual(WRAPPED);
    token.allowDecrypt(token.wrapperHandle);
    const recovered = token.decryptBytes(token.wrapperHandle, WRAPPED);
    recovered.fill(0);
    expect(token.decryptBytes(token.wrapperHandle, WRAPPED)).toEqual(TARGET);
    expectCode(() => token.readValue(token.targetHandle), 'SENSITIVE_VALUE');
  });

  it('fails closed for unrecognized policy, extractability and malformed fixture material', () => {
    expectCode(() => new HandleToken('unknown' as HandlePolicy), 'INVALID_INPUT');
    expectCode(() => new HandleToken('fixed-roles', 'yes' as unknown as boolean), 'INVALID_INPUT');
    for (const length of [0, 16, 24, 31, 33]) {
      expectCode(
        () => new HandleToken('fixed-roles', true, () => new Uint8Array(length)),
        'INVALID_KEY_MATERIAL',
      );
    }
    expectCode(
      () => new HandleToken('fixed-roles', true, () => null as unknown as Uint8Array),
      'INVALID_KEY_MATERIAL',
    );
    expectCode(() => new HandleToken('fixed-roles', true, () => WRAPPER), 'INVALID_KEY_MATERIAL');
    expectCode(
      () =>
        new HandleToken('fixed-roles', true, (role) =>
          role === 'wrapping-key' ? WRAPPER : new Uint8Array(16),
        ),
      'INVALID_KEY_MATERIAL',
    );
    expect(WRAPPER).toEqual(
      hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
    );
  });

  it('rejects unknown and foreign-token handles without changing local policy', async () => {
    const token = fixture();
    const foreign = fixture();
    const before = token.describe(token.wrapperHandle);
    for (const handle of ['missing', foreign.wrapperHandle]) {
      for (const action of [
        () => token.describe(handle),
        () => token.readValue(handle),
        () => token.wrapKey(handle, token.targetHandle),
        () => token.wrapKey(token.wrapperHandle, handle),
        () => token.allowDecrypt(handle),
        () => token.decryptBytes(handle, WRAPPED),
        () => token.unwrapKey(handle, WRAPPED),
      ])
        expectCode(action, 'UNKNOWN_HANDLE');
      await expect(token.sealChallenge(handle, new Uint8Array())).rejects.toMatchObject({
        code: 'UNKNOWN_HANDLE',
      });
      await expect(token.openChallenge(handle, {} as HandleChallenge)).rejects.toMatchObject({
        code: 'UNKNOWN_HANDLE',
      });
    }
    expect(token.describe(token.wrapperHandle)).toEqual(before);
  });

  it('keeps AES-KW and AES-GCM handles in their declared mechanisms', async () => {
    const token = fixture('mutable-usages');
    for (const action of [
      () => token.wrapKey(token.targetHandle, token.targetHandle),
      () => token.allowDecrypt(token.targetHandle),
      () => token.decryptBytes(token.targetHandle, WRAPPED),
      () => token.unwrapKey(token.targetHandle, WRAPPED),
    ])
      expectCode(action, 'MECHANISM_MISMATCH');
    await expect(token.sealChallenge(token.wrapperHandle, new Uint8Array())).rejects.toMatchObject({
      code: 'MECHANISM_MISMATCH',
    });
    await expect(
      token.openChallenge(token.wrapperHandle, {} as HandleChallenge),
    ).rejects.toMatchObject({ code: 'MECHANISM_MISMATCH' });
  });

  it('rejects corrupt or wrongly keyed wraps before creating any new handle', () => {
    const token = fixture('mutable-usages');
    token.allowDecrypt(token.wrapperHandle);
    const before = token.describe(token.wrapperHandle);
    const corrupt = WRAPPED.slice();
    corrupt[0] ^= 1;
    const wrongWrapper = WRAPPER.slice();
    wrongWrapper[0] ^= 1;
    const wrong = keyWrap.aesKwWrap(wrongWrapper, TARGET);
    const allocations = vi.spyOn(crypto, 'randomUUID');
    for (const wrapped of [corrupt, wrong]) {
      expectCode(() => token.decryptBytes(token.wrapperHandle, wrapped), 'INTEGRITY_CHECK_FAILED');
      expectCode(() => token.unwrapKey(token.wrapperHandle, wrapped), 'INTEGRITY_CHECK_FAILED');
    }
    expect(allocations).not.toHaveBeenCalled();
    expect(token.describe(token.wrapperHandle)).toEqual(before);
    expect(token.decryptBytes(token.wrapperHandle, WRAPPED)).toEqual(TARGET);
  });

  it('rejects malformed wraps at the model boundary without modifying caller bytes', () => {
    const token = fixture('mutable-usages');
    token.allowDecrypt(token.wrapperHandle);
    for (const length of [0, 24, 39, 41, 48]) {
      const wrapped = new Uint8Array(length).fill(0x91);
      const before = wrapped.slice();
      expectCode(() => token.decryptBytes(token.wrapperHandle, wrapped), 'INVALID_INPUT');
      expectCode(() => token.unwrapKey(token.wrapperHandle, wrapped), 'INVALID_INPUT');
      expect(wrapped).toEqual(before);
    }
    expectCode(
      () => token.decryptBytes(token.wrapperHandle, null as unknown as Uint8Array),
      'INVALID_INPUT',
    );
  });

  it.each(['iv', 'ciphertext', 'tag', 'aad'] as const)(
    'GCM rejects modified %s and retains a usable target',
    async (field) => {
      const token = fixture();
      const plaintext = encoder.encode('Tamper me');
      const challenge = await token.sealChallenge(token.targetHandle, plaintext);
      const corrupt = copyChallenge(challenge);
      corrupt[field][0] ^= 1;
      await expect(token.openChallenge(token.targetHandle, corrupt)).rejects.toMatchObject({
        code: 'INTEGRITY_CHECK_FAILED',
      });
      expect(await token.openChallenge(token.targetHandle, challenge)).toEqual(plaintext);
    },
  );

  it('GCM rejects the wrong target key and malformed challenge shapes', async () => {
    const token = fixture();
    const other = new HandleToken();
    const challenge = await token.sealChallenge(token.targetHandle, encoder.encode('challenge'));
    await expect(other.openChallenge(other.targetHandle, challenge)).rejects.toMatchObject({
      code: 'INTEGRITY_CHECK_FAILED',
    });
    for (const malformed of [
      null,
      { ...challenge, iv: new Uint8Array(11) },
      { ...challenge, tag: new Uint8Array(15) },
      { ...challenge, iv: null },
      { ...challenge, tag: null },
      { ...challenge, ciphertext: null },
      { ...challenge, aad: null },
    ]) {
      await expect(
        token.openChallenge(token.targetHandle, malformed as unknown as HandleChallenge),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    }
    await expect(
      token.sealChallenge(token.targetHandle, null as unknown as Uint8Array),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('copies asynchronous inputs before yielding and supports an empty authenticated message', async () => {
    const token = fixture();
    const original = encoder.encode('Snapshot before await');
    const plaintext = original.slice();
    const pending = token.sealChallenge(token.targetHandle, plaintext);
    plaintext.fill(0);
    const challenge = await pending;
    const opening = token.openChallenge(token.targetHandle, challenge);
    challenge.tag[0] ^= 1;
    expect(await opening).toEqual(original);
    const empty = await token.sealChallenge(token.targetHandle, new Uint8Array());
    expect(await token.openChallenge(token.targetHandle, empty)).toEqual(new Uint8Array());
  });

  it('does not relabel unexpected runtime failures as successful policy defenses', async () => {
    const token = fixture('mutable-usages');
    token.allowDecrypt(token.wrapperHandle);
    const unavailable = new Error('Synthetic unavailable runtime');
    vi.spyOn(keyWrap, 'aesKwUnwrap').mockImplementationOnce(() => {
      throw unavailable;
    });
    expect(() => token.decryptBytes(token.wrapperHandle, WRAPPED)).toThrow(unavailable);
    const challenge = await token.sealChallenge(token.targetHandle, encoder.encode('runtime'));
    vi.spyOn(aead, 'aeadOpen').mockRejectedValueOnce(unavailable);
    await expect(token.openChallenge(token.targetHandle, challenge)).rejects.toBe(unavailable);
  });
});
