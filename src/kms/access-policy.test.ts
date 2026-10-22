import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { bytesToHex, equalBytes, zeroize } from '../crypto/bytes';
import { auditLog } from './audit-log';
import { AccessDeniedError, decryptWithGrants, type KeyGrant } from './access-policy';
import { kekStore } from './kek-store';
import { kmsApi } from './kms-api';

beforeEach(() => {
  auditLog.clear();
  kekStore.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
  auditLog.clear();
  kekStore.clear();
});

describe('teaching grant checks', () => {
  it('demonstrates that a logged principal is not authorization', async () => {
    const { keyId } = await kmsApi.CreateKey('AES256', 'alice');
    const dataKey = await kmsApi.GenerateDataKey(keyId, 32, 'alice');
    try {
      const recovered = await kmsApi.Decrypt(dataKey, 'mallory');
      expect(equalBytes(recovered, dataKey.plaintextDEK)).toBe(true);
      zeroize(recovered);
      expect(auditLog.list().some((entry) => entry.principal === 'mallory' && entry.success)).toBe(
        true,
      );
    } finally {
      zeroize(dataKey.plaintextDEK);
    }
  });

  it('denies a caller or mismatched key before any unwrap and returns no DEK', async () => {
    const { keyId } = await kmsApi.CreateKey('AES256', 'alice');
    const { keyId: otherKeyId } = await kmsApi.CreateKey('AES256', 'alice');
    const dataKey = await kmsApi.GenerateDataKey(keyId, 32, 'alice');
    const marker = bytesToHex(dataKey.plaintextDEK);
    const unwrap = vi.spyOn(kekStore, 'getMaterialForUnwrap');
    const grants: KeyGrant[] = [{ principal: 'alice', keyId: otherKeyId, operation: 'Decrypt' }];
    try {
      await expect(decryptWithGrants(dataKey, 'mallory', grants)).rejects.toBeInstanceOf(
        AccessDeniedError,
      );
      await expect(decryptWithGrants(dataKey, 'alice', grants)).rejects.toBeInstanceOf(
        AccessDeniedError,
      );
      expect(unwrap).not.toHaveBeenCalled();
      const denials = auditLog.list().filter((entry) => entry.operation === 'Decrypt');
      expect(denials).toHaveLength(2);
      expect(denials.every((entry) => !entry.success)).toBe(true);
      expect(JSON.stringify(denials)).not.toContain(marker);
      expect(JSON.stringify(denials)).not.toContain(bytesToHex(dataKey.wrappedDEK));
    } finally {
      zeroize(dataKey.plaintextDEK);
    }
  });

  it('allows the matching caller, key and operation and returns the original DEK', async () => {
    const { keyId } = await kmsApi.CreateKey('AES256', 'alice');
    const dataKey = await kmsApi.GenerateDataKey(keyId, 32, 'alice');
    const grants: KeyGrant[] = [{ principal: 'alice', keyId, operation: 'Decrypt' }];
    try {
      const returned = await decryptWithGrants(dataKey, 'alice', grants);
      expect(equalBytes(returned, dataKey.plaintextDEK)).toBe(true);
      zeroize(returned);
      expect(
        auditLog
          .list()
          .some(
            (entry) =>
              entry.operation === 'Decrypt' && entry.principal === 'alice' && entry.success,
          ),
      ).toBe(true);
    } finally {
      zeroize(dataKey.plaintextDEK);
    }
  });
});
