import { aeadSeal } from '../crypto/aead';
import { zeroize } from '../crypto/bytes';
import { auditLog } from '../kms/audit-log';
import { kmsApi } from '../kms/kms-api';

export type EnvelopeRecord = {
  ciphertext: Uint8Array;
  iv: Uint8Array;
  tag: Uint8Array;
  wrappedDEK: Uint8Array;
  kekId: string;
  kekVersion: number;
  aad: Uint8Array;
};

export async function seal(plaintext: Uint8Array, keyId: string, aad: Uint8Array): Promise<EnvelopeRecord> {
  const { plaintextDEK, wrappedDEK, kekId, kekVersion } = await kmsApi.GenerateDataKey(keyId, 32, 'seal');
  const { ciphertext, iv, tag } = await aeadSeal(plaintext, plaintextDEK, aad);
  zeroize(plaintextDEK);
  auditLog.append({
    operation: 'Seal',
    principal: 'seal',
    keyId: kekId,
    kekVersion,
    success: true,
    details: `ciphertext=${ciphertext.length}, wrappedDEK=${wrappedDEK.length}`,
  });
  return { ciphertext, iv, tag, wrappedDEK, kekId, kekVersion, aad };
}
