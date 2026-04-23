import { aeadOpen } from '../crypto/aead';
import { zeroize } from '../crypto/bytes';
import { auditLog } from '../kms/audit-log';
import { kmsApi } from '../kms/kms-api';
import type { EnvelopeRecord } from './seal';

export async function open(envelope: EnvelopeRecord): Promise<Uint8Array> {
  const plaintextDEK = await kmsApi.Decrypt(
    { wrappedDEK: envelope.wrappedDEK, kekId: envelope.kekId, kekVersion: envelope.kekVersion },
    'open',
  );
  const plaintext = await aeadOpen(envelope.ciphertext, envelope.iv, envelope.tag, plaintextDEK, envelope.aad);
  zeroize(plaintextDEK);
  auditLog.append({
    operation: 'Open',
    principal: 'open',
    keyId: envelope.kekId,
    kekVersion: envelope.kekVersion,
    success: true,
    details: `plaintext=${plaintext.length}`,
  });
  return plaintext;
}
