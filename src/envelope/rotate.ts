import { auditLog } from '../kms/audit-log';
import { kmsApi } from '../kms/kms-api';
import type { EnvelopeRecord } from './seal';

export async function rewrapEnvelope(envelope: EnvelopeRecord, destinationKeyId: string): Promise<EnvelopeRecord> {
  const rewrapped = await kmsApi.ReEncrypt(
    {
      wrappedDEK: envelope.wrappedDEK,
      sourceKek: { wrappedDEK: envelope.wrappedDEK, kekId: envelope.kekId, kekVersion: envelope.kekVersion },
      destKek: { keyId: destinationKeyId },
    },
    'rotate',
  );

  auditLog.append({
    operation: 'RewrapEnvelope',
    principal: 'rotate',
    keyId: destinationKeyId,
    kekVersion: rewrapped.kekVersion,
    success: true,
    details: `rewrapped from ${envelope.kekId}@v${envelope.kekVersion}`,
  });

  return {
    ...envelope,
    wrappedDEK: rewrapped.wrappedDEK,
    kekId: rewrapped.kekId,
    kekVersion: rewrapped.kekVersion,
  };
}
