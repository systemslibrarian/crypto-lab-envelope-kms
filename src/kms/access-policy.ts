import { auditLog } from './audit-log';
import { kmsApi, type WrappedDekRef } from './kms-api';

/** A small, explicit teaching grant. This is not an authenticated IAM identity. */
export type KeyGrant = {
  principal: string;
  keyId: string;
  operation: 'Decrypt';
};

export class AccessDeniedError extends Error {
  constructor() {
    super('Access denied before unwrap');
    this.name = 'AccessDeniedError';
  }
}

/**
 * Opt-in policy gate for the access-control exhibit. The normal KmsApi.Decrypt
 * remains deliberately permissive so learners can compare the two paths.
 * A real service must authenticate its callers; this browser's labels are
 * caller-supplied strings and must never be treated as a security boundary.
 */
export async function decryptWithGrants(
  input: WrappedDekRef,
  principal: string,
  grants: readonly KeyGrant[],
): Promise<Uint8Array> {
  const permitted = grants.some(
    (grant) =>
      grant.principal === principal && grant.keyId === input.kekId && grant.operation === 'Decrypt',
  );
  if (!permitted) {
    auditLog.append({
      operation: 'Decrypt',
      principal,
      keyId: input.kekId,
      kekVersion: input.kekVersion,
      success: false,
      details: 'teaching grant denied before unwrap',
    });
    throw new AccessDeniedError();
  }
  return kmsApi.Decrypt(input, principal);
}
