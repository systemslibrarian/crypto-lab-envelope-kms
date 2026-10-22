import { equalBytes, zeroize } from '../crypto/bytes';
import { AccessDeniedError, decryptWithGrants, type KeyGrant } from '../kms/access-policy';
import { kmsApi, type WrappedDekRef } from '../kms/kms-api';

export type AccessPolicyResult = {
  permissiveAllowedMallory: boolean;
  grantDeniedMallory: boolean;
  grantAllowedAlice: boolean;
};

/** Exercise one valid wrap under the same KEK in both paths; return no key bytes. */
export async function runAccessPolicyExercise(): Promise<AccessPolicyResult> {
  const { keyId } = await kmsApi.CreateKey('AES256', 'exercise');
  const dataKey = await kmsApi.GenerateDataKey(keyId, 32, 'alice');
  const ref: WrappedDekRef = {
    wrappedDEK: dataKey.wrappedDEK,
    kekId: dataKey.kekId,
    kekVersion: dataKey.kekVersion,
  };
  const grants: KeyGrant[] = [{ principal: 'alice', keyId, operation: 'Decrypt' }];
  try {
    const unguarded = await kmsApi.Decrypt(ref, 'mallory');
    const permissiveAllowedMallory = equalBytes(unguarded, dataKey.plaintextDEK);
    zeroize(unguarded);

    let grantDeniedMallory = false;
    try {
      const unexpected = await decryptWithGrants(ref, 'mallory', grants);
      zeroize(unexpected);
    } catch (error) {
      if (!(error instanceof AccessDeniedError)) throw error;
      grantDeniedMallory = true;
    }

    const authorized = await decryptWithGrants(ref, 'alice', grants);
    const grantAllowedAlice = equalBytes(authorized, dataKey.plaintextDEK);
    zeroize(authorized);
    return { permissiveAllowedMallory, grantDeniedMallory, grantAllowedAlice };
  } finally {
    zeroize(dataKey.plaintextDEK);
  }
}
