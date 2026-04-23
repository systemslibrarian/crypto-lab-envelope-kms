import { encoder } from '../crypto/bytes';
import { open } from '../envelope/open';
import { rewrapEnvelope } from '../envelope/rotate';
import { seal } from '../envelope/seal';
import { kmsApi } from '../kms/kms-api';

export async function rotationDrillScenario(): Promise<{ keyId: string; beforeVersion: number; afterVersion: number; stillDecrypts: boolean }> {
  const { keyId } = await kmsApi.CreateKey('AES256', 'rotation-drill');
  const envelope = await seal(encoder.encode('rotation drill data'), keyId, encoder.encode('drill=1'));
  const beforeVersion = envelope.kekVersion;
  await kmsApi.RotateKey(keyId, 'rotation-drill');
  const rewrapped = await rewrapEnvelope(envelope, keyId);
  const recovered = await open(rewrapped);
  return {
    keyId,
    beforeVersion,
    afterVersion: rewrapped.kekVersion,
    stillDecrypts: new TextDecoder().decode(recovered) === 'rotation drill data',
  };
}
