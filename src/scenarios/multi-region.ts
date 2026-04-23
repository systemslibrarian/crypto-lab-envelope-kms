import { encoder } from '../crypto/bytes';
import { rewrapEnvelope } from '../envelope/rotate';
import { seal } from '../envelope/seal';
import { kmsApi } from '../kms/kms-api';

export async function multiRegionScenario(): Promise<{ fromRegionKey: string; toRegionKey: string; sourceVersion: number; destVersion: number }> {
  const us = await kmsApi.CreateKey('AES256', 'scenario-us-east-1');
  const eu = await kmsApi.CreateKey('AES256', 'scenario-eu-west-1');
  const envelope = await seal(encoder.encode('regional payload'), us.keyId, encoder.encode('region=us-east-1'));
  const moved = await rewrapEnvelope(envelope, eu.keyId);
  return { fromRegionKey: us.keyId, toRegionKey: eu.keyId, sourceVersion: envelope.kekVersion, destVersion: moved.kekVersion };
}
