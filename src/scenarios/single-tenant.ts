import { encoder } from '../crypto/bytes';
import { open } from '../envelope/open';
import { seal, type EnvelopeRecord } from '../envelope/seal';
import { kmsApi } from '../kms/kms-api';

export async function singleTenantScenario(): Promise<{ keyId: string; envelope: EnvelopeRecord; plaintext: string }> {
  const { keyId } = await kmsApi.CreateKey('AES256', 'scenario-single-tenant');
  const envelope = await seal(encoder.encode('single tenant object'), keyId, encoder.encode('tenant=acme'));
  const plaintext = new TextDecoder().decode(await open(envelope));
  return { keyId, envelope, plaintext };
}
