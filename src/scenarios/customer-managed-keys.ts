import { encoder } from '../crypto/bytes';
import { open } from '../envelope/open';
import { seal } from '../envelope/seal';
import { kmsApi } from '../kms/kms-api';

export async function customerManagedKeysScenario(): Promise<{ customerKeyId: string; recoveredText: string }> {
  const customer = await kmsApi.CreateKey('AES256', 'customer-vault');
  const envelope = await seal(encoder.encode('customer managed material'), customer.keyId, encoder.encode('cmk=true'));
  const recoveredText = new TextDecoder().decode(await open(envelope));
  return { customerKeyId: customer.keyId, recoveredText };
}
