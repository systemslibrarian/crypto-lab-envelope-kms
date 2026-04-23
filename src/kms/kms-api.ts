import { aesKwUnwrap, aesKwWrap } from '../crypto/aes-kw';
import { aeadOpen, aeadSeal } from '../crypto/aead';
import { auditLog } from './audit-log';
import { kekStore } from './kek-store';

export type WrappedDekRef = {
  wrappedDEK: Uint8Array;
  kekId: string;
  kekVersion: number;
};

export type DataKeyResponse = WrappedDekRef & { plaintextDEK: Uint8Array };

export type EncryptResponse = WrappedDekRef & {
  ciphertext: Uint8Array;
  iv: Uint8Array;
  tag: Uint8Array;
  aad: Uint8Array;
};

export class KmsApi {
  async CreateKey(spec = 'AES256', principal = 'app'): Promise<{ keyId: string; version: number }> {
    try {
      const created = kekStore.createKey(spec);
      auditLog.append({ operation: 'CreateKey', principal, keyId: created.keyId, kekVersion: created.version, success: true });
      return created;
    } catch (error) {
      auditLog.append({ operation: 'CreateKey', principal, success: false, details: String(error) });
      throw error;
    }
  }

  async GenerateDataKey(keyId: string, keyLength = 32, principal = 'app'): Promise<DataKeyResponse> {
    try {
      if (keyLength !== 32) throw new Error('This demo supports 256-bit DEKs only');
      const plaintextDEK = crypto.getRandomValues(new Uint8Array(keyLength));
      const { material, version } = kekStore.getMaterialForWrap(keyId);
      const wrappedDEK = aesKwWrap(material, plaintextDEK);
      auditLog.append({
        operation: 'GenerateDataKey',
        principal,
        keyId,
        kekVersion: version,
        success: true,
        details: `plaintextDEK=${keyLength} bytes, wrappedDEK=${wrappedDEK.length} bytes`,
      });
      return { plaintextDEK, wrappedDEK, kekId: keyId, kekVersion: version };
    } catch (error) {
      auditLog.append({ operation: 'GenerateDataKey', principal, keyId, success: false, details: String(error) });
      throw error;
    }
  }

  async Encrypt(input: { plaintext: Uint8Array; keyId: string; aad?: Uint8Array }, principal = 'app'): Promise<EncryptResponse> {
    try {
      const aad = input.aad ?? new Uint8Array();
      const dataKey = await this.GenerateDataKey(input.keyId, 32, principal);
      const { ciphertext, iv, tag } = await aeadSeal(input.plaintext, dataKey.plaintextDEK, aad);
      dataKey.plaintextDEK.fill(0);
      auditLog.append({
        operation: 'Seal',
        principal,
        keyId: input.keyId,
        kekVersion: dataKey.kekVersion,
        success: true,
        details: `kms Encrypt ciphertext=${ciphertext.length}`,
      });
      return { ciphertext, iv, tag, aad, wrappedDEK: dataKey.wrappedDEK, kekId: dataKey.kekId, kekVersion: dataKey.kekVersion };
    } catch (error) {
      auditLog.append({ operation: 'Seal', principal, keyId: input.keyId, success: false, details: String(error) });
      throw error;
    }
  }

  async Decrypt(input: WrappedDekRef, principal = 'app'): Promise<Uint8Array> {
    try {
      const material = kekStore.getMaterialForUnwrap(input.kekId, input.kekVersion);
      const plaintextDEK = aesKwUnwrap(material, input.wrappedDEK);
      auditLog.append({
        operation: 'Decrypt',
        principal,
        keyId: input.kekId,
        kekVersion: input.kekVersion,
        success: true,
        details: `returned DEK bytes=${plaintextDEK.length}`,
      });
      return plaintextDEK;
    } catch (error) {
      auditLog.append({
        operation: 'Decrypt',
        principal,
        keyId: input.kekId,
        kekVersion: input.kekVersion,
        success: false,
        details: String(error),
      });
      throw error;
    }
  }

  async DecryptEnvelope(
    input: WrappedDekRef & { ciphertext: Uint8Array; iv: Uint8Array; tag: Uint8Array; aad?: Uint8Array },
    principal = 'app',
  ): Promise<Uint8Array> {
    const dek = await this.Decrypt(input, principal);
    try {
      const plaintext = await aeadOpen(input.ciphertext, input.iv, input.tag, dek, input.aad ?? new Uint8Array());
      return plaintext;
    } finally {
      dek.fill(0);
    }
  }

  async ReEncrypt(
    input: { wrappedDEK: Uint8Array; sourceKek: WrappedDekRef; destKek: { keyId: string; version?: number } },
    principal = 'app',
  ): Promise<WrappedDekRef> {
    try {
      const sourceMaterial = kekStore.getMaterialForUnwrap(input.sourceKek.kekId, input.sourceKek.kekVersion);
      const plaintext = aesKwUnwrap(sourceMaterial, input.wrappedDEK);
      const destVersion = input.destKek.version ?? kekStore.getCurrentVersion(input.destKek.keyId);
      const destMaterial = kekStore.getMaterialForUnwrap(input.destKek.keyId, destVersion);
      const wrappedDEK = aesKwWrap(destMaterial, plaintext);
      plaintext.fill(0);
      auditLog.append({
        operation: 'ReEncrypt',
        principal,
        keyId: input.destKek.keyId,
        kekVersion: destVersion,
        success: true,
        details: `${input.sourceKek.kekId}@v${input.sourceKek.kekVersion} -> ${input.destKek.keyId}@v${destVersion}`,
      });
      return { wrappedDEK, kekId: input.destKek.keyId, kekVersion: destVersion };
    } catch (error) {
      auditLog.append({ operation: 'ReEncrypt', principal, success: false, details: String(error) });
      throw error;
    }
  }

  async ScheduleKeyDeletion(keyId: string, windowDays: number, principal = 'app'): Promise<void> {
    try {
      kekStore.scheduleDeletion(keyId, windowDays);
      auditLog.append({ operation: 'ScheduleKeyDeletion', principal, keyId, success: true, details: `${windowDays} days` });
    } catch (error) {
      auditLog.append({ operation: 'ScheduleKeyDeletion', principal, keyId, success: false, details: String(error) });
      throw error;
    }
  }

  async RotateKey(keyId: string, principal = 'app'): Promise<{ keyId: string; version: number }> {
    try {
      const rotated = kekStore.rotateKey(keyId);
      auditLog.append({ operation: 'RotateKey', principal, keyId, kekVersion: rotated.version, success: true });
      return rotated;
    } catch (error) {
      auditLog.append({ operation: 'RotateKey', principal, keyId, success: false, details: String(error) });
      throw error;
    }
  }
}

export const kmsApi = new KmsApi();
