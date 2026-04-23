import { concatBytes } from './bytes';

export type AeadSealResult = {
  ciphertext: Uint8Array;
  iv: Uint8Array;
  tag: Uint8Array;
};

async function importAesGcmKey(key: Uint8Array): Promise<CryptoKey> {
  const raw = key.buffer.slice(key.byteOffset, key.byteOffset + key.byteLength) as ArrayBuffer;
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

export async function aeadSeal(plaintext: Uint8Array, key: Uint8Array, aad: Uint8Array): Promise<AeadSealResult> {
  const iv = new Uint8Array(crypto.getRandomValues(new Uint8Array(12)).buffer) as Uint8Array<ArrayBuffer>;
  const cryptoKey = await importAesGcmKey(key);
  const plaintextRaw = plaintext.buffer.slice(plaintext.byteOffset, plaintext.byteOffset + plaintext.byteLength) as ArrayBuffer;
  const aadRaw = aad.buffer.slice(aad.byteOffset, aad.byteOffset + aad.byteLength) as ArrayBuffer;
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aadRaw, tagLength: 128 }, cryptoKey, plaintextRaw),
  );
  return { ciphertext: sealed.slice(0, -16), iv, tag: sealed.slice(-16) };
}

export async function aeadOpen(
  ciphertext: Uint8Array,
  iv: Uint8Array,
  tag: Uint8Array,
  key: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  const ivBuf = new Uint8Array(iv.buffer.slice(iv.byteOffset, iv.byteOffset + iv.byteLength) as ArrayBuffer);
  const cryptoKey = await importAesGcmKey(key);
  const aadRaw = aad.buffer.slice(aad.byteOffset, aad.byteOffset + aad.byteLength) as ArrayBuffer;
  const payload = concatBytes(ciphertext, tag);
  const payloadRaw = payload.buffer.slice(payload.byteOffset, payload.byteOffset + payload.byteLength) as ArrayBuffer;
  const opened = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivBuf, additionalData: aadRaw, tagLength: 128 },
    cryptoKey,
    payloadRaw,
  );
  return new Uint8Array(opened);
}
