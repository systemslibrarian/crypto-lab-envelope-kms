export async function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  lengthBytes = 32,
): Promise<Uint8Array> {
  const ikmRaw = ikm.buffer.slice(ikm.byteOffset, ikm.byteOffset + ikm.byteLength) as ArrayBuffer;
  const saltRaw = salt.buffer.slice(salt.byteOffset, salt.byteOffset + salt.byteLength) as ArrayBuffer;
  const infoRaw = info.buffer.slice(info.byteOffset, info.byteOffset + info.byteLength) as ArrayBuffer;
  const key = await crypto.subtle.importKey('raw', ikmRaw, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: saltRaw, info: infoRaw }, key, lengthBytes * 8);
  return new Uint8Array(bits);
}
