import { aesKwUnwrap, aesKwWrap } from './aes-kw';
import { aesKwpUnwrap, aesKwpWrap } from './aes-kwp';
import { bytesToHex, equalBytes, hexToBytes } from './bytes';

type Vector = { kek: string; plaintext: string; ciphertext: string; name: string };

const RFC3394_VECTORS: Vector[] = [
  {
    name: 'RFC3394-A.1-128/128',
    kek: '000102030405060708090A0B0C0D0E0F',
    plaintext: '00112233445566778899AABBCCDDEEFF',
    ciphertext: '1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5',
  },
  {
    name: 'RFC3394-A.2-192/128',
    kek: '000102030405060708090A0B0C0D0E0F1011121314151617',
    plaintext: '00112233445566778899AABBCCDDEEFF',
    ciphertext: '96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D',
  },
  {
    name: 'RFC3394-A.3-256/128',
    kek: '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
    plaintext: '00112233445566778899AABBCCDDEEFF',
    ciphertext: '64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7',
  },
];

const RFC5649_VECTORS: Vector[] = [
  {
    name: 'RFC5649-A.4-40-octets',
    kek: '5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8',
    plaintext: 'c37b7e6492584340bed12207808941155068f738',
    ciphertext: '138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a',
  },
  {
    name: 'RFC5649-A.5-7-octets',
    kek: '5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8',
    plaintext: '466f7250617369',
    ciphertext: 'afbeb0f07dfbf5419200f2ccb50bb24f',
  },
];

export function runRfcVectors(): { ok: true } {
  for (const v of RFC3394_VECTORS) {
    const kek = hexToBytes(v.kek);
    const plaintext = hexToBytes(v.plaintext);
    const expected = hexToBytes(v.ciphertext);
    const wrapped = aesKwWrap(kek, plaintext);
    if (!equalBytes(wrapped, expected)) {
      throw new Error(`${v.name} wrap mismatch: got ${bytesToHex(wrapped)}`);
    }
    const unwrapped = aesKwUnwrap(kek, expected);
    if (!equalBytes(unwrapped, plaintext)) {
      throw new Error(`${v.name} unwrap mismatch: got ${bytesToHex(unwrapped)}`);
    }
  }

  for (const v of RFC5649_VECTORS) {
    const kek = hexToBytes(v.kek);
    const plaintext = hexToBytes(v.plaintext);
    const expected = hexToBytes(v.ciphertext);
    const wrapped = aesKwpWrap(kek, plaintext);
    if (!equalBytes(wrapped, expected)) {
      throw new Error(`${v.name} wrap mismatch: got ${bytesToHex(wrapped)}`);
    }
    const unwrapped = aesKwpUnwrap(kek, expected);
    if (!equalBytes(unwrapped, plaintext)) {
      throw new Error(`${v.name} unwrap mismatch: got ${bytesToHex(unwrapped)}`);
    }
  }

  return { ok: true };
}
