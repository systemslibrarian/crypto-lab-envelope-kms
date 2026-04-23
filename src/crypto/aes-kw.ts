import { ecb } from '@noble/ciphers/aes.js';
import { bigIntToU64be, concatBytes, equalBytes, u64beToBigInt } from './bytes';

const DEFAULT_IV = new Uint8Array(8).fill(0xa6);

function xorWithT(a: Uint8Array, t: number): Uint8Array {
  const x = u64beToBigInt(a) ^ BigInt(t);
  return bigIntToU64be(x);
}

function aesBlockEncrypt(kek: Uint8Array, block: Uint8Array): Uint8Array {
  return ecb(kek, { disablePadding: true }).encrypt(block);
}

function aesBlockDecrypt(kek: Uint8Array, block: Uint8Array): Uint8Array {
  return ecb(kek, { disablePadding: true }).decrypt(block);
}

export function wrapWithIv3394(kek: Uint8Array, plaintext: Uint8Array, iv: Uint8Array): Uint8Array {
  if (iv.length !== 8) throw new Error('IV must be 64-bit');
  if (plaintext.length < 16 || plaintext.length % 8 !== 0) {
    throw new Error('RFC 3394 requires at least 16 bytes and 64-bit blocks');
  }
  const n = plaintext.length / 8;
  let a: Uint8Array = iv.slice();
  const r = Array.from({ length: n }, (_, i) => plaintext.slice(i * 8, (i + 1) * 8));

  for (let j = 0; j <= 5; j += 1) {
    for (let i = 0; i < n; i += 1) {
      const b = aesBlockEncrypt(kek, concatBytes(a, r[i]));
      const t = n * j + i + 1;
      a = xorWithT(b.slice(0, 8), t);
      r[i] = b.slice(8, 16);
    }
  }

  return concatBytes(a, ...r);
}

export function unwrapWithIv3394(kek: Uint8Array, ciphertext: Uint8Array, iv: Uint8Array): Uint8Array {
  if (iv.length !== 8) throw new Error('IV must be 64-bit');
  if (ciphertext.length < 24 || ciphertext.length % 8 !== 0) {
    throw new Error('RFC 3394 ciphertext must be at least 24 bytes and 64-bit blocks');
  }
  const { a, plaintext } = unwrap3394Core(kek, ciphertext);

  if (!equalBytes(a, iv)) throw new Error('RFC 3394 integrity check failed');
  return plaintext;
}

export function unwrap3394Core(kek: Uint8Array, ciphertext: Uint8Array): { a: Uint8Array; plaintext: Uint8Array } {
  if (ciphertext.length < 24 || ciphertext.length % 8 !== 0) {
    throw new Error('RFC 3394 ciphertext must be at least 24 bytes and 64-bit blocks');
  }
  const n = ciphertext.length / 8 - 1;
  let a = ciphertext.slice(0, 8);
  const r = Array.from({ length: n }, (_, i) => ciphertext.slice((i + 1) * 8, (i + 2) * 8));

  for (let j = 5; j >= 0; j -= 1) {
    for (let i = n - 1; i >= 0; i -= 1) {
      const t = n * j + i + 1;
      const b = aesBlockDecrypt(kek, concatBytes(xorWithT(a, t), r[i]));
      a = b.slice(0, 8);
      r[i] = b.slice(8, 16);
    }
  }

  return { a, plaintext: concatBytes(...r) };
}

export function aesKwWrap(kek: Uint8Array, plaintext: Uint8Array): Uint8Array {
  return wrapWithIv3394(kek, plaintext, DEFAULT_IV);
}

export function aesKwUnwrap(kek: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  return unwrapWithIv3394(kek, ciphertext, DEFAULT_IV);
}
