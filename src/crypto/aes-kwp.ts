import { ecb } from '@noble/ciphers/aes.js';
import { aesKwUnwrap, aesKwWrap, unwrap3394Core, wrapWithIv3394 } from './aes-kw';
import { concatBytes, equalBytes } from './bytes';

const PREFIX = new Uint8Array([0xa6, 0x59, 0x59, 0xa6]);

function buildAiv(length: number): Uint8Array {
  const aiv = new Uint8Array(8);
  aiv.set(PREFIX, 0);
  new DataView(aiv.buffer).setUint32(4, length, false);
  return aiv;
}

function parseAiv(aiv: Uint8Array): { length: number } {
  if (!equalBytes(aiv.slice(0, 4), PREFIX)) throw new Error('RFC 5649 AIV prefix mismatch');
  const length = new DataView(aiv.buffer, aiv.byteOffset, aiv.byteLength).getUint32(4, false);
  return { length };
}

function padTo8(plaintext: Uint8Array): Uint8Array {
  const pad = (8 - (plaintext.length % 8)) % 8;
  if (pad === 0) return plaintext.slice();
  const out = new Uint8Array(plaintext.length + pad);
  out.set(plaintext);
  return out;
}

export function aesKwpWrap(kek: Uint8Array, plaintext: Uint8Array): Uint8Array {
  if (plaintext.length === 0 || plaintext.length > 0xffffffff) {
    throw new Error('RFC 5649 plaintext length out of range');
  }
  const aiv = buildAiv(plaintext.length);
  const padded = padTo8(plaintext);

  if (padded.length === 8) {
    return ecb(kek, { disablePadding: true }).encrypt(concatBytes(aiv, padded));
  }
  return wrapWithIv3394(kek, padded, aiv);
}

/** expectedLength must come from trusted application policy, not the wrapped blob. */
export function aesKwpUnwrap(
  kek: Uint8Array,
  ciphertext: Uint8Array,
  expectedLength?: number,
): Uint8Array {
  if (
    expectedLength !== undefined &&
    (!Number.isInteger(expectedLength) || expectedLength < 1 || expectedLength > 0xffffffff)
  ) {
    throw new Error('Expected plaintext length must be an integer from 1 through 2^32-1');
  }
  if (ciphertext.length < 16 || ciphertext.length % 8 !== 0) {
    throw new Error('RFC 5649 ciphertext length invalid');
  }

  let aiv: Uint8Array;
  let padded: Uint8Array;

  if (ciphertext.length === 16) {
    const block = ecb(kek, { disablePadding: true }).decrypt(ciphertext);
    aiv = block.slice(0, 8);
    padded = block.slice(8, 16);
  } else {
    const recovered = unwrap3394Core(kek, ciphertext);
    aiv = recovered.a;
    padded = recovered.plaintext;
  }

  const { length } = parseAiv(aiv);
  if (length > padded.length || length <= padded.length - 8) {
    throw new Error('RFC 5649 invalid recovered length');
  }
  const padLen = padded.length - length;
  if (padLen > 0 && !equalBytes(padded.slice(length), new Uint8Array(padLen))) {
    throw new Error('RFC 5649 non-zero padding bytes');
  }
  // Supplement all standard AIV/MLI/padding checks before releasing plaintext.
  if (expectedLength !== undefined && length !== expectedLength) {
    throw new Error('RFC 5649 recovered length does not match expected plaintext length');
  }
  return padded.slice(0, length);
}

export { aesKwWrap, aesKwUnwrap };
