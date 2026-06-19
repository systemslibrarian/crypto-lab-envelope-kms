import { describe, expect, it } from 'vitest';
import { aesKwUnwrap, aesKwWrap, wrapWithIv3394 } from './aes-kw';
import { aesKwpUnwrap, aesKwpWrap } from './aes-kwp';
import { concatBytes, equalBytes, hexToBytes } from './bytes';
import { runRfcVectors } from './rfc-vectors';

describe('RFC 3394 / 5649 vectors', () => {
  it('all canonical vectors pass', () => {
    expect(runRfcVectors()).toEqual({ ok: true });
  });

  it('RFC 3394 A.1 (128-bit KEK / 128-bit key) wraps to expected bytes', () => {
    const kek = hexToBytes('000102030405060708090A0B0C0D0E0F');
    const pt = hexToBytes('00112233445566778899AABBCCDDEEFF');
    const expected = hexToBytes('1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5');
    expect(equalBytes(aesKwWrap(kek, pt), expected)).toBe(true);
    expect(equalBytes(aesKwUnwrap(kek, expected), pt)).toBe(true);
  });

  it('RFC 5649 short (7-byte) plaintext uses single-block ECB path', () => {
    const kek = hexToBytes('5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8');
    const pt = hexToBytes('466f7250617369');
    const ct = aesKwpWrap(kek, pt);
    expect(ct.length).toBe(16);
    expect(equalBytes(aesKwpUnwrap(kek, ct), pt)).toBe(true);
  });

  it('RFC 3394 unwrap detects integrity failure', () => {
    const kek = hexToBytes('000102030405060708090A0B0C0D0E0F');
    const ct = hexToBytes('1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5');
    ct[ct.length - 1] ^= 0x01;
    expect(() => aesKwUnwrap(kek, ct)).toThrow(/integrity/i);
  });

  it('RFC 5649 unwrap detects AIV prefix tamper', () => {
    const kek = hexToBytes('5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8');
    const ct = aesKwpWrap(kek, hexToBytes('466f7250617369'));
    ct[0] ^= 0xff;
    expect(() => aesKwpUnwrap(kek, ct)).toThrow();
  });

  it('RFC 5649 rejects a blob declaring 8 padding bytes (MLI must satisfy 8(n-1) < MLI)', () => {
    // Craft a 2-block (16-byte) padded buffer whose AIV declares MLI = 8, i.e.
    // a full block of 8 padding octets. RFC 5649 §4.2 requires 8(n-1) < MLI,
    // so padding is 0..7 octets; b == 8 is invalid and must be rejected.
    const kek = new Uint8Array(32).fill(7);
    const aiv = new Uint8Array(8);
    aiv.set([0xa6, 0x59, 0x59, 0xa6], 0);
    new DataView(aiv.buffer).setUint32(4, 8, false); // MLI = 8
    const padded = concatBytes(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]), new Uint8Array(8));
    const malformed = wrapWithIv3394(kek, padded, aiv);
    expect(() => aesKwpUnwrap(kek, malformed)).toThrow(/invalid recovered length/i);
  });

  it('RFC 3394 rejects misaligned plaintext', () => {
    const kek = hexToBytes('000102030405060708090A0B0C0D0E0F');
    expect(() => aesKwWrap(kek, new Uint8Array(15))).toThrow();
  });

  it('RFC 5649 rejects empty plaintext', () => {
    const kek = hexToBytes('5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8');
    expect(() => aesKwpWrap(kek, new Uint8Array(0))).toThrow();
  });
});
