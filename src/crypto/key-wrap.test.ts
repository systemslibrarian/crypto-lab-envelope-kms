import { describe, expect, it } from 'vitest';
import { aesKwUnwrap, aesKwWrap } from './aes-kw';
import { aesKwpUnwrap, aesKwpWrap } from './aes-kwp';
import { equalBytes, hexToBytes } from './bytes';
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

  it('RFC 3394 rejects misaligned plaintext', () => {
    const kek = hexToBytes('000102030405060708090A0B0C0D0E0F');
    expect(() => aesKwWrap(kek, new Uint8Array(15))).toThrow();
  });

  it('RFC 5649 rejects empty plaintext', () => {
    const kek = hexToBytes('5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8');
    expect(() => aesKwpWrap(kek, new Uint8Array(0))).toThrow();
  });
});
