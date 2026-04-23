import { describe, expect, it } from 'vitest';
import { hkdfSha256 } from './kdf';
import { bytesToHex } from './bytes';

describe('HKDF-SHA256', () => {
  it('matches RFC 5869 test case 1', async () => {
    const ikm = new Uint8Array(22).fill(0x0b);
    const salt = new Uint8Array([
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ]);
    const info = new Uint8Array([0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9]);
    const okm = await hkdfSha256(ikm, salt, info, 42);
    expect(bytesToHex(okm)).toBe(
      '3cb25f25faacd57a90434f64d0362f2a' +
        '2d2d0a90cf1a5a4c5db02d56ecc4c5bf' +
        '34007208d5b887185865',
    );
  });

  it('produces different outputs for different info', async () => {
    const ikm = new Uint8Array(32).fill(0x11);
    const salt = new Uint8Array(16);
    const a = await hkdfSha256(ikm, salt, new TextEncoder().encode('a'));
    const b = await hkdfSha256(ikm, salt, new TextEncoder().encode('b'));
    expect(bytesToHex(a)).not.toBe(bytesToHex(b));
  });
});
