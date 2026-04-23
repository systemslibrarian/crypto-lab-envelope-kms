import { describe, expect, it } from 'vitest';
import {
  bigIntToU64be,
  bytesToHex,
  concatBytes,
  equalBytes,
  hexToBytes,
  u64beToBigInt,
  zeroize,
} from './bytes';

describe('bytes', () => {
  it('round-trips hex', () => {
    const original = new Uint8Array([0x00, 0xa6, 0xff, 0x10]);
    const hex = bytesToHex(original);
    expect(hex).toBe('00a6ff10');
    expect(equalBytes(hexToBytes(hex), original)).toBe(true);
  });

  it('hex parser is whitespace and case insensitive', () => {
    expect(equalBytes(hexToBytes('00 A6 FF 10'), new Uint8Array([0x00, 0xa6, 0xff, 0x10]))).toBe(
      true,
    );
  });

  it('hex parser rejects odd-length input', () => {
    expect(() => hexToBytes('abc')).toThrow();
  });

  it('concatenates byte arrays', () => {
    const out = concatBytes(new Uint8Array([1, 2]), new Uint8Array([3]), new Uint8Array([4, 5]));
    expect(Array.from(out)).toEqual([1, 2, 3, 4, 5]);
  });

  it('equalBytes is constant-time-shaped (same length only)', () => {
    expect(equalBytes(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true);
    expect(equalBytes(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false);
    expect(equalBytes(new Uint8Array([1]), new Uint8Array([1, 2]))).toBe(false);
  });

  it('round-trips u64be ↔ bigint at edges', () => {
    const samples = [0n, 1n, 0xffn, 0x1234567890abcdefn, 0xffffffffffffffffn];
    for (const s of samples) {
      const bytes = bigIntToU64be(s);
      expect(bytes.length).toBe(8);
      expect(u64beToBigInt(bytes)).toBe(s);
    }
  });

  it('zeroize wipes buffer in place', () => {
    const buf = new Uint8Array([1, 2, 3, 4]);
    zeroize(buf);
    expect(Array.from(buf)).toEqual([0, 0, 0, 0]);
  });
});
