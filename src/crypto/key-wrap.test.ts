import { describe, expect, it } from 'vitest';
import { aesKwUnwrap, aesKwWrap, unwrap3394Core, wrapWithIv3394 } from './aes-kw';
import { aesKwpUnwrap, aesKwpWrap } from './aes-kwp';
import { concatBytes, equalBytes, hexToBytes } from './bytes';
import { runRfcVectors } from './rfc-vectors';

describe('RFC 3394 / 5649 vectors', () => {
  it('all canonical vectors pass', () => {
    expect(runRfcVectors()).toEqual({ ok: true });
  });

  it('RFC 3394 4.1 (128-bit KEK / 128-bit key) wraps to expected bytes', () => {
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

  it('RFC 5649 rejects non-zero padding octets behind a well-formed AIV', () => {
    // The sharpest case in this file. Everything about this blob is valid
    // except the padding:
    //
    //   - it is wrapped under the real KEK, so the RFC 3394 layer unwraps it
    //     cleanly and no integrity check fires;
    //   - its AIV carries the correct A65959A6 prefix, so the prefix check
    //     passes;
    //   - its MLI of 13 against a 16-byte padded buffer means 3 padding
    //     octets, which is inside the legal 0..7 range, so the length check
    //     passes too.
    //
    // The only thing wrong is that those 3 octets are DEADBE rather than
    // zeros. RFC 5649 §4.2 requires the padding be zero, and this is the sole
    // check standing between the caller and 3 attacker-chosen bytes riding
    // along inside an otherwise authentic wrap. Drop it and the padding
    // becomes a covert channel: two distinct blobs unwrap to the same key
    // while differing in bytes the caller never sees. Unwrap must refuse.
    const kek = new Uint8Array(32).fill(7);
    const aiv = new Uint8Array(8);
    aiv.set([0xa6, 0x59, 0x59, 0xa6], 0);
    new DataView(aiv.buffer).setUint32(4, 13, false); // MLI = 13 of 16 → 3 pad octets
    const padded = concatBytes(new Uint8Array(13).fill(0x42), hexToBytes('deadbe'));
    const forged = wrapWithIv3394(kek, padded, aiv);

    expect(() => aesKwpUnwrap(kek, forged)).toThrow(/non-zero padding/i);

    // Control: the identical blob with the padding actually zeroed is accepted
    // and returns exactly the 13 declared bytes — so the rejection above is
    // the padding check firing, not the construction being malformed.
    const honest = wrapWithIv3394(
      kek,
      concatBytes(new Uint8Array(13).fill(0x42), new Uint8Array(3)),
      aiv,
    );
    expect(equalBytes(aesKwpUnwrap(kek, honest), new Uint8Array(13).fill(0x42))).toBe(true);
  });

  it('RFC 3394 unwrap rejects ciphertext that is too short or misaligned', () => {
    // Two blocks is the minimum a wrap can produce (an 8-byte A plus at least
    // one 8-byte R). Anything shorter, or anything not a whole number of
    // 64-bit blocks, cannot be a 3394 blob and must be refused before the
    // cipher runs rather than indexing off the end of the buffer.
    const kek = hexToBytes('000102030405060708090A0B0C0D0E0F');
    expect(() => aesKwUnwrap(kek, new Uint8Array(16))).toThrow(/24 bytes/);
    expect(() => aesKwUnwrap(kek, new Uint8Array(28))).toThrow(/64-bit blocks/);
    expect(() => aesKwUnwrap(kek, new Uint8Array(0))).toThrow();
  });

  it('RFC 3394 core unwrap enforces the same length rule as the IV-checked entry point', () => {
    // unwrap3394Core is exported so AES-KWP can reach the raw A register
    // without the fixed-IV comparison. That bypasses unwrapWithIv3394's guard,
    // so the core has to carry its own — otherwise a KWP caller reaches the
    // block loop with a buffer it cannot address.
    const kek = hexToBytes('000102030405060708090A0B0C0D0E0F');
    expect(() => unwrap3394Core(kek, new Uint8Array(16))).toThrow(/24 bytes/);
    expect(() => unwrap3394Core(kek, new Uint8Array(25))).toThrow(/64-bit blocks/);
  });

  it('RFC 5649 unwrap rejects ciphertext that is too short or misaligned', () => {
    // KWP's floor is one AES block (the 16-byte single-block path); below that
    // there is no AIV to parse at all.
    const kek = hexToBytes('5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8');
    expect(() => aesKwpUnwrap(kek, new Uint8Array(8))).toThrow(/length invalid/i);
    expect(() => aesKwpUnwrap(kek, new Uint8Array(20))).toThrow(/length invalid/i);
    expect(() => aesKwpUnwrap(kek, new Uint8Array(0))).toThrow(/length invalid/i);
  });
});
