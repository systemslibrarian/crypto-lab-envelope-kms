export const encoder = new TextEncoder();
export const decoder = new TextDecoder();

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.replace(/\s+/g, '').toLowerCase();
  if (normalized.length % 2 !== 0) {
    throw new Error('hex string must have even length');
  }
  const out = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function u64beToBigInt(bytes: Uint8Array): bigint {
  if (bytes.length !== 8) throw new Error('u64 requires 8 bytes');
  let out = 0n;
  for (const b of bytes) out = (out << 8n) | BigInt(b);
  return out;
}

export function bigIntToU64be(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  let tmp = value;
  for (let i = 7; i >= 0; i -= 1) {
    out[i] = Number(tmp & 0xffn);
    tmp >>= 8n;
  }
  return out;
}

export function zeroize(bytes: Uint8Array): void {
  bytes.fill(0);
}
