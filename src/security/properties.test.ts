import { describe, expect, it } from 'vitest';
import { PROPERTY_CATALOG, PROPERTY_IDS, runAllProperties, runProperty } from './properties';

describe('security properties', () => {
  it('every catalog entry has a runnable experiment', () => {
    expect(PROPERTY_CATALOG.map((p) => p.id).sort()).toEqual([...PROPERTY_IDS].sort());
  });

  it('AAD binding rejects an envelope opened with the wrong context', async () => {
    const result = await runProperty('aad-binding');
    expect(result.held).toBe(true);
    expect(result.observed.toLowerCase()).toContain('rejected');
  });

  it('ciphertext is tamper-evident', async () => {
    const result = await runProperty('ciphertext-tamper');
    expect(result.held).toBe(true);
  });

  it('tenant isolation rejects a cross-KEK unwrap', async () => {
    const result = await runProperty('tenant-isolation');
    expect(result.held).toBe(true);
    expect(result.observed.toLowerCase()).toContain('rejected');
  });

  it('wrapped DEK integrity rejects a corrupted wrap', async () => {
    const result = await runProperty('wrap-integrity');
    expect(result.held).toBe(true);
  });

  it('rotation keeps old envelopes readable and routes new writes to the new version', async () => {
    const result = await runProperty('rotation-access');
    expect(result.held).toBe(true);
    expect(result.observed).toContain('no bulk re-encryption');
  });

  it('runAllProperties returns a held result for every property', async () => {
    const results = await runAllProperties();
    expect(results).toHaveLength(PROPERTY_IDS.length);
    expect(results.every((r) => r.held)).toBe(true);
  });
});
