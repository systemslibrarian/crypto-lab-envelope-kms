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
    expect(results.every((r) => r.mode === 'defended')).toBe(true);
  });

  it('every property is genuinely breakable — the weakened build fails all of them', async () => {
    // The "Property broken" badge must be reachable. If any weakened experiment
    // still holds, the lab has a failure state a learner can never observe.
    const results = await runAllProperties('weakened');
    expect(results).toHaveLength(PROPERTY_IDS.length);
    expect(results.filter((r) => r.held).map((r) => r.id)).toEqual([]);
    expect(results.every((r) => r.mode === 'weakened')).toBe(true);
  });

  it('each weakened experiment reports what actually happened', async () => {
    for (const id of PROPERTY_IDS) {
      const result = await runProperty(id, 'weakened');
      expect(result.held).toBe(false);
      expect(result.observed.length).toBeGreaterThan(20);
    }
  });

  it('every catalog entry names the defense its weakened run removes', () => {
    for (const meta of PROPERTY_CATALOG) {
      expect(meta.weakening.length).toBeGreaterThan(10);
    }
  });
});
