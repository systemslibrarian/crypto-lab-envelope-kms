import { describe, expect, it } from 'vitest';
import { concatBytes, decoder, hexToBytes } from '../crypto/bytes';
import {
  exploreKeyHandleStates,
  replayKeyHandleWitness,
  type SearchKeyFactory,
  type SearchResult,
  type SearchScenario,
} from './key-handle-search';

const MATERIAL = {
  'protected-target': hexToBytes(
    '00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f',
  ),
  'transport-key': hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
  'caller-known-key': hexToBytes(
    '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f',
  ),
  'opaque-pivot': hexToBytes('202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'),
} as const;

const fixtureFactory: SearchKeyFactory = (value) => MATERIAL[value].slice();
const SCENARIOS: SearchScenario[] = ['mutable-role', 'known-key-import', 'same-value-handles'];

function raw(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

describe('bounded key-handle state search', () => {
  it.each([
    ['mutable-role', 3, ['WrapKey', 'GrantKwDecrypt', 'DecryptBytes']],
    ['known-key-import', 3, ['EncryptKnown', 'UnwrapAs', 'WrapKey']],
    ['same-value-handles', 4, ['UnwrapAs', 'UnwrapAs', 'WrapKey', 'DecryptBytes']],
  ] as const)('finds a shortest deterministic %s witness', (scenario, depth, kinds) => {
    const result = exploreKeyHandleStates(scenario, 'per-handle-templates');
    expect(result.verdict).toBe('witness-found');
    expect(result.capHit).toBe(false);
    expect(result.witness).toHaveLength(depth);
    expect(result.witness?.map((action) => action.kind)).toEqual(kinds);
    expect(result.terminalEvidence?.attackerKnownValues).toContain('protected-target');
    expect(exploreKeyHandleStates(scenario, 'per-handle-templates')).toEqual(result);
  });

  it.each([
    ['mutable-role', 3],
    ['known-key-import', 3],
    ['same-value-handles', 2],
  ] as const)(
    'fully checks the fixed-template %s model without overclaiming',
    (scenario, deepestExpanded) => {
      const result = exploreKeyHandleStates(scenario, 'fixed-template');
      expect(result.verdict).toBe('no-witness-within-bounds');
      expect(result.capHit).toBe(false);
      expect(result.witness).toBeNull();
      expect(result.terminalEvidence).toBeNull();
      expect(result.deepestCompleted).toBe(deepestExpanded);
      expect(result.statesVisited).toBeGreaterThan(0);
      expect(result.invariant).toBe('protected-target not in attacker-known raw values');
    },
  );

  it.each([
    ['mutable-role', 2],
    ['known-key-import', 2],
    ['same-value-handles', 3],
  ] as const)('does not report the %s witness below its minimum depth', (scenario, depth) => {
    const result = exploreKeyHandleStates(scenario, 'per-handle-templates', {
      maxSuccessfulCalls: depth,
    });
    expect(result.verdict).toBe('no-witness-within-bounds');
    expect(result.witness).toBeNull();
  });

  it('distinguishes a resource cutoff from a completed no-witness search', () => {
    const incomplete = exploreKeyHandleStates('same-value-handles', 'fixed-template', {
      maxStates: 1,
    });
    expect(incomplete).toMatchObject({
      verdict: 'search-incomplete',
      capHit: true,
      statesVisited: 1,
      witness: null,
    });
    const complete = exploreKeyHandleStates('same-value-handles', 'fixed-template');
    expect(complete).toMatchObject({
      verdict: 'no-witness-within-bounds',
      capHit: false,
    });
  });

  it.each(SCENARIOS)(
    'checks a terminal %s witness before the non-witness retention cap',
    (scenario) => {
      const unrestricted = exploreKeyHandleStates(scenario, 'per-handle-templates');
      const retainedBeforeWitness = unrestricted.statesVisited - 1;
      const boundary = exploreKeyHandleStates(scenario, 'per-handle-templates', {
        maxStates: retainedBeforeWitness,
      });
      expect(boundary.verdict).toBe('witness-found');
      expect(boundary.capHit).toBe(false);
      expect(boundary.witness).toEqual(unrestricted.witness);
      expect(boundary.statesVisited).toBe(retainedBeforeWitness + 1);
    },
  );

  it.each([2, 3])(
    'honors a %i-handle bound instead of allocating an unreported alias',
    (maxHandles) => {
      const result = exploreKeyHandleStates('same-value-handles', 'per-handle-templates', {
        maxHandles,
      });
      expect(result).toMatchObject({
        verdict: 'no-witness-within-bounds',
        capHit: false,
        witness: null,
      });
      expect(result.bounds.maxHandles).toBe(maxHandles);
    },
  );

  it('honors the blob bound instead of emitting an unreported target wrap', () => {
    const result = exploreKeyHandleStates('known-key-import', 'per-handle-templates', {
      maxBlobs: 1,
    });
    expect(result).toMatchObject({
      verdict: 'no-witness-within-bounds',
      capHit: false,
      witness: null,
    });
    expect(result.bounds.maxBlobs).toBe(1);
  });

  it('publishes the exact finite bounds and scenario-specific initial knowledge', () => {
    const imported = exploreKeyHandleStates('known-key-import', 'fixed-template');
    expect(imported.bounds).toEqual({
      maxSuccessfulCalls: 4,
      maxHandles: 4,
      maxBlobs: 4,
      maxStates: 50_000,
      atomicValues: 3,
      templates: 3,
    });
    expect(imported.initialKnowledge).toContain('raw caller-known-key bytes');
    expect(exploreKeyHandleStates('mutable-role', 'fixed-template').bounds.atomicValues).toBe(2);
  });

  it('tracks distinct same-value handles instead of collapsing the alias witness', async () => {
    const result = exploreKeyHandleStates('same-value-handles', 'per-handle-templates');
    const unwraps = result.witness?.filter((action) => action.kind === 'UnwrapAs') ?? [];
    expect(unwraps).toHaveLength(2);
    expect(unwraps[0]).toMatchObject({ template: 'kw-wrap-only' });
    expect(unwraps[1]).toMatchObject({ template: 'kw-decrypt-only' });
    expect(unwraps[0]).toHaveProperty('outputHandle');
    expect(unwraps[1]).toHaveProperty('outputHandle');
    if (unwraps[0].kind !== 'UnwrapAs' || unwraps[1].kind !== 'UnwrapAs') {
      throw new Error('Expected two unwrap actions.');
    }
    expect(unwraps[0].outputHandle).not.toBe(unwraps[1].outputHandle);
    expect(result.terminalEvidence?.opaquePivotHandles).toEqual([
      { id: unwraps[0].outputHandle, capabilities: ['KW_WRAP_KEY'] },
      { id: unwraps[1].outputHandle, capabilities: ['KW_DECRYPT_BYTES'] },
    ]);

    const proof = await replayKeyHandleWitness(result, fixtureFactory);
    expect(proof.sameValueHandles).toEqual([unwraps[0].outputHandle, unwraps[1].outputHandle]);
    expect(proof.wrappedBlobLengths.every((length) => length === 40)).toBe(true);
    expect(proof.escapedKey).toEqual(MATERIAL['protected-target']);
  });

  it.each(SCENARIOS)(
    'replays the searched %s witness with real AES-KW and AES-GCM',
    async (scenario) => {
      const result = exploreKeyHandleStates(scenario, 'per-handle-templates');
      const proof = await replayKeyHandleWitness(result, fixtureFactory);
      expect(proof.apiCalls).toBe(result.witness?.length);
      expect(proof.wrappedBlobLengths.length).toBeGreaterThan(0);
      expect(proof.wrappedBlobLengths.every((length) => length === 40)).toBe(true);
      expect(proof.escapedKey).toEqual(MATERIAL['protected-target']);

      const key = await crypto.subtle.importKey(
        'raw',
        raw(proof.escapedKey),
        { name: 'AES-GCM' },
        false,
        ['decrypt'],
      );
      const opened = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: raw(proof.challenge.iv),
          additionalData: raw(proof.challenge.aad),
          tagLength: 128,
        },
        key,
        raw(concatBytes(proof.challenge.ciphertext, proof.challenge.tag)),
      );
      expect(decoder.decode(opened)).toBe(decoder.decode(proof.expectedPlaintext));
    },
  );

  it('rejects fixed, incomplete, and structurally altered witnesses before crypto replay', async () => {
    await expect(
      replayKeyHandleWitness(exploreKeyHandleStates('known-key-import', 'fixed-template')),
    ).rejects.toThrow('unsafe-policy disclosure witness');
    await expect(
      replayKeyHandleWitness(
        exploreKeyHandleStates('known-key-import', 'per-handle-templates', {
          maxSuccessfulCalls: 2,
        }),
      ),
    ).rejects.toThrow('unsafe-policy disclosure witness');

    const valid = exploreKeyHandleStates('known-key-import', 'per-handle-templates');
    const altered = {
      ...valid,
      witness: valid.witness?.slice(1) ?? null,
    } as SearchResult;
    await expect(replayKeyHandleWitness(altered, fixtureFactory)).rejects.toThrow(
      'not a valid transition sequence',
    );
    const overBound = {
      ...valid,
      bounds: { ...valid.bounds, maxSuccessfulCalls: 2 },
    } as SearchResult;
    await expect(replayKeyHandleWitness(overBound, fixtureFactory)).rejects.toThrow(
      'exceeds its declared',
    );

    const sameValue = exploreKeyHandleStates('same-value-handles', 'per-handle-templates');
    const collapsedAlias = {
      ...sameValue,
      terminalEvidence: {
        ...sameValue.terminalEvidence!,
        opaquePivotHandles: sameValue.terminalEvidence!.opaquePivotHandles.slice(0, 1),
      },
    } as SearchResult;
    await expect(replayKeyHandleWitness(collapsedAlias, fixtureFactory)).rejects.toThrow(
      'terminal evidence does not match',
    );
  });

  it('rejects invalid bounds, policies, scenarios, and key fixtures', async () => {
    expect(() =>
      exploreKeyHandleStates('known-key-import', 'fixed-template', { maxStates: 0 }),
    ).toThrow('maxStates');
    expect(() =>
      exploreKeyHandleStates('not-a-scenario' as SearchScenario, 'fixed-template'),
    ).toThrow('named state-search scenario');
    expect(() =>
      exploreKeyHandleStates('known-key-import', 'not-a-policy' as 'fixed-template'),
    ).toThrow('Choose fixed-template');

    const witness = exploreKeyHandleStates('known-key-import', 'per-handle-templates');
    await expect(replayKeyHandleWitness(witness, () => new Uint8Array(31))).rejects.toThrow(
      '32-byte AES keys',
    );
    await expect(replayKeyHandleWitness(witness, () => new Uint8Array(32).fill(7))).rejects.toThrow(
      'distinct material',
    );
  });
});
