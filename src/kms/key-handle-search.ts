import { aeadOpen, aeadSeal } from '../crypto/aead';
import { aesKwUnwrap, aesKwWrap } from '../crypto/aes-kw';
import { encoder, equalBytes, zeroize } from '../crypto/bytes';

export type SearchPolicy = 'fixed-template' | 'per-handle-templates';
export type SearchScenario = 'mutable-role' | 'known-key-import' | 'same-value-handles';
export type SearchTemplate = 'data-only' | 'kw-wrap-only' | 'kw-decrypt-only';
export type SearchCapability =
  'KW_ENCRYPT_BYTES' | 'KW_WRAP_KEY' | 'KW_UNWRAP_KEY' | 'KW_DECRYPT_BYTES' | 'GCM_OPEN_DATA';

type ValueId = 'protected-target' | 'transport-key' | 'caller-known-key' | 'opaque-pivot';

type SearchObject = {
  id: string;
  valueId: ValueId;
  capabilities: SearchCapability[];
  sensitive: true;
  extractable: boolean;
};

type SearchBlob = {
  id: string;
  wrapperValue: ValueId;
  payloadValue: ValueId;
};

type SearchState = {
  objects: SearchObject[];
  blobs: SearchBlob[];
  knownValues: ValueId[];
  nextHandle: number;
};

export type SearchAction =
  | {
      kind: 'EncryptKnown';
      keyHandle: string;
      payloadValue: ValueId;
      outputBlob: string;
    }
  | {
      kind: 'WrapKey';
      wrapperHandle: string;
      targetHandle: string;
      outputBlob: string;
    }
  | {
      kind: 'UnwrapAs';
      keyHandle: string;
      inputBlob: string;
      template: SearchTemplate;
      outputHandle: string;
    }
  | { kind: 'GrantKwDecrypt'; handle: string }
  | { kind: 'DecryptBytes'; keyHandle: string; inputBlob: string };

export type SearchBounds = Readonly<{
  maxSuccessfulCalls: number;
  maxHandles: number;
  maxBlobs: number;
  maxStates: number;
  atomicValues: number;
  templates: 3;
}>;

export type SearchResult = Readonly<{
  scenario: SearchScenario;
  policy: SearchPolicy;
  bounds: SearchBounds;
  invariant: 'protected-target not in attacker-known raw values';
  initialKnowledge: readonly string[];
  statesVisited: number;
  transitionsAccepted: number;
  deepestCompleted: number;
  verdict: 'witness-found' | 'no-witness-within-bounds' | 'search-incomplete';
  capHit: boolean;
  witness: readonly SearchAction[] | null;
}>;

export type SearchProof = Readonly<{
  scenario: SearchScenario;
  apiCalls: number;
  wrappedBlobLengths: readonly number[];
  sameValueHandles: readonly [string, string] | null;
  escapedKey: Uint8Array;
  expectedPlaintext: Uint8Array;
  challenge: Readonly<{
    iv: Uint8Array;
    ciphertext: Uint8Array;
    tag: Uint8Array;
    aad: Uint8Array;
  }>;
}>;

export type SearchSetup = Readonly<{
  bounds: SearchBounds;
  invariant: 'protected-target not in attacker-known raw values';
  initialKnowledge: readonly string[];
}>;

export type SearchKeyFactory = (value: ValueId) => Uint8Array;

type SearchOptions = Partial<{
  maxSuccessfulCalls: number;
  maxHandles: number;
  maxBlobs: number;
  maxStates: number;
}>;

const TARGET: ValueId = 'protected-target';
export const DEFAULT_STATE_SEARCH_BOUNDS: SearchBounds = Object.freeze({
  maxSuccessfulCalls: 4,
  maxHandles: 4,
  maxBlobs: 4,
  maxStates: 50_000,
  atomicValues: 3,
  templates: 3,
});

const TEMPLATES: readonly SearchTemplate[] = Object.freeze([
  'data-only',
  'kw-wrap-only',
  'kw-decrypt-only',
]);

export const STATE_SEARCH_RULES: readonly Readonly<{ name: string; rule: string }>[] =
  Object.freeze([
    {
      name: 'EncryptKnown',
      rule: 'A KW_ENCRYPT_BYTES handle may AES-KW-encrypt raw bytes already known to the attacker, emitting a ciphertext blob.',
    },
    {
      name: 'WrapKey',
      rule: 'A KW_WRAP_KEY handle may wrap an extractable key object.',
    },
    {
      name: 'UnwrapAs',
      rule: 'A KW_UNWRAP_KEY handle may unwrap a matching blob. The unsafe policy accepts one of three caller templates; the fixed policy accepts only data-only.',
    },
    {
      name: 'GrantKwDecrypt',
      rule: 'Only the unsafe mutable-role preset may add byte-returning AES-KW decrypt permission to a handle that already has KW_WRAP_KEY.',
    },
    {
      name: 'DecryptBytes',
      rule: 'A KW_DECRYPT_BYTES handle may return the plaintext of a matching AES-KW blob.',
    },
    {
      name: 'Local knowledge closure',
      rule: 'Outside the API, a blob can be unwrapped whenever the attacker already knows its exact wrapping-key value; this deduction is not counted as an API call.',
    },
  ]);

const randomKey: SearchKeyFactory = () => crypto.getRandomValues(new Uint8Array(32));

function capabilities(...values: SearchCapability[]): SearchCapability[] {
  return [...values].sort();
}

function object(
  id: string,
  valueId: ValueId,
  objectCapabilities: SearchCapability[],
  extractable: boolean,
): SearchObject {
  return {
    id,
    valueId,
    capabilities: capabilities(...objectCapabilities),
    sensitive: true,
    extractable,
  };
}

function blobId(wrapperValue: ValueId, payloadValue: ValueId): string {
  return `kw(${wrapperValue},${payloadValue})`;
}

function initialState(scenario: SearchScenario): SearchState {
  const target = object('h-target', TARGET, ['GCM_OPEN_DATA'], true);
  if (scenario === 'mutable-role') {
    return {
      objects: [
        target,
        object('h-wrapper', 'transport-key', ['KW_WRAP_KEY', 'KW_UNWRAP_KEY'], false),
      ],
      blobs: [],
      knownValues: [],
      nextHandle: 1,
    };
  }
  if (scenario === 'known-key-import') {
    return {
      objects: [
        target,
        object('h-importer', 'transport-key', ['KW_ENCRYPT_BYTES', 'KW_UNWRAP_KEY'], false),
      ],
      blobs: [],
      knownValues: ['caller-known-key'],
      nextHandle: 1,
    };
  }
  if (scenario === 'same-value-handles') {
    return {
      objects: [target, object('h-importer', 'transport-key', ['KW_UNWRAP_KEY'], false)],
      blobs: [
        {
          id: blobId('transport-key', 'opaque-pivot'),
          wrapperValue: 'transport-key',
          payloadValue: 'opaque-pivot',
        },
      ],
      knownValues: [],
      nextHandle: 1,
    };
  }
  throw new TypeError('Choose a named state-search scenario.');
}

function initialKnowledge(scenario: SearchScenario): string[] {
  if (scenario === 'known-key-import') {
    return [
      'public handles h-target and h-importer',
      'raw caller-known-key bytes',
      'no protected-target or transport-key bytes',
    ];
  }
  if (scenario === 'same-value-handles') {
    return [
      'public handles h-target and h-importer',
      'blob kw(transport-key,opaque-pivot)',
      'no protected-target, transport-key or opaque-pivot bytes',
    ];
  }
  return ['public handles h-target and h-wrapper', 'no protected-target or transport-key bytes'];
}

function checkedInteger(value: number, name: string, minimum: number, maximum: number): number {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new RangeError(`${name} must be an integer from ${minimum} through ${maximum}.`);
  }
  return value;
}

function resolveBounds(options: SearchOptions, scenario: SearchScenario): SearchBounds {
  return Object.freeze({
    maxSuccessfulCalls: checkedInteger(
      options.maxSuccessfulCalls ?? DEFAULT_STATE_SEARCH_BOUNDS.maxSuccessfulCalls,
      'maxSuccessfulCalls',
      0,
      8,
    ),
    maxHandles: checkedInteger(
      options.maxHandles ?? DEFAULT_STATE_SEARCH_BOUNDS.maxHandles,
      'maxHandles',
      2,
      8,
    ),
    maxBlobs: checkedInteger(
      options.maxBlobs ?? DEFAULT_STATE_SEARCH_BOUNDS.maxBlobs,
      'maxBlobs',
      1,
      8,
    ),
    maxStates: checkedInteger(
      options.maxStates ?? DEFAULT_STATE_SEARCH_BOUNDS.maxStates,
      'maxStates',
      1,
      100_000,
    ),
    atomicValues: scenario === 'mutable-role' ? 2 : 3,
    templates: 3,
  });
}

function cloneState(state: SearchState): SearchState {
  return {
    objects: state.objects.map((entry) => ({ ...entry, capabilities: [...entry.capabilities] })),
    blobs: state.blobs.map((entry) => ({ ...entry })),
    knownValues: [...state.knownValues],
    nextHandle: state.nextHandle,
  };
}

function hasCapability(entry: SearchObject, capability: SearchCapability): boolean {
  return entry.capabilities.includes(capability);
}

function addKnown(state: SearchState, value: ValueId): boolean {
  if (state.knownValues.includes(value)) return false;
  state.knownValues.push(value);
  state.knownValues.sort();
  return true;
}

function closeKnowledge(state: SearchState): void {
  let changed = true;
  while (changed) {
    changed = false;
    for (const wrapped of state.blobs) {
      if (state.knownValues.includes(wrapped.wrapperValue)) {
        changed = addKnown(state, wrapped.payloadValue) || changed;
      }
    }
  }
}

function canonicalState(state: SearchState): string {
  // Handle names are references, not identities. Canonicalize a multiset of
  // object descriptions so alpha-renamed fresh handles share one search state,
  // while multiplicity and same-value aliases remain visible.
  const objects = state.objects
    .map(
      (entry) =>
        `${entry.valueId}:${entry.capabilities.join('+')}:${entry.sensitive ? 'S' : 'P'}:${entry.extractable ? 'E' : 'N'}`,
    )
    .sort();
  const blobs = state.blobs.map((entry) => `${entry.wrapperValue}>${entry.payloadValue}`).sort();
  return JSON.stringify({ objects, blobs, known: [...state.knownValues].sort() });
}

type Transition = { state: SearchState; action: SearchAction };

function addBlob(
  state: SearchState,
  wrapperValue: ValueId,
  payloadValue: ValueId,
  maxBlobs: number,
): SearchBlob | null {
  const id = blobId(wrapperValue, payloadValue);
  if (state.blobs.some((entry) => entry.id === id) || state.blobs.length >= maxBlobs) return null;
  const blob = { id, wrapperValue, payloadValue };
  state.blobs.push(blob);
  state.blobs.sort((left, right) => left.id.localeCompare(right.id));
  return blob;
}

function transitions(
  state: SearchState,
  scenario: SearchScenario,
  policy: SearchPolicy,
  bounds: SearchBounds,
): Transition[] {
  const next: Transition[] = [];
  const sortedObjects = [...state.objects].sort((left, right) => left.id.localeCompare(right.id));
  const sortedBlobs = [...state.blobs].sort((left, right) => left.id.localeCompare(right.id));

  for (const key of sortedObjects) {
    if (!hasCapability(key, 'KW_ENCRYPT_BYTES')) continue;
    for (const known of [...state.knownValues].sort()) {
      const candidate = cloneState(state);
      const emitted = addBlob(candidate, key.valueId, known, bounds.maxBlobs);
      if (!emitted) continue;
      closeKnowledge(candidate);
      next.push({
        state: candidate,
        action: {
          kind: 'EncryptKnown',
          keyHandle: key.id,
          payloadValue: known,
          outputBlob: emitted.id,
        },
      });
    }
  }

  for (const wrapper of sortedObjects) {
    if (!hasCapability(wrapper, 'KW_WRAP_KEY')) continue;
    for (const target of sortedObjects) {
      if (!target.extractable) continue;
      const candidate = cloneState(state);
      const emitted = addBlob(candidate, wrapper.valueId, target.valueId, bounds.maxBlobs);
      if (!emitted) continue;
      closeKnowledge(candidate);
      next.push({
        state: candidate,
        action: {
          kind: 'WrapKey',
          wrapperHandle: wrapper.id,
          targetHandle: target.id,
          outputBlob: emitted.id,
        },
      });
    }
  }

  if (state.objects.length < bounds.maxHandles) {
    for (const unwrapper of sortedObjects) {
      if (!hasCapability(unwrapper, 'KW_UNWRAP_KEY')) continue;
      for (const wrapped of sortedBlobs) {
        if (wrapped.wrapperValue !== unwrapper.valueId) continue;
        for (const template of TEMPLATES) {
          if (policy === 'fixed-template' && template !== 'data-only') continue;
          const candidate = cloneState(state);
          const outputHandle = `h-new-${candidate.nextHandle}`;
          candidate.nextHandle += 1;
          const templateCapabilities: Record<SearchTemplate, SearchCapability[]> = {
            'data-only': ['GCM_OPEN_DATA'],
            'kw-wrap-only': ['KW_WRAP_KEY'],
            'kw-decrypt-only': ['KW_DECRYPT_BYTES'],
          };
          candidate.objects.push(
            object(outputHandle, wrapped.payloadValue, templateCapabilities[template], false),
          );
          candidate.objects.sort((left, right) => left.id.localeCompare(right.id));
          next.push({
            state: candidate,
            action: {
              kind: 'UnwrapAs',
              keyHandle: unwrapper.id,
              inputBlob: wrapped.id,
              template,
              outputHandle,
            },
          });
        }
      }
    }
  }

  if (scenario === 'mutable-role' && policy === 'per-handle-templates') {
    for (const entry of sortedObjects) {
      if (!hasCapability(entry, 'KW_WRAP_KEY') || hasCapability(entry, 'KW_DECRYPT_BYTES'))
        continue;
      const candidate = cloneState(state);
      const changed = candidate.objects.find((item) => item.id === entry.id)!;
      changed.capabilities = capabilities(...changed.capabilities, 'KW_DECRYPT_BYTES');
      next.push({
        state: candidate,
        action: { kind: 'GrantKwDecrypt', handle: entry.id },
      });
    }
  }

  for (const key of sortedObjects) {
    if (!hasCapability(key, 'KW_DECRYPT_BYTES')) continue;
    for (const wrapped of sortedBlobs) {
      if (wrapped.wrapperValue !== key.valueId || state.knownValues.includes(wrapped.payloadValue))
        continue;
      const candidate = cloneState(state);
      addKnown(candidate, wrapped.payloadValue);
      closeKnowledge(candidate);
      next.push({
        state: candidate,
        action: { kind: 'DecryptBytes', keyHandle: key.id, inputBlob: wrapped.id },
      });
    }
  }

  const priority: Record<SearchAction['kind'], number> = {
    EncryptKnown: 0,
    UnwrapAs: 1,
    WrapKey: 2,
    GrantKwDecrypt: 3,
    DecryptBytes: 4,
  };
  return next.sort((left, right) => priority[left.action.kind] - priority[right.action.kind]);
}

function assertPolicy(policy: SearchPolicy): void {
  if (policy !== 'fixed-template' && policy !== 'per-handle-templates') {
    throw new TypeError('Choose fixed-template or per-handle-templates.');
  }
}

export function describeKeyHandleSearch(scenario: SearchScenario): SearchSetup {
  // Validate the preset through the same initializer used by the explorer.
  initialState(scenario);
  return Object.freeze({
    bounds: resolveBounds({}, scenario),
    invariant: 'protected-target not in attacker-known raw values',
    initialKnowledge: Object.freeze(initialKnowledge(scenario)),
  });
}

/**
 * Exhaustively explores this finite teaching model through the reported bound.
 * This is a reachability check for the displayed alphabet, not a PKCS #11
 * implementation, an unbounded result, or a security proof.
 */
export function exploreKeyHandleStates(
  scenario: SearchScenario,
  policy: SearchPolicy = 'fixed-template',
  options: SearchOptions = {},
): SearchResult {
  assertPolicy(policy);
  const bounds = resolveBounds(options, scenario);
  const initial = initialState(scenario);
  closeKnowledge(initial);
  const queue: { state: SearchState; path: SearchAction[] }[] = [{ state: initial, path: [] }];
  const visited = new Set([canonicalState(initial)]);
  let cursor = 0;
  let transitionsAccepted = 0;
  let deepestCompleted = 0;

  while (cursor < queue.length) {
    const current = queue[cursor++];
    if (current.state.knownValues.includes(TARGET)) {
      return Object.freeze({
        scenario,
        policy,
        bounds,
        invariant: 'protected-target not in attacker-known raw values',
        initialKnowledge: Object.freeze(initialKnowledge(scenario)),
        statesVisited: visited.size,
        transitionsAccepted,
        deepestCompleted: current.path.length,
        verdict: 'witness-found',
        capHit: false,
        witness: Object.freeze([...current.path]),
      });
    }
    if (current.path.length >= bounds.maxSuccessfulCalls) {
      deepestCompleted = Math.max(deepestCompleted, current.path.length);
      continue;
    }
    const outgoing = transitions(current.state, scenario, policy, bounds);
    const witnessIndex = outgoing.findIndex((transition) =>
      transition.state.knownValues.includes(TARGET),
    );
    if (witnessIndex >= 0) {
      transitionsAccepted += witnessIndex + 1;
      const witness = [...current.path, outgoing[witnessIndex].action];
      return Object.freeze({
        scenario,
        policy,
        bounds,
        invariant: 'protected-target not in attacker-known raw values',
        initialKnowledge: Object.freeze(initialKnowledge(scenario)),
        statesVisited: visited.size + 1,
        transitionsAccepted,
        deepestCompleted: witness.length,
        verdict: 'witness-found',
        capHit: false,
        witness: Object.freeze(witness),
      });
    }
    transitionsAccepted += outgoing.length;
    for (const transition of outgoing) {
      const canonical = canonicalState(transition.state);
      if (visited.has(canonical)) continue;
      if (visited.size >= bounds.maxStates) {
        return Object.freeze({
          scenario,
          policy,
          bounds,
          invariant: 'protected-target not in attacker-known raw values',
          initialKnowledge: Object.freeze(initialKnowledge(scenario)),
          statesVisited: visited.size,
          transitionsAccepted,
          deepestCompleted: Math.max(deepestCompleted, current.path.length),
          verdict: 'search-incomplete',
          capHit: true,
          witness: null,
        });
      }
      visited.add(canonical);
      queue.push({ state: transition.state, path: [...current.path, transition.action] });
    }
    deepestCompleted = Math.max(deepestCompleted, current.path.length);
  }

  return Object.freeze({
    scenario,
    policy,
    bounds,
    invariant: 'protected-target not in attacker-known raw values',
    initialKnowledge: Object.freeze(initialKnowledge(scenario)),
    statesVisited: visited.size,
    transitionsAccepted,
    deepestCompleted,
    verdict: 'no-witness-within-bounds',
    capHit: false,
    witness: null,
  });
}

export function formatSearchAction(action: SearchAction): string {
  switch (action.kind) {
    case 'EncryptKnown':
      return `EncryptKnown(${action.keyHandle}, ${action.payloadValue}) -> ${action.outputBlob}`;
    case 'WrapKey':
      return `WrapKey(${action.wrapperHandle}, ${action.targetHandle}) -> ${action.outputBlob}`;
    case 'UnwrapAs':
      return `UnwrapAs(${action.keyHandle}, ${action.inputBlob}, ${action.template}) -> ${action.outputHandle}`;
    case 'GrantKwDecrypt':
      return `GrantKwDecrypt(${action.handle})`;
    case 'DecryptBytes':
      return `DecryptBytes(${action.keyHandle}, ${action.inputBlob}) -> raw key value`;
  }
}

function scenarioValues(scenario: SearchScenario): ValueId[] {
  if (scenario === 'known-key-import') {
    return [TARGET, 'transport-key', 'caller-known-key'];
  }
  if (scenario === 'same-value-handles') {
    return [TARGET, 'transport-key', 'opaque-pivot'];
  }
  return [TARGET, 'transport-key'];
}

function checkedMaterials(
  scenario: SearchScenario,
  factory: SearchKeyFactory,
): Map<ValueId, Uint8Array> {
  const result = new Map<ValueId, Uint8Array>();
  for (const value of scenarioValues(scenario)) {
    const material = factory(value);
    if (!(material instanceof Uint8Array) || material.length !== 32) {
      for (const existing of result.values()) zeroize(existing);
      throw new TypeError('State-search fixtures must return 32-byte AES keys.');
    }
    const copy = material.slice();
    for (const existing of result.values()) {
      if (equalBytes(existing, copy)) {
        zeroize(copy);
        for (const retained of result.values()) zeroize(retained);
        throw new TypeError('State-search key roles require distinct material.');
      }
    }
    result.set(value, copy);
  }
  return result;
}

function verifyWitness(result: SearchResult): readonly SearchAction[] {
  if (
    result.policy !== 'per-handle-templates' ||
    result.verdict !== 'witness-found' ||
    !result.witness
  ) {
    throw new TypeError('Concrete replay requires an unsafe-policy disclosure witness.');
  }
  if (result.witness.length > result.bounds.maxSuccessfulCalls) {
    throw new TypeError('The supplied witness exceeds its declared successful-call bound.');
  }
  let state = initialState(result.scenario);
  closeKnowledge(state);
  for (const expected of result.witness) {
    const match = transitions(state, result.scenario, result.policy, result.bounds).find(
      (candidate) => JSON.stringify(candidate.action) === JSON.stringify(expected),
    );
    if (!match) throw new TypeError('The supplied witness is not a valid transition sequence.');
    state = match.state;
  }
  if (!state.knownValues.includes(TARGET)) {
    throw new TypeError('The supplied witness does not violate the displayed invariant.');
  }
  return result.witness;
}

/** Replay the search-produced witness with real RFC 3394 and AES-256-GCM. */
export async function replayKeyHandleWitness(
  result: SearchResult,
  factory: SearchKeyFactory = randomKey,
): Promise<SearchProof> {
  const witness = verifyWitness(result);
  const materials = checkedMaterials(result.scenario, factory);
  const handles = new Map<string, Uint8Array>();
  const blobs = new Map<string, Uint8Array>();
  const known = new Map<ValueId, Uint8Array>();
  const temporary: Uint8Array[] = [];
  let escaped: Uint8Array | undefined;
  let opened: Uint8Array | undefined;
  let expectedPlaintext: Uint8Array | undefined;
  try {
    handles.set('h-target', materials.get(TARGET)!);
    if (result.scenario === 'mutable-role') {
      handles.set('h-wrapper', materials.get('transport-key')!);
    } else {
      handles.set('h-importer', materials.get('transport-key')!);
    }
    if (result.scenario === 'known-key-import') {
      known.set('caller-known-key', materials.get('caller-known-key')!);
    }
    if (result.scenario === 'same-value-handles') {
      blobs.set(
        blobId('transport-key', 'opaque-pivot'),
        aesKwWrap(materials.get('transport-key')!, materials.get('opaque-pivot')!),
      );
    }

    expectedPlaintext = encoder.encode(
      `Bounded key-handle challenge ${crypto.randomUUID()} (${result.scenario})`,
    );
    const aad = encoder.encode('Envelope KMS bounded key-handle search v1');
    const challenge = await aeadSeal(expectedPlaintext, materials.get(TARGET)!, aad);

    for (const action of witness) {
      if (action.kind === 'EncryptKnown') {
        const key = handles.get(action.keyHandle);
        const payload = known.get(action.payloadValue);
        if (!key || !payload) throw new Error('Concrete EncryptKnown inputs are unavailable.');
        blobs.set(action.outputBlob, aesKwWrap(key, payload));
      } else if (action.kind === 'WrapKey') {
        const wrapper = handles.get(action.wrapperHandle);
        const target = handles.get(action.targetHandle);
        if (!wrapper || !target) throw new Error('Concrete WrapKey inputs are unavailable.');
        blobs.set(action.outputBlob, aesKwWrap(wrapper, target));
      } else if (action.kind === 'UnwrapAs') {
        const key = handles.get(action.keyHandle);
        const wrapped = blobs.get(action.inputBlob);
        if (!key || !wrapped) throw new Error('Concrete UnwrapAs inputs are unavailable.');
        const recovered = aesKwUnwrap(key, wrapped);
        temporary.push(recovered);
        handles.set(action.outputHandle, recovered);
      } else if (action.kind === 'DecryptBytes') {
        const key = handles.get(action.keyHandle);
        const wrapped = blobs.get(action.inputBlob);
        if (!key || !wrapped) throw new Error('Concrete DecryptBytes inputs are unavailable.');
        const recovered = aesKwUnwrap(key, wrapped);
        temporary.push(recovered);
        for (const [value, material] of materials) {
          if (equalBytes(material, recovered)) known.set(value, recovered);
        }
      }

      // Concrete counterpart of the symbolic local-knowledge closure.
      let changed = true;
      while (changed) {
        changed = false;
        for (const [id, wrapped] of blobs) {
          const match = /^kw\(([^,]+),([^)]+)\)$/.exec(id);
          if (!match) continue;
          const wrapperId = match[1] as ValueId;
          const payloadId = match[2] as ValueId;
          if (!known.has(wrapperId) || known.has(payloadId)) continue;
          const recovered = aesKwUnwrap(known.get(wrapperId)!, wrapped);
          temporary.push(recovered);
          if (!equalBytes(recovered, materials.get(payloadId)!)) {
            throw new Error('Concrete AES-KW replay disagrees with the symbolic blob term.');
          }
          known.set(payloadId, recovered);
          changed = true;
        }
      }
    }

    escaped = known.get(TARGET)?.slice();
    if (!escaped || !equalBytes(escaped, materials.get(TARGET)!)) {
      throw new Error('Concrete witness did not recover the protected target.');
    }
    opened = await aeadOpen(challenge.ciphertext, challenge.iv, challenge.tag, escaped, aad);
    if (!equalBytes(opened, expectedPlaintext)) {
      throw new Error('Recovered target opened a different AES-GCM challenge.');
    }

    const sameValueHandles =
      result.scenario === 'same-value-handles'
        ? (witness
            .filter(
              (action): action is Extract<SearchAction, { kind: 'UnwrapAs' }> =>
                action.kind === 'UnwrapAs',
            )
            .slice(0, 2)
            .map((action) => action.outputHandle) as [string, string])
        : null;

    return Object.freeze({
      scenario: result.scenario,
      apiCalls: witness.length,
      wrappedBlobLengths: Object.freeze([...blobs.values()].map((value) => value.length)),
      sameValueHandles: sameValueHandles ? Object.freeze(sameValueHandles) : null,
      escapedKey: escaped.slice(),
      expectedPlaintext: expectedPlaintext.slice(),
      challenge: Object.freeze({
        iv: challenge.iv.slice(),
        ciphertext: challenge.ciphertext.slice(),
        tag: challenge.tag.slice(),
        aad: aad.slice(),
      }),
    });
  } finally {
    if (escaped) zeroize(escaped);
    if (opened) zeroize(opened);
    if (expectedPlaintext) zeroize(expectedPlaintext);
    for (const value of temporary) zeroize(value);
    for (const value of materials.values()) zeroize(value);
  }
}
