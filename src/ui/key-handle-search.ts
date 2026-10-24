import { bytesToHex, decoder, zeroize } from '../crypto/bytes';
import {
  STATE_SEARCH_RULES,
  describeKeyHandleSearch,
  exploreKeyHandleStates,
  formatSearchAction,
  replayKeyHandleWitness,
  type SearchPolicy,
  type SearchProof,
  type SearchResult,
  type SearchScenario,
} from '../kms/key-handle-search';
import './key-handle-search.css';

type Outcome = 'ready' | 'protected' | 'exposed' | 'incomplete' | 'error';

const SCENARIOS: Readonly<
  Record<SearchScenario, Readonly<{ title: string; summary: string; source: string }>>
> = Object.freeze({
  'mutable-role': {
    title: 'Mutable wrapping role',
    summary:
      'Re-search the first exercise: wrap the target, add byte-returning AES-KW decrypt permission, then decrypt the blob.',
    source: 'The manual trace above, now checked as a reachability problem.',
  },
  'known-key-import': {
    title: 'Known-key import and template confusion',
    summary:
      'The attacker imports a key whose bytes they already know, asks for a wrapping role, and tries to export the protected target under it.',
    source: 'Adapted from Delaune, Kremer and Steel, journal Figure 3.',
  },
  'same-value-handles': {
    title: 'Same-value handles with conflicting roles',
    summary:
      'The same opaque wrapped value is unwrapped twice into distinct handles, then given wrapping and byte-returning decrypt roles.',
    source: 'Adapted from Delaune, Kremer and Steel, journal Figure 5.',
  },
});

const escape = (value: string): string =>
  value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

function clearProof(proof: SearchProof): void {
  zeroize(proof.escapedKey);
  zeroize(proof.expectedPlaintext);
  zeroize(proof.challenge.iv);
  zeroize(proof.challenge.ciphertext);
  zeroize(proof.challenge.tag);
  zeroize(proof.challenge.aad);
}

function proofMarkup(proof: SearchProof): string {
  const expected = escape(decoder.decode(proof.expectedPlaintext));
  const escaped = bytesToHex(proof.escapedKey);
  const challenge = proof.challenge;
  return `<div class="state-search-proof">
    <p><strong>Concrete replay:</strong> The ${proof.apiCalls}-call replay used ${proof.wrappedBlobLengths.length} real RFC 3394 blob(s), including any preset fixture. Their lengths were ${proof.wrappedBlobLengths.map((length) => `${length} bytes`).join(', ')}. The escaped 32-byte target independently opened the exact AES-256-GCM challenge below.</p>
    ${proof.sameValueHandles ? `<p id="state-search-alias-proof">Distinct handles <code>${escape(proof.sameValueHandles[0])}</code> and <code>${escape(proof.sameValueHandles[1])}</code> contained equal key bytes but received different per-handle roles.</p>` : ''}
    <dl class="state-search-wire">
      <div><dt>Escaped synthetic target key</dt><dd><code id="state-search-escaped-key">${escaped}</code></dd></div>
      <div><dt>Expected synthetic message</dt><dd><code id="state-search-expected-plaintext">${expected}</code></dd></div>
      <div><dt>Challenge IV (hex)</dt><dd><code id="state-search-challenge-iv">${bytesToHex(challenge.iv)}</code></dd></div>
      <div><dt>Challenge ciphertext (hex)</dt><dd><code id="state-search-challenge-ciphertext">${bytesToHex(challenge.ciphertext)}</code></dd></div>
      <div><dt>Challenge tag (hex)</dt><dd><code id="state-search-challenge-tag">${bytesToHex(challenge.tag)}</code></dd></div>
      <div><dt>Challenge AAD (hex)</dt><dd><code id="state-search-challenge-aad">${bytesToHex(challenge.aad)}</code></dd></div>
    </dl>
  </div>`;
}

function resultMessage(result: SearchResult): string {
  if (result.verdict === 'witness-found') {
    return `DISCLOSURE WITNESS FOUND at depth ${result.witness!.length}: protected-target entered attacker-known raw values.`;
  }
  if (result.verdict === 'search-incomplete') {
    return `SEARCH INCOMPLETE: stopped at the ${result.bounds.maxStates.toLocaleString()} retained-non-witness-state cap. No safety conclusion is available.`;
  }
  return `No disclosure found in all ${result.statesVisited.toLocaleString()} distinct states through ${result.bounds.maxSuccessfulCalls} successful API calls under the displayed alphabet and object bounds.`;
}

/** A stable component: unrelated envelope actions preserve the completed search. */
export function keyHandleSearchPanel(): HTMLElement {
  const panel = document.createElement('section');
  panel.className = 'panel key-state-search';
  panel.id = 'key-handle-state-search';
  panel.setAttribute('aria-labelledby', 'state-search-heading');
  panel.innerHTML = `<h2 id="state-search-heading">Can another call sequence expose it?</h2>
    <p class="panel-lede">A breadth-first explorer now checks more than one handwritten trace. It tracks raw key values separately from handles, so two distinct handles can contain equal bytes while carrying different permissions.</p>
    <div class="state-search-controls">
      <label for="state-search-scenario">Search preset<select id="state-search-scenario" class="chip">
        <option value="known-key-import">Known-key import</option>
        <option value="same-value-handles">Same-value handles</option>
        <option value="mutable-role">Mutable wrapping role</option>
      </select></label>
      <label for="state-search-policy">API and key-role policy<select id="state-search-policy" class="chip">
        <option value="fixed-template">Fixed roles + fixed data-only unwrap template (default)</option>
        <option value="per-handle-templates">Unsafe preset rules: mutable roles / caller templates</option>
      </select></label>
      <label for="state-search-cap">Operational state cap<select id="state-search-cap" class="chip">
        <option value="50000">50,000 retained non-witness states (default)</option>
        <option value="1">1 retained non-witness state (demonstrate incomplete)</option>
      </select></label>
    </div>
    <p id="state-search-policy-note"></p>
    <section class="state-search-model" aria-labelledby="state-search-model-heading">
      <h3 id="state-search-model-heading"></h3>
      <p id="state-search-scenario-summary"></p>
      <p id="state-search-scenario-source"></p>
      <dl class="state-search-bounds"></dl>
      <h4>Initial attacker knowledge</h4><ul id="state-search-knowledge"></ul>
      <h4>Transition alphabet</h4><ol id="state-search-rules">${STATE_SEARCH_RULES.map((entry) => `<li><strong>${escape(entry.name)}:</strong> ${escape(entry.rule)}</li>`).join('')}</ol>
    </section>
    <div class="controls-row"><button id="state-search-run" class="chip" type="button">Explore bounded state space</button>
      <button id="state-search-reset" class="chip ghost" type="button">Reset this search</button></div>
    <div id="state-search-outcome" class="state-search-outcome" data-outcome="ready">
      <p id="state-search-status" role="status" aria-live="polite">Not run.</p>
      <div id="state-search-evidence"></div>
    </div>
    <ol id="state-search-witness" class="state-search-witness" aria-label="Shortest disclosure witness"></ol>
    <p id="state-search-invariant" class="state-search-invariant"></p>
    <p id="state-search-limit" class="state-search-limit">This is a bounded browser model inspired by historical cryptographic-API analyses. It is not a PKCS #11 implementation, HSM assessment, vendor vulnerability claim, exhaustive search, or security proof. The fixed roles and fixed unwrap template block the modeled traces; they do not establish security for unmodeled operations, mechanisms, sessions, authentication, concurrency, runtime compromise, or side channels.</p>
    <p id="state-search-scope">The operation names are mechanism-qualified: AES-KW byte decryption is not AES-GCM data opening. “Same-value handles” means distinct objects containing equal key bytes, not two handles to one PKCS #11 object. RFC 3394 integrity-checks the 32 key bytes in this implementation's blob; caller-selected role metadata is outside that blob.</p>
    <p class="state-search-sources">Primary sources: <a href="https://lsv.ens-paris-saclay.fr/Publis/PAPERS/PDF/DKS-jcs09.pdf">Delaune, Kremer and Steel, Formal Security Analysis of PKCS#11 and Proprietary Extensions</a>; <a href="https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html">OASIS PKCS #11 v3.2</a>; and <a href="https://www.rfc-editor.org/rfc/rfc3394.html">RFC 3394</a>.</p>`;

  const scenarioSelect = panel.querySelector<HTMLSelectElement>('#state-search-scenario')!;
  const policySelect = panel.querySelector<HTMLSelectElement>('#state-search-policy')!;
  const capSelect = panel.querySelector<HTMLSelectElement>('#state-search-cap')!;
  const controls = Array.from(
    panel.querySelectorAll<HTMLButtonElement | HTMLSelectElement>('button, select'),
  );
  const policyNote = panel.querySelector<HTMLElement>('#state-search-policy-note')!;
  const modelHeading = panel.querySelector<HTMLElement>('#state-search-model-heading')!;
  const scenarioSummary = panel.querySelector<HTMLElement>('#state-search-scenario-summary')!;
  const scenarioSource = panel.querySelector<HTMLElement>('#state-search-scenario-source')!;
  const boundsView = panel.querySelector<HTMLElement>('.state-search-bounds')!;
  const knowledgeView = panel.querySelector<HTMLElement>('#state-search-knowledge')!;
  const outcomeView = panel.querySelector<HTMLElement>('#state-search-outcome')!;
  const status = panel.querySelector<HTMLElement>('#state-search-status')!;
  const evidence = panel.querySelector<HTMLElement>('#state-search-evidence')!;
  const witnessView = panel.querySelector<HTMLOListElement>('#state-search-witness')!;
  const invariantView = panel.querySelector<HTMLElement>('#state-search-invariant')!;
  let scenario: SearchScenario = 'known-key-import';
  let policy: SearchPolicy = 'fixed-template';
  let stateCap = 50_000;
  let outcome: Outcome = 'ready';
  let message = 'Not run. Choose a preset and policy, then start the explorer.';
  let evidenceMarkup = '';
  let witness: readonly string[] = [];

  function renderModel(): void {
    const meta = SCENARIOS[scenario];
    const setup = describeKeyHandleSearch(scenario);
    modelHeading.textContent = meta.title;
    scenarioSummary.textContent = meta.summary;
    scenarioSource.textContent = meta.source;
    boundsView.innerHTML = `<div><dt>Invariant</dt><dd><code>${escape(setup.invariant)}</code></dd></div>
      <div><dt>Search depth</dt><dd>${setup.bounds.maxSuccessfulCalls} successful API calls, breadth first</dd></div>
      <div><dt>Object bounds</dt><dd>${setup.bounds.atomicValues} atomic values, at most ${setup.bounds.maxHandles} handles and ${setup.bounds.maxBlobs} blobs</dd></div>
      <div><dt>Finite templates</dt><dd>${setup.bounds.templates}: data-only, KW-wrap-only, KW-decrypt-to-bytes-only</dd></div>
      <div><dt>Operational cap</dt><dd>Up to ${stateCap.toLocaleString()} retained non-witness states; every generated successor is checked for a terminal witness before retention. Hitting the cap is “incomplete,” never “safe.”</dd></div>`;
    knowledgeView.innerHTML = setup.initialKnowledge
      .map((entry) => `<li>${escape(entry)}</li>`)
      .join('');
    invariantView.textContent = `Claim checked: ${setup.invariant}. Rejected calls do not change state; successful calls consume depth.`;
    policyNote.textContent =
      policy === 'fixed-template'
        ? 'Fixed policy: roles cannot escalate, and unwrap accepts only a sensitive, nonextractable GCM data handle. Conflicting caller templates are rejected without allocating an object.'
        : 'Intentionally unsafe preset rules: caller-selected templates create independent per-handle permissions in the import presets; the mutable-role preset may add byte-returning AES-KW decrypt permission to a wrapping handle.';
    policyNote.className = policy === 'per-handle-templates' ? 'state-search-warning' : '';
  }

  function renderResult(): void {
    outcomeView.dataset.outcome = outcome;
    status.textContent = message;
    evidence.innerHTML = evidenceMarkup;
    witnessView.innerHTML = witness
      .map(
        (entry, index) =>
          `<li><span class="state-search-step">Call ${index + 1}</span><code>${escape(entry)}</code></li>`,
      )
      .join('');
  }

  function retire(nextMessage: string): void {
    outcome = 'ready';
    message = nextMessage;
    evidenceMarkup = '';
    witness = [];
    renderModel();
    renderResult();
  }

  async function execute(): Promise<void> {
    const startingFocus = document.activeElement;
    controls.forEach((control) => {
      control.disabled = true;
    });
    outcome = 'ready';
    message = 'Exploring the finite state graph…';
    evidenceMarkup = '';
    witness = [];
    renderResult();
    try {
      const result = exploreKeyHandleStates(scenario, policy, { maxStates: stateCap });
      message = resultMessage(result);
      witness = result.witness?.map(formatSearchAction) ?? [];
      if (result.verdict === 'witness-found') {
        const proof = await replayKeyHandleWitness(result);
        try {
          evidenceMarkup = `<p>Retained ${(result.statesVisited - 1).toLocaleString()} non-witness states, then checked the terminal witness (the ${result.statesVisited.toLocaleString()}th distinct state), and accepted ${result.transitionsAccepted.toLocaleString()} transition instances before stopping. Symbolic reachability and concrete cryptographic replay are separate checks.</p>${proofMarkup(proof)}`;
        } finally {
          clearProof(proof);
        }
        outcome = 'exposed';
      } else if (result.verdict === 'search-incomplete') {
        outcome = 'incomplete';
        evidenceMarkup = `<p>Visited ${result.statesVisited.toLocaleString()} states. Increase or simplify the declared model before drawing a bounded conclusion.</p>`;
      } else {
        outcome = 'protected';
        evidenceMarkup = `<p id="state-search-complete">Complete within these bounds: ${result.statesVisited.toLocaleString()} distinct states visited, ${result.transitionsAccepted.toLocaleString()} accepted transition instances, and no state placed the protected target in attacker knowledge. This does not cover calls or resources outside the displayed model.</p>`;
      }
    } catch (error) {
      outcome = 'error';
      message = `Search error: ${error instanceof Error ? error.message : String(error)} No verdict is available.`;
      evidenceMarkup = '';
      witness = [];
    } finally {
      renderResult();
      controls.forEach((control) => {
        control.disabled = false;
      });
      if (
        startingFocus instanceof HTMLElement &&
        panel.isConnected &&
        (document.activeElement === document.body || document.activeElement === startingFocus)
      ) {
        startingFocus.focus();
      }
    }
  }

  scenarioSelect.addEventListener('change', () => {
    const next = scenarioSelect.value as SearchScenario;
    if (next === scenario) return;
    scenario = next;
    retire('Previous result retired. Run the new search preset.');
  });
  policySelect.addEventListener('change', () => {
    const next: SearchPolicy =
      policySelect.value === 'per-handle-templates' ? 'per-handle-templates' : 'fixed-template';
    if (next === policy) return;
    policy = next;
    retire('Previous result retired. Run the new API and key-role policy.');
  });
  capSelect.addEventListener('change', () => {
    const next = capSelect.value === '1' ? 1 : 50_000;
    if (next === stateCap) return;
    stateCap = next;
    retire('Previous result retired. Run with the new operational state cap.');
  });
  panel.querySelector('#state-search-run')!.addEventListener('click', () => {
    void execute();
  });
  panel.querySelector('#state-search-reset')!.addEventListener('click', () => {
    scenario = 'known-key-import';
    policy = 'fixed-template';
    stateCap = 50_000;
    scenarioSelect.value = scenario;
    policySelect.value = policy;
    capSelect.value = String(stateCap);
    retire('Reset: default preset and fixed template restored.');
  });

  renderModel();
  renderResult();
  return panel;
}
