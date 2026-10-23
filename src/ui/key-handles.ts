import { aeadOpen } from '../crypto/aead';
import './key-handles.css';
import { bytesToHex, decoder, encoder, equalBytes, zeroize } from '../crypto/bytes';
import {
  ApiPolicyError,
  HandleToken,
  type HandleChallenge,
  type HandlePolicy,
  type KeyDescription,
} from '../kms/key-handles';

const KEY_DISCLOSURE_LIMIT =
  'Valid cryptographic checks do not prevent key disclosure when this API permits conflicting operations.';

type TraceRow = { operation: string; result: string; detail: string };
type Outcome =
  'ready' | 'blocked-role' | 'blocked-target' | 'exposed' | 'protected-handle' | 'error';

const escape = (value: string): string =>
  value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

function keyCard(title: string, key: KeyDescription): string {
  const yes = (value: boolean): string => (value ? 'yes' : 'no');
  return `<article class="handle-key" data-key-role="${key.role}">
    <h3>${title}</h3><code class="handle-id">${key.handle}</code>
    <dl><div><dt>Mechanism</dt><dd>${key.mechanism}</dd></div>
      <div><dt>Direct value read</dt><dd>forbidden (sensitive)</dd></div>
      <div><dt>May be wrapped</dt><dd>${yes(key.extractable)}</dd></div>
      <div><dt>Wrap / unwrap keys</dt><dd>${yes(key.wrap)} / ${yes(key.unwrap)}</dd></div>
      <div><dt>Decrypt to bytes</dt><dd class="handle-decrypt">${yes(key.decrypt)}</dd></div></dl>
    <p>${key.role === 'wrapping-key' ? 'Starts with wrap and unwrap permission. The trace tries to add byte-returning decrypt permission to this same key.' : 'The data role may open messages. That permission does not reveal its own key value.'}</p>
  </article>`;
}

/** A stable component: unrelated envelope actions preserve its current experiment. */
export function keyHandlesPanel(): HTMLElement {
  const panel = document.createElement('section');
  panel.className = 'panel key-handles';
  panel.id = 'key-handles-lab';
  panel.setAttribute('aria-labelledby', 'key-handles-heading');
  panel.innerHTML = `<h2 id="key-handles-heading">What may this key do?</h2>
    <p class="panel-lede">A key handle is a reference you can use without reading the key. Can a sequence of allowed operations still expose its bytes? Try the same AES Key Wrap mechanism as both <strong>WrapKey</strong> and byte-returning <strong>Decrypt</strong>.</p>
    <div class="handle-controls">
      <label for="handle-policy">Key usage policy<select id="handle-policy" class="chip"><option value="fixed-roles">Fixed roles (default)</option><option value="mutable-usages">Mutable usages (intentionally unsafe)</option></select></label>
      <label for="handle-target">Target key protection<select id="handle-target" class="chip"><option value="wrappable">Sensitive, but wrappable</option><option value="nonextractable">Sensitive and nonextractable</option></select></label>
    </div>
    <p id="handle-policy-note"></p>
    <div class="controls-row"><button id="handle-attack" class="chip" type="button">Run wrap-then-decrypt trace</button>
      <button id="handle-legitimate" class="chip" type="button">Wrap and unwrap to a handle</button>
      <button id="handle-reset" class="chip ghost" type="button">Reset this exercise</button></div>
    <div id="handle-keys" class="handle-keys"></div>
    <div id="handle-outcome" class="handle-outcome" data-outcome="ready"><p id="handle-status" role="status" aria-live="polite">Not run.</p><div id="handle-proof"></div></div>
    <ol id="handle-trace" class="handle-trace" aria-label="Executed API calls"></ol>
    <div id="handle-wire"></div>
    <p id="handle-limit" class="handle-limit">${KEY_DISCLOSURE_LIMIT}</p>
    <p id="handle-scope">Not production crypto: this is one executed trace in a small browser model. Fixed roles block this trace with internally generated, nonexportable wrapping keys; they are not a proof for every key API. General import, copy, derive and hardware isolation are outside this model. Every run uses fresh synthetic keys.</p>
    <details class="handle-model-details"><summary>Why sensitive and nonextractable differ</summary>
      <p><strong>Sensitive</strong> forbids directly reading the key value. A sensitive key with <code>extractable=true</code> may still be wrapped. Setting <code>extractable=false</code> refuses wrapping under either policy. The model's protected unwrap returns a fresh sensitive, nonextractable data handle for the same key bytes; it cannot revoke an existing copy.</p>
      <p>PKCS #11 allows a token to restrict changes to usage attributes. The unsafe choice here models a permissive configuration; it does not describe every token. The normal envelope API elsewhere in this lab deliberately returns raw DEKs and has a different contract.</p>
      <p><a href="https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html">OASIS PKCS #11 v3.0 mechanisms §2.16.3</a> permits AES-KW for wrap/unwrap and single-part encrypt/decrypt. <a href="https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html">The base specification §4.10 and §5.21.3</a> defines sensitive keys and wrapping permissions.</p>
    </details>`;

  const policySelect = panel.querySelector<HTMLSelectElement>('#handle-policy')!;
  const targetSelect = panel.querySelector<HTMLSelectElement>('#handle-target')!;
  const controls = Array.from(
    panel.querySelectorAll<HTMLButtonElement | HTMLSelectElement>('button, select'),
  );
  const keys = panel.querySelector<HTMLElement>('#handle-keys')!;
  const policyNote = panel.querySelector<HTMLElement>('#handle-policy-note')!;
  const status = panel.querySelector<HTMLElement>('#handle-status')!;
  const proof = panel.querySelector<HTMLElement>('#handle-proof')!;
  const traceView = panel.querySelector<HTMLOListElement>('#handle-trace')!;
  const wire = panel.querySelector<HTMLElement>('#handle-wire')!;
  const outcomeView = panel.querySelector<HTMLElement>('#handle-outcome')!;
  let policy: HandlePolicy = 'fixed-roles';
  let extractable = true;
  let token = new HandleToken(policy, extractable);
  let trace: TraceRow[] = [];
  let challenge: HandleChallenge | undefined;
  let wrapped: Uint8Array | undefined;
  let plaintext = '';
  let outcome: Outcome = 'ready';
  let message = 'Not run. Choose a policy, then execute a trace.';
  let proofMarkup = '';

  function render(): void {
    keys.innerHTML =
      keyCard('Wrapping key', token.describe(token.wrapperHandle)) +
      keyCard('Target data key', token.describe(token.targetHandle));
    policyNote.textContent =
      policy === 'fixed-roles'
        ? 'Fixed roles: wrapping keys cannot gain byte-returning decrypt permission. Intended wrap/unwrap remains available.'
        : 'Intentionally unsafe: the same wrapping key may gain byte-returning decrypt permission. A successful cryptographic check can still expose the target.';
    policyNote.className = policy === 'mutable-usages' ? 'handle-warning' : '';
    outcomeView.dataset.outcome = outcome;
    status.textContent = message;
    proof.innerHTML = proofMarkup;
    traceView.innerHTML = trace
      .map(
        (row) =>
          `<li data-operation="${escape(row.operation)}"><div><strong>${escape(row.operation)}</strong><code>${escape(row.result)}</code></div><p>${escape(row.detail)}</p></li>`,
      )
      .join('');
    wire.innerHTML = challenge
      ? `<details id="handle-wire-details"><summary>Inspect this run's challenge and wrapped bytes</summary>
      <p>A fresh synthetic message is sealed under the target handle with AES-256-GCM. Opening it outside the handle API demonstrates useful key disclosure.</p>
      <dl class="handle-wire-fields"><div><dt>Expected synthetic message</dt><dd><code id="handle-expected-plaintext">${escape(plaintext)}</code></dd></div>
        ${(['iv', 'ciphertext', 'tag', 'aad'] as const).map((name) => `<div><dt>Challenge ${name} (hex)</dt><dd><code id="handle-challenge-${name}">${bytesToHex(challenge![name])}</code></dd></div>`).join('')}
        ${wrapped ? `<div><dt>Wrapped target (40 bytes, RFC 3394)</dt><dd><code id="handle-wrapped">${bytesToHex(wrapped)}</code></dd></div>` : ''}</dl></details>`
      : '';
  }

  function freshSession(nextMessage: string): void {
    token = new HandleToken(policy, extractable);
    trace = [];
    challenge = undefined;
    wrapped = undefined;
    plaintext = '';
    outcome = 'ready';
    message = nextMessage;
    proofMarkup = '';
    render();
  }

  function recordError(operation: string, error: unknown): ApiPolicyError {
    if (!(error instanceof ApiPolicyError)) throw error;
    trace.push({ operation, result: error.code, detail: error.message });
    return error;
  }

  async function execute(legitimate: boolean): Promise<void> {
    const startingFocus = document.activeElement;
    freshSession('Running the actual API calls…');
    controls.forEach((control) => {
      control.disabled = true;
    });
    try {
      plaintext = `Synthetic challenge ${bytesToHex(crypto.getRandomValues(new Uint8Array(12)))}`;
      challenge = await token.sealChallenge(token.targetHandle, encoder.encode(plaintext));
      trace.push({
        operation: 'SealChallenge',
        result: 'OK',
        detail: 'Target handle sealed a fresh message with AES-256-GCM.',
      });
      try {
        token.readValue(token.targetHandle);
        throw new Error('Direct key reading unexpectedly returned instead of refusing.');
      } catch (error) {
        if (recordError('ReadValue', error).code !== 'SENSITIVE_VALUE') throw error;
      }
      try {
        wrapped = token.wrapKey(token.wrapperHandle, token.targetHandle);
        trace.push({
          operation: 'WrapKey',
          result: 'OK',
          detail: `AES-KW returned ${wrapped.length} wrapped bytes; target value remains unreadable directly.`,
        });
      } catch (error) {
        if (recordError('WrapKey', error).code !== 'KEY_NOT_EXTRACTABLE') throw error;
        outcome = 'blocked-target';
        message =
          'Wrapping refused: the target is nonextractable. No wrapped key or plaintext key was returned.';
        return;
      }
      if (legitimate) {
        const restoredHandle = token.unwrapKey(token.wrapperHandle, wrapped);
        const restored = token.describe(restoredHandle);
        trace.push({
          operation: 'UnwrapKey',
          result: 'OK',
          detail: `Integrity check passed. Created sensitive, nonextractable data handle ${restoredHandle}.`,
        });
        try {
          token.readValue(restoredHandle);
          throw new Error('The restored handle unexpectedly allowed direct key reading.');
        } catch (error) {
          if (recordError('ReadRestoredValue', error).code !== 'SENSITIVE_VALUE') throw error;
        }
        const opened = await token.openChallenge(restoredHandle, challenge);
        try {
          if (!equalBytes(opened, encoder.encode(plaintext)))
            throw new Error('The restored handle opened a different message.');
          trace.push({
            operation: 'OpenChallenge',
            result: 'OK',
            detail:
              'The new protected handle opened the exact challenge; no key value was returned.',
          });
          outcome = 'protected-handle';
          message =
            'Intended use succeeds: unwrap created a protected handle that opens the challenge.';
          proofMarkup = `<p>Restored handle: <code id="handle-restored">${restored.handle}</code></p><p>Sensitive: ${String(restored.sensitive)} · Extractable: ${String(restored.extractable)}</p><p>Recovered message: <code id="handle-legitimate-message">${escape(decoder.decode(opened))}</code></p>`;
        } finally {
          zeroize(opened);
        }
        return;
      }
      try {
        token.allowDecrypt(token.wrapperHandle);
        trace.push({
          operation: 'AddDecryptPermission',
          result: 'OK',
          detail: 'Wrapping key changed: decrypt to bytes no → yes; wrap and unwrap remain yes.',
        });
      } catch (error) {
        if (recordError('AddDecryptPermission', error).code !== 'ROLE_LOCKED') throw error;
        // Execute the attempted decrypt too: the refusal must preserve the old permission.
        try {
          const unexpectedBytes = token.decryptBytes(token.wrapperHandle, wrapped);
          zeroize(unexpectedBytes);
        } catch (decryptError) {
          if (recordError('Decrypt', decryptError).code !== 'OPERATION_NOT_PERMITTED')
            throw decryptError;
          outcome = 'blocked-role';
          message =
            'Trace blocked: the wrapping role stayed fixed, and byte-returning decrypt was refused. Try protected unwrap to check intended use.';
          return;
        }
        throw new Error('Decrypt returned bytes despite the rejected permission change.', {
          cause: error,
        });
      }
      const recovered = token.decryptBytes(token.wrapperHandle, wrapped);
      try {
        trace.push({
          operation: 'Decrypt',
          result: 'OK',
          detail: `The same AES-KW mechanism passed its integrity check and returned ${recovered.length} plaintext key bytes.`,
        });
        const opened = await aeadOpen(
          challenge.ciphertext,
          challenge.iv,
          challenge.tag,
          recovered,
          challenge.aad,
        );
        try {
          if (!equalBytes(opened, encoder.encode(plaintext)))
            throw new Error('Recovered bytes opened a different challenge.');
          const recoveredHex = bytesToHex(recovered);
          trace.push({
            operation: 'OpenOutsideToken',
            result: 'OK',
            detail: 'The returned bytes opened the exact AES-GCM challenge outside the handle API.',
          });
          outcome = 'exposed';
          message = `KEY EXPOSED: ${recovered.length} bytes escaped and opened the challenge. Every permitted cryptographic operation succeeded.`;
          proofMarkup = `<p>Escaped synthetic key (${recovered.length} bytes): <code id="handle-escaped-key">${recoveredHex}</code></p><p>Recovered message: <code id="handle-recovered-message">${escape(decoder.decode(opened))}</code></p>`;
        } finally {
          zeroize(opened);
        }
      } finally {
        zeroize(recovered);
      }
    } catch (error) {
      outcome = 'error';
      message = `Experiment error: ${error instanceof Error ? error.message : String(error)} No security verdict is available.`;
      proofMarkup = '';
    } finally {
      render();
      controls.forEach((control) => {
        control.disabled = false;
      });
      if (
        startingFocus instanceof HTMLElement &&
        panel.isConnected &&
        (document.activeElement === document.body || document.activeElement === startingFocus)
      )
        startingFocus.focus();
    }
  }

  const changeOptions = (): void => {
    const nextPolicy: HandlePolicy =
      policySelect.value === 'mutable-usages' ? 'mutable-usages' : 'fixed-roles';
    const nextExtractable = targetSelect.value === 'wrappable';
    if (nextPolicy === policy && nextExtractable === extractable) return;
    policy = nextPolicy;
    extractable = nextExtractable;
    freshSession('Previous results retired. Run the new configuration.');
  };
  policySelect.addEventListener('change', changeOptions);
  targetSelect.addEventListener('change', changeOptions);
  panel.querySelector('#handle-attack')!.addEventListener('click', () => {
    void execute(false);
  });
  panel.querySelector('#handle-legitimate')!.addEventListener('click', () => {
    void execute(true);
  });
  panel.querySelector('#handle-reset')!.addEventListener('click', () => {
    freshSession('Reset: new handles; previous results retired.');
  });
  render();
  return panel;
}
