import { decoder, encoder } from './crypto/bytes';
import { runRfcVectors } from './crypto/rfc-vectors';
import { open } from './envelope/open';
import { rewrapEnvelope } from './envelope/rotate';
import { seal, type EnvelopeRecord } from './envelope/seal';
import { auditLog } from './kms/audit-log';
import { kmsApi } from './kms/kms-api';
import { kekStore } from './kms/kek-store';
import { customerManagedKeysScenario } from './scenarios/customer-managed-keys';
import { multiRegionScenario } from './scenarios/multi-region';
import { rotationDrillScenario } from './scenarios/rotation-drill';
import { singleTenantScenario } from './scenarios/single-tenant';
import { renderAuditView } from './ui/audit-view';
import { renderHierarchyView } from './ui/hierarchy-view';
import { renderRequestFlow } from './ui/request-flow';
import { renderRotationPanel } from './ui/rotation-panel';

function b64(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += String.fromCharCode(b);
  return btoa(out);
}

function fromB64(text: string): Uint8Array {
  const decoded = atob(text);
  const out = new Uint8Array(decoded.length);
  for (let i = 0; i < decoded.length; i += 1) out[i] = decoded.charCodeAt(i);
  return out;
}

type AppState = {
  keyId: string | null;
  envelopes: EnvelopeRecord[];
  timeline: string[];
  flow: string;
};

const state: AppState = {
  keyId: null,
  envelopes: [],
  timeline: ['Ready'],
  flow: 'GenerateDataKey',
};

function envelopeInspector(envelopes: EnvelopeRecord[]): string {
  if (envelopes.length === 0) {
    return '<p>No envelope yet. Click "Generate + Seal".</p>';
  }
  const env = envelopes[envelopes.length - 1];
  const payload = {
    ciphertext: b64(env.ciphertext),
    iv: b64(env.iv),
    tag: b64(env.tag),
    wrappedDEK: b64(env.wrappedDEK),
    kekId: env.kekId,
    kekVersion: env.kekVersion,
    aad: b64(env.aad),
  };
  return `<pre>${JSON.stringify(payload, null, 2)}</pre>
  <ul class="bytes-legend">
    <li>iv: 12 bytes</li>
    <li>tag: 16 bytes</li>
    <li>wrappedDEK: 40 bytes (for 32-byte DEK under RFC 3394)</li>
  </ul>`;
}

function comparisonPanel(): string {
  return `<section class="panel">
    <h2>KMS Comparison</h2>
    <div class="table-scroll-hint" aria-hidden="true">← scroll →</div>
    <table class="comparison-table" aria-label="KMS provider feature comparison">
      <caption class="sr-only">Side-by-side comparison of AWS KMS, Google Cloud KMS, Azure Key Vault, and HashiCorp Vault transit engine.</caption>
      <thead>
        <tr>
          <th scope="col">Feature</th>
          <th scope="col">AWS KMS</th>
          <th scope="col">Google Cloud KMS</th>
          <th scope="col">Azure Key Vault</th>
          <th scope="col">HashiCorp Vault (transit)</th>
        </tr>
      </thead>
      <tbody>
        <tr><th scope="row">Envelope pattern</th><td>Data keys via GenerateDataKey [1]</td><td>Envelope model in docs [2]</td><td>Wrap/unwrap key APIs [3]</td><td>Transit encrypt/decrypt [4]</td></tr>
        <tr><th scope="row">Default symmetric algorithm</th><td>AES-256 for symmetric KMS keys [1]</td><td>AES-256 for software/HSM symmetric keys [2]</td><td>AES key wrap / RSA wrap options [3]</td><td>AES-GCM96 for transit data keys [4]</td></tr>
        <tr><th scope="row">Rotation model</th><td>Automatic or on-demand key rotation [1]</td><td>Scheduled/manual version rotation [2]</td><td>Versioned keys with rotation policies [3]</td><td>Versioned key rotation endpoint [4]</td></tr>
        <tr><th scope="row">Audit integration</th><td>CloudTrail [1]</td><td>Cloud Audit Logs [2]</td><td>Azure Monitor diagnostics [3]</td><td>Audit devices [4]</td></tr>
        <tr><th scope="row">BYOK/HYOK support</th><td>BYOK import + external key store [1]</td><td>Import jobs + EKM [2]</td><td>BYOK and managed HSM options [3]</td><td>Customer-managed deployment [4]</td></tr>
        <tr><th scope="row">FIPS 140-3 level</th><td>HSM-backed tiers documented by region [1]</td><td>Cloud HSM tiers documented [2]</td><td>Managed HSM validation docs [3]</td><td>Depends on underlying HSM boundary [4]</td></tr>
        <tr><th scope="row">Typical latency per call</th><td>Single-digit to low tens of ms [1]</td><td>Low tens of ms typical [2]</td><td>Single-digit to tens of ms [3]</td><td>Deployment dependent [4]</td></tr>
      </tbody>
    </table>
    <p class="citations">[1] AWS KMS docs, [2] Google Cloud KMS docs, [3] Azure Key Vault docs, [4] Vault transit docs.</p>
  </section>`;
}

function architectureDiagram(): string {
  return `<section class="panel">
    <h2>Architecture Diagram</h2>
    <svg class="arch-svg" viewBox="0 0 980 360" role="img" aria-label="Envelope encryption architecture">
      <rect x="36" y="120" width="200" height="80" rx="12" class="node-root" />
      <text x="56" y="166" class="node-text">Client App</text>
      <rect x="388" y="48" width="220" height="90" rx="12" class="node-kek" />
      <text x="410" y="86" class="node-text">KMS API</text>
      <text x="410" y="108" class="node-subtext">GenerateDataKey / Decrypt / ReEncrypt</text>
      <rect x="730" y="120" width="220" height="80" rx="12" class="node-root" />
      <text x="760" y="165" class="node-text">Storage</text>
      <line x1="236" y1="145" x2="388" y2="90" class="edge" />
      <text x="250" y="120" class="node-subtext">AWS GenerateDataKey</text>
      <line x1="236" y1="175" x2="730" y2="160" class="edge" />
      <text x="430" y="184" class="node-subtext">put ciphertext + wrapped DEK</text>
      <line x1="730" y1="136" x2="608" y2="108" class="edge" />
      <text x="592" y="90" class="node-subtext">AWS Decrypt / GCP decrypt / Azure unwrap</text>
      <text x="40" y="300" class="node-subtext">Root KEK in HSM, KEKs in KMS, DEKs are ephemeral per object.</text>
    </svg>
  </section>`;
}

function explainers(): string {
  return `<section class="panel">
    <h2>Why Envelope Encryption</h2>
    <p>HSM-backed KMS systems are powerful but cannot process raw application payload volume directly. Envelope encryption keeps heavy data movement local and asks KMS to protect short-lived DEKs instead.</p>
    <p>The DEK/KEK/root-KEK split keeps blast radius bounded: DEKs protect data, KEKs protect DEKs, and a top-tier root protects KEKs. Rotation at higher tiers avoids bulk data re-encryption.</p>
    <p>The audit trail is hash-chained with SHA-256. If any historical entry is edited, chain verification fails at the first broken index.</p>
  </section>`;
}

function scenariosPanel(): string {
  return `<section class="panel">
    <h2>Scenario Presets</h2>
    <div class="chip-row">
      <button class="chip preset-btn" data-preset="hello">Hello World</button>
      <button class="chip preset-btn" data-preset="rotation">Rotation Drill</button>
      <button class="chip preset-btn" data-preset="tenant">Multi-tenant</button>
      <button class="chip preset-btn" data-preset="breach">Breach Response</button>
    </div>
  </section>`;
}

function appMarkup(): string {
  const keys = kekStore.exportMetadata();
  const auditEntries = auditLog.list();
  const auditState = auditLog.verify();
  const latestKey = state.keyId ?? (keys[0]?.keyId ?? 'none');

  return `
  <header class="hero">
    <h1>Envelope KMS Lab</h1>
    <p>The operational crypto layer: DEK/KEK hierarchy, wrapping, rotation, and chained audit proofs.</p>
    <button id="theme-toggle" aria-label="Switch to light mode" style="position: absolute; top: 0; right: 0">🌙</button>
  </header>

  <section class="panel controls">
    <h2>Envelope Operations</h2>
    <div class="controls-row">
      <button id="create-key" class="chip">Create KEK</button>
      <button id="seal-btn" class="chip" ${latestKey === 'none' ? 'disabled' : ''}>Generate + Seal</button>
      <button id="open-btn" class="chip" ${state.envelopes.length ? '' : 'disabled'}>Open Latest</button>
      <button id="rotate-btn" class="chip" ${latestKey === 'none' ? 'disabled' : ''}>Rotate KEK</button>
      <button id="rewrap-btn" class="chip" ${state.envelopes.length ? '' : 'disabled'}>Re-wrap Latest</button>
    </div>
    <p>Current key: <strong>${latestKey}</strong></p>
  </section>

  ${scenariosPanel()}
  ${renderHierarchyView(keys, state.envelopes)}
  <section class="panel"><h2>Envelope Inspector</h2>${envelopeInspector(state.envelopes)}</section>
  ${renderRequestFlow(state.flow)}
  ${renderRotationPanel(state.timeline)}
  ${renderAuditView(auditEntries, auditState)}
  ${explainers()}
  ${comparisonPanel()}
  ${architectureDiagram()}

  <section class="panel landing-card">
    <h2>Landing Card Metadata</h2>
    <p><strong>Category:</strong> Key Management</p>
    <p><strong>Chips:</strong> AES Key Wrap (RFC 3394) | Envelope Encryption | Key Rotation | Audit Chain</p>
    <p><strong>Description:</strong> The operational crypto layer - DEK/KEK hierarchies, RFC 3394 key wrap, versioned rotation, and hash-chained audit logging. How AWS KMS, Google Cloud KMS, and HashiCorp Vault work under the hood.</p>
  </section>`;
}

async function onCreateKey() {
  const created = await kmsApi.CreateKey('AES256', 'ui');
  state.keyId = created.keyId;
  state.timeline.push(`CreateKey -> ${created.keyId}@v${created.version}`);
}

async function onSeal() {
  if (!state.keyId) throw new Error('Create a key first');
  const envelope = await seal(encoder.encode('Hello envelope world'), state.keyId, encoder.encode('ctx=demo'));
  state.envelopes.push(envelope);
  state.timeline.push(`Seal -> ${envelope.kekId}@v${envelope.kekVersion}`);
}

async function onOpen() {
  const latest = state.envelopes[state.envelopes.length - 1];
  if (!latest) return;
  const plaintext = await open(latest);
  state.timeline.push(`Open -> ${decoder.decode(plaintext)}`);
}

async function onRotate() {
  if (!state.keyId) return;
  const rotated = await kmsApi.RotateKey(state.keyId, 'ui');
  state.timeline.push(`RotateKey -> ${rotated.keyId}@v${rotated.version}`);
}

async function onRewrap() {
  const latest = state.envelopes[state.envelopes.length - 1];
  if (!latest || !state.keyId) return;
  const rewrapped = await rewrapEnvelope(latest, state.keyId);
  state.envelopes[state.envelopes.length - 1] = rewrapped;
  state.timeline.push(`Rewrap -> ${rewrapped.kekId}@v${rewrapped.kekVersion}`);
}

async function runPreset(name: string) {
  if (name === 'hello') {
    const result = await singleTenantScenario();
    state.keyId = result.keyId;
    state.envelopes.push(result.envelope);
    state.timeline.push(`Preset Hello World -> ${result.keyId}`);
    return;
  }
  if (name === 'rotation') {
    const result = await rotationDrillScenario();
    state.timeline.push(`Preset Rotation -> ${result.keyId} v${result.beforeVersion} to v${result.afterVersion}`);
    return;
  }
  if (name === 'tenant') {
    await singleTenantScenario();
    await customerManagedKeysScenario();
    state.timeline.push('Preset Multi-tenant -> isolated key paths verified');
    return;
  }
  if (name === 'breach') {
    if (!state.keyId) {
      const created = await kmsApi.CreateKey('AES256', 'breach-response');
      state.keyId = created.keyId;
    }
    // Rotate first to create a new active version, then re-wrap envelopes to it,
    // then schedule deletion so the old version enters its grace window.
    const rotated = await kmsApi.RotateKey(state.keyId, 'breach-response');
    if (state.envelopes.length) {
      const latest = state.envelopes[state.envelopes.length - 1];
      state.envelopes[state.envelopes.length - 1] = await rewrapEnvelope(latest, state.keyId);
    }
    await kmsApi.ScheduleKeyDeletion(state.keyId, 7, 'breach-response');
    state.timeline.push(`Preset Breach Response -> rotate to v${rotated.version}, re-wrap, schedule deletion (7 days)`);
  }
}

function announce(message: string): void {
  const region = document.getElementById('status-region');
  if (region) {
    region.textContent = message;
    // briefly clear so repeated identical messages still fire
    setTimeout(() => { region.textContent = ''; }, 3000);
  }
}

function handleError(err: unknown, context: string): void {
  const msg = err instanceof Error ? err.message : String(err);
  state.timeline.push(`Error in ${context}: ${msg}`);
  announce(`Error: ${msg}`);
}

function bind(root: HTMLElement): void {
  root.querySelector('#create-key')?.addEventListener('click', async () => {
    try { await onCreateKey(); } catch (err) { handleError(err, 'CreateKey'); }
    render(root);
  });
  root.querySelector('#seal-btn')?.addEventListener('click', async () => {
    try { await onSeal(); } catch (err) { handleError(err, 'Seal'); }
    render(root);
  });
  root.querySelector('#open-btn')?.addEventListener('click', async () => {
    try { await onOpen(); } catch (err) { handleError(err, 'Open'); }
    render(root);
  });
  root.querySelector('#rotate-btn')?.addEventListener('click', async () => {
    try { await onRotate(); } catch (err) { handleError(err, 'Rotate'); }
    render(root);
  });
  root.querySelector('#rewrap-btn')?.addEventListener('click', async () => {
    try { await onRewrap(); } catch (err) { handleError(err, 'Rewrap'); }
    render(root);
  });

  root.querySelectorAll<HTMLButtonElement>('.preset-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const preset = btn.dataset.preset ?? 'hello';
      try { await runPreset(preset); } catch (err) { handleError(err, `preset:${preset}`); }
      render(root);
    });
  });

  root.querySelectorAll<HTMLButtonElement>('.flow-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.flow = btn.dataset.flow ?? 'GenerateDataKey';
      render(root);
    });
  });

  root.querySelector('#tamper-btn')?.addEventListener('click', () => {
    if (auditLog.list().length > 1) {
      auditLog.tamper(1, 'tampered-entry');
      announce('Audit entry tampered — chain broken at index 1');
      render(root);
    }
  });

  const inspector = root.querySelector('pre');
  inspector?.addEventListener('dblclick', () => {
    const latest = state.envelopes[state.envelopes.length - 1];
    if (!latest) return;
    const parsed = fromB64(b64(latest.ciphertext));
    state.timeline.push(`Inspector roundtrip bytes=${parsed.length}`);
    render(root);
  });
}

export function render(root: HTMLElement): void {
  root.innerHTML = appMarkup();
  bind(root);
}

export async function bootstrap(root: HTMLElement): Promise<void> {
  runRfcVectors();
  await multiRegionScenario();
  render(root);
}
