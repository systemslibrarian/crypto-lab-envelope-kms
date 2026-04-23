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

function field(label: string, value: string, bytes: number, hint?: string): string {
  const safe = value.replace(/&/g, '&amp;').replace(/</g, '&lt;');
  return `<div class="insp-field">
    <div class="insp-field-head">
      <span class="insp-label">${label}</span>
      <span class="insp-meta">${bytes}B${hint ? ` · ${hint}` : ''}</span>
      <button class="insp-copy chip" type="button" data-copy="${safe}" aria-label="Copy ${label}">Copy</button>
    </div>
    <code class="insp-value">${safe}</code>
  </div>`;
}

function envelopeInspector(envelopes: EnvelopeRecord[]): string {
  if (envelopes.length === 0) {
    return `<div class="empty-state">
      <p class="empty-title">No envelope yet</p>
      <p class="empty-copy">Create a KEK and click <strong>Generate + Seal</strong> to encrypt a sample payload and inspect the wire format.</p>
    </div>`;
  }
  const env = envelopes[envelopes.length - 1];
  return `<div class="insp-grid">
    ${field('iv', b64(env.iv), env.iv.length, 'AES-GCM nonce')}
    ${field('tag', b64(env.tag), env.tag.length, 'AEAD auth tag')}
    ${field('ciphertext', b64(env.ciphertext), env.ciphertext.length)}
    ${field('wrappedDEK', b64(env.wrappedDEK), env.wrappedDEK.length, 'RFC 3394')}
    ${field('aad', b64(env.aad), env.aad.length, 'additional data')}
    <div class="insp-field insp-meta-row">
      <div><span class="insp-label">kekId</span><code class="insp-value">${env.kekId}</code></div>
      <div><span class="insp-label">kekVersion</span><code class="insp-value">v${env.kekVersion}</code></div>
    </div>
  </div>`;
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
    <h2>Architecture</h2>
    <p class="panel-lede">A typical envelope-encryption deployment. Bulk data never leaves the client; only short-lived data keys travel to the KMS.</p>
    <svg class="arch-svg" viewBox="0 0 980 280" role="img" aria-label="Envelope encryption architecture: client, KMS, and storage">
      <defs>
        <marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M0,0 L10,5 L0,10 z" fill="currentColor" />
        </marker>
      </defs>

      <!-- Client -->
      <rect x="40" y="100" width="200" height="80" rx="6" class="node-root" />
      <text x="140" y="135" text-anchor="middle" class="node-text">Client App</text>
      <text x="140" y="156" text-anchor="middle" class="node-subtext">AES-GCM encrypt / decrypt</text>

      <!-- KMS -->
      <rect x="390" y="40" width="200" height="80" rx="6" class="node-kek" />
      <text x="490" y="75" text-anchor="middle" class="node-text">KMS</text>
      <text x="490" y="96" text-anchor="middle" class="node-subtext">GenerateDataKey · Decrypt · ReEncrypt</text>

      <!-- Storage -->
      <rect x="740" y="100" width="200" height="80" rx="6" class="node-root" />
      <text x="840" y="135" text-anchor="middle" class="node-text">Object Storage</text>
      <text x="840" y="156" text-anchor="middle" class="node-subtext">ciphertext + wrappedDEK</text>

      <!-- Edges: client <-> kms -->
      <g class="edge-arrow" color="var(--teal)">
        <line x1="240" y1="125" x2="390" y2="75" class="edge teal" marker-end="url(#arr)" />
      </g>
      <text x="315" y="95" text-anchor="middle" class="node-subtext">1. GenerateDataKey</text>

      <g class="edge-arrow" color="var(--violet)">
        <line x1="390" y1="105" x2="240" y2="155" class="edge violet" marker-end="url(#arr)" />
      </g>
      <text x="315" y="180" text-anchor="middle" class="node-subtext">plaintextDEK + wrappedDEK</text>

      <!-- Edge: client -> storage -->
      <line x1="240" y1="140" x2="740" y2="140" class="edge" marker-end="url(#arr)" color="var(--text-dim)" />
      <text x="490" y="135" text-anchor="middle" class="node-subtext">2. PUT ciphertext + wrappedDEK</text>

      <!-- Edge: storage -> kms (decrypt) -->
      <g class="edge-arrow" color="var(--amber)">
        <line x1="740" y1="125" x2="590" y2="75" class="edge amber" marker-end="url(#arr)" />
      </g>
      <text x="665" y="95" text-anchor="middle" class="node-subtext">3. Decrypt(wrappedDEK)</text>

      <!-- Footer note -->
      <text x="40" y="240" class="node-subtext">Root KEK lives in the HSM. KEKs live in KMS. DEKs are ephemeral, one per object.</text>
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
  const presets: Array<{ id: string; title: string; copy: string; tone: string }> = [
    { id: 'hello', title: 'Hello World', copy: 'Create a KEK, seal a message, decrypt it back. The smallest end-to-end envelope flow.', tone: 'teal' },
    { id: 'rotation', title: 'Rotation Drill', copy: 'Rotate a KEK to a new version while old envelopes remain readable under the previous version.', tone: 'violet' },
    { id: 'tenant', title: 'Multi-tenant', copy: 'Two tenants, two KEKs. Verify keys cannot cross the tenant boundary.', tone: 'amber' },
    { id: 'breach', title: 'Breach Response', copy: 'Rotate, re-wrap existing envelopes, then schedule the compromised version for deletion.', tone: 'crimson' },
  ];
  const cards = presets
    .map(
      (p) => `<button class="preset-card preset-btn" data-preset="${p.id}" data-tone="${p.tone}" type="button">
        <span class="preset-title">${p.title}</span>
        <span class="preset-copy">${p.copy}</span>
        <span class="preset-cta">Run preset →</span>
      </button>`,
    )
    .join('');
  return `<section class="panel">
    <h2>Scenario Presets</h2>
    <p class="panel-lede">One-click runs of common KMS workflows. Each preset writes to the timeline, the audit log, and (where relevant) the envelope inspector.</p>
    <div class="preset-grid">${cards}</div>
  </section>`;
}

function appMarkup(): string {
  const keys = kekStore.exportMetadata();
  const auditEntries = auditLog.list();
  const auditState = auditLog.verify();
  const latestKey = state.keyId ?? (keys[0]?.keyId ?? 'none');

  return `
  <section class="hero-main">
    <span class="eyebrow">Crypto Lab · Key Management</span>
    <h1>Envelope <span>KMS</span> Lab</h1>
    <p class="hero-copy">The operational crypto layer — DEK/KEK hierarchies, RFC 3394 key wrap, versioned rotation, and hash-chained audit logging. How AWS KMS, Google Cloud KMS, Azure Key Vault, and HashiCorp Vault work under the hood.</p>
    <div class="hero-stack" aria-label="Topics covered">
      <span class="tag">AES Key Wrap · RFC 3394</span>
      <span class="tag">Envelope Encryption</span>
      <span class="tag">Key Rotation</span>
      <span class="tag">Audit Chain</span>
    </div>
  </section>

  <section class="panel controls" aria-labelledby="ops-heading">
    <h2 id="ops-heading">Envelope Operations</h2>
    <div class="key-status" data-state="${latestKey === 'none' ? 'empty' : 'ready'}">
      <span class="key-status-label">Active KEK</span>
      <code class="key-status-value">${latestKey}</code>
      <span class="key-status-meta">${state.envelopes.length} envelope${state.envelopes.length === 1 ? '' : 's'}</span>
    </div>
    <div class="controls-row">
      <button id="create-key" class="chip" type="button">Create KEK</button>
      <button id="seal-btn" class="chip" type="button" ${latestKey === 'none' ? 'disabled' : ''}>Generate + Seal</button>
      <button id="open-btn" class="chip" type="button" ${state.envelopes.length ? '' : 'disabled'}>Open Latest</button>
      <button id="rotate-btn" class="chip" type="button" ${latestKey === 'none' ? 'disabled' : ''}>Rotate KEK</button>
      <button id="rewrap-btn" class="chip" type="button" ${state.envelopes.length ? '' : 'disabled'}>Re-wrap Latest</button>
      <button id="reset-btn" class="chip ghost" type="button" ${latestKey === 'none' && !state.envelopes.length ? 'disabled' : ''}>Reset</button>
    </div>
  </section>

  ${scenariosPanel()}
  ${explainers()}
  ${architectureDiagram()}
  ${renderHierarchyView(keys, state.envelopes)}
  <section class="panel"><h2>Envelope Inspector</h2><p class="panel-lede">The on-the-wire payload for the most recently sealed message. Click any field to copy.</p>${envelopeInspector(state.envelopes)}</section>
  ${renderRequestFlow(state.flow)}
  ${renderRotationPanel(state.timeline)}
  ${renderAuditView(auditEntries, auditState)}
  ${comparisonPanel()}`;
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

function announce(message: string, tone: 'info' | 'error' = 'info'): void {
  const region = document.getElementById('status-region');
  if (region) {
    region.textContent = message;
    setTimeout(() => {
      region.textContent = '';
    }, 3000);
  }
  const host = document.getElementById('toast-host');
  if (!host) return;
  const el = document.createElement('div');
  el.className = `toast ${tone}`;
  el.textContent = message;
  host.appendChild(el);
  requestAnimationFrame(() => el.classList.add('show'));
  setTimeout(() => {
    el.classList.remove('show');
    el.addEventListener('transitionend', () => el.remove(), { once: true });
  }, 2400);
}

function handleError(err: unknown, context: string): void {
  const msg = err instanceof Error ? err.message : String(err);
  state.timeline.push(`Error in ${context}: ${msg}`);
  announce(`Error: ${msg}`, 'error');
}

function bind(root: HTMLElement): void {
  root.querySelector('#create-key')?.addEventListener('click', async () => {
    try { await onCreateKey(); announce(`Created KEK ${state.keyId}`); } catch (err) { handleError(err, 'CreateKey'); }
    render(root);
  });
  root.querySelector('#seal-btn')?.addEventListener('click', async () => {
    try { await onSeal(); announce('Sealed envelope'); } catch (err) { handleError(err, 'Seal'); }
    render(root);
  });
  root.querySelector('#open-btn')?.addEventListener('click', async () => {
    try { await onOpen(); announce('Opened latest envelope'); } catch (err) { handleError(err, 'Open'); }
    render(root);
  });
  root.querySelector('#rotate-btn')?.addEventListener('click', async () => {
    try { await onRotate(); announce('Rotated KEK to new version'); } catch (err) { handleError(err, 'Rotate'); }
    render(root);
  });
  root.querySelector('#rewrap-btn')?.addEventListener('click', async () => {
    try { await onRewrap(); announce('Re-wrapped envelope to active version'); } catch (err) { handleError(err, 'Rewrap'); }
    render(root);
  });
  root.querySelector('#reset-btn')?.addEventListener('click', () => {
    state.keyId = null;
    state.envelopes = [];
    state.timeline = ['Ready'];
    state.flow = 'GenerateDataKey';
    auditLog.clear();
    kekStore.clear();
    announce('Reset — cleared keys, envelopes, and audit log');
    render(root);
  });

  root.querySelectorAll<HTMLButtonElement>('.preset-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const preset = btn.dataset.preset ?? 'hello';
      try { await runPreset(preset); announce(`Ran "${preset}" preset`); } catch (err) { handleError(err, `preset:${preset}`); }
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
      announce('Audit entry #1 tampered — chain now broken', 'error');
      render(root);
    } else {
      announce('Need at least two entries to tamper', 'error');
    }
  });

  root.querySelectorAll<HTMLButtonElement>('.insp-copy').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const value = btn.dataset.copy ?? '';
      try {
        await navigator.clipboard.writeText(value);
        const original = btn.textContent;
        btn.textContent = 'Copied';
        btn.classList.add('active');
        announce('Copied to clipboard');
        setTimeout(() => {
          btn.textContent = original;
          btn.classList.remove('active');
        }, 1200);
      } catch {
        announce('Copy failed', 'error');
      }
    });
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
