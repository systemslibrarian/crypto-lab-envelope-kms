import { aeadOpen, aeadSeal } from './crypto/aead';
import { decoder, encoder, zeroize } from './crypto/bytes';
import { runRfcVectors } from './crypto/rfc-vectors';
import { open } from './envelope/open';
import { rewrapEnvelope } from './envelope/rotate';
import { type EnvelopeRecord } from './envelope/seal';
import { auditLog } from './kms/audit-log';
import { kmsApi } from './kms/kms-api';
import { kekStore } from './kms/kek-store';
import { multiRegionScenario } from './scenarios/multi-region';
import { rotationDrillScenario } from './scenarios/rotation-drill';
import { singleTenantScenario } from './scenarios/single-tenant';
import {
  PROPERTY_IDS,
  runAllProperties,
  runProperty,
  type PropertyId,
  type PropertyMode,
  type PropertyResult,
} from './security/properties';
import { renderAuditView } from './ui/audit-view';
import { renderHierarchyView } from './ui/hierarchy-view';
import { renderRequestFlow } from './ui/request-flow';
import { renderRotationPanel } from './ui/rotation-panel';
import { renderSecurityLab } from './ui/security-lab';

function b64(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += String.fromCharCode(b);
  return btoa(out);
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function escapeAttr(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function escapeText(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/**
 * One-line gloss for jargon on first appearance. Renders a dotted-underline term
 * with an accessible tooltip (native title + aria-label) so newcomers get the
 * definition on hover/focus without cluttering the page for experts.
 */
const GLOSS: Record<string, string> = {
  DEK: 'DEK — data encryption key: the per-object key that actually encrypts your data.',
  KEK: 'KEK — key encryption key: a key whose only job is to encrypt (wrap) other keys, never data.',
  'root-KEK':
    'root-KEK — the top key, kept inside the HSM; it encrypts the KEKs and never leaves the vault.',
  AAD: 'AAD — associated data: authenticated but NOT encrypted; it binds context (tenant, purpose) to the ciphertext so a stolen envelope cannot be replayed elsewhere.',
  iv: 'iv — initialization vector: the 12-byte random nonce AES-GCM needs; unique per message, not secret.',
  tag: 'tag — the 128-bit AES-GCM authentication tag; any change to ciphertext or AAD makes it fail.',
  wrappedDEK: 'wrappedDEK — the DEK after being encrypted (wrapped) under the KEK via RFC 3394.',
};

function gloss(term: string, label = term): string {
  const def = GLOSS[term];
  if (!def) return escapeText(label);
  // `title` only, no `aria-label`. <abbr> has no implicit ARIA role, and ARIA
  // prohibits naming a role-less element, so the aria-label that used to be
  // here was discarded by the accessibility tree — the definition reached
  // sighted hover users and nobody else. `title` on an <abbr> is the mapping
  // that actually carries the expansion to assistive technology. axe reports
  // the prohibited attribute as `incomplete`, which the old gate never read.
  return `<abbr class="gloss" tabindex="0" title="${escapeAttr(def)}">${escapeText(label)}</abbr>`;
}

/** A real, in-browser snapshot of one seal, captured for the wrap visualizer. */
type WrapSnapshot = {
  dekHex: string;
  ciphertextHex: string;
  wrappedHex: string;
  plaintext: string;
  aad: string;
  kekId: string;
  kekVersion: number;
};

type AppState = {
  keyId: string | null;
  envelopes: EnvelopeRecord[];
  timeline: string[];
  flow: string;
  securityResults: Record<string, PropertyResult>;
  plaintext: string;
  context: string;
  wrap: WrapSnapshot | null;
  crossTenant: { attempted: boolean; held: boolean; observed: string } | null;
  deepOpen: boolean;
};

const state: AppState = {
  keyId: null,
  envelopes: [],
  timeline: ['Ready'],
  flow: 'GenerateDataKey',
  securityResults: {},
  plaintext: 'Hello envelope world',
  context: 'tenant=acme',
  wrap: null,
  crossTenant: null,
  deepOpen: false,
};

function field(
  label: string,
  value: string,
  bytes: number,
  hint?: string,
  plainName?: string,
): string {
  const safe = value.replace(/&/g, '&amp;').replace(/</g, '&lt;');
  const copyLabel = plainName ?? label;
  return `<div class="insp-field">
    <div class="insp-field-head">
      <span class="insp-label">${label}</span>
      <span class="insp-meta">${bytes}B${hint ? ` · ${hint}` : ''}</span>
      <button class="insp-copy chip" type="button" data-copy="${safe}" aria-label="Copy ${escapeAttr(copyLabel)}">Copy</button>
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
    ${field(gloss('iv'), b64(env.iv), env.iv.length, 'AES-GCM nonce', 'iv')}
    ${field(gloss('tag'), b64(env.tag), env.tag.length, 'AEAD auth tag', 'tag')}
    ${field('ciphertext', b64(env.ciphertext), env.ciphertext.length, undefined, 'ciphertext')}
    ${field(gloss('wrappedDEK'), b64(env.wrappedDEK), env.wrappedDEK.length, 'RFC 3394', 'wrappedDEK')}
    ${field(gloss('AAD', 'aad'), b64(env.aad), env.aad.length, 'additional data', 'aad')}
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
    <!-- tabindex only, for the same reason as .hierarchy-scroll: under 900px
         this table becomes its own horizontally scrolling box, and without it
         a keyboard user cannot scroll to the columns the hint points at. The
         accessible name comes from the caption and the element's own table
         role, so no extra ARIA is needed or wanted here. -->
    <table class="comparison-table" tabindex="0" aria-label="KMS provider feature comparison">
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

function primerPanel(): string {
  return `<section class="panel primer" aria-labelledby="primer-heading">
    <h2 id="primer-heading">What is envelope encryption?</h2>
    <p class="primer-lede">You lock your data in a box with a paper key. Instead of guarding a
      million paper keys, you lock each one inside a small tamper-proof safe that never leaves the
      vault. That is envelope encryption: encrypt data with a cheap, throwaway key, then encrypt
      <em>that key</em> under a stronger key you guard closely.</p>
    <ul class="primer-defs">
      <li>
        <span class="primer-term">${gloss('DEK')}</span>
        <span class="primer-def">the <strong>paper key</strong> — a fresh 32-byte key that encrypts one object's data, then is thrown away.</span>
      </li>
      <li>
        <span class="primer-term">${gloss('KEK')}</span>
        <span class="primer-def">the <strong>safe</strong> — a key whose only job is to encrypt (wrap) DEKs. It never touches your data.</span>
      </li>
      <li>
        <span class="primer-term">${gloss('root-KEK', 'root-KEK')}</span>
        <span class="primer-def">the <strong>vault itself</strong> — the top key, kept inside an HSM; it encrypts the KEKs and never leaves.</span>
      </li>
    </ul>
    <p class="primer-foot">So the chain is <strong>data → DEK → KEK → root-KEK</strong>. Only the tiny
      wrapped keys ever travel to the KMS; the bulk data stays put. Run <strong>Generate + Seal</strong>
      below to watch a real DEK get created, used, wrapped, and destroyed.</p>
  </section>`;
}

/**
 * The wrap visualizer. Every hex string here is a REAL value computed in-browser
 * by the last seal (see onSeal): the random DEK, the AES-256-GCM ciphertext, and
 * the RFC 3394 wrappedDEK. The plaintext DEK is shown once and then struck
 * through, because the live copy was zeroized the instant the seal completed.
 */
function wrapVisualizer(): string {
  const w = state.wrap;
  if (!w) {
    return `<section class="panel wrap-viz" aria-labelledby="wrapviz-heading">
      <h2 id="wrapviz-heading">Watch the wrap</h2>
      <div class="empty-state">
        <p class="empty-title">Nothing sealed yet</p>
        <p class="empty-copy">Create a KEK, then click <strong>Generate + Seal</strong>. This panel replays the four real steps a KMS performs: draw a DEK, encrypt data, wrap the DEK, and destroy the plaintext DEK.</p>
      </div>
    </section>`;
  }
  const dekShort = `${w.dekHex.slice(0, 32)}…`;
  const ctShort = `${w.ciphertextHex.slice(0, 32)}${w.ciphertextHex.length > 32 ? '…' : ''}`;
  const wrapShort = `${w.wrappedHex.slice(0, 32)}…`;
  // Each hex value is named by a visually-hidden span rather than by
  // aria-label. <code> has no implicit ARIA role, and ARIA prohibits naming a
  // role-less element, so the aria-labels that used to sit on these tags were
  // discarded outright: a screen reader read 32 characters of hex with no
  // indication of what it was. axe files that under `incomplete` rather than
  // `violations`, and this panel only exists after a seal, so the old gate
  // missed it twice over — wrong result bucket and wrong state.
  const step = (n: number, title: string, body: string): string =>
    `<li class="wrap-step" data-step="${n}">
      <span class="wrap-step-caption">Step ${n}/4</span>
      <span class="wrap-step-title">${title}</span>
      <div class="wrap-step-body">${body}</div>
    </li>`;
  return `<section class="panel wrap-viz" aria-labelledby="wrapviz-heading">
    <h2 id="wrapviz-heading">Watch the wrap</h2>
    <p class="panel-lede">A real replay of the seal you just ran. The ${gloss('DEK')} is used
      <strong>twice</strong> — once to encrypt your data, once to be wrapped — then its plaintext copy
      is destroyed. Every hex string below is the actual value your browser computed.</p>
    <ol class="wrap-steps" aria-label="Seal steps, one through four">
      ${step(
        1,
        `Draw a random 32-byte ${gloss('DEK')}`,
        `<span class="sr-only">plaintext DEK, 32 bytes: </span><code class="wrap-hex dek">${dekShort}</code>
         <span class="wrap-note">crypto.getRandomValues(32) — fresh, per object</span>`,
      )}
      ${step(
        2,
        `Encrypt your data under the DEK (AES-256-GCM)`,
        `<span class="sr-only">ciphertext: </span><code class="wrap-hex ct">${ctShort}</code>
         <span class="wrap-note">plaintext "${escapeText(w.plaintext)}" + ${gloss('AAD')} "${escapeText(w.aad)}" → ciphertext + ${gloss('tag')}</span>`,
      )}
      ${step(
        3,
        `Wrap the SAME DEK under the ${gloss('KEK')} (RFC 3394)`,
        `<span class="sr-only">wrapped DEK: </span><code class="wrap-hex wrapped">${wrapShort}</code>
         <span class="wrap-note">${escapeText(w.kekId)}@v${w.kekVersion} wraps the DEK → ${gloss('wrappedDEK')} (40B, 8B longer)</span>`,
      )}
      ${step(
        4,
        `Zeroize the plaintext DEK`,
        `<span class="sr-only">plaintext DEK destroyed: </span><code class="wrap-hex dek zeroized">${dekShort}</code>
         <span class="wrap-note">the live DEK bytes were overwritten with zeros — only the wrapped copy survives</span>`,
      )}
    </ol>
    <p class="wrap-foot">Stored to disk: <strong>ciphertext + tag + wrappedDEK</strong>. Never stored:
      the plaintext DEK. To read the data later, the KMS unwraps the DEK with the KEK — the one step
      that requires the vault.</p>
  </section>`;
}

function scenariosPanel(): string {
  const presets: Array<{ id: string; title: string; copy: string; tone: string }> = [
    {
      id: 'hello',
      title: 'Hello World',
      copy: 'Create a KEK, seal a message, decrypt it back. The smallest end-to-end envelope flow.',
      tone: 'teal',
    },
    {
      id: 'rotation',
      title: 'Rotation Drill',
      copy: 'Rotate a KEK to a new version while old envelopes remain readable under the previous version.',
      tone: 'violet',
    },
    {
      id: 'tenant',
      title: 'Multi-tenant',
      copy: 'Two tenants, two KEKs. Verify keys cannot cross the tenant boundary.',
      tone: 'amber',
    },
    {
      id: 'breach',
      title: 'Breach Response',
      copy: 'Rotate, re-wrap existing envelopes, then schedule the compromised version for deletion.',
      tone: 'crimson',
    },
  ];
  const cards = presets
    .map(
      (
        p,
      ) => `<button class="preset-card preset-btn" data-preset="${p.id}" data-tone="${p.tone}" type="button">
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

/**
 * The KEK the page is actually operating on — and the one the header displays as
 * "Active KEK". `state.keyId` is only set once the user (or a preset) creates a
 * key, but the KEK store is already populated by the bootstrap scenario, so
 * before that the first stored key is the active one.
 *
 * Handlers MUST resolve the key through here rather than reading `state.keyId`
 * directly. While they disagreed, the header advertised an active KEK and
 * enabled the controls, yet "Generate + Seal" failed with "Create a key first"
 * and "Rotate KEK" announced success without rotating anything.
 */
function activeKeyId(): string | null {
  return state.keyId ?? kekStore.exportMetadata()[0]?.keyId ?? null;
}

function appMarkup(): string {
  const keys = kekStore.exportMetadata();
  const auditEntries = auditLog.list();
  const auditState = auditLog.verifyDetail();
  const latestKey = activeKeyId() ?? 'none';

  return `
  <header class="cl-hero">
    <div class="cl-hero-main">
      <h1 class="cl-hero-title">Envelope KMS</h1>
      <p class="cl-hero-sub">DEK/KEK/root-KEK hierarchy · AES Key Wrap · RFC 3394</p>
      <p class="cl-hero-desc">Build a KEK, seal payloads into DEK-wrapped envelopes, rotate keys with decrypt-only states, and watch the hash-chained audit log verify or break.</p>
    </div>
    <aside class="cl-hero-why" aria-label="Why it matters">
      <span class="cl-hero-why-label">WHY IT MATTERS</span>
      <p class="cl-hero-why-text">This is how AWS, GCP, Azure, and Vault KMS work under the hood. Getting the key hierarchy, rotation, and tamper-evident audit right is what keeps a breach of one layer from decrypting everything.</p>
    </aside>
  </header>

  ${primerPanel()}
  ${architectureDiagram()}

  <section class="panel controls" aria-labelledby="ops-heading">
    <h2 id="ops-heading">Envelope Operations</h2>
    <div class="key-status" data-state="${latestKey === 'none' ? 'empty' : 'ready'}">
      <span class="key-status-label">Active KEK</span>
      <code class="key-status-value">${latestKey}</code>
      <span class="key-status-meta">${state.envelopes.length} envelope${state.envelopes.length === 1 ? '' : 's'}</span>
    </div>
    <div class="seal-inputs">
      <label class="seal-field">
        <span class="seal-field-label">Plaintext to seal</span>
        <input id="plaintext-input" class="seal-input" type="text" value="${escapeAttr(state.plaintext)}" maxlength="120" autocomplete="off" spellcheck="false" placeholder="Type any message…" />
      </label>
      <label class="seal-field">
        <span class="seal-field-label">Context / ${gloss('AAD')}</span>
        <input id="context-input" class="seal-input" type="text" value="${escapeAttr(state.context)}" maxlength="64" autocomplete="off" spellcheck="false" placeholder="tenant=acme" />
      </label>
    </div>
    <p class="seal-hint">The context becomes the ${gloss('AAD')}: authenticated but not encrypted, and cryptographically bound to this envelope. Change it, seal, then use <strong>Open as different tenant</strong> to watch the math refuse.</p>
    <div class="controls-row">
      <button id="create-key" class="chip" type="button">Create KEK</button>
      <button id="seal-btn" class="chip" type="button" ${latestKey === 'none' ? 'disabled' : ''}>Generate + Seal</button>
      <button id="open-btn" class="chip" type="button" ${state.envelopes.length ? '' : 'disabled'}>Open Latest</button>
      <button id="open-evil-btn" class="chip" type="button" ${state.envelopes.length ? '' : 'disabled'}>Open as different tenant</button>
      <button id="rotate-btn" class="chip" type="button" ${latestKey === 'none' ? 'disabled' : ''}>Rotate KEK</button>
      <button id="rewrap-btn" class="chip" type="button" ${state.envelopes.length ? '' : 'disabled'}>Re-wrap Latest</button>
      <button id="reset-btn" class="chip ghost" type="button" ${latestKey === 'none' && !state.envelopes.length ? 'disabled' : ''}>Reset</button>
    </div>
    ${crossTenantResult()}
  </section>

  ${wrapVisualizer()}
  ${scenariosPanel()}
  ${renderHierarchyView(keys, state.envelopes)}
  <section class="panel"><h2>Envelope Inspector</h2><p class="panel-lede">The on-the-wire payload for the most recently sealed message. Click any field to copy.</p>${envelopeInspector(state.envelopes)}</section>

  <section class="panel deeper" aria-labelledby="deeper-heading">
    <h2 id="deeper-heading">Ready to go deeper?</h2>
    <p class="panel-lede">Now that you can see the mechanism, put the guarantees under attack. Each experiment runs the <em>real</em> primitives and tries to defeat a property — the crypto refuses in front of you.</p>
    <details class="deeper-details"${state.deepOpen ? ' open' : ''}>
      <summary id="deeper-summary">Open the security lab &amp; wire internals</summary>
      <div class="deeper-body">
        ${renderSecurityLab(state.securityResults)}
        ${explainers()}
        ${renderRequestFlow(state.flow)}
      </div>
    </details>
  </section>

  ${renderRotationPanel(state.timeline)}
  ${renderAuditView(auditEntries, auditState)}
  ${comparisonPanel()}`;
}

function crossTenantResult(): string {
  const r = state.crossTenant;
  if (!r) return '';
  const badge = r.held
    ? '<span class="prop-badge held"><span aria-hidden="true">✓ </span>Refused</span>'
    : '<span class="prop-badge broken"><span aria-hidden="true">✕ </span>Opened — binding failed</span>';
  return `<div class="cross-tenant-result ${r.held ? 'held' : 'broken'}" role="status">
    ${badge}
    <p class="cross-tenant-observed">${escapeText(r.observed)}</p>
  </div>`;
}

async function onCreateKey() {
  const created = await kmsApi.CreateKey('AES256', 'ui');
  state.keyId = created.keyId;
  state.timeline.push(`CreateKey -> ${created.keyId}@v${created.version}`);
}

/**
 * Instrumented seal — identical cryptography to envelope/seal.ts, but it captures
 * the REAL intermediate values (the random DEK, the ciphertext, the wrapped DEK)
 * for the wrap visualizer BEFORE zeroizing the plaintext DEK. Nothing here is
 * faked: the DEK is drawn by GenerateDataKey, the ciphertext is AES-256-GCM, and
 * the wrappedDEK is RFC 3394 key wrap. We snapshot hex strings, then destroy the
 * live key bytes exactly as the production path does.
 */
async function onSeal() {
  const keyId = activeKeyId();
  if (!keyId) throw new Error('Create a key first');
  state.keyId = keyId;
  const plaintext = state.plaintext.length ? state.plaintext : 'Hello envelope world';
  const context = state.context;
  const aadBytes = encoder.encode(context);
  const { plaintextDEK, wrappedDEK, kekId, kekVersion } = await kmsApi.GenerateDataKey(
    keyId,
    32,
    'seal',
  );
  try {
    const { ciphertext, iv, tag } = await aeadSeal(
      encoder.encode(plaintext),
      plaintextDEK,
      aadBytes,
    );
    // Snapshot the real values while the plaintext DEK is still live.
    state.wrap = {
      dekHex: hex(plaintextDEK),
      ciphertextHex: hex(ciphertext),
      wrappedHex: hex(wrappedDEK),
      plaintext,
      aad: context,
      kekId,
      kekVersion,
    };
    const envelope: EnvelopeRecord = {
      ciphertext,
      iv,
      tag,
      wrappedDEK,
      kekId,
      kekVersion,
      aad: aadBytes,
    };
    auditLog.append({
      operation: 'Seal',
      principal: 'seal',
      keyId: kekId,
      kekVersion,
      success: true,
      details: `ciphertext=${ciphertext.length}, wrappedDEK=${wrappedDEK.length}`,
    });
    state.envelopes.push(envelope);
    state.crossTenant = null;
    state.timeline.push(`Seal -> ${envelope.kekId}@v${envelope.kekVersion} (ctx="${context}")`);
  } finally {
    // Destroy the live plaintext DEK — only the wrapped copy survives.
    zeroize(plaintextDEK);
  }
}

/**
 * "Open as a different tenant" — the AAD-binding experiment, run on the learner's
 * OWN envelope. We unwrap the real DEK via the KMS, then attempt aeadOpen with a
 * deliberately different context. AES-256-GCM's tag covers the AAD, so the open
 * throws. This is the real primitive refusing, not a scripted message.
 */
async function onOpenAsEvil() {
  const latest = state.envelopes[state.envelopes.length - 1];
  if (!latest) return;
  const sealedContext = decoder.decode(latest.aad);
  const wrongContext = sealedContext === 'tenant=evil' ? 'tenant=acme' : 'tenant=evil';
  const dek = await kmsApi.Decrypt(
    { wrappedDEK: latest.wrappedDEK, kekId: latest.kekId, kekVersion: latest.kekVersion },
    'open-cross-tenant',
  );
  try {
    await aeadOpen(latest.ciphertext, latest.iv, latest.tag, dek, encoder.encode(wrongContext));
    state.crossTenant = {
      attempted: true,
      held: false,
      observed: `Opened "${sealedContext}" envelope while claiming "${wrongContext}" — context binding FAILED.`,
    };
    state.timeline.push(`Open-as-different-tenant -> WARNING binding failed`);
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    state.crossTenant = {
      attempted: true,
      held: true,
      observed: `Claimed context "${wrongContext}" but the envelope was sealed for "${sealedContext}". AES-GCM tag check rejected it: ${msg || 'authentication failed'}.`,
    };
    state.timeline.push(
      `Open-as-different-tenant -> refused (AAD "${wrongContext}" ≠ "${sealedContext}")`,
    );
  } finally {
    zeroize(dek);
  }
}

async function onOpen() {
  const latest = state.envelopes[state.envelopes.length - 1];
  if (!latest) return;
  const plaintext = await open(latest);
  state.timeline.push(`Open -> ${decoder.decode(plaintext)}`);
}

async function onRotate() {
  const keyId = activeKeyId();
  if (!keyId) throw new Error('Create a KEK first');
  state.keyId = keyId;
  const rotated = await kmsApi.RotateKey(keyId, 'ui');
  state.timeline.push(`RotateKey -> ${rotated.keyId}@v${rotated.version}`);
}

async function onRewrap() {
  const latest = state.envelopes[state.envelopes.length - 1];
  const keyId = activeKeyId();
  if (!latest) throw new Error('Seal an envelope first');
  if (!keyId) throw new Error('Create a KEK first');
  state.keyId = keyId;
  const rewrapped = await rewrapEnvelope(latest, keyId);
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
    state.timeline.push(
      `Preset Rotation -> ${result.keyId} v${result.beforeVersion} to v${result.afterVersion}`,
    );
    return;
  }
  if (name === 'tenant') {
    // Two tenants, two KEKs — then *prove* the boundary by trying to unwrap
    // tenant A's DEK with tenant B's KEK and watching RFC 3394 reject it.
    const acme = await singleTenantScenario();
    state.keyId = acme.keyId;
    state.envelopes.push(acme.envelope);
    const isolation = await runProperty('tenant-isolation');
    state.securityResults[isolation.id] = isolation;
    state.timeline.push(
      isolation.held
        ? `Preset Multi-tenant -> cross-tenant unwrap rejected: ${isolation.observed}`
        : `Preset Multi-tenant -> WARNING isolation failed: ${isolation.observed}`,
    );
    return;
  }
  if (name === 'breach') {
    const keyId = activeKeyId() ?? (await kmsApi.CreateKey('AES256', 'breach-response')).keyId;
    state.keyId = keyId;
    // Rotate first to create a new active version, then re-wrap envelopes to it,
    // then schedule deletion so the old version enters its grace window.
    const rotated = await kmsApi.RotateKey(keyId, 'breach-response');
    if (state.envelopes.length) {
      const latest = state.envelopes[state.envelopes.length - 1];
      state.envelopes[state.envelopes.length - 1] = await rewrapEnvelope(latest, keyId);
    }
    await kmsApi.ScheduleKeyDeletion(keyId, 7, 'breach-response');
    state.timeline.push(
      `Preset Breach Response -> rotate to v${rotated.version}, re-wrap, schedule deletion (7 days)`,
    );
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
    try {
      await onCreateKey();
      announce(`Created KEK ${state.keyId}`);
    } catch (err) {
      handleError(err, 'CreateKey');
    }
    render(root);
  });
  root.querySelector('#seal-btn')?.addEventListener('click', async () => {
    try {
      await onSeal();
      announce('Sealed envelope');
    } catch (err) {
      handleError(err, 'Seal');
    }
    render(root);
  });
  root.querySelector('#open-btn')?.addEventListener('click', async () => {
    try {
      await onOpen();
      announce('Opened latest envelope');
    } catch (err) {
      handleError(err, 'Open');
    }
    render(root);
  });
  root.querySelector('#open-evil-btn')?.addEventListener('click', async () => {
    try {
      await onOpenAsEvil();
      announce(
        state.crossTenant?.held
          ? 'Refused: wrong context cannot open the envelope'
          : 'Context binding failed',
        state.crossTenant?.held ? 'info' : 'error',
      );
    } catch (err) {
      handleError(err, 'OpenAsEvil');
    }
    render(root);
  });
  const plaintextInput = root.querySelector<HTMLInputElement>('#plaintext-input');
  if (plaintextInput) {
    plaintextInput.addEventListener('input', () => {
      state.plaintext = plaintextInput.value;
    });
  }
  const contextInput = root.querySelector<HTMLInputElement>('#context-input');
  if (contextInput) {
    contextInput.addEventListener('input', () => {
      state.context = contextInput.value;
    });
  }
  root.querySelector<HTMLDetailsElement>('.deeper-details')?.addEventListener('toggle', (e) => {
    state.deepOpen = (e.currentTarget as HTMLDetailsElement).open;
  });
  root.querySelector('#rotate-btn')?.addEventListener('click', async () => {
    try {
      await onRotate();
      announce('Rotated KEK to new version');
    } catch (err) {
      handleError(err, 'Rotate');
    }
    render(root);
  });
  root.querySelector('#rewrap-btn')?.addEventListener('click', async () => {
    try {
      await onRewrap();
      announce('Re-wrapped envelope to active version');
    } catch (err) {
      handleError(err, 'Rewrap');
    }
    render(root);
  });
  root.querySelector('#reset-btn')?.addEventListener('click', () => {
    state.keyId = null;
    state.envelopes = [];
    state.timeline = ['Ready'];
    state.flow = 'GenerateDataKey';
    state.securityResults = {};
    state.wrap = null;
    state.crossTenant = null;
    auditLog.clear();
    kekStore.clear();
    announce('Reset — cleared keys, envelopes, and audit log');
    render(root);
  });

  root.querySelectorAll<HTMLButtonElement>('.preset-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const preset = btn.dataset.preset ?? 'hello';
      try {
        await runPreset(preset);
        announce(`Ran "${preset}" preset`);
      } catch (err) {
        handleError(err, `preset:${preset}`);
      }
      render(root);
    });
  });

  root.querySelectorAll<HTMLButtonElement>('.prop-run-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const id = (btn.dataset.prop ?? '') as PropertyId;
      if (!PROPERTY_IDS.includes(id)) return;
      const mode: PropertyMode = btn.dataset.mode === 'weakened' ? 'weakened' : 'defended';
      try {
        const result = await runProperty(id, mode);
        state.securityResults[id] = result;
        const build = mode === 'weakened' ? ' (weakened build)' : '';
        announce(
          result.held
            ? `Property held${build}: ${result.title}`
            : `Property BROKEN${build}: ${result.title}`,
          result.held ? 'info' : 'error',
        );
      } catch (err) {
        handleError(err, `property:${id}:${mode}`);
      }
      render(root);
    });
  });

  const runAll = async (mode: PropertyMode): Promise<void> => {
    try {
      const results = await runAllProperties(mode);
      for (const result of results) state.securityResults[result.id] = result;
      const broken = results.filter((r) => !r.held).length;
      const build = mode === 'weakened' ? ' (weakened build)' : '';
      announce(
        broken === 0
          ? `All ${results.length} properties held${build}`
          : `${broken} of ${results.length} properties BROKEN${build}`,
        broken === 0 ? 'info' : 'error',
      );
    } catch (err) {
      handleError(err, `run-all-properties:${mode}`);
    }
    render(root);
  };

  root.querySelector('#run-all-props')?.addEventListener('click', () => void runAll('defended'));
  root
    .querySelector('#run-all-props-weakened')
    ?.addEventListener('click', () => void runAll('weakened'));

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

/**
 * A stable CSS selector for the currently focused control, so we can restore
 * focus after the full re-render below. Without this, every action sends focus
 * back to <body>, which strands keyboard and screen-reader users (WCAG 2.4.3).
 */
function focusSelector(el: Element | null): string | null {
  if (!(el instanceof HTMLElement) || el === document.body) return null;
  if (el.id) return `#${CSS.escape(el.id)}`;
  for (const attr of ['data-prop', 'data-preset', 'data-flow', 'data-copy']) {
    const value = el.getAttribute(attr);
    if (value !== null) return `[${attr}="${CSS.escape(value)}"]`;
  }
  return null;
}

export function render(root: HTMLElement): void {
  const selector = focusSelector(document.activeElement);
  root.innerHTML = appMarkup();
  bind(root);
  if (selector) {
    const next = root.querySelector<HTMLElement>(selector);
    // Preserve focus across the re-render; the element may be gone (e.g. after
    // Reset), in which case we simply leave focus where the browser put it.
    if (next) next.focus();
  }
}

export async function bootstrap(root: HTMLElement): Promise<void> {
  runRfcVectors();
  await multiRegionScenario();
  render(root);
}
