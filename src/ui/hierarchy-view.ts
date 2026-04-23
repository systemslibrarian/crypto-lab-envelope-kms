import type { KekMetadata } from '../kms/kek-store';
import type { EnvelopeRecord } from '../envelope/seal';

function escapeText(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function truncate(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

export function renderHierarchyView(keys: KekMetadata[], envelopes: EnvelopeRecord[]): string {
  if (keys.length === 0 && envelopes.length === 0) {
    return `<section class="panel hierarchy-panel">
      <h2>Hierarchy View</h2>
      <div class="empty-state">
        <p class="empty-title">No KEKs yet</p>
        <p class="empty-copy">Create a KEK to begin building the Root → KEK → DEK hierarchy.</p>
      </div>
    </section>`;
  }

  // Layout
  const width = 880;
  const padX = 24;
  const rootY = 28;
  const rootHeight = 44;
  const colKekX = padX;
  const colKekW = 360;
  const colDekX = colKekX + colKekW + 80;
  const colDekW = width - colDekX - padX;

  const kekRowH = 56;
  const dekRowH = 36;

  const kekStartY = rootY + rootHeight + 56;
  const dekStartY = kekStartY;

  const kekHeight = Math.max(keys.length, 1) * kekRowH;
  const dekHeight = Math.max(envelopes.length, 1) * dekRowH;
  const bodyHeight = Math.max(kekHeight, dekHeight);
  const height = kekStartY + bodyHeight + 28;

  // Root node
  const rootCenterX = colKekX + colKekW / 2;
  const rootRect = `
    <rect x="${colKekX}" y="${rootY}" width="${colKekW}" height="${rootHeight}" rx="6" class="node-root" />
    <text x="${colKekX + 16}" y="${rootY + 27}" class="node-text">Root KEK · HSM boundary</text>
  `;

  // KEK rows
  const keyNodes = keys
    .map((k, i) => {
      const y = kekStartY + i * kekRowH;
      const activeVersion = k.versions.find((v) => v.status === 'active')?.version ?? k.versions[0]?.version ?? 1;
      const versionsText = k.versions
        .map((v) => `v${v.version}·${v.status}`)
        .join('  ');
      const label = truncate(escapeText(k.keyId), 32);
      return `
        <line x1="${rootCenterX}" y1="${rootY + rootHeight}" x2="${rootCenterX}" y2="${y + 18}" class="edge" />
        <line x1="${rootCenterX}" y1="${y + 18}" x2="${colKekX}" y2="${y + 18}" class="edge" />
        <rect x="${colKekX}" y="${y}" width="${colKekW}" height="36" rx="6" class="node-kek" />
        <text x="${colKekX + 14}" y="${y + 16}" class="node-text">${label} · v${activeVersion}</text>
        <text x="${colKekX + 14}" y="${y + 30}" class="node-subtext">${escapeText(versionsText)}</text>
      `;
    })
    .join('');

  // DEK rows (envelopes)
  const dekNodes = envelopes
    .map((e, i) => {
      const y = dekStartY + i * dekRowH;
      const targetKekY = (() => {
        const idx = keys.findIndex((k) => k.keyId === e.kekId);
        return idx >= 0 ? kekStartY + idx * kekRowH + 18 : kekStartY + 18;
      })();
      const label = `wrappedDEK · ${e.wrappedDEK.length}B → ${truncate(escapeText(e.kekId), 18)}@v${e.kekVersion}`;
      return `
        <line x1="${colKekX + colKekW}" y1="${targetKekY}" x2="${colDekX}" y2="${y + 18}" class="edge" />
        <rect x="${colDekX}" y="${y + 4}" width="${colDekW}" height="28" rx="6" class="node-dek" />
        <text x="${colDekX + 12}" y="${y + 22}" class="node-text dek-text">${label}</text>
      `;
    })
    .join('');

  // Column headers
  const headers = `
    <text x="${colKekX}" y="${rootY - 10}" class="node-eyebrow">KEKs</text>
    <text x="${colDekX}" y="${rootY - 10}" class="node-eyebrow">Wrapped DEKs</text>
  `;

  return `<section class="panel hierarchy-panel">
    <h2>Hierarchy View</h2>
    <div class="hierarchy-scroll">
      <svg viewBox="0 0 ${width} ${height}" class="hierarchy-svg" role="img" aria-label="Root KEK to KEK to wrapped DEK hierarchy" preserveAspectRatio="xMinYMin meet">
        ${headers}
        ${rootRect}
        ${keyNodes}
        ${dekNodes}
      </svg>
    </div>
  </section>`;
}
