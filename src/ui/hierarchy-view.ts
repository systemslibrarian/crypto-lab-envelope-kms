import type { KekMetadata } from '../kms/kek-store';
import type { EnvelopeRecord } from '../envelope/seal';

export function renderHierarchyView(keys: KekMetadata[], envelopes: EnvelopeRecord[]): string {
  const rowHeight = 56;
  const width = 860;
  const height = 120 + keys.length * rowHeight + envelopes.length * 26;

  const keyNodes = keys
    .map((k, i) => {
      const y = 70 + i * rowHeight;
      const versions = k.versions.map((v) => `v${v.version} (${v.status})`).join(' | ');
      return `<g>
        <rect x="70" y="${y}" width="430" height="36" rx="10" class="node-kek" />
        <text x="86" y="${y + 23}" class="node-text">${k.keyId} - ${versions}</text>
      </g>`;
    })
    .join('');

  const dekNodes = envelopes
    .map((e, i) => {
      const y = 70 + i * 26;
      return `<g>
        <line x1="500" y1="${y + 10}" x2="760" y2="${y + 10}" class="edge" />
        <text x="520" y="${y + 14}" class="node-subtext">wrappedDEK (${e.wrappedDEK.length} bytes) -> ${e.kekId}@v${e.kekVersion}</text>
      </g>`;
    })
    .join('');

  return `<section class="panel">
    <h2>Hierarchy View</h2>
    <svg viewBox="0 0 ${width} ${height}" class="hierarchy-svg" role="img" aria-label="Root KEK to KEK to DEK hierarchy">
      <rect x="70" y="14" width="260" height="36" rx="10" class="node-root" />
      <text x="86" y="37" class="node-text">Root KEK (HSM boundary)</text>
      <line x1="200" y1="50" x2="200" y2="70" class="edge" />
      ${keyNodes}
      ${dekNodes}
    </svg>
  </section>`;
}
