import type { AuditEntry } from '../kms/audit-log';

export function renderAuditView(entries: AuditEntry[], verify: { ok: boolean; brokenIndex: number | null }): string {
  const status = verify.ok ? 'Chain valid' : `Broken link at index ${verify.brokenIndex}`;
  return `<section class="panel">
    <h2>Audit Log</h2>
    <div class="audit-toolbar">
      <strong>${status}</strong>
      <button id="tamper-btn" class="chip">Tamper</button>
    </div>
    <div class="audit-list">
      ${entries
        .map(
          (e) => `<article class="audit-item ${verify.brokenIndex === e.index ? 'broken' : ''}">
          <header>#${e.index} ${e.operation} ${e.success ? 'ok' : 'fail'}</header>
          <p>${e.timestamp} | key=${e.keyId ?? '-'} | version=${e.kekVersion ?? '-'} | prev=${e.prev_hash.slice(0, 16)}...</p>
          <p>hash=${e.hash.slice(0, 24)}... ${e.details ?? ''}</p>
        </article>`,
        )
        .join('')}
    </div>
  </section>`;
}
