import type { AuditEntry } from '../kms/audit-log';

function escapeText(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export function renderAuditView(
  entries: AuditEntry[],
  verify: { ok: boolean; brokenIndex: number | null },
): string {
  const statusClass = verify.ok ? 'audit-status ok' : 'audit-status broken';
  const statusLabel = verify.ok ? 'Chain valid' : `Broken at #${verify.brokenIndex}`;

  if (entries.length === 0) {
    return `<section class="panel audit-panel">
      <h2>Audit Log</h2>
      <div class="empty-state">
        <p class="empty-title">No entries yet</p>
        <p class="empty-copy">Operations are SHA-256 hash-chained as they happen. Run any envelope action to see entries appear here.</p>
      </div>
    </section>`;
  }

  return `<section class="panel audit-panel">
    <h2>Audit Log</h2>
    <div class="audit-toolbar">
      <span class="${statusClass}">
        <span class="audit-status-dot" aria-hidden="true"></span>
        ${statusLabel}
      </span>
      <span class="audit-count">${entries.length} ${entries.length === 1 ? 'entry' : 'entries'}</span>
      <button id="tamper-btn" class="chip" type="button">Tamper Entry #1</button>
    </div>
    <div class="audit-list" role="list">
      ${entries
        .slice()
        .reverse()
        .map((e) => {
          const broken = verify.brokenIndex === e.index;
          return `<article class="audit-item ${broken ? 'broken' : ''}" role="listitem">
            <header>
              <span class="audit-idx">#${e.index}</span>
              <span class="audit-op">${escapeText(e.operation)}</span>
              <span class="audit-result ${e.success ? 'ok' : 'fail'}">${e.success ? 'ok' : 'fail'}</span>
              <time>${escapeText(e.timestamp)}</time>
            </header>
            <dl class="audit-fields">
              <div><dt>key</dt><dd>${escapeText(e.keyId ?? '—')}</dd></div>
              <div><dt>version</dt><dd>${e.kekVersion ?? '—'}</dd></div>
              <div><dt>prev</dt><dd class="audit-hash">${escapeText(e.prev_hash.slice(0, 16))}…</dd></div>
              <div><dt>hash</dt><dd class="audit-hash">${escapeText(e.hash.slice(0, 24))}…</dd></div>
              ${e.details ? `<div class="full"><dt>details</dt><dd>${escapeText(String(e.details))}</dd></div>` : ''}
            </dl>
          </article>`;
        })
        .join('')}
    </div>
  </section>`;
}
