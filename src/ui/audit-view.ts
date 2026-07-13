import type { AuditEntry } from '../kms/audit-log';

function escapeText(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export type VerifyDetail = {
  ok: boolean;
  brokenIndex: number | null;
  reason: 'content-hash' | 'prev-link' | null;
  storedHash: string | null;
  recomputedHash: string | null;
  expectedPrev: string | null;
};

/**
 * Render a short hash with the first character that differs from `other`
 * highlighted, so a learner can literally see which byte of the digest changed
 * when the entry was tampered.
 */
function hashWithDiff(hash: string, other: string | null, len: number): string {
  const shown = hash.slice(0, len);
  if (!other) return `${escapeText(shown)}…`;
  let diffAt = -1;
  for (let i = 0; i < shown.length; i += 1) {
    if (shown[i] !== other[i]) {
      diffAt = i;
      break;
    }
  }
  if (diffAt === -1) return `${escapeText(shown)}…`;
  return `${escapeText(shown.slice(0, diffAt))}<mark class="hash-diff">${escapeText(shown.slice(diffAt, diffAt + 2))}</mark>${escapeText(shown.slice(diffAt + 2))}…`;
}

export function renderAuditView(entries: AuditEntry[], verify: VerifyDetail): string {
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

  // When tampered, explain the specific break: entry #N's stored hash no longer
  // matches its recomputed content, so entry #N+1's prev_hash no longer commits
  // to real data — the append-only chain is severed at that link.
  let breakExplainer = '';
  if (!verify.ok && verify.brokenIndex !== null) {
    const i = verify.brokenIndex;
    const stored = verify.storedHash ? `${escapeText(verify.storedHash.slice(0, 24))}…` : '—';
    const recomputed = verify.recomputedHash
      ? hashWithDiff(verify.recomputedHash, verify.storedHash, 24)
      : '—';
    breakExplainer = `<div class="chain-break" role="status">
      <p class="chain-break-head"><span aria-hidden="true">🔗✕ </span>Broken link at entry #${i}</p>
      <p class="chain-break-body">Entry #${i}'s content was altered, so its SHA-256 digest changed. The stored hash still reads
        <code class="audit-hash">${stored}</code>, but re-hashing the (now edited) entry yields
        <code class="audit-hash recomputed">${recomputed}</code> — the highlighted byte no longer matches.
        Because entry #${i + 1}'s <code>prev_hash</code> committed to the <em>old</em> hash, every later entry is now exposed as tampered.</p>
    </div>`;
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
    ${breakExplainer}
    <div class="audit-list" role="list" tabindex="0" aria-label="Audit log entries, scrollable">
      ${entries
        .slice()
        .reverse()
        .map((e) => {
          const broken = verify.brokenIndex === e.index;
          // The entry whose prev_hash committed to the broken entry's hash.
          const downstream = verify.brokenIndex !== null && e.index === verify.brokenIndex + 1;
          const cls = broken ? 'broken' : downstream ? 'downstream' : '';
          return `<article class="audit-item ${cls}" role="listitem">
            <header>
              <span class="audit-idx">#${e.index}</span>
              <span class="audit-op">${escapeText(e.operation)}</span>
              <span class="audit-result ${e.success ? 'ok' : 'fail'}">${e.success ? 'ok' : 'fail'}</span>
              <time>${escapeText(e.timestamp)}</time>
            </header>
            <dl class="audit-fields">
              <div><dt>key</dt><dd>${escapeText(e.keyId ?? '—')}</dd></div>
              <div><dt>version</dt><dd>${e.kekVersion ?? '—'}</dd></div>
              <div><dt>prev</dt><dd class="audit-hash${downstream ? ' link-broken' : ''}">${escapeText(e.prev_hash.slice(0, 16))}…</dd></div>
              <div><dt>hash</dt><dd class="audit-hash${broken ? ' link-broken' : ''}">${escapeText(e.hash.slice(0, 24))}…</dd></div>
              ${e.details ? `<div class="full"><dt>details</dt><dd>${escapeText(String(e.details))}</dd></div>` : ''}
            </dl>
          </article>`;
        })
        .join('')}
    </div>
  </section>`;
}
