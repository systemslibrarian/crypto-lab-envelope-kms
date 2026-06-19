import { PROPERTY_CATALOG, type PropertyResult } from '../security/properties';

function escapeText(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function escapeAttr(value: string): string {
  return escapeText(value).replace(/"/g, '&quot;');
}

/**
 * The "try to break it" lab. Each card describes a guarantee and lets the learner
 * run a real experiment that attempts to defeat it; the result reveals whether
 * the property held, the observed outcome, and why it matters.
 */
export function renderSecurityLab(results: Record<string, PropertyResult>): string {
  const ran = Object.keys(results).length;

  const cards = PROPERTY_CATALOG.map((meta) => {
    const result = results[meta.id];
    const runLabel = result ? 'Run again' : 'Run experiment';
    let resultBlock = '';
    if (result) {
      const badge = result.held
        ? '<span class="prop-badge held"><span aria-hidden="true">✓ </span>Property held</span>'
        : '<span class="prop-badge broken"><span aria-hidden="true">✕ </span>Property broken</span>';
      resultBlock = `<div class="prop-result ${result.held ? 'held' : 'broken'}">
        ${badge}
        <p class="prop-observed">${escapeText(result.observed)}</p>
        <p class="prop-lesson"><strong>Why it matters:</strong> ${escapeText(result.lesson)}</p>
      </div>`;
    }
    return `<article class="prop-card" data-tone="${meta.tone}">
      <h3 class="prop-title">${escapeText(meta.title)}</h3>
      <span class="prop-claim">${escapeText(meta.claim)}</span>
      <span class="prop-experiment"><strong>Experiment:</strong> ${escapeText(meta.experiment)}</span>
      <button class="chip prop-run-btn" type="button" data-prop="${meta.id}" aria-label="${escapeAttr(`${runLabel}: ${meta.title}`)}">${runLabel}</button>
      ${resultBlock}
    </article>`;
  }).join('');

  return `<section class="panel security-lab" aria-labelledby="seclab-heading">
    <h2 id="seclab-heading">Security Properties — Try to Break It</h2>
    <p class="panel-lede">These run the <em>real</em> primitives — RFC 3394 key wrap and AES-256-GCM — and try to defeat each guarantee. Watch the math refuse. ${ran > 0 ? `<strong>${ran}/${PROPERTY_CATALOG.length} run.</strong>` : ''}</p>
    <div class="chip-row">
      <button id="run-all-props" class="chip" type="button">Run all experiments</button>
    </div>
    <div class="prop-grid">${cards}</div>
  </section>`;
}
