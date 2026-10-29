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
 *
 * Each card has two run buttons. Against the real build the property always
 * holds — correct AES-GCM and correct RFC 3394 do not fail — so a "Property
 * broken" badge that only ever saw the real build could never render, and a
 * security lab whose failure state cannot occur teaches that the guarantee is
 * unconditional. The second button removes the one specific defense the
 * guarantee rests on and runs the identical attack, so the learner can break the
 * property on purpose and watch the badge flip.
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
      const modeTag =
        result.mode === 'weakened'
          ? '<span class="prop-mode-tag weakened">weakened build</span>'
          : '<span class="prop-mode-tag defended">real build</span>';
      resultBlock = `<div class="prop-result ${result.held ? 'held' : 'broken'}">
        <div class="prop-badge-row">${badge}${modeTag}</div>
        <p class="prop-observed">${escapeText(result.observed)}</p>
        <p class="prop-lesson"><strong>Why it matters:</strong> ${escapeText(result.lesson)}</p>
      </div>`;
    }
    return `<article class="prop-card" data-tone="${meta.tone}">
      <h3 class="prop-title">${escapeText(meta.title)}</h3>
      <span class="prop-claim">${escapeText(meta.claim)}</span>
      <span class="prop-experiment"><strong>Experiment:</strong> ${escapeText(meta.experiment)}</span>
      <span class="prop-experiment prop-weakening"><strong>Break it:</strong> run the same attack against a build where ${escapeText(meta.weakening)}.</span>
      <div class="prop-btn-row">
        <button class="chip prop-run-btn" type="button" data-prop="${meta.id}" data-mode="defended" aria-label="${escapeAttr(`${runLabel} against the real build: ${meta.title}`)}">${runLabel}</button>
        <button class="chip prop-weaken-btn prop-run-btn" type="button" data-prop="${meta.id}" data-mode="weakened" aria-label="${escapeAttr(`Run weakened: against the weakened build, where ${meta.weakening}: ${meta.title}`)}">Run weakened</button>
      </div>
      ${resultBlock}
    </article>`;
  }).join('');

  return `<section class="panel security-lab" aria-labelledby="seclab-heading">
    <h2 id="seclab-heading">Security Properties — Try to Break It</h2>
    <p class="panel-lede">These run the <em>real</em> primitives — RFC 3394 key wrap and AES-256-GCM — and try to defeat each guarantee. Observe whether this trial is rejected; one trial does not establish a universal integrity guarantee. Then press <strong>Run weakened</strong>: the identical attack against a build missing the one defense that guarantee rests on. The badge goes red, and it means it. ${ran > 0 ? `<strong>${ran}/${PROPERTY_CATALOG.length} run.</strong>` : ''}</p>
    <div class="chip-row">
      <button id="run-all-props" class="chip" type="button">Run all experiments</button>
      <button id="run-all-props-weakened" class="chip prop-weaken-btn" type="button">Run all weakened</button>
    </div>
    <aside id="key-wrap-research-note" role="note">
      <h3>Key-wrap integrity has bounds</h3>
      <p>John Preuß Mattsson, <a href="https://eprint.iacr.org/2026/2636"><em>Revisiting AES Key Wrap: Forgery Bounds, Structural Observations, and Recommendations for the Revision of NIST SP 800-38F</em></a> (October 2026 preprint), studies conditional forgery bounds. A rejected corruption is not proof that every forgery is impossible.</p>
      <p>KWP can additionally require a trusted expected plaintext length before releasing a key. This supplements its standard prefix, recovered-length and zero-padding checks. The idealized fixed-length expression is 2<sup>−64−8p</sup> for p padding bytes: 32-byte keys have no padding contribution (2<sup>−64</sup>); 66-byte material has six padding bytes (2<sup>−112</sup> in that model). This is not a universal adaptive bound or a finalized NIST requirement. The API keeps the standard single-block path; replay and context binding remain application responsibilities.</p>
    </aside>
    <div class="prop-grid">${cards}</div>
  </section>`;
}
