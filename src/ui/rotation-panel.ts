/**
 * Timeline lines embed values the learner typed — the plaintext echoed back by
 * "Open Latest", the context echoed by "Seal" — so they must be escaped. Before
 * this they were interpolated raw, and typing `<b>x</b>` into the plaintext box
 * rendered real markup here instead of the text the panel claims to be showing.
 */
function escapeText(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export function renderRotationPanel(timeline: string[]): string {
  return `<section class="panel">
    <h2>Rotation Drill</h2>
    <ol class="timeline">
      ${timeline.map((line) => `<li>${escapeText(line)}</li>`).join('')}
    </ol>
  </section>`;
}
