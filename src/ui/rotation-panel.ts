export function renderRotationPanel(timeline: string[]): string {
  return `<section class="panel">
    <h2>Rotation Drill</h2>
    <ol class="timeline">
      ${timeline.map((line) => `<li>${line}</li>`).join('')}
    </ol>
  </section>`;
}
