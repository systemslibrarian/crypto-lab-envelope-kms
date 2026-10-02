import { runCompromise } from '../scenarios/compromise';

export function compromisePanel(): HTMLElement {
  const panel = document.createElement('section');
  panel.className = 'panel';
  panel.id = 'compromise-lab';
  panel.innerHTML = `<h2>Steal one KEK: what still opens?</h2>
    <p>Four records, two per tenant. Give the attacker Tenant A’s version 1 KEK and copies of every original envelope. Compare a shared KEK with separate tenant KEKs.</p>
    <label for="compromise-layout">Key layout</label>
    <select class="chip" id="compromise-layout"><option value="isolated">Separate tenant KEKs</option><option value="shared">One shared KEK</option></select>
    <button id="compromise-run" class="chip" type="button">Run compromise experiment</button>
    <p>Each cell counts real successful decryptions. Re-wrapping cannot revoke a DEK already recovered from a stolen envelope. Fresh DEKs protect the replacement ciphertext, but cannot erase the attacker’s archived plaintext.</p>
    <div id="compromise-result" role="status" aria-live="polite">Not run. This separate experiment does not change your envelopes above.</div>`;
  const select = panel.querySelector<HTMLSelectElement>('select')!;
  const button = panel.querySelector<HTMLButtonElement>('button')!;
  const result = panel.querySelector<HTMLElement>('#compromise-result')!;
  let last = select.value;
  select.addEventListener('change', () => {
    if (select.value !== last)
      result.textContent = 'Previous results retired. Run the new key layout.';
    last = select.value;
  });
  button.addEventListener('click', async () => {
    button.disabled = true;
    select.disabled = true;
    result.textContent = 'Running actual unwrap and decrypt attempts…';
    try {
      const rows = await runCompromise(select.value === 'isolated');
      const count = (v: boolean[]) =>
        v.length ? `${v.filter(Boolean).length}/${v.length}` : 'Not created';
      result.innerHTML = `<p>Attacker holds ${select.value === 'isolated' ? 'Tenant A' : 'the shared'} KEK v1. Records 1–2 belong to A; 3–4 to B.</p>
        <div style="overflow-x:auto" tabindex="0" role="region" aria-label="Compromise results"><table class="comparison-table" tabindex="0" aria-label="Compromise decryption counts"><caption>Successful opens at each maintenance stage</caption>
        <thead><tr><th scope="col">Stage</th><th scope="col">Archived copies</th><th scope="col">Current wrap + stolen KEK</th><th scope="col">Current data + retained DEK</th><th scope="col">Future data + stolen KEK</th><th scope="col">Owner opens</th></tr></thead>
        <tbody>${rows.map((r) => `<tr><th scope="row">${r.name}</th><td>${count(r.archived)}</td><td>${count(r.currentWrap)}</td><td>${count(r.currentRetained)}</td><td>${count(r.future)}</td><td>${count(r.owner)}</td></tr>`).join('')}</tbody></table></div>
        <p>Scope: stolen raw key material; no further KMS access. All keys are fresh and in memory. Tenant labels and AAD are not access controls against someone who has the key.</p>`;
    } catch {
      result.textContent = 'Experiment failed to run; no security verdict is available.';
    } finally {
      button.disabled = false;
      select.disabled = false;
    }
  });
  return panel;
}
