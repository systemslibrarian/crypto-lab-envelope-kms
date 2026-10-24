import { bytesToHex, zeroize } from '../crypto/bytes';
import {
  buildAuthenticatedLog,
  compromiseBeforePeriod,
  createRetainedCheckpoint,
  forgeSuffixFromCompromise,
  rewriteFromCompromise,
  verifyAuthenticatedLog,
  type AuthenticatedLogRecord,
  type AuthenticatedLogScheme,
  type CompromiseMaterial,
  type RetainedCheckpoint,
  type RewriteAttempt,
  type VerificationReport,
  type VerificationTrust,
} from '../kms/forward-secure-log';
import './key-evolving-audit.css';

const PANEL_DISPOSERS = new WeakMap<HTMLElement, () => void>();

/** Best-effort zeroize synthetic verifier/logger state before the app drops a stable panel. */
export function disposeKeyEvolvingAuditPanel(panel: HTMLElement | undefined): void {
  if (!panel) return;
  PANEL_DISPOSERS.get(panel)?.();
  PANEL_DISPOSERS.delete(panel);
  panel.dataset.disposed = 'true';
}

const SCHEMES = ['STATIC', 'FORWARD_SECURE'] as const;
const EVENTS = [
  'OPEN audit window',
  'READ tenant/acme/invoice-17',
  'ROTATE kek-acme to version 8',
  'EXPORT billing batch',
  'WRITE retention-policy=90-days',
] as const;
const CLOSE_MESSAGE = 'CLOSE audit window';
const RECORD_COUNT = EVENTS.length + 1;
const CLOSE_PERIOD = EVENTS.length;

type CompletenessInput = 'none' | 'trusted-close';
type FreshnessInput = 'none' | 'trusted-heartbeat';

type Track = {
  scheme: AuthenticatedLogScheme;
  initialState: Uint8Array;
  records: readonly AuthenticatedLogRecord[];
  compromise: CompromiseMaterial;
  checkpoint: RetainedCheckpoint;
};

type Experiment = {
  logId: string;
  beforePeriod: number;
  tracks: Record<AuthenticatedLogScheme, Track>;
};

type AttackTrack = {
  records: readonly AuthenticatedLogRecord[];
  integrity: VerificationReport;
  checkpoint: VerificationReport;
  attackerCanRetag?: boolean;
};

type AttackPair = Record<AuthenticatedLogScheme, AttackTrack>;

type TruncationTrack = AttackTrack & {
  completeness: VerificationReport;
  freshness: VerificationReport;
};

type TruncationPair = Record<AuthenticatedLogScheme, TruncationTrack>;

function escapeText(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function schemeLabel(scheme: AuthenticatedLogScheme): string {
  return scheme === 'STATIC' ? 'Ordinary static-key chain' : 'Key-evolving chain';
}

function createLogId(): string {
  return `s02-${bytesToHex(crypto.getRandomValues(new Uint8Array(8)))}`;
}

function verificationTrust(
  track: Track,
  additions: Partial<
    Pick<VerificationTrust, 'checkpoint' | 'expectedClosePeriod' | 'trustedMinimumRecords'>
  > = {},
): VerificationTrust {
  return {
    scheme: track.scheme,
    logId: track.records[0].logId,
    initialState: track.initialState,
    ...additions,
  };
}

function verifyIntegrityOnly(
  track: Track,
  records: readonly AuthenticatedLogRecord[],
): VerificationReport {
  return verifyAuthenticatedLog(records, verificationTrust(track));
}

function verifyCheckpoint(
  track: Track,
  records: readonly AuthenticatedLogRecord[],
): VerificationReport {
  return verifyAuthenticatedLog(
    records,
    verificationTrust(track, { checkpoint: track.checkpoint }),
  );
}

function makeTrack(
  scheme: AuthenticatedLogScheme,
  initialState: Uint8Array,
  logId: string,
  beforePeriod: number,
): Track {
  const records = buildAuthenticatedLog({
    scheme,
    initialState,
    logId,
    events: EVENTS,
    closeMessage: CLOSE_MESSAGE,
  });
  return {
    scheme,
    initialState,
    records,
    compromise: compromiseBeforePeriod(initialState, logId, beforePeriod, scheme),
    // This copy is retained outside the modeled logger immediately before the
    // compromised period. It commits only to the exact prefix through c - 1.
    checkpoint: createRetainedCheckpoint(records, beforePeriod),
  };
}

function buildExperiment(beforePeriod: number): Experiment {
  const logId = createLogId();
  const staticInitial = crypto.getRandomValues(new Uint8Array(32));
  const forwardInitial = crypto.getRandomValues(new Uint8Array(32));
  let staticTrack: Track | undefined;
  let forwardTrack: Track | undefined;
  try {
    staticTrack = makeTrack('STATIC', staticInitial, logId, beforePeriod);
    forwardTrack = makeTrack('FORWARD_SECURE', forwardInitial, logId, beforePeriod);
    return {
      logId,
      beforePeriod,
      tracks: { STATIC: staticTrack, FORWARD_SECURE: forwardTrack },
    };
  } catch (error) {
    zeroize(staticTrack?.compromise.state ?? new Uint8Array());
    zeroize(forwardTrack?.compromise.state ?? new Uint8Array());
    zeroize(staticInitial);
    zeroize(forwardInitial);
    throw error;
  }
}

function disposeExperiment(experiment: Experiment | undefined): void {
  if (!experiment) return;
  for (const scheme of SCHEMES) {
    zeroize(experiment.tracks[scheme].initialState);
    zeroize(experiment.tracks[scheme].compromise.state);
  }
}

function priorRewrite(experiment: Experiment): AttackPair {
  const targetPeriod = experiment.beforePeriod - 1;
  const replacement = `FORGED: ${EVENTS[targetPeriod]} approved by attacker`;
  const run = (track: Track): AttackTrack => {
    const attempted: RewriteAttempt = rewriteFromCompromise(
      track.records,
      track.compromise,
      targetPeriod,
      replacement,
    );
    return {
      records: attempted.records,
      integrity: verifyIntegrityOnly(track, attempted.records),
      checkpoint: verifyCheckpoint(track, attempted.records),
      attackerCanRetag: attempted.attackerCanRetag,
    };
  };
  return {
    STATIC: run(experiment.tracks.STATIC),
    FORWARD_SECURE: run(experiment.tracks.FORWARD_SECURE),
  };
}

function forgedSuffix(experiment: Experiment): AttackPair {
  const run = (track: Track): AttackTrack => {
    const suffix = track.records.slice(experiment.beforePeriod).map((record, index) => ({
      kind: record.kind,
      message:
        index === 0
          ? `FORGED: attacker replaced period ${experiment.beforePeriod}`
          : record.message,
    }));
    const records = forgeSuffixFromCompromise(track.records, track.compromise, suffix);
    return {
      records,
      integrity: verifyIntegrityOnly(track, records),
      checkpoint: verifyCheckpoint(track, records),
      attackerCanRetag: true,
    };
  };
  return {
    STATIC: run(experiment.tracks.STATIC),
    FORWARD_SECURE: run(experiment.tracks.FORWARD_SECURE),
  };
}

function truncatedPrefix(
  experiment: Experiment,
  completenessInput: CompletenessInput,
  freshnessInput: FreshnessInput,
): TruncationPair {
  const run = (track: Track): TruncationTrack => {
    const records = track.records.slice(0, experiment.beforePeriod);
    const completenessTrust = verificationTrust(
      track,
      completenessInput === 'trusted-close' ? { expectedClosePeriod: CLOSE_PERIOD } : {},
    );
    const freshnessTrust = verificationTrust(
      track,
      freshnessInput === 'trusted-heartbeat' ? { trustedMinimumRecords: RECORD_COUNT } : {},
    );
    return {
      records,
      integrity: verifyIntegrityOnly(track, records),
      checkpoint: verifyCheckpoint(track, records),
      completeness: verifyAuthenticatedLog(records, completenessTrust),
      freshness: verifyAuthenticatedLog(records, freshnessTrust),
    };
  };
  return {
    STATIC: run(experiment.tracks.STATIC),
    FORWARD_SECURE: run(experiment.tracks.FORWARD_SECURE),
  };
}

function periodOption(period: number, selected: number): string {
  const ordinal = period === 2 ? 'third' : period === 3 ? 'fourth' : 'fifth';
  return `<option value="${period}"${period === selected ? ' selected' : ''}>Before period ${period} (${ordinal} record; exposes S_${period})</option>`;
}

function recordFields(record: AuthenticatedLogRecord): string {
  return `<dl class="kea-record-fields">
    <div><dt>Version</dt><dd><code data-field="version">${record.version}</code></dd></div>
    <div><dt>Scheme</dt><dd><code data-field="scheme">${record.scheme}</code></dd></div>
    <div><dt>Log ID</dt><dd><code data-field="log-id">${escapeText(record.logId)}</code></dd></div>
    <div><dt>Period</dt><dd><code data-field="period">${record.period}</code></dd></div>
    <div><dt>Kind</dt><dd><code data-field="kind">${record.kind}</code></dd></div>
    <div class="kea-field-wide"><dt>Message</dt><dd><code data-field="message">${escapeText(record.message)}</code></dd></div>
    <div class="kea-field-wide"><dt>Previous tag</dt><dd><code data-field="previous-tag">${record.previousTag}</code></dd></div>
    <div class="kea-field-wide"><dt>Tag</dt><dd><code data-field="tag">${record.tag}</code></dd></div>
  </dl>`;
}

function originalRecords(experiment: Experiment): string {
  return experiment.tracks.STATIC.records
    .map((staticRecord, period) => {
      const evolvingRecord = experiment.tracks.FORWARD_SECURE.records[period];
      return `<li class="kea-record" data-period="${period}">
        <header><span>Period ${period}</span><strong>${staticRecord.kind}</strong><span>${escapeText(staticRecord.message)}</span></header>
        <div class="kea-record-schemes">
          <section data-record-scheme="STATIC" aria-label="Static-key record at period ${period}">
            <h4>${schemeLabel('STATIC')}</h4>${recordFields(staticRecord)}
          </section>
          <section data-record-scheme="FORWARD_SECURE" aria-label="Key-evolving record at period ${period}">
            <h4>${schemeLabel('FORWARD_SECURE')}</h4>${recordFields(evolvingRecord)}
          </section>
        </div>
      </li>`;
    })
    .join('');
}

function forgedRecords(records: readonly AuthenticatedLogRecord[]): string {
  return records
    .map((record) => `<li data-forged-period="${record.period}">${recordFields(record)}</li>`)
    .join('');
}

function integritySentence(report: VerificationReport): string {
  if (report.integrity === 'VALID') {
    return `All ${report.authenticatedRecords} presented records authenticate as one running chain.`;
  }
  return `Verification stops at record index ${report.firstInvalidIndex}: ${report.integrityReason}.`;
}

function attackTrackMarkup(
  scheme: AuthenticatedLogScheme,
  track: AttackTrack,
  verdict: 'accepted' | 'rejected' | 'valid-prefix',
): string {
  const retag =
    track.attackerCanRetag === undefined
      ? ''
      : `<p>Compromised state can retag this target: <strong>${track.attackerCanRetag ? 'yes' : 'no'}</strong>.</p>`;
  return `<section class="kea-attack-track" data-scheme="${scheme}" data-verdict="${verdict}" aria-label="${schemeLabel(scheme)} attack result">
    <h4>${schemeLabel(scheme)}</h4>
    <p><strong>${verdict === 'rejected' ? 'Rejected' : verdict === 'valid-prefix' ? 'Valid prefix' : 'Accepted'}:</strong> ${integritySentence(track.integrity)}</p>
    ${retag}
    <p>Retained-checkpoint comparison: <strong>${track.checkpoint.consistency}</strong>.</p>
    <details class="kea-attack-wire"><summary>Inspect the complete presented log</summary>
      <ol data-forged-records>${forgedRecords(track.records)}</ol>
    </details>
  </section>`;
}

function attackEvidence(
  experiment: Experiment | undefined,
  prior: AttackPair | undefined,
  suffix: AttackPair | undefined,
  truncation: TruncationPair | undefined,
): string {
  if (!experiment) return '';
  const sections: string[] = [];
  if (prior) {
    sections.push(`<article class="kea-attack" data-attack="prior-rewrite" aria-labelledby="kea-prior-heading">
      <h3 id="kea-prior-heading">Rewrite before compromise</h3>
      <p>The attacker changed period ${experiment.beforePeriod - 1} using only the state exposed immediately before period ${experiment.beforePeriod}.</p>
      <div class="kea-attack-grid">
        ${attackTrackMarkup('STATIC', prior.STATIC, prior.STATIC.integrity.integrity === 'VALID' ? 'accepted' : 'rejected')}
        ${attackTrackMarkup('FORWARD_SECURE', prior.FORWARD_SECURE, prior.FORWARD_SECURE.integrity.integrity === 'VALID' ? 'accepted' : 'rejected')}
      </div>
    </article>`);
  }
  if (suffix) {
    sections.push(`<article class="kea-attack" data-attack="suffix-forgery" aria-labelledby="kea-suffix-heading">
      <h3 id="kea-suffix-heading">Forge from the compromise boundary</h3>
      <p>The first altered record is period ${experiment.beforePeriod}. The prefix through period ${experiment.beforePeriod - 1} is copied byte for byte.</p>
      <div class="kea-attack-grid">
        ${attackTrackMarkup('STATIC', suffix.STATIC, suffix.STATIC.integrity.integrity === 'VALID' ? 'accepted' : 'rejected')}
        ${attackTrackMarkup('FORWARD_SECURE', suffix.FORWARD_SECURE, suffix.FORWARD_SECURE.integrity.integrity === 'VALID' ? 'accepted' : 'rejected')}
      </div>
    </article>`);
  }
  if (truncation) {
    const track = (scheme: AuthenticatedLogScheme): string => {
      const result = truncation[scheme];
      return `${attackTrackMarkup(scheme, result, result.integrity.integrity === 'VALID' ? 'valid-prefix' : 'rejected')}
        <dl class="kea-dimension-report">
          <div><dt>Completeness check</dt><dd>${result.completeness.completeness}</dd></div>
          <div><dt>Freshness check</dt><dd>${result.freshness.freshness}</dd></div>
        </dl>`;
    };
    sections.push(`<article class="kea-attack" data-attack="truncation" aria-labelledby="kea-truncation-heading">
      <h3 id="kea-truncation-heading">Delete the final records</h3>
      <p>The attacker presents only periods 0 through ${experiment.beforePeriod - 1}. That prefix can remain cryptographically valid even though period ${CLOSE_PERIOD}'s CLOSE is gone.</p>
      <div class="kea-attack-grid">
        <div data-truncation-scheme="STATIC">${track('STATIC')}</div>
        <div data-truncation-scheme="FORWARD_SECURE">${track('FORWARD_SECURE')}</div>
      </div>
    </article>`);
  }
  return sections.join('');
}

type Card = { verdict: string; text: string };

function forwardCard(prior: AttackPair | undefined, suffix: AttackPair | undefined): Card {
  const priorRejected = prior?.FORWARD_SECURE.integrity.integrity === 'INVALID';
  const suffixAccepted = suffix?.FORWARD_SECURE.integrity.integrity === 'VALID';
  if (priorRejected && suffixAccepted) {
    return {
      verdict: 'split-boundary',
      text: 'The pre-compromise rewrite was rejected, but a replacement chain beginning at the exposed period authenticated. Under the modeled erasure and one-way-evolution assumptions, earlier periods remain protected; the compromised period and its future are forgeable.',
    };
  }
  if (priorRejected) {
    return {
      verdict: 'past-rewrite-rejected',
      text: 'The key-evolving verifier rejected the changed earlier record. The exposed state cannot derive the erased state for that period.',
    };
  }
  if (suffixAccepted) {
    return {
      verdict: 'suffix-forgeable',
      text: 'The forged suffix authenticated from the exposed state. No claim about earlier protection extends to the compromised period or its future.',
    };
  }
  return {
    verdict: 'not-run',
    text: 'Not tested. Build the logs, then try an earlier rewrite and a forged suffix.',
  };
}

function checkpointCard(
  prior: AttackPair | undefined,
  suffix: AttackPair | undefined,
  truncation: TruncationPair | undefined,
): Card {
  const priorMismatch = prior?.STATIC.checkpoint.consistency === 'INCONSISTENT';
  const laterViewMatches =
    (suffix?.STATIC.checkpoint.consistency === 'CONSISTENT' &&
      suffix.FORWARD_SECURE.checkpoint.consistency === 'CONSISTENT') ||
    (truncation?.STATIC.checkpoint.consistency === 'CONSISTENT' &&
      truncation.FORWARD_SECURE.checkpoint.consistency === 'CONSISTENT');
  if (priorMismatch && laterViewMatches) {
    return {
      verdict: 'bounded',
      text: 'The retained checkpoint caught the static-key alternate history before its boundary, but it still matched the later presented view because that view preserved the checkpointed prefix. It says nothing about records after the retained tag.',
    };
  }
  if (priorMismatch) {
    return {
      verdict: 'mismatch',
      text: 'The independently retained tag disagreed with the otherwise valid static-key rewrite of the covered prefix.',
    };
  }
  if (laterViewMatches) {
    return {
      verdict: 'match',
      text: 'The presented view preserved the checkpointed prefix exactly, so the checkpoint still matches. It cannot say whether records after its boundary were replaced or deleted.',
    };
  }
  return {
    verdict: 'not-run',
    text: 'Not compared. The retained count-and-tag checkpoint commits only to the exact prefix seen when that checkpoint was stored outside the logger.',
  };
}

function completenessCard(truncation: TruncationPair | undefined, input: CompletenessInput): Card {
  if (!truncation) {
    return { verdict: 'not-run', text: 'Not tested. Delete the suffix to test completeness.' };
  }
  const result = truncation.FORWARD_SECURE.completeness.completeness;
  if (input === 'trusted-close' && result === 'TRUNCATED') {
    return {
      verdict: 'missing-close',
      text: `A trusted expectation says CLOSE belongs at period ${CLOSE_PERIOD}; the presented prefix is therefore detected as truncated. A CLOSE authenticated after compromise could still be fabricated.`,
    };
  }
  return {
    verdict: 'unknown',
    text: 'The remaining records authenticate, but without an external expected CLOSE the verifier cannot tell whether this valid prefix is the whole log.',
  };
}

function freshnessCard(truncation: TruncationPair | undefined, input: FreshnessInput): Card {
  if (!truncation) {
    return { verdict: 'not-run', text: 'Not tested. Delete the suffix to test freshness.' };
  }
  const result = truncation.FORWARD_SECURE.freshness.freshness;
  if (input === 'trusted-heartbeat' && result === 'STALE') {
    return {
      verdict: 'missed-heartbeat',
      text: `A trusted outside observer retained a receipt that at least ${RECORD_COUNT} records existed by its deadline, so the ${truncation.FORWARD_SECURE.records.length}-record prefix is stale relative to that bound.`,
    };
  }
  return {
    verdict: 'unknown',
    text: 'No external observer supplied a newer lower bound. Timestamps or tags supplied by the compromised logger do not prove that this view is current.',
  };
}

function propertyCard(property: string, heading: string, statusId: string, card: Card): string {
  return `<article class="kea-property" data-property="${property}" data-verdict="${card.verdict}">
    <h3>${heading}</h3><p id="${statusId}">${escapeText(card.text)}</p>
  </article>`;
}

function boundary(experiment: Experiment): string {
  const c = experiment.beforePeriod;
  return `<dl id="kea-boundary" class="kea-boundary">
    <div><dt>Log ID</dt><dd><code id="kea-log-id">${escapeText(experiment.logId)}</code></dd></div>
    <div><dt>Compromise boundary</dt><dd id="kea-compromise-label">Immediately before period ${c}; the logger exposes S_${c}.</dd></div>
    <div><dt>Retained checkpoint</dt><dd>Count ${c} plus the tag at period ${c - 1}, retained outside the logger and committing to periods 0–${c - 1}.</dd></div>
    <div><dt>Terminal record</dt><dd>Expected teaching fixture: CLOSE at period ${CLOSE_PERIOD}.</dd></div>
    <div class="kea-field-wide"><dt>Static compromised state</dt><dd><code id="kea-static-compromised-state">${bytesToHex(experiment.tracks.STATIC.compromise.state)}</code></dd></div>
    <div class="kea-field-wide"><dt>Key-evolving compromised state</dt><dd><code id="kea-forward-compromised-state">${bytesToHex(experiment.tracks.FORWARD_SECURE.compromise.state)}</code></dd></div>
  </dl>`;
}

function wireEvidence(experiment: Experiment | undefined): string {
  if (!experiment) {
    return '<p>Build the comparison to expose this run’s synthetic verifier states, checkpoints, records, and full tags.</p>';
  }
  return `<p class="kea-wire-warning">These are synthetic teaching secrets rendered so the computation can be independently checked. Only the two compromised states above belong to the modeled logger attacker; the initial states remain with the private verifier.</p>
    <dl class="kea-wire-secrets">
      <div><dt>Static verifier S_0</dt><dd><code id="kea-static-initial-state">${bytesToHex(experiment.tracks.STATIC.initialState)}</code></dd></div>
      <div><dt>Key-evolving verifier S_0</dt><dd><code id="kea-forward-initial-state">${bytesToHex(experiment.tracks.FORWARD_SECURE.initialState)}</code></dd></div>
      <div><dt>Static checkpoint tag</dt><dd><code id="kea-static-checkpoint-tag">${experiment.tracks.STATIC.checkpoint.lastTag}</code></dd></div>
      <div><dt>Key-evolving checkpoint tag</dt><dd><code id="kea-forward-checkpoint-tag">${experiment.tracks.FORWARD_SECURE.checkpoint.lastTag}</code></dd></div>
    </dl>
    <ol id="kea-records" class="kea-records">${originalRecords(experiment)}</ol>`;
}

/**
 * A stable, self-contained S02 exercise. The outer app may detach and reattach
 * this element during its own full render; all experiment state and listeners
 * stay with the element until the app deliberately creates a fresh panel.
 */
export function keyEvolvingAuditPanel(): HTMLElement {
  const panel = document.createElement('section');
  panel.className = 'panel key-evolving-audit';
  panel.id = 'key-evolving-audit-lab';
  panel.setAttribute('aria-labelledby', 'key-evolving-audit-heading');

  let compromisePeriod = 3;
  let completenessInput: CompletenessInput = 'none';
  let freshnessInput: FreshnessInput = 'none';
  let experiment: Experiment | undefined;
  let prior: AttackPair | undefined;
  let suffix: AttackPair | undefined;
  let truncation: TruncationPair | undefined;
  let status = 'Not run. Choose the external trust inputs, then build both logs.';
  let state: 'ready' | 'built' | 'error' = 'ready';
  let retired = false;

  function clearEvidence(): void {
    disposeExperiment(experiment);
    experiment = undefined;
    prior = undefined;
    suffix = undefined;
    truncation = undefined;
  }

  function retire(reason: string): void {
    const hadEvidence = experiment !== undefined;
    clearEvidence();
    state = 'ready';
    retired = hadEvidence;
    status = hadEvidence ? `Previous results retired. ${reason}` : `Selection updated. ${reason}`;
  }

  function restoreFocus(id: string | null): void {
    if (!id || !panel.isConnected) return;
    panel.querySelector<HTMLElement>(`#${CSS.escape(id)}`)?.focus();
  }

  function act(controlId: string, action: () => void): void {
    try {
      action();
    } catch (error) {
      const hadEvidence = experiment !== undefined;
      clearEvidence();
      state = 'error';
      retired = hadEvidence;
      status = `Experiment error: ${error instanceof Error ? error.message : String(error)} No security result is available.`;
    }
    render();
    restoreFocus(controlId);
  }

  function bind(): void {
    const compromiseSelect = panel.querySelector<HTMLSelectElement>('#kea-compromise-period')!;
    const completenessSelect = panel.querySelector<HTMLSelectElement>('#kea-completeness-input')!;
    const freshnessSelect = panel.querySelector<HTMLSelectElement>('#kea-freshness-input')!;

    compromiseSelect.addEventListener('change', () => {
      const next = Number.parseInt(compromiseSelect.value, 10);
      if (next === compromisePeriod) return;
      compromisePeriod = next;
      retire('Build again at the new compromise boundary.');
      render();
      restoreFocus('kea-compromise-period');
    });
    completenessSelect.addEventListener('change', () => {
      const next: CompletenessInput =
        completenessSelect.value === 'trusted-close' ? 'trusted-close' : 'none';
      if (next === completenessInput) return;
      completenessInput = next;
      retire('Build again with the new completeness input.');
      render();
      restoreFocus('kea-completeness-input');
    });
    freshnessSelect.addEventListener('change', () => {
      const next: FreshnessInput =
        freshnessSelect.value === 'trusted-heartbeat' ? 'trusted-heartbeat' : 'none';
      if (next === freshnessInput) return;
      freshnessInput = next;
      retire('Build again with the new freshness input.');
      render();
      restoreFocus('kea-freshness-input');
    });

    panel.querySelector('#kea-build')!.addEventListener('click', () => {
      act('kea-build', () => {
        clearEvidence();
        experiment = buildExperiment(compromisePeriod);
        state = 'built';
        retired = false;
        status = `Built two ${RECORD_COUNT}-record logs and exposed each logger state immediately before period ${compromisePeriod}.`;
      });
    });
    panel.querySelector('#kea-rewrite-prior')!.addEventListener('click', () => {
      act('kea-rewrite-prior', () => {
        if (!experiment) throw new Error('Build the comparison first.');
        prior = priorRewrite(experiment);
        status = `Attempted to rewrite period ${experiment.beforePeriod - 1} using only state exposed before period ${experiment.beforePeriod}.`;
      });
    });
    panel.querySelector('#kea-forge-suffix')!.addEventListener('click', () => {
      act('kea-forge-suffix', () => {
        if (!experiment) throw new Error('Build the comparison first.');
        suffix = forgedSuffix(experiment);
        status = `Forged and verified a replacement chain beginning at compromised period ${experiment.beforePeriod}.`;
      });
    });
    panel.querySelector('#kea-truncate')!.addEventListener('click', () => {
      act('kea-truncate', () => {
        if (!experiment) throw new Error('Build the comparison first.');
        truncation = truncatedPrefix(experiment, completenessInput, freshnessInput);
        status = `Deleted periods ${experiment.beforePeriod}–${CLOSE_PERIOD} and checked integrity, checkpoint consistency, completeness, and freshness separately.`;
      });
    });
    panel.querySelector('#kea-reset')!.addEventListener('click', () => {
      act('kea-reset', () => {
        clearEvidence();
        compromisePeriod = 3;
        completenessInput = 'none';
        freshnessInput = 'none';
        state = 'ready';
        retired = false;
        status = 'Reset: defaults restored; previous synthetic states were zeroized best-effort.';
      });
    });
  }

  function render(): void {
    const forward = forwardCard(prior, suffix);
    const checkpoint = checkpointCard(prior, suffix, truncation);
    const completeness = completenessCard(truncation, completenessInput);
    const freshness = freshnessCard(truncation, freshnessInput);
    const actionsDisabled = experiment ? '' : ' disabled';
    panel.dataset.state = state;
    panel.dataset.retired = String(retired);
    panel.innerHTML = `<h2 id="key-evolving-audit-heading">What survives a logging-key compromise?</h2>
      <p class="panel-lede">Compare one static HMAC state with a domain-separated key-evolving chain. Compromise is modeled immediately <strong>before</strong> period <em>c</em>: the attacker learns logger state S_c, after states for earlier periods were erased, and can derive period c and later states.</p>

      <div class="kea-controls">
        <label for="kea-compromise-period">Compromise boundary
          <select id="kea-compromise-period" class="chip">
            ${[2, 3, 4].map((period) => periodOption(period, compromisePeriod)).join('')}
          </select>
        </label>
        <label for="kea-completeness-input">External completeness input
          <select id="kea-completeness-input" class="chip">
            <option value="none"${completenessInput === 'none' ? ' selected' : ''}>No trusted CLOSE expectation</option>
            <option value="trusted-close"${completenessInput === 'trusted-close' ? ' selected' : ''}>Trusted verifier expects CLOSE at period ${CLOSE_PERIOD}</option>
          </select>
        </label>
        <label for="kea-freshness-input">External freshness input
          <select id="kea-freshness-input" class="chip">
            <option value="none"${freshnessInput === 'none' ? ' selected' : ''}>No outside heartbeat observation</option>
            <option value="trusted-heartbeat"${freshnessInput === 'trusted-heartbeat' ? ' selected' : ''}>Observer retained receipt for ${RECORD_COUNT} records by deadline</option>
          </select>
        </label>
      </div>

      <div class="controls-row kea-build-controls">
        <button id="kea-build" class="chip" type="button">Build both logs + compromise state</button>
        <button id="kea-reset" class="chip ghost" type="button">Reset this exercise</button>
      </div>
      <div class="controls-row kea-attack-controls" role="group" aria-label="Audit-log attack controls">
        <button id="kea-rewrite-prior" class="chip" type="button"${actionsDisabled}>Rewrite a pre-compromise record</button>
        <button id="kea-forge-suffix" class="chip" type="button"${actionsDisabled}>Forge the compromised suffix</button>
        <button id="kea-truncate" class="chip" type="button"${actionsDisabled}>Delete the final records</button>
      </div>
      <p id="kea-status" class="kea-status" role="status" aria-live="polite">${escapeText(status)}</p>

      ${experiment ? boundary(experiment) : ''}

      <div id="kea-property-results" class="kea-property-results" role="group" aria-label="Separate audit-log results">
        ${propertyCard('forward-integrity', 'Forward integrity', 'kea-forward-integrity-status', forward)}
        ${propertyCard('checkpoint-consistency', 'Append-only checkpoint consistency', 'kea-checkpoint-status', checkpoint)}
        ${propertyCard('completeness', 'Completeness / truncation', 'kea-completeness-status', completeness)}
        ${propertyCard('freshness', 'Freshness', 'kea-freshness-status', freshness)}
      </div>

      <div id="kea-attack-evidence" class="kea-attack-evidence">${attackEvidence(experiment, prior, suffix, truncation)}</div>

      <details id="kea-construction-details" class="kea-details">
        <summary>Construction and trust inputs</summary>
        <div class="kea-details-body">
          <p>The framing rule is exact: <code>FRAME(fields) = U32BE(fieldCount) || each(U32BE(byteLength) || bytes)</code>. Integers inside a field use unsigned 64-bit big-endian encoding, text must be well-formed UTF-16 and uses its exact UTF-8 bytes, and the first previous tag is 32 zero bytes.</p>
          <p>For period i, the separate record key is <code>tagKey_i = HMAC-SHA-256(S_i, FRAME("crypto-lab/envelope-kms/log/v1/tag-key", scheme, logId, U64BE(i)))</code>. The running tag is <code>tag_i = HMAC-SHA-256(tagKey_i, FRAME("crypto-lab/envelope-kms/log/v1/record", versionByte, scheme, logId, U64BE(i), kind, message, previousTag))</code>. The message remains plaintext.</p>
          <p>Forward mode updates <code>S_(i+1) = HMAC-SHA-256(S_i, FRAME("crypto-lab/envelope-kms/log/v1/update", "FORWARD_SECURE", logId, U64BE(i)))</code>, then models erasing S_i and tagKey_i. Static mode deliberately keeps S_0. The retained checkpoint is the tuple <code>(version, scheme, logId, recordCount, lastTag)</code>.</p>
          <p>This is a bounded teaching adaptation with one logger and one private verifier, not a standardized wire format or a proof for a production logging system. Primary background: <a href="https://eprint.iacr.org/2001/035">Bellare and Yee, Forward-Security in Private-Key Cryptography</a>; <a href="https://www.schneier.com/wp-content/uploads/2016/02/paper-secure-logs.pdf">Schneier and Kelsey, Cryptographic Support for Secure Logs on Untrusted Machines</a>; <a href="https://www.rfc-editor.org/rfc/rfc2104.html">RFC 2104</a>; and <a href="https://www.rfc-editor.org/rfc/rfc4231.html">RFC 4231</a>. <a href="https://www.rfc-editor.org/rfc/rfc9162.html">RFC 9162</a> is linked only to contrast its Merkle consistency proofs with this lesson's linear checkpoint.</p>
        </div>
      </details>

      <details id="kea-wire-details" class="kea-details">
        <summary>Inspect this run's complete wire evidence</summary>
        <div class="kea-details-body">${wireEvidence(experiment)}</div>
      </details>

      <section class="kea-scope" aria-labelledby="kea-scope-heading">
        <h3 id="kea-scope-heading">Scope that every result keeps</h3>
        <ul id="kea-limits">
          <li>This is symmetric/private verification. A verifier holding S_0 can forge; compromise of that verifier defeats the history claim.</li>
          <li>Messages remain plaintext. Authentication detects certain record changes; it does not prove that a logged event was true.</li>
          <li>JavaScript erasure is best-effort. Crash atomicity, rollback, concurrency, snapshots, and backup copies are outside this browser model.</li>
          <li>The checkpoint is a linear retained-prefix comparison. It is not an RFC 9162 Merkle consistency proof, Certificate Transparency, or a gossip protocol.</li>
          <li>Key evolution alone does not establish completeness or freshness. Those results require their own trusted external expectations.</li>
        </ul>
      </section>`;
    bind();
  }

  render();
  PANEL_DISPOSERS.set(panel, clearEvidence);
  return panel;
}
