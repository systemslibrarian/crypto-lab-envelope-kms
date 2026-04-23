type FlowLine = { step: string; bytes: string };

const FLOWS: Record<string, FlowLine[]> = {
  GenerateDataKey: [
    { step: 'Client -> KMS: GenerateDataKey(keyId)', bytes: 'request ~ 64B' },
    { step: 'KMS: random DEK (32B) + wrap under KEK', bytes: 'internal 32B' },
    { step: 'KMS -> Client: plaintextDEK + wrappedDEK + metadata', bytes: 'response ~ 120B' },
  ],
  Encrypt: [
    { step: 'Client: AES-256-GCM encrypt plaintext under DEK', bytes: 'iv=12B tag=16B' },
    { step: 'Client -> Storage: ciphertext + wrappedDEK + kekId/version', bytes: 'object payload + 64B envelope' },
  ],
  Decrypt: [
    { step: 'Client -> Storage: read envelope', bytes: 'request varies' },
    { step: 'Client -> KMS: Decrypt(wrappedDEK, kekId, kekVersion)', bytes: 'request ~ 96B' },
    { step: 'KMS -> Client: plaintextDEK', bytes: 'response 32B' },
    { step: 'Client: AES-256-GCM decrypt with AAD', bytes: 'iv=12B tag=16B' },
  ],
  ReEncrypt: [
    { step: 'Client -> KMS: ReEncrypt(wrappedDEK, source, dest)', bytes: 'request ~ 120B' },
    { step: 'KMS: unwrap source DEK and wrap with destination KEK', bytes: 'internal DEK 32B' },
    { step: 'KMS -> Client: new wrappedDEK + destination metadata', bytes: 'response ~ 72B' },
  ],
};

export function renderRequestFlow(active = 'GenerateDataKey'): string {
  const rows = FLOWS[active] ?? FLOWS.GenerateDataKey;
  const options = Object.keys(FLOWS)
    .map((name) => `<button class="chip flow-btn" data-flow="${name}">${name}</button>`)
    .join('');

  return `<section class="panel">
    <h2>Request Flow</h2>
    <div class="chip-row">${options}</div>
    <ol class="flow-list">
      ${rows.map((r) => `<li><strong>${r.step}</strong><span>${r.bytes}</span></li>`).join('')}
    </ol>
  </section>`;
}
