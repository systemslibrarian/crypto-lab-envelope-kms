# crypto-lab-envelope-kms

[![CI](https://github.com/systemslibrarian/crypto-lab-envelope-kms/actions/workflows/ci.yml/badge.svg)](https://github.com/systemslibrarian/crypto-lab-envelope-kms/actions/workflows/ci.yml)
[![CodeQL](https://github.com/systemslibrarian/crypto-lab-envelope-kms/actions/workflows/codeql.yml/badge.svg)](https://github.com/systemslibrarian/crypto-lab-envelope-kms/actions/workflows/codeql.yml)
[![Pages](https://github.com/systemslibrarian/crypto-lab-envelope-kms/actions/workflows/pages.yml/badge.svg)](https://github.com/systemslibrarian/crypto-lab-envelope-kms/actions/workflows/pages.yml)

## What It Is

Envelope encryption is the operational layer of modern cryptographic architecture — a data encryption key (DEK) encrypts data; a key encryption key (KEK) encrypts DEKs; a root KEK encrypts KEKs. This demo implements:

- A **plain-language primer** that grounds DEK, KEK, and root-KEK in the paper-key / safe / vault analogy before any acronym is reused, so the hierarchy is defined up front rather than assumed.
- A **"Watch the wrap" visualizer** that replays a real seal step-by-step: a random 32-byte DEK is drawn, used to AES-256-GCM-encrypt your data, wrapped under the KEK, and then its plaintext copy is zeroized on screen. Every hex value shown is the actual value computed in the browser.
- An **interactive seal** — type your own plaintext and context/AAD, then use **Open as a different tenant** to watch the real AES-GCM tag refuse to open your envelope under a mismatched context.
- **RFC 3394** AES Key Wrap and **RFC 5649** padded Key Wrap, validated against the official test vectors.
- A **KMS-style API surface** (`CreateKey`, `GenerateDataKey`, `Encrypt`, `Decrypt`, `ReEncrypt`, `RotateKey`, `ScheduleKeyDeletion`).
- **Versioned KEK rotation** with `active`, `decrypt-only`, and `pending-deletion` states.
- A **SHA-256 hash-chained audit log** with a tamper-detection demo that highlights the exact digest byte that changed and draws the broken link between an entry's hash and the next entry's `prev_hash`.
- A **"Try to Break It" security lab** — one-click experiments that run the _real_ primitives and attempt to defeat each guarantee (wrong AAD, tampered ciphertext, cross-tenant unwrap, corrupted key wrap, rotation), so the properties are demonstrated rather than asserted. It sits behind a **"Ready to go deeper?"** disclosure so the page opens with intuition and layers the attacks on top.

The security model assumes KEKs never leave a trust boundary and that the audit log is append-only.

## When to Use It

- Encrypting large volumes of data where round-tripping every byte to an HSM is impractical — envelope encryption amortizes the HSM call across the object.
- Multi-tenant systems needing per-tenant key isolation — the KEK hierarchy enforces it cryptographically.
- Regulated environments (PCI-DSS, HIPAA, FedRAMP) requiring documented key rotation and audit trails.
- Do **NOT** use this pattern for ephemeral session keys — TLS-style key schedules are the right shape there.
- Do **NOT** reinvent — real deployments use AWS KMS, Google Cloud KMS, Azure Key Vault, or HashiCorp Vault. This demo shows how they work internally.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-envelope-kms](https://systemslibrarian.github.io/crypto-lab-envelope-kms/)**

Users can read the primer, generate KEKs, type their own plaintext and context, seal and watch the DEK be drawn / used / wrapped / zeroized in the "Watch the wrap" panel, open envelopes (and try to open them as a different tenant and watch the AAD binding refuse), rotate a KEK and watch old envelopes still decrypt, re-wrap envelopes to the new version, tamper with the audit log to see the hash chain detect it, and — under "Ready to go deeper?" — run the security-properties experiments to watch the crypto reject every attack.

## What Can Go Wrong

- **KEK compromise is total.** Because every DEK is wrapped under a KEK, leakage of a KEK (or the root KEK) exposes all data encrypted under it; the whole model rests on KEKs never leaving the trust boundary.
- **Rotation without re-wrap.** Rotating a KEK does not re-encrypt existing envelopes; the old KEK version must be retained in `decrypt-only` state, and deleting it too early permanently loses access to data still wrapped under it.
- **AAD / context misuse.** AES-GCM and key wrap bind associated data; omitting or mismatching the AAD (tenant/context) can allow a ciphertext to be decrypted in the wrong context or break decryption entirely.
- **Audit-log integrity assumptions.** Tamper detection relies on the hash chain plus an append-only store; if the log can be silently rewritten or truncated, the integrity guarantee is lost.
- **Multi-tenant isolation gaps.** If unwrap requests are not strictly scoped per tenant/key, a cross-tenant unwrap can break the isolation the KEK hierarchy is meant to enforce.

## Real-World Usage

- **AWS KMS** — `GenerateDataKey` returns a plaintext DEK plus a wrapped DEK; the envelope pattern in this demo mirrors its API surface.
- **Google Cloud KMS and Azure Key Vault** — provide managed KEKs and key wrap/unwrap for the same DEK/KEK hierarchy.
- **HashiCorp Vault** — the transit secrets engine performs envelope-style encryption and key rotation for applications.
- **Storage-at-rest encryption** — services like S3, EBS, and database TDE use envelope encryption so bulk data is encrypted under DEKs while only KEKs touch the HSM/KMS.
- **Regulated workloads** — PCI-DSS, HIPAA, and FedRAMP deployments use envelope encryption with documented KEK rotation and audit trails.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-envelope-kms
cd crypto-lab-envelope-kms
npm install
npm run dev
```

Additional scripts: `npm run test` runs the suite (RFC vectors, envelope, audit chain, KEK store); `npm run ci` runs typecheck + lint + test + build (same as CI).

## Related Demos

- [crypto-lab-aes-modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/) — AES-GCM and authenticated encryption, the DEK layer of this demo.
- [crypto-lab-format-ward](https://systemslibrarian.github.io/crypto-lab-format-ward/) — FF1/FF3-1 format-preserving encryption and tokenization for data at rest.
- [crypto-lab-kdf-chain](https://systemslibrarian.github.io/crypto-lab-kdf-chain/) — HKDF/PBKDF2/scrypt/Argon2id key derivation feeding key hierarchies.
- [crypto-lab-pq-rotation](https://systemslibrarian.github.io/crypto-lab-pq-rotation/) — hybrid X.509 and CNSA 2.0 key rotation and migration planning.

## Architecture at a glance

```
   ┌────────────┐    1. GenerateDataKey         ┌────────────┐
   │            │ ────────────────────────────► │            │
   │  Client    │                                │    KMS     │
   │  (browser) │ ◄──────────────────────────── │ (in-mem)   │
   │            │   plaintextDEK + wrappedDEK    │            │
   └─────┬──────┘                                └─────┬──────┘
         │                                              │
         │ 2. AES-256-GCM seal under DEK                │ 3. Decrypt(wrappedDEK)
         │                                              │
         ▼                                              ▼
   ┌────────────┐                                ┌────────────┐
   │  Storage   │                                │   Root KEK │
   │ ciphertext │                                │   (HSM in  │
   │ +wrappedDEK│                                │   real life)│
   └────────────┘                                └────────────┘
```

See [SECURITY.md](./SECURITY.md) for what's real vs. simulated, and [CONTRIBUTING.md](./CONTRIBUTING.md) for development workflow.

---

_One of 170+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite._

_"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31_
