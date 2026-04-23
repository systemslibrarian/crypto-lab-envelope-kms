# crypto-lab-envelope-kms

[![CI](https://github.com/systemslibrarian/crypto-lab-envelope-kms/actions/workflows/ci.yml/badge.svg)](https://github.com/systemslibrarian/crypto-lab-envelope-kms/actions/workflows/ci.yml)
[![Pages](https://github.com/systemslibrarian/crypto-lab-envelope-kms/actions/workflows/pages.yml/badge.svg)](https://github.com/systemslibrarian/crypto-lab-envelope-kms/actions/workflows/pages.yml)

## 1. What It Is

Envelope encryption is the operational layer of modern cryptographic architecture — a data encryption key (DEK) encrypts data; a key encryption key (KEK) encrypts DEKs; a root KEK encrypts KEKs. This demo implements:

- **RFC 3394** AES Key Wrap and **RFC 5649** padded Key Wrap, validated against the official test vectors.
- A **KMS-style API surface** (`CreateKey`, `GenerateDataKey`, `Encrypt`, `Decrypt`, `ReEncrypt`, `RotateKey`, `ScheduleKeyDeletion`).
- **Versioned KEK rotation** with `active`, `decrypt-only`, and `pending-deletion` states.
- A **SHA-256 hash-chained audit log** with a tamper-detection demo.

The security model assumes KEKs never leave a trust boundary and that the audit log is append-only.

## 2. When to Use It

- Encrypting large volumes of data where round-tripping every byte to an HSM is impractical — envelope encryption amortizes the HSM call across the object.
- Multi-tenant systems needing per-tenant key isolation — the KEK hierarchy enforces it cryptographically.
- Regulated environments (PCI-DSS, HIPAA, FedRAMP) requiring documented key rotation and audit trails.
- Do **NOT** use this pattern for ephemeral session keys — TLS-style key schedules are the right shape there.
- Do **NOT** reinvent — real deployments use AWS KMS, Google Cloud KMS, Azure Key Vault, or HashiCorp Vault. This demo shows how they work internally.

## 3. Live Demo

→ https://systemslibrarian.github.io/crypto-lab-envelope-kms/

Users can generate KEKs, seal and open envelopes, rotate a KEK and watch old envelopes still decrypt, re-wrap envelopes to the new version, and tamper with the audit log to see the hash chain detect it.

## 4. How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-envelope-kms
cd crypto-lab-envelope-kms
npm install
npm run dev      # http://localhost:5173
npm run test     # run the test suite (RFC vectors, envelope, audit chain, KEK store)
npm run ci       # typecheck + lint + test + build (same as CI)
```

## 5. Architecture at a glance

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

## 6. Part of the Crypto-Lab Suite

> One of 100+ live browser demos at
> [systemslibrarian.github.io/crypto-lab](https://systemslibrarian.github.io/crypto-lab/)
> — spanning Atbash (600 BCE) through NIST FIPS 203/204/205 (2024).

---

*"Whether you eat or drink, or whatever you do, do all to the glory of God." — 1 Corinthians 10:31*