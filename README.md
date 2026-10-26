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
- A **who may unwrap?** exercise: with a valid handle and intact wrap, the log-only `Decrypt` call accepts Mallory's caller label; an opt-in caller/key/operation grant rejects that label before unwrap, while Alice's grant succeeds. The labels are unverified browser strings, not authenticated identities.
- A **"What may this key do?"** exercise with a separate key-handle API: compare fixed roles, the default, with intentionally unsafe mutable usages. Direct key reads are refused in both, but allowing a wrapping key to gain byte-returning decrypt permission exposes a sensitive, wrappable target. Real recovered bytes open an independent AES-GCM challenge, and the result is shown as an exposure alarm. A legitimate unwrap-to-handle still works with fixed roles.
- A **bounded key-handle state explorer** that breadth-first searches the original mutable-role case plus known-key import/template confusion and same-value-handle cases. It publishes the invariant, initial attacker knowledge, transition alphabet, object/depth/state bounds, shortest witness, and cutoff status. Search witnesses are replayed with real RFC 3394 blobs and independently verified against a fresh AES-GCM challenge; a fixed-policy result says only that no witness was found within the displayed model.
- **Versioned KEK rotation** with `active`, `decrypt-only`, and `pending-deletion` states.
- A **SHA-256 hash-chained audit log** with a tamper-detection demo that highlights the exact digest byte that changed and draws the broken link between an entry's hash and the next entry's `prev_hash`.
- A separate **key-evolving audit-log compromise exercise** that compares one ordinary HMAC key with a two-branch, HMAC-SHA-256 state schedule. Compromise immediately before a chosen period exposes that period and the future, while the one-way evolution plus modeled erasure assumptions protect earlier authenticators. Retained checkpoints, expected close records, and external heartbeat receipts then show why forward integrity, append-only consistency, completeness, and freshness are different claims.
- A **"Try to Break It" security lab** — one-click experiments that run the _real_ primitives and attempt to defeat each guarantee (wrong AAD, tampered ciphertext, cross-tenant unwrap, corrupted key wrap, rotation), so the properties are demonstrated rather than asserted. It sits behind a **"Ready to go deeper?"** disclosure so the page opens with intuition and layers the attacks on top.

The normal security model assumes KEKs stay inside a trust boundary and the basic audit log is append-only. The separate KEK-compromise exhibit deliberately violates the first assumption. The key-evolving log exercise instead tests the second assumption under a logger-key compromise; it is an integrity-only teaching adaptation, not the full Schneier–Kelsey confidential logging protocol or Bellare–Yee's exact construction. See [the compromise architecture](docs/compromise.md) and [the key-evolving audit-log brief](docs/forward-secure-audit-log-brief.md). The key-handle exercises model operation policy separately; the normal KMS API still deliberately returns raw DEKs. See [the manual-trace brief](docs/key-handles-brief.md) and [bounded-search brief](docs/key-handle-state-search-brief.md) for their exact invariants and limits.

## When to Use It

- Encrypting large volumes of data where round-tripping every byte to an HSM is impractical — envelope encryption amortizes the HSM call across the object.
- Multi-tenant systems needing per-tenant key isolation — distinct KEKs separate cryptographic key material, but requests still require authenticated callers and key-scoped authorization.
- Regulated environments (PCI-DSS, HIPAA, FedRAMP) requiring documented key rotation and audit trails.
- Do **NOT** use this pattern for ephemeral session keys — TLS-style key schedules are the right shape there.
- Do **NOT** reinvent — real deployments use AWS KMS, Google Cloud KMS, Azure Key Vault, or HashiCorp Vault. This demo shows how they work internally.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-envelope-kms](https://systemslibrarian.github.io/crypto-lab-envelope-kms/)**

Users can read the primer, generate KEKs, type their own plaintext and context, seal and watch the DEK be drawn / used / wrapped / zeroized in the "Watch the wrap" panel, open envelopes (and try to open them as a different tenant and watch the AAD binding refuse), compare log-only and granted unwrap requests, rotate a KEK and watch old envelopes still decrypt, re-wrap envelopes to the new version, tamper with the audit log to see the hash chain detect it, and — under "Ready to go deeper?" — run the security-properties experiments to compare defended and weakened results.

In **"What survives a logging-key compromise?"**, build the same six-record history with an ordinary static HMAC key and with a key-evolving schedule, then compromise the logger immediately before a selected period. A prior-record rewrite succeeds with the stolen static key but fails against an erased earlier evolving key; the compromised period and later suffix remain forgeable in both tracks. Truncation can still leave a valid prefix. The panel therefore reports four claims separately and only upgrades completeness or freshness when the verifier receives the corresponding external evidence.

In **"What may this key do?"** inside that advanced disclosure, choose fixed roles or intentionally unsafe mutable usages and a sensitive target that is either wrappable or nonextractable. **Run wrap-then-decrypt trace** shows the refused direct read, the permitted or refused calls, and the actual outcome. With mutable usages and a wrappable target, the trace discloses 32 key bytes and independently opens a WebCrypto AES-GCM challenge outside the handle API. Fixed roles refuse the permission change; a nonextractable target refuses wrapping under either policy. **Wrap and unwrap to a handle** demonstrates intended use: a wrappable target becomes a new sensitive, nonextractable data handle that can open the challenge while its bytes remain unavailable through direct reads.

In **"Can another call sequence expose it?"**, choose one of three presets and compare fixed roles plus a fixed data-only unwrap template with intentionally unsafe preset rules (mutable roles in the original trace and caller-selected templates in the import cases). **Explore bounded state space** performs a deterministic breadth-first search through four successful API calls, at most four handles and four blobs, three finite templates, and a selected operational cap (50,000 retained non-witness states by default; one retained state demonstrates cutoff handling). Every generated successor is checked for a terminal witness before retention. The known-key-import witness is three API calls; the same-value-handle witness is four. A fixed-policy result reports every distinct state checked within those exact bounds, while a cutoff is labeled incomplete rather than safe.

## What Can Go Wrong

- **A stolen KEK exposes data whose DEKs it can unwrap.** The compromise experiment actually opens four envelopes with one stolen version: a shared KEK exposes both tenants, while independent KEKs contain the exposure to one tenant. Rotation alone leaves old wraps exposed. Re-wrap protects the replacement wrap but cannot revoke retained DEKs or archived copies. Fresh-DEK re-encryption protects replacement ciphertext, not previously exposed plaintext.
- **Rotation without re-wrap.** Rotating a KEK does not re-encrypt existing envelopes; the old KEK version must be retained in `decrypt-only` state, and deleting it too early permanently loses access to data still wrapped under it.
- **AAD / context misuse.** This lab passes the context as AES-GCM `additionalData`; a mismatched value fails the GCM tag check. Its RFC 3394/5649 key-wrap functions protect the wrapped key bytes but have no separate AAD argument. Changing only the context leaves the wrapped DEK intact; an application must consistently supply and check the intended context when opening ciphertext. See [WebCrypto AES-GCM](https://www.w3.org/TR/WebCryptoAPI/#aes-gcm) and [RFC 3394 §2.2.3.1](https://www.rfc-editor.org/rfc/rfc3394.html#section-2.2.3.1).
- **Audit-log integrity assumptions.** The basic unkeyed hash chain detects direct edits while the old hash and link fields survive. A writer that can replace the whole chain can recompute it unless a trusted anchor or history survives elsewhere. The separate key-evolving exercise protects earlier authenticators only under its stated logger-compromise, one-way-evolution, HMAC, and erasure assumptions. It still permits forgery from the compromised period onward, and key evolution alone does not prove that a valid prefix is complete or fresh.
- **Multi-tenant isolation gaps.** The normal `KmsApi.Decrypt` only logs its caller-supplied `principal` and grants use to anyone with a valid wrapped-key reference. The opt-in `decryptWithGrants` exercise checks a caller/key/`Decrypt` tuple before touching key material, but a real KMS also authenticates that caller and enforces key policies. [AWS KMS key policies](https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html) illustrate the production distinction. Neither path here provides a hardware HSM or non-extractable DEK: `Decrypt` returns raw key bytes, which the exercise zeroizes after comparison.
- **Individually allowed calls can disclose a sensitive key.** Sensitive means direct value reads are forbidden; wrappable means an encrypted representation may leave the model. Those differ from nonextractable. The manual mutable-usage trace composes AES-KW wrapping and byte-returning AES-KW decryption. The bounded explorer additionally finds a caller-known key imported with a wrapping role and two distinct handles containing equal bytes but conflicting roles. Every successful witness uses real RFC 3394 and independently opens an AES-GCM challenge; AES-GCM is not used to decrypt a wrap. Fixed roles and a fixed data-only unwrap template block the modeled traces, not every API composition. See the [manual-trace brief](docs/key-handles-brief.md), [bounded-search brief](docs/key-handle-state-search-brief.md), [Delaune–Kremer–Steel](https://doi.org/10.3233/JCS-2009-0394), and [OASIS PKCS #11 v3.2](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html).

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

Additional scripts: `npm run test` runs the suite (RFC vectors, envelope, audit chains, KEK store and key-handle policies); `npm run ci` runs typecheck + lint + test + build (same as CI).

For the key-handle exercises, `npx vitest run src/kms/key-handles.test.ts src/kms/key-handle-search.test.ts` runs the focused models: RFC 3394 fixtures, independent WebCrypto checks, manual-trace controls, deterministic bounded search, cutoff handling, same-value handles, and concrete witness replay. Browser claims independently open the printed challenge, and accessibility/reflow states run through `npm run test:e2e`. The compatibility alias `npm run test:key-handles:mutations` invokes the combined claim-mutation gate described below; use the committed baseline and restore procedure described in the briefs. These checks establish the named behavior within its declared bounds, not an unbounded API-security proof.

For the key-evolving audit-log exercise, `npx vitest run src/kms/forward-secure-log.test.ts` runs its RFC vector, construction, compromise-boundary, checkpoint, truncation, and replay cases. Browser claims independently recompute the displayed state schedule and tags. `npm run test:claims:mutations` runs the combined key-handle and audit-log browser mutation gate against a committed clean baseline.

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

_Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite._

_"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31_

## Publishing

`npm run deploy` requests the existing `pages.yml` workflow for the current remote `main`. That workflow runs this lab's verification gates before publishing its Pages artifact. A successful request means the run was queued; check the workflow and public site separately to confirm publication. GitHub CLI authentication and workflow-dispatch access are required. Local `dist` files are not uploaded by this command.

## Key-wrap integrity and expected length

A rejected tamper trial is an observed result, not a guarantee that forgery has zero probability. `aesKwpUnwrap(kek, ciphertext, expectedLength?)` optionally requires a trusted application-supplied plaintext length. It always checks the RFC 5649 AIV prefix, recovered-length range and zero padding, then checks the expected length before releasing plaintext. The optional policy must not be inferred from attacker-supplied data. Omitting it preserves RFC behavior, including the single-block path for 1–8-byte inputs.

John Preuß Mattsson, *Revisiting AES Key Wrap: Forgery Bounds, Structural Observations, and Recommendations for the Revision of NIST SP 800-38F*, [ePrint 2026/2636](https://eprint.iacr.org/2026/2636), section 4.2, analyzes conditional forgery bounds. Its idealized fixed-length expression is 2^(-64-8p), where p is the number of padding bytes: 32-byte AES-256 keys have no extra padding contribution (2^-64); 66-byte material has six padding bytes (2^-112 in that model). This is not a universal adaptive-forgery guarantee. The October 2026 preprint is not a finalized NIST requirement. This lab does not adopt its proposed minimum-length construction change. Replay prevention and context binding remain application responsibilities.
