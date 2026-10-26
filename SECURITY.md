# Security Policy

## Scope

This is an **educational demo**. It is intentionally simplified and is **not** a hardened, production-ready KMS. Do not use this codebase to protect real data.

## Real cryptographic primitives in use

- **AES-256-GCM** for envelope sealing/opening (WebCrypto `crypto.subtle`).
- **AES Key Wrap (RFC 3394)** for wrapping data encryption keys and for the separate key-handle model's byte-returning decrypt operation using the same mechanism.
- **AES Key Wrap with Padding (RFC 5649)** for wrapping non-aligned material.
- **HKDF-SHA-256** (RFC 5869) for key derivation.
- **SHA-256** for the audit log's hash chain.
- **HMAC-SHA-256** (RFC 2104 and RFC 4231) for the isolated key-evolving audit-log exercise.

The envelope primitives retain their startup RFC-vector checks in `src/crypto/rfc-vectors.ts`. The unit suite (`npm run test`) also checks those vectors and independently checks HMAC-SHA-256 against RFC 4231.

## Known limitations vs. a real KMS

| Concern                  | Production KMS                                 | This demo                                                        |
| ------------------------ | ---------------------------------------------- | ---------------------------------------------------------------- |
| Root KEK boundary        | HSM (FIPS 140-3 L3+)                           | Module-scoped, in-process memory                                 |
| KEK material at rest     | Sealed in HSM, never exported                  | `Uint8Array` in `KekStore`                                       |
| DEK lifetime             | Zeroized on memory free                        | Zeroized via `bytes.zeroize()` ASAP                              |
| Audit log durability     | Append-only, authenticated, off-host           | Basic log in `localStorage`; separate in-memory compromise model |
| Access control           | Authenticated callers, key policies and grants | Toy grant on `Decrypt`; unverified labels; normal API permissive |
| Multi-region replication | Cryptographically-bound replicas               | Simulated in one runtime                                         |
| Side-channel resistance  | Constant-time HSM operations                   | Best-effort JS (e.g. `equalBytes`)                               |

RFC 3394/5649 protect the wrapped key material in this implementation but accept no separate AAD parameter. The context is authenticated by AES-GCM on the payload, and changing it leaves the wrapped DEK unchanged. The browser keeps raw DEK bytes in memory for the demonstration, and `Decrypt` can return them. The teaching grant does not make them non-extractable or protect against direct calls to the normal permissive API. See [RFC 3394 §2.2.3.1](https://www.rfc-editor.org/rfc/rfc3394.html#section-2.2.3.1), [WebCrypto AES-GCM](https://www.w3.org/TR/WebCryptoAPI/#aes-gcm), and [AWS KMS key policies](https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html).

**The key-evolving audit log is a separate, integrity-only teaching model.** It derives a distinct per-period tag key and successor state through domain-separated HMAC-SHA-256 branches. A compromise immediately before period `c` exposes the state needed to authenticate period `c` and derive every later period. Under the explicit assumption that earlier states and tag keys were successfully erased, it does not expose the keys for periods before `c`. The ordinary comparison track deliberately reuses one static HMAC key, so stealing that key permits authenticating a rewritten history.

The exercise does not claim the full Schneier–Kelsey secure-logging protocol or Bellare–Yee's exact proven construction. Its `Uint8Array.fill(0)` calls make erasure visible and testable but cannot guarantee erasure in a JavaScript engine, garbage collector, debugger, browser extension, or compromised same-origin runtime. The verifier's initial material and retained checkpoints are modeled as separate trusted inputs and are not persisted in `localStorage`. A retained checkpoint can establish agreement with a prefix; by itself it cannot establish that no records were removed afterward. Likewise, a valid close record or recent logger-supplied timestamp is not trusted freshness evidence when the attacker already controlled the current key. The UI therefore keeps forward integrity, checkpoint consistency, completeness, and freshness as separate outcomes. See the [model brief](docs/forward-secure-audit-log-brief.md), [Bellare–Yee](https://eprint.iacr.org/2001/035), [Schneier–Kelsey](https://www.schneier.com/wp-content/uploads/2016/02/paper-secure-logs.pdf), and [RFC 9162 §2.1.4](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1.4).

**The key-handle exercise has a separate policy model.** `HandleToken` in `src/kms/key-handles.ts` models sensitive keys behind opaque handles; it does not change the normal KMS API. Sensitive keys refuse direct value reads. The default target is sensitive and wrappable (`extractable=true`); selecting a nonextractable target (`extractable=false`) instead refuses wrapping under both policies. The wrapping key is generated internally, is sensitive and nonextractable, uses different bytes from the target, and starts with wrapping/unwrapping permissions only. Fixed roles are the default and refuse adding byte-returning decrypt permission. The intentionally unsafe mutable policy permits that one transition.

**The exposure is measured, with cryptographic checks still active.** Wrapping a 32-byte target produces a 40-byte RFC 3394 blob. In the mutable-usage trace, decrypting that blob with the wrapping key and the same AES-KW mechanism returns the target's actual 32 bytes. Independent WebCrypto AES-GCM challenge decryption demonstrates that those bytes can be used outside the handle API; successful extraction is presented as a confidentiality alarm. The trace does not bypass RFC 3394 integrity or decrypt an AES-KW blob with AES-GCM. The positive path unwraps to a fresh sensitive, nonextractable data handle using a fixed output template and can still open the challenge under fixed roles, without returning key bytes.

**These are boundaries of a browser model.** `HandleToken` has no hardware token, full PKCS #11 emulator, authenticated login, general key import, copy, derive, restore or security guarantee across sessions. Unknown and foreign-token handles are refused, but that store-membership check is not caller authentication. No key material from this exercise is persisted or sent over the network; JavaScript memory, developer tools, same-origin code and runtime compromise remain outside its protection. The optional deterministic key factory is for unit fixtures only. The browser uses internally generated keys.

**The bounded explorer is a separate model, not a wider token API.** `src/kms/key-handle-search.ts` records symbolic key values separately from public handles, finite per-handle capabilities, AES-KW blob terms, and attacker-known raw values. It searches three presets: the existing mutable wrapping role, a caller-known key imported through a privileged unwrap template, and two distinct handles containing equal key bytes with conflicting roles. The invariant is that the protected target never enters attacker-known raw values. Unsafe witnesses are replayed with fresh, distinct AES-256 values and real RFC 3394; recovered bytes must independently open a fresh AES-GCM challenge.

The explorer performs deterministic breadth-first search through at most four successful API calls, four handles, four blobs, three finite templates, and 50,000 retained non-witness states. Every generated successor is checked for an invariant violation before the non-witness retention cap applies. Rejected calls are atomic and do not consume successful-call depth. A state-cap hit is **incomplete**. Exhausting this graph permits only “no witness within these bounds,” never “secure” or “attack impossible.” The fixed policy keeps roles fixed, accepts only a sensitive, nonextractable GCM data-handle template, and rejects caller-selected AES-KW roles; that policy is a deliberately narrow teaching defense, not PKCS #11 conformance.

Neither exercise assesses a vendor HSM. Unmodeled mechanisms, copy/derive operations, sessions, authentication, concurrency, larger bounds, runtime compromise, and side channels remain outside scope. RFC 3394 integrity-checks the 32 key bytes in this implementation's blob; the explorer does not claim that caller-selected role metadata is inside or integrity-checked by that 40-byte blob. See the [manual-trace brief](docs/key-handles-brief.md), [bounded-search brief](docs/key-handle-state-search-brief.md), [Delaune–Kremer–Steel](https://doi.org/10.3233/JCS-2009-0394), and [OASIS PKCS #11 v3.2](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html).

## Reporting an issue

If you find a security-relevant bug — even though this is a demo — please open an issue at:

https://github.com/systemslibrarian/crypto-lab-envelope-kms/issues

Or email the repository owner directly via their GitHub profile. For real-world cryptographic vulnerabilities, please follow responsible disclosure practices.

## Cryptographic correctness

Any change that touches `src/crypto/**` **must**:

1. Keep the existing RFC vectors green (`npm run test`).
2. Add a new vector or property test if the change introduces new behavior.
3. Avoid introducing variable-time branches over secret material.

Pull requests modifying crypto code without test coverage will not be merged.

The key-handle suites additionally check fixed-role and fixed-template refusals, nonextractable wrapping, legitimate unwrap-to-handle use, defensive snapshots, mechanism separation, malformed inputs, deterministic shortest search, below-bound misses, cutoff labeling, same-value handles, integrity failures, and unchanged state after rejected calls. RFC 3394 fixtures and native WebCrypto checks independently test the mechanism; unit tests independently open all three replay challenges, and a browser claim opens the rendered known-key-import challenge using only displayed bytes. Run `npm run test:claims:mutations` for the combined key-handle and audit-log fault-injection gate; `npm run test:key-handles:mutations` remains a compatibility alias. Follow the briefs' committed-baseline and restore requirements. Passing these checks establishes the tested behavior within the declared model and bounds, not security for unmodeled operation sequences.

The audit-log suite additionally checks RFC 4231 HMAC output, independent WebCrypto agreement, fixed construction vectors, exact compromise boundaries, earlier and suffix rewrites, retained checkpoints, malformed records, truncation, forged close records, and replay with or without trusted external bounds. Run `npm run test:claims:mutations` for the combined clean-baseline browser mutation gate.

## Key-wrap integrity and expected length

A rejected tamper trial is an observed result, not a guarantee that forgery has zero probability. `aesKwpUnwrap(kek, ciphertext, expectedLength?)` optionally requires a trusted application-supplied plaintext length. It always checks the RFC 5649 AIV prefix, recovered-length range and zero padding, then checks the expected length before releasing plaintext. The optional policy must not be inferred from attacker-supplied data. Omitting it preserves RFC behavior, including the single-block path for 1–8-byte inputs.

John Preuß Mattsson, *Revisiting AES Key Wrap: Forgery Bounds, Structural Observations, and Recommendations for the Revision of NIST SP 800-38F*, [ePrint 2026/2636](https://eprint.iacr.org/2026/2636), section 4.2, analyzes conditional forgery bounds. Its idealized fixed-length expression is 2^(-64-8p), where p is the number of padding bytes: 32-byte AES-256 keys have no extra padding contribution (2^-64); 66-byte material has six padding bytes (2^-112 in that model). This is not a universal adaptive-forgery guarantee. The October 2026 preprint is not a finalized NIST requirement. This lab does not adopt its proposed minimum-length construction change. Replay prevention and context binding remain application responsibilities.
