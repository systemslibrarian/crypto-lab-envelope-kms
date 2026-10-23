# Security Policy

## Scope

This is an **educational demo**. It is intentionally simplified and is **not** a hardened, production-ready KMS. Do not use this codebase to protect real data.

## Real cryptographic primitives in use

- **AES-256-GCM** for envelope sealing/opening (WebCrypto `crypto.subtle`).
- **AES Key Wrap (RFC 3394)** for wrapping data encryption keys and for the separate key-handle model's byte-returning decrypt operation using the same mechanism.
- **AES Key Wrap with Padding (RFC 5649)** for wrapping non-aligned material.
- **HKDF-SHA-256** (RFC 5869) for key derivation.
- **SHA-256** for the audit log's hash chain.

All primitives are validated against the RFC test vectors at startup (see `src/crypto/rfc-vectors.ts`) and in the unit-test suite (`npm run test`).

## Known limitations vs. a real KMS

| Concern                  | Production KMS                                 | This demo                                                        |
| ------------------------ | ---------------------------------------------- | ---------------------------------------------------------------- |
| Root KEK boundary        | HSM (FIPS 140-3 L3+)                           | Module-scoped, in-process memory                                 |
| KEK material at rest     | Sealed in HSM, never exported                  | `Uint8Array` in `KekStore`                                       |
| DEK lifetime             | Zeroized on memory free                        | Zeroized via `bytes.zeroize()` ASAP                              |
| Audit log durability     | Append-only, signed, off-host                  | `localStorage` (tamperable on purpose, for the demo)             |
| Access control           | Authenticated callers, key policies and grants | Toy grant on `Decrypt`; unverified labels; normal API permissive |
| Multi-region replication | Cryptographically-bound replicas               | Simulated in one runtime                                         |
| Side-channel resistance  | Constant-time HSM operations                   | Best-effort JS (e.g. `equalBytes`)                               |

RFC 3394/5649 protect the wrapped key material in this implementation but accept no separate AAD parameter. The context is authenticated by AES-GCM on the payload, and changing it leaves the wrapped DEK unchanged. The browser keeps raw DEK bytes in memory for the demonstration, and `Decrypt` can return them. The teaching grant does not make them non-extractable or protect against direct calls to the normal permissive API. See [RFC 3394 §2.2.3.1](https://www.rfc-editor.org/rfc/rfc3394.html#section-2.2.3.1), [WebCrypto AES-GCM](https://www.w3.org/TR/WebCryptoAPI/#aes-gcm), and [AWS KMS key policies](https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html).

**The key-handle exercise has a separate policy model.** `HandleToken` in `src/kms/key-handles.ts` models sensitive keys behind opaque handles; it does not change the normal KMS API. Sensitive keys refuse direct value reads. The default target is sensitive and wrappable (`extractable=true`); selecting a nonextractable target (`extractable=false`) instead refuses wrapping under both policies. The wrapping key is generated internally, is sensitive and nonextractable, uses different bytes from the target, and starts with wrapping/unwrapping permissions only. Fixed roles are the default and refuse adding byte-returning decrypt permission. The intentionally unsafe mutable policy permits that one transition.

**The exposure is measured, with cryptographic checks still active.** Wrapping a 32-byte target produces a 40-byte RFC 3394 blob. In the mutable-usage trace, decrypting that blob with the wrapping key and the same AES-KW mechanism returns the target's actual 32 bytes. Independent WebCrypto AES-GCM challenge decryption demonstrates that those bytes can be used outside the handle API; successful extraction is presented as a confidentiality alarm. The trace does not bypass RFC 3394 integrity or decrypt an AES-KW blob with AES-GCM. The positive path unwraps to a fresh sensitive, nonextractable data handle using a fixed output template and can still open the challenge under fixed roles, without returning key bytes.

**These are boundaries of a browser model.** There is no hardware token, full PKCS #11 emulator, authenticated login, general key import, copy, derive, restore or security guarantee across sessions. Unknown and foreign-token handles are refused, but that store-membership check is not caller authentication. No key material from this exercise is persisted or sent over the network; JavaScript memory, developer tools, same-origin code and runtime compromise remain outside its protection. The optional deterministic key factory is for unit fixtures only. The browser uses internally generated keys; a larger API accepting caller-known wrapping keys would need a separate provenance policy, because fixed roles do not prevent someone who already knows a wrapping key from decrypting outside the API.

The exercise implements the first concrete trace for E-K-01, not an exhaustive search, security proof or assessment of any vendor's HSM. Broader API-composition coverage remains open. See the [key-handle extension brief](docs/key-handles-brief.md), [PKCS #11 v3.0 Base §4.10 and C_WrapKey](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html) for sensitivity, extractability and wrapping permission, and [Current Mechanisms Table 91 and §2.16.3](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html) for AES-KW wrap/unwrap and single-part encrypt/decrypt support. Attribute changes remain subject to token policy; this exercise compares two explicitly chosen policies.

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

The key-handle suite additionally checks the fixed-role transition refusal, nonextractable wrapping refusal, legitimate unwrap-to-handle use, defensive snapshots, mechanism separation, malformed inputs, integrity failures and unchanged state after rejected calls. Its RFC 3394 known-answer and native WebCrypto AES-KW comparisons provide independent checks on the mechanism; browser claims must independently open the challenge with the disclosed bytes. Run `npm run test:key-handles:mutations` for the focused fault-injection checks, following the [brief's committed-baseline and restore requirements](docs/key-handles-brief.md). Passing these checks establishes the tested behavior, not security for unmodeled operation sequences.
