# Security Policy

## Scope

This is an **educational demo**. It is intentionally simplified and is **not** a hardened, production-ready KMS. Do not use this codebase to protect real data.

## Real cryptographic primitives in use

- **AES-256-GCM** for envelope sealing/opening (WebCrypto `crypto.subtle`).
- **AES Key Wrap (RFC 3394)** for wrapping data encryption keys.
- **AES Key Wrap with Padding (RFC 5649)** for wrapping non-aligned material.
- **HKDF-SHA-256** (RFC 5869) for key derivation.
- **SHA-256** for the audit log's hash chain.

All primitives are validated against the RFC test vectors at startup (see `src/crypto/rfc-vectors.ts`) and in the unit-test suite (`npm run test`).

## Known limitations vs. a real KMS

| Concern                    | Production KMS                                  | This demo                          |
| -------------------------- | ----------------------------------------------- | ---------------------------------- |
| Root KEK boundary          | HSM (FIPS 140-3 L3+)                            | Module-scoped, in-process memory   |
| KEK material at rest       | Sealed in HSM, never exported                   | `Uint8Array` in `KekStore`         |
| DEK lifetime               | Zeroized on memory free                         | Zeroized via `bytes.zeroize()` ASAP |
| Audit log durability       | Append-only, signed, off-host                   | `localStorage` (tamperable on purpose, for the demo) |
| Access control             | IAM policies, key grants, condition keys        | Module boundary only               |
| Multi-region replication   | Cryptographically-bound replicas                | Simulated in one runtime           |
| Side-channel resistance    | Constant-time HSM operations                    | Best-effort JS (e.g. `equalBytes`) |

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
