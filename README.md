# crypto-lab-envelope-kms

## 1. What It Is

Envelope encryption is the operational layer of modern cryptographic architecture - a data encryption key (DEK) encrypts data; a key encryption key (KEK) encrypts DEKs; a root KEK encrypts KEKs. This demo implements RFC 3394 and RFC 5649 key wrap, KMS-style API surface, versioned rotation, and hash-chained audit logging. The security model assumes KEKs never leave a trust boundary and that the audit log is append-only.

## 2. When to Use It

- Encrypting large volumes of data where round-tripping every byte to an HSM is impractical - envelope encryption amortizes the HSM call across the object.
- Multi-tenant systems needing per-tenant key isolation - the KEK hierarchy enforces it cryptographically.
- Regulated environments (PCI-DSS, HIPAA, FedRAMP) requiring documented key rotation and audit trails.
- Do NOT use this pattern for ephemeral session keys - TLS-style key schedules are the right shape there.
- Do NOT reinvent - real deployments use AWS KMS, Google Cloud KMS, Azure Key Vault, or HashiCorp Vault; this demo shows how they work internally.

## 3. Live Demo

Link: https://systemslibrarian.github.io/crypto-lab-envelope-kms/

Users can generate KEKs, seal and open envelopes, rotate a KEK and watch old envelopes still decrypt, re-wrap envelopes to the new version, and tamper with the audit log to see the hash chain detect it.

## 4. How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-envelope-kms
cd crypto-lab-envelope-kms
npm install
npm run dev
```

## 5. Part of the Crypto-Lab Suite

> One of 100+ live browser demos at
> [systemslibrarian.github.io/crypto-lab](https://systemslibrarian.github.io/crypto-lab/)
> - spanning Atbash (600 BCE) through NIST FIPS 203/204/205 (2024).

---

*"Whether you eat or drink, or whatever you do, do all to the glory of God." - 1 Corinthians 10:31*