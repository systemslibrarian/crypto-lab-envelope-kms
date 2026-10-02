# KEK compromise and recovery

`src/scenarios/compromise.ts` owns an isolated `KekStore` and uses the existing RFC 3394 AES-KW and WebCrypto AES-GCM functions. It creates two records per tenant with independent random DEKs. The default layout uses independent tenant KEKs; the shared layout gives both tenants the same KEK.

The attacker receives Tenant A's version 1 raw KEK and deep copies of all original envelopes. Every envelope is attempted, without trusting key-ID labels. Successfully unwrapped DEKs are retained across the experiment.

Four stages run: baseline, KEK rotation only, re-wrap of existing DEKs, and re-encryption of the same sample records with fresh DEKs. Each row independently opens archived envelopes, current wraps, current ciphertext using retained DEKs, and newly created future records. Owner opens are positive controls. Future records are absent at baseline and created after rotation.

Re-wrap leaves the payload and DEK unchanged. Therefore a current wrap can reject the stolen KEK while a retained DEK still opens the current payload. Re-encryption changes that result, but archived copies stay readable. Tenant separation is a comparison between fresh deployments, not a claim that splitting keys can retract an earlier leak.

`src/ui/compromise.ts` renders the measured counts and retires results on a layout change. The panel survives unrelated app renders; Reset discards it. Key material is in memory only; typed arrays used by the attack are cleared after measurement (no claim of guaranteed JavaScript memory erasure). KMS authorization, HSM extraction, continuing attacker access, and archive deletion are out of scope.

Validation: `src/scenarios/compromise.test.ts` checks both layouts and all recovery stages; `e2e/claims.spec.ts` checks the rendered recovery distinction and result retirement. Run `npm run ci` and `npm run test:a11y`.
