# Contributing

Thanks for your interest in improving the Envelope KMS Lab.

## Quick start

```bash
git clone https://github.com/systemslibrarian/crypto-lab-envelope-kms
cd crypto-lab-envelope-kms
npm install
npm run dev      # http://localhost:5173
```

## Scripts

| Script                  | Purpose                                      |
| ----------------------- | -------------------------------------------- |
| `npm run dev`           | Vite dev server with HMR                     |
| `npm run build`         | `tsc -b` typecheck + `vite build` to `dist/` |
| `npm run preview`       | Preview the production build                 |
| `npm run typecheck`     | TypeScript only, no emit                     |
| `npm run test`          | Run Vitest once                              |
| `npm run test:watch`    | Vitest in watch mode                         |
| `npm run test:coverage` | Run Vitest with V8 coverage report           |
| `npm run lint`          | ESLint over the repo                         |
| `npm run lint:fix`      | ESLint with `--fix`                          |
| `npm run format`        | Prettier write                               |
| `npm run format:check`  | Prettier check (CI-friendly)                 |
| `npm run ci`            | typecheck + lint + test + build (mirrors CI) |

## Project layout

```
src/
  crypto/      Pure-function crypto: AES-KW, AES-KWP, AEAD, HKDF, byte utils, RFC vectors
  envelope/    seal / open / rewrap glue between crypto and KMS
  kms/         In-memory KMS API, KEK store, hash-chained audit log
  scenarios/   One-shot canned flows used by both UI presets and tests
  ui/          DOM render functions (no framework)
  app.ts       Top-level app rendering and event wiring
  main.ts      Bootstrap + theme toggle
```

## Code style

- TypeScript, ES2022, ESM only.
- 2-space indent, single quotes, trailing commas (Prettier-enforced).
- ESLint + `typescript-eslint` recommended ruleset.
- Prefer `Uint8Array` over `Buffer` so code stays browser-portable.
- Avoid mutating function arguments. Where mutation of secret material is needed (e.g., zeroization), do it at a clearly-marked boundary.

## Cryptographic changes

- Any change to files under `src/crypto/**` must keep the RFC vector tests green and add a focused test for the new behavior.
- Do not add variable-time branches over secret bytes.
- Prefer the WebCrypto API where it covers the use case; fall back to `@noble/*` only when it does not.

### Changing validation/conformance logic (bounds, length checks, tag/integrity checks)

A comparison operator or boundary in crypto validation is a security control, not a
detail. Loosening one (e.g. `<=` → `<`) can silently accept malformed inputs while every
existing test stays green. Before changing any such check:

1. **Cite the exact normative bound.** Quote the RFC clause and the inequality it requires.
   Example: RFC 5649 §4.2 requires `8·(n−1) < MLI ≤ 8·n`, so padding is 0–7 octets and the
   unwrap rejection condition is `length <= padded.length - 8` — the `<=` is load-bearing.
2. **Write a failing-then-passing test.** Add a test that **fails before** your change and
   **passes after** it. If you cannot construct an input that fails first, the bug you are
   "fixing" probably does not exist — stop and re-read the spec.
3. **Add the boundary as a permanent regression test**, not just a local check. See
   `src/crypto/key-wrap.test.ts` ("rejects a blob declaring 8 padding bytes") for the
   pattern: craft the malformed input with `wrapWithIv3394` + a hand-built AIV and assert
   the unwrap throws.

"All tests green" only proves the change broke nothing that was already covered — it does
not prove the change was correct.

## Pull requests

1. Fork and create a feature branch.
2. Run `npm run ci` locally before pushing — the CI workflow runs the same checks.
3. Keep PRs focused. Big mixed PRs are hard to review.
4. Reference the issue number in the PR description if applicable.

## Reporting bugs

Please open an issue with:

- Browser + OS
- Steps to reproduce
- Expected vs. actual behavior
- Console output (if any)
