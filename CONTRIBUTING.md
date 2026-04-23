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

| Script                | Purpose                                                 |
| --------------------- | ------------------------------------------------------- |
| `npm run dev`         | Vite dev server with HMR                                |
| `npm run build`       | `tsc -b` typecheck + `vite build` to `dist/`            |
| `npm run preview`     | Preview the production build                            |
| `npm run typecheck`   | TypeScript only, no emit                                |
| `npm run test`        | Run Vitest once                                         |
| `npm run test:watch`  | Vitest in watch mode                                    |
| `npm run test:coverage` | Run Vitest with V8 coverage report                    |
| `npm run lint`        | ESLint over the repo                                    |
| `npm run lint:fix`    | ESLint with `--fix`                                     |
| `npm run format`      | Prettier write                                          |
| `npm run format:check` | Prettier check (CI-friendly)                           |
| `npm run ci`          | typecheck + lint + test + build (mirrors CI)            |

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
