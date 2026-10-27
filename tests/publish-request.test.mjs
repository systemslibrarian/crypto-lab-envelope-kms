import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, existsSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));

// npm publishes its own CLI path as npm_execpath to every script it runs, so
// under `npm test` the control exercises exactly the npm that invoked it. A
// bare `node --test` has no such variable; Node's bundled npm then lives beside
// the binary in the official layout, but not under every package manager
// (Homebrew keeps npm beside the Cellar, not beside the binary), so the last
// resort is the `npm` on PATH resolved to its real CLI script. Whatever is
// chosen is still run by process.execPath, so the control never changes Node.
const derivedNpmCli = join(
  process.execPath,
  '..',
  '..',
  'lib',
  'node_modules',
  'npm',
  'bin',
  'npm-cli.js',
);

function npmCliFromPath() {
  for (const dir of (process.env.PATH ?? '').split(delimiter)) {
    if (!dir) continue;
    const candidate = join(dir, 'npm');
    if (!existsSync(candidate)) continue;
    const real = realpathSync(candidate);
    if (real.endsWith('.js')) return real;
  }
  return undefined;
}

const npmCli =
  process.env.npm_execpath && existsSync(process.env.npm_execpath)
    ? process.env.npm_execpath
    : existsSync(derivedNpmCli)
      ? derivedNpmCli
      : (npmCliFromPath() ?? derivedNpmCli);

// Replace only the external GitHub boundary; exercise the real npm script.
// Neither control dispatches a workflow or uploads any local build.
function request(exitCode) {
  const dir = mkdtempSync(join(tmpdir(), 'publish-request-control-'));
  const gh = join(dir, 'gh');
  writeFileSync(
    gh,
    '#!/usr/bin/env node\nconsole.log(JSON.stringify(process.argv.slice(2)));\nprocess.exit(Number(process.env.PUBLISH_CONTROL_EXIT));\n',
  );
  chmodSync(gh, 0o700);
  try {
    assert.ok(
      existsSync(npmCli),
      `npm CLI not found at ${npmCli}; run this control through \`npm test\` so npm_execpath names the npm to exercise`,
    );
    return spawnSync(process.execPath, [npmCli, 'run', 'deploy', '--silent'], {
      cwd: root,
      env: {
        ...process.env,
        PATH: dir + delimiter + process.env.PATH,
        GH_TOKEN: '',
        PUBLISH_CONTROL_EXIT: String(exitCode),
      },
      encoding: 'utf8',
      timeout: 5000,
    });
  } finally {
    rmSync(dir, { recursive: true });
  }
}

test('publishing requests the existing gated main workflow', () => {
  const result = request(0);
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0);
  assert.deepEqual(JSON.parse(result.stdout.trim()), [
    'workflow',
    'run',
    'pages.yml',
    '--repo',
    'systemslibrarian/crypto-lab-envelope-kms',
    '--ref',
    'main',
  ]);
});

test('a rejected publishing request retains its failing exit status', () => {
  const result = request(73);
  assert.equal(result.error, undefined);
  assert.equal(result.status, 73);
});
