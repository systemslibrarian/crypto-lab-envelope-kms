#!/usr/bin/env node
/**
 * Reproduce the key-handle browser mutation checks from master §4.1c and the
 * bounded state-search extension.
 *
 * Run only after committing the real source, tests and this runner:
 *   node scripts/key-handle-mutations.mjs
 *
 * Every result below is derived by this run. A compile error, unchanged bundle,
 * missing/failed baseline, server error or unrelated failure is never a kill.
 * Evidence stays in ignored test-results/key-handle-mutations/<run-id>/.
 */
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SPEC = 'e2e/claims.spec.ts';
const RUNNER = 'scripts/key-handle-mutations.mjs';
const RESULT_ROOT = path.join(ROOT, 'test-results/key-handle-mutations');
const BUILD_TIMEOUT_MS = 180_000;
const TEST_TIMEOUT_MS = 240_000;
const NODE_BIN = path.dirname(process.execPath);
const CHILD_ENV = {
  ...process.env,
  PATH: NODE_BIN + path.delimiter + (process.env.PATH || ''),
  CI: '1',
  FORCE_COLOR: '0',
};
const MUTATIONS = [
  {
    id: 'KHI-01',
    finding: 'Fixed wrapping roles cannot acquire byte-returning decrypt permission.',
    file: 'src/kms/key-handles.ts',
    anchor: "if (this.#policy === 'fixed-roles') {",
    replacement: 'if (false) {',
  },
  {
    id: 'KHI-02',
    finding: 'Nonextractable targets must be rejected before wrapping.',
    file: 'src/kms/key-handles.ts',
    anchor: 'if (!target.description.extractable) {',
    replacement: 'if (false) {',
  },
  {
    id: 'KHI-03',
    finding: 'Displayed escaped bytes must independently authenticate the displayed challenge.',
    file: 'src/ui/key-handles.ts',
    anchor: 'const recoveredHex = bytesToHex(recovered);',
    replacement: "const recoveredHex = '00'.repeat(recovered.length);",
  },
  {
    id: 'KHI-04',
    finding: 'The successful primitive trace must retain its visible confidentiality limitation.',
    file: 'src/ui/key-handles.ts',
    anchor:
      "'Valid cryptographic checks do not prevent key disclosure when this API permits conflicting operations.'",
    replacement: "''",
  },
  {
    id: 'KHS-01',
    finding: 'The fixed unwrap policy must reject privileged caller templates.',
    file: 'src/kms/key-handle-search.ts',
    anchor: "if (policy === 'fixed-template' && template !== 'data-only') continue;",
    replacement: 'if (false) continue;',
  },
  {
    id: 'KHS-02',
    finding: 'Displayed escaped bytes must open the displayed state-search challenge.',
    file: 'src/ui/key-handle-search.ts',
    anchor: 'const escaped = bytesToHex(proof.escapedKey);',
    replacement: "const escaped = '00'.repeat(proof.escapedKey.length);",
  },
  {
    id: 'KHS-03',
    finding: 'Distinct handles containing equal values must not collapse into one object.',
    file: 'src/kms/key-handle-search.ts',
    anchor:
      'candidate.objects.push(\n            object(outputHandle, wrapped.payloadValue, templateCapabilities[template], false),\n          );',
    replacement:
      'candidate.objects = candidate.objects.filter(\n            (entry) => entry.valueId !== wrapped.payloadValue,\n          );\n          candidate.objects.push(\n            object(outputHandle, wrapped.payloadValue, templateCapabilities[template], false),\n          );',
  },
  {
    id: 'KHS-04',
    finding: 'The state-search result must retain its visible bounded-model limitation.',
    file: 'src/ui/key-handle-search.ts',
    anchor:
      'This is a bounded browser model inspired by historical cryptographic-API analyses. It is not a PKCS #11 implementation, HSM assessment, vendor vulnerability claim, exhaustive search, or security proof. The fixed roles and fixed unwrap template block the modeled traces; they do not establish security for unmodeled operations, mechanisms, sessions, authentication, concurrency, runtime compromise, or side channels.',
    replacement: '',
  },
  {
    id: 'KHS-05',
    finding: 'Changing the search preset must retire evidence from the prior model.',
    file: 'src/ui/key-handle-search.ts',
    anchor: 'if (next === scenario) return;',
    replacement: 'return;',
  },
  {
    id: 'KHS-06',
    finding: 'A resource cutoff must be reported as incomplete, never as no witness.',
    file: 'src/ui/key-handle-search.ts',
    anchor:
      "if (result.verdict === 'search-incomplete') {\n    return `SEARCH INCOMPLETE: stopped at the ${result.bounds.maxStates.toLocaleString()} retained-non-witness-state cap. No safety conclusion is available.`;",
    replacement:
      'if (false) {\n    return `SEARCH INCOMPLETE: stopped at the ${result.bounds.maxStates.toLocaleString()} retained-non-witness-state cap. No safety conclusion is available.`;',
  },
];

let activeChild = null;
let interrupted = null;
let runDirectory;
let report;

function failure(classification, message) {
  return Object.assign(new Error(message), { classification });
}

function requireThat(condition, classification, message) {
  if (!condition) throw failure(classification, message);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function git(args, options = {}) {
  return execFileSync('git', ['-C', ROOT, ...args], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    ...options,
  });
}

function assertCleanTree() {
  requireThat(
    !report?.head || git(['rev-parse', 'HEAD']).trim() === report.head,
    'BASELINE_MOVED',
    'HEAD changed after this mutation run captured its baseline.',
  );
  const dirty = git(['status', '--porcelain=v1', '-z', '--untracked-files=all']);
  requireThat(
    dirty.length === 0,
    'DIRTY_SOURCE',
    'Commit all real work before mutation. Nonignored changes: ' +
      dirty.split('\0').filter(Boolean).join('; '),
  );
}

function assertMutatedTree(mutation, changed) {
  requireThat(
    git(['rev-parse', 'HEAD']).trim() === report.head &&
      git(['status', '--porcelain=v1', '-z', '--untracked-files=all']) ===
        ' M ' + mutation.file + '\0' &&
      fs.readFileSync(path.join(ROOT, mutation.file)).equals(changed),
    'TORN_SOURCE',
    mutation.id + ': source changed beyond this one patch during the run.',
  );
}

function countOccurrences(text, anchor) {
  return text.split(anchor).length - 1;
}

function assertAnchor(mutation, bytes) {
  const text = bytes.toString('utf8');
  requireThat(
    Buffer.from(text, 'utf8').equals(bytes),
    'INVALID_PATCH',
    mutation.file + ' is not round-trippable UTF-8.',
  );
  requireThat(
    mutation.anchor !== mutation.replacement && countOccurrences(text, mutation.anchor) === 1,
    'INVALID_PATCH',
    mutation.id + ': source anchor must occur exactly once in ' + mutation.file,
  );
  const changed = Buffer.from(text.replace(mutation.anchor, mutation.replacement), 'utf8');
  requireThat(!changed.equals(bytes), 'INVALID_PATCH', mutation.id + ': patch was a no-op.');
  return changed;
}

function snapshotBundles() {
  const assets = path.join(ROOT, 'dist/assets');
  requireThat(fs.existsSync(assets), 'MISSING_BUNDLE', 'Build produced no dist/assets directory.');
  const files = [];
  function walk(directory) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const full = path.join(directory, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && entry.name.endsWith('.js')) files.push(full);
    }
  }
  walk(assets);
  requireThat(files.length > 0, 'MISSING_BUNDLE', 'Build produced no JavaScript assets.');
  const entries = files.sort().map((file) => {
    const bytes = fs.readFileSync(file);
    return {
      file: path.relative(ROOT, file).split(path.sep).join('/'),
      bytes: bytes.length,
      sha256: sha256(bytes),
    };
  });
  return { sha256: sha256(JSON.stringify(entries)), assets: entries };
}

function cleanBuildOutput(label, restoring = false) {
  if (interrupted && !restoring) throw failure('INTERRUPTED', 'Interrupted by ' + interrupted);
  const directory = path.join(ROOT, 'dist');
  const observed = {
    label,
    directory: 'dist',
    startedAt: new Date().toISOString(),
    before: { exists: false },
    absentAfter: false,
  };
  report.outputCleanups.push(observed);
  saveReport();
  try {
    const existing = fs.lstatSync(directory, { throwIfNoEntry: false });
    observed.before.exists = Boolean(existing);
    if (existing) {
      requireThat(
        existing.isDirectory() && !existing.isSymbolicLink(),
        'OUTPUT_CLEAN_FAILED',
        label + ': dist must be a real directory before cleaning it.',
      );
      const entries = [];
      function walk(current) {
        for (const entry of fs
          .readdirSync(current, { withFileTypes: true })
          .sort((a, b) => a.name.localeCompare(b.name))) {
          const full = path.join(current, entry.name);
          const file = path.relative(ROOT, full).split(path.sep).join('/');
          if (entry.isDirectory()) {
            entries.push({ file, type: 'directory' });
            walk(full);
          } else {
            requireThat(
              entry.isFile(),
              'OUTPUT_CLEAN_FAILED',
              label + ': unexpected nonregular output entry ' + file,
            );
            const bytes = fs.readFileSync(full);
            entries.push({ file, type: 'file', bytes: bytes.length, sha256: sha256(bytes) });
          }
        }
      }
      walk(directory);
      observed.before.manifest = { sha256: sha256(JSON.stringify(entries)), entries };
      // Preserve the complete old tree's manifest before removing any output.
      // Delete the directory itself, not only the files known to the last build.
      saveReport();
      fs.rmSync(directory, { recursive: true, force: true });
    }
    observed.absentAfter = !fs.lstatSync(directory, { throwIfNoEntry: false });
    requireThat(
      observed.absentAfter,
      'OUTPUT_CLEAN_FAILED',
      label + ': dist still exists after whole-directory cleanup.',
    );
  } catch (error) {
    observed.failure = {
      classification: error.classification || 'OUTPUT_CLEAN_FAILED',
      message: error.message,
    };
    throw failure('OUTPUT_CLEAN_FAILED', label + ': ' + error.message);
  } finally {
    observed.finishedAt = new Date().toISOString();
    saveReport();
  }
}

function saveReport() {
  if (!report || !runDirectory) return;
  const target = path.join(runDirectory, 'report.json');
  fs.writeFileSync(target + '.tmp', JSON.stringify(report, null, 2) + '\n');
  fs.renameSync(target + '.tmp', target);
}

function terminateChild(child, signal = 'SIGTERM') {
  if (!child?.pid) return;
  try {
    if (process.platform === 'win32') child.kill(signal);
    else process.kill(-child.pid, signal);
  } catch (error) {
    if (error.code !== 'ESRCH') console.error('Could not stop child:', error.message);
  }
}

function onInterrupt(signal) {
  interrupted ||= signal;
  console.error(signal + ': stopping the current command; original source will be restored.');
  const child = activeChild;
  terminateChild(child);
  if (child) {
    const force = setTimeout(() => terminateChild(child, 'SIGKILL'), 2000);
    force.unref();
    child.once('close', () => clearTimeout(force));
  }
}

function executable(name) {
  const candidate = path.join(NODE_BIN, name + (process.platform === 'win32' ? '.cmd' : ''));
  return fs.existsSync(candidate) ? candidate : name;
}

async function command(label, program, args, { test = false, restoring = false, env = {} } = {}) {
  if (interrupted && !restoring) throw failure('INTERRUPTED', 'Interrupted by ' + interrupted);
  const log = path.join(runDirectory, label + '.log');
  const started = Date.now();
  const observed = {
    label,
    program,
    args,
    cwd: ROOT,
    startedAt: new Date(started).toISOString(),
    log: path.relative(runDirectory, log),
    ci: '1',
    timeoutMs: test ? TEST_TIMEOUT_MS : BUILD_TIMEOUT_MS,
  };
  report.commands.push(observed);
  saveReport();
  console.info('[' + label + '] ' + path.basename(program) + ' ' + args.join(' '));
  const descriptor = fs.openSync(log, 'w');
  fs.writeSync(descriptor, program + ' ' + args.join(' ') + '\n');
  return await new Promise((resolve, reject) => {
    let timedOut = false;
    let spawnError = null;
    let outputError = null;
    let forcedKill;
    const child = spawn(program, args, {
      cwd: ROOT,
      env: { ...CHILD_ENV, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: process.platform !== 'win32',
    });
    activeChild = child;
    const appendOutput = (chunk) => {
      if (outputError) return;
      try {
        fs.writeSync(descriptor, chunk);
      } catch (error) {
        outputError = error;
        terminateChild(child);
      }
    };
    for (const stream of [child.stdout, child.stderr]) {
      stream.on('data', appendOutput);
    }
    child.on('error', (error) => {
      spawnError = { code: error.code, message: error.message };
      appendOutput('\nSPAWN ERROR: ' + error.message + '\n');
    });
    const timeout = setTimeout(() => {
      timedOut = true;
      appendOutput('\nCOMMAND TIMEOUT\n');
      terminateChild(child);
      forcedKill = setTimeout(() => terminateChild(child, 'SIGKILL'), 2000);
    }, observed.timeoutMs);
    child.on('close', (exitCode, signal) => {
      clearTimeout(timeout);
      if (forcedKill) clearTimeout(forcedKill);
      if (activeChild === child) activeChild = null;
      try {
        fs.closeSync(descriptor);
        Object.assign(observed, {
          finishedAt: new Date().toISOString(),
          durationMs: Date.now() - started,
          exitCode,
          signal,
          timedOut,
          spawnError,
        });
        if (outputError) throw failure('EVIDENCE_WRITE_FAILED', outputError.message);
        saveReport();
        resolve(observed);
      } catch (error) {
        // Reject through the awaited command so the source-restoration finally runs.
        reject(error);
      }
    });
  });
}

function requireSuccessfulCommand(observed, classification) {
  requireThat(
    observed.exitCode === 0 && !observed.signal && !observed.timedOut && !observed.spawnError,
    classification,
    observed.label + ' failed; inspect ' + observed.log,
  );
}

async function build(label, restoring = false) {
  cleanBuildOutput(label, restoring);
  const observed = await command(label, executable('npm'), ['run', 'build'], { restoring });
  requireSuccessfulCommand(observed, 'DOES_NOT_BUILD');
  return observed;
}

function reportTests(browserReport) {
  const tests = [];
  function walk(suite, parents = []) {
    const titles = suite.title ? [...parents, suite.title] : parents;
    for (const spec of suite.specs || []) {
      for (const test of spec.tests || []) {
        tests.push({
          title: [...titles, spec.title].join(' > '),
          file: spec.file,
          project: test.projectName,
          expectedStatus: test.expectedStatus,
          status: test.status,
          results: (test.results || []).map((result) => ({
            status: result.status,
            retry: result.retry,
            errors: (result.errors || (result.error ? [result.error] : [])).map((error) => ({
              message: error.message || error.value || '',
              stack: error.stack || '',
            })),
          })),
        });
      }
    }
    for (const child of suite.suites || []) walk(child, titles);
  }
  for (const suite of browserReport.suites || []) walk(suite);
  return tests;
}

async function browser(label, ids, restoring = false) {
  // Playwright's webServer builds again; give that build the same empty-output
  // starting point as the explicit build whose complete asset manifest we hash.
  cleanBuildOutput(label, restoring);
  const jsonPath = path.join(runDirectory, label + '.json');
  const grep = '\\b(?:' + ids.join('|') + ')\\b';
  const observed = await command(
    label,
    executable('npx'),
    [
      '--no-install',
      'playwright',
      'test',
      SPEC,
      '--grep',
      grep,
      '--retries=0',
      '--workers=1',
      '--reporter=line,json',
      '--output',
      path.join(runDirectory, label + '-artifacts'),
    ],
    {
      test: true,
      restoring,
      env: {
        // The webServer plugin otherwise suppresses the second build's stdout.
        DEBUG: 'pw:webserver',
        PLAYWRIGHT_JSON_OUTPUT_NAME: jsonPath,
        PLAYWRIGHT_JSON_OUTPUT_FILE: jsonPath,
      },
    },
  );
  requireThat(
    fs.existsSync(jsonPath),
    'INVALID_BROWSER_RUN',
    label + ': no Playwright JSON report; inspect ' + observed.log,
  );
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
  } catch (error) {
    throw failure('INVALID_BROWSER_RUN', label + ': invalid Playwright JSON: ' + error.message);
  }
  const tests = reportTests(parsed);
  const scoped = {};
  for (const id of ids) {
    const matching = tests.filter((entry) => new RegExp('\\b' + id + '\\b').test(entry.title));
    requireThat(
      matching.length === 1,
      'INVALID_BROWSER_RUN',
      label + ': expected exactly one owning test for ' + id + ', found ' + matching.length,
    );
    scoped[id] = matching[0];
  }
  requireThat(
    tests.length === ids.length && !(parsed.errors || []).length,
    'INVALID_BROWSER_RUN',
    label + ': unexpected tests or global Playwright errors.',
  );
  return {
    command: observed,
    report: path.relative(runDirectory, jsonPath),
    tests: scoped,
  };
}

function requirePassed(result, ids) {
  requireSuccessfulCommand(result.command, 'BASELINE_FAILED');
  for (const id of ids) {
    const test = result.tests[id];
    requireThat(
      test.expectedStatus === 'passed' &&
        test.status === 'expected' &&
        test.results.length === 1 &&
        test.results[0].status === 'passed' &&
        test.results[0].retry === 0,
      'BASELINE_FAILED',
      result.command.label + ': ' + id + ' did not pass once without retries.',
    );
  }
}

function requireNamedFailure(result, id) {
  const observed = result.command;
  const test = result.tests[id];
  if (
    observed.exitCode === 0 &&
    !observed.signal &&
    !observed.timedOut &&
    !observed.spawnError &&
    test.results.some((entry) => entry.status === 'passed')
  ) {
    throw failure('SURVIVED', id + ': the owning test passed with the source mutation.');
  }
  requireThat(
    observed.exitCode === 1 && !observed.signal && !observed.timedOut && !observed.spawnError,
    'INVALID_BROWSER_RUN',
    id + ': browser run did not exit with an ordinary test failure.',
  );
  requireThat(
    test.expectedStatus === 'passed' &&
      test.status === 'unexpected' &&
      test.results.length === 1 &&
      test.results[0].status === 'failed' &&
      test.results[0].retry === 0,
    test.results.some((entry) => entry.status === 'passed') ? 'SURVIVED' : 'INVALID_BROWSER_RUN',
    id + ': owning test did not fail once without retries.',
  );
  const errors = test.results[0].errors
    .map((error) => error.message + '\n' + error.stack)
    .join('\n');
  const infrastructure =
    /ERR_CONNECTION|ECONNREFUSED|EADDRINUSE|browserType\.launch|Executable doesn't exist|Host system is missing|webServer.*(?:fail|timed out)|Process from config\.webServer|Test timeout of|worker process exited|Target page, context or browser has been closed/i;
  requireThat(
    !infrastructure.test(errors),
    'INVALID_BROWSER_RUN',
    id + ': infrastructure failure is not a killed source mutation.',
  );
  requireThat(
    new RegExp('\\b' + id + '\\b').test(errors) &&
      /expect\(|AssertionError|Expected:|Received:/.test(errors),
    'UNOWNED_FAILURE',
    id + ': failure did not name the owning assertion.',
  );
  return { title: test.title, finding: id, assertionErrors: test.results[0].errors };
}

async function oneMutation(mutation, baselineBundle) {
  assertCleanTree();
  if (interrupted) throw failure('INTERRUPTED', 'Interrupted by ' + interrupted);
  const file = path.join(ROOT, mutation.file);
  const original = fs.readFileSync(file);
  const changed = assertAnchor(mutation, original);
  const observed = {
    ...mutation,
    status: 'RUNNING',
    baselinePassed: true,
    originalSourceSha256: sha256(original),
    mutatedSourceSha256: sha256(changed),
    startedAt: new Date().toISOString(),
    restoration: { sourceRestored: false, verified: false },
  };
  report.mutations.push(observed);
  saveReport();
  let mutantFailure = null;
  let restoreFailure = null;
  try {
    fs.writeFileSync(file, changed);
    requireThat(
      fs.readFileSync(file).equals(changed),
      'INVALID_PATCH',
      mutation.id + ': written patch differs from expected bytes.',
    );
    observed.patchApplied = true;
    await build(mutation.id + '-mutant-build');
    assertMutatedTree(mutation, changed);
    observed.mutantBundle = snapshotBundles();
    requireThat(
      observed.mutantBundle.sha256 !== baselineBundle.sha256,
      'UNCHANGED_BUNDLE',
      mutation.id + ': successful build did not change any JavaScript asset.',
    );
    observed.browser = await browser(mutation.id + '-mutant-test', [mutation.id]);
    assertMutatedTree(mutation, changed);
    observed.bundleAfterBrowser = snapshotBundles();
    requireThat(
      observed.bundleAfterBrowser.sha256 === observed.mutantBundle.sha256,
      'TORN_BUNDLE',
      mutation.id + ': browser webServer rebuild did not preserve the mutated bundle.',
    );
    observed.namedFailure = requireNamedFailure(observed.browser, mutation.id);
  } catch (error) {
    mutantFailure = error;
    observed.failure = {
      classification: error.classification || 'INVALID_RUN',
      message: error.message,
    };
  } finally {
    // Restore the exact saved bytes, never git checkout and never a reverse grep.
    try {
      const current = fs.readFileSync(file);
      if (!current.equals(changed) && !current.equals(original)) {
        const captured = mutation.id + '-unexpected-source.txt';
        fs.writeFileSync(path.join(runDirectory, captured), current);
        observed.restoration.unexpectedSourceCapture = captured;
        mutantFailure ||= failure(
          'TORN_SOURCE',
          mutation.id + ': source changed before restoration.',
        );
        observed.failure = {
          classification: mutantFailure.classification || 'TORN_SOURCE',
          message: mutantFailure.message,
        };
      }
      fs.writeFileSync(file, original);
      observed.restoration.sourceRestored = fs.readFileSync(file).equals(original);
      requireThat(
        observed.restoration.sourceRestored,
        'RESTORE_FAILED',
        mutation.id + ': original source bytes were not restored.',
      );
      await build(mutation.id + '-restored-build', true);
      observed.restoration.bundle = snapshotBundles();
      requireThat(
        observed.restoration.bundle.sha256 === baselineBundle.sha256,
        'RESTORE_FAILED',
        mutation.id + ': restored JavaScript assets differ from the original baseline.',
      );
      observed.restoration.browser = await browser(
        mutation.id + '-restored-test',
        [mutation.id],
        true,
      );
      requirePassed(observed.restoration.browser, [mutation.id]);
      observed.restoration.bundleAfterBrowser = snapshotBundles();
      requireThat(
        observed.restoration.bundleAfterBrowser.sha256 === baselineBundle.sha256,
        'RESTORE_FAILED',
        mutation.id + ': restored browser build differs from the original baseline.',
      );
      assertCleanTree();
      observed.restoration.verified = true;
    } catch (error) {
      restoreFailure = error;
      observed.restoration.failure = {
        classification: error.classification || 'RESTORE_FAILED',
        message: error.message,
      };
    }
    observed.finishedAt = new Date().toISOString();
    observed.status = restoreFailure
      ? 'RESTORE_FAILED'
      : mutantFailure
        ? observed.failure.classification
        : 'KILLED';
    saveReport();
    console.info('[' + mutation.id + '] ' + observed.status);
  }
  if (restoreFailure)
    throw failure('RESTORE_FAILED', mutation.id + ': restoration did not verify.');
  if (interrupted) throw failure('INTERRUPTED', 'Interrupted by ' + interrupted);
}

async function main() {
  requireThat(
    fs.realpathSync(git(['rev-parse', '--show-toplevel']).trim()) === fs.realpathSync(ROOT),
    'INVALID_ROOT',
    'Run this committed script from its own repository.',
  );
  try {
    git(['check-ignore', '--quiet', '--', 'test-results/key-handle-mutations/']);
  } catch {
    throw failure('UNIGNORED_RESULTS', 'Mutation evidence must be ignored by Git.');
  }
  fs.mkdirSync(RESULT_ROOT, { recursive: true });
  const lock = path.join(RESULT_ROOT, 'run.lock');
  let lockDescriptor;
  try {
    lockDescriptor = fs.openSync(lock, 'wx');
  } catch {
    throw failure(
      'RUN_LOCKED',
      'Another run or an interrupted run owns ' +
        lock +
        '. Inspect it before removing a stale lock.',
    );
  }
  const runId = new Date().toISOString().replace(/[:.]/g, '-') + '-' + process.pid;
  runDirectory = path.join(RESULT_ROOT, runId);
  fs.mkdirSync(runDirectory);
  fs.writeFileSync(lockDescriptor, JSON.stringify({ pid: process.pid, runDirectory }) + '\n');
  fs.closeSync(lockDescriptor);
  report = {
    schemaVersion: 1,
    startedAt: new Date().toISOString(),
    status: 'RUNNING',
    repository: ROOT,
    head: git(['rev-parse', 'HEAD']).trim(),
    node: process.version,
    nodeExecutable: process.execPath,
    specification: SPEC,
    sourcePatches: MUTATIONS,
    baseline: {},
    mutations: [],
    commands: [],
    outputCleanups: [],
  };
  process.on('SIGINT', onInterrupt);
  process.on('SIGTERM', onInterrupt);
  try {
    saveReport();
    assertCleanTree();
    const committedFiles = [
      ...new Set(MUTATIONS.map((mutation) => mutation.file)),
      SPEC,
      RUNNER,
      'package.json',
      'package-lock.json',
      'playwright.config.ts',
      'tsconfig.json',
      'vite.config.ts',
    ];
    report.baseline.sourceFiles = [];
    for (const relative of committedFiles) {
      const file = path.join(ROOT, relative);
      // Reject symbolic links at open time, then inspect and read that same
      // descriptor so a path replacement cannot race the regular-file check.
      const descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
      let bytes;
      try {
        requireThat(
          fs.fstatSync(descriptor).isFile(),
          'INVALID_SOURCE',
          relative + ' must be a regular committed file.',
        );
        bytes = fs.readFileSync(descriptor);
      } finally {
        fs.closeSync(descriptor);
      }
      const committed = git(['show', 'HEAD:' + relative], { encoding: null });
      requireThat(
        bytes.equals(committed),
        'DIRTY_SOURCE',
        relative + ' differs from the committed baseline.',
      );
      report.baseline.sourceFiles.push({ file: relative, sha256: sha256(bytes) });
    }
    for (const mutation of MUTATIONS) {
      assertAnchor(mutation, fs.readFileSync(path.join(ROOT, mutation.file)));
    }
    await build('baseline-build');
    report.baseline.bundle = snapshotBundles();
    report.baseline.browser = await browser(
      'baseline-tests',
      MUTATIONS.map((mutation) => mutation.id),
    );
    requirePassed(
      report.baseline.browser,
      MUTATIONS.map((mutation) => mutation.id),
    );
    report.baseline.bundleAfterBrowser = snapshotBundles();
    requireThat(
      report.baseline.bundleAfterBrowser.sha256 === report.baseline.bundle.sha256,
      'TORN_BUNDLE',
      'Baseline browser rebuild changed the JavaScript assets.',
    );
    assertCleanTree();
    report.baseline.passed = true;
    saveReport();
    for (const mutation of MUTATIONS) await oneMutation(mutation, report.baseline.bundle);
    report.status =
      report.mutations.length === MUTATIONS.length &&
      report.mutations.every((mutation) => mutation.status === 'KILLED')
        ? 'PASSED'
        : 'FAILED';
  } catch (error) {
    report.status = 'FAILED';
    report.failure = {
      classification: error.classification || 'INVALID_RUN',
      message: error.message,
    };
    console.error(report.failure.classification + ': ' + error.message);
  } finally {
    report.finishedAt = new Date().toISOString();
    report.interrupted = interrupted;
    saveReport();
    fs.unlinkSync(lock);
    process.removeListener('SIGINT', onInterrupt);
    process.removeListener('SIGTERM', onInterrupt);
  }
  console.info('Evidence: ' + path.join(runDirectory, 'report.json'));
  return report.status === 'PASSED';
}

if (process.argv.length > 2) {
  console.error('Usage: node scripts/key-handle-mutations.mjs (commit real work first)');
  process.exitCode = 1;
} else {
  main().then(
    (passed) => {
      process.exitCode = passed ? 0 : 1;
    },
    (error) => {
      console.error((error.classification || 'INVALID_RUN') + ': ' + error.message);
      process.exitCode = 1;
    },
  );
}
