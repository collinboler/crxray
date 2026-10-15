import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { renameWithHumanify } from '../src/humanify.js';

function makeDir() {
  return mkdtempSync(path.join(tmpdir(), 'crxray-humanify-'));
}

function bigEnough(content) {
  return content.padEnd(100, '/* pad */');
}

test('renameWithHumanify renames a candidate file and writes a sibling .humanify.js', async () => {
  const dir = makeDir();
  const file = path.join(dir, 'min.js');
  writeFileSync(file, bigEnough('function a(b,c){return b+c}'));

  const exec = (cmd, args, opts) => {
    if (args[0] === '--help') return 'usage: humanify ...'; // preflight
    const outFile = args[args.indexOf('-o') + 1];
    writeFileSync(outFile, 'function add(left,right){return left+right}');
    return '';
  };
  const results = await renameWithHumanify(dir, { quiet: true, exec });

  assert.equal(results.processed, 1);
  assert.equal(results.renamed, 1);
  assert.equal(results.errors.length, 0);
  assert.ok(existsSync(path.join(dir, 'min.humanify.js')));
  assert.match(readFileSync(path.join(dir, 'min.humanify.js'), 'utf8'), /add/);
  rmSync(dir, { recursive: true });
});

test('renameWithHumanify reports all files skipped when the preflight check fails once, not once per file', async () => {
  const dir = makeDir();
  writeFileSync(path.join(dir, 'a.js'), bigEnough('function a(){}'));
  writeFileSync(path.join(dir, 'b.js'), bigEnough('function b(){}'));

  let calls = 0;
  const exec = () => {
    calls++;
    throw new Error('spawn humanify ENOENT');
  };
  const results = await renameWithHumanify(dir, { quiet: true, exec });

  assert.equal(calls, 1); // one preflight attempt, not one per candidate file
  assert.equal(results.renamed, 0);
  assert.equal(results.errors.length, 1);
  assert.match(results.errors[0].error, /humanify is not available/);
  rmSync(dir, { recursive: true });
});

test('renameWithHumanify records a per-file subprocess failure without throwing or stopping other files', async () => {
  const dir = makeDir();
  writeFileSync(path.join(dir, 'ok.js'), bigEnough('function a(){}'));
  writeFileSync(path.join(dir, 'bad.js'), bigEnough('function b(){}'));

  const exec = (cmd, args) => {
    if (args[0] === '--help') return 'usage';
    if (args[1].endsWith('bad.js')) throw new Error('model error: context deadline exceeded');
    const outFile = args[args.indexOf('-o') + 1];
    writeFileSync(outFile, 'function ok(){}');
    return '';
  };
  const results = await renameWithHumanify(dir, { quiet: true, exec });

  assert.equal(results.processed, 2);
  assert.equal(results.renamed, 1);
  assert.equal(results.errors.length, 1);
  assert.match(results.errors[0].error, /humanify failed/);
  rmSync(dir, { recursive: true });
});

test('renameWithHumanify treats "exec succeeded but no output file" as an error, not a silent success', async () => {
  const dir = makeDir();
  writeFileSync(path.join(dir, 'min.js'), bigEnough('function a(){}'));

  const exec = (cmd, args) => {
    if (args[0] === '--help') return 'usage';
    return ''; // exits 0 but never writes the -o file -- must not be trusted blindly
  };
  const results = await renameWithHumanify(dir, { quiet: true, exec });

  assert.equal(results.renamed, 0);
  assert.equal(results.errors.length, 1);
  assert.match(results.errors[0].error, /no output file/);
  rmSync(dir, { recursive: true });
});

test('renameWithHumanify treats a zero-byte output file as an error, not a silent success', async () => {
  const dir = makeDir();
  writeFileSync(path.join(dir, 'min.js'), bigEnough('function a(){}'));

  const exec = (cmd, args) => {
    if (args[0] === '--help') return 'usage';
    const outFile = args[args.indexOf('-o') + 1];
    writeFileSync(outFile, '');
    return '';
  };
  const results = await renameWithHumanify(dir, { quiet: true, exec });

  assert.equal(results.renamed, 0);
  assert.equal(results.errors.length, 1);
  assert.match(results.errors[0].error, /empty output/);
  rmSync(dir, { recursive: true });
});

test('renameWithHumanify skips a file below the minimum size', async () => {
  const dir = makeDir();
  writeFileSync(path.join(dir, 'tiny.js'), 'x');

  const exec = () => { throw new Error('should not be called for a skipped file'); };
  const results = await renameWithHumanify(dir, { quiet: true, exec });

  assert.equal(results.processed, 1);
  assert.equal(results.skipped, 1);
  assert.equal(results.renamed, 0);
  rmSync(dir, { recursive: true });
});

test('renameWithHumanify skips files already inside a .humanify.js sibling relationship (its own prior output)', async () => {
  const dir = makeDir();
  writeFileSync(path.join(dir, 'min.js'), bigEnough('function a(){}'));
  writeFileSync(path.join(dir, 'min.humanify.js'), bigEnough('function add(){}'));

  const exec = (cmd, args) => {
    if (args[0] === '--help') return 'usage';
    const outFile = args[args.indexOf('-o') + 1];
    writeFileSync(outFile, 'function renamed(){}');
    return '';
  };
  const results = await renameWithHumanify(dir, { quiet: true, exec });

  // only min.js is a candidate; min.humanify.js (prior output) is not re-processed
  assert.equal(results.processed, 1);
  rmSync(dir, { recursive: true });
});

test('renameWithHumanify passes the provider and an explicit model through to the CLI invocation', async () => {
  const dir = makeDir();
  writeFileSync(path.join(dir, 'min.js'), bigEnough('function a(){}'));

  let seenArgs;
  const exec = (cmd, args) => {
    if (args[0] === '--help') return 'usage';
    seenArgs = args;
    const outFile = args[args.indexOf('-o') + 1];
    writeFileSync(outFile, 'function renamed(){}');
    return '';
  };
  await renameWithHumanify(dir, { quiet: true, exec, provider: 'ollama', model: 'llama3.1:8b' });

  assert.equal(seenArgs[0], 'ollama');
  assert.ok(seenArgs.includes('-m'));
  assert.equal(seenArgs[seenArgs.indexOf('-m') + 1], 'llama3.1:8b');
  rmSync(dir, { recursive: true });
});
