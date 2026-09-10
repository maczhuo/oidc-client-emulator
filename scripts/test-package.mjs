import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const exec = promisify(execFile);
const root = fileURLToPath(new URL('../', import.meta.url));
const cache = join(root, '.prototype/npm-cache');
const temp = await mkdtemp(join(tmpdir(), 'oidc-package-'));
try {
  const { stdout } = await exec('npm', ['pack', '--ignore-scripts', '--json', '--cache', cache], { cwd: root });
  const [packed] = JSON.parse(stdout);
  assert.ok(packed.files.some(file => file.path === 'native/URLHelper.swift'));
  assert.ok(packed.files.some(file => file.path === 'dist/index.d.ts'));
  assert.equal(packed.files.some(file => /(^|\/)(\.env|\.prototype|scripts|test)(\/|\.|$)/.test(file.path)), false);
  await exec('npm', ['install', join(root, packed.filename), '--prefix', temp, '--ignore-scripts', '--no-audit', '--no-fund', '--cache', cache]);
  const help = await exec(join(temp, 'node_modules/.bin/oidc-client-emulator'), ['--help']);
  assert.match(help.stdout, /intercept on/);
  const imported = await exec(process.execPath, ['--input-type=module', '-e',
    'import {authorize, interceptOn, interceptOff, discover} from "@jzhuo3/oidc-client-emulator"; console.log([authorize,interceptOn,interceptOff,discover].every(x=>typeof x === "function"));'], { cwd: temp });
  assert.equal(imported.stdout.trim(), 'true');
  // Exercise npx/npm exec resolution against the installed package, without registry access.
  const executable = await exec('npm', ['exec', '--offline', '--cache', cache, '--', 'oidc-client-emulator', '--help'], { cwd: temp });
  assert.match(executable.stdout, /authorize --issuer/);
  console.log(`PASS: ${packed.filename}, ${packed.entryCount} safe package files, installed module, executable, and npm exec`);
} finally { await rm(temp, { recursive: true, force: true }); }
