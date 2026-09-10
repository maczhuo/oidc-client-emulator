import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { withSchemeLease } from '../dist/macos.js';

test('a killed process leaves a recoverable lease, with one winner among simultaneous recoverers', async t => {
  const root = await mkdtemp(join(tmpdir(), 'oidc-lease-'));
  const module = new URL('../dist/macos.js', import.meta.url).href;
  const scheme = 'dev.oidc.lease-test';
  const child = spawn(process.execPath, ['--input-type=module', '-e',
    `import { withSchemeLease } from ${JSON.stringify(module)};
     await withSchemeLease(${JSON.stringify(scheme)}, ${JSON.stringify(root)}, async () => {
       console.log('ready'); await new Promise(() => setInterval(() => {}, 1000));
     });`], { stdio: ['ignore', 'pipe', 'pipe'] });
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await rm(root, { recursive: true, force: true }); });
  await once(child.stdout, 'data');
  const exited = once(child, 'exit');
  child.kill('SIGKILL');
  await exited;
  const results = await Promise.allSettled([0, 1].map(() => withSchemeLease(scheme, root, async () => {
    await new Promise(resolve => setTimeout(resolve, 50));
    return true;
  })));
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  const rejected = results.find(result => result.status === 'rejected');
  assert.equal(rejected.reason.code, 'BUSY');
  assert.equal(await withSchemeLease(scheme, root, async () => 'recovered'), 'recovered');
});
