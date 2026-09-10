import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { rm } from 'node:fs/promises';
import { join } from 'node:path';
import { authorize, interceptOff, interceptOn, interceptStatus } from '../dist/index.js';
import { build, command, makeApp, setHandler, work } from './prototype.mjs';

if (process.platform !== 'darwin') throw new Error('Run this test on macOS with a GUI session.');
const id = Date.now().toString(36), scheme = `dev.oidc-client-emulator.test-${id}`;
const stateDir = join(work, `integration-${id}`);
const apps = [];
let issuer;
const provider = createServer((req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({ issuer, authorization_endpoint: `${issuer}/authorize`, response_types_supported: ['code'], code_challenge_methods_supported: ['S256'] }));
});
await new Promise(resolve => provider.listen(0, '127.0.0.1', resolve));
issuer = `http://127.0.0.1:${provider.address().port}`;
const options = { issuer, clientId: 'test', redirectUri: `${scheme}://callback`, stateDir,
  allowInsecureHttp: true, timeoutMs: 30_000, openBrowser: async raw => {
    const auth = new URL(raw), redirect = new URL(auth.searchParams.get('redirect_uri'));
    redirect.searchParams.set('state', auth.searchParams.get('state'));
    redirect.searchParams.set('code', 'native+code/value=');
    await command('/usr/bin/open', [redirect.href]);
  } };
try {
  await build();
  assert.equal((await interceptStatus({ scheme, stateDir })).current.path, null);
  assert.equal((await authorize(options)).code, 'native+code/value=');
  assert.equal((await interceptStatus({ scheme, stateDir })).current.path, null);
  console.log('PASS: managed authorization through native URL dispatch, no previous handler restored');

  const original = await makeApp(`package-original-${id}`, scheme, 'http://127.0.0.1:1/callback', 'x'.repeat(43));
  apps.push(original);
  await setHandler(scheme, original);
  assert.equal((await authorize(options)).code, 'native+code/value=');
  assert.equal((await interceptStatus({ scheme, stateDir })).current.path, original);
  console.log('PASS: managed authorization restores competing application');

  const probe = createServer();
  await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve));
  const port = probe.address().port;
  await new Promise(resolve => probe.close(resolve));
  const enabled = await interceptOn({ scheme, stateDir, port });
  assert.equal(enabled.enabled, true);
  assert.deepEqual(await interceptOn({ scheme, stateDir, port }), enabled);
  await assert.rejects(interceptOn({ scheme, stateDir, port: port === 65535 ? port - 1 : port + 1 }), error => error.code === 'ALREADY_ENABLED');
  assert.equal((await authorize({ ...options, interception: 'existing' })).code, 'native+code/value=');
  assert.equal((await interceptStatus({ scheme, stateDir })).enabled, true);
  await interceptOff({ scheme, stateDir });
  await interceptOff({ scheme, stateDir });
  assert.equal((await interceptStatus({ scheme, stateDir })).current.path, original);
  console.log('PASS: persistent interception, idempotent on/off, existing-mode authorization');

  await assert.rejects(authorize({ ...options, timeoutMs: 1200, openBrowser: false }), error => error.code === 'TIMEOUT');
  assert.equal((await interceptStatus({ scheme, stateDir })).current.path, original);
  console.log('PASS: timeout cleans up the macOS handler');

  const cancel = new AbortController();
  let ready;
  const prepared = new Promise(resolve => { ready = resolve; });
  const first = authorize({ ...options, signal: cancel.signal, openBrowser: false, onAuthorizationUrl: () => ready() });
  await prepared;
  try {
    await assert.rejects(authorize(options), error => error.code === 'BUSY');
  } finally { cancel.abort(); }
  await assert.rejects(first, error => error.code === 'CANCELLED');
  assert.equal((await interceptStatus({ scheme, stateDir })).current.path, original);
  console.log('PASS: simultaneous authorization is rejected; cancellation restores the handler');

  // Simulate abrupt termination with a saved managed interceptor and no live owner.
  // The public recovery command must handle this without knowing the owner token.
  const { enable } = await import('../dist/macos.js');
  await enable({ scheme, stateDir, port }, 'interrupted-test-owner');
  await interceptOff({ scheme, stateDir });
  assert.equal((await interceptStatus({ scheme, stateDir })).current.path, original);
  console.log('PASS: off recovers an interrupted managed registration');

  // Test native forwarding's no-redirect policy with a 307 destination trap.
  let leaked = false, redirected;
  const reached = new Promise(resolve => { redirected = resolve; });
  const trap = createServer((req, res) => { leaked = true; res.end(); });
  await new Promise(resolve => trap.listen(0, '127.0.0.1', resolve));
  const redirector = createServer((req, res) => {
    res.writeHead(307, { Location: `http://127.0.0.1:${trap.address().port}/leak` }).end();
    redirected();
  });
  await new Promise(resolve => redirector.listen(0, '127.0.0.1', resolve));
  try {
    await interceptOn({ scheme, stateDir, port: redirector.address().port });
    await command('/usr/bin/open', [`${scheme}://callback?code=redirect-test`]);
    await Promise.race([reached, new Promise((_, reject) => setTimeout(() => reject(new Error('Redirect test delivery timed out')), 5000).unref())]);
    await new Promise(resolve => setTimeout(resolve, 500));
    assert.equal(leaked, false);
    await interceptOff({ scheme, stateDir });
  } finally {
    await new Promise(resolve => { redirector.close(resolve); redirector.closeAllConnections(); });
    await new Promise(resolve => { trap.close(resolve); trap.closeAllConnections(); });
  }
  console.log('PASS: native forwarding does not follow HTTP redirects');

  await interceptOn({ scheme, stateDir, port });
  const replacement = await makeApp(`package-replacement-${id}`, scheme, 'http://127.0.0.1:1/callback', 'x'.repeat(43));
  apps.push(replacement);
  await setHandler(scheme, replacement);
  await interceptOff({ scheme, stateDir });
  assert.equal((await interceptStatus({ scheme, stateDir })).current.path, replacement);
  console.log('PASS: off preserves a subsequent handler change');
} finally {
  await interceptOff({ scheme, stateDir });
  await new Promise(resolve => { provider.close(resolve); provider.closeAllConnections(); });
  for (const app of apps.reverse()) {
    await command('/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister', ['-u', app]);
    await rm(app, { recursive: true, force: true });
  }
  await rm(stateDir, { recursive: true, force: true });
}
