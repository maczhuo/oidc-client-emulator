import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';
import { createDaemonApp, startDaemon } from '../dist/daemon/server.js';
import { LoginJobs } from '../dist/daemon/jobs.js';
import { OIDCEmulatorError } from '../dist/errors.js';

const token = 'a'.repeat(43);
const body = { issuer: 'https://identity.example.com', clientId: 'test', redirectUri: 'com.example.app://callback', scopes: ['openid', 'email'] };
async function fixture(t, run, retentionMs = 60_000) {
  const jobs = new LoginJobs(run, '/tmp/daemon-test-state', retentionMs);
  const server = createServer(createDaemonApp(token, jobs)).listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => { await jobs.close(); await new Promise(resolve => server.close(resolve)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const request = (path, method = 'GET', data, headers = {}) => fetch(`${base}${path}`, {
    method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...headers },
    ...(data === undefined ? {} : { body: typeof data === 'string' ? data : JSON.stringify(data) }),
  });
  return { jobs, request };
}

test('daemon starts a job, rejects concurrent login, and retains repeatable results until expiry', async t => {
  let finish, supplied;
  const { request } = await fixture(t, options => { supplied = options; return new Promise(resolve => { finish = resolve; }); }, 100);
  const start = await request('/login', 'POST', body);
  assert.equal(start.status, 202);
  assert.equal(start.headers.get('cache-control'), 'no-store');
  const { jobId } = await start.json();
  const path = `/login/${jobId}`;
  assert.equal(start.headers.get('location'), path);
  assert.equal(supplied.clientId, body.clientId);
  assert.equal(supplied.interception, 'managed');
  assert.equal(supplied.stateDir, '/tmp/daemon-test-state');
  assert.equal(supplied.timeoutMs, 300_000);
  assert.equal((await request('/login', 'POST', body)).status, 409);
  assert.equal((await (await request(path)).json()).status, 'pending');
  finish({ code: 'test-code', codeVerifier: 'test-verifier', nonce: 'test-nonce' });
  await delay(0);
  for (let i = 0; i < 2; i++) {
    const result = await (await request(path)).json();
    assert.equal(result.status, 'completed');
    assert.equal(result.result.code, 'test-code');
  }
  await delay(130);
  assert.equal((await request(path)).status, 404);
});

test('daemon authenticates all endpoints, rejects origins and invalid input before running authorization', async t => {
  let calls = 0;
  const { request } = await fixture(t, async () => { calls++; });
  assert.equal((await request('/health', 'GET', undefined, { Authorization: '' })).status, 401);
  assert.equal((await request('/health', 'GET', undefined, { Origin: 'https://example.com' })).status, 403);
  assert.equal((await request('/health')).status, 200);
  for (const invalid of [{}, { ...body, stateDir: '/tmp/x' }, { ...body, openBrowser: false }, { ...body, issuer: 'http://example.com' }, { ...body, scopes: ['email'] }, { ...body, timeoutMs: 300001 }, { ...body, authorizationParams: { state: 'override' } }, { ...body, redirectUri: 'https://example.com' }]) {
    assert.equal((await request('/login', 'POST', invalid)).status, 400);
  }
  assert.equal((await request('/login', 'POST', '{')).status, 400);
  assert.equal((await request('/login', 'POST', body, { 'Content-Type': 'text/plain' })).status, 415);
  assert.equal((await request('/login', 'POST', { ...body, clientId: 'x'.repeat(17000) })).status, 413);
  assert.equal((await request('/missing')).status, 404);
  assert.equal((await request('/login/missing', 'DELETE')).status, 404);
  assert.equal(calls, 0);
});

test('cancellation and shutdown await authorization cleanup before releasing the active slot', async t => {
  let cleaned = false;
  const { jobs, request } = await fixture(t, ({ signal }) => new Promise((_, reject) => {
    signal.addEventListener('abort', () => { setTimeout(() => { cleaned = true; reject(new OIDCEmulatorError('CANCELLED', 'Authorization cancelled.')); }, 30); }, { once: true });
  }));
  const { jobId } = await (await request('/login', 'POST', body)).json();
  assert.equal((await request(`/login/${jobId}`, 'DELETE')).status, 202);
  assert.equal((await request('/login', 'POST', body)).status, 409);
  await delay(50);
  assert.equal(cleaned, true);
  const failed = await (await request(`/login/${jobId}`)).json();
  assert.equal(failed.status, 'failed');
  assert.equal(failed.error.code, 'CANCELLED');
  cleaned = false;
  await request('/login', 'POST', body);
  await jobs.close();
  assert.equal(cleaned, true);
  assert.equal((await request('/login', 'POST', body)).status, 503);
});

test('daemon reports failures without leaking unexpected error details', async t => {
  const { request } = await fixture(t, async () => { throw new Error('secret provider response'); });
  const { jobId } = await (await request('/login', 'POST', body)).json();
  const result = await (await request(`/login/${jobId}`)).json();
  assert.equal(result.status, 'failed');
  assert.equal(result.error.message, 'Authorization failed.');
});

test('server validates binding and token and supports clean close', async () => {
  await assert.rejects(startDaemon({ token, host: '0.0.0.0' }), { code: 'INVALID_OPTIONS' });
  await assert.rejects(startDaemon({ token: 'short' }), { code: 'INVALID_OPTIONS' });
  const daemon = await startDaemon({ token, port: 0 });
  assert.ok(daemon.server.address().port > 0);
  await daemon.close();
  await daemon.close();
  assert.equal(daemon.server.listening, false);
});

for (const generated of [false, true]) {
test(`daemon CLI authenticates with a ${generated ? 'generated' : 'configured'} token and exits cleanly`, async t => {
  const { spawn } = await import('node:child_process');
  const child = spawn(process.execPath, ['dist/cli.js', 'daemon', '--port', '0'], {
    env: { ...process.env, OIDC_DAEMON_TOKEN: generated ? '' : token }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  t.after(() => { if (child.exitCode === null) child.kill('SIGKILL'); });
  const exited = once(child, 'exit');
  let stdout = '';
  child.stdout.on('data', chunk => { stdout += chunk; });
  const { url, bearer } = await new Promise((resolve, reject) => {
    let stderr = '';
    const timer = setTimeout(() => reject(new Error('Daemon startup timed out')), 5000);
    child.once('exit', () => { clearTimeout(timer); reject(new Error('Daemon exited before startup')); });
    child.stderr.on('data', chunk => {
      stderr += chunk;
      const match = stderr.match(/listening on (http:\/\/127\.0\.0\.1:\d+)/);
      const displayed = stderr.match(/Authorization: Bearer ([A-Za-z0-9_-]{43})/);
      if (match && (!generated || displayed)) {
        if (!generated) assert.equal(stderr.includes(token), false);
        clearTimeout(timer); resolve({ url: match[1], bearer: generated ? displayed[1] : token });
      }
    });
  });
  const response = await fetch(`${url}/health`, { headers: { Authorization: `Bearer ${bearer}` } });
  assert.equal(response.status, 200);
  child.kill('SIGTERM');
  assert.deepEqual(await exited, [0, null]);
  assert.equal(stdout, '');
});
}

test('job logs show request context and lifecycle without exposing authorization secrets', async () => {
  const logs = [];
  const jobs = new LoginJobs(async options => {
    await options.onAuthorizationUrl('https://identity.example/authorize?state=secret-state');
    return { code: 'secret-code', codeVerifier: 'secret-verifier', nonce: 'secret-nonce' };
  }, undefined, 20, line => logs.push(line));
  const { jobId } = jobs.start({ ...body, redirectUri: `${body.redirectUri}?private=secret-query`, timeoutMs: 300000,
    authorizationParams: { login_hint: 'secret-login-hint' } });
  await delay(0);
  assert.equal(jobs.get(jobId).status, 'completed');
  await delay(30);
  const output = logs.join('\n');
  for (const expected of [jobId, body.issuer, body.clientId, 'pending:', 'preparing:', 'ready:', 'completed:', 'status requested: completed', 'expired:']) assert.ok(output.includes(expected), expected);
  assert.doesNotMatch(output, /secret-/);
  await jobs.close();
});

test('daemon validates and forwards optional PKCE', async t => {
  const received = [];
  const { request } = await fixture(t, async options => { received.push(options.pkce); return { code: 'test' }; });
  for (const extra of [{}, { pkce: false }, { pkce: true }]) {
    assert.equal((await request('/login', 'POST', { ...body, ...extra })).status, 202);
  }
  assert.deepEqual(received, [undefined, false, true]);
  for (const pkce of ['true', 1, null]) assert.equal((await request('/login', 'POST', { ...body, pkce })).status, 400);
});
