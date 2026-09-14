import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { authorize, discover } from '../dist/index.js';
import { parseResponse } from '../dist/oidc.js';

const token = 'a'.repeat(43);
async function provider(t, overrides = {}) {
  let origin;
  const server = createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ issuer: origin, authorization_endpoint: `${origin}/authorize`,
      token_endpoint: `${origin}/token`, response_types_supported: ['code'],
      code_challenge_methods_supported: ['S256'], ...overrides }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  return origin;
}
async function freePort() {
  const server = createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}
async function options(t, extra = {}) {
  return { issuer: await provider(t), clientId: 'test-client', redirectUri: 'dev.example.app://callback?fixed=one',
    allowInsecureHttp: true, interception: 'none', callback: { host: '127.0.0.1', port: await freePort(), token },
    timeoutMs: 3000, ...extra };
}
function callback(auth, params = {}) {
  const uri = new URL(auth.searchParams.get('redirect_uri'));
  uri.searchParams.set('state', auth.searchParams.get('state'));
  for (const [key, value] of Object.entries(params)) uri.searchParams.set(key, value);
  return uri.href;
}
async function send(opts, url, authorization = `Bearer ${token}`) {
  return fetch(`http://127.0.0.1:${opts.callback.port}/callback`, { method: 'POST',
    headers: { Authorization: authorization, 'Content-Type': 'application/json' }, body: JSON.stringify({ url }) });
}

test('authorization sends standards-based parameters and returns redeemable PKCE context', async t => {
  const opts = await options(t);
  let auth;
  const result = await authorize({ ...opts, scopes: ['openid', 'email'], openBrowser: async raw => {
    auth = new URL(raw);
    assert.equal(auth.searchParams.get('response_type'), 'code');
    assert.equal(auth.searchParams.get('response_mode'), 'query');
    assert.equal(auth.searchParams.get('code_challenge_method'), 'S256');
    assert.equal(auth.searchParams.get('scope'), 'openid email');
    assert.ok(auth.searchParams.get('nonce'));
    assert.equal((await send(opts, callback(auth, { code: 'a+b/c=' }))).status, 204);
  } });
  assert.equal(result.code, 'a+b/c=');
  assert.equal(result.state, auth.searchParams.get('state'));
  assert.equal(createHash('sha256').update(result.codeVerifier).digest('base64url'), auth.searchParams.get('code_challenge'));
  await assert.rejects(fetch(`http://127.0.0.1:${opts.callback.port}/callback`));
});

test('unauthenticated and wrong-state traffic cannot finish a pending authorization', async t => {
  const opts = await options(t);
  const result = await authorize({ ...opts, openBrowser: async raw => {
    const auth = new URL(raw);
    assert.equal((await send(opts, callback(auth, { code: 'bad' }), 'Bearer wrong')).status, 403);
    assert.equal((await send(opts, callback(auth, { code: 'bad', state: 'wrong' }))).status, 400);
    assert.equal((await send(opts, callback(auth, { code: 'good' }))).status, 204);
  } });
  assert.equal(result.code, 'good');
});

test('provider error rejects immediately, with cleanup', async t => {
  const opts = await options(t);
  await assert.rejects(authorize({ ...opts, openBrowser: async raw => {
    assert.equal((await send(opts, callback(new URL(raw), { error: 'access_denied' }))).status, 204);
  } }), error => error.code === 'AUTHORIZATION_DENIED' && error.oauthError === 'access_denied');
  await assert.rejects(fetch(`http://127.0.0.1:${opts.callback.port}/callback`));
});

test('cancellation and a hanging browser hook respect the transaction deadline', async t => {
  const opts = await options(t);
  await assert.rejects(authorize({ ...opts, timeoutMs: 100, openBrowser: () => new Promise(() => {}) }), error => error.code === 'TIMEOUT');
  await assert.rejects(fetch(`http://127.0.0.1:${opts.callback.port}/callback`));
  const abort = new AbortController(); abort.abort();
  await assert.rejects(authorize({ ...opts, signal: abort.signal }), error => error.code === 'CANCELLED');
});

test('network interface, scopes, and protected parameters are validated before browser launch', async t => {
  const opts = await options(t, { openBrowser: () => assert.fail('Browser must not open') });
  for (const change of [ { callback: { ...opts.callback, host: '0.0.0.0' } }, { scopes: ['email'] },
    { authorizationParams: { state: 'attacker' } }, { redirectUri: 'https://example.com/callback' },
    { callback: { ...opts.callback, port: -1 } }, { redirectUri: 'dev.example.app://callback?state=fixed' } ]) {
    await assert.rejects(authorize({ ...opts, ...change }), error => error.code === 'INVALID_OPTIONS');
  }
});

test('discovery rejects issuer substitution; PKCE checks provider support only when enabled', async t => {
  const wrong = await provider(t, { issuer: 'https://wrong.example' });
  await assert.rejects(discover(wrong, { allowInsecureHttp: true }), { code: 'INVALID_METADATA' });
  const issuer = await provider(t, { code_challenge_methods_supported: ['plain'] });
  const opts = { ...await options(t), issuer };
  await discover(issuer, { allowInsecureHttp: true });
  for (const pkce of [undefined, true]) {
    await assert.rejects(authorize({ ...opts, pkce }), { code: 'UNSUPPORTED_PROVIDER' });
  }
  for (const pkce of [false]) {
    const result = await authorize({ ...opts, pkce, openBrowser: async raw => {
      const auth = new URL(raw);
      assert.equal(auth.searchParams.has('code_challenge'), false);
      assert.equal(auth.searchParams.has('code_challenge_method'), false);
      assert.ok(auth.searchParams.get('state'));
      assert.ok(auth.searchParams.get('nonce'));
      await send(opts, callback(auth, { code: 'no-pkce-code' }));
    } });
    assert.equal(result.code, 'no-pkce-code');
    assert.equal(Object.hasOwn(result, 'codeVerifier'), false);
  }
  await assert.rejects(authorize({ ...opts, pkce: 'true' }), { code: 'INVALID_OPTIONS' });
});

test('callback parser rejects destination substitution, duplicates, fragments, mixed responses, and issuer mismatch', () => {
  const expected = { redirectUri: 'dev.example.app://callback?fixed=one', state: 'expected', issuer: 'https://id.example', requireIssuer: true };
  const valid = 'dev.example.app://callback?fixed=one&state=expected&code=ok&iss=https%3A%2F%2Fid.example';
  assert.equal(parseResponse(valid, expected), 'ok');
  for (const invalid of [ valid.replace('://callback', '://other'), valid + '&code=extra', valid + '&state=expected',
    valid + '#fragment', valid.replace('fixed=one', 'fixed=two'), valid.replace('id.example', 'other.example'),
    valid + '&error=access_denied', valid.replace(/&iss=.*/, ''), valid.replace('code=ok', 'code=') ]) {
    assert.throws(() => parseResponse(invalid, expected));
  }
});

test('port conflicts fail before opening a browser', async t => {
  const opts = await options(t);
  const occupied = createServer();
  await new Promise(resolve => occupied.listen(opts.callback.port, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => occupied.close(resolve)));
  await assert.rejects(authorize({ ...opts, openBrowser: () => assert.fail('Browser must not open') }), /bind/);
});

test('oversized and malformed callback bodies are rejected without settling the transaction', async t => {
  const opts = await options(t);
  const result = await authorize({ ...opts, openBrowser: async raw => {
    assert.equal((await send(opts, 'x'.repeat(20_000))).status, 413);
    assert.equal((await send(opts, 'not-a-url')).status, 400);
    assert.equal((await send(opts, callback(new URL(raw), { code: 'valid' }))).status, 204);
  } });
  assert.equal(result.code, 'valid');
});

test('module signal handlers cancel active authorization, close the receiver, and preserve host handlers', async t => {
  for (const name of ['SIGINT', 'SIGTERM']) {
    const opts = await options(t);
    let hostCalls = 0;
    const host = () => { hostCalls++; };
    process.on(name, host);
    const counts = ['SIGINT', 'SIGTERM'].map(signal => process.listenerCount(signal));
    try {
      await assert.rejects(authorize({ ...opts, openBrowser: () => {
        process.emit(name);
        return new Promise(() => {});
      } }), { code: 'CANCELLED' });
      assert.equal(hostCalls, 1);
      assert.ok(process.listeners(name).includes(host));
      assert.deepEqual(['SIGINT', 'SIGTERM'].map(signal => process.listenerCount(signal)), counts);
      await assert.rejects(fetch(`http://127.0.0.1:${opts.callback.port}/callback`));
    } finally { process.off(name, host); }
  }
});

test('module signal handling can be disabled and timeout removes default handlers', async t => {
  const counts = ['SIGINT', 'SIGTERM'].map(signal => process.listenerCount(signal));
  const opts = await options(t);
  await assert.rejects(authorize({ ...opts, handleSignals: false, timeoutMs: 30, openBrowser: () => {
    assert.deepEqual(['SIGINT', 'SIGTERM'].map(signal => process.listenerCount(signal)), counts);
    return new Promise(() => {});
  } }), { code: 'TIMEOUT' });
  await assert.rejects(authorize({ ...opts, timeoutMs: 30, openBrowser: () => new Promise(() => {}) }), { code: 'TIMEOUT' });
  assert.deepEqual(['SIGINT', 'SIGTERM'].map(signal => process.listenerCount(signal)), counts);
});
