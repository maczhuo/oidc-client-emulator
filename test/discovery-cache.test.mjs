import test from 'node:test';
import assert from 'node:assert/strict';
import { discover } from '../dist/index.js';

const metadata = issuer => ({ issuer, authorization_endpoint: `${issuer}/authorize`, code_challenge_methods_supported: ['S256'] });

test('discovery caches for exactly 300 seconds without sliding expiry or sharing mutable metadata', async t => {
  const issuer = 'https://cache-expiry.example';
  let now = 1_000, calls = 0;
  t.mock.method(Date, 'now', () => now);
  t.mock.method(globalThis, 'fetch', async () => {
    calls++;
    return Response.json({ ...metadata(issuer), token_endpoint: `${issuer}/token-${calls}` });
  });
  const first = await discover(issuer);
  first.code_challenge_methods_supported.push('plain');
  first.authorization_endpoint = 'https://changed.example';
  now += 299_999;
  const hit = await discover(issuer);
  assert.equal(calls, 1);
  assert.equal(hit.authorization_endpoint, `${issuer}/authorize`);
  assert.deepEqual(hit.code_challenge_methods_supported, ['S256']);
  hit.code_challenge_methods_supported.length = 0;
  assert.deepEqual((await discover(issuer)).code_challenge_methods_supported, ['S256']);
  now++;
  assert.equal((await discover(issuer)).token_endpoint, `${issuer}/token-2`);
  assert.equal(calls, 2);
});

test('cache separates issuer, discovery URL, and insecure HTTP policy', async t => {
  let calls = 0;
  t.mock.method(globalThis, 'fetch', async url => {
    calls++;
    const parsed = new URL(url);
    return Response.json(metadata(parsed.origin));
  });
  const issuer = 'https://cache-keys.example';
  await discover(issuer);
  await discover(issuer, { discoveryUrl: `${issuer}/.well-known/openid-configuration` });
  assert.equal(calls, 1);
  await discover(issuer, { discoveryUrl: `${issuer}/custom` });
  await discover(issuer, { allowInsecureHttp: true });
  await discover('https://cache-other.example');
  assert.equal(calls, 4);
  await assert.rejects(discover(`${issuer}/different`, { discoveryUrl: `${issuer}/custom` }), { code: 'INVALID_METADATA' });
  assert.equal(calls, 5);
});

test('failed or invalid discovery is retried and cache hits honor cancellation', async t => {
  const issuer = 'https://cache-failures.example';
  let calls = 0;
  t.mock.method(globalThis, 'fetch', async () => {
    calls++;
    if (calls === 1) return new Response('', { status: 503 });
    if (calls === 2) return Response.json(metadata('https://wrong.example'));
    return Response.json(metadata(issuer));
  });
  await assert.rejects(discover(issuer), { code: 'DISCOVERY_FAILED' });
  await assert.rejects(discover(issuer), { code: 'INVALID_METADATA' });
  await discover(issuer);
  await discover(issuer);
  assert.equal(calls, 3);
  const reason = new Error('cancelled');
  await assert.rejects(discover(issuer, { signal: AbortSignal.abort(reason) }), error => error === reason);
  assert.equal(calls, 3);
});
