import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { generateKeyPair, exportJWK, SignJWT, customFetch } from 'jose';
import { accessOptions, createAccessVerifier } from '../dist/daemon/access.js';
import { createDaemonApp } from '../dist/daemon/server.js';
import { LoginJobs } from '../dist/daemon/jobs.js';

const config = { teamDomain: 'test-team.cloudflareaccess.com', audience: 'test-audience' };
const issuer = `https://${config.teamDomain}`;
const pair = await generateKeyPair('RS256');
const jwk = { ...await exportJWK(pair.publicKey), kid: 'test-key', alg: 'RS256' };
const sign = (claims = {}, key = pair.privateKey, alg = 'RS256') => new SignJWT({ iss: issuer, aud: config.audience,
  iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 60, ...claims }).setProtectedHeader({ alg, kid: 'test-key' }).sign(key);

test('Access config requires a pair and confines JWKS to the team domain', () => {
  assert.equal(accessOptions(), undefined);
  assert.deepEqual(accessOptions('TEST-TEAM.cloudflareaccess.com', ' test-audience '), config);
  for (const [domain, audience] of [[config.teamDomain], [undefined, 'aud'], ['', 'aud'], [config.teamDomain, ' '],
    ['https://test-team.cloudflareaccess.com', 'aud'], ['test-team.cloudflareaccess.com.evil.com', 'aud'], ['localhost', 'aud'],
    ['test-team.cloudflareaccess.com/path', 'aud']]) assert.throws(() => accessOptions(domain, audience), { code: 'INVALID_OPTIONS' });
});

test('Access verifies claims and signatures, caches JWKS, and refreshes on key rotation', async () => {
  let calls = 0, current = jwk;
  const verify = createAccessVerifier(config, { cooldownDuration: 0, [customFetch]: async url => {
    assert.equal(String(url), `${issuer}/cdn-cgi/access/certs`);
    calls++; return Response.json({ keys: [current] });
  } });
  assert.equal(await verify(await sign()), true);
  assert.equal(await verify(await sign()), true);
  assert.equal(calls, 1);
  for (const claims of [{ iss: 'https://wrong.cloudflareaccess.com' }, { aud: 'wrong' }, { exp: 1 }, { exp: undefined }, { iat: undefined }, { nbf: Math.floor(Date.now()/1000) + 3600 }]) {
    assert.equal(await verify(await sign(claims)), false);
  }
  assert.equal(await verify('not-a-jwt'), false);
  const other = await generateKeyPair('RS256');
  assert.equal(await verify(await sign({}, other.privateKey)), false);
  assert.equal(await verify(await sign({}, new Uint8Array(32), 'HS256')), false);
  current = { ...await exportJWK(other.publicKey), alg: 'RS256', kid: 'rotated' };
  const rotated = await new SignJWT({ iss: issuer, aud: config.audience }).setIssuedAt().setExpirationTime('1m').setProtectedHeader({ alg: 'RS256', kid: 'rotated' }).sign(other.privateKey);
  assert.equal(await verify(rotated), true);
  assert.equal(calls, 2);
  const unavailable = createAccessVerifier(config, { [customFetch]: async () => { throw new Error('unavailable'); } });
  assert.equal(await unavailable(await sign()), false);
});

test('HTTP accepts Access JWT or bearer, and never trusts an unverified Access header', async t => {
  const originalFetch = globalThis.fetch;
  t.mock.method(globalThis, 'fetch', (url, options) => String(url) === `${issuer}/cdn-cgi/access/certs`
    ? Promise.resolve(Response.json({ keys: [jwk] })) : originalFetch(url, options));
  const token = 'a'.repeat(43);
  for (const access of [undefined, config]) {
    const jobs = new LoginJobs();
    const server = createServer(createDaemonApp(token, jobs, access)).listen(0, '127.0.0.1');
    await once(server, 'listening');
    try {
      const base = `http://127.0.0.1:${server.address().port}`;
      const request = (headers = {}) => originalFetch(`${base}/health`, { headers });
      assert.equal((await request()).status, 401);
      assert.equal((await request({ 'Cf-Access-Jwt-Assertion': 'fake' })).status, 401);
      assert.equal((await request({ 'Cf-Access-Jwt-Assertion': await sign() })).status, access ? 200 : 401);
      assert.equal((await request({ Authorization: `Bearer ${token}`, 'Cf-Access-Jwt-Assertion': 'fake' })).status, 200);
      assert.equal((await request({ Authorization: `Bearer ${token}`, Origin: 'https://example.com' })).status, 403);
    } finally { await jobs.close(); await new Promise(resolve => server.close(resolve)); }
  }
});

test('CLI reads Access environment values, allows flag overrides, and rejects incomplete setup', async t => {
  const { spawn } = await import('node:child_process');
  for (const flags of [[], ['--access-team-domain', 'override.cloudflareaccess.com', '--access-audience', 'override-aud']]) {
    const child = spawn(process.execPath, ['dist/cli.js', 'daemon', '--port', '0', ...flags], {
      env: { ...process.env, OIDC_DAEMON_TOKEN: 'a'.repeat(43), OIDC_ACCESS_TEAM_DOMAIN: config.teamDomain, OIDC_ACCESS_AUDIENCE: config.audience },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    t.after(() => { if (child.exitCode === null) child.kill('SIGKILL'); });
    const exited = once(child, 'exit');
    let text = '';
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('startup timeout')), 5000);
      child.once('exit', () => { clearTimeout(timer); reject(new Error('startup failed')); });
      child.stderr.on('data', chunk => {
        text += chunk;
        if (text.includes('Local bearer tokens also accepted.')) { clearTimeout(timer); resolve(); }
      });
    });
    assert.ok(text.includes(flags.length ? 'override.cloudflareaccess.com; audience "override-aud"' : `${config.teamDomain}; audience "${config.audience}"`));
    child.kill('SIGTERM');
    assert.deepEqual(await exited, [0, null]);
  }
  const { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  await assert.rejects(promisify(execFile)(process.execPath, ['dist/cli.js', 'daemon'], {
    env: { ...process.env, OIDC_ACCESS_TEAM_DOMAIN: config.teamDomain, OIDC_ACCESS_AUDIENCE: '' },
  }), error => error.code === 1 && /requires both/.test(error.stderr));
});
