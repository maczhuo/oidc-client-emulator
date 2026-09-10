import test from 'node:test';
import assert from 'node:assert/strict';
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from 'jose';
import { IDTokenValidationError, providerKeys, validateIdToken } from '../scripts/validate-id-token.mjs';

const { privateKey, publicKey } = await generateKeyPair('RS256');
const jwk = await exportJWK(publicKey);
const keys = createLocalJWKSet({ keys: [{ ...jwk, kid: 'test-key', alg: 'RS256', use: 'sig' }] });
const expected = { keys, issuer: 'https://identity.example.com', clientId: 'test-client', nonce: 'expected-test-nonce' };
async function token(changes = {}, signingKey = privateKey) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ iss: expected.issuer, sub: 'test-subject', aud: expected.clientId,
    iat: now, exp: now + 300, nonce: expected.nonce, ...changes })
    .setProtectedHeader({ alg: 'RS256', kid: 'test-key' }).sign(signingKey);
}

test('ID token signature and matching nonce must validate together', async () => {
  assert.deepEqual(await validateIdToken(await token(), expected), { idTokenValidated: true, nonceValidated: true });
});

test('missing and mismatched nonce, or missing ID token, fail closed', async () => {
  for (const value of [undefined, '', await token({ nonce: undefined }), await token({ nonce: 'different-nonce' })]) {
    await assert.rejects(validateIdToken(value, expected), IDTokenValidationError);
  }
});

test('invalid signature, issuer, audience, lifetime, or authorized party rejects the ID token', async () => {
  const other = await generateKeyPair('RS256');
  await assert.rejects(validateIdToken(await token({}, other.privateKey), expected), IDTokenValidationError);
  for (const changes of [ { iss: 'https://other.example.com' }, { aud: 'other-client' },
    { exp: Math.floor(Date.now() / 1000) - 1 }, { exp: undefined }, { iat: undefined },
    { iat: Math.floor(Date.now() / 1000) + 60 }, { sub: '' }, { azp: 'other-client' },
    { aud: [expected.clientId, 'other-client'] } ]) {
    await assert.rejects(validateIdToken(await token(changes), expected), IDTokenValidationError);
  }
});

test('JWKS configuration requires HTTPS and the supported signing algorithm', () => {
  for (const metadata of [{}, { jwks_uri: 'http://example.com/jwks' },
    { jwks_uri: 'https://example.com/jwks', id_token_signing_alg_values_supported: ['HS256'] }]) {
    assert.throws(() => providerKeys(metadata), IDTokenValidationError);
  }
});
