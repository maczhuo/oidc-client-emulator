import { fileURLToPath } from 'node:url';
import { authorize, discover, OIDCEmulatorError } from '../dist/index.js';
import { IDTokenValidationError, providerKeys, validateIdToken } from './validate-id-token.mjs';

const required = name => {
  const value = process.env[name];
  if (!value) throw new Error(`Missing environment variable: ${name}`);
  return value;
};
const controller = new AbortController();
const stop = () => controller.abort();
process.once('SIGINT', stop); process.once('SIGTERM', stop);

try {
  const issuer = required('OIDC_ENDPOINT');
  const clientId = required('OIDC_CLIENT_ID');
  const clientSecret = required('OIDC_CLIENT_SECRET');
  const redirectUri = required('OIDC_REDIRECT_URI');
  const metadata = await discover(issuer, { signal: AbortSignal.timeout(15_000) });
  if (!metadata.token_endpoint) throw new Error('Provider has no token endpoint.');
  const keys = providerKeys(metadata);
  const method = process.env.OIDC_TOKEN_ENDPOINT_AUTH_METHOD ?? 'client_secret_basic';
  if (!['client_secret_basic', 'client_secret_post'].includes(method) ||
      (metadata.token_endpoint_auth_methods_supported && !metadata.token_endpoint_auth_methods_supported.includes(method))) {
    throw new Error('Configured token endpoint authentication method is unsupported.');
  }
  console.error('Preparing authorization. Complete sign-in with your identity provider after opening the browser; this check will redeem and discard the resulting tokens.');
  const result = await authorize({ issuer, clientId, redirectUri,
    scopes: (process.env.OIDC_SCOPES ?? 'openid').split(/\s+/).filter(Boolean),
    stateDir: fileURLToPath(new URL('../.prototype/live-state', import.meta.url)),
    signal: controller.signal, timeoutMs: 300_000,
  });
  const body = new URLSearchParams({ grant_type: 'authorization_code', code: result.code,
    redirect_uri: result.redirectUri, code_verifier: result.codeVerifier });
  const headers = { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' };
  if (method === 'client_secret_basic') {
    const encode = value => new URLSearchParams({ v: value }).toString().slice(2);
    headers.Authorization = 'Basic ' + Buffer.from(`${encode(clientId)}:${encode(clientSecret)}`).toString('base64');
  } else { body.set('client_id', clientId); body.set('client_secret', clientSecret); }
  const response = await fetch(metadata.token_endpoint, { method: 'POST', headers, body,
    redirect: 'error', signal: AbortSignal.any([controller.signal, AbortSignal.timeout(15_000)]) });
  const payload = await response.json();
  if (!response.ok || typeof payload.access_token !== 'string' || !payload.access_token || typeof payload.token_type !== 'string') {
    const safeError = typeof payload.error === 'string' && /^[a-z_]{1,64}$/.test(payload.error) ? payload.error : 'unknown';
    throw new Error(`Token exchange failed (HTTP ${response.status}, ${safeError}). No response body logged.`);
  }
  const validation = await validateIdToken(payload.id_token, { keys, issuer, clientId, nonce: result.nonce });
  console.log(JSON.stringify({ verified: true, ...validation, tokenExchangeStatus: response.status,
    accessTokenReceived: true, idTokenReceived: typeof payload.id_token === 'string',
    refreshTokenReceived: typeof payload.refresh_token === 'string', handlerCleanupCompleted: true }));
} catch (error) {
  console.error(error instanceof IDTokenValidationError ? error.message :
    error instanceof OIDCEmulatorError ? `${error.code}: ${error.message}` :
    error instanceof Error && /^(Missing environment variable:|Provider has no token endpoint|Configured token endpoint|Token exchange failed)/.test(error.message)
      ? error.message : 'Live verification failed; credentials and provider response bodies are suppressed.');
  process.exitCode = 1;
} finally { process.off('SIGINT', stop); process.off('SIGTERM', stop); }
