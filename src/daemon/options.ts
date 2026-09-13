import type { AuthorizationOptions } from '../oidc.js';
import { fail, validateScheme } from '../util.js';

const fields = new Set(['issuer', 'clientId', 'redirectUri', 'discoveryUrl', 'scopes', 'timeoutMs', 'authorizationParams', 'pkce']);
const protectedParams = new Set(['client_id', 'redirect_uri', 'response_type', 'response_mode', 'scope', 'state', 'nonce', 'code_challenge', 'code_challenge_method', 'request', 'request_uri', 'client_secret']);
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);

/** Only accept wire parameters; filesystem, browser, and callback settings belong to the daemon. */
export function loginOptions(body: unknown): AuthorizationOptions {
  if (!object(body) || Object.keys(body).some(key => !fields.has(key))) fail('INVALID_OPTIONS', 'Body must be a JSON object containing supported login parameters.');
  for (const key of ['issuer', 'clientId', 'redirectUri']) {
    if (typeof body[key] !== 'string' || !body[key].trim()) fail('INVALID_OPTIONS', `${key} is required.`);
  }
  for (const key of ['issuer', 'discoveryUrl']) {
    if (key === 'discoveryUrl' && body[key] === undefined) continue;
    let url: URL;
    try { url = new URL(body[key] as string); } catch { return fail('INVALID_OPTIONS', `${key} must be an HTTPS URL.`); }
    if (url.protocol !== 'https:' || url.username || url.password || url.hash || (key === 'issuer' && url.search)) fail('INVALID_OPTIONS', `${key} must be an HTTPS URL without credentials or fragments.`);
  }
  let redirect: URL;
  try { redirect = new URL(body.redirectUri as string); } catch { return fail('INVALID_OPTIONS', 'redirectUri must be a custom-scheme URL.'); }
  validateScheme(redirect.protocol.slice(0, -1));
  if (redirect.username || redirect.password || redirect.hash || ['code', 'state', 'error', 'error_description', 'error_uri', 'iss'].some(key => redirect.searchParams.has(key))) fail('INVALID_OPTIONS', 'redirectUri contains reserved response fields, credentials, or a fragment.');
  if (body.scopes !== undefined && (!Array.isArray(body.scopes) || !body.scopes.includes('openid') || body.scopes.some(scope => typeof scope !== 'string' || !/^[\x21\x23-\x5b\x5d-\x7e]+$/.test(scope)))) fail('INVALID_OPTIONS', 'scopes must be an array of scope tokens including openid.');
  if (body.pkce !== undefined && typeof body.pkce !== 'boolean') fail('INVALID_OPTIONS', 'pkce must be a boolean.');
  const timeoutMs = body.timeoutMs ?? 300_000;
  if (!Number.isInteger(timeoutMs) || (timeoutMs as number) < 1 || (timeoutMs as number) > 300_000) fail('INVALID_OPTIONS', 'timeoutMs must be an integer from 1 to 300000.');
  if (body.authorizationParams !== undefined && (!object(body.authorizationParams) || Object.entries(body.authorizationParams).some(([key, value]) => protectedParams.has(key) || typeof value !== 'string'))) fail('INVALID_OPTIONS', 'authorizationParams must contain string values and cannot override protocol fields.');
  return { issuer: body.issuer as string, clientId: body.clientId as string, redirectUri: body.redirectUri as string,
    discoveryUrl: body.discoveryUrl as string | undefined, scopes: body.scopes as string[] | undefined,
    pkce: body.pkce as boolean | undefined, timeoutMs: timeoutMs as number, authorizationParams: body.authorizationParams as Record<string, string> | undefined };
}
