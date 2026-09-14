import { registerAuthorizationSignals } from './signals.js';
import { createHash } from 'node:crypto';
import { AuthorizationResponseError, OIDCEmulatorError } from './errors.js';
import { listen } from './receiver.js';
import { enable, existingInterception, interceptOff, withSchemeLease } from './macos.js';
import { equal, fail, loopback, openDefaultBrowser, secret, validatePort, validateScheme, validateToken } from './util.js';

export interface AuthorizationOptions {
  issuer: string;
  discoveryUrl?: string;
  clientId: string;
  redirectUri: string;
  scopes?: string[];
  /** Use PKCE S256 by default; set false to disable. */
  pkce?: boolean;
  callback?: { host?: string; port?: number; token?: string };
  /** managed: temporary takeover; existing: persistent interception; none: external relay. */
  interception?: 'managed' | 'existing' | 'none';
  stateDir?: string;
  timeoutMs?: number;
  signal?: AbortSignal;
  /** Cancel on SIGINT/SIGTERM while active. Defaults to true. */
  handleSignals?: boolean;
  /** Wait for Enter before the default browser opens. CLI-only by default. */
  promptBeforeBrowser?: boolean;
  openBrowser?: false | ((url: string) => void | Promise<void>);
  onAuthorizationUrl?: (url: string) => void | Promise<void>;
  authorizationParams?: Record<string, string>;
  /** Only permits HTTP provider URLs on loopback, for local test providers. */
  allowInsecureHttp?: boolean;
}

export interface AuthorizationResult {
  code: string;
  codeVerifier?: string;
  state: string;
  nonce: string;
  redirectUri: string;
  issuer: string;
  tokenEndpoint?: string;
  receivedAt: string;
}

export interface ProviderMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint?: string;
  response_types_supported?: string[];
  response_modes_supported?: string[];
  code_challenge_methods_supported?: string[];
  authorization_response_iss_parameter_supported?: boolean;
  require_pushed_authorization_requests?: boolean;
  token_endpoint_auth_methods_supported?: string[];
}

function providerURL(value: string, insecure: boolean): URL {
  let url: URL;
  try { url = new URL(value); } catch { return fail('INVALID_OPTIONS', 'Provider URLs must be absolute URLs.'); }
  if (url.username || url.password || url.hash || (url.protocol !== 'https:' && !(insecure && url.protocol === 'http:' && loopback(url.hostname.replace(/^\[|\]$/g, ''))))) {
    fail('INVALID_OPTIONS', 'Provider URLs require HTTPS (or explicitly enabled loopback HTTP).');
  }
  return url;
}

const discoveryCache = new Map<string, { metadata: ProviderMetadata; expiresAt: number }>();
const discoveryCacheTtlMs = 300_000;
const discoveryCacheMaxEntries = 100;

export async function discover(issuer: string, options: { discoveryUrl?: string; allowInsecureHttp?: boolean; signal?: AbortSignal } = {}): Promise<ProviderMetadata> {
  options.signal?.throwIfAborted();
  const issuerURL = providerURL(issuer, !!options.allowInsecureHttp);
  if (issuerURL.search) fail('INVALID_OPTIONS', 'Issuer cannot contain a query.');
  const url = providerURL(options.discoveryUrl ?? `${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`, !!options.allowInsecureHttp);
  // Keep insecure local-test metadata separate from normal HTTPS-only discovery.
  const cacheKey = JSON.stringify([issuer, url.href, !!options.allowInsecureHttp]);
  const now = Date.now();
  for (const [key, entry] of discoveryCache) {
    if (entry.expiresAt <= now) discoveryCache.delete(key);
  }
  const cached = discoveryCache.get(cacheKey);
  if (cached) return structuredClone(cached.metadata);
  let metadata: ProviderMetadata;
  try {
    const response = await fetch(url, { signal: options.signal, redirect: 'error', headers: { Accept: 'application/json' } });
    if (!response.ok) fail('DISCOVERY_FAILED', 'Provider discovery returned an unsuccessful HTTP status.');
    // Bound discovery response size before parsing.
    const reader = response.body?.getReader();
    if (!reader) fail('DISCOVERY_FAILED', 'Empty discovery response.');
    const chunks: Uint8Array[] = []; let size = 0;
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.length;
      if (size > 1024 * 1024) { await reader.cancel(); fail('DISCOVERY_FAILED', 'Discovery document is too large.'); }
      chunks.push(part.value);
    }
    metadata = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch (error) {
    if (options.signal?.aborted) throw options.signal.reason;
    if (error instanceof OIDCEmulatorError) throw error;
    return fail('DISCOVERY_FAILED', 'Could not retrieve or parse provider discovery.');
  }
  if (!metadata || metadata.issuer !== issuer || typeof metadata.authorization_endpoint !== 'string') fail('INVALID_METADATA', 'Discovery issuer must exactly match the configured issuer and include an authorization endpoint.');
  providerURL(metadata.authorization_endpoint, !!options.allowInsecureHttp);
  if (metadata.token_endpoint !== undefined) {
    if (typeof metadata.token_endpoint !== 'string') fail('INVALID_METADATA', 'Invalid token endpoint metadata.');
    providerURL(metadata.token_endpoint, !!options.allowInsecureHttp);
  }
  for (const key of ['response_types_supported', 'response_modes_supported', 'code_challenge_methods_supported', 'token_endpoint_auth_methods_supported'] as const) {
    const value = metadata[key];
    if (value !== undefined && (!Array.isArray(value) || !value.every(x => typeof x === 'string'))) fail('INVALID_METADATA', 'Invalid provider capability metadata.');
  }
  if (metadata.response_types_supported && !metadata.response_types_supported.includes('code')) fail('UNSUPPORTED_PROVIDER', 'Provider does not advertise response_type=code.');
  if (metadata.response_modes_supported && !metadata.response_modes_supported.includes('query')) fail('UNSUPPORTED_PROVIDER', 'This version requires query authorization responses.');
  if (metadata.require_pushed_authorization_requests) fail('UNSUPPORTED_PROVIDER', 'Required pushed authorization requests are not supported in this version.');
  options.signal?.throwIfAborted();
  if (discoveryCache.size >= discoveryCacheMaxEntries) discoveryCache.delete(discoveryCache.keys().next().value!);
  discoveryCache.set(cacheKey, { metadata: structuredClone(metadata), expiresAt: Date.now() + discoveryCacheTtlMs });
  return metadata;
}

const responseFields = ['code', 'state', 'iss', 'error', 'error_description', 'error_uri'];
const protectedFields = new Set(['client_id', 'redirect_uri', 'scope', 'response_type', 'response_mode', 'state', 'nonce', 'code_challenge', 'code_challenge_method', 'request', 'request_uri', 'client_secret']);

export function parseResponse(raw: string, expected: { redirectUri: string; state: string; issuer: string; requireIssuer?: boolean }): string | AuthorizationResponseError {
  const actual = new URL(raw), redirect = new URL(expected.redirectUri);
  for (const key of ['protocol', 'hostname', 'port', 'pathname', 'username', 'password'] as const) {
    if (actual[key] !== redirect[key]) fail('INVALID_CALLBACK', 'Callback destination does not match redirectUri.');
  }
  if (actual.hash) fail('INVALID_CALLBACK', 'Fragment authorization responses are unsupported.');
  for (const key of new Set(redirect.searchParams.keys())) {
    if (JSON.stringify(actual.searchParams.getAll(key)) !== JSON.stringify(redirect.searchParams.getAll(key))) fail('INVALID_CALLBACK', 'Callback changed a fixed redirect query parameter.');
  }
  const params = actual.searchParams;
  if (responseFields.some(key => params.getAll(key).length > 1)) fail('INVALID_CALLBACK', 'Duplicate authorization response parameters.');
  if (!equal(params.get('state') ?? '', expected.state)) fail('INVALID_CALLBACK', 'Callback state does not match.');
  const issuer = params.get('iss');
  if ((expected.requireIssuer && issuer === null) || (issuer !== null && issuer !== expected.issuer)) fail('INVALID_CALLBACK', 'Authorization response issuer does not match.');
  if (params.has('error')) {
    if (params.has('code') || !params.get('error')) fail('INVALID_CALLBACK', 'Conflicting authorization response.');
    return new AuthorizationResponseError(params.get('error')!);
  }
  const code = params.get('code');
  if (!code || params.has('error_description') || params.has('error_uri')) fail('INVALID_CALLBACK', 'Missing code or conflicting authorization response.');
  return code;
}

/** Acquire a code with state and optional PKCE; token exchange is deliberately left to the caller. */
export async function authorize(options: AuthorizationOptions): Promise<AuthorizationResult> {
  if (typeof options.clientId !== 'string' || !options.clientId.trim()) fail('INVALID_OPTIONS', 'clientId is required.');
  if (options.pkce !== undefined && typeof options.pkce !== 'boolean') fail('INVALID_OPTIONS', 'pkce must be a boolean.');
  if (options.handleSignals !== undefined && typeof options.handleSignals !== 'boolean') fail('INVALID_OPTIONS', 'handleSignals must be a boolean.');
  const scopes = options.scopes ?? ['openid'];
  if (!Array.isArray(scopes) || !scopes.includes('openid') || scopes.some(scope => typeof scope !== 'string' || !/^[\x21\x23-\x5b\x5d-\x7e]+$/.test(scope))) fail('INVALID_OPTIONS', 'Scopes must contain openid and consist of nonempty OAuth scope tokens.');
  let redirect: URL;
  try { redirect = new URL(options.redirectUri); } catch { return fail('INVALID_OPTIONS', 'redirectUri must be an absolute custom-scheme URL.'); }
  const scheme = redirect.protocol.slice(0, -1);
  validateScheme(scheme);
  if (redirect.username || redirect.password || redirect.hash || responseFields.some(key => redirect.searchParams.has(key))) fail('INVALID_OPTIONS', 'redirectUri cannot contain credentials, a fragment, or reserved response parameters.');
  const mode = options.interception ?? 'managed';
  if (!['managed', 'existing', 'none'].includes(mode)) fail('INVALID_OPTIONS', 'Unknown interception mode.');
  const host = options.callback?.host ?? '127.0.0.1', port = options.callback?.port ?? 0;
  if (!loopback(host)) fail('INVALID_OPTIONS', 'Callback host must be 127.0.0.1 or ::1.');
  validatePort(port);
  if (options.callback?.token !== undefined) validateToken(options.callback.token);
  if (mode === 'none' && !options.callback?.token) fail('INVALID_OPTIONS', 'External relay mode requires a callback token.');
  if (mode === 'none' && port === 0) fail('INVALID_OPTIONS', 'External relay mode requires a fixed callback port.');
  const timeoutMs = options.timeoutMs ?? 300_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 2_147_483_647) fail('INVALID_OPTIONS', 'timeoutMs must be a positive integer within the timer range.');
  for (const [key, value] of Object.entries(options.authorizationParams ?? {})) {
    if (protectedFields.has(key) || typeof value !== 'string') fail('INVALID_OPTIONS', 'Extra authorization parameters cannot override protected protocol fields.');
  }
  const abort = new AbortController();
  const cancel = () => abort.abort(new OIDCEmulatorError('CANCELLED', 'Authorization cancelled.'));
  const removeSignalHandlers = options.handleSignals === false ? () => {} : registerAuthorizationSignals(cancel);
  options.signal?.addEventListener('abort', cancel, { once: true });
  if (options.signal?.aborted) cancel();
  const timer = setTimeout(() => abort.abort(new OIDCEmulatorError('TIMEOUT', 'Authorization timed out.')), timeoutMs);
  const signal = abort.signal;
  const interrupted = new Promise<never>((_, reject) => {
    if (signal.aborted) reject(signal.reason);
    else signal.addEventListener('abort', () => reject(signal.reason), { once: true });
  });
  interrupted.catch(() => {});
  const owner = secret();
  async function run(): Promise<AuthorizationResult> {
    signal.throwIfAborted();
    const provider = await discover(options.issuer, { ...options, signal });
    if (options.pkce !== false && provider.code_challenge_methods_supported && !provider.code_challenge_methods_supported.includes('S256')) fail('UNSUPPORTED_PROVIDER', 'Provider does not advertise PKCE S256; no downgrade is allowed.');
    signal.throwIfAborted();
    let bindHost = host, bindPort = port, token = options.callback?.token ?? secret();
    if (mode === 'existing') {
      const existing = await existingInterception(scheme, options.stateDir);
      const target = new URL(existing.endpoint);
      bindHost = target.hostname.replace(/^\[|\]$/g, ''); bindPort = Number(target.port);
      if ((options.callback?.host !== undefined && host !== bindHost) || (options.callback?.port !== undefined && port !== bindPort) || (options.callback?.token !== undefined && token !== existing.token)) fail('INVALID_OPTIONS', 'Callback configuration must match the persistent interceptor.');
      token = existing.token;
    }
    const state = secret(), codeVerifier = options.pkce !== false ? secret() : undefined, nonce = secret();
    const authURL = new URL(provider.authorization_endpoint);
    for (const [key, value] of Object.entries(options.authorizationParams ?? {})) authURL.searchParams.set(key, value);
    for (const [key, value] of Object.entries({ client_id: options.clientId, redirect_uri: options.redirectUri,
      scope: [...new Set(scopes)].join(' '), response_type: 'code', response_mode: 'query', state, nonce })) authURL.searchParams.set(key, value);
    // Discovery endpoints may carry query parameters; disabled PKCE must omit both fields.
    authURL.searchParams.delete('code_challenge');
    authURL.searchParams.delete('code_challenge_method');
    if (codeVerifier) {
      authURL.searchParams.set('code_challenge', createHash('sha256').update(codeVerifier).digest('base64url'));
      authURL.searchParams.set('code_challenge_method', 'S256');
    }
    const receiver = await listen<string>({ host: bindHost, port: bindPort, token, signal,
      parse: raw => parseResponse(raw, { redirectUri: options.redirectUri, state, issuer: options.issuer,
        requireIssuer: provider.authorization_response_iss_parameter_supported === true }) });
    let owns = false;
    try {
      signal.throwIfAborted();
      if (mode === 'managed') {
        const target = new URL(receiver.endpoint);
        await enable({ scheme, host: bindHost, port: Number(target.port), stateDir: options.stateDir }, owner, token);
        owns = true;
      }
      signal.throwIfAborted();
      if (options.onAuthorizationUrl) await Promise.race([Promise.resolve().then(() => options.onAuthorizationUrl!(authURL.href)), interrupted]);
      const opener = options.openBrowser;
      if (opener !== false) await Promise.race([Promise.resolve().then(() => opener ? opener(authURL.href) : openDefaultBrowser(authURL.href, signal, options.promptBeforeBrowser === true)), interrupted]);
      const code = await receiver.result;
      return { code, ...(codeVerifier ? { codeVerifier } : {}), state, nonce, redirectUri: options.redirectUri, issuer: options.issuer,
        tokenEndpoint: provider.token_endpoint, receivedAt: new Date().toISOString() };
    } finally {
      await receiver.close();
      if (owns) {
        try { await interceptOff({ scheme, stateDir: options.stateDir }, owner); }
        catch { fail('CLEANUP_FAILED', 'Could not restore the scheme handler. Run intercept off to retry recovery.'); }
      }
    }
  }
  try {
    return mode === 'none' ? await run() : await withSchemeLease(scheme, options.stateDir, run);
  } finally {
    clearTimeout(timer);
    removeSignalHandlers();
    options.signal?.removeEventListener('abort', cancel);
  }
}
