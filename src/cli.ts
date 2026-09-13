#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { authorize, interceptOff, interceptOn, interceptStatus, OIDCEmulatorError } from './index.js';

const help = `oidc-client-emulator

  authorize --issuer URL --client-id ID --redirect-uri URI [--scope "openid email"]
    [--host 127.0.0.1] [--port 0] [--timeout-ms 300000]
    [--intercept managed|existing|none] [--no-open] [--json]
    [--discovery-url URL] [--param name=value] [--state-dir PATH]
  daemon [--host 127.0.0.1] [--port 43187] [--state-dir PATH]
  intercept on --scheme SCHEME --port PORT [--host 127.0.0.1] [--state-dir PATH]
  intercept off --scheme SCHEME [--state-dir PATH]
  intercept status --scheme SCHEME [--state-dir PATH]

Managed mode temporarily takes over the scheme and restores it after the attempt.
Existing mode uses an interceptor enabled with 'intercept on'. External relay mode
(none) reads OIDC_CALLBACK_TOKEN from the environment and requires a fixed port.
Results go to stdout. Progress goes to stderr. --no-open prints the authorization
URL to stderr for manual use. macOS interception requires Xcode Command Line Tools.
Daemon mode requires OIDC_DAEMON_TOKEN (32–256 base64url characters) and accepts
authenticated POST /login, GET /login/:jobId, DELETE /login/:jobId, and GET /health.
`;

try {
  const { values, positionals } = parseArgs({ allowPositionals: true, strict: true, options: {
    help: { type: 'boolean', short: 'h' }, json: { type: 'boolean' }, 'no-open': { type: 'boolean' },
    issuer: { type: 'string' }, 'client-id': { type: 'string' }, 'redirect-uri': { type: 'string' },
    'discovery-url': { type: 'string' }, scope: { type: 'string', multiple: true }, scheme: { type: 'string' },
    host: { type: 'string' }, port: { type: 'string' }, 'timeout-ms': { type: 'string' },
    intercept: { type: 'string' }, param: { type: 'string', multiple: true }, 'state-dir': { type: 'string' },
  } });
  const required = (name: 'issuer' | 'client-id' | 'redirect-uri' | 'scheme') => {
    const value = values[name];
    if (!value) throw new OIDCEmulatorError('INVALID_OPTIONS', `--${name} is required.`);
    return value;
  };
  const numeric = (value: string | undefined, fallback: number) => value === undefined ? fallback : /^\d+$/.test(value) ? Number(value) : NaN;
  if (values.help || !positionals.length) { console.log(help); }
  else if (positionals[0] === 'daemon' && positionals.length === 1) {
    if (Object.keys(values).some(key => !['host', 'port', 'state-dir'].includes(key))) {
      throw new OIDCEmulatorError('INVALID_OPTIONS', 'Daemon options are --host, --port, and --state-dir; send OIDC parameters in POST /login.');
    }
    const token = process.env.OIDC_DAEMON_TOKEN;
    if (!token) throw new OIDCEmulatorError('INVALID_OPTIONS', 'Set OIDC_DAEMON_TOKEN before starting the daemon.');
    const { startDaemon } = await import('./daemon/server.js');
    const daemon = await startDaemon({ token, host: values.host, port: numeric(values.port, 43187), stateDir: values['state-dir'] });
    const address = daemon.server.address();
    console.error(`OIDC daemon listening on http://${values.host === '::1' ? '[::1]' : '127.0.0.1'}:${typeof address === 'object' && address ? address.port : 43187}`);
    await new Promise<void>((resolve, reject) => {
      const stop = () => {
        daemon.close().then(resolve, reject).finally(() => {
          process.off('SIGINT', stop); process.off('SIGTERM', stop);
        });
      };
      process.on('SIGINT', stop); process.on('SIGTERM', stop);
    });
  }
  else if (positionals[0] === 'intercept' && positionals.length === 2) {
    const options = { scheme: required('scheme'), stateDir: values['state-dir'] };
    switch (positionals[1]) {
      case 'on': console.log(JSON.stringify(await interceptOn({ ...options, host: values.host, port: numeric(values.port, 0) }))); break;
      case 'off': await interceptOff(options); console.log(JSON.stringify({ scheme: options.scheme, enabled: false })); break;
      case 'status': console.log(JSON.stringify(await interceptStatus(options))); break;
      default: throw new OIDCEmulatorError('INVALID_OPTIONS', 'Use intercept on, off, or status.');
    }
  } else if (positionals[0] === 'authorize' && positionals.length === 1) {
    const params: Record<string, string> = {};
    for (const item of values.param ?? []) {
      const split = item.indexOf('=');
      if (split < 1) throw new OIDCEmulatorError('INVALID_OPTIONS', '--param expects name=value.');
      params[item.slice(0, split)] = item.slice(split + 1);
    }
    const controller = new AbortController();
    const stop = () => controller.abort();
    process.once('SIGINT', stop); process.once('SIGTERM', stop);
    try {
      console.error('Preparing authorization. Complete sign-in in your browser when it opens.');
      const result = await authorize({
        issuer: required('issuer'), clientId: required('client-id'), redirectUri: required('redirect-uri'),
        discoveryUrl: values['discovery-url'], scopes: values.scope?.flatMap(value => value.split(/\s+/).filter(Boolean)),
        callback: { host: values.host, port: values.port === undefined ? undefined : numeric(values.port, 0),
          token: values.intercept === 'none' ? process.env.OIDC_CALLBACK_TOKEN : undefined },
        timeoutMs: numeric(values['timeout-ms'], 300_000), stateDir: values['state-dir'],
        interception: (values.intercept ?? 'managed') as 'managed' | 'existing' | 'none',
        authorizationParams: params, signal: controller.signal,
        openBrowser: values['no-open'] ? false : undefined,
        onAuthorizationUrl: values['no-open'] ? url => { console.error(url); } : undefined,
      });
      // This is the requested result, never a diagnostic log. PKCE redemption needs the verifier.
      console.log(JSON.stringify(result, null, values.json ? undefined : 2));
    } finally { process.off('SIGINT', stop); process.off('SIGTERM', stop); }
  } else { throw new OIDCEmulatorError('INVALID_OPTIONS', 'Unknown command. Use --help.'); }
} catch (error) {
  if (error instanceof OIDCEmulatorError) {
    console.error(`${error.code}: ${error.message}`);
    process.exitCode = error.code === 'CANCELLED' ? 130 : 1;
  } else {
    console.error('Operation failed. Check the command options and local environment.');
    process.exitCode = 1;
  }
}
