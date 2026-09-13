import express, { type ErrorRequestHandler } from 'express';
import { createServer } from 'node:http';
import { equal, fail, loopback, validatePort, validateToken } from '../util.js';
import { OIDCEmulatorError } from '../errors.js';
import { LoginJobs } from './jobs.js';
import { loginRoutes } from './routes.js';

export function createDaemonApp(token: string, jobs: LoginJobs) {
  validateToken(token);
  const app = express();
  app.disable('x-powered-by');
  app.disable('etag');
  app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    if (req.headers.origin !== undefined) { res.status(403).json({ error: { code: 'ORIGIN_REJECTED', message: 'Browser-origin requests are not supported.' } }); return; }
    if (!equal(req.headers.authorization ?? '', `Bearer ${token}`)) {
      res.set('WWW-Authenticate', 'Bearer').status(401).json({ error: { code: 'UNAUTHORIZED', message: 'A valid daemon bearer token is required.' } }); return;
    }
    next();
  });
  app.use(express.json({ limit: '16kb' }));
  app.get('/health', (_req, res) => { res.json({ status: 'ok' }); });
  app.use('/login', loginRoutes(jobs));
  app.use((_req, res) => { res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Endpoint not found.' } }); });
  const errors: ErrorRequestHandler = (error, _req, res, _next) => {
    if (error instanceof OIDCEmulatorError) {
      res.status(error.code === 'BUSY' ? 409 : error.code === 'STOPPING' ? 503 : 400).json({ error: { code: error.code, message: error.message } });
    } else {
      const status = error?.status === 413 ? 413 : error?.status === 400 ? 400 : 500;
      res.status(status).json({ error: { code: status === 500 ? 'INTERNAL_ERROR' : 'INVALID_BODY', message: status === 500 ? 'Request failed.' : 'Invalid or oversized JSON body.' } });
    }
  };
  app.use(errors);
  return app;
}

export async function startDaemon(options: { token: string; host?: string; port?: number; stateDir?: string }) {
  const host = options.host ?? '127.0.0.1', port = options.port ?? 43187;
  if (!loopback(host)) fail('INVALID_OPTIONS', 'Daemon host must be 127.0.0.1 or ::1.');
  validatePort(port);
  const jobs = new LoginJobs(undefined, options.stateDir);
  const server = createServer(createDaemonApp(options.token, jobs));
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => { server.off('error', reject); resolve(); });
  });
  let closing: Promise<void> | undefined;
  return { server, close: () => closing ??= (async () => {
    const closed = new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    server.closeIdleConnections();
    await Promise.all([jobs.close(), closed]);
  })() };
}
