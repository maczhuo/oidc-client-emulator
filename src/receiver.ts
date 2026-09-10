import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { equal, fail, loopback, validatePort, validateToken } from './util.js';

export interface ReceiverOptions<T> {
  host: string;
  port: number;
  token: string;
  signal: AbortSignal;
  parse: (url: string) => T | Error;
}

/** Internal authenticated relay. Invalid traffic cannot settle a transaction. */
export async function listen<T>({ host, port, token, signal, parse }: ReceiverOptions<T>) {
  if (!loopback(host)) fail('INVALID_OPTIONS', 'The callback listener must bind to 127.0.0.1 or ::1.');
  validatePort(port); validateToken(token);
  signal.throwIfAborted();
  let resolve!: (value: T) => void, reject!: (error: unknown) => void;
  let done = false;
  const result = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  result.catch(() => {});
  function finish(value: T | Error) {
    if (done) return;
    done = true;
    if (value instanceof Error) reject(value); else resolve(value);
  }
  const aborted = () => finish(signal.reason instanceof Error ? signal.reason : new Error('Cancelled'));
  const server = createServer(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    if (req.method !== 'POST' || req.url !== '/callback' || !equal(req.headers.authorization ?? '', `Bearer ${token}`)) {
      res.writeHead(403).end(); return;
    }
    if (req.headers['content-type']?.split(';')[0] !== 'application/json') { res.writeHead(415).end(); return; }
    if (done) { res.writeHead(409).end(); return; }
    try {
      const chunks: Buffer[] = []; let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 16384) { res.writeHead(413, { Connection: 'close' }).end(); return; }
        chunks.push(chunk);
      }
      // A second request may have completed while this request body was arriving.
      if (done) { res.writeHead(409).end(); return; }
      const body: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (!body || typeof body !== 'object' || !('url' in body) || typeof body.url !== 'string') throw new Error();
      const value = parse(body.url);
      res.writeHead(204).end();
      finish(value);
    } catch { res.writeHead(400).end(); }
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 10_000;
  server.setTimeout(10_000, socket => socket.destroy());
  await new Promise<void>((yes, no) => {
    const error = () => no(new Error('Could not bind callback host/port.'));
    server.once('error', error);
    server.listen(port, host, () => { server.off('error', error); yes(); });
  });
  server.on('error', () => finish(new Error('Callback listener failed.')));
  signal.addEventListener('abort', aborted, { once: true });
  if (signal.aborted) aborted();
  const endpoint = `http://${host === '::1' ? '[::1]' : host}:${(server.address() as AddressInfo).port}/callback`;
  let closing: Promise<void> | undefined;
  return {
    result, endpoint,
    close(): Promise<void> {
      if (closing) return closing;
      signal.removeEventListener('abort', aborted);
      finish(new Error('Callback receiver closed.'));
      closing = new Promise(yes => {
        server.close(() => yes());
        server.closeAllConnections();
      });
      return closing;
    },
  };
}
