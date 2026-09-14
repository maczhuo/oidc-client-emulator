import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { createInterface } from 'node:readline';
import { OIDCEmulatorError } from './errors.js';

const execute = promisify(execFile);
export const secret = () => randomBytes(32).toString('base64url');
export function equal(a: string, b: string): boolean {
  const left = Buffer.from(a), right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}
export function fail(code: string, message: string): never { throw new OIDCEmulatorError(code, message); }
export function loopback(host: string): boolean { return host === '127.0.0.1' || host === '::1'; }
export function validatePort(port: number): void {
  if (!Number.isInteger(port) || port < 0 || port > 65535) fail('INVALID_OPTIONS', 'Port must be an integer from 0 to 65535.');
}
export function validateToken(token: string): void {
  if (!/^[A-Za-z0-9_-]{32,256}$/.test(token)) fail('INVALID_OPTIONS', 'Callback token must be 32–256 base64url characters.');
}
export function validateScheme(scheme: string): void {
  if (!/^[a-z][a-z0-9+.-]{1,127}$/.test(scheme) || ['http', 'https', 'file', 'mailto', 'tel', 'data', 'javascript'].includes(scheme)) {
    fail('INVALID_OPTIONS', 'Specify a private custom URL scheme.');
  }
}
export async function command(file: string, args: string[]): Promise<string> {
  try { return (await execute(file, args, { timeout: 60_000, maxBuffer: 1024 * 1024 })).stdout; }
  catch { return fail('NATIVE_COMMAND_FAILED', `${file.split('/').at(-1)} failed. Check macOS consent and Xcode Command Line Tools; arguments are suppressed.`); }
}
export async function openDefaultBrowser(url: string, signal?: AbortSignal, prompt = false): Promise<void> {
  if (process.platform !== 'darwin') fail('UNSUPPORTED_PLATFORM', 'Default browser opening requires macOS; inject openBrowser on other platforms.');
  signal?.throwIfAborted();
  if (!prompt) { await command('/usr/bin/open', [url]); return; }
  const input = createInterface({ input: process.stdin, output: process.stderr });
  const cancel = () => input.close();
  try {
    await new Promise<void>((resolve, reject) => {
      input.once('line', () => resolve());
      input.once('close', () => reject(signal?.reason ?? new OIDCEmulatorError('CANCELLED', 'Input closed before browser opening.')));
      input.once('SIGINT', () => reject(new OIDCEmulatorError('CANCELLED', 'Authorization cancelled.')));
      signal?.addEventListener('abort', cancel, { once: true });
      process.stderr.write('Press Enter to open your default browser.\n');
    });
  } finally {
    signal?.removeEventListener('abort', cancel);
    input.close();
  }
  signal?.throwIfAborted();
  await command('/usr/bin/open', [url]);
}
