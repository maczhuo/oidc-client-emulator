import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, copyFile, writeFile, readFile, rm, access } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, join } from 'node:path';
import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';

const exec = promisify(execFile);
export const root = fileURLToPath(new URL('../', import.meta.url));
export const work = join(root, '.prototype');
const binary = join(work, 'url-helper');
const journal = join(work, 'restore.json');

export async function command(file, args) {
  try { return (await exec(file, args, { timeout: 60_000 })).stdout; }
  catch { throw new Error(`Command failed: ${file.split('/').at(-1)} (arguments suppressed)`); }
}

export async function build() {
  if (process.platform !== 'darwin') throw new Error('This prototype requires macOS');
  await mkdir(work, { recursive: true, mode: 0o700 });
  await command('/usr/bin/xcrun', ['swiftc', '-module-cache-path', join(work, 'module-cache'),
    join(root, 'native/Prototype.swift'), '-o', binary]);
}

export async function status(scheme) {
  if (!/^[a-z][a-z0-9+.-]*$/.test(scheme)) throw new Error('Invalid URL scheme');
  return JSON.parse(await command(binary, ['status', scheme]));
}

export async function setHandler(scheme, path) {
  await command(binary, ['set', scheme, path]);
  if ((await status(scheme)).path !== path) throw new Error('Default handler did not change');
}

export async function makeApp(name, scheme, endpoint, token) {
  if (!/^[a-z][a-z0-9+.-]*$/.test(scheme)) throw new Error('Invalid URL scheme');
  if (!/^[a-z0-9-]+$/.test(name)) throw new Error('Invalid helper name');
  const app = join(work, name + '.app');
  await mkdir(join(app, 'Contents/MacOS'), { recursive: true, mode: 0o700 });
  await mkdir(join(app, 'Contents/Resources'), { recursive: true, mode: 0o700 });
  await copyFile(binary, join(app, 'Contents/MacOS/url-helper'));
  await writeFile(join(app, 'Contents/Info.plist'), `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>url-helper</string>
<key>CFBundleIdentifier</key><string>dev.oidc-emulator.prototype.${name}</string>
<key>CFBundleName</key><string>OIDC Prototype ${name}</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>LSUIElement</key><true/>
<key>CFBundleURLTypes</key><array><dict><key>CFBundleURLSchemes</key><array><string>${scheme}</string></array></dict></array>
</dict></plist>`);
  await writeFile(join(app, 'Contents/Resources/forwarding.json'), JSON.stringify({ endpoint, token }), { mode: 0o600 });
  await command('/usr/bin/codesign', ['--force', '--sign', '-', app]);
  return app;
}

export async function takeover(scheme, app) {
  const previous = await status(scheme);
  if (!previous.path) throw new Error('Prototype requires a previous handler so restoration can be verified');
  // Exclusive creation protects the recovery journal from overlapping invocations.
  await writeFile(journal, JSON.stringify({ scheme, previous, app }), { flag: 'wx', mode: 0o600 });
  await setHandler(scheme, app);
}

export async function restore() {
  let saved;
  try { saved = JSON.parse(await readFile(journal, 'utf8')); }
  catch (error) { if (error.code === 'ENOENT') return; throw error; }
  const current = await status(saved.scheme);
  if (current.path === saved.app) {
    await access(saved.previous.path);
    await setHandler(saved.scheme, saved.previous.path);
  }
  await rm(journal);
}

export async function receiver(onURL, { timeoutMs = 300_000, signal } = {}) {
  const token = randomBytes(32).toString('base64url');
  let settle, reject, timer;
  let completed = false;
  const result = new Promise((res, rej) => { settle = res; reject = rej; });
  // A browser or native helper can fail before the caller starts awaiting result.
  result.catch(() => {});
  const abort = () => finish(new Error('Authorization cancelled'));
  function finish(error, value) {
    if (completed) return;
    completed = true;
    clearTimeout(timer);
    signal?.removeEventListener('abort', abort);
    if (error) reject(error); else settle(value);
  }
  const server = createServer(async (req, res) => {
    const auth = Buffer.from(req.headers.authorization ?? '');
    const expected = Buffer.from(`Bearer ${token}`);
    if (req.method !== 'POST' || req.url !== '/callback' || auth.length !== expected.length || !timingSafeEqual(auth, expected)) {
      res.writeHead(403).end(); return;
    }
    if (completed) { res.writeHead(409).end(); return; }
    try {
      const chunks = []; let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 16384) { res.writeHead(413).end(); return; }
        chunks.push(chunk);
      }
      const { url } = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (typeof url !== 'string') throw new Error('Missing URL');
      const value = onURL(url);
      res.writeHead(204).end();
      if (value !== undefined) finish(null, value);
    } catch { res.writeHead(400).end(); }
  });
  server.requestTimeout = 10_000;
  server.headersTimeout = 10_000;
  await new Promise((res, rej) => { server.once('error', rej); server.listen(0, '127.0.0.1', res); });
  timer = setTimeout(() => finish(new Error('Authorization timed out')), timeoutMs);
  signal?.addEventListener('abort', abort, { once: true });
  if (signal?.aborted) abort();
  return {
    token, endpoint: `http://127.0.0.1:${server.address().port}/callback`, result,
    async close() {
      finish(new Error('Receiver closed'));
      server.closeAllConnections();
      await new Promise(res => server.close(res));
    },
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    await build();
    if (process.argv[2] === 'restore') { await restore(); console.log('Restoration complete'); }
    else console.log(JSON.stringify(await status(process.argv[2] ?? 'com.example.app')));
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
