import { access, chmod, copyFile, mkdir, open, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { command, fail, loopback, secret, validatePort, validateScheme, validateToken } from './util.js';

export interface InterceptOptions {
  scheme: string;
  host?: string;
  port: number;
  stateDir?: string;
}
export interface Handler { path: string | null; bundleId: string | null; }
interface RecordState {
  version: 1;
  scheme: string;
  previous: Handler;
  app: string;
  endpoint: string;
  token: string;
  owner?: string;
}
export interface InterceptStatus {
  scheme: string;
  enabled: boolean;
  recoveryPending: boolean;
  endpoint?: string;
  current: Handler;
  previous?: Handler;
}

export function stateDirectory(custom?: string): string {
  return resolve(custom ?? join(homedir(), 'Library/Application Support/oidc-client-emulator'));
}
const lsregister = '/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister';

async function locked<T>(root: string, name: string, action: () => Promise<T>): Promise<T> {
  await mkdir(root, { recursive: true, mode: 0o700 });
  const path = join(root, `${name}.lock`);
  let handle;
  for (let attempt = 0; attempt < 2; attempt++) {
    try { handle = await open(path, 'wx', 0o600); break; }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      // Serialize stale-lock removal so two recoverers cannot delete each other's
      // newly acquired lock. Re-read ownership only after acquiring this guard.
      let recovery;
      try { recovery = await open(`${path}.recovery`, 'wx', 0o600); }
      catch { fail('BUSY', 'Another operation owns or is recovering this lock.'); }
      try {
        let pid = 0;
        try { pid = JSON.parse(await readFile(path, 'utf8')).pid; }
        catch (e) { if ((e as NodeJS.ErrnoException).code === 'ENOENT') continue; }
        let alive = true;
        if (Number.isSafeInteger(pid) && pid > 0) {
          try { process.kill(pid, 0); } catch (e) { alive = (e as NodeJS.ErrnoException).code !== 'ESRCH'; }
        } else {
          try { alive = Date.now() - (await stat(path)).mtimeMs < 60_000; }
          catch (e) { if ((e as NodeJS.ErrnoException).code === 'ENOENT') continue; throw e; }
        }
        if (alive || attempt) fail('BUSY', 'Another operation owns this lock; wait for it to finish.');
        await rm(path, { force: true });
      } finally { await recovery.close(); await rm(`${path}.recovery`, { force: true }); }
    }
  }
  if (!handle) return fail('BUSY', 'Could not acquire operation lock.');
  try {
    await handle.writeFile(JSON.stringify({ pid: process.pid }));
    return await action();
  } finally { await handle.close(); await rm(path, { force: true }); }
}

async function native(root: string): Promise<string> {
  if (process.platform !== 'darwin') fail('UNSUPPORTED_PLATFORM', 'URL scheme interception requires macOS.');
  const source = fileURLToPath(new URL('../native/URLHelper.swift', import.meta.url));
  const hash = createHash('sha256').update(await readFile(source)).digest('hex').slice(0, 16);
  const binary = join(root, `helper-${hash}-${process.arch}`);
  try { await access(binary); return binary; } catch { /* compile once per source version */ }
  return locked(root, 'build', async () => {
    try { await access(binary); return binary; } catch { /* not built */ }
    const temp = `${binary}.${process.pid}`;
    const cache = join(root, 'module-cache');
    try {
      await command('/usr/bin/xcrun', ['swiftc', '-module-cache-path', cache, '-target',
        `${process.arch === 'arm64' ? 'arm64' : 'x86_64'}-apple-macosx12.0`, source, '-o', temp]);
      await rename(temp, binary);
      return binary;
    } finally { await rm(temp, { force: true }); }
  });
}

async function current(binary: string, scheme: string): Promise<Handler> {
  return JSON.parse(await command(binary, ['status', scheme]));
}
async function set(binary: string, scheme: string, app: string) {
  await command(binary, ['set', scheme, app]);
  if ((await current(binary, scheme)).path !== app) fail('HANDLER_CHANGE_FAILED', 'macOS did not select the requested handler.');
}
const recordPath = (root: string, scheme: string) => join(root, scheme, 'state.json');
async function record(root: string, scheme: string): Promise<RecordState | undefined> {
  try { return JSON.parse(await readFile(recordPath(root, scheme), 'utf8')); }
  catch (e) { if ((e as NodeJS.ErrnoException).code === 'ENOENT') return; throw e; }
}

async function install(binary: string, saved: RecordState) {
  const contents = join(saved.app, 'Contents');
  await mkdir(join(contents, 'MacOS'), { recursive: true, mode: 0o700 });
  await mkdir(join(contents, 'Resources'), { recursive: true, mode: 0o700 });
  await copyFile(binary, join(contents, 'MacOS/url-helper'));
  await chmod(join(contents, 'MacOS/url-helper'), 0o700);
  const id = createHash('sha256').update(saved.app).digest('hex').slice(0, 24);
  await writeFile(join(contents, 'Info.plist'), `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>url-helper</string>
<key>CFBundleIdentifier</key><string>dev.oidc-client-emulator.${id}</string>
<key>CFBundleName</key><string>OIDC Client Emulator</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>LSUIElement</key><true/>
<key>CFBundleURLTypes</key><array><dict><key>CFBundleURLSchemes</key><array><string>${saved.scheme}</string></array></dict></array>
</dict></plist>`);
  await writeFile(join(contents, 'Resources/forwarding.json'), JSON.stringify({ endpoint: saved.endpoint, token: saved.token }), { mode: 0o600 });
  await command('/usr/bin/codesign', ['--force', '--sign', '-', saved.app]);
}

async function disable(root: string, binary: string, saved: RecordState) {
  // Stop forwarding even if the previous application was removed or consent is denied.
  await rm(join(saved.app, 'Contents/Resources/forwarding.json'), { force: true });
  await command(binary, ['stop', saved.app]);
  const handler = await current(binary, saved.scheme);
  if (handler.path === saved.app && saved.previous.path) {
    try { await access(saved.previous.path); }
    catch { fail('RESTORE_FAILED', 'The previous application is missing. Forwarding is disabled; recovery state is retained.'); }
    await set(binary, saved.scheme, saved.previous.path);
  }
  // lsregister is a macOS system utility; this behavior is covered by real-macOS tests.
  try { await access(saved.app); await command(lsregister, ['-u', saved.app]); }
  catch (e) { if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e; }
  await rm(saved.app, { recursive: true, force: true });
  const after = await current(binary, saved.scheme);
  if (after.path === saved.app) fail('RESTORE_FAILED', 'macOS still resolves the disabled helper; recovery state is retained.');
  await rm(recordPath(root, saved.scheme), { force: true });
}

/** Enable persistent forwarding. Repeating an identical request is idempotent. */
export async function interceptOn(options: InterceptOptions): Promise<InterceptStatus> {
  await enable(options);
  return interceptStatus(options);
}

export async function enable(options: InterceptOptions, owner?: string, token = secret()): Promise<RecordState> {
  const { scheme, port } = options, host = options.host ?? '127.0.0.1';
  validateScheme(scheme); validatePort(port); validateToken(token);
  if (!loopback(host) || port === 0) fail('INVALID_OPTIONS', 'Forwarding requires a loopback host and a nonzero destination port.');
  const root = stateDirectory(options.stateDir);
  const binary = await native(root);
  return locked(root, scheme, async () => {
    const endpoint = `http://${host === '::1' ? '[::1]' : host}:${port}/callback`;
    const existing = await record(root, scheme);
    if (existing) {
      let configured = false;
      try { await access(join(existing.app, 'Contents/Resources/forwarding.json')); configured = true; } catch { /* pending recovery */ }
      if (!owner && !existing.owner && configured && existing.endpoint === endpoint && (await current(binary, scheme)).path === existing.app) return existing;
      fail('ALREADY_ENABLED', 'This scheme already has saved interception state. Use existing mode or run intercept off first.');
    }
    const previous = await current(binary, scheme);
    const saved: RecordState = { version: 1, scheme, previous, app: join(root, scheme, 'Handler.app'), endpoint, token, owner };
    await mkdir(dirname(recordPath(root, scheme)), { recursive: true, mode: 0o700 });
    // Journal is durable before creating an app that Launch Services may discover.
    const file = await open(recordPath(root, scheme), 'wx', 0o600);
    try { await file.writeFile(JSON.stringify(saved)); await file.sync(); } finally { await file.close(); }
    try { await install(binary, saved); await set(binary, scheme, saved.app); }
    catch (error) {
      try { await disable(root, binary, saved); }
      catch { fail('RESTORE_FAILED', 'Handler setup failed and needs recovery. Run intercept off to retry cleanup.'); }
      throw error;
    }
    return saved;
  });
}

/** Disable forwarding and restore the previous handler if this helper still owns the scheme. */
export async function interceptOff(options: { scheme: string; stateDir?: string }, owner?: string): Promise<void> {
  validateScheme(options.scheme);
  const root = stateDirectory(options.stateDir), binary = await native(root);
  await locked(root, options.scheme, async () => {
    const saved = await record(root, options.scheme);
    if (!saved || (owner && saved.owner !== owner)) return;
    await disable(root, binary, saved);
  });
}

export async function interceptStatus(options: { scheme: string; stateDir?: string }): Promise<InterceptStatus> {
  validateScheme(options.scheme);
  const root = stateDirectory(options.stateDir), binary = await native(root);
  const saved = await record(root, options.scheme), handler = await current(binary, options.scheme);
  let configured = false;
  if (saved) { try { await access(join(saved.app, 'Contents/Resources/forwarding.json')); configured = true; } catch { /* disabled */ } }
  return { scheme: options.scheme, enabled: !!saved && configured && handler.path === saved.app,
    recoveryPending: !!saved && (!configured || handler.path !== saved.app),
    endpoint: saved?.endpoint, current: handler, previous: saved?.previous };
}

export async function existingInterception(scheme: string, stateDir?: string): Promise<RecordState> {
  const root = stateDirectory(stateDir);
  const saved = await record(root, scheme);
  if (!saved || saved.owner || !(await interceptStatus({ scheme, stateDir })).enabled) {
    fail('NOT_ENABLED', 'Enable persistent interception first, or use managed mode.');
  }
  return saved;
}

/** Held for the full transaction, independent of short-lived configuration locks. */
export async function withSchemeLease<T>(scheme: string, stateDir: string | undefined, action: () => Promise<T>): Promise<T> {
  validateScheme(scheme);
  return locked(stateDirectory(stateDir), `${scheme}.session`, action);
}
