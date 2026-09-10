import { mkdir } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

if (process.platform !== 'darwin') throw new Error('Native compilation requires macOS and Xcode Command Line Tools.');
const exec = promisify(execFile);
const root = fileURLToPath(new URL('../', import.meta.url));
const output = join(root, '.prototype/native-check');
await mkdir(output, { recursive: true });
for (const arch of ['arm64', 'x86_64']) {
  await exec('/usr/bin/xcrun', ['swiftc', '-module-cache-path', join(output, `cache-${arch}`),
    '-target', `${arch}-apple-macosx12.0`, join(root, 'native/URLHelper.swift'),
    '-o', join(output, `url-helper-${arch}`)], { timeout: 120_000 });
  console.log(`PASS: native helper compiles for ${arch} (macOS 12 deployment target)`);
}
