import assert from 'node:assert/strict';
import { rm } from 'node:fs/promises';
import { build, command, makeApp, receiver, restore, setHandler, status, takeover } from './prototype.mjs';

const id = Date.now().toString(36);
const scheme = `dev.oidc-emulator.test-${id}`;
const urls = [
  `${scheme}://callback?code=a%2Bb%2fc%3D&state=x+y&repeat=1&repeat=2#fragment%20value`,
  `${scheme}://callback?code=warm&state=%E2%9C%93`,
];
const seen = [];
const apps = [];
let server;
try {
  await build();
  assert.equal((await status(scheme)).path, null);
  server = await receiver(url => {
    assert.equal(url, urls[seen.length]);
    seen.push(url);
    if (seen.length === urls.length) return true;
  }, { timeoutMs: 30_000 });
  const original = await makeApp(`original-${id}`, scheme, server.endpoint, server.token);
  apps.push(original);
  await setHandler(scheme, original);
  const interceptor = await makeApp(`interceptor-${id}`, scheme, server.endpoint, server.token);
  apps.push(interceptor);
  await takeover(scheme, interceptor);
  for (const url of urls) {
    await command('/usr/bin/open', [url]);
    // Let the first URL launch the app before delivering the warm-launch URL.
    const target = urls.indexOf(url) + 1;
    const deadline = Date.now() + 10_000;
    while (seen.length < target && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    assert.equal(seen.length, target, 'Native delivery timed out');
  }
  await server.result;
  await restore();
  assert.equal((await status(scheme)).path, original);
  console.log('PASS: takeover, cold/warm URL delivery, exact payload preservation, and restoration');
} finally {
  await restore();
  await server?.close();
  for (const app of apps.reverse()) {
    await command('/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister', ['-u', app]);
    await rm(app, { recursive: true, force: true });
  }
  assert.equal((await status(scheme)).path, null);
  console.log('PASS: unregistering and removing test apps restores an unhandled scheme');
}
