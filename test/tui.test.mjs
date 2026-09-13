import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { DaemonTUI } from '../dist/daemon/tui.js';

function fixture() {
  const input = new PassThrough();
  input.isRaw = false;
  input.setRawMode = value => { input.isRaw = value; };
  const output = new PassThrough();
  output.columns = 100; output.rows = 24;
  let text = '';
  output.on('data', chunk => { text += chunk; });
  let cancelled, quit = 0;
  const tui = new DaemonTUI('http://127.0.0.1:43187', 'test-token', id => { cancelled = id; }, () => quit++, input, output);
  return { input, output, tui, text: () => text, cancelled: () => cancelled, quit: () => quit };
}
const event = { jobId: 'job-123', status: 'pending', startedAt: Date.now(), timeoutMs: 300000,
  issuer: 'https://example.com', clientId: 'client', redirectUri: 'example:/callback', message: 'ready: press Enter' };

test('TUI keeps the prompt visible across events and resize, handles keys, and restores terminal', async () => {
  const f = fixture();
  f.tui.start();
  try {
    f.tui.event(event);
    const wait = f.tui.waitForEnter(event.jobId, new AbortController().signal);
    for (let i = 0; i < 120; i++) f.tui.event({ ...event, message: `event ${i}` });
    const screen = f.text().split('\x1b[2J').at(-1);
    assert.match(screen, /Press Enter to open browser/);
    assert.match(screen, /Authorization: Bearer test-token/);
    f.output.columns = 40; f.output.rows = 8; f.output.emit('resize');
    assert.match(f.text().split('\x1b[2J').at(-1), /Press Enter/);
    f.input.emit('keypress', '', { name: 'return' });
    await wait;
    f.input.emit('keypress', 'c', { name: 'c' });
    assert.equal(f.cancelled(), event.jobId);
    f.input.emit('keypress', '', { name: 'up' });
    f.input.emit('keypress', '', { name: 'down' });
    f.input.emit('keypress', 'q', { name: 'q' });
    f.input.emit('keypress', 'q', { name: 'q' });
    assert.equal(f.quit(), 1);
  } finally { f.tui.stop(); }
  assert.equal(f.input.isRaw, false);
  assert.match(f.text(), /\x1b\[\?25h\x1b\[\?1049l$/);
});

test('TUI releases pending prompt on cancellation or timeout and strips terminal escapes', async () => {
  const f = fixture(); f.tui.start();
  try {
    const controller = new AbortController();
    const waiting = f.tui.waitForEnter(event.jobId, controller.signal);
    const rejected = assert.rejects(waiting, { code: 'CANCELLED' });
    controller.abort(); await rejected;
    f.tui.event({ ...event, clientId: '\x1b[2Jmalicious\ntext' });
    const timeout = f.tui.waitForEnter(event.jobId, new AbortController().signal);
    const expired = assert.rejects(timeout, { code: 'CANCELLED' });
    f.tui.event({ ...event, status: 'failed', message: 'TIMEOUT' });
    await expired;
    const screen = f.text().split('\x1b[2J').at(-1);
    assert.doesNotMatch(screen, /Press Enter to open browser/);
    assert.match(screen, /failed/);
  } finally { f.tui.stop(); }
});
