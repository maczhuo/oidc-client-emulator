import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import xterm from '@xterm/headless';
import { DaemonTUI } from '../dist/daemon/tui.js';

process.env.TERM = 'xterm-256color';

function fixture() {
  const input = new PassThrough();
  input.isRaw = false; input.isTTY = true;
  input.ref = input.unref = () => input;
  input.setRawMode = value => { input.isRaw = value; };
  const output = new PassThrough();
  output.isTTY = true; output.columns = 100; output.rows = 24;
  const terminal = new xterm.Terminal({ cols: 100, rows: 24, allowProposedApi: true, convertEol: true });
  let text = '';
  output.on('data', chunk => { text += chunk; terminal.write(chunk.toString()); });
  let cancelled, quit = 0;
  const tui = new DaemonTUI('http://127.0.0.1:43187', 'test-token', id => { cancelled = id; }, () => quit++, input, output);
  const flush = async () => {
    await new Promise(resolve => setImmediate(resolve));
    await tui.instance.waitUntilRenderFlush();
    await new Promise(resolve => terminal.write('', resolve));
  };
  return {
    input, output, tui, terminal, flush, text: () => text,
    screen: () => Array.from({ length: terminal.rows }, (_, i) => terminal.buffer.active.getLine(i)?.translateToString(true) ?? '').join('\n'),
    key: async sequence => { input.write(sequence); await flush(); },
    cancelled: () => cancelled, quit: () => quit,
    stop: async () => { tui.stop(); await tui.instance.waitUntilExit(); terminal.dispose(); },
  };
}
const event = { jobId: 'job-123', status: 'pending', startedAt: Date.now(), timeoutMs: 300000,
  issuer: 'https://example.com', clientId: 'client', redirectUri: 'example:/callback', message: 'ready: press Enter' };

test('Ink keeps prompt visible through events and resize, handles actions and restores terminal', async () => {
  const f = fixture(); f.tui.start();
  try {
    f.tui.event(event);
    const wait = f.tui.waitForEnter(event.jobId, new AbortController().signal);
    void wait.catch(() => {});
    for (let i = 0; i < 120; i++) f.tui.event({ ...event, message: `event ${i}` });
    await f.flush();
    assert.match(f.screen(), /Press Enter to open browser/);
    assert.match(f.screen(), /Authorization: Bearer test-token/);
    f.output.columns = 40; f.output.rows = 8; f.terminal.resize(40, 8); f.output.emit('resize');
    await f.flush();
    assert.match(f.screen(), /Press Enter/);
    await f.key('\r'); await wait;
    await f.key('c'); assert.equal(f.cancelled(), event.jobId);
    await f.key('q'); await f.key('q'); assert.equal(f.quit(), 1);
  } finally { await f.stop(); }
  assert.equal(f.input.isRaw, false);
  assert.match(f.text(), /\x1b\[\?25h/);
  assert.match(f.text(), /\x1b\[\?1049l/);
});

test('Ink releases prompts on cancellation, failure and shutdown and sanitizes external text', async () => {
  const f = fixture(); f.tui.start();
  try {
    const controller = new AbortController();
    const rejected = assert.rejects(f.tui.waitForEnter(event.jobId, controller.signal), { code: 'CANCELLED' });
    controller.abort(); await rejected;
    const expired = assert.rejects(f.tui.waitForEnter(event.jobId, new AbortController().signal), { code: 'CANCELLED' });
    f.tui.event({ ...event, status: 'failed', message: 'TIMEOUT', clientId: '\x1b[2Jmalicious\ntext' });
    await expired; await f.flush();
    assert.doesNotMatch(f.screen(), /Press Enter to open browser/);
    assert.match(f.screen(), /failed/);
    assert.match(f.screen(), /Client:.*malicious text/);
    const stopped = assert.rejects(f.tui.waitForEnter(event.jobId, new AbortController().signal), { code: 'CANCELLED' });
    f.tui.stop(); await stopped;
  } finally { await f.stop(); }
});

test('history stays paused; trackpad, mouse, paste and copy shortcuts cannot activate UI', async () => {
  const f = fixture(); f.tui.start();
  try {
    for (let i = 0; i < 80; i++) f.tui.event({ ...event, message: `event ${i}` });
    await f.flush(); await f.key('\x1b[5~');
    assert.match(f.screen(), /History paused/);
    const history = () => f.screen().split('Recent events\n')[1].split('PgUp/PgDn')[0];
    const before = history();
    f.tui.event({ ...event, message: 'new event' });
    await f.flush(); assert.equal(history(), before);
    await f.key('\x1b[A\x1b[B');
    await f.key('\x1b[<0;10;3M\x1b[<0;10;3m');
    await f.key('\x1bc'); // Option/Cmd forwarded as Meta+C
    await f.key('\x1b[200~cq\r\x1b[201~'); // bracketed paste is not commands
    assert.equal(history(), before);
    assert.equal(f.cancelled(), undefined); assert.equal(f.quit(), 0);
    assert.doesNotMatch(f.text(), /\x1b\[\?(?:1000|1002|1003|1006)h/);
    await f.key('\x1b[F');
    assert.match(f.screen(), /Following/); assert.match(f.screen(), /new event/);
    const outputStart = f.text().length;
    f.tui.event({ ...event, startedAt: event.startedAt - 2000, message: 'countdown update' });
    await f.flush();
    assert.doesNotMatch(f.text().slice(outputStart), /Authorization|test-token|\x1b\[2J/);
    await f.key('\x03'); assert.equal(f.quit(), 1);
  } finally { await f.stop(); }
});

test('Ink preserves host signal handlers and preexisting raw mode', async () => {
  const handler = () => {};
  process.on('SIGTERM', handler);
  const f = fixture(); f.input.isRaw = true;
  try {
    f.tui.start(); await f.flush();
    assert.ok(process.listeners('SIGTERM').includes(handler));
  } finally { await f.stop(); process.off('SIGTERM', handler); }
  assert.equal(f.input.isRaw, true);
});
