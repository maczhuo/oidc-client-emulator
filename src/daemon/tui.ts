import type { AccessOptions } from './access.js';
import { createElement } from 'react';
import { Box, Text, render, useInput, type Instance, type Key } from 'ink';
import { OIDCEmulatorError } from '../errors.js';

export interface JobEvent {
  jobId: string; status: string; message: string; startedAt: number; timeoutMs: number;
  issuer: string; clientId: string; redirectUri: string;
}
export interface JobUI {
  event(event: JobEvent): void;
  waitForEnter(jobId: string, signal: AbortSignal): Promise<void>;
}
const clean = (value: string) => value.replace(/[\x00-\x1f\x7f-\x9f]/g, ' ');

function Dashboard({ lines, width, onInput, alertLine, alertBright }: {
  lines: string[]; width: number; alertLine: number; alertBright: boolean; onInput: (input: string, key: Key) => void;
}) {
  useInput(onInput);
  return createElement(Box, { flexDirection: 'column', width },
    ...lines.map((line, index) => createElement(Text, {
      key: index, wrap: 'truncate-end',
      ...(index === alertLine ? { bold: true, color: alertBright ? 'whiteBright' : 'redBright',
        backgroundColor: alertBright ? 'red' : undefined } : {}),
    }, line || ' ')));
}

export class DaemonTUI implements JobUI {
  private current?: JobEvent;
  private events: string[] = [];
  private instance?: Instance;
  private scroll = 0;
  private historyRows = 1;
  private pending?: { jobId: string; resolve(): void; reject(error: Error): void };
  private timer?: NodeJS.Timeout;
  private alertBright = true;
  private stopped = false;
  private quitting = false;
  private wasRaw = false;
  constructor(private address: string, private token: string | undefined,
    private cancelJob: (id: string) => void, private quit: () => void,
    private input = process.stdin, private output = process.stderr, private access?: AccessOptions) {}

  event(event: JobEvent) {
    // Expiry of an older result must not replace a newer active job.
    if (!this.current || this.current.jobId === event.jobId || event.startedAt >= this.current.startedAt) this.current = event;
    this.events.push(`${new Date().toLocaleTimeString()} ${event.jobId.slice(0, 8)} ${event.message}`);
    // Keep the same events visible while reading older history.
    if (this.scroll > 0) this.scroll++;
    this.events = this.events.slice(-100);
    this.scroll = Math.min(this.scroll, Math.max(0, this.events.length - this.historyRows));
    if (event.status !== 'pending' && this.pending?.jobId === event.jobId) this.rejectPrompt();
    this.render();
  }

  waitForEnter(jobId: string, signal: AbortSignal): Promise<void> {
    signal.throwIfAborted();
    this.alertBright = true;
    return new Promise<void>((resolve, reject) => {
      const abort = () => this.rejectPrompt();
      const finish = () => { signal.removeEventListener('abort', abort); this.pending = undefined; };
      this.pending = { jobId, resolve: () => { finish(); resolve(); this.render(); }, reject: error => { finish(); reject(error); this.render(); } };
      signal.addEventListener('abort', abort, { once: true });
      this.render();
    });
  }

  private rejectPrompt() { this.pending?.reject(new OIDCEmulatorError('CANCELLED', 'Authorization cancelled.')); }
  private key = (input: string, key: Key) => {
    // Leave mouse selection and Cmd/Option shortcuts to the terminal. In
    // particular, never interpret trackpad-generated arrows as UI actions.
    if (key.meta || key.super || key.hyper || key.eventType === 'release') return;
    if ((input === 'q' && !key.ctrl) || (input === 'c' && key.ctrl)) {
      if (!this.quitting) { this.quitting = true; this.render(); this.quit(); }
    } else if (this.quitting) return;
    else if (key.return) this.pending?.resolve();
    else if (input === 'c' && !key.ctrl && this.current?.status === 'pending') this.cancelJob(this.current.jobId);
    else if (key.pageUp) this.scroll += this.historyRows;
    else if (key.pageDown) this.scroll -= this.historyRows;
    else if (key.home) this.scroll = this.events.length;
    else if (key.end) this.scroll = 0;
    else return;
    this.scroll = Math.max(0, Math.min(this.scroll, this.events.length - this.historyRows));
    this.render();
  };
  private resize = () => this.render();

  start() {
    if (this.instance || this.stopped) return;
    this.wasRaw = !!this.input.isRaw;
    this.instance = render(this.view(), {
      stdin: this.input, stdout: this.output, stderr: this.output,
      alternateScreen: true, incrementalRendering: true,
      exitOnCtrlC: false, patchConsole: false,
      // The CLI already selects plain logs for redirected streams and TERM=dumb.
      interactive: true,
    });
    this.output.on('resize', this.resize);
    this.timer = setInterval(() => { this.alertBright = !this.alertBright; this.render(); }, 1000).unref();
  }

  private view() {
    const height = Math.max(1, (this.output.rows || 24) - 1);
    const job = this.current;
    const left = job ? Math.max(0, Math.ceil((job.timeoutMs - (Date.now() - job.startedAt)) / 1000)) : 0;
    const status = this.quitting ? 'Shutting down; waiting for cleanup' : this.pending ? 'Waiting for Enter' : (job ? `${job.status}: ${job.message.split(':')[0]}` : 'Idle; waiting for a request');
    const needsBrowser = !!this.pending && !this.quitting;
    const lines = [`OIDC Emulator | ${this.address}`, `Status: ${status}`, 'Enter: open browser   c: cancel   q: quit', ''];
    if (this.access) lines.push(`Access: ${this.access.teamDomain}`, `Audience: ${this.access.audience}`, '');
    if (this.token) lines.push(`Authorization: Bearer ${this.token}`, '');
    const alertLine = lines.length;
    if (needsBrowser) lines.push('>>> Press Enter to open browser <<< NEW REQUEST');
    if (job) lines.push(`Job: ${job.jobId}`, `Issuer: ${job.issuer}`, `Client: ${job.clientId}`, `Redirect: ${job.redirectUri}`,
      job.status === 'pending' ? `Remaining: ${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}` : `Result: GET /login/${job.jobId}`, '');
    const summary = lines.slice(0, Math.max(3, height - 3));
    this.historyRows = Math.max(0, height - summary.length - 2);
    this.scroll = Math.max(0, Math.min(this.scroll, this.events.length - this.historyRows));
    const end = this.events.length - this.scroll;
    const history = this.events.slice(Math.max(0, end - this.historyRows), end);
    while (history.length < this.historyRows) history.push('');
    const frame = [...summary, 'Recent events', ...history,
      `PgUp/PgDn: history  Home/End: oldest/latest | ${this.scroll === 0 ? 'Following' : 'History paused'}`];
    return createElement(Dashboard, {
      lines: frame.slice(0, height).map(clean),
      alertLine: needsBrowser && alertLine < summary.length ? alertLine : -1, alertBright: this.alertBright,
      width: Math.max(1, (this.output.columns || 80) - 1), onInput: this.key,
    });
  }

  render() {
    if (!this.stopped) this.instance?.rerender(this.view());
  }

  stop() {
    if (this.stopped) return;
    this.stopped = true;
    clearInterval(this.timer);
    this.rejectPrompt();
    this.output.off('resize', this.resize);
    if (this.instance) {
      this.instance.unmount();
      this.instance.cleanup();
      this.input.setRawMode(this.wasRaw);
      this.input.pause();
    }
  }
}
