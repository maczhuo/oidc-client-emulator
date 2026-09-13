import type { AccessOptions } from './access.js';
import { emitKeypressEvents } from 'node:readline';
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

export class DaemonTUI implements JobUI {
  private current?: JobEvent;
  private events: string[] = [];
  private scroll = 0;
  private pending?: { jobId: string; resolve(): void; reject(error: Error): void };
  private timer?: NodeJS.Timeout;
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
    this.events = this.events.slice(-100);
    this.scroll = 0;
    if (event.status !== 'pending' && this.pending?.jobId === event.jobId) this.rejectPrompt();
    this.render();
  }

  waitForEnter(jobId: string, signal: AbortSignal): Promise<void> {
    signal.throwIfAborted();
    return new Promise<void>((resolve, reject) => {
      const abort = () => this.rejectPrompt();
      const finish = () => { signal.removeEventListener('abort', abort); this.pending = undefined; };
      this.pending = { jobId, resolve: () => { finish(); resolve(); this.render(); }, reject: error => { finish(); reject(error); this.render(); } };
      signal.addEventListener('abort', abort, { once: true });
      this.render();
    });
  }

  private rejectPrompt() { this.pending?.reject(new OIDCEmulatorError('CANCELLED', 'Authorization cancelled.')); }
  private key = (_text: string, key: { name?: string; ctrl?: boolean } = {}) => {
    if (key.name === 'q' || key.name === 'c' && key.ctrl) {
      if (!this.quitting) { this.quitting = true; this.render(); this.quit(); }
    } else if (key.name === 'return' && !this.quitting) this.pending?.resolve();
    else if (key.name === 'c' && this.current?.status === 'pending') this.cancelJob(this.current.jobId);
    else if (key.name === 'up') { this.scroll = Math.min(this.scroll + 1, Math.max(0, this.events.length - 1)); this.render(); }
    else if (key.name === 'down') { this.scroll = Math.max(0, this.scroll - 1); this.render(); }
  };
  private resize = () => this.render();

  start() {
    this.wasRaw = !!this.input.isRaw;
    emitKeypressEvents(this.input);
    this.input.setRawMode(true);
    this.input.on('keypress', this.key);
    this.input.resume();
    this.output.on('resize', this.resize);
    this.output.write('\x1b[?1049h\x1b[?25l');
    this.timer = setInterval(() => this.render(), 1000).unref();
    this.render();
  }

  render() {
    if (this.stopped || !this.timer) return;
    const width = Math.max(1, (this.output.columns || 80) - 1), height = Math.max(1, this.output.rows || 24);
    const job = this.current;
    const left = job ? Math.max(0, Math.ceil((job.timeoutMs - (Date.now() - job.startedAt)) / 1000)) : 0;
    const status = this.quitting ? 'Shutting down; waiting for cleanup' : this.pending ? 'Waiting for Enter' : (job ? `${job.status}: ${job.message.split(':')[0]}` : 'Idle; waiting for a request');
    const lines = [`OIDC Emulator | ${this.address}`, `Status: ${status}`, this.pending ? '>>> Press Enter to open browser <<<' : 'Enter: open browser   c: cancel   q: quit   Up/Down: event history', ''];
    if (this.access) lines.push(`Access: ${this.access.teamDomain}`, `Audience: ${this.access.audience}`, '');
    if (this.token) lines.push(`Authorization: Bearer ${this.token}`, '');
    if (job) lines.push(`Job: ${job.jobId}`, `Issuer: ${job.issuer}`, `Client: ${job.clientId}`, `Redirect: ${job.redirectUri}`,
      job.status === 'pending' ? `Remaining: ${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}` : `Result: GET /login/${job.jobId}`, '');
    lines.push('Recent events');
    const room = Math.max(0, height - lines.length - 1);
    const end = Math.max(0, this.events.length - this.scroll);
    if (room) lines.push(...this.events.slice(Math.max(0, end - room), end));
    this.output.write('\x1b[H\x1b[2J' + lines.slice(0, height - 1).map(line => clean(line).slice(0, width)).join('\r\n'));
  }

  stop() {
    if (this.stopped) return;
    this.stopped = true;
    clearInterval(this.timer);
    this.rejectPrompt();
    this.input.off('keypress', this.key);
    this.output.off('resize', this.resize);
    if (this.timer) { this.input.setRawMode(this.wasRaw); this.input.pause(); this.output.write('\x1b[?25h\x1b[?1049l'); }
  }
}
