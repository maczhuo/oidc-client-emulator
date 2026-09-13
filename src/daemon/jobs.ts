import { randomUUID } from 'node:crypto';
import { authorize, type AuthorizationOptions, type AuthorizationResult } from '../oidc.js';
import { OIDCEmulatorError } from '../errors.js';

interface Job {
  jobId: string;
  status: 'pending' | 'completed' | 'failed';
  result?: AuthorizationResult;
  error?: { code: string; message: string };
  controller: AbortController;
  done: Promise<void>;
  startedAt: number;
  expiry?: NodeJS.Timeout;
}

export class LoginJobs {
  private jobs = new Map<string, Job>();
  private active?: Job;
  private stopping = false;
  constructor(private run: typeof authorize = authorize, private stateDir?: string, private retentionMs = 60_000,
    private log: (line: string) => void = line => console.error(line)) {}

  private report(job: Job, message: string) {
    this.log(`[${new Date().toISOString()}] [job ${job.jobId}] ${message}`);
  }

  start(options: AuthorizationOptions) {
    if (this.stopping) throw new OIDCEmulatorError('STOPPING', 'Daemon is shutting down.');
    if (this.active) throw new OIDCEmulatorError('BUSY', 'Another login is still active.');
    if (this.jobs.size >= 100) throw new OIDCEmulatorError('BUSY', 'Job capacity reached; retry after results expire.');
    const job: Job = { jobId: randomUUID(), status: 'pending', controller: new AbortController(), done: Promise.resolve(), startedAt: Date.now() };
    this.jobs.set(job.jobId, job);
    this.active = job;
    const safeUrl = (value: string) => {
      const url = new URL(value);
      url.username = ''; url.password = ''; url.search = ''; url.hash = '';
      return url.href;
    };
    this.report(job, `pending: request accepted ${JSON.stringify({ issuer: safeUrl(options.issuer), clientId: options.clientId,
      redirectUri: safeUrl(options.redirectUri), scopes: options.scopes ?? ['openid'], timeoutMs: options.timeoutMs ?? 300_000 })}`);
    this.report(job, 'preparing: discovering provider and setting up callback interception.');
    job.done = Promise.resolve().then(() => this.run({ ...options, interception: 'managed', stateDir: this.stateDir, signal: job.controller.signal,
      onAuthorizationUrl: () => { this.report(job, 'ready: callback listener and interceptor are ready. Press Enter below, then complete browser sign-in.'); },
    }))
      .then(result => {
        job.result = result; job.status = 'completed';
        this.report(job, `completed: authorization and cleanup finished in ${Date.now() - job.startedAt}ms. Result available for ${this.retentionMs / 1000}s at GET /login/${job.jobId}.`);
      }, error => {
        job.status = 'failed';
        job.error = error instanceof OIDCEmulatorError
          ? { code: error.code, message: error.message }
          : { code: 'AUTHORIZATION_FAILED', message: 'Authorization failed.' };
        this.report(job, `failed after ${Date.now() - job.startedAt}ms: ${JSON.stringify(job.error)}`);
      }).finally(() => {
        this.active = undefined;
        if (!this.stopping) job.expiry = setTimeout(() => {
          this.jobs.delete(job.jobId);
          this.report(job, 'expired: retained job and result removed.');
        }, this.retentionMs).unref();
      });
    return { jobId: job.jobId, status: 'pending', pollAfterMs: 1000, expiresInSeconds: Math.ceil(options.timeoutMs! / 1000) };
  }

  get(id: string) {
    const job = this.jobs.get(id);
    if (!job) return undefined;
    this.report(job, `status requested: ${job.status} (${Date.now() - job.startedAt}ms since start).`);
    return { jobId: job.jobId, status: job.status, ...(job.status === 'pending' ? { pollAfterMs: 1000 } : {}),
      ...(job.result ? { result: job.result } : {}), ...(job.error ? { error: job.error } : {}) };
  }

  cancel(id: string) {
    const job = this.jobs.get(id);
    if (!job) return false;
    if (job.status === 'pending' && !job.controller.signal.aborted) {
      this.report(job, 'cancellation requested: waiting for authorization cleanup.');
      job.controller.abort();
    }
    return true;
  }

  async close() {
    this.stopping = true;
    if (this.active) this.report(this.active, 'daemon shutting down: cancelling authorization and waiting for cleanup.');
    this.active?.controller.abort();
    await this.active?.done;
    for (const job of this.jobs.values()) clearTimeout(job.expiry);
    this.jobs.clear();
  }
}
