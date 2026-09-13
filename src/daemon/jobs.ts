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
  expiry?: NodeJS.Timeout;
}

export class LoginJobs {
  private jobs = new Map<string, Job>();
  private active?: Job;
  private stopping = false;
  constructor(private run: typeof authorize = authorize, private stateDir?: string, private retentionMs = 60_000) {}

  start(options: AuthorizationOptions) {
    if (this.stopping) throw new OIDCEmulatorError('STOPPING', 'Daemon is shutting down.');
    if (this.active) throw new OIDCEmulatorError('BUSY', 'Another login is still active.');
    if (this.jobs.size >= 100) throw new OIDCEmulatorError('BUSY', 'Job capacity reached; retry after results expire.');
    const job: Job = { jobId: randomUUID(), status: 'pending', controller: new AbortController(), done: Promise.resolve() };
    this.jobs.set(job.jobId, job);
    this.active = job;
    job.done = Promise.resolve().then(() => this.run({ ...options, interception: 'managed', stateDir: this.stateDir, signal: job.controller.signal }))
      .then(result => { job.result = result; job.status = 'completed'; }, error => {
        job.status = 'failed';
        job.error = error instanceof OIDCEmulatorError
          ? { code: error.code, message: error.message }
          : { code: 'AUTHORIZATION_FAILED', message: 'Authorization failed.' };
      }).finally(() => {
        this.active = undefined;
        if (!this.stopping) job.expiry = setTimeout(() => this.jobs.delete(job.jobId), this.retentionMs).unref();
      });
    return { jobId: job.jobId, status: 'pending', pollAfterMs: 1000, expiresInSeconds: Math.ceil(options.timeoutMs! / 1000) };
  }

  get(id: string) {
    const job = this.jobs.get(id);
    if (!job) return undefined;
    return { jobId: job.jobId, status: job.status, ...(job.status === 'pending' ? { pollAfterMs: 1000 } : {}),
      ...(job.result ? { result: job.result } : {}), ...(job.error ? { error: job.error } : {}) };
  }

  cancel(id: string) {
    const job = this.jobs.get(id);
    if (!job) return false;
    job.controller.abort();
    return true;
  }

  async close() {
    this.stopping = true;
    this.active?.controller.abort();
    await this.active?.done;
    for (const job of this.jobs.values()) clearTimeout(job.expiry);
    this.jobs.clear();
  }
}
