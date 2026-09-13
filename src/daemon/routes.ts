import { Router } from 'express';
import { loginOptions } from './options.js';
import type { LoginJobs } from './jobs.js';

export function loginRoutes(jobs: LoginJobs) {
  const router = Router();
  router.post('/', (req, res) => {
    if (!req.is('application/json')) { res.status(415).json({ error: { code: 'JSON_REQUIRED', message: 'Use Content-Type: application/json.' } }); return; }
    const job = jobs.start(loginOptions(req.body));
    res.location(`/login/${job.jobId}`).status(202).json(job);
  });
  router.get('/:jobId', (req, res) => {
    const job = jobs.get(req.params.jobId);
    if (!job) { res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Job not found or expired.' } }); return; }
    res.json(job);
  });
  router.delete('/:jobId', (req, res) => {
    if (!jobs.cancel(req.params.jobId)) { res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Job not found or expired.' } }); return; }
    res.status(202).json(jobs.get(req.params.jobId));
  });
  return router;
}
