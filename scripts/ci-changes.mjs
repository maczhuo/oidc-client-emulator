import { execFileSync } from 'node:child_process';
import { appendFileSync, readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export function requiresTests(files) {
  return files.some(file => {
    if (file === '.github/workflows/ci.yml' || file === '.github/workflows/publish.yml') return true;
    if (file.endsWith('.md') || file.startsWith('docs/')) return false;
    if (/^\.github\/workflows\/[^/]+\.ya?ml$/.test(file)) return false;
    return true;
  });
}

export function shouldRunTests(event, eventName, ref, diff = range =>
  execFileSync('git', ['diff', '--name-only', '--no-renames', '-z', range, '--'], { encoding: 'utf8' })
) {
  // Publishing always verifies the complete application at the exact release commit.
  if (ref) return true;
  const base = eventName === 'pull_request' ? event.pull_request?.base?.sha : event.before;
  const head = eventName === 'pull_request' ? event.pull_request?.head?.sha : event.after;
  if (!['pull_request', 'push'].includes(eventName) ||
      !/^[a-f0-9]{40}$/.test(base ?? '') || !/^[a-f0-9]{40}$/.test(head ?? '') || /^0+$/.test(base)) return true;
  try {
    const range = `${base}${eventName === 'pull_request' ? '...' : '..'}${head}`;
    return requiresTests(diff(range).split('\0').filter(Boolean));
  } catch {
    // Missing history or an unreadable diff must never suppress verification.
    console.warn('Could not determine changed files; running full verification.');
    return true;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const event = JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
  const run = shouldRunTests(event, process.env.GITHUB_EVENT_NAME, process.env.VERIFY_REF);
  appendFileSync(process.env.GITHUB_OUTPUT, `run_tests=${run}\n`);
  console.log(run ? 'Application verification required.' : 'Only documentation or unrelated workflows changed; skipping application tests.');
}
