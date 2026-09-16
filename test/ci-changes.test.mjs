import test from 'node:test';
import assert from 'node:assert/strict';
import { requiresTests, shouldRunTests } from '../scripts/ci-changes.mjs';

test('documentation and unrelated workflows skip tests; application and verification changes do not', () => {
  assert.equal(requiresTests(['README.md', 'AGENTS.md', 'docs/usage.txt', '.github/workflows/pr-title.yml']), false);
  assert.equal(requiresTests(['.github/workflows/release-please.yml']), false);
  for (const file of ['src/daemon/tui.ts', 'test/tui.test.mjs', 'scripts/ci-changes.mjs',
    'package.json', 'package-lock.json', 'tsconfig.json', 'native/URLHelper.swift',
    '.github/workflows/ci.yml', '.github/workflows/publish.yml', 'unknown.config']) {
    assert.equal(requiresTests(['README.md', file]), true, file);
  }
});

const base = 'a'.repeat(40), head = 'b'.repeat(40);
test('PRs compare against merge base; pushes compare the whole pushed range', () => {
  for (const name of ['pull_request', 'push']) {
    const event = { before: base, after: head, pull_request: { base: { sha: base }, head: { sha: head } } };
    assert.equal(shouldRunTests(event, name, '', range => {
      assert.equal(range, `${base}${name === 'pull_request' ? '...' : '..'}${head}`);
      return 'README.md\0.github/workflows/pr-title.yml\0';
    }), false);
    // With --no-renames a source file renamed into docs still appears as deleted source.
    assert.equal(shouldRunTests(event, name, '', () => 'src/old.ts\0docs/old.md\0'), true);
  }
});

test('release verification, unknown events, missing commits and failed diffs run full tests', () => {
  const event = { before: base, after: head };
  assert.equal(shouldRunTests(event, 'push', head, () => { throw Error('must not diff release'); }), true);
  assert.equal(shouldRunTests(event, 'release', '', () => ''), true);
  assert.equal(shouldRunTests({ ...event, before: '0'.repeat(40) }, 'push', '', () => ''), true);
  assert.equal(shouldRunTests({}, 'pull_request', '', () => ''), true);
  assert.equal(shouldRunTests(event, 'push', '', () => { throw Error('missing history'); }), true);
});
