# Repository conventions

## Start changes from the latest main

- Before editing files for a new task, fetch the latest `main` from `origin` and create a feature branch from `origin/main` (for example, `git fetch origin main` followed by `git switch -c codex/<feature-name> origin/main`).
- Do not start changes on local `main` or create a feature branch from a stale local `main`.
- If fetching fails, report the blocker rather than silently using a stale base.
- Preserve existing uncommitted work when switching branches; never discard it to follow this convention.
- Continue follow-up work on the task's existing feature branch unless the user requests otherwise.

## PR titles and releases

- Use Conventional Commits for commit messages and PR titles: `type(scope): description` (scope is optional). Use `feat` for new features, `fix` for bug fixes, and the appropriate maintenance type for other changes. Do not label every change `feat` merely to trigger a release.
- When preparing a PR, choose a title describing the final change, not the branch name. Example: `feat(tui): highlight pending browser requests in job info`.
- If the user will create the PR manually, include a ready-to-copy Conventional Commits PR title in the handoff.
- Before squash merging, ensure the PR-title check passes and the final squash commit title retains the correct prefix. Release Please reads the merged commit, so editing the PR title after merging does not fix that commit.
- Keep the `Conventional PR title` status check required for `main` in GitHub. The workflow validates titles on PR creation, edits, and updates; agents must not bypass a failed check.
- Do not manually bump versions or rewrite published `main` history to repair release metadata unless explicitly requested.
