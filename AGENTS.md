# Repository conventions

## Start changes from the latest main

- Before editing files for a new task, fetch the latest `main` from `origin` and create a feature branch from `origin/main` (for example, `git fetch origin main` followed by `git switch -c codex/<feature-name> origin/main`).
- Do not start changes on local `main` or create a feature branch from a stale local `main`.
- If fetching fails, report the blocker rather than silently using a stale base.
- Preserve existing uncommitted work when switching branches; never discard it to follow this convention.
- Continue follow-up work on the task's existing feature branch unless the user requests otherwise.
