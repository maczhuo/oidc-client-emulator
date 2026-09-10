# Publishing to npm with GitHub Actions

This setup follows the same GitHub App → release-please → GitHub Release → npm
trusted-publishing pattern as the DynamoDB library, adapted to this package's tests.
The files are prepared locally; creating them does not configure accounts or publish
anything. GitHub-hosted execution has not yet been verified for this repository.

## 1. Package and repository

| Setting | Value |
| --- | --- |
| npm package | `@jzhuo3/oidc-client-emulator` |
| GitHub repository | `maczhuo/oidc-client-emulator` |
| Default branch | `main` |
| Initial version | `0.1.0` |
| Release tag format | `vX.Y.Z` |
| npm registry | `https://registry.npmjs.org` |
| Package access | Public |

Confirm that you can publish under the `@jzhuo3` scope. The package name and GitHub
username are separate identities. Create the GitHub repository, preferably public
for an open-source package and npm provenance, and add its remote:

```sh
git remote add origin git@github.com:maczhuo/oidc-client-emulator.git
```

If `origin` already exists, inspect it before changing it. This package uses the
[MIT License](LICENSE), with copyright attributed to jzhuo3 (2026), matching the
DynamoDB library. The license file is included in the npm archive.
The repository, homepage, bugs URL, and public npm registry are already configured.

## 2. What each workflow does

| File | Trigger | Work |
| --- | --- | --- |
| `.github/workflows/ci.yml` | PRs, pushes to `main`, or reusable call from publishing | Node 22/24 on Linux: typecheck, automated tests, and packed-install checks |
| `.github/workflows/release-please.yml` | Push to `main` | Uses a GitHub App token to maintain a version/changelog PR and create its release when merged |
| `.github/workflows/publish.yml` | A non-prerelease GitHub Release is published | Validate tag/package/manifest/repository, rerun CI on the exact release commit, then publish through npm OIDC |

Required CI never opens a real login browser, loads `.env`, changes default URL
handlers, or needs provider credentials. All GitHub jobs use Linux runners;
macOS compilation and native handler tests are excluded from CI and release gates.
Run `check:native` and `test:macos` locally when changing the native integration.
`test:live` also remains local because it needs real sign-in.

Run these locally before your first push:

```sh
npm ci
npm run typecheck
npm test
npm run test:package
npm run check:native     # macOS only; no GUI needed
npm run test:macos       # optional native regression check; macOS GUI needed
npm run test:live        # optional real-provider check; local .env needed
```

Only source and configuration files belong in Git. `.env`, `.prototype/`, build
output, dependencies, and tarballs are ignored. `.env.sample` contains placeholders
and should be committed. Existing staged files are left for you to review.

## 3. GitHub repository settings

In **Settings → Actions → General**, allow the actions used by these workflows.
If restricted to selected actions, allow `actions/*` and
`googleapis/release-please-action`. Enable **Allow GitHub Actions to create and
approve pull requests** if that setting is available and your organization allows it.
The release bot opens PRs; it does not automatically approve or merge them.

After CI has run once, protect `main` with a ruleset requiring pull requests and
the **Verify complete** status check. Use squash merges and Conventional Commit
PR titles so release-please can identify changes.

Create **Settings → Environments → New environment → `npm`**. Configure its
deployment rules to allow release tags such as `v*`. You can add a required
reviewer if you want a pause before each npm publication; it is not required by
these workflow files. No npm access-token secret is needed.

## 4. Create or reuse the release GitHub App

You can reuse the release App from the DynamoDB project by granting its installation
access to this repository, or create a separate App:

1. Open your GitHub account **Settings → Developer settings → GitHub Apps**.
2. Select **New GitHub App** and choose a unique name, such as
   `maczhuo-oidc-release-bot`. Set its homepage to the repository URL. Webhooks can
   be disabled; this App is used by Actions to mint an installation token.
3. Under **Repository permissions**, grant **Contents: Read and write**,
   **Pull requests: Read and write**, and **Issues: Read and write**. Metadata is
   read-only automatically. No organization or account permissions are needed.
4. Restrict installation to your account if this is a personal release App, then
   create it. On its settings page, note the **Client ID** and generate a private key.
5. In the App's left sidebar, select **Install App**, then **Install** beside
   `maczhuo`. On the installation screen select **Only select repositories** and
   choose `oidc-client-emulator`. Repository selection is on this installation
   screen, not the App-creation form. For an existing installation, choose
   **Configure** and add this repository to its allowed repositories.
6. In this repository's **Settings → Secrets and variables → Actions**, add:

| Type | Name | Value |
| --- | --- | --- |
| Repository variable | `RELEASE_APP_CLIENT_ID` | The App's Client ID |
| Repository secret | `RELEASE_APP_PRIVATE_KEY` | Complete generated PEM private key, including its header/footer and newlines |

The token action is scoped to the current repository. Do not commit the PEM key.
The workflow uses an App installation token because events created with the
default `GITHUB_TOKEN` normally do not trigger subsequent workflows; a release
created that way would not start the separate publishing workflow.

## 5. Bootstrap the first npm version

Use a current Node 24 release and npm 11 (at least npm 11.5.1). Sign in locally with
the npm account that controls the scope and complete its 2FA prompts:

```sh
npm login --registry=https://registry.npmjs.org
npm whoami --registry=https://registry.npmjs.org
```

Review and commit the initial source, workflows, metadata, and chosen license,
then push `main`. Use an initial message such as `chore: initialize package` so
release-please does not open an unintended feature release during bootstrap.
Wait for GitHub CI to pass and review the packed files:

```sh
npm pack --dry-run
npm run test:package
```

If the package does not yet exist on npm, publish the initial `0.1.0` version
locally after you are ready to make it public:

```sh
npm publish --access public
```

`prepublishOnly` runs typechecking, automated tests, and packed-install checks;
`prepack` builds the distribution. These commands do not run interactive tests.
Keep the release-please manifest at `0.1.0`, and tag the exact published commit:

```sh
git tag v0.1.0
git push origin v0.1.0
```

Do not publish a GitHub Release for this bootstrap tag: it would trigger a second
attempt to publish the already-existing npm version. Pushing a tag alone does not
trigger `publish.yml`. If the package already exists, first align package.json,
package-lock.json, the manifest, and the baseline tag with its real released version.

## 6. Configure npm trusted publishing

On npmjs.com, open **the package → Settings → Trusted Publisher → GitHub Actions**.
Use these exact values:

| Field | Value |
| --- | --- |
| Organization or user | `maczhuo` |
| Repository | `oidc-client-emulator` |
| Workflow filename | `publish.yml` (not its full path) |
| Environment | `npm` |
| Allowed action | Allow direct `npm publish` |

Complete npm's authentication prompts to save the trust. The workflow grants
`id-token: write` only to its publish job, uses a GitHub-hosted runner, and installs
npm 11. npm obtains short-lived publishing credentials from the Actions OIDC
identity. Do not add `NPM_TOKEN` or put your provider's `.env` credentials in CI.
The library's OIDC sign-in test and npm's publishing OIDC identity are unrelated.

## 7. Normal releases

1. Make a change through a PR with a Conventional Commit title, for example
   `fix: reject invalid callback state` or `feat: add a new option`.
2. Merge it into `main` after CI passes.
3. Release-please creates or updates a release PR containing package/lockfile and
   manifest version changes plus `CHANGELOG.md`.
4. Review that release PR and merge it after its checks pass. Do not manually
   change its versions or create an extra tag.
5. Release-please creates the `vX.Y.Z` tag and GitHub Release. The App identity
   allows that event to trigger `publish.yml`.
6. Publishing verifies the tag, package identity, license, repository, and manifest;
   runs the reusable CI workflow against the release commit; enters the `npm`
   environment; and publishes only after those jobs succeed.

Before 1.0, the supplied release-please settings treat ordinary features and fixes
as patch bumps, and breaking changes as minor bumps. Use `feat!:` or a
`BREAKING CHANGE:` footer when appropriate. Docs/chore-only changes may not create
a release PR. The first feature/fix after a `0.1.0` bootstrap normally releases
`0.1.1`. Draft releases and prereleases do not publish through this workflow.

## Troubleshooting

- **No repository picker during App creation:** finish creation, then use
  **Install App → Install/Configure → Only select repositories**.
- **Release PR/release created but no new workflow run:** confirm release-please
  uses the App token, not `GITHUB_TOKEN`.
- **App token creation fails:** check the Client ID, full PEM secret, installation,
  and access/permissions for this repository.
- **Publication fails validation:** follow the metadata error; the tag, manifest,
  and package version must agree, and the license/repository must be configured.
- **npm OIDC returns 401/404:** check all trusted-publisher fields, the `npm`
  environment and tag rules, npm version, and permission for direct publication.
- **A workflow fails before publication:** after correcting external settings,
  rerun the failed jobs. npm versions cannot be overwritten; source/workflow fixes
  that change the released commit should be delivered through a new release.

## Official references

- [npm trusted publishers](https://docs.npmjs.com/trusted-publishers/)
- [Publishing scoped public packages](https://docs.npmjs.com/creating-and-publishing-scoped-public-packages/)
- [GitHub App installation tokens](https://github.com/actions/create-github-app-token)
- [Release Please Action and event-trigger behavior](https://github.com/googleapis/release-please-action)
- [GitHub publishing workflows](https://docs.github.com/en/actions/tutorials/publish-packages/publish-nodejs-packages)
