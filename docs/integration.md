# Where to use pkgsnitch

Each recipe is independent. Pick the places where a dependency change passes through your hands.

| Where | What it catches | Command |
|---|---|---|
| [Before a commit](#before-a-commit) | A lockfile change on your machine | `pkgsnitch lock --since HEAD` |
| [Pull requests](#pull-requests) | Dependabot, Renovate and hand-made bumps | the GitHub Action, or `lock --since` in any CI |
| [Scheduled runs](#scheduled-runs) | Versions falling behind; a tested update plan | `outdated`, `updates` |
| [Code scanning](#code-scanning) | Findings as alerts on the lockfile line | `--format sarif` |
| [Before publishing](#before-publishing) | Your own release doing more than the last one | `diff old.tgz new.tgz` |

All commands need Docker on the machine that runs them. On hosted CI runners (GitHub, GitLab shared runners with Docker) it is already there.

## Before a commit

A git hook that checks a changed lockfile before it is committed. Save as `.git/hooks/pre-commit` and make it executable:

```sh
#!/bin/sh
git diff --cached --quiet -- package-lock.json yarn.lock pnpm-lock.yaml requirements.txt poetry.lock uv.lock \
  || pkgsnitch lock --since HEAD
```

It does nothing unless a lockfile is staged. `--since HEAD` compares the lockfiles in the working tree with the last commit, so only versions that are new get observed. Results for exact versions are cached, which makes a repeated run instant.

## Pull requests

On GitHub, the action comments the plan on the pull request and fails the check at `high`:

```yaml
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  pkgsnitch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Beneking102/pkgsnitch@v0.3.0
        with:
          lockfile: package-lock.json   # or yarn.lock, pnpm-lock.yaml, requirements.txt, poetry.lock, uv.lock
```

Anywhere else it is one command. GitLab CI:

```yaml
pkgsnitch:
  image: docker:27
  services: [docker:27-dind]
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - apk add --no-cache git
    - wget -qO /usr/local/bin/pkgsnitch https://github.com/Beneking102/pkgsnitch/releases/latest/download/pkgsnitch-linux-x86_64
    - chmod +x /usr/local/bin/pkgsnitch
    - git fetch --depth=1 origin "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
    - pkgsnitch lock --since FETCH_HEAD --format markdown
```

The exit status is `1` when a new version shows high or critical behavior, so the job fails by itself.

## Scheduled runs

Two different questions, on a timer.

**What is behind?** `outdated` reads every dependency file and asks the registries. It runs no package code and works for all ten ecosystems:

```yaml
on:
  schedule: [{ cron: "0 6 * * 1" }]
jobs:
  outdated:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          curl -sSfL -o pkgsnitch https://github.com/Beneking102/pkgsnitch/releases/latest/download/pkgsnitch-linux-x86_64
          chmod +x pkgsnitch
          ./pkgsnitch outdated --recursive --format markdown >> "$GITHUB_STEP_SUMMARY"
          ./pkgsnitch outdated --recursive --fail-if major > /dev/null
```

**Which updates are safe to take?** For npm and Python, `updates` tests every newer version and writes the plan to the job summary:

```yaml
      - uses: Beneking102/pkgsnitch@v0.3.0
        with:
          command: updates
          lockfile: package-lock.json   # or requirements.txt
          level: minor                  # do not propose major versions
```

## Code scanning

The action writes the findings as SARIF. Uploading them puts each one in the repository's Security tab, pointing at the line of the lockfile that pins the version:

```yaml
permissions:
  contents: read
  pull-requests: write
  security-events: write
steps:
  - uses: actions/checkout@v4
  - uses: Beneking102/pkgsnitch@v0.3.0
    id: pkgsnitch
    continue-on-error: true
  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: ${{ steps.pkgsnitch.outputs.sarif }}
```

On the command line: `pkgsnitch lock --since origin/main --format sarif > pkgsnitch.sarif`.

## Before publishing

A maintainer's last check: does the release about to go out do anything the published one does not? In a release workflow, after building the package:

```sh
npm pack                                   # produces my-package-1.4.0.tgz
npm pack my-package@1.3.0                  # the version users have now
pkgsnitch diff my-package-1.3.0.tgz my-package-1.4.0.tgz
```

For Python: `pkgsnitch diff pypi:dist/old.tar.gz pypi:dist/new.tar.gz`, or two `.whl` files. A build machine that was compromised between two releases shows up here.

## Accepting known behavior

A package that legitimately downloads a binary on install will be reported the first time it appears. Record the decision once in `.pkgsnitch-allow` at the repository root, and commit it:

```
# <package>   <behavior>: <target>      (* is a wildcard)
puppeteer     DNS lookup: storage.googleapis.com
puppeteer     TLS connection: storage.googleapis.com:443
esbuild       runs command: esbuild --version
```

Accepted findings stay in the report as `info`, so the decision remains visible.
