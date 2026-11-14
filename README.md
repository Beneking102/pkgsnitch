# pkgsnitch

_by [Bene Pankratz (@Beneking102)](https://github.com/Beneking102) · [benedikt-pkr.info](https://benedikt-pkr.info)_

**Behavioral diff and patch management for npm and PyPI packages.** See what a new version *does* at install and import time that the old one did not, and get a plan for which updates are safe to apply.

![pkgsnitch reporting a simulated hijacked patch release](docs/demo.svg)

A source diff shows what changed in the code. pkgsnitch shows what changed in the behavior: this patch release now reads `~/.ssh/id_rsa`, contacts a new host and runs `curl`. That is the signal of a hijacked package, and a version bump in a lockfile hides it.

## Commands

| You want to | Command |
|---|---|
| Check one update | `pkgsnitch diff <package> <old> <new>` |
| See what a package does at all | `pkgsnitch scan <package>[@version]` |
| Keep a project patched | `pkgsnitch updates [dir]` |
| Review a dependency pull request | `pkgsnitch lock <old-lock> <new-lock>` |
| Check your own release before publishing | `pkgsnitch diff old.tgz new.tgz` (also `.whl`, or `pypi:x.tar.gz`) |

For Python, prefix the package with `pypi:`, as in `pkgsnitch diff pypi:requests 2.31.0 2.32.3`. `updates` reads a `requirements.txt` the same way as a `package-lock.json`.

## Install

Requires Docker. Download a binary from the [releases](https://github.com/Beneking102/pkgsnitch/releases), or build it:

```
cargo install --git https://github.com/Beneking102/pkgsnitch
```

The sandbox image is built on first use.

## How it works

Each version runs in a throwaway container, in three phases:

1. **Fetch.** The package is downloaded without running any of its code (`npm install --ignore-scripts`, or `pip download --only-binary`).
2. **Install.** The network is cut. The install runs under `strace`: npm lifecycle scripts, or the build script of a Python source distribution.
3. **Import.** The entry point is loaded, again under `strace`.

While package code runs, a sinkhole answers all DNS and accepts connections on ports 80 and 443, so code that phones home reveals the host it wanted and nothing leaves the machine. The home directory and the environment hold worthless honeytoken credentials, so code that looks for secrets finds something to take. Each carries a marker: if it turns up again in a request, a DNS name or a command line, that is reported as exfiltration. The tracer runs as root and the package as an unprivileged user, so the evidence is out of the package's reach.

The traces are reduced to behaviors (sensitive files read, unexpected writes, processes started, network activity), each attributed to the command responsible. Comparing two versions as sets cancels everything npm and node do on their own; what remains is rated.

## Patch management

```
pkgsnitch updates                  # in a directory with package-lock.json
pkgsnitch updates --level patch    # bug-fix releases only
```

Finds newer versions of your direct dependencies, runs the behavioral diff for each, and prints a plan:

| Advice | Meaning |
|---|---|
| **apply** | Nothing new observed. The plan ends with one `npm install` line for all of these. |
| **review** | New medium-severity behavior, or a clean major version whose changelog you should read. |
| **hold** | New high or critical behavior. |

`pkgsnitch lock base.json package-lock.json` does the same for every version that differs between two lockfiles, including transitive ones. It reads `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `poetry.lock` and `uv.lock`. As a GitHub Action it comments the plan on the pull request:

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
      - uses: Beneking102/pkgsnitch@v0.1.0
```

## Options

| Option | Meaning |
|---|---|
| `--format terminal\|json\|markdown` | For people, tools, or a pull request |
| `--fail-on <severity>` | Exit 1 at this severity or above (default `high`) |
| `--allow <file>` | Accepted behaviors (default `.pkgsnitch-allow` if present) |
| `--level patch\|minor\|major` | `updates`: largest version jump to propose (default `major`) |
| `--max <n>`, `--jobs <n>` | `updates` and `lock`: how many to evaluate (default 20), how many at once (default 2) |
| `--timeout <seconds>` | Limit per phase (default 180) |
| `--no-cache` | Do not reuse stored results for exact versions |

Exit status: `0` below the threshold, `1` at or above it, `2` on errors.

An allowlist accepts behavior you have reviewed. Matching findings stay in the report as `info`:

```
# <package>   <behavior>: <target>      (* is a wildcard)
puppeteer     DNS lookup: storage.googleapis.com
esbuild       runs command: esbuild --version
```

## Severities

| Severity | Examples |
|---|---|
| critical | sends a planted secret anywhere; reads SSH keys or cloud credentials; writes a shell profile, cron entry or git hook; runs `curl`, `wget`, `nc` |
| high | any network activity; a new install script; reads `~/.npmrc`; writes in the home directory |
| medium | starts a process; a changed install script; a new dependency with an install script |
| low | a new dependency |

A rating says how alarming it is for a package to *start* doing something. A tool that has always downloaded a binary on install produces no finding on update.

On 30 real updates of widely used packages (lodash, express, typescript, next, vite, prisma and others) pkgsnitch reported nothing above `info`.

## Limits

- **It observes, it does not prove.** Code that waits for a date, checks for CI, or triggers only on a specific call stays quiet in a short run. A clean report means "nothing new was observed", not "safe".
- **Only install and import are exercised.** With the network cut, an install script that downloads a binary fails there: the attempt is reported, what the binary would do is not.
- **Sandbox detection is possible**, and a container is not a hard boundary against kernel exploits. Run pkgsnitch where that is acceptable, such as a CI runner.
- **Python specifics.** Only pinned lines (`name==1.2.3`) of a `requirements.txt` are read. A package without a wheel is installed without its dependencies, so its import may fail.

To try it without Docker, replay the recorded demo: `cargo run -- compare-dirs tests/fixtures/demo-old tests/fixtures/demo-new`. The demo packages in `demo/` (npm) and `demo/pypi/` (a Python source distribution) are harmless by construction. To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

MIT © 2026 Bene Pankratz
