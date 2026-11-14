//! pkgsnitch: behavioral diff for package updates.
//!
//! Installs two versions of a package in a throwaway sandbox, watches what
//! each does at install and import time, and reports what is new.

mod diff;
mod extract;
mod model;
mod profile;
mod report;
mod rules;
mod sandbox;
mod strace;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};

use crate::diff::Mode;
use crate::model::{Profile, Severity};
use crate::profile::Cache;
use crate::report::Format;
use crate::sandbox::{Sandbox, Target};

#[derive(Parser)]
#[command(name = "pkgsnitch", version, about, max_term_width = 100)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show what a new version does that the old one did not
    #[command(
        after_help = "Examples:\n  pkgsnitch diff left-pad 1.2.0 1.3.0\n  pkgsnitch diff ./pkg-1.0.0.tgz ./pkg-1.0.1.tgz"
    )]
    Diff {
        /// `<package> <old-version> <new-version>`, or two `npm pack` tarballs
        #[arg(num_args = 2..=3, required = true, value_name = "PACKAGE OLD NEW | OLD.tgz NEW.tgz")]
        targets: Vec<String>,
        #[command(flatten)]
        opts: Options,
    },
    /// Show what a single version does at install and import time
    #[command(
        after_help = "Examples:\n  pkgsnitch scan esbuild@0.21.5\n  pkgsnitch scan ./my-package-1.0.0.tgz"
    )]
    Scan {
        /// `name`, `name@version` or a tarball
        package: String,
        #[command(flatten)]
        opts: Options,
    },
    /// Analyze the raw output directory of a sandbox run (for debugging)
    #[command(hide = true)]
    Analyze { dir: PathBuf },
    /// Compare two raw output directories instead of running the sandbox.
    /// Used by the test harness to exercise the full pipeline without Docker.
    #[command(hide = true)]
    CompareDirs {
        old: PathBuf,
        new: PathBuf,
        #[command(flatten)]
        opts: Options,
    },
}

#[derive(Args)]
struct Options {
    /// Output format
    #[arg(long, value_enum, default_value = "terminal")]
    format: Format,
    /// Exit with status 1 when a finding is at least this severe
    #[arg(long, value_enum, default_value = "high")]
    fail_on: Severity,
    /// Seconds each phase may run before it is stopped
    #[arg(long, default_value_t = 180)]
    timeout: u32,
    /// Container runtime to drive
    #[arg(long, default_value = "docker")]
    runtime: String,
    /// Observe again even if a cached result exists
    #[arg(long)]
    no_cache: bool,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    let (old, new, mode, opts) = match cli.command {
        Cmd::Analyze { dir } => {
            println!("{}", serde_json::to_string_pretty(&profile::build(&dir)?)?);
            return Ok(ExitCode::SUCCESS);
        }
        Cmd::CompareDirs { old, new, opts } => {
            let before =
                profile::build(&old).with_context(|| format!("analyzing {}", old.display()))?;
            let after =
                profile::build(&new).with_context(|| format!("analyzing {}", new.display()))?;
            let report = diff::compare(&before, &after, Mode::Update);
            anstream::print!("{}", report::render(&report, opts.format));
            return Ok(if report.verdict >= opts.fail_on {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            });
        }
        Cmd::Diff { targets, opts } => {
            let (old, new) = diff_targets(&targets)?;
            (old, new, Mode::Update, opts)
        }
        Cmd::Scan { package, opts } => (Target::Baseline, scan_target(&package)?, Mode::Scan, opts),
    };

    let sandbox = Sandbox::new(&opts.runtime, opts.timeout)?;
    sandbox.ensure_image()?;
    let cache = Cache::new(!opts.no_cache, sandbox.fingerprint());
    let session = Session {
        sandbox: &sandbox,
        cache: &cache,
    };

    // Both observations are independent, so they run side by side.
    let (before, after) = std::thread::scope(|scope| {
        let before = scope.spawn(|| session.profile(&old));
        let after = session.profile(&new);
        (before.join().expect("observer thread panicked"), after)
    });
    let (before, after) = (before?, after?);
    if mode == Mode::Update && before.name != after.name {
        bail!(
            "cannot compare different packages: `{}` and `{}`",
            before.name,
            after.name
        );
    }

    let report = diff::compare(&before, &after, mode);
    anstream::print!("{}", report::render(&report, opts.format));
    Ok(if report.verdict >= opts.fail_on {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

struct Session<'a> {
    sandbox: &'a Sandbox,
    cache: &'a Cache,
}

impl Session<'_> {
    fn profile(&self, target: &Target) -> Result<Profile> {
        let label = target.label();
        // Only exact registry versions are immutable enough to cache.
        let key = match target {
            Target::Baseline => Some(("", "baseline")),
            Target::Registry {
                name,
                version: Some(v),
            } if is_exact(v) => Some((name.as_str(), v.as_str())),
            _ => None,
        };
        if let Some(hit) = key.and_then(|(name, version)| self.cache.load(name, version)) {
            eprintln!("  {label}: cached");
            return Ok(hit);
        }
        eprintln!("  {label}: observing...");
        let raw = self.sandbox.observe(target)?;
        let profile =
            profile::build(raw.dir.path()).with_context(|| format!("analyzing {label}"))?;
        if let Some((name, version)) = key {
            if let Err(e) = self.cache.store(name, version, &profile) {
                eprintln!("  warning: could not cache the result: {e:#}");
            }
        }
        Ok(profile)
    }
}

fn diff_targets(args: &[String]) -> Result<(Target, Target)> {
    match args {
        [old, new] if is_tarball(old) && is_tarball(new) => Ok((tarball(old)?, tarball(new)?)),
        [name, old, new] => {
            validate(name, "package name")?;
            validate(old, "version")?;
            validate(new, "version")?;
            let registry = |v: &String| Target::Registry {
                name: name.clone(),
                version: Some(v.clone()),
            };
            Ok((registry(old), registry(new)))
        }
        _ => bail!("expected `<package> <old-version> <new-version>` or two .tgz files"),
    }
}

fn scan_target(arg: &str) -> Result<Target> {
    if is_tarball(arg) {
        return tarball(arg);
    }
    let (name, version) = split_spec(arg);
    validate(name, "package name")?;
    if let Some(v) = version {
        validate(v, "version")?;
    }
    Ok(Target::Registry {
        name: name.to_string(),
        version: version.map(str::to_string),
    })
}

fn is_tarball(arg: &str) -> bool {
    arg.ends_with(".tgz") || arg.ends_with(".tar.gz")
}

fn tarball(arg: &str) -> Result<Target> {
    let path = Path::new(arg);
    if !path.is_file() {
        bail!("`{arg}` is not a file");
    }
    Ok(Target::Tarball(
        path.canonicalize()
            .with_context(|| format!("resolving `{arg}`"))?,
    ))
}

/// Split `name@version`, keeping the leading `@` of scoped packages.
fn split_spec(spec: &str) -> (&str, Option<&str>) {
    match spec.rfind('@') {
        Some(at) if at > 0 => (&spec[..at], Some(&spec[at + 1..])),
        _ => (spec, None),
    }
}

/// `1.2.3`, `1.2.3-beta.1`: a concrete version rather than a tag or range.
fn is_exact(version: &str) -> bool {
    let core = version.split(['-', '+']).next().unwrap_or("");
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Names and versions become arguments of commands inside the sandbox, so
/// only the characters npm itself allows are accepted.
fn validate(value: &str, what: &str) -> Result<()> {
    let ok = !value.is_empty()
        && value.len() <= 214
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@/._~-+^<>=*| ".contains(&b));
    if !ok {
        bail!("`{value}` is not a valid {what}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_specs() {
        assert_eq!(split_spec("left-pad@1.3.0"), ("left-pad", Some("1.3.0")));
        assert_eq!(
            split_spec("@scope/name@2.0.0"),
            ("@scope/name", Some("2.0.0"))
        );
        assert_eq!(split_spec("@scope/name"), ("@scope/name", None));
        assert_eq!(split_spec("plain"), ("plain", None));
    }

    #[test]
    fn recognizes_exact_versions() {
        assert!(is_exact("1.2.3"));
        assert!(is_exact("1.2.3-beta.1"));
        assert!(!is_exact("latest"));
        assert!(!is_exact("^1.2.3"));
        assert!(!is_exact("1.2"));
    }

    #[test]
    fn rejects_hostile_input() {
        assert!(validate("left-pad", "package name").is_ok());
        assert!(validate("@babel/core", "package name").is_ok());
        assert!(validate("--registry=http://evil", "package name").is_err());
        assert!(validate("a; rm -rf /", "package name").is_err());
        assert!(validate("$(id)", "version").is_err());
        assert!(validate("", "version").is_err());
    }

    #[test]
    fn parses_diff_arguments() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let (old, new) = diff_targets(&args(&["left-pad", "1.2.0", "1.3.0"])).unwrap();
        assert_eq!(
            old,
            Target::Registry {
                name: "left-pad".into(),
                version: Some("1.2.0".into())
            }
        );
        assert_eq!(new.label(), "left-pad@1.3.0");
        assert!(diff_targets(&args(&["left-pad", "1.3.0"])).is_err());
        assert!(diff_targets(&args(&["missing-a.tgz", "missing-b.tgz"])).is_err());
    }
}
