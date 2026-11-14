//! Runs a package inside a throwaway container and collects raw evidence.
//!
//! The container runtime is driven through its CLI so that pkgsnitch stays a
//! small static binary and works with any Docker-compatible engine.

use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use tempfile::TempDir;

use crate::plan::Available;

const ASSETS: &[(&str, &str)] = &[
    ("Dockerfile", include_str!("../sandbox/Dockerfile")),
    ("probe.js", include_str!("../sandbox/probe.js")),
    ("fetch.sh", include_str!("../sandbox/fetch.sh")),
    ("trace.sh", include_str!("../sandbox/trace.sh")),
    ("honey.sh", include_str!("../sandbox/honey.sh")),
    ("pyfetch.py", include_str!("../sandbox/pyfetch.py")),
    ("pymodules.py", include_str!("../sandbox/pymodules.py")),
];

/// Where a copied-in tarball lives inside the sandbox.
const TARBALL: &str = "/tmp/pkgsnitch-target.tgz";

/// A package ecosystem pkgsnitch can observe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    Npm,
    PyPI,
}

impl Ecosystem {
    /// The name used on the command line, in the sandbox and in the cache.
    pub fn id(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPI => "pypi",
        }
    }
}

/// What to observe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// An empty project: everything the package manager does on its own.
    Baseline(Ecosystem),
    Registry {
        ecosystem: Ecosystem,
        name: String,
        version: Option<String>,
    },
    /// A local `npm pack` tarball.
    Tarball(PathBuf),
}

impl Target {
    pub fn ecosystem(&self) -> Ecosystem {
        match self {
            Target::Baseline(ecosystem) | Target::Registry { ecosystem, .. } => *ecosystem,
            Target::Tarball(_) => Ecosystem::Npm,
        }
    }

    pub fn label(&self) -> String {
        match self {
            Target::Baseline(_) => "empty baseline".into(),
            Target::Registry {
                ecosystem: Ecosystem::PyPI,
                ..
            } => format!("pypi:{}", self.spec()),
            Target::Registry { .. } => self.spec(),
            Target::Tarball(path) => path.display().to_string(),
        }
    }

    /// The requirement as the ecosystem's own installer writes it.
    fn spec(&self) -> String {
        match self {
            Target::Registry {
                name,
                version: None,
                ..
            } => name.clone(),
            Target::Registry {
                ecosystem: Ecosystem::Npm,
                name,
                version: Some(v),
            } => format!("{name}@{v}"),
            Target::Registry {
                ecosystem: Ecosystem::PyPI,
                name,
                version: Some(v),
            } => format!("{name}=={v}"),
            Target::Baseline(_) | Target::Tarball(_) => String::new(),
        }
    }
}

pub struct Sandbox {
    runtime: String,
    image: String,
    timeout: u32,
}

/// Raw output of one observation; analyzed by [`crate::profile`].
pub struct RawRun {
    pub dir: TempDir,
}

impl Sandbox {
    pub fn new(runtime: &str, timeout: u32) -> Result<Self> {
        let probe = Command::new(runtime)
            .args(["version", "--format", "{{.Server.Version}}"])
            .stdin(Stdio::null())
            .output();
        match probe {
            Ok(out) if out.status.success() => {}
            Ok(out) => bail!(
                "`{runtime}` is installed but its daemon is not reachable:\n{}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
            Err(e) => bail!(
                "could not run `{runtime}` ({e}). pkgsnitch needs Docker to sandbox packages."
            ),
        }
        Ok(Self {
            runtime: runtime.to_string(),
            image: format!("pkgsnitch-npm:{:016x}", assets_hash()),
            timeout,
        })
    }

    /// Identifies the sandbox contents; part of the cache key.
    pub fn fingerprint(&self) -> &str {
        self.image.rsplit(':').next().unwrap_or(&self.image)
    }

    /// Build the sandbox image unless this exact version already exists.
    pub fn ensure_image(&self) -> Result<()> {
        if self.run(&["image", "inspect", &self.image]).is_ok() {
            return Ok(());
        }
        eprintln!("  building sandbox image (first run only, takes a minute)...");
        let ctx = tempfile::tempdir()?;
        for (name, body) in ASSETS {
            // Shell scripts must keep LF endings even when built on Windows.
            std::fs::write(ctx.path().join(name), body.replace("\r\n", "\n"))?;
        }
        let dir = ctx
            .path()
            .to_str()
            .context("temp path is not valid UTF-8")?;
        self.run(&["build", "--quiet", "--tag", &self.image, dir])
            .context("building the sandbox image failed")?;
        Ok(())
    }

    /// Install and exercise one target.
    pub fn observe(&self, target: &Target) -> Result<RawRun> {
        let container = Container::start(self)?;
        let id = container.id.as_str();
        let timeout = self.timeout.to_string();

        let ecosystem = target.ecosystem().id();
        let spec = match target {
            Target::Baseline(_) | Target::Registry { .. } => target.spec(),
            Target::Tarball(path) => {
                // Streamed in as the sandbox user: `docker cp` would keep the
                // host's file owner, which the capability-less container
                // cannot change afterwards.
                let file = File::open(path)
                    .with_context(|| format!("could not open `{}`", path.display()))?;
                let write = format!("cat > {TARBALL}");
                self.run_with(
                    &[
                        "exec",
                        "--interactive",
                        "--user",
                        "dev",
                        id,
                        "sh",
                        "-c",
                        &write,
                    ],
                    Stdio::from(file),
                )
                .with_context(|| format!("could not copy `{}` into the sandbox", path.display()))?;
                TARBALL.to_string()
            }
        };

        // Phase 0: download only. No package code runs while the network is up.
        self.run(&[
            "exec",
            "--user",
            "dev",
            id,
            "/opt/pkgsnitch/fetch.sh",
            ecosystem,
            &spec,
        ])
        .with_context(|| format!("could not fetch {}", target.label()))?;

        // Secure what the fetch recorded, and plant the honeytokens, before
        // any package code runs: /probe is writable by root only.
        self.run(&[
            "exec", "--user", "root", id, "cp", "-r", "/out/.", "/probe/",
        ])?;
        self.run(&["exec", "--user", "dev", id, "/opt/pkgsnitch/honey.sh"])?;

        // Cut the cable, then point DNS at the sinkhole.
        self.run(&["network", "disconnect", "bridge", id])
            .context("could not disconnect the sandbox network")?;
        self.run(&[
            "exec",
            "--user",
            "root",
            id,
            "sh",
            "-c",
            "echo 'nameserver 127.0.0.1' > /etc/resolv.conf",
        ])?;
        self.run(&[
            "exec",
            "--detach",
            "--user",
            "root",
            id,
            "node",
            "/opt/pkgsnitch/probe.js",
        ])?;
        self.run(&["exec", id, "sh", "-c", "i=0; until [ -e /probe/ready ]; do i=$((i+1)); [ $i -gt 100 ] && exit 1; sleep 0.1; done"])
            .context("the network sinkhole did not start")?;

        // Phases 1 and 2: run the code, watched. The tracer is root; the code
        // it starts is the unprivileged user.
        let trace = |phase: &str| {
            self.run(&[
                "exec",
                "--user",
                "root",
                id,
                "/opt/pkgsnitch/trace.sh",
                &timeout,
                phase,
                ecosystem,
            ])
        };
        trace("install")?;
        // Anything the install phase left running must not act during the
        // import phase. `kill -1` as that user ends all of its processes,
        // including the kill itself, hence no check of the result.
        let _ = self.run(&["exec", "--user", "dev", id, "sh", "-c", "kill -9 -1"]);
        trace("import")?;

        let dir = tempfile::tempdir()?;
        self.copy_out(id, "/probe/.", dir.path())?;
        Ok(RawRun { dir })
    }

    /// Ask the registry which versions of each package exist. Packages it
    /// does not know are left out of the result.
    pub fn available_versions(&self, names: &[String]) -> Result<BTreeMap<String, Available>> {
        if names.is_empty() {
            return Ok(BTreeMap::new());
        }
        // The lookup runs in the sandbox, so the host needs no npm of its own.
        // One line per package: its name, a tab, and npm's JSON on one line.
        const SCRIPT: &str = r#"for p in "$@"; do v=$(npm view --json -- "$p" dist-tags.latest versions 2>/dev/null | tr -d '\n') && printf '%s\t%s\n' "$p" "$v"; done"#;
        let container = Container::start(self)?;
        let mut args = vec![
            "exec",
            "--user",
            "dev",
            container.id.as_str(),
            "sh",
            "-c",
            SCRIPT,
            "sh",
        ];
        args.extend(names.iter().map(String::as_str));
        let out = self.run(&args).context("could not query the registry")?;
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|line| line.split_once('\t'))
            .filter_map(|(name, json)| Some((name.to_string(), Available::parse(json)?)))
            .collect())
    }

    fn copy_out(&self, id: &str, from: &str, to: &Path) -> Result<()> {
        let to = to.to_str().context("temp path is not valid UTF-8")?;
        self.run(&["cp", &format!("{id}:{from}"), to]).map(drop)
    }

    fn run(&self, args: &[&str]) -> Result<Output> {
        self.run_with(args, Stdio::null())
    }

    fn run_with(&self, args: &[&str], stdin: Stdio) -> Result<Output> {
        let out = Command::new(&self.runtime)
            .args(args)
            .stdin(stdin)
            .output()
            .with_context(|| format!("could not run `{}`", self.runtime))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            bail!(
                "`{} {}` failed:\n{}{}",
                self.runtime,
                args.join(" "),
                stdout.trim_end(),
                stderr.trim_end()
            );
        }
        Ok(out)
    }
}

/// A running sandbox container, removed on drop.
struct Container<'a> {
    sandbox: &'a Sandbox,
    id: String,
}

impl<'a> Container<'a> {
    fn start(sandbox: &'a Sandbox) -> Result<Self> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let id = format!("pkgsnitch-{}-{nanos}", std::process::id());
        sandbox
            .run(&[
                "run",
                "--detach",
                // Removed by the engine once it stops, even if pkgsnitch
                // itself was interrupted and could not clean up.
                "--rm",
                "--name",
                &id,
                "--label",
                "pkgsnitch=1",
                // The observed code runs as an ordinary user: it holds no
                // capabilities, cannot gain any, and is bounded in processes
                // and memory. Root keeps only what the tracer needs to start
                // that user's process and watch it.
                "--cap-drop",
                "ALL",
                "--cap-add",
                "SETUID",
                "--cap-add",
                "SETGID",
                "--cap-add",
                "SYS_PTRACE",
                // strace resolves file descriptors through /proc/<pid>/fd,
                // which belongs to the observed user.
                "--cap-add",
                "DAC_READ_SEARCH",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "1024",
                "--memory",
                "2g",
                // Lets the capability-less sinkhole bind ports 53/80/443.
                "--sysctl",
                "net.ipv4.ip_unprivileged_port_start=0",
                &sandbox.image,
            ])
            .context("could not start the sandbox container")?;
        Ok(Self { sandbox, id })
    }
}

impl Drop for Container<'_> {
    fn drop(&mut self) {
        let _ = self.sandbox.run(&["rm", "--force", "--volumes", &self.id]);
    }
}

/// FNV-1a over all sandbox files: a stable tag without a hashing dependency.
fn assets_hash() -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for (name, body) in ASSETS {
        for byte in name
            .bytes()
            .chain(body.bytes().filter(|b| *b != b'\r'))
            .chain([0])
        {
            h ^= u64::from(byte);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    h
}
