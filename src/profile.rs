//! Builds a [`Profile`] from the raw files a sandbox run leaves behind, and
//! caches finished profiles on disk.

use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;

use crate::canary;
use crate::extract::{self, Behaviors};
use crate::model::{Behavior, Kind, Manifest, Observed, Phase, PhaseStat, Profile};
use crate::rules;

const PHASES: [Phase; 2] = [Phase::Install, Phase::Import];
const LIFECYCLE: [&str; 3] = ["preinstall", "install", "postinstall"];

/// Analyze the output directory of one sandbox run.
pub fn build(dir: &Path) -> Result<Profile> {
    let name = fs::read_to_string(dir.join("name")).unwrap_or_default();
    let name = name.trim();
    let mut behaviors = Behaviors::new();
    let mut phases = Vec::new();

    for phase in PHASES {
        let label = phase.label();
        let trace = dir.join(format!("{label}.trace"));
        let mut syscalls = 0;
        if let Ok(file) = File::open(&trace) {
            let (found, count) = extract::from_trace(phase, BufReader::new(file));
            syscalls = count;
            for (behavior, n) in found {
                *behaviors.entry(behavior).or_insert(0) += n;
            }
        }
        let exit_code = fs::read_to_string(dir.join(format!("{label}.rc")))
            .ok()
            .and_then(|s| s.trim().parse().ok());
        phases.push(PhaseStat {
            phase,
            exit_code,
            syscalls,
        });
    }

    let windows = phase_windows(&fs::read_to_string(dir.join("times")).unwrap_or_default());
    for line in fs::read_to_string(dir.join("net.jsonl"))
        .unwrap_or_default()
        .lines()
    {
        let Ok(event) = serde_json::from_str::<NetEvent>(line) else {
            continue;
        };
        let Some(phase) = windows
            .iter()
            .find(|w| (w.1..=w.2).contains(&event.ts))
            .map(|w| w.0)
        else {
            continue;
        };
        if let Some((kind, target)) = event.describe() {
            let mut record = |kind, target| {
                let behavior = Behavior {
                    phase,
                    kind,
                    target,
                    actor: String::new(),
                };
                *behaviors.entry(behavior).or_insert(0) += 1;
            };
            if event.carries_secret() {
                record(
                    Kind::Exfil,
                    format!("{}: {target}", rules::kind_title(kind)),
                );
            }
            record(kind, target);
        }
    }

    let manifest_json = read_json(&dir.join("manifest.json"));
    let version = manifest_json
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or("0")
        .to_string();
    Ok(Profile {
        name: name.to_string(),
        version,
        behaviors: behaviors
            .into_iter()
            .map(|(behavior, count)| Observed { behavior, count })
            .collect(),
        manifest: manifest(&manifest_json, &read_json(&dir.join("lock.json")), name),
        phases,
    })
}

/// One line of the sinkhole's log.
#[derive(Deserialize)]
struct NetEvent {
    ts: u64,
    t: String,
    name: Option<String>,
    sni: Option<String>,
    host: Option<String>,
    method: Option<String>,
    path: Option<String>,
    port: Option<u16>,
    /// The first bytes the client sent, for unencrypted connections.
    data: Option<String>,
}

impl NetEvent {
    /// Whether a planted secret shows up in the name asked for or the
    /// bytes sent.
    fn carries_secret(&self) -> bool {
        [&self.name, &self.host, &self.path, &self.data]
            .into_iter()
            .flatten()
            .any(|text| canary::leaked(text))
    }

    fn describe(&self) -> Option<(Kind, String)> {
        let port = self.port.unwrap_or(0);
        match self.t.as_str() {
            "dns" => Some((Kind::Dns, self.name.clone()?)),
            "tls" => Some((
                Kind::Tls,
                format!(
                    "{}:{port}",
                    self.sni.as_deref().unwrap_or("(no server name)")
                ),
            )),
            "http" => Some((
                Kind::Http,
                format!(
                    "{} http://{}{}",
                    self.method.as_deref().unwrap_or("?"),
                    self.host.as_deref().unwrap_or("(no host)"),
                    self.path.as_deref().unwrap_or("/")
                ),
            )),
            "tcp" => Some((Kind::Connect, format!("raw TCP to sinkhole port {port}"))),
            _ => None,
        }
    }
}

/// Parse `phase start end` lines (milliseconds since the epoch).
fn phase_windows(times: &str) -> Vec<(Phase, u64, u64)> {
    times
        .lines()
        .filter_map(|line| {
            let mut f = line.split_whitespace();
            let phase = match f.next()? {
                "install" => Phase::Install,
                "import" => Phase::Import,
                _ => return None,
            };
            Some((phase, f.next()?.parse().ok()?, f.next()?.parse().ok()?))
        })
        .collect()
}

fn read_json(path: &Path) -> Value {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null)
}

/// Collect static facts from the package's `package.json` and the lockfile.
fn manifest(package_json: &Value, lock: &Value, name: &str) -> Manifest {
    let mut m = Manifest::default();
    if let Some(scripts) = package_json.get("scripts").and_then(Value::as_object) {
        for key in LIFECYCLE {
            if let Some(cmd) = scripts.get(key).and_then(Value::as_str) {
                m.scripts.insert(key.to_string(), cmd.to_string());
            }
        }
    }
    let packages = lock.get("packages").and_then(Value::as_object);
    for (path, info) in packages.into_iter().flatten() {
        // Keys look like `node_modules/a/node_modules/@scope/b`.
        let Some(at) = path.rfind("node_modules/") else {
            continue;
        };
        let dep = &path[at + "node_modules/".len()..];
        if dep == name {
            continue;
        }
        let version = info.get("version").and_then(Value::as_str).unwrap_or("?");
        m.packages
            .entry(dep.to_string())
            .or_default()
            .insert(version.to_string());
        if info.get("hasInstallScript").and_then(Value::as_bool) == Some(true) {
            m.install_scripts.insert(dep.to_string());
        }
    }
    m
}

/// On-disk cache of finished profiles, keyed by package, version, pkgsnitch
/// version and sandbox contents.
pub struct Cache {
    root: Option<PathBuf>,
    key: String,
}

impl Cache {
    pub fn new(enabled: bool, sandbox_fingerprint: &str) -> Self {
        let root = enabled.then(cache_root).flatten();
        Self {
            root,
            key: format!("{}-{sandbox_fingerprint}", env!("CARGO_PKG_VERSION")),
        }
    }

    fn path(&self, name: &str, version: &str) -> Option<PathBuf> {
        let safe = |s: &str| {
            if s.is_empty() {
                "_baseline".to_string()
            } else {
                s.replace(['/', '\\', ':'], "__")
            }
        };
        Some(
            self.root
                .as_ref()?
                .join("npm")
                .join(safe(name))
                .join(format!("{}-{}.json", safe(version), self.key)),
        )
    }

    pub fn load(&self, name: &str, version: &str) -> Option<Profile> {
        let text = fs::read_to_string(self.path(name, version)?).ok()?;
        serde_json::from_str(&text).ok()
    }

    pub fn store(&self, name: &str, version: &str, profile: &Profile) -> Result<()> {
        let Some(path) = self.path(name, version) else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, serde_json::to_vec(profile)?)
            .with_context(|| format!("writing {}", path.display()))
    }
}

fn cache_root() -> Option<PathBuf> {
    let var = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    var("PKGSNITCH_CACHE")
        .or_else(|| var("XDG_CACHE_HOME").map(|p| p.join("pkgsnitch")))
        .or_else(|| var("LOCALAPPDATA").map(|p| p.join("pkgsnitch").join("cache")))
        .or_else(|| var("HOME").map(|p| p.join(".cache").join("pkgsnitch")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_manifest_and_lock() {
        let pkg = json!({ "version": "2.0.0", "scripts": { "postinstall": "node x.js", "test": "jest" } });
        let lock = json!({ "packages": {
            "": { "name": "pkgsnitch-probe" },
            "node_modules/target": { "version": "2.0.0", "hasInstallScript": true },
            "node_modules/a": { "version": "1.0.0" },
            "node_modules/b/node_modules/a": { "version": "0.9.0" },
            "node_modules/@s/native": { "version": "3.1.0", "hasInstallScript": true }
        }});
        let m = manifest(&pkg, &lock, "target");
        assert_eq!(m.scripts.len(), 1);
        assert_eq!(m.scripts["postinstall"], "node x.js");
        assert_eq!(m.packages["a"].len(), 2);
        assert!(!m.packages.contains_key("target"));
        assert!(m.install_scripts.contains("@s/native"));
    }

    #[test]
    fn attributes_network_events_to_phases() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("times"),
            "install 1000 2000\nimport 2001 3000\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("net.jsonl"),
            concat!(
                r#"{"ts":1500,"t":"dns","name":"evil.example","qtype":1}"#, "\n",
                r#"{"ts":2500,"t":"tls","port":443,"sni":"api.example"}"#, "\n",
                r#"{"ts":2600,"t":"http","port":80,"method":"POST","path":"/c","host":"x.example"}"#, "\n",
                r#"{"ts":9999,"t":"dns","name":"late.example","qtype":1}"#, "\n",
            ),
        )
        .unwrap();
        fs::write(dir.path().join("name"), "x").unwrap();
        let p = build(dir.path()).unwrap();
        assert_eq!(p.name, "x");
        let got: Vec<_> = p
            .behaviors
            .iter()
            .map(|o| {
                (
                    o.behavior.phase,
                    o.behavior.kind,
                    o.behavior.target.as_str(),
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                (Phase::Install, Kind::Dns, "evil.example"),
                (Phase::Import, Kind::Http, "POST http://x.example/c"),
                (Phase::Import, Kind::Tls, "api.example:443"),
            ]
        );
    }
}
