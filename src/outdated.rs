//! Version management: which pinned dependencies are behind their registry.
//!
//! Unlike the rest of pkgsnitch this runs no package code. It reads the
//! dependency files of a project, asks each registry for the latest stable
//! version, and reports the gap. It covers more ecosystems than the sandbox
//! does, because knowing that a version is old needs no sandbox.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use owo_colors::OwoColorize;
use serde::Serialize;

use crate::manifest::{self, Pinned, Registry};
use crate::model::SCHEMA;
use crate::plan::{self, Bump, Level};
use crate::report::Format;
use crate::sandbox::Ecosystem;

/// Lockfiles the behavioral commands already read; here they are just pins.
const SANDBOXED: [&str; 7] = [
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "poetry.lock",
    "uv.lock",
];

/// Directories that hold other people's projects, not this one's.
const SKIPPED: [&str; 8] = [
    "node_modules",
    "vendor",
    "target",
    "dist",
    "build",
    ".git",
    ".venv",
    "venv",
];

/// How deep `--recursive` looks.
const MAX_DEPTH: usize = 6;

/// A pin together with the file it was read from.
#[derive(Debug, Clone)]
pub struct Located {
    pub pinned: Pinned,
    pub file: String,
}

/// One dependency that is behind.
#[derive(Debug, Serialize)]
pub struct Entry {
    pub registry: Registry,
    pub name: String,
    pub current: String,
    pub latest: String,
    pub bump: Bump,
    pub file: String,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: u32,
    /// Distinct pins that were looked up.
    pub checked: usize,
    pub outdated: Vec<Entry>,
    /// Pins the registry could not answer for.
    pub unknown: Vec<String>,
}

/// Whether `name` is a dependency file this command reads.
fn is_dependency_file(name: &str) -> bool {
    SANDBOXED.contains(&name) || manifest::FILES.contains(&name) || name.ends_with(".csproj")
}

/// The dependency files of a project: `path` itself if it is a file,
/// otherwise the known files in the directory, and below it if asked.
pub fn discover(path: &Path, recursive: bool) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    let mut found = Vec::new();
    walk(path, recursive, 0, &mut found)?;
    found.sort();
    Ok(found)
}

fn walk(dir: &Path, recursive: bool, depth: usize, found: &mut Vec<PathBuf>) -> Result<()> {
    let entries = std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if recursive && depth < MAX_DEPTH && !SKIPPED.contains(&name.as_str()) {
                walk(&path, recursive, depth + 1, found)?;
            }
        } else if is_dependency_file(&name) {
            found.push(path);
        }
    }
    Ok(())
}

/// Read every pin from the given files.
pub fn collect(files: &[PathBuf], base: &Path) -> Result<Vec<Located>> {
    let mut all = Vec::new();
    for file in files {
        let text =
            std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        let name = file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let shown = file
            .strip_prefix(base)
            .unwrap_or(file)
            .to_string_lossy()
            .replace('\\', "/");
        let pins = match manifest::read(&name, &text) {
            Some(pins) => pins,
            None => sandboxed(&text, &shown)?,
        };
        all.extend(pins.into_iter().map(|pinned| Located {
            pinned,
            file: shown.clone(),
        }));
    }
    Ok(all)
}

/// The pins of an npm or Python lockfile, through the parsers the
/// behavioral commands use.
fn sandboxed(text: &str, label: &str) -> Result<Vec<Pinned>> {
    let lock = plan::lock_from_text(text, label)?;
    let registry = match lock.ecosystem {
        Ecosystem::Npm => Registry::Npm,
        Ecosystem::PyPI => Registry::PyPI,
    };
    Ok(lock
        .pins()
        .map(|(name, version)| Pinned {
            registry,
            name: name.to_string(),
            version: version.to_string(),
            direct: lock.is_direct(name),
        })
        .collect())
}

/// What to ask the registries: one line per distinct package.
pub fn questions(pins: &[Located]) -> String {
    let distinct: BTreeSet<(&str, &str)> = pins
        .iter()
        .map(|l| (l.pinned.registry.id(), l.pinned.name.as_str()))
        .collect();
    distinct
        .iter()
        .fold(String::new(), |mut out, (registry, name)| {
            let _ = writeln!(out, "{registry}\t{name}");
            out
        })
}

/// Combine the pins with the registries' answers (`registry\tname\tversion`
/// per line).
pub fn compare(pins: Vec<Located>, answers: &str, only_direct: bool) -> Report {
    let latest: BTreeMap<(&str, &str), &str> = answers
        .lines()
        .filter_map(|line| {
            let mut fields = line.splitn(3, '\t');
            Some(((fields.next()?, fields.next()?), fields.next()?.trim()))
        })
        .collect();

    let mut seen = BTreeSet::new();
    let mut outdated = Vec::new();
    let mut unknown = BTreeSet::new();
    for Located { pinned, file } in pins {
        // A file that does not tell direct from transitive counts as direct.
        if only_direct && pinned.direct == Some(false) {
            continue;
        }
        let id = pinned.registry.id();
        if !seen.insert((id, pinned.name.clone(), pinned.version.clone())) {
            continue;
        }
        let newest = latest
            .get(&(id, pinned.name.as_str()))
            .map(|v| v.to_string());
        let Some(newest) = newest else {
            unknown.insert(format!("{id}:{}", pinned.name));
            continue;
        };
        if plan::order(&pinned.version, &newest) == std::cmp::Ordering::Less {
            outdated.push(Entry {
                registry: pinned.registry,
                bump: plan::bump(&pinned.version, &newest),
                name: pinned.name,
                current: pinned.version,
                latest: newest,
                file,
            });
        }
    }
    // The biggest jumps first, then by name.
    outdated.sort_by(|a, b| (rank(b.bump), &a.name).cmp(&(rank(a.bump), &b.name)));
    Report {
        schema: SCHEMA,
        checked: seen.len(),
        outdated,
        unknown: unknown.into_iter().collect(),
    }
}

/// How far behind a pin is: major 3, minor 2, patch 1, anything else 0.
fn rank(bump: Bump) -> u8 {
    match bump {
        Bump::Major => 3,
        Bump::Minor => 2,
        Bump::Patch => 1,
        _ => 0,
    }
}

impl Report {
    /// Whether anything is behind by at least `level`.
    pub fn exceeds(&self, level: Level) -> bool {
        let needed = match level {
            Level::Patch => 1,
            Level::Minor => 2,
            Level::Major => 3,
        };
        self.outdated.iter().any(|entry| rank(entry.bump) >= needed)
    }

    fn summary(&self) -> String {
        let count = |wanted: u8| {
            self.outdated
                .iter()
                .filter(|e| rank(e.bump) == wanted)
                .count()
        };
        let mut text = format!(
            "{} of {} pinned versions are behind ({} major, {} minor, {} patch)",
            self.outdated.len(),
            self.checked,
            count(3),
            count(2),
            count(1)
        );
        if !self.unknown.is_empty() {
            let _ = write!(text, "; {} could not be looked up", self.unknown.len());
        }
        text
    }
}

pub fn render(report: &Report, format: Format) -> Result<String> {
    Ok(match format {
        Format::Terminal => terminal(report),
        Format::Json => serde_json::to_string_pretty(report)? + "\n",
        Format::Markdown => markdown(report),
        Format::Sarif => bail!("the sarif format is for `lock` and `updates`"),
    })
}

fn terminal(report: &Report) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "\n  {}  {}\n", "pkgsnitch".bold(), "outdated".bold());
    if report.outdated.is_empty() {
        let _ = writeln!(
            o,
            "  {} Every pinned version is the latest.",
            "ok".green().bold()
        );
    }
    let width = |text: fn(&Entry) -> &str| {
        report
            .outdated
            .iter()
            .map(|e| text(e).len())
            .max()
            .unwrap_or(0)
    };
    let (names, currents, latests) = (
        width(|e| &e.name),
        width(|e| &e.current),
        width(|e| &e.latest),
    );
    for e in &report.outdated {
        let label = format!("{:<5}", e.bump.label().to_uppercase());
        let label = match rank(e.bump) {
            3 => label.red().bold().to_string(),
            2 => label.yellow().bold().to_string(),
            1 => label.blue().to_string(),
            _ => label.dimmed().to_string(),
        };
        let _ = writeln!(
            o,
            "  {label}  {:<9}  {:<names$}  {:<currents$}  ->  {:<latests$}  {}",
            e.registry.id().dimmed(),
            e.name,
            e.current,
            e.latest,
            e.file.dimmed()
        );
    }
    let _ = writeln!(o, "\n  {}.", report.summary());
    o
}

fn markdown(report: &Report) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "### pkgsnitch outdated\n\n{}.\n", report.summary());
    if !report.outdated.is_empty() {
        o.push_str("| Behind by | Registry | Package | Pinned | Latest | File |\n|---|---|---|---|---|---|\n");
        for e in &report.outdated {
            let _ = writeln!(
                o,
                "| **{}** | {} | `{}` | {} | {} | `{}` |",
                e.bump.label(),
                e.registry.id(),
                e.name,
                e.current,
                e.latest,
                e.file
            );
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, text: &str) {
        let path = dir.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn finds_dependency_files() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "requirements.txt", "");
        write(dir.path(), "composer.lock", "{}");
        write(dir.path(), "App.csproj", "");
        write(dir.path(), "README.md", "");
        write(dir.path(), "services/api/go.mod", "");
        write(dir.path(), "node_modules/dep/package-lock.json", "{}");

        let names = |recursive| -> Vec<String> {
            discover(dir.path(), recursive)
                .unwrap()
                .iter()
                .map(|p| {
                    p.strip_prefix(dir.path())
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/")
                })
                .collect()
        };
        assert_eq!(
            names(false),
            ["App.csproj", "composer.lock", "requirements.txt"]
        );
        assert_eq!(
            names(true),
            [
                "App.csproj",
                "composer.lock",
                "requirements.txt",
                "services/api/go.mod"
            ]
        );
        assert_eq!(
            discover(&dir.path().join("composer.lock"), false)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn reports_what_is_behind_across_ecosystems() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "requirements.txt",
            "requests==2.31.0\nidna==3.7\nprivate-thing==1.0.0\n",
        );
        write(dir.path(), "go.mod", "module x\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n\tgolang.org/x/sys v0.20.0 // indirect\n)\n");
        write(
            dir.path(),
            "composer.lock",
            r#"{"packages":[{"name":"symfony/console","version":"v6.4.0"}]}"#,
        );
        write(dir.path(), "conanfile.txt", "[requires]\nzlib/1.3.1\n");

        let files = discover(dir.path(), false).unwrap();
        let pins = collect(&files, dir.path()).unwrap();
        assert_eq!(pins.len(), 7);
        let asked = questions(&pins);
        assert!(asked.contains("go\tgithub.com/gin-gonic/gin\n"));
        assert!(asked.contains("packagist\tsymfony/console\n"));
        assert_eq!(asked.lines().count(), 7);

        let answers = "pypi\trequests\t2.32.3\npypi\tidna\t3.7\ngo\tgithub.com/gin-gonic/gin\t1.9.2\n\
                       go\tgolang.org/x/sys\t0.21.0\npackagist\tsymfony/console\t7.1.0\nconan\tzlib\t1.3.1\n";
        let report = compare(pins.clone(), answers, false);
        let rows: Vec<_> = report
            .outdated
            .iter()
            .map(|e| {
                (
                    e.registry.id(),
                    e.name.as_str(),
                    e.current.as_str(),
                    e.latest.as_str(),
                    e.bump.label(),
                    e.file.as_str(),
                )
            })
            .collect();
        assert_eq!(
            rows,
            [
                (
                    "packagist",
                    "symfony/console",
                    "6.4.0",
                    "7.1.0",
                    "major",
                    "composer.lock"
                ),
                (
                    "go",
                    "golang.org/x/sys",
                    "0.20.0",
                    "0.21.0",
                    "minor",
                    "go.mod"
                ),
                (
                    "pypi",
                    "requests",
                    "2.31.0",
                    "2.32.3",
                    "minor",
                    "requirements.txt"
                ),
                (
                    "go",
                    "github.com/gin-gonic/gin",
                    "1.9.1",
                    "1.9.2",
                    "patch",
                    "go.mod"
                ),
            ]
        );
        assert_eq!(report.checked, 7);
        assert_eq!(report.unknown, ["pypi:private-thing"]);
        assert!(report.exceeds(Level::Major) && report.exceeds(Level::Patch));
        assert_eq!(
            report.summary(),
            "4 of 7 pinned versions are behind (1 major, 2 minor, 1 patch); 1 could not be looked up"
        );

        // `--direct` leaves out what go.mod marks as indirect.
        let direct = compare(pins, answers, true);
        assert!(direct.outdated.iter().all(|e| e.name != "golang.org/x/sys"));
        assert!(!compare(Vec::new(), "", false).exceeds(Level::Patch));

        let text = render(&report, Format::Terminal).unwrap();
        assert!(text.contains("symfony/console"));
        assert!(render(&report, Format::Markdown).unwrap().contains(
            "| **major** | packagist | `symfony/console` | 6.4.0 | 7.1.0 | `composer.lock` |"
        ));
        assert!(render(&report, Format::Sarif).is_err());
    }
}
