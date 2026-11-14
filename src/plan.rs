//! Patch management: work out which dependency updates exist, and turn the
//! behavioral diff of each one into advice (apply, review or hold).

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context, Result};
use owo_colors::OwoColorize;
use serde::Serialize;
use serde_json::Value;

use crate::lockfile::{self, normalize_python};
use crate::model::{Change, Report, Severity, SCHEMA};
use crate::report::Format;
use crate::sandbox::Ecosystem;

/// What a project pins: a `package-lock.json` or a `requirements.txt`.
#[derive(Debug)]
pub struct Lock {
    pub ecosystem: Ecosystem,
    /// Every installed package with all versions present in the tree.
    packages: BTreeMap<String, BTreeSet<String>>,
    /// Version installed at the top level, i.e. what `require(name)` loads.
    top: BTreeMap<String, String>,
    /// Names the project itself depends on.
    direct: BTreeSet<String>,
    /// The subset of `direct` that are development dependencies.
    dev: BTreeSet<String>,
}

pub fn read_lock(path: &Path) -> Result<Lock> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    // yarn, pnpm and the Python TOML locks are recognized by their content.
    if let Some((ecosystem, pins)) = lockfile::pinned(&text) {
        return Ok(Lock::from_pins(ecosystem, pins));
    }
    // npm's lockfile is JSON; anything else is read as pip requirements.
    if !text.trim_start().starts_with('{') {
        return Ok(parse_requirements(&text));
    }
    let json: Value =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    parse_lock(&json).with_context(|| format!("{} is not a usable lockfile", path.display()))
}

fn parse_lock(json: &Value) -> Result<Lock> {
    let packages = json
        .get("packages")
        .and_then(Value::as_object)
        .context("no `packages` section (lockfileVersion 2 or newer is required)")?;
    let mut lock = Lock::empty(Ecosystem::Npm);
    for (path, info) in packages {
        if path.is_empty() {
            for (section, is_dev) in [
                ("dependencies", false),
                ("optionalDependencies", false),
                ("devDependencies", true),
            ] {
                for name in info
                    .get(section)
                    .and_then(Value::as_object)
                    .into_iter()
                    .flatten()
                    .map(|(k, _)| k)
                {
                    lock.direct.insert(name.clone());
                    if is_dev {
                        lock.dev.insert(name.clone());
                    }
                }
            }
            continue;
        }
        // Workspace links have no version of their own.
        if info.get("link").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let Some(at) = path.rfind("node_modules/") else {
            continue;
        };
        let name = &path[at + "node_modules/".len()..];
        let Some(version) = info.get("version").and_then(Value::as_str) else {
            continue;
        };
        lock.packages
            .entry(name.to_string())
            .or_default()
            .insert(version.to_string());
        if at == 0 {
            lock.top.insert(name.to_string(), version.to_string());
        }
    }
    Ok(lock)
}

/// Read pinned requirements (`name==1.2.3`), as `pip freeze` and pip-tools
/// write them. Unpinned lines, options and URLs are skipped: without an
/// exact version there is nothing to compare.
fn parse_requirements(text: &str) -> Lock {
    let mut lock = Lock::empty(Ecosystem::PyPI);
    for line in text.lines() {
        // Drop comments, environment markers and hash options.
        let line = line.split(" #").next().unwrap_or("");
        let line = line.split([';', ' ']).next().unwrap_or("").trim();
        if line.starts_with(['#', '-']) {
            continue;
        }
        let Some((name, version)) = line.split_once("==") else {
            continue;
        };
        // `requests[socks]` installs the same distribution as `requests`.
        let name = name.split('[').next().unwrap_or(name).trim();
        if name.is_empty() || version.is_empty() || version.contains('*') {
            continue;
        }
        let name = normalize_python(name);
        lock.packages
            .entry(name.clone())
            .or_default()
            .insert(version.to_string());
        lock.top.insert(name.clone(), version.to_string());
        lock.direct.insert(name);
    }
    lock
}

impl Lock {
    /// A lockfile that only says which versions are present. It does not
    /// tell direct from transitive dependencies, so `updates` finds nothing
    /// to propose from it; `lock` compares it like any other.
    fn from_pins(ecosystem: Ecosystem, pins: Vec<lockfile::Pin>) -> Self {
        let mut lock = Self::empty(ecosystem);
        for (name, version) in pins {
            lock.packages.entry(name).or_default().insert(version);
        }
        lock
    }

    /// Whether the file names the project's own dependencies.
    pub fn knows_direct(&self) -> bool {
        !self.direct.is_empty()
    }

    fn empty(ecosystem: Ecosystem) -> Self {
        Self {
            ecosystem,
            packages: BTreeMap::new(),
            top: BTreeMap::new(),
            direct: BTreeSet::new(),
            dev: BTreeSet::new(),
        }
    }

    /// Direct dependencies with the version currently installed.
    pub fn direct(&self, include_dev: bool) -> impl Iterator<Item = (&str, &str)> {
        self.direct
            .iter()
            .filter(move |name| include_dev || !self.dev.contains(*name))
            .filter_map(|name| Some((name.as_str(), self.top.get(name)?.as_str())))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Bump {
    Patch,
    Minor,
    Major,
    Prerelease,
    Downgrade,
    /// The package was not in the tree before.
    Added,
    /// Not a comparable pair of semantic versions.
    Other,
}

impl Bump {
    fn label(self) -> &'static str {
        match self {
            Bump::Patch => "patch",
            Bump::Minor => "minor",
            Bump::Major => "major",
            Bump::Prerelease => "prerelease",
            Bump::Downgrade => "downgrade",
            Bump::Added => "new",
            Bump::Other => "other",
        }
    }
}

/// A version as its numeric release segments plus whatever follows them.
///
/// Covers npm (`1.2.3`, `1.2.3-beta.1+build`) and PEP 440 (`2.32`, `1.0rc1`,
/// `2024.2.2`). A non-empty tail marks a prerelease or other special build.
fn parse_version(v: &str) -> Option<(Vec<u64>, &str)> {
    let v = v.split('+').next()?;
    let end = v
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(v.len());
    let (core, tail) = v.split_at(end);
    let numbers: Option<Vec<u64>> = core
        .trim_end_matches('.')
        .split('.')
        .map(|p| p.parse().ok())
        .collect();
    let numbers = numbers.filter(|n| !n.is_empty())?;
    Some((numbers, tail.trim_start_matches(['-', '_', '.'])))
}

/// The `index`-th release segment; missing ones count as zero (1.0 = 1.0.0).
fn segment(numbers: &[u64], index: usize) -> u64 {
    numbers.get(index).copied().unwrap_or(0)
}

fn order(a: &str, b: &str) -> Ordering {
    match (parse_version(a), parse_version(b)) {
        (Some((x, xp)), Some((y, yp))) => (0..x.len().max(y.len()))
            .map(|i| segment(&x, i).cmp(&segment(&y, i)))
            .find(|o| o.is_ne())
            .unwrap_or(Ordering::Equal)
            .then_with(|| match (xp.is_empty(), yp.is_empty()) {
                // A release is newer than any of its prereleases.
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                _ => xp.cmp(yp),
            }),
        _ => a.cmp(b),
    }
}

fn bump(from: &str, to: &str) -> Bump {
    let (Some((a, _)), Some((b, _))) = (parse_version(from), parse_version(to)) else {
        return Bump::Other;
    };
    if order(from, to) == Ordering::Greater {
        return Bump::Downgrade;
    }
    match (0..a.len().max(b.len())).find(|i| segment(&a, *i) != segment(&b, *i)) {
        Some(0) => Bump::Major,
        Some(1) => Bump::Minor,
        Some(_) => Bump::Patch,
        None => Bump::Prerelease,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Update {
    pub ecosystem: Ecosystem,
    pub name: String,
    /// `None` when the package is new to the tree.
    pub from: Option<String>,
    pub to: String,
    pub bump: Bump,
    /// Whether the project depends on it directly.
    pub direct: bool,
}

impl Update {
    fn new(name: &str, from: Option<&str>, to: &str, direct: bool) -> Self {
        Self {
            ecosystem: Ecosystem::Npm,
            name: name.to_string(),
            from: from.map(str::to_string),
            to: to.to_string(),
            bump: from.map_or(Bump::Added, |f| bump(f, to)),
            direct,
        }
    }

    fn of(mut self, ecosystem: Ecosystem) -> Self {
        self.ecosystem = ecosystem;
        self
    }
}

/// Everything that differs between two lockfiles, as a pull request that
/// updates dependencies would change it. Direct dependencies come first.
pub fn changes(old: &Lock, new: &Lock) -> Vec<Update> {
    let mut out = Vec::new();
    for (name, versions) in &new.packages {
        let before = old.packages.get(name);
        let previous = before.and_then(|set| set.iter().max_by(|a, b| order(a, b)));
        for version in versions {
            if before.is_some_and(|set| set.contains(version)) {
                continue;
            }
            let update = Update::new(
                name,
                previous.map(String::as_str),
                version,
                new.direct.contains(name),
            );
            out.push(update.of(new.ecosystem));
        }
    }
    out.sort_by(|a, b| b.direct.cmp(&a.direct).then_with(|| a.name.cmp(&b.name)));
    out
}

/// What the registry offers for one package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Available {
    /// The version the `latest` tag points at.
    pub latest: String,
    pub versions: Vec<String>,
}

impl Available {
    /// Parse the output of `npm view --json <pkg> dist-tags.latest versions`.
    pub fn parse(json: &str) -> Option<Self> {
        let value: Value = serde_json::from_str(json).ok()?;
        let latest = value.get("dist-tags.latest")?.as_str()?.to_string();
        // npm prints a bare string instead of a list for a single version.
        let versions = match value.get("versions") {
            Some(Value::Array(list)) => list
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect(),
            Some(Value::String(only)) => vec![only.clone()],
            _ => vec![latest.clone()],
        };
        Some(Self { latest, versions })
    }

    /// The newest stable version above `installed` that stays within
    /// `level` and does not go past what the maintainers call latest.
    fn pick(&self, installed: &str, level: Level) -> Option<&str> {
        let (current, _) = parse_version(installed)?;
        self.versions
            .iter()
            .map(String::as_str)
            .filter(|v| {
                let Some((candidate, pre)) = parse_version(v) else {
                    return false;
                };
                pre.is_empty()
                    && order(installed, v) == Ordering::Less
                    && order(v, &self.latest) != Ordering::Greater
                    && match level {
                        Level::Patch => {
                            (0..2).all(|i| segment(&candidate, i) == segment(&current, i))
                        }
                        Level::Minor => segment(&candidate, 0) == segment(&current, 0),
                        Level::Major => true,
                    }
            })
            .max_by(|a, b| order(a, b))
    }
}

/// The largest version jump `updates` may propose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Level {
    /// Bug fixes only: 1.2.3 to 1.2.9
    Patch,
    /// New features too: 1.2.3 to 1.9.0
    Minor,
    /// Anything up to the latest release
    Major,
}

/// Direct dependencies for which the registry has something newer.
pub fn outdated(
    lock: &Lock,
    available: &BTreeMap<String, Available>,
    level: Level,
    include_dev: bool,
) -> Vec<Update> {
    lock.direct(include_dev)
        .filter_map(|(name, installed)| {
            let newer = available.get(name)?.pick(installed, level)?;
            Some(Update::new(name, Some(installed), newer, true).of(lock.ecosystem))
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Advice {
    /// Nothing new was observed; take the update.
    Apply,
    /// Clean enough to consider, but a person should look first.
    Review,
    /// New high-risk behavior; do not update until it is understood.
    Hold,
    /// The update could not be observed.
    Unknown,
}

impl Advice {
    fn label(self) -> &'static str {
        match self {
            Advice::Apply => "apply",
            Advice::Review => "review",
            Advice::Hold => "hold",
            Advice::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Outcome {
    #[serde(flatten)]
    pub update: Update,
    pub advice: Advice,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<Report>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Outcome {
    pub fn new(update: Update, result: Result<Report>) -> Self {
        let (advice, reason) = advise(&update, result.as_ref().map_err(|e| format!("{e:#}")));
        let (report, error) = match result {
            Ok(report) => (Some(report), None),
            Err(e) => (None, Some(format!("{e:#}"))),
        };
        Self {
            update,
            advice,
            reason,
            report,
            error,
        }
    }

    fn severity(&self) -> Severity {
        self.report.as_ref().map_or(Severity::Info, |r| r.verdict)
    }
}

fn advise(update: &Update, result: Result<&Report, String>) -> (Advice, String) {
    let report = match result {
        Ok(report) => report,
        Err(e) => return (Advice::Unknown, format!("could not be observed: {e}")),
    };
    let worst = report.findings.iter().find(|f| f.change != Change::Removed);
    match (report.verdict, update.bump) {
        (Severity::High | Severity::Critical, _) => {
            let what = worst.map_or(String::new(), |f| format!(": {} {}", f.title, f.target));
            (
                Advice::Hold,
                format!("new {} behavior{what}", report.verdict.label()),
            )
        }
        (Severity::Medium, _) => {
            let what = worst.map_or(String::new(), |f| format!(": {} {}", f.title, f.target));
            (Advice::Review, format!("new behavior{what}"))
        }
        (_, Bump::Major) => (
            Advice::Review,
            "no new behavior, but a major version: check the changelog for breaking changes".into(),
        ),
        (_, Bump::Downgrade) => (
            Advice::Review,
            "no new behavior, but this moves to an older version".into(),
        ),
        (_, Bump::Added) => (
            Advice::Apply,
            "new dependency, nothing notable at install or import time".into(),
        ),
        _ => (
            Advice::Apply,
            "no new behavior at install or import time".into(),
        ),
    }
}

/// The result of evaluating a set of updates.
#[derive(Debug, Serialize)]
pub struct Plan {
    pub schema: u32,
    pub verdict: Severity,
    pub outcomes: Vec<Outcome>,
    /// Updates that were found but not evaluated because of `--max`.
    pub skipped: usize,
    /// Whether to print the `npm install` line for the safe updates.
    #[serde(skip)]
    pub suggest_command: bool,
}

impl Plan {
    pub fn new(outcomes: Vec<Outcome>, skipped: usize, suggest_command: bool) -> Self {
        let verdict = outcomes
            .iter()
            .map(Outcome::severity)
            .max()
            .unwrap_or(Severity::Info);
        Self {
            schema: SCHEMA,
            verdict,
            outcomes,
            skipped,
            suggest_command,
        }
    }

    fn count(&self, advice: Advice) -> usize {
        self.outcomes.iter().filter(|o| o.advice == advice).count()
    }

    /// The command that applies every update rated safe, if there is one.
    fn apply_command(&self) -> Option<String> {
        let safe: Vec<String> = self
            .outcomes
            .iter()
            .filter(|o| o.advice == Advice::Apply && o.update.direct)
            .map(|o| match o.update.ecosystem {
                Ecosystem::Npm => format!("{}@{}", o.update.name, o.update.to),
                Ecosystem::PyPI => format!("{}=={}", o.update.name, o.update.to),
            })
            .collect();
        let installer = match self.outcomes.first()?.update.ecosystem {
            Ecosystem::Npm => "npm install",
            Ecosystem::PyPI => "pip install",
        };
        (self.suggest_command && !safe.is_empty())
            .then(|| format!("{installer} {}", safe.join(" ")))
    }

    fn summary(&self) -> String {
        let mut parts = Vec::new();
        for advice in [Advice::Apply, Advice::Review, Advice::Hold, Advice::Unknown] {
            let n = self.count(advice);
            if n > 0 {
                parts.push(format!("{n} {}", advice.label()));
            }
        }
        if self.skipped > 0 {
            parts.push(format!("{} not evaluated (raise --max)", self.skipped));
        }
        parts.join(", ")
    }
}

pub fn render(plan: &Plan, format: Format) -> String {
    match format {
        Format::Terminal => terminal(plan),
        Format::Json => serde_json::to_string_pretty(plan).expect("plan is serializable") + "\n",
        Format::Markdown => markdown(plan),
    }
}

fn versions(u: &Update) -> String {
    match &u.from {
        Some(from) => format!("{from} -> {}", u.to),
        None => format!("(new) {}", u.to),
    }
}

fn terminal(plan: &Plan) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "\n  {}  {}\n", "pkgsnitch".bold(), "patch plan".bold());
    if plan.outcomes.is_empty() {
        let _ = writeln!(o, "  {} Nothing to update.", "ok".green().bold());
        return o;
    }
    let name_width = plan
        .outcomes
        .iter()
        .map(|x| x.update.name.len())
        .max()
        .unwrap_or(0);
    let version_width = plan
        .outcomes
        .iter()
        .map(|x| versions(&x.update).len())
        .max()
        .unwrap_or(0);
    for x in &plan.outcomes {
        let tag = format!("{:<7}", x.advice.label().to_uppercase());
        let tag = match x.advice {
            Advice::Apply => tag.green().bold().to_string(),
            Advice::Review => tag.yellow().bold().to_string(),
            Advice::Hold => tag.white().on_red().bold().to_string(),
            Advice::Unknown => tag.dimmed().to_string(),
        };
        let _ = writeln!(
            o,
            "  {tag}  {:<name_width$}  {:<version_width$}  {:<10}  {}",
            x.update.name,
            versions(&x.update),
            x.update.bump.label().dimmed(),
            x.reason
        );
    }
    if let Some(command) = plan.apply_command() {
        let _ = writeln!(o, "\n  Safe to apply now:\n    {}", command.bold());
    }
    let _ = writeln!(
        o,
        "\n  {}. Run `pkgsnitch diff <package> <old> <new>` for the details of one update.",
        plan.summary()
    );
    o
}

fn markdown(plan: &Plan) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "### pkgsnitch patch plan\n");
    if plan.outcomes.is_empty() {
        o.push_str("Nothing to update.\n");
        return o;
    }
    let _ = writeln!(o, "{}\n", plan.summary());
    o.push_str("| Advice | Package | Version | Bump | Why |\n|---|---|---|---|---|\n");
    for x in &plan.outcomes {
        let _ = writeln!(
            o,
            "| **{}** | `{}` | {} | {} | {} |",
            x.advice.label(),
            x.update.name,
            versions(&x.update),
            x.update.bump.label(),
            x.reason.replace('|', "\\|").replace(['\n', '\r'], " ")
        );
    }
    if let Some(command) = plan.apply_command() {
        let _ = writeln!(o, "\nSafe to apply now:\n\n```\n{command}\n```");
    }
    for x in plan
        .outcomes
        .iter()
        .filter(|x| matches!(x.advice, Advice::Hold | Advice::Review))
    {
        if let Some(report) = &x.report {
            let _ = writeln!(
                o,
                "\n<details><summary>{} {}</summary>\n",
                x.update.name,
                versions(&x.update)
            );
            o.push_str(&crate::report::render(report, Format::Markdown));
            o.push_str("\n</details>\n");
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Finding, Phase};
    use serde_json::json;

    fn lock(root: Value, packages: &[(&str, &str)]) -> Lock {
        let mut map = serde_json::Map::new();
        map.insert(String::new(), root);
        for (path, version) in packages {
            map.insert((*path).to_string(), json!({ "version": version }));
        }
        parse_lock(&json!({ "lockfileVersion": 3, "packages": map })).unwrap()
    }

    fn report(verdict: Severity) -> Report {
        let findings = (verdict > Severity::Info)
            .then(|| Finding {
                severity: verdict,
                change: Change::Added,
                phase: Some(Phase::Install),
                title: "runs command".into(),
                target: "curl evil".into(),
                actor: String::new(),
                why: String::new(),
            })
            .into_iter()
            .collect();
        Report {
            schema: SCHEMA,
            package: "x".into(),
            old: None,
            new: "1".into(),
            verdict,
            findings,
            phases: vec![],
        }
    }

    #[test]
    fn orders_and_classifies_versions() {
        assert_eq!(order("1.2.3", "1.10.0"), Ordering::Less);
        assert_eq!(order("2.0.0", "2.0.0-rc.1"), Ordering::Greater);
        assert_eq!(bump("1.2.3", "1.2.4"), Bump::Patch);
        assert_eq!(bump("1.2.3", "1.3.0"), Bump::Minor);
        assert_eq!(bump("1.2.3", "2.0.0"), Bump::Major);
        assert_eq!(bump("2.0.0-rc.1", "2.0.0"), Bump::Prerelease);
        assert_eq!(bump("2.0.0", "1.9.9"), Bump::Downgrade);
        assert_eq!(bump("github:a/b", "1.0.0"), Bump::Other);
    }

    #[test]
    fn reads_lockfile_structure() {
        let l = lock(
            json!({ "dependencies": { "a": "^1.0.0" }, "devDependencies": { "d": "^3.0.0" } }),
            &[
                ("node_modules/a", "1.0.0"),
                ("node_modules/d", "3.0.0"),
                ("node_modules/t", "0.1.0"),
                ("node_modules/a/node_modules/t", "0.2.0"),
                ("node_modules/@s/p", "5.0.0"),
            ],
        );
        assert_eq!(l.direct(false).collect::<Vec<_>>(), [("a", "1.0.0")]);
        assert_eq!(
            l.direct(true).collect::<Vec<_>>(),
            [("a", "1.0.0"), ("d", "3.0.0")]
        );
        assert_eq!(l.packages["t"].len(), 2);
        assert!(l.packages.contains_key("@s/p"));
        assert!(parse_lock(&json!({ "lockfileVersion": 1, "dependencies": {} })).is_err());
    }

    #[test]
    fn finds_changes_between_lockfiles() {
        let root = json!({ "dependencies": { "a": "^1.0.0" } });
        let old = lock(
            root.clone(),
            &[
                ("node_modules/a", "1.0.0"),
                ("node_modules/t", "0.1.0"),
                ("node_modules/gone", "9.0.0"),
            ],
        );
        let new = lock(
            root,
            &[
                ("node_modules/a", "1.0.1"),
                ("node_modules/t", "0.1.0"),
                ("node_modules/fresh", "2.0.0"),
            ],
        );
        assert_eq!(
            changes(&old, &new),
            [
                Update::new("a", Some("1.0.0"), "1.0.1", true),
                Update::new("fresh", None, "2.0.0", false)
            ]
        );
        assert!(changes(&new, &new).is_empty());
    }

    #[test]
    fn finds_outdated_direct_dependencies() {
        let l = lock(
            json!({ "dependencies": { "a": "*", "b": "*" }, "devDependencies": { "d": "*" } }),
            &[
                ("node_modules/a", "1.0.0"),
                ("node_modules/b", "2.0.0"),
                ("node_modules/d", "3.0.0"),
            ],
        );
        let offer = |latest: &str, versions: &[&str]| Available {
            latest: latest.into(),
            versions: versions.iter().map(|v| v.to_string()).collect(),
        };
        let available: BTreeMap<String, Available> = [
            (
                "a",
                offer(
                    "2.1.0",
                    &[
                        "1.0.0",
                        "1.0.5",
                        "1.4.0",
                        "2.0.0",
                        "2.1.0",
                        "3.0.0-rc.1",
                        "3.0.0",
                    ],
                ),
            ),
            ("b", offer("2.0.0", &["1.9.0", "2.0.0"])),
            ("d", offer("4.0.0", &["3.0.0", "4.0.0"])),
        ]
        .into_iter()
        .map(|(name, offer)| (name.to_string(), offer))
        .collect();

        let to = |level, dev| -> Vec<(String, String)> {
            outdated(&l, &available, level, dev)
                .into_iter()
                .map(|u| (u.name, u.to))
                .collect()
        };
        // 3.0.0 exists but is beyond the `latest` tag, so it is never proposed.
        assert_eq!(
            to(Level::Major, false),
            [("a".to_string(), "2.1.0".to_string())]
        );
        assert_eq!(
            to(Level::Minor, false),
            [("a".to_string(), "1.4.0".to_string())]
        );
        assert_eq!(
            to(Level::Patch, false),
            [("a".to_string(), "1.0.5".to_string())]
        );
        assert_eq!(to(Level::Major, true).len(), 2);
        assert!(to(Level::Patch, true).iter().all(|(name, _)| name == "a"));
    }

    #[test]
    fn parses_registry_answers() {
        let many = Available::parse(r#"{"dist-tags.latest":"1.3.0","versions":["1.2.0","1.3.0"]}"#)
            .unwrap();
        assert_eq!(many.latest, "1.3.0");
        assert_eq!(many.versions, ["1.2.0", "1.3.0"]);
        let single =
            Available::parse(r#"{"dist-tags.latest":"0.0.1","versions":"0.0.1"}"#).unwrap();
        assert_eq!(single.versions, ["0.0.1"]);
        assert!(Available::parse("").is_none());
        assert!(Available::parse("{}").is_none());
    }

    #[test]
    fn compares_python_versions_too() {
        assert_eq!(order("2.9", "2.10"), Ordering::Less);
        assert_eq!(order("1.0", "1.0.0"), Ordering::Equal);
        assert_eq!(order("1.0rc1", "1.0"), Ordering::Less);
        assert_eq!(order("2024.2.2", "2024.12.14"), Ordering::Less);
        assert_eq!(bump("3.6", "3.7"), Bump::Minor);
        assert_eq!(bump("2.31.0", "2.32.3"), Bump::Minor);
        assert_eq!(bump("2.32.2", "2.32.3"), Bump::Patch);
        assert_eq!(bump("1.26.18", "2.2.1"), Bump::Major);
        assert_eq!(bump("1.0rc1", "1.0"), Bump::Prerelease);

        let offer = Available {
            latest: "3.7".into(),
            versions: ["3.4", "3.6", "3.6.1", "3.7", "4.0rc1"]
                .map(String::from)
                .to_vec(),
        };
        assert_eq!(offer.pick("3.6", Level::Major), Some("3.7"));
        assert_eq!(offer.pick("3.6", Level::Patch), Some("3.6.1"));
        assert_eq!(offer.pick("3.7", Level::Major), None);
    }

    #[test]
    fn reads_pinned_requirements() {
        let lock = parse_requirements(
            "# frozen\nrequests==2.31.0\nCharset_Normalizer==3.3.2 ; python_version >= '3.7'\n\
             urllib3[socks]==2.0.7  # via requests\nidna==3.6 --hash=sha256:abc\n\
             -r other.txt\n--index-url https://example.invalid\nflask>=2.0\nnumpy==1.*\n",
        );
        assert_eq!(lock.ecosystem, Ecosystem::PyPI);
        let pinned: Vec<_> = lock.direct(false).collect();
        assert_eq!(
            pinned,
            [
                ("charset-normalizer", "3.3.2"),
                ("idna", "3.6"),
                ("requests", "2.31.0"),
                ("urllib3", "2.0.7")
            ]
        );

        let newer = parse_requirements("requests==2.32.3\nidna==3.6\ncertifi==2024.2.2\n");
        let found = changes(&lock, &newer);
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|u| u.ecosystem == Ecosystem::PyPI));
        assert_eq!(
            (found[0].name.as_str(), found[0].from.as_deref()),
            ("certifi", None)
        );
        assert_eq!(
            (found[1].name.as_str(), found[1].bump),
            ("requests", Bump::Minor)
        );

        let plan = Plan::new(
            vec![Outcome::new(found[1].clone(), Ok(report(Severity::Info)))],
            0,
            true,
        );
        assert_eq!(
            plan.apply_command().as_deref(),
            Some("pip install requests==2.32.3")
        );
    }

    #[test]
    fn advice_follows_risk_then_semver() {
        let patch = Update::new("a", Some("1.0.0"), "1.0.1", true);
        let major = Update::new("a", Some("1.0.0"), "2.0.0", true);
        assert_eq!(advise(&patch, Ok(&report(Severity::Info))).0, Advice::Apply);
        assert_eq!(advise(&patch, Ok(&report(Severity::Low))).0, Advice::Apply);
        assert_eq!(
            advise(&patch, Ok(&report(Severity::Medium))).0,
            Advice::Review
        );
        assert_eq!(
            advise(&patch, Ok(&report(Severity::Critical))).0,
            Advice::Hold
        );
        assert_eq!(
            advise(&major, Ok(&report(Severity::Info))).0,
            Advice::Review
        );
        assert_eq!(advise(&major, Ok(&report(Severity::High))).0, Advice::Hold);
        assert_eq!(advise(&patch, Err("boom".into())).0, Advice::Unknown);
    }

    #[test]
    fn plan_suggests_only_safe_direct_updates() {
        let outcomes = vec![
            Outcome::new(
                Update::new("safe", Some("1.0.0"), "1.0.1", true),
                Ok(report(Severity::Info)),
            ),
            Outcome::new(
                Update::new("deep", Some("1.0.0"), "1.0.1", false),
                Ok(report(Severity::Info)),
            ),
            Outcome::new(
                Update::new("evil", Some("1.0.0"), "1.0.1", true),
                Ok(report(Severity::Critical)),
            ),
            Outcome::new(
                Update::new("broken", Some("1.0.0"), "1.0.1", true),
                Err(anyhow::anyhow!("no network")),
            ),
        ];
        let plan = Plan::new(outcomes, 2, true);
        assert_eq!(plan.verdict, Severity::Critical);
        assert_eq!(
            plan.apply_command().as_deref(),
            Some("npm install safe@1.0.1")
        );
        assert_eq!(
            plan.summary(),
            "2 apply, 1 hold, 1 unknown, 2 not evaluated (raise --max)"
        );

        let text = render(&plan, Format::Terminal);
        assert!(text.contains("npm install safe@1.0.1"));
        let md = render(&plan, Format::Markdown);
        assert!(md.contains("| **hold** | `evil` | 1.0.0 -> 1.0.1 | patch |"));
        let json: Value = serde_json::from_str(&render(&plan, Format::Json)).unwrap();
        assert_eq!(json["outcomes"][2]["advice"], "hold");
        assert_eq!(json["outcomes"][3]["error"], "no network");
    }
}
