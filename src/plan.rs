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

use crate::model::{Change, Report, Severity, SCHEMA};
use crate::report::Format;

/// The parts of a `package-lock.json` that matter here.
#[derive(Debug, Default)]
pub struct Lock {
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
    let json: Value =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    parse_lock(&json).with_context(|| format!("{} is not a usable lockfile", path.display()))
}

fn parse_lock(json: &Value) -> Result<Lock> {
    let packages = json
        .get("packages")
        .and_then(Value::as_object)
        .context("no `packages` section (lockfileVersion 2 or newer is required)")?;
    let mut lock = Lock::default();
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

impl Lock {
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

/// `major.minor.patch` plus the prerelease tag, build metadata dropped.
fn semver(v: &str) -> Option<([u64; 3], &str)> {
    let v = v.split('+').next()?;
    let (core, pre) = v.split_once('-').unwrap_or((v, ""));
    let mut parts = core.split('.').map(|p| p.parse::<u64>().ok());
    let triple = [parts.next()??, parts.next()??, parts.next()??];
    parts.next().is_none().then_some((triple, pre))
}

fn order(a: &str, b: &str) -> Ordering {
    match (semver(a), semver(b)) {
        (Some((x, xp)), Some((y, yp))) => {
            x.cmp(&y)
                .then_with(|| match (xp.is_empty(), yp.is_empty()) {
                    // A release is newer than any of its prereleases.
                    (true, false) => Ordering::Greater,
                    (false, true) => Ordering::Less,
                    _ => xp.cmp(yp),
                })
        }
        _ => a.cmp(b),
    }
}

fn bump(from: &str, to: &str) -> Bump {
    let (Some((a, _)), Some((b, _))) = (semver(from), semver(to)) else {
        return Bump::Other;
    };
    match order(from, to) {
        Ordering::Greater => Bump::Downgrade,
        _ if a[0] != b[0] => Bump::Major,
        _ if a[1] != b[1] => Bump::Minor,
        _ if a[2] != b[2] => Bump::Patch,
        _ => Bump::Prerelease,
    }
}

/// One version change to evaluate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Update {
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
            name: name.to_string(),
            from: from.map(str::to_string),
            to: to.to_string(),
            bump: from.map_or(Bump::Added, |f| bump(f, to)),
            direct,
        }
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
            out.push(Update::new(
                name,
                previous.map(String::as_str),
                version,
                new.direct.contains(name),
            ));
        }
    }
    out.sort_by(|a, b| b.direct.cmp(&a.direct).then_with(|| a.name.cmp(&b.name)));
    out
}

/// Direct dependencies for which the registry has something newer.
pub fn outdated(lock: &Lock, latest: &BTreeMap<String, String>, include_dev: bool) -> Vec<Update> {
    lock.direct(include_dev)
        .filter_map(|(name, installed)| {
            let newest = latest.get(name)?;
            (order(installed, newest) == Ordering::Less)
                .then(|| Update::new(name, Some(installed), newest, true))
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
            .map(|o| format!("{}@{}", o.update.name, o.update.to))
            .collect();
        (self.suggest_command && !safe.is_empty())
            .then(|| format!("npm install {}", safe.join(" ")))
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
        let latest: BTreeMap<String, String> = [("a", "1.4.0"), ("b", "2.0.0"), ("d", "4.0.0")]
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        assert_eq!(
            outdated(&l, &latest, false),
            [Update::new("a", Some("1.0.0"), "1.4.0", true)]
        );
        assert_eq!(outdated(&l, &latest, true).len(), 2);
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
