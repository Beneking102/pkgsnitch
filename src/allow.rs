//! The allowlist: behavior a team has looked at and accepted.
//!
//! One rule per line, `#` starts a comment:
//!
//! ```text
//! # <package>   <behavior>: <target>
//! esbuild       runs command: esbuild --version
//! @scope/*      DNS lookup: registry.npmjs.org
//! ```
//!
//! `*` matches any run of characters in the package and target. A finding
//! that matches a rule is kept in the report but downgraded to `info`, so
//! it no longer fails a build and still leaves a trace of what was accepted.

use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::model::{Change, Report, Severity};

/// Picked up automatically from the working directory.
pub const DEFAULT_FILE: &str = ".pkgsnitch-allow";

#[derive(Debug, Default)]
pub struct Allowlist {
    rules: Vec<Rule>,
    source: String,
}

#[derive(Debug)]
struct Rule {
    line: usize,
    package: String,
    title: String,
    target: String,
}

impl Allowlist {
    /// Load `path`, or the default file if it exists; otherwise allow nothing.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let path = match path {
            Some(path) => path,
            None if Path::new(DEFAULT_FILE).is_file() => Path::new(DEFAULT_FILE),
            None => return Ok(Self::default()),
        };
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading allowlist {}", path.display()))?;
        Self::parse(&text, &path.display().to_string())
    }

    fn parse(text: &str, source: &str) -> Result<Self> {
        let mut rules = Vec::new();
        for (index, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let parsed = line
                .split_once(char::is_whitespace)
                .and_then(|(package, rest)| {
                    let (title, target) = rest.split_once(':')?;
                    Some((package, title.trim(), target.trim()))
                });
            let Some((package, title, target)) =
                parsed.filter(|(_, t, x)| !t.is_empty() && !x.is_empty())
            else {
                bail!(
                    "{source}:{}: expected `<package> <behavior>: <target>`, got `{line}`",
                    index + 1
                );
            };
            rules.push(Rule {
                line: index + 1,
                package: package.to_string(),
                title: title.to_lowercase(),
                target: target.to_string(),
            });
        }
        Ok(Self {
            rules,
            source: source.to_string(),
        })
    }

    /// Downgrade every accepted finding and recompute the verdict.
    /// Returns how many findings were accepted.
    pub fn apply(&self, report: &mut Report) -> usize {
        let mut accepted = 0;
        for finding in report
            .findings
            .iter_mut()
            .filter(|f| f.change != Change::Removed)
        {
            let rule = self.rules.iter().find(|r| {
                glob(&r.package, &report.package)
                    && r.title == finding.title.to_lowercase()
                    && glob(&r.target, &finding.target)
            });
            if let Some(rule) = rule {
                finding.severity = Severity::Info;
                finding.why = format!("accepted by {}:{}", self.source, rule.line);
                accepted += 1;
            }
        }
        if accepted > 0 {
            report
                .findings
                .sort_by_key(|f| std::cmp::Reverse(f.severity));
            report.verdict = report
                .findings
                .iter()
                .filter(|f| f.change != Change::Removed)
                .map(|f| f.severity)
                .max()
                .unwrap_or(Severity::Info);
        }
        accepted
    }
}

/// Match `text` against `pattern`, where `*` stands for any characters.
fn glob(pattern: &str, text: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or("");
    let Some(mut rest) = text.strip_prefix(first) else {
        return false;
    };
    let mut last: Option<&str> = None;
    for part in parts {
        if let Some(previous) = last.replace(part) {
            match rest.find(previous) {
                Some(at) => rest = &rest[at + previous.len()..],
                None => return false,
            }
        }
    }
    match last {
        // No `*` at all: the whole text must have been the prefix.
        None => rest.is_empty(),
        Some(tail) => rest.ends_with(tail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Finding, Phase, SCHEMA};

    fn finding(severity: Severity, title: &str, target: &str) -> Finding {
        Finding {
            severity,
            change: Change::Added,
            phase: Some(Phase::Install),
            title: title.into(),
            target: target.into(),
            actor: String::new(),
            why: "original".into(),
        }
    }

    fn report(package: &str, findings: Vec<Finding>) -> Report {
        let verdict = findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Info);
        Report {
            schema: SCHEMA,
            package: package.into(),
            old: Some("1.0.0".into()),
            new: "1.0.1".into(),
            verdict,
            findings,
            phases: vec![],
        }
    }

    #[test]
    fn glob_matches_like_a_shell() {
        assert!(glob("esbuild", "esbuild"));
        assert!(!glob("esbuild", "esbuild-wasm"));
        assert!(glob("*", "anything"));
        assert!(glob("@scope/*", "@scope/pkg"));
        assert!(!glob("@scope/*", "@other/pkg"));
        assert!(glob(
            "curl * https://*.example.com/*",
            "curl -s https://cdn.example.com/x.sh"
        ));
        assert!(!glob(
            "curl * https://*.example.com/*",
            "curl -s https://example.org/x.sh"
        ));
        assert!(glob("*.node", "build/out.node"));
        assert!(!glob("a*a", "a"));
    }

    #[test]
    fn accepted_findings_are_downgraded_and_verdict_recomputed() {
        let list = Allowlist::parse(
            "# ours\nesbuild  Runs Command: esbuild --version   # checked 2026-11\n\n*  DNS lookup: *.npmjs.org\n",
            "allow",
        )
        .unwrap();
        let mut r = report(
            "esbuild",
            vec![
                finding(Severity::High, "DNS lookup", "registry.npmjs.org"),
                finding(Severity::Medium, "runs command", "esbuild --version"),
                finding(Severity::Medium, "runs command", "node install.js"),
            ],
        );
        assert_eq!(list.apply(&mut r), 2);
        assert_eq!(r.verdict, Severity::Medium);
        assert_eq!(r.findings[0].target, "node install.js");
        assert_eq!(r.findings[1].why, "accepted by allow:4");

        // Rules are scoped to the package they name.
        let mut other = report(
            "left-pad",
            vec![finding(
                Severity::Medium,
                "runs command",
                "esbuild --version",
            )],
        );
        assert_eq!(list.apply(&mut other), 0);
        assert_eq!(other.verdict, Severity::Medium);
    }

    #[test]
    fn malformed_rules_are_rejected_with_their_line() {
        let err = Allowlist::parse("ok runs command: x\nbroken-line\n", "allow").unwrap_err();
        assert!(err.to_string().contains("allow:2"), "{err}");
        assert!(Allowlist::parse("pkg runs command:\n", "allow").is_err());
    }
}
