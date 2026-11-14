//! Compares two profiles and turns the difference into rated findings.

use std::collections::BTreeSet;

use crate::model::{Behavior, Change, Finding, Kind, Profile, Report, Severity, SCHEMA};
use crate::rules;

/// What the comparison is for; decides how the manifest is read.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Old version against new version.
    Update,
    /// A single version against the empty baseline project.
    Scan,
}

pub fn compare(old: &Profile, new: &Profile, mode: Mode) -> Report {
    let before: BTreeSet<&Behavior> = old.behaviors.iter().map(|o| &o.behavior).collect();
    let after: BTreeSet<&Behavior> = new.behaviors.iter().map(|o| &o.behavior).collect();
    let mut findings = Vec::new();
    // The observation each behavior was read from, to quote in its finding.
    let evidence = |profile: &Profile, b: &Behavior| {
        let seen = profile.behaviors.iter().find(|o| &o.behavior == b);
        seen.map(|o| o.evidence.clone()).unwrap_or_default()
    };

    let added: Vec<&Behavior> = after.difference(&before).copied().collect();
    for b in &added {
        if is_shell_wrapper(b, &added) || is_shebang_reexec(b, &added) {
            continue;
        }
        let (severity, why) = rules::rate(b);
        let mut finding = behavior_finding(b, Change::Added, severity, why);
        finding.evidence = evidence(new, b);
        findings.push(finding);
    }
    if mode == Mode::Update {
        for b in before.difference(&after) {
            findings.push(behavior_finding(
                b,
                Change::Removed,
                Severity::Info,
                "no longer observed".into(),
            ));
        }
    }

    scripts(old, new, mode, &mut findings);
    dependencies(old, new, mode, &mut findings);

    let mut findings = merge_repeats(findings);
    findings.sort_by(|a, b| {
        (b.severity, a.phase, &a.title, &a.target).cmp(&(a.severity, b.phase, &b.title, &b.target))
    });
    let verdict = findings
        .iter()
        .filter(|f| f.change != Change::Removed)
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Info);

    Report {
        schema: SCHEMA,
        package: new.name.clone(),
        old: (mode == Mode::Update).then(|| old.version.clone()),
        new: new.version.clone(),
        verdict,
        findings,
        phases: new.phases.clone(),
    }
}

/// The same thing done by several processes (a build script that runs twice,
/// a worker pool) is one finding. The first process is named, the others
/// are counted.
fn merge_repeats(findings: Vec<Finding>) -> Vec<Finding> {
    let mut merged: Vec<(Finding, usize)> = Vec::new();
    for finding in findings {
        let same = merged.iter_mut().find(|(known, _)| {
            known.change == finding.change
                && known.severity == finding.severity
                && known.phase == finding.phase
                && known.title == finding.title
                && known.target == finding.target
        });
        match same {
            Some((_, others)) => *others += 1,
            None => merged.push((finding, 0)),
        }
    }
    merged
        .into_iter()
        .map(|(mut finding, others)| {
            if others > 0 && !finding.actor.is_empty() {
                finding.actor = format!("{} (and {others} more)", finding.actor);
            }
            finding
        })
        .collect()
}

/// `sh -c "node x.js"` followed by `node x.js` is one event, not two: the
/// shell is only how a script gets started. Report the command it ran and
/// drop the wrapper.
fn is_shell_wrapper(b: &Behavior, added: &[&Behavior]) -> bool {
    const SHELLS: [&str; 3] = ["sh -c ", "bash -c ", "dash -c "];
    b.kind == Kind::Exec
        && SHELLS.iter().any(|shell| b.target.starts_with(shell))
        && added
            .iter()
            .any(|x| x.kind == Kind::Exec && x.phase == b.phase && x.actor.starts_with(&b.target))
}

/// A script started by name (`node-gyp rebuild`) shows up a second time when
/// its shebang line hands it to the interpreter (`node …/node-gyp rebuild`).
/// Keep the command as it was called.
fn is_shebang_reexec(b: &Behavior, added: &[&Behavior]) -> bool {
    if b.kind != Kind::Exec {
        return false;
    }
    let mut words = b.target.splitn(3, ' ');
    let (Some(interpreter), Some(script)) = (words.next(), words.next()) else {
        return false;
    };
    let name = script.rsplit('/').next().unwrap_or(script);
    let called_as = match words.next() {
        Some(args) => format!("{name} {args}"),
        None => name.to_string(),
    };
    interpreter != name
        && added.iter().any(|x| {
            x.kind == Kind::Exec
                && x.phase == b.phase
                && x.target == called_as
                && b.actor.starts_with(&x.target)
        })
}

fn behavior_finding(b: &Behavior, change: Change, severity: Severity, why: String) -> Finding {
    Finding {
        severity,
        change,
        phase: Some(b.phase),
        title: rules::kind_title(b.kind).to_string(),
        target: b.target.clone(),
        actor: b.actor.clone(),
        why,
        evidence: String::new(),
    }
}

fn manifest_finding(
    severity: Severity,
    change: Change,
    title: &str,
    target: String,
    why: &str,
) -> Finding {
    Finding {
        severity,
        change,
        phase: None,
        title: title.into(),
        target,
        actor: String::new(),
        why: why.into(),
        evidence: "read from the manifest and lockfile the fetch left behind".into(),
    }
}

/// Lifecycle scripts of the package itself.
fn scripts(old: &Profile, new: &Profile, mode: Mode, out: &mut Vec<Finding>) {
    for (hook, cmd) in &new.manifest.scripts {
        let target = format!("{hook}: {cmd}");
        match old.manifest.scripts.get(hook) {
            _ if mode == Mode::Scan => out.push(manifest_finding(
                Severity::Medium,
                Change::Added,
                "has install script",
                target,
                "runs automatically on every install",
            )),
            None => out.push(manifest_finding(
                Severity::High,
                Change::Added,
                "install script added",
                target,
                "this version starts running code on every install",
            )),
            Some(previous) if previous != cmd => out.push(manifest_finding(
                Severity::Medium,
                Change::Changed,
                "install script changed",
                target,
                "the command run on install is different",
            )),
            Some(_) => {}
        }
    }
    if mode == Mode::Update {
        for (hook, cmd) in &old.manifest.scripts {
            if !new.manifest.scripts.contains_key(hook) {
                out.push(manifest_finding(
                    Severity::Info,
                    Change::Removed,
                    "install script removed",
                    format!("{hook}: {cmd}"),
                    "no longer runs code on install",
                ));
            }
        }
    }
}

/// The resolved dependency tree.
fn dependencies(old: &Profile, new: &Profile, mode: Mode, out: &mut Vec<Finding>) {
    let join = |v: &BTreeSet<String>| v.iter().map(String::as_str).collect::<Vec<_>>().join(", ");
    for (dep, versions) in &new.manifest.packages {
        let scripted = new.manifest.install_scripts.contains(dep);
        if mode == Mode::Scan {
            if scripted {
                out.push(manifest_finding(
                    Severity::Low,
                    Change::Added,
                    "dependency with install script",
                    format!("{dep}@{}", join(versions)),
                    "a dependency that runs code on install",
                ));
            }
            continue;
        }
        match old.manifest.packages.get(dep) {
            None if scripted => out.push(manifest_finding(
                Severity::Medium,
                Change::Added,
                "new dependency with install script",
                format!("{dep}@{}", join(versions)),
                "a new dependency that runs code on install",
            )),
            None => out.push(manifest_finding(
                Severity::Low,
                Change::Added,
                "new dependency",
                format!("{dep}@{}", join(versions)),
                "more code from another author enters your tree",
            )),
            Some(previous) if previous != versions => {
                let gained_script = scripted && !old.manifest.install_scripts.contains(dep);
                out.push(manifest_finding(
                    if gained_script {
                        Severity::Medium
                    } else {
                        Severity::Info
                    },
                    Change::Changed,
                    if gained_script {
                        "dependency gained install script"
                    } else {
                        "dependency version changed"
                    },
                    format!("{dep} {} -> {}", join(previous), join(versions)),
                    if gained_script {
                        "an updated dependency now runs code on install"
                    } else {
                        "resolved to a different version"
                    },
                ));
            }
            Some(_) => {}
        }
    }
    if mode == Mode::Update {
        for (dep, versions) in &old.manifest.packages {
            if !new.manifest.packages.contains_key(dep) {
                out.push(manifest_finding(
                    Severity::Info,
                    Change::Removed,
                    "dependency removed",
                    format!("{dep}@{}", join(versions)),
                    "no longer in the tree",
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Manifest, Observed, Phase};

    #[test]
    fn the_same_act_by_several_processes_is_one_finding() {
        let read = |actor: &str| Observed {
            behavior: Behavior {
                phase: Phase::Install,
                kind: Kind::Read,
                target: "~/.ssh/id_rsa".into(),
                actor: actor.into(),
            },
            count: 1,
            evidence: String::new(),
        };
        let a = profile("1.0.0", &[]);
        let mut b = profile("1.0.1", &[]);
        b.behaviors = vec![
            read("python setup.py egg_info"),
            read("python setup.py install"),
            read("python setup.py bdist"),
        ];
        let report = compare(&a, &b, Mode::Update);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(
            report.findings[0].actor,
            "python setup.py bdist (and 2 more)"
        );
        assert_eq!(report.verdict, Severity::Critical);
    }

    #[test]
    fn shell_wrapper_is_folded_into_its_command() {
        let exec = |target: &str, actor: &str| Observed {
            behavior: Behavior {
                phase: Phase::Install,
                kind: Kind::Exec,
                target: target.into(),
                actor: actor.into(),
            },
            count: 1,
            evidence: String::new(),
        };
        let a = profile("1.0.0", &[]);
        let mut b = profile("1.0.1", &[]);
        b.behaviors = vec![
            exec("sh -c node setup.js", "npm rebuild"),
            exec("node setup.js", "sh -c node setup.js (in demo)"),
            exec("sh -c true", "npm rebuild"),
        ];
        let targets: Vec<_> = compare(&a, &b, Mode::Update)
            .findings
            .into_iter()
            .map(|f| f.target)
            .collect();
        assert_eq!(targets, ["node setup.js", "sh -c true"]);

        // A tool re-executed through its shebang is reported once, as called.
        b.behaviors = vec![
            exec("node-gyp rebuild", "npm rebuild"),
            exec(
                "node node_modules/.bin/node-gyp rebuild",
                "node-gyp rebuild (in demo)",
            ),
            exec(
                "python3 -c x",
                "node node_modules/.bin/node-gyp rebuild (in demo)",
            ),
        ];
        let targets: Vec<_> = compare(&a, &b, Mode::Update)
            .findings
            .into_iter()
            .map(|f| f.target)
            .collect();
        assert_eq!(targets, ["node-gyp rebuild", "python3 -c x"]);
    }

    fn profile(version: &str, behaviors: &[(Kind, &str)]) -> Profile {
        Profile {
            name: "demo".into(),
            version: version.into(),
            behaviors: behaviors
                .iter()
                .map(|(kind, target)| Observed {
                    behavior: Behavior {
                        phase: Phase::Install,
                        kind: *kind,
                        target: (*target).into(),
                        actor: "npm".into(),
                    },
                    count: 1,
                    evidence: String::new(),
                })
                .collect(),
            manifest: Manifest::default(),
            phases: vec![],
        }
    }

    #[test]
    fn identical_profiles_are_clean() {
        let a = profile(
            "1.0.0",
            &[(Kind::Read, "~/.npmrc"), (Kind::Exec, "node build.js")],
        );
        let b = profile(
            "1.0.1",
            &[(Kind::Read, "~/.npmrc"), (Kind::Exec, "node build.js")],
        );
        let r = compare(&a, &b, Mode::Update);
        assert!(r.findings.is_empty());
        assert_eq!(r.verdict, Severity::Info);
    }

    #[test]
    fn new_behavior_sets_verdict_and_sorts_first() {
        let a = profile("1.0.0", &[(Kind::Exec, "node build.js")]);
        let b = profile(
            "1.0.1",
            &[(Kind::Read, "~/.ssh/id_rsa"), (Kind::Dns, "evil.example")],
        );
        let r = compare(&a, &b, Mode::Update);
        assert_eq!(r.verdict, Severity::Critical);
        assert_eq!(r.findings[0].target, "~/.ssh/id_rsa");
        assert_eq!(r.findings[1].target, "evil.example");
        let removed = r.findings.last().unwrap();
        assert_eq!(
            (removed.change, removed.severity),
            (Change::Removed, Severity::Info)
        );
    }

    #[test]
    fn removed_behavior_never_raises_verdict() {
        let a = profile("1.0.0", &[(Kind::Read, "~/.ssh/id_rsa")]);
        let b = profile("1.0.1", &[]);
        assert_eq!(compare(&a, &b, Mode::Update).verdict, Severity::Info);
    }

    #[test]
    fn manifest_changes_are_reported() {
        let mut a = profile("1.0.0", &[]);
        let mut b = profile("1.0.1", &[]);
        a.manifest
            .packages
            .insert("left".into(), ["1.0.0".to_string()].into());
        b.manifest
            .packages
            .insert("left".into(), ["1.1.0".to_string()].into());
        b.manifest
            .packages
            .insert("fresh".into(), ["0.0.1".to_string()].into());
        b.manifest.install_scripts.insert("fresh".into());
        b.manifest
            .scripts
            .insert("postinstall".into(), "node x.js".into());

        let r = compare(&a, &b, Mode::Update);
        let titles: Vec<_> = r.findings.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(
            titles,
            [
                "install script added",
                "new dependency with install script",
                "dependency version changed"
            ]
        );
        assert_eq!(r.verdict, Severity::High);

        let scan = compare(&a, &b, Mode::Scan);
        let titles: Vec<_> = scan.findings.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(
            titles,
            ["has install script", "dependency with install script"]
        );
        assert_eq!(scan.old, None);
    }
}
