//! SARIF output, the format code scanning tools ingest. Each new behavior
//! becomes a result that points at the line of the lockfile which pins the
//! version showing it.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::model::{Change, Severity};
use crate::plan::{versions, Plan};
use crate::sandbox::Ecosystem;

pub fn render(plan: &Plan) -> String {
    let mut rules: BTreeMap<String, &str> = BTreeMap::new();
    let mut results = Vec::new();
    for outcome in &plan.outcomes {
        let update = &outcome.update;
        let Some(report) = &outcome.report else {
            continue;
        };
        // Where there is no lockfile at hand, name the one this ecosystem uses.
        let file = update.source.clone().unwrap_or_else(|| {
            match update.ecosystem {
                Ecosystem::Npm => "package-lock.json",
                Ecosystem::PyPI => "requirements.txt",
            }
            .to_string()
        });
        let noteworthy = report
            .findings
            .iter()
            .filter(|f| f.change != Change::Removed && f.severity >= Severity::Low);
        for finding in noteworthy {
            let rule = rule_id(&finding.title);
            rules.insert(rule.clone(), &finding.title);
            let by = if finding.actor.is_empty() {
                String::new()
            } else {
                format!(" by `{}`", finding.actor)
            };
            results.push(json!({
                "ruleId": rule,
                "level": level(finding.severity),
                "message": { "text": format!(
                    "{} {}: {} `{}`{by}. {}.",
                    update.name, versions(update), finding.title, finding.target, finding.why
                )},
                "locations": [{ "physicalLocation": {
                    "artifactLocation": { "uri": file },
                    "region": { "startLine": update.line.unwrap_or(1) },
                }}],
                "properties": {
                    "severity": finding.severity.label(),
                    "package": update.name,
                    "version": update.to,
                    "phase": finding.phase.map(|p| p.label()),
                },
            }));
        }
    }
    let rules: Vec<Value> = rules
        .into_iter()
        .map(|(id, title)| json!({ "id": id, "name": id, "shortDescription": { "text": title } }))
        .collect();
    let document = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "pkgsnitch",
                "informationUri": "https://github.com/Beneking102/pkgsnitch",
                "version": env!("CARGO_PKG_VERSION"),
                "rules": rules,
            }},
            "results": results,
        }],
    });
    serde_json::to_string_pretty(&document).expect("SARIF is serializable") + "\n"
}

/// `reads file` becomes `pkgsnitch/reads-file`.
fn rule_id(title: &str) -> String {
    let slug: String = title
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    format!("pkgsnitch/{slug}")
}

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Finding, Phase, Report, SCHEMA};
    use crate::plan::{lock_from_text, Outcome};
    use std::path::Path;

    #[test]
    fn findings_point_at_the_lockfile_line() {
        let old = "# pins\nidna==3.6\nrequests==2.31.0\n";
        let new = "# pins\nidna==3.6\nrequests==2.32.3\n";
        let update = crate::plan::changes(
            &lock_from_text(old, "old").unwrap(),
            &lock_from_text(new, "new").unwrap(),
        )
        .remove(0)
        .located(Path::new("app\\requirements.txt"), new);
        assert_eq!(update.line, Some(3));

        let finding = |severity, change, title: &str| Finding {
            severity,
            change,
            phase: Some(Phase::Install),
            title: title.into(),
            target: "~/.ssh/id_rsa".into(),
            actor: "python setup.py".into(),
            why: "reads SSH keys".into(),
            evidence: String::new(),
        };
        let report = Report {
            schema: SCHEMA,
            package: "requests".into(),
            old: Some("2.31.0".into()),
            new: "2.32.3".into(),
            verdict: Severity::Critical,
            findings: vec![
                finding(Severity::Critical, Change::Added, "reads file"),
                finding(Severity::Info, Change::Removed, "runs command"),
                finding(
                    Severity::Info,
                    Change::Changed,
                    "dependency version changed",
                ),
            ],
            phases: vec![],
        };
        let plan = Plan::new(vec![Outcome::new(update, Ok(report))], 0, false);
        let sarif: Value = serde_json::from_str(&render(&plan)).unwrap();

        assert_eq!(sarif["version"], "2.1.0");
        let run = &sarif["runs"][0];
        assert_eq!(
            run["tool"]["driver"]["rules"][0]["id"],
            "pkgsnitch/reads-file"
        );
        // Removed behavior and info-level notes are not alerts.
        assert_eq!(run["results"].as_array().unwrap().len(), 1);
        let result = &run["results"][0];
        assert_eq!(result["level"], "error");
        let location = &result["locations"][0]["physicalLocation"];
        assert_eq!(location["artifactLocation"]["uri"], "app/requirements.txt");
        assert_eq!(location["region"]["startLine"], 3);
        assert!(result["message"]["text"]
            .as_str()
            .unwrap()
            .starts_with("requests 2.31.0 -> 2.32.3: reads file"));
    }
}
