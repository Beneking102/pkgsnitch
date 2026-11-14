//! Renders a [`Report`] for humans (terminal), machines (JSON) and pull
//! requests (Markdown).

use std::fmt::Write as _;

use owo_colors::OwoColorize;

use crate::model::{Change, Finding, Report, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    Terminal,
    Json,
    Markdown,
    /// For code scanning tools; `lock` and `updates` only
    Sarif,
}

pub fn render(report: &Report, format: Format) -> String {
    match format {
        Format::Terminal => terminal(report),
        Format::Json => {
            serde_json::to_string_pretty(report).expect("report is serializable") + "\n"
        }
        Format::Markdown => markdown(report),
        // A single report has no file to point at; the commands that
        // produce one refuse this format before getting here.
        Format::Sarif => String::new(),
    }
}

fn heading(r: &Report) -> String {
    match &r.old {
        Some(old) => format!("{} {} -> {}", r.package, old, r.new),
        None => format!("{} {}", r.package, r.new),
    }
}

fn badge(s: Severity) -> String {
    paint(s, &format!("{:<8}", s.label().to_uppercase()))
}

fn paint(s: Severity, text: &str) -> String {
    match s {
        Severity::Critical => text.white().on_red().bold().to_string(),
        Severity::High => text.red().bold().to_string(),
        Severity::Medium => text.yellow().bold().to_string(),
        Severity::Low => text.blue().to_string(),
        Severity::Info => text.dimmed().to_string(),
    }
}

fn split(r: &Report) -> (Vec<&Finding>, Vec<&Finding>) {
    r.findings.iter().partition(|f| f.change != Change::Removed)
}

fn terminal(r: &Report) -> String {
    let mut o = String::new();
    let (new, gone) = split(r);
    let _ = writeln!(o, "\n  {}  {}\n", "pkgsnitch".bold(), heading(r).bold());

    if new.is_empty() {
        let what = if r.old.is_some() {
            "No new behavior."
        } else {
            "Nothing notable observed."
        };
        let _ = writeln!(o, "  {} {what}", "ok".green().bold());
    }
    for f in &new {
        let phase = f.phase.map_or("manifest", |p| p.label());
        // Minor findings get one line, so the serious ones stand out.
        if f.severity <= Severity::Low {
            let _ = writeln!(
                o,
                "  {}  {:<8}  {}",
                badge(f.severity),
                phase.dimmed(),
                format!("{}: {}", f.title, f.target).dimmed()
            );
            continue;
        }
        let _ = writeln!(
            o,
            "  {}  {:<8}  {}",
            badge(f.severity),
            phase.dimmed(),
            f.title.bold()
        );
        let _ = writeln!(o, "  {:<8}  {:<8}  {}", "", "", f.target);
        if !f.actor.is_empty() {
            let _ = writeln!(
                o,
                "  {:<8}  {:<8}  {}",
                "",
                "",
                format!("by {}", f.actor).dimmed()
            );
        }
        let _ = writeln!(o, "  {:<8}  {:<8}  {}\n", "", "", f.why.dimmed());
    }
    if new.last().is_some_and(|f| f.severity <= Severity::Low) {
        o.push('\n');
    }
    if !gone.is_empty() {
        let _ = writeln!(
            o,
            "  {}",
            format!("No longer observed ({}):", gone.len()).dimmed()
        );
        for f in &gone {
            let _ = writeln!(o, "  {}", format!("  - {}: {}", f.title, f.target).dimmed());
        }
        o.push('\n');
    }

    for p in &r.phases {
        if matches!(p.exit_code, Some(code) if code != 0) {
            let note = match p.exit_code {
                Some(124) | Some(137) => "timed out".to_string(),
                Some(code) => format!("exited with status {code}"),
                None => unreachable!(),
            };
            let _ = writeln!(
                o,
                "  {} the {} phase {note}; behavior after that point was not observed",
                "note".yellow().bold(),
                p.phase.label()
            );
        }
    }

    let syscalls: usize = r.phases.iter().map(|p| p.syscalls).sum();
    let _ = writeln!(
        o,
        "  {} new, {} gone, {} syscalls watched. Verdict: {}",
        new.len(),
        gone.len(),
        syscalls,
        paint(r.verdict, &r.verdict.label().to_uppercase())
    );
    o
}

fn markdown(r: &Report) -> String {
    let mut o = String::new();
    let (new, gone) = split(r);
    let _ = writeln!(o, "### pkgsnitch: `{}`\n", heading(r));
    let _ = writeln!(
        o,
        "**Verdict: {}** ({} new, {} gone)\n",
        r.verdict.label(),
        new.len(),
        gone.len()
    );
    if new.is_empty() {
        o.push_str("No new behavior at install or import time.\n");
    } else {
        o.push_str("| Severity | Phase | Behavior | Target | By |\n|---|---|---|---|---|\n");
        for f in &new {
            let _ = writeln!(
                o,
                "| **{}** | {} | {} | `{}` | {} |",
                f.severity.label(),
                f.phase.map_or("manifest", |p| p.label()),
                f.title,
                cell(&f.target),
                if f.actor.is_empty() {
                    String::new()
                } else {
                    format!("`{}`", cell(&f.actor))
                },
            );
        }
    }
    if !gone.is_empty() {
        let _ = writeln!(
            o,
            "\n<details><summary>No longer observed ({})</summary>\n",
            gone.len()
        );
        for f in &gone {
            let _ = writeln!(o, "- {}: `{}`", f.title, cell(&f.target));
        }
        o.push_str("\n</details>\n");
    }
    o
}

/// Make arbitrary observed text safe inside a Markdown table cell.
fn cell(s: &str) -> String {
    s.replace('|', "\\|")
        .replace('`', "'")
        .replace(['\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Phase;

    fn report() -> Report {
        Report {
            schema: crate::model::SCHEMA,
            package: "demo".into(),
            old: Some("1.0.0".into()),
            new: "1.0.1".into(),
            verdict: Severity::Critical,
            findings: vec![
                Finding {
                    severity: Severity::Critical,
                    change: Change::Added,
                    phase: Some(Phase::Install),
                    title: "reads file".into(),
                    target: "~/.ssh/id_rsa".into(),
                    actor: "sh -c a | b `c`".into(),
                    why: "reads SSH keys".into(),
                },
                Finding {
                    severity: Severity::Info,
                    change: Change::Removed,
                    phase: Some(Phase::Install),
                    title: "runs command".into(),
                    target: "node old.js".into(),
                    actor: String::new(),
                    why: "no longer observed".into(),
                },
            ],
            phases: vec![],
        }
    }

    #[test]
    fn markdown_escapes_table_breakers() {
        let md = render(&report(), Format::Markdown);
        assert!(md.contains("demo 1.0.0 -> 1.0.1"));
        assert!(md.contains(r"`sh -c a \| b 'c'`"));
        assert!(md.contains("No longer observed (1)"));
    }

    #[test]
    fn json_round_trips() {
        let json = render(&report(), Format::Json);
        let back: Report = serde_json::from_str(&json).unwrap();
        assert_eq!(back.findings.len(), 2);
        assert_eq!(back.verdict, Severity::Critical);
    }

    #[test]
    fn terminal_mentions_every_new_finding() {
        let text = render(&report(), Format::Terminal);
        assert!(text.contains("~/.ssh/id_rsa"));
        assert!(text.contains("1 new, 1 gone"));
    }
}
