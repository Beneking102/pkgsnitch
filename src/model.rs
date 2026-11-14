//! Data model shared by the sandbox, the analyzer and the reporters.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// The moment in a package's life at which a behavior was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    /// Lifecycle scripts (`preinstall`, `install`, `postinstall`).
    Install,
    /// First `import` of the package's entry point.
    Import,
}

impl Phase {
    pub fn label(self) -> &'static str {
        match self {
            Phase::Install => "install",
            Phase::Import => "import",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Dns,
    Http,
    Tls,
    Connect,
    Exec,
    Read,
    Write,
    Delete,
}

/// One normalized, comparable thing a package did.
///
/// Two runs of the same code must produce equal `Behavior` values, so every
/// field is stripped of pids, temp names and other run-specific noise.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Behavior {
    pub phase: Phase,
    pub kind: Kind,
    pub target: String,
    /// Command line of the process responsible, empty when unknown.
    pub actor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observed {
    #[serde(flatten)]
    pub behavior: Behavior,
    pub count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseStat {
    pub phase: Phase,
    pub exit_code: Option<i32>,
    pub syscalls: usize,
}

/// Static facts read from the installed tree.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Manifest {
    /// Lifecycle scripts of the package under test.
    pub scripts: BTreeMap<String, String>,
    /// Every package in the resolved tree, with all versions present.
    pub packages: BTreeMap<String, BTreeSet<String>>,
    /// Packages in the tree that declare install scripts.
    pub install_scripts: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub version: String,
    pub behaviors: Vec<Observed>,
    pub manifest: Manifest,
    pub phases: Vec<PhaseStat>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Change {
    Added,
    Removed,
    Changed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub change: Change,
    pub phase: Option<Phase>,
    pub title: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub actor: String,
    pub why: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub package: String,
    /// `None` when a single version was scanned against the empty baseline.
    pub old: Option<String>,
    pub new: String,
    pub verdict: Severity,
    pub findings: Vec<Finding>,
    pub phases: Vec<PhaseStat>,
}
