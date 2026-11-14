//! Knowledge about what matters: which paths are secrets, where a package may
//! legitimately write, and how alarming each kind of behavior is.

use crate::model::{Behavior, Kind, Severity};

/// Home directory of the unprivileged user inside the sandbox.
pub const HOME: &str = "/home/dev";
/// Project directory inside the sandbox.
pub const WORK: &str = "/work";

/// Strip run-specific noise so that equal behavior compares equal.
pub fn norm(s: &str) -> String {
    let s = s
        .replace("/work/node_modules/", "node_modules/")
        .replace("/work/venv/", "venv/")
        .replace(HOME, "~");
    let s = collapse_tmp(&s);
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        if !chars[i].is_ascii_hexdigit() {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let mut j = i;
        while j < chars.len() && chars[j].is_ascii_hexdigit() {
            j += 1;
        }
        let run = &chars[i..j];
        let digits = run.iter().filter(|c| c.is_ascii_digit()).count();
        // Hashes, pids and timestamps; ordinary words and short numbers stay.
        if (run.len() >= 8 && digits > 0) || (run.len() >= 5 && digits == run.len()) {
            out.push('*');
        } else {
            out.extend(run);
        }
        i = j;
    }
    out
}

/// Whatever sits directly under `/tmp` has a random name (build directories
/// of npm and pip, Python's tempfile), so only its position is kept.
fn collapse_tmp(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(at) = rest.find("/tmp/") {
        let (head, tail) = rest.split_at(at + "/tmp/".len());
        out.push_str(head);
        let end = tail
            .find(|c: char| c == '/' || c.is_whitespace() || c == '"' || c == '\'')
            .unwrap_or(tail.len());
        if end > 0 {
            out.push('*');
        }
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

struct Secret {
    needle: &'static str,
    label: &'static str,
    severity: Severity,
}

const fn secret(needle: &'static str, label: &'static str, severity: Severity) -> Secret {
    Secret {
        needle,
        label,
        severity,
    }
}

/// Matched against the path with the home directory written as `~`.
const SECRETS: &[Secret] = &[
    secret("~/.ssh", "SSH keys", Severity::Critical),
    secret("~/.aws", "AWS credentials", Severity::Critical),
    secret(
        "~/.config/gcloud",
        "Google Cloud credentials",
        Severity::Critical,
    ),
    secret("~/.azure", "Azure credentials", Severity::Critical),
    secret("~/.kube", "Kubernetes credentials", Severity::Critical),
    secret(
        "~/.docker/config.json",
        "Docker registry credentials",
        Severity::Critical,
    ),
    secret("~/.git-credentials", "Git credentials", Severity::Critical),
    secret("~/.config/gh", "GitHub CLI token", Severity::Critical),
    secret("~/.netrc", "netrc credentials", Severity::Critical),
    secret("~/.gnupg", "GPG keys", Severity::Critical),
    // Many tools read this for registry settings, so it rates below the
    // files that hold nothing but credentials.
    secret("~/.npmrc", "npm config and auth token", Severity::High),
    secret("~/.pypirc", "PyPI token", Severity::Critical),
    secret("~/.config/solana", "crypto wallet", Severity::Critical),
    secret("~/.ethereum", "crypto wallet", Severity::Critical),
    secret("~/.bitcoin", "crypto wallet", Severity::Critical),
    secret("wallet.dat", "crypto wallet", Severity::Critical),
    secret("~/.mozilla", "browser profile", Severity::Critical),
    secret(
        "~/.config/google-chrome",
        "browser profile",
        Severity::Critical,
    ),
    secret("~/.config/chromium", "browser profile", Severity::Critical),
    secret("~/.bash_history", "shell history", Severity::High),
    secret("~/.zsh_history", "shell history", Severity::High),
    secret("/etc/shadow", "password hashes", Severity::Critical),
    secret(
        "/var/run/secrets",
        "service account token",
        Severity::Critical,
    ),
    secret("/run/secrets", "container secrets", Severity::Critical),
    secret("~/.gitconfig", "Git identity", Severity::Medium),
    secret("/etc/passwd", "user list", Severity::Low),
];

/// Classify a path as sensitive. Accepts raw or normalized paths.
pub fn sensitive(path: &str) -> Option<(&'static str, Severity)> {
    let p = path.replace(HOME, "~");
    if let Some(s) = SECRETS.iter().find(|s| p.contains(s.needle)) {
        return Some((s.label, s.severity));
    }
    let file = p.rsplit('/').next().unwrap_or("");
    if file == ".env" || file.starts_with(".env.") {
        return Some(("environment secrets", Severity::Critical));
    }
    // Environment of *another* process; a process reading its own is routine.
    if p.starts_with("/proc/") && p.ends_with("/environ") && !p.starts_with("/proc/self/") {
        return Some(("another process's environment", Severity::High));
    }
    None
}

/// Places an install is expected to write to.
pub fn write_expected(path: &str) -> bool {
    const ZONES: &[&str] = &[
        "/work/node_modules/",
        "/work/venv/",
        "/work/wheels/",
        "/tmp/",
        "/home/dev/.npm/",
        "/home/dev/.cache/",
        "/dev/",
        "/proc/self/",
    ];
    !path.starts_with('/')
        || ZONES.iter().any(|z| path.starts_with(z))
        || matches!(
            path,
            "/work/node_modules"
                | "/work/package.json"
                | "/work/package-lock.json"
                | "/home/dev/.cache"
                | "/home/dev/.npm"
        )
}

const PERSISTENCE: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".profile",
    ".zshrc",
    ".zshenv",
    "/etc/profile",
    "/etc/cron",
    "/var/spool/cron",
    "/etc/systemd",
    ".config/systemd",
    ".config/autostart",
    "authorized_keys",
    ".git/hooks/",
    "/etc/ld.so.preload",
];

const NETWORK_TOOLS: &[&str] = &[
    "curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp", "ftp", "telnet",
];

/// How alarming is it that a package *started* doing this?
pub fn rate(b: &Behavior) -> (Severity, String) {
    let t = b.target.as_str();
    match b.kind {
        Kind::Dns => (
            Severity::High,
            format!("looks up a host name during {}", b.phase.label()),
        ),
        Kind::Http => (
            Severity::High,
            format!("sends an HTTP request during {}", b.phase.label()),
        ),
        Kind::Tls => (
            Severity::High,
            format!("opens a TLS connection during {}", b.phase.label()),
        ),
        Kind::Connect if t.contains("docker.sock") => (
            Severity::Critical,
            "talks to the Docker daemon, which grants root on the host".into(),
        ),
        Kind::Connect => (Severity::High, "opens a network connection".into()),
        Kind::Read => match sensitive(t) {
            Some((label, sev)) => (sev, format!("reads {label}")),
            None => (Severity::Medium, "reads a file outside the project".into()),
        },
        Kind::Write | Kind::Delete => {
            let verb = if b.kind == Kind::Write {
                "writes"
            } else {
                "deletes"
            };
            if PERSISTENCE.iter().any(|p| t.contains(p)) {
                (
                    Severity::Critical,
                    format!("{verb} a file that runs code at login or on a schedule"),
                )
            } else if t.starts_with("~/") || t == "~" {
                (Severity::High, format!("{verb} in the home directory"))
            } else if t.starts_with(WORK) {
                (
                    Severity::Medium,
                    format!("{verb} in the project outside node_modules"),
                )
            } else {
                (Severity::High, format!("{verb} outside the project"))
            }
        }
        Kind::Exfil => (
            Severity::Critical,
            "sends a planted secret out: proof that credentials are being stolen".into(),
        ),
        Kind::Exec => {
            let program = t.split_whitespace().next().unwrap_or("");
            if NETWORK_TOOLS.contains(&program) {
                (
                    Severity::Critical,
                    format!("runs the network tool `{program}`"),
                )
            } else {
                (Severity::Medium, "starts a new process".into())
            }
        }
    }
}

pub fn kind_title(kind: Kind) -> &'static str {
    match kind {
        Kind::Dns => "DNS lookup",
        Kind::Http => "HTTP request",
        Kind::Tls => "TLS connection",
        Kind::Connect => "network connection",
        Kind::Exec => "runs command",
        Kind::Read => "reads file",
        Kind::Write => "writes file",
        Kind::Delete => "deletes file",
        Kind::Exfil => "exfiltrates secret",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Phase;

    #[test]
    fn norm_strips_noise_but_keeps_words() {
        assert_eq!(
            norm("/work/node_modules/esbuild/bin"),
            "node_modules/esbuild/bin"
        );
        assert_eq!(
            norm("/home/dev/.npm/_logs/2026-11-14T10_52_08_123Z"),
            "~/.npm/_logs/2026-11-14T10_52_08_123Z"
        );
        assert_eq!(norm("/tmp/build-9f8e7d6c5b4a"), "/tmp/*");
        assert_eq!(
            norm("/tmp/pip-build-env-k3x9_qzt/overlay/bin/python setup.py /tmp/tmpab12cd34"),
            "/tmp/*/overlay/bin/python setup.py /tmp/*"
        );
        assert_eq!(norm("cache-9f8e7d6c5b4a.lock"), "cache-*.lock");
        assert_eq!(
            norm("/work/venv/lib/python3.11/site-packages/x.pth"),
            "venv/lib/python3.11/site-packages/x.pth"
        );
        assert_eq!(
            norm("node feedback.js --port 8080"),
            "node feedback.js --port 8080"
        );
    }

    #[test]
    fn classifies_secrets() {
        assert_eq!(
            sensitive("/home/dev/.ssh/id_rsa").unwrap().1,
            Severity::Critical
        );
        assert_eq!(
            sensitive("~/.npmrc").unwrap(),
            ("npm config and auth token", Severity::High)
        );
        assert!(write_expected("/home/dev/.cache"));
        assert_eq!(
            sensitive("/work/.env.production").unwrap().0,
            "environment secrets"
        );
        assert!(sensitive("/proc/1/environ").is_some());
        assert!(sensitive("/proc/self/environ").is_none());
        assert!(sensitive("/work/node_modules/x/index.js").is_none());
    }

    #[test]
    fn write_zones() {
        assert!(write_expected("/work/node_modules/x/build/out.node"));
        assert!(write_expected("/tmp/x"));
        assert!(!write_expected("/home/dev/.bashrc"));
        assert!(!write_expected("/work/src/index.js"));
    }

    #[test]
    fn rates_by_impact() {
        let b = |kind, target: &str| Behavior {
            phase: Phase::Install,
            kind,
            target: target.into(),
            actor: String::new(),
        };
        assert_eq!(rate(&b(Kind::Write, "~/.bashrc")).0, Severity::Critical);
        assert_eq!(rate(&b(Kind::Write, "~/notes.txt")).0, Severity::High);
        assert_eq!(
            rate(&b(Kind::Exec, "curl -s http://x")).0,
            Severity::Critical
        );
        assert_eq!(rate(&b(Kind::Exec, "node build.js")).0, Severity::Medium);
        assert_eq!(
            rate(&b(Kind::Read, "~/.aws/credentials")).0,
            Severity::Critical
        );
        assert_eq!(rate(&b(Kind::Dns, "example.com")).0, Severity::High);
    }
}
