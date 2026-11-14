//! A small, allocation-light parser for `strace -f -y -o FILE` output.
//!
//! It only understands what the analyzer needs: joining `<unfinished ...>` /
//! `<... resumed>` pairs, splitting a call into name, raw arguments and
//! result, and pulling quoted strings and socket addresses out of arguments.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ret {
    Ok(i64),
    Err(String),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub pid: u32,
    pub name: String,
    pub args: String,
    pub ret: Ret,
}

#[derive(Default)]
pub struct Parser {
    pending: HashMap<u32, String>,
}

impl Parser {
    /// Feed one line; returns a call once it is complete.
    pub fn feed(&mut self, line: &str) -> Option<Call> {
        let line = line.trim_end();
        let (pid, rest) = line.split_once(char::is_whitespace)?;
        let pid: u32 = pid.parse().ok()?;
        let rest = rest.trim_start();
        if rest.starts_with("+++") || rest.starts_with("---") {
            return None;
        }
        if let Some(resumed) = rest.strip_prefix("<... ") {
            let (_, tail) = resumed.split_once(" resumed>")?;
            let mut full = self.pending.remove(&pid)?;
            full.push_str(tail);
            return parse_complete(pid, &full);
        }
        if let Some(head) = rest.strip_suffix("<unfinished ...>") {
            self.pending.insert(pid, head.trim_end().to_string());
            return None;
        }
        parse_complete(pid, rest)
    }
}

fn parse_complete(pid: u32, s: &str) -> Option<Call> {
    let open = s.find('(')?;
    let name = &s[..open];
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return None;
    }
    let eq = s.rfind(" = ")?;
    let close = s[..eq].rfind(')')?;
    if close < open {
        return None;
    }
    Some(Call {
        pid,
        name: name.to_string(),
        args: s[open + 1..close].to_string(),
        ret: parse_ret(s[eq + 3..].trim()),
    })
}

fn parse_ret(s: &str) -> Ret {
    let mut tokens = s.split_whitespace();
    let Some(first) = tokens.next() else {
        return Ret::Unknown;
    };
    if first == "-1" {
        return match tokens.next() {
            Some(errno) if errno.starts_with('E') => Ret::Err(errno.to_string()),
            _ => Ret::Ok(-1),
        };
    }
    // With `-y` a returned fd looks like `3</path>`; keep the number only.
    let digits = first.split('<').next().unwrap_or(first);
    if let Some(hex) = digits.strip_prefix("0x") {
        return i64::from_str_radix(hex, 16).map_or(Ret::Unknown, Ret::Ok);
    }
    digits.parse().map_or(Ret::Unknown, Ret::Ok)
}

/// A quoted string argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrTok {
    pub value: String,
    /// Nesting depth in `[...]`, so argv entries can be told from the path.
    pub depth: u32,
    /// Byte offset of the opening quote within the argument text.
    pub start: usize,
}

/// Extract every quoted string from an argument list, decoding escapes.
pub fn strings(args: &str) -> Vec<StrTok> {
    let b = args.as_bytes();
    let mut out = Vec::new();
    let mut depth = 0u32;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'[' => depth += 1,
            b']' => depth = depth.saturating_sub(1),
            b'"' => {
                let start = i;
                let mut buf = Vec::new();
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' && i + 1 < b.len() {
                        i += 1;
                        i += unescape(&b[i..], &mut buf);
                    } else {
                        buf.push(b[i]);
                        i += 1;
                    }
                }
                out.push(StrTok {
                    value: String::from_utf8_lossy(&buf).into_owned(),
                    depth,
                    start,
                });
            }
            _ => {}
        }
        i += 1;
    }
    out
}

/// Decode one escape sequence (after the backslash); returns bytes consumed.
fn unescape(b: &[u8], buf: &mut Vec<u8>) -> usize {
    match b[0] {
        b'n' => buf.push(b'\n'),
        b't' => buf.push(b'\t'),
        b'r' => buf.push(b'\r'),
        b'x' => {
            let hex: Vec<u8> = b[1..]
                .iter()
                .copied()
                .take(2)
                .take_while(u8::is_ascii_hexdigit)
                .collect();
            if let Ok(v) = u8::from_str_radix(&String::from_utf8_lossy(&hex), 16) {
                buf.push(v);
                return 1 + hex.len();
            }
            buf.push(b'x');
        }
        b'0'..=b'7' => {
            let oct: Vec<u8> = b
                .iter()
                .copied()
                .take(3)
                .take_while(|c| (b'0'..=b'7').contains(c))
                .collect();
            let v = u32::from_str_radix(&String::from_utf8_lossy(&oct), 8).unwrap_or(0);
            buf.push(v as u8);
            return oct.len();
        }
        other => buf.push(other),
    }
    1
}

/// The argument text with all string literals blanked out, for flag checks
/// that must not be fooled by file names such as `O_WRONLY.txt`.
pub fn without_strings(args: &str) -> String {
    let mut out = String::with_capacity(args.len());
    let mut last = 0;
    let b = args.as_bytes();
    for tok in strings(args) {
        out.push_str(&args[last..tok.start]);
        let mut end = tok.start + 1;
        while end < b.len() && b[end] != b'"' {
            end += if b[end] == b'\\' { 2 } else { 1 };
        }
        last = (end + 1).min(args.len());
    }
    out.push_str(&args[last..]);
    out
}

/// For `*at()` calls with `-y`: the directory a relative path is resolved
/// against, read from the `fd</dir>` annotation preceding the string.
pub fn dirfd_before(args: &str, start: usize) -> Option<&str> {
    let pre = args[..start].trim_end().trim_end_matches(',');
    let pre = pre.strip_suffix('>')?;
    let lt = pre.rfind('<')?;
    Some(&pre[lt + 1..])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Addr {
    Inet { ip: String, port: u16 },
    Unix(String),
}

/// Find a socket address structure in the arguments of `connect`, `sendto`,
/// `sendmsg` and friends.
///
/// strace escapes quotes inside buffers, so the unescaped markers searched
/// for here cannot be forged by payload bytes.
pub fn sockaddr(args: &str) -> Option<Addr> {
    let at = args.find("sa_family=AF_")?;
    let s = &args[at..];
    if s.starts_with("sa_family=AF_INET6") {
        Some(Addr::Inet {
            ip: between(s, "inet_pton(AF_INET6, \"", "\"")?.to_string(),
            port: between(s, "sin6_port=htons(", ")")?.parse().ok()?,
        })
    } else if s.starts_with("sa_family=AF_INET") {
        Some(Addr::Inet {
            ip: between(s, "sin_addr=inet_addr(\"", "\"")?.to_string(),
            port: between(s, "sin_port=htons(", ")")?.parse().ok()?,
        })
    } else if s.starts_with("sa_family=AF_UNIX") {
        let rest = &s[s.find("sun_path=")? + "sun_path=".len()..];
        let abstract_ns = rest.starts_with('@');
        let tok = strings(rest).into_iter().next()?;
        Some(Addr::Unix(if abstract_ns {
            format!("@{}", tok.value)
        } else {
            tok.value
        }))
    } else {
        None
    }
}

fn between<'a>(s: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let from = s.find(open)? + open.len();
    let len = s[from..].find(close)?;
    Some(&s[from..from + len])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(line: &str) -> Call {
        Parser::default().feed(line).expect("line should parse")
    }

    #[test]
    fn parses_simple_call() {
        let c = one(
            r#"4242  openat(AT_FDCWD</work>, "/home/dev/.npmrc", O_RDONLY|O_CLOEXEC) = 17</home/dev/.npmrc>"#,
        );
        assert_eq!(c.pid, 4242);
        assert_eq!(c.name, "openat");
        assert_eq!(c.ret, Ret::Ok(17));
        assert_eq!(strings(&c.args)[0].value, "/home/dev/.npmrc");
    }

    #[test]
    fn parses_errno() {
        let c =
            one(r#"7  openat(AT_FDCWD, "/x", O_RDONLY) = -1 ENOENT (No such file or directory)"#);
        assert_eq!(c.ret, Ret::Err("ENOENT".into()));
    }

    #[test]
    fn joins_unfinished_and_resumed() {
        let mut p = Parser::default();
        assert!(p
            .feed(r#"10  openat(AT_FDCWD, "/etc/passwd", O_RDONLY <unfinished ...>"#)
            .is_none());
        assert!(p.feed(r#"11  chdir("/tmp") = 0"#).is_some());
        let c = p.feed("10  <... openat resumed>) = 3").unwrap();
        assert_eq!(c.name, "openat");
        assert_eq!(c.args, r#"AT_FDCWD, "/etc/passwd", O_RDONLY"#);
        assert_eq!(c.ret, Ret::Ok(3));
    }

    #[test]
    fn ignores_signals_and_exits() {
        let mut p = Parser::default();
        assert!(p.feed("10  +++ exited with 0 +++").is_none());
        assert!(p.feed("10  --- SIGCHLD {si_signo=SIGCHLD} ---").is_none());
    }

    #[test]
    fn argv_strings_carry_depth() {
        let c = one(
            r#"5  execve("/bin/sh", ["sh", "-c", "echo \"hi\" > a]b"], 0x7ffd /* 9 vars */) = 0"#,
        );
        let s = strings(&c.args);
        assert_eq!(s[0].depth, 0);
        let argv: Vec<_> = s
            .iter()
            .filter(|t| t.depth == 1)
            .map(|t| t.value.as_str())
            .collect();
        assert_eq!(argv, ["sh", "-c", "echo \"hi\" > a]b"]);
    }

    #[test]
    fn decodes_escapes() {
        let s = strings(r#""a\x41\101\n\\""#);
        assert_eq!(s[0].value, "aAA\n\\");
    }

    #[test]
    fn flags_ignore_string_contents() {
        let args = r#"AT_FDCWD, "/tmp/O_WRONLY \" x", O_RDONLY"#;
        let bare = without_strings(args);
        assert!(!bare.contains("O_WRONLY"));
        assert!(bare.contains("O_RDONLY"));
    }

    #[test]
    fn reads_dirfd_annotation() {
        let args = r#"5</work/node_modules/x>, "lib/a.js", O_RDONLY"#;
        let tok = &strings(args)[0];
        assert_eq!(dirfd_before(args, tok.start), Some("/work/node_modules/x"));
        assert_eq!(dirfd_before(r#""abs""#, 0), None);
    }

    #[test]
    fn parses_socket_addresses() {
        let v4 = r#"3<socket:[1]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16"#;
        assert_eq!(
            sockaddr(v4),
            Some(Addr::Inet {
                ip: "93.184.216.34".into(),
                port: 443
            })
        );
        let v6 = r#"3, {sa_family=AF_INET6, sin6_port=htons(53), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, 28"#;
        assert_eq!(
            sockaddr(v6),
            Some(Addr::Inet {
                ip: "::1".into(),
                port: 53
            })
        );
        let unix = r#"3, {sa_family=AF_UNIX, sun_path="/var/run/docker.sock"}, 110"#;
        assert_eq!(
            sockaddr(unix),
            Some(Addr::Unix("/var/run/docker.sock".into()))
        );
        assert_eq!(sockaddr(r#"3, "inet_addr(\"1.2.3.4\")", 5"#), None);
    }
}
