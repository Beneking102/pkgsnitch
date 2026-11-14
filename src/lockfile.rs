//! Reads the pinned versions out of lockfiles that are not npm's JSON:
//! `yarn.lock`, `pnpm-lock.yaml`, and the TOML locks of Poetry, uv and PDM.
//!
//! These formats are recognized by their content, not their file name, and
//! parsed line by line: only package names and versions are needed, which
//! each format writes in a fixed, simple shape.

use crate::sandbox::Ecosystem;

/// One pinned package: name and exact version.
pub type Pin = (String, String);

/// The pins of a yarn, pnpm or TOML lockfile, or `None` if `text` is none
/// of those.
pub fn pinned(text: &str) -> Option<(Ecosystem, Vec<Pin>)> {
    let has_line = |wanted: &str| text.lines().any(|line| line.trim_end() == wanted);
    // A Cargo.lock has the same tables as the Python locks but is neither.
    if text.trim_start().starts_with('{') || crate::manifest::is_cargo_lock(text) {
        None
    } else if has_line("[[package]]") {
        Some((Ecosystem::PyPI, toml_packages(text)))
    } else if text.contains("# yarn lockfile v1") || has_line("__metadata:") {
        Some((Ecosystem::Npm, yarn(text)))
    } else if text
        .lines()
        .any(|line| line.starts_with("lockfileVersion:"))
    {
        Some((Ecosystem::Npm, pnpm(text)))
    } else {
        None
    }
}

/// `poetry.lock`, `uv.lock`, `pdm.lock`: a `[[package]]` table per package.
fn toml_packages(text: &str) -> Vec<Pin> {
    let mut pins = Vec::new();
    let mut inside = false;
    let (mut name, mut version): (Option<String>, Option<String>) = (None, None);
    let value = |line: &str, key: &str| {
        let rest = line.strip_prefix(key)?.trim_start().strip_prefix('=')?;
        Some(rest.trim().trim_matches('"').to_string())
    };
    for line in text.lines().map(str::trim).chain(["["]) {
        if line.starts_with('[') {
            if let (Some(name), Some(version)) = (name.take(), version.take()) {
                pins.push((normalize_python(&name), version));
            }
            inside = line == "[[package]]";
        } else if inside {
            name = name.or_else(|| value(line, "name"));
            version = version.or_else(|| value(line, "version"));
        }
    }
    pins
}

/// `yarn.lock`, classic and Berry. A block starts with the requests it
/// satisfies (`"@scope/name@^1.0.0", name@~1.2:`) and holds one version.
fn yarn(text: &str) -> Vec<Pin> {
    let mut pins = Vec::new();
    let mut names: Vec<String> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') {
            names = line
                .trim_end()
                .trim_end_matches(':')
                .split(',')
                .filter_map(|request| yarn_name(request.trim().trim_matches('"')))
                .map(str::to_string)
                .collect();
            names.dedup();
        } else if let Some(rest) = line.trim().strip_prefix("version") {
            let version = rest.trim_start_matches(':').trim().trim_matches('"');
            // Berry lists the project's own workspaces with a fake version.
            if !version.is_empty() && !version.contains("use.local") {
                pins.extend(names.drain(..).map(|name| (name, version.to_string())));
            }
        }
    }
    pins
}

/// The package a yarn request installs. The name ends at the first `@` that
/// is not the scope's. An alias (`eslint-v7@npm:eslint@^7.7.0`) is installed
/// under one name but *is* another package, and that one is what counts.
fn yarn_name(request: &str) -> Option<&str> {
    let at = request.get(1..)?.find('@')? + 1;
    let (name, range) = (&request[..at], &request[at + 1..]);
    let aliased = range
        .strip_prefix("npm:")
        .and_then(|real| Some(&real[..real.get(1..)?.rfind('@')? + 1]));
    Some(aliased.unwrap_or(name))
}

/// `pnpm-lock.yaml`: the keys of the `packages:` section, written as
/// `/name@1.2.3`, `name@1.2.3(peer@2)` or, in old files, `/name/1.2.3`.
fn pnpm(text: &str) -> Vec<Pin> {
    let mut pins = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        if !line.starts_with(' ') && !line.trim().is_empty() {
            inside = line.trim_end() == "packages:";
            continue;
        }
        let is_key =
            line.starts_with("  ") && !line.starts_with("   ") && line.trim_end().ends_with(':');
        if !inside || !is_key {
            continue;
        }
        let key = line.trim().trim_end_matches(':').trim_matches(['\'', '"']);
        let key = key.trim_start_matches('/');
        let key = key.split('(').next().unwrap_or(key);
        // Old files separate name and version with a slash; the version is
        // then the last path segment and starts with a digit.
        let old_style = key
            .rfind('/')
            .filter(|at| key[at + 1..].starts_with(|c: char| c.is_ascii_digit()));
        let split = old_style.or_else(|| Some(key.get(1..)?.rfind('@')? + 1));
        let Some(at) = split else { continue };
        // Old files append the peers after an underscore.
        let version = key[at + 1..].split('_').next().unwrap_or("");
        if !version.is_empty() && version.starts_with(|c: char| c.is_ascii_digit()) {
            pins.push((key[..at].to_string(), version.to_string()));
        }
    }
    pins
}

/// PyPI treats `Foo_Bar`, `foo-bar` and `foo.bar` as one name.
pub fn normalize_python(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !out.ends_with('-') {
                out.push('-');
            }
        } else {
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pins(text: &str) -> (Ecosystem, Vec<(String, String)>) {
        pinned(text).expect("should be recognized")
    }

    fn pair(name: &str, version: &str) -> Pin {
        (name.to_string(), version.to_string())
    }

    #[test]
    fn reads_yarn_classic() {
        let text = "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n\n\"@babel/core@^7.0.0\", \"@babel/core@^7.24.0\":\n  version \"7.24.5\"\n  resolved \"https://registry.yarnpkg.com/@babel/core/-/core-7.24.5.tgz#abc\"\n  dependencies:\n    debug \"^4.1.0\"\n\ndebug@^4.1.0:\n  version \"4.3.4\"\n\nleft-pad@1.2.0, left-pad@^1.2.0:\n  version \"1.2.0\"\n";
        let (ecosystem, found) = pins(text);
        assert_eq!(ecosystem, Ecosystem::Npm);
        assert_eq!(
            found,
            [
                pair("@babel/core", "7.24.5"),
                pair("debug", "4.3.4"),
                pair("left-pad", "1.2.0")
            ]
        );
    }

    #[test]
    fn reads_yarn_berry() {
        let text = "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\"left-pad@npm:^1.3.0\":\n  version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n  checksum: abc\n  languageName: node\n  linkType: hard\n\n\"my-app@workspace:.\":\n  version: 0.0.0-use.local\n  resolution: \"my-app@workspace:.\"\n";
        assert_eq!(pins(text).1, [pair("left-pad", "1.3.0")]);
    }

    #[test]
    fn yarn_aliases_resolve_to_the_real_package() {
        assert_eq!(yarn_name("left-pad@^1.2.0"), Some("left-pad"));
        assert_eq!(yarn_name("@babel/core@^7.0.0"), Some("@babel/core"));
        assert_eq!(yarn_name("left-pad@npm:^1.3.0"), Some("left-pad"));
        assert_eq!(yarn_name("eslint-v7@npm:eslint@^7.7.0"), Some("eslint"));
        assert_eq!(
            yarn_name("@typescript-eslint/parser-v2@npm:@typescript-eslint/parser@^2.26.0"),
            Some("@typescript-eslint/parser")
        );
        assert_eq!(
            yarn_name("esbuild@npm:esbuild-wasm@^0.23.0"),
            Some("esbuild-wasm")
        );
        assert_eq!(
            yarn_name("typescript@patch:typescript@npm%3A^5.5.2#builtin"),
            Some("typescript")
        );
        assert_eq!(yarn_name("__metadata"), None);

        let classic = "# yarn lockfile v1\n\n\n\"eslint-v7@npm:eslint@^7.7.0\":\n  version \"7.32.0\"\n\neslint@^8.57.1:\n  version \"8.57.1\"\n";
        assert_eq!(
            pins(classic).1,
            [pair("eslint", "7.32.0"), pair("eslint", "8.57.1")]
        );
    }

    #[test]
    fn reads_pnpm_in_every_generation() {
        let v9 = "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      left-pad:\n        specifier: ^1.3.0\n        version: 1.3.0\n\npackages:\n\n  left-pad@1.3.0:\n    resolution: {integrity: sha512-abc}\n\n  '@scope/pkg@2.0.0(react@18.2.0)':\n    resolution: {integrity: sha512-def}\n\nsnapshots:\n\n  left-pad@1.3.0: {}\n";
        assert_eq!(
            pins(v9),
            (
                Ecosystem::Npm,
                vec![pair("left-pad", "1.3.0"), pair("@scope/pkg", "2.0.0")]
            )
        );
        let v6 = "lockfileVersion: '6.0'\n\npackages:\n\n  /left-pad@1.3.0:\n    resolution: {integrity: sha512-abc}\n    dev: false\n\n  /@scope/pkg@2.0.0(react@18.2.0):\n    dev: false\n";
        assert_eq!(
            pins(v6).1,
            [pair("left-pad", "1.3.0"), pair("@scope/pkg", "2.0.0")]
        );
        let v5 = "lockfileVersion: 5.4\n\npackages:\n\n  /left-pad/1.3.0:\n    dev: false\n\n  /@scope/pkg/2.0.0_react@18.2.0:\n    dev: false\n";
        assert_eq!(
            pins(v5).1,
            [pair("left-pad", "1.3.0"), pair("@scope/pkg", "2.0.0")]
        );
    }

    #[test]
    fn reads_python_toml_locks() {
        let poetry = "# This file is automatically @generated by Poetry.\n\n[[package]]\nname = \"Charset_Normalizer\"\nversion = \"3.3.2\"\ndescription = \"x\"\noptional = false\n\n[package.dependencies]\nname = \"not-a-package\"\n\n[[package]]\nname = \"idna\"\nversion = \"3.6\"\n\n[metadata]\nlock-version = \"2.0\"\n";
        assert_eq!(
            pins(poetry),
            (
                Ecosystem::PyPI,
                vec![pair("charset-normalizer", "3.3.2"), pair("idna", "3.6")]
            )
        );
        let uv = "version = 1\nrequires-python = \">=3.12\"\n\n[[package]]\nname = \"requests\"\nversion = \"2.32.3\"\nsource = { registry = \"https://pypi.org/simple\" }\n";
        assert_eq!(pins(uv).1, [pair("requests", "2.32.3")]);
    }

    #[test]
    fn leaves_other_files_alone() {
        assert_eq!(pinned("{\"lockfileVersion\": 3}"), None);
        assert_eq!(pinned("requests==2.31.0\nidna==3.6\n"), None);
        assert_eq!(pinned(""), None);
    }
}
