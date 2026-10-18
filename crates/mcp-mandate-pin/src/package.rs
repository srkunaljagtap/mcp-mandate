//! Spotting servers launched from a package with no pinned version.
//!
//! Launchers such as `npx -y some-server` fetch the newest release on every
//! run, so a server's code can change while its tool descriptions (and so
//! its pins) stay the same. This is a heuristic for a warning, not a check.

use std::path::Path;

/// Options of npm-style launchers that take a value, so the value isn't
/// mistaken for the package.
const NPM_VALUE_OPTIONS: &[&str] = &[
    "--registry",
    "--cache",
    "--prefix",
    "--userconfig",
    "-c",
    "--call",
    "-w",
    "--workspace",
];
/// The same for `pnpm dlx` and `yarn dlx`, whose `-c` takes no value.
const DLX_VALUE_OPTIONS: &[&str] = &["--registry", "--cache", "--prefix", "--userconfig"];
/// The same for uvx.
const UVX_VALUE_OPTIONS: &[&str] = &[
    "-p",
    "--python",
    "--with",
    "--with-editable",
    "--with-requirements",
    "--index",
    "--default-index",
    "-i",
    "--index-url",
    "--extra-index-url",
    "-f",
    "--find-links",
    "--cache-dir",
    "--directory",
    "--project",
    "--config-file",
    "--env-file",
];

/// If `program` is a package launcher (npx, bunx, pnpm dlx, yarn dlx, uvx)
/// and the package it runs has no pinned version, returns the package spec.
pub fn unpinned_package(program: &str, args: &[String]) -> Option<String> {
    let launcher = Path::new(program)
        .file_stem()?
        .to_str()?
        .to_ascii_lowercase();
    match launcher.as_str() {
        "npx" | "bunx" => {
            unversioned_npm(package_arg(args, &["-p", "--package"], NPM_VALUE_OPTIONS)?)
        }
        "pnpm" | "yarn" => {
            let dlx = args.iter().position(|arg| arg == "dlx")?;
            unversioned_npm(package_arg(
                &args[dlx + 1..],
                &["-p", "--package"],
                DLX_VALUE_OPTIONS,
            )?)
        }
        "uvx" => unversioned_python(package_arg(args, &["--from"], UVX_VALUE_OPTIONS)?),
        _ => None,
    }
}

/// The package a launcher runs: the value of a package option if given,
/// else the first argument that is neither an option nor an option's value.
fn package_arg<'a>(
    args: &'a [String],
    package_options: &[&str],
    value_options: &[&str],
) -> Option<&'a str> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if package_options.contains(&arg.as_str()) {
            return iter.next().map(String::as_str);
        }
        for option in package_options {
            if let Some(value) = arg.strip_prefix(&format!("{option}=")) {
                return Some(value);
            }
        }
        if value_options.contains(&arg.as_str()) {
            iter.next();
        } else if !arg.starts_with('-') {
            return Some(arg);
        }
    }
    None
}

/// npm specs carry a version after the last `@` that isn't a scope's
/// leading one: `pkg@1.2.3`, `@scope/pkg@1.2.3`. Only an exact version is
/// pinned: tags (`latest`, `beta`) and ranges (`^1.2.0`, `1.x`, `*`) move.
fn unversioned_npm(spec: &str) -> Option<String> {
    let version = spec
        .rfind('@')
        .filter(|&at| at > 0)
        .map(|at| &spec[at + 1..]);
    match version {
        Some(version) if exact_semver(version) => None,
        _ => Some(spec.to_owned()),
    }
}

/// Python specs pin with `pkg==1.2.3` or `pkg@1.2.3`. Anything else moves:
/// no version, `pkg@latest`, ranges (`>=1.0`, `~=1.2`), wildcards (`==1.*`).
fn unversioned_python(spec: &str) -> Option<String> {
    let version = spec
        .split_once("==")
        .or_else(|| spec.rsplit_once('@'))
        .map(|(_, version)| version.trim_start_matches('='));
    match version {
        Some(version) if exact_python_version(version) => None,
        _ => Some(spec.to_owned()),
    }
}

/// `1.2.3`, optionally with a pre-release (`-beta.1`) and build (`+abc`).
fn exact_semver(version: &str) -> bool {
    let (core, suffix) = match version.find(['-', '+']) {
        Some(at) => version.split_at(at),
        None => (version, ""),
    };
    let numbers: Vec<&str> = core.split('.').collect();
    numbers.len() == 3
        && numbers
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
}

/// A single exact version such as `0.6.2`, `2024.1` or `1.0rc1`: no
/// wildcard, range or list.
fn exact_python_version(version: &str) -> bool {
    version.starts_with(|c: char| c.is_ascii_digit())
        && version.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+' | b'!')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(command: &str) -> Option<String> {
        let mut parts = command.split_whitespace().map(str::to_owned);
        let program = parts.next().unwrap();
        unpinned_package(&program, &parts.collect::<Vec<_>>())
    }

    #[test]
    fn flags_packages_without_a_version() {
        assert_eq!(
            check("npx -y @modelcontextprotocol/server-everything").as_deref(),
            Some("@modelcontextprotocol/server-everything")
        );
        assert_eq!(
            check("npx some-server@latest").as_deref(),
            Some("some-server@latest")
        );
        assert_eq!(
            check("pnpm dlx some-server").as_deref(),
            Some("some-server")
        );
        assert_eq!(
            check("uvx mcp-server-git").as_deref(),
            Some("mcp-server-git")
        );
        assert_eq!(
            check("C:/tools/npx.cmd -y server").as_deref(),
            Some("server")
        );
    }

    #[test]
    fn flags_versions_that_move() {
        for spec in [
            "some-server@^1.2.0",
            "some-server@~1.2.0",
            "some-server@1",
            "some-server@1.2",
            "some-server@1.x",
            "some-server@*",
            "some-server@beta",
            "some-server@canary",
            "some-server@>=1.2.3",
            "@scope/server@next",
        ] {
            assert_eq!(check(&format!("npx -y {spec}")).as_deref(), Some(spec));
        }
        for spec in [
            "mcp-server-git@latest",
            "mcp-server-git>=0.6",
            "mcp-server-git~=0.6",
            "mcp-server-git==0.*",
            "mcp-server-git==0.6,<1",
        ] {
            assert_eq!(check(&format!("uvx {spec}")).as_deref(), Some(spec));
        }
    }

    #[test]
    fn skips_the_values_of_options() {
        assert_eq!(
            check("npx --registry https://u@registry.example/ some-server").as_deref(),
            Some("some-server")
        );
        assert_eq!(
            check("uvx --python 3.12 --with httpx==0.28.1 mcp-server-git").as_deref(),
            Some("mcp-server-git")
        );
        assert_eq!(
            check("npx --registry https://registry.example/ some-server@1.2.3"),
            None
        );
    }

    #[test]
    fn accepts_pinned_versions_and_other_programs() {
        assert_eq!(
            check("npx -y @modelcontextprotocol/server-everything@2025.9.25"),
            None
        );
        assert_eq!(check("npx -p some-server@1.2.3 run-it"), None);
        assert_eq!(check("npx some-server@1.2.3-beta.1"), None);
        assert_eq!(check("uvx mcp-server-git==0.6.2"), None);
        assert_eq!(check("uvx mcp-server-git@0.6.2"), None);
        assert_eq!(check("uvx mcp-server-git[cli]===0.6.2"), None);
        assert_eq!(
            check("uvx --from mcp-server-git@0.6.2 mcp-server-git"),
            None
        );
        assert_eq!(check("node build/index.js"), None);
        assert_eq!(check("./my-server --port 1"), None);
    }
}
