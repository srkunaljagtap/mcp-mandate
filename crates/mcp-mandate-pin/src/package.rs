//! Spotting servers launched from a package with no pinned version.
//!
//! Launchers such as `npx -y some-server` fetch the newest release on every
//! run, so a server's code can change while its tool descriptions (and so
//! its pins) stay the same. This is a heuristic for a warning, not a check.

use std::path::Path;

/// If `program` is a package launcher (npx, bunx, pnpm dlx, yarn dlx, uvx)
/// and the package it runs has no pinned version, returns the package spec.
pub fn unpinned_package(program: &str, args: &[String]) -> Option<String> {
    let launcher = Path::new(program)
        .file_stem()?
        .to_str()?
        .to_ascii_lowercase();
    match launcher.as_str() {
        "npx" | "bunx" => unversioned_npm(package_arg(args, &["-p", "--package"])?),
        "pnpm" | "yarn" => {
            let dlx = args.iter().position(|arg| arg == "dlx")?;
            unversioned_npm(package_arg(&args[dlx + 1..], &["-p", "--package"])?)
        }
        "uvx" => {
            let spec = package_arg(args, &["--from"])?;
            (!spec.contains("==") && !spec.contains('@')).then(|| spec.to_owned())
        }
        _ => None,
    }
}

/// The package a launcher runs: the value of a package option if given,
/// else the first argument that isn't an option.
fn package_arg<'a>(args: &'a [String], package_options: &[&str]) -> Option<&'a str> {
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
        if !arg.starts_with('-') {
            return Some(arg);
        }
    }
    None
}

/// npm specs carry a version after the last `@` that isn't a scope's
/// leading one: `pkg@1.2.3`, `@scope/pkg@1.2.3`. Tags like `latest` move.
fn unversioned_npm(spec: &str) -> Option<String> {
    let version = spec
        .rfind('@')
        .filter(|&at| at > 0)
        .map(|at| &spec[at + 1..]);
    match version {
        Some(version) if !version.is_empty() && version != "latest" && version != "next" => None,
        _ => Some(spec.to_owned()),
    }
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
    fn accepts_pinned_versions_and_other_programs() {
        assert_eq!(
            check("npx -y @modelcontextprotocol/server-everything@2025.9.25"),
            None
        );
        assert_eq!(check("npx -p some-server@1.2.3 run-it"), None);
        assert_eq!(check("uvx mcp-server-git==0.6.2"), None);
        assert_eq!(
            check("uvx --from mcp-server-git@0.6.2 mcp-server-git"),
            None
        );
        assert_eq!(check("node build/index.js"), None);
        assert_eq!(check("./my-server --port 1"), None);
    }
}
