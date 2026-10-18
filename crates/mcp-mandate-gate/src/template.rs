//! Matching resource URIs against an approved template (RFC 6570, level 1
//! and 2 forms), strictly enough that a variable can't climb out of the
//! place the template names.
//!
//! - `{var}` matches one path segment's worth of text: no `/`, `?` or `#`,
//!   even percent-encoded.
//! - `{+var}` may span segments, but never a `.` or `..` segment (before or
//!   after percent-decoding), and no `?` or `#`.
//! - A template without variables matches only itself.
//! - Any other expression (`{#x}`, `{.x}`, `{/x}`, `{;x}`, `{?x}`, `{&x}`)
//!   matches nothing: the gate can't tell what it would reach, so it fails
//!   closed.

use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Variable {
    Simple,
    Reserved,
}

/// An approved resource template.
pub(crate) struct Template {
    /// `None` when the template uses an expression this doesn't support.
    pattern: Option<(Regex, Vec<Variable>)>,
}

impl Template {
    pub(crate) fn parse(template: &str) -> Self {
        let mut source = String::from("^");
        let mut variables = Vec::new();
        let mut rest = template;
        while let Some(open) = rest.find('{') {
            source.push_str(&regex::escape(&rest[..open]));
            let Some(close) = rest[open..].find('}') else {
                return Self { pattern: None };
            };
            let expression = &rest[open + 1..open + close];
            let (variable, group) = match expression.chars().next() {
                Some('+') => (Variable::Reserved, "([^?#]*)"),
                Some(c) if c.is_ascii_alphanumeric() || c == '_' || c == '%' => {
                    (Variable::Simple, "([^/?#]*)")
                }
                _ => return Self { pattern: None },
            };
            source.push_str(group);
            variables.push(variable);
            rest = &rest[open + close + 1..];
        }
        source.push_str(&regex::escape(rest));
        source.push('$');
        Self {
            pattern: Regex::new(&source).ok().map(|regex| (regex, variables)),
        }
    }

    pub(crate) fn matches(&self, uri: &str) -> bool {
        let Some((regex, variables)) = &self.pattern else {
            return false;
        };
        let Some(captures) = regex.captures(uri) else {
            return false;
        };
        variables.iter().enumerate().all(|(index, variable)| {
            let raw = captures.get(index + 1).map_or("", |value| value.as_str());
            let decoded = percent_decode(raw);
            match variable {
                Variable::Simple => !decoded.contains(['/', '\\', '?', '#']),
                Variable::Reserved => {
                    !decoded.contains(['?', '#'])
                        && ![raw, decoded.as_str()].iter().any(|text| {
                            text.split(['/', '\\'])
                                .any(|segment| segment == "." || segment == "..")
                        })
                }
            }
        })
    }
}

/// `%XX` sequences decoded (lossily); anything else kept as is.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let hex = bytes
            .get(index + 1..index + 3)
            .and_then(|pair| std::str::from_utf8(pair).ok())
            .and_then(|pair| u8::from_str_radix(pair, 16).ok());
        match (bytes[index], hex) {
            (b'%', Some(byte)) => {
                out.push(byte);
                index += 3;
            }
            (byte, _) => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_simple_variable_stays_within_one_segment() {
        let docs = Template::parse("docs://pages/{id}");
        assert!(docs.matches("docs://pages/intro"));
        assert!(docs.matches("docs://pages/"));
        for escape in [
            "docs://pages/../../etc/passwd",
            "docs://pages/a/b",
            "docs://pages/%2e%2e%2fsecrets",
            "docs://pages/a%2Fb",
            "docs://pages/a?x=1",
            "docs://other/intro",
            "docs://pages.evil/x",
        ] {
            assert!(!docs.matches(escape), "{escape}");
        }
    }

    #[test]
    fn a_reserved_variable_spans_segments_but_never_climbs() {
        let files = Template::parse("file:///home/u/project/{+path}");
        assert!(files.matches("file:///home/u/project/src/main.rs"));
        for escape in [
            "file:///home/u/project/../../.ssh/id_rsa",
            "file:///home/u/project/src/%2e%2e/%2e%2e/.aws/credentials",
            "file:///home/u/project/./x",
            "file:///home/u/project/a\\..\\b",
            "file:///home/u/projectx/y",
        ] {
            assert!(!files.matches(escape), "{escape}");
        }
    }

    #[test]
    fn a_template_without_variables_matches_only_itself() {
        let exact = Template::parse("docs://a");
        assert!(exact.matches("docs://a"));
        assert!(!exact.matches("docs://a.evil/x"));
    }

    #[test]
    fn unsupported_expressions_match_nothing() {
        for template in [
            "search://q{?query}",
            "docs://{#frag}",
            "docs://{/path}",
            "broken://{id",
        ] {
            let parsed = Template::parse(template);
            assert!(!parsed.matches("search://q?query=x"), "{template}");
            assert!(!parsed.matches("docs://x"), "{template}");
        }
    }
}
