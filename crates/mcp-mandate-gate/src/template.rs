//! Matching resource URIs against an approved template (RFC 6570, level 1
//! and 2 forms), strictly enough that a variable can't climb out of the
//! place the template names.
//!
//! - `{var}` matches one path segment's worth of text: no `/`, `?` or `#`,
//!   even percent-encoded.
//! - `{+var}` may span segments, but no `?` or `#`.
//! - Whatever the variables hold, the URI can't have a `.` or `..` segment
//!   (before or after percent-decoding) that the template doesn't have
//!   itself: not from one variable, from two side by side (`{a}{b}` as `.`
//!   and `.`), or from a variable next to a dot (`.{a}` as `.`).
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
    /// The template's own `.` and `..` segments, as written and
    /// percent-decoded: a matching URI may have those and no more.
    dots: [usize; 2],
}

impl Template {
    pub(crate) fn parse(template: &str) -> Self {
        let dots = dot_segments(template);
        let mut source = String::from("^");
        let mut variables = Vec::new();
        let mut rest = template;
        while let Some(open) = rest.find('{') {
            source.push_str(&regex::escape(&rest[..open]));
            let Some(close) = rest[open..].find('}') else {
                return Self {
                    pattern: None,
                    dots,
                };
            };
            let expression = &rest[open + 1..open + close];
            let (variable, group) = match expression.chars().next() {
                Some('+') => (Variable::Reserved, "([^?#]*)"),
                Some(c) if c.is_ascii_alphanumeric() || c == '_' || c == '%' => {
                    (Variable::Simple, "([^/?#]*)")
                }
                _ => {
                    return Self {
                        pattern: None,
                        dots,
                    };
                }
            };
            source.push_str(group);
            variables.push(variable);
            rest = &rest[open + close + 1..];
        }
        source.push_str(&regex::escape(rest));
        source.push('$');
        Self {
            pattern: Regex::new(&source).ok().map(|regex| (regex, variables)),
            dots,
        }
    }

    pub(crate) fn matches(&self, uri: &str) -> bool {
        let Some((regex, variables)) = &self.pattern else {
            return false;
        };
        let Some(captures) = regex.captures(uri) else {
            return false;
        };
        // Counted over the whole URI, not one variable at a time: two
        // variables, or a variable and a literal dot, can make a segment
        // neither makes alone.
        let dots = dot_segments(uri);
        if dots[0] > self.dots[0] || dots[1] > self.dots[1] {
            return false;
        }
        variables.iter().enumerate().all(|(index, variable)| {
            let raw = captures.get(index + 1).map_or("", |value| value.as_str());
            let decoded = percent_decode(raw);
            match variable {
                Variable::Simple => !decoded.contains(['/', '\\', '?', '#']),
                Variable::Reserved => !decoded.contains(['?', '#']),
            }
        })
    }
}

/// How many `.` and `..` segments `text` has, as written and
/// percent-decoded (`\` counts as a separator too).
fn dot_segments(text: &str) -> [usize; 2] {
    let count = |text: &str| {
        text.split(['/', '\\'])
            .filter(|segment| matches!(*segment, "." | ".."))
            .count()
    };
    [count(text), count(&percent_decode(text))]
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
    fn no_variable_makes_a_dot_segment() {
        let cases = [
            ("file:///docs/{name}", "file:///docs/.."),
            ("file:///docs/{name}", "file:///docs/%2e%2e"),
            ("file:///docs/{name}", "file:///docs/%2E."),
            ("file:///docs/{name}", "file:///docs/."),
            ("file:///p/{a}/{b}", "file:///p/../.aws"),
            ("file:///p/{a}{b}", "file:///p/.%2e"),
            ("file:///p/.{a}", "file:///p/.."),
            ("file:///p/.{a}", "file:///p/."),
            ("file:///base/{dir}/{+rest}", "file:///base/../etc/passwd"),
            ("docs://a/./{x}", "docs://a/./.."),
        ];
        for (template, uri) in cases {
            assert!(!Template::parse(template).matches(uri), "{template} {uri}");
        }
        // Dots inside a name are fine, and so is a dot segment the
        // template has itself.
        for (template, uri) in [
            ("file:///docs/{name}", "file:///docs/.env"),
            ("file:///docs/{name}", "file:///docs/..."),
            ("file:///docs/{name}", "file:///docs/v1..2.md"),
            ("file:///p/.{a}", "file:///p/.env"),
            (
                "file:///base/{dir}/{+rest}",
                "file:///base/src/.config/app.toml",
            ),
            ("docs://a/./{x}", "docs://a/./y"),
        ] {
            assert!(Template::parse(template).matches(uri), "{template} {uri}");
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
