//! Matching resource URIs against an approved template (RFC 6570, level 1
//! and 2 forms), strictly enough that a variable can't climb out of the
//! place the template names.
//!
//! - `{var}` matches one path segment's worth of text: no `/`, `?` or `#`,
//!   even percent-encoded.
//! - `{+var}` may span segments, but no `?` or `#`.
//! - No variable holds whitespace or a control character unencoded, ASCII
//!   or not: expanding a template encodes them, and URL parsers drop or
//!   trim some of them (`.\t.` becomes `..`) before they resolve the path,
//!   as do servers that trim text (`..` and a no-break space).
//! - Whatever the variables hold, the URI can't have a `.` or `..` segment
//!   (before or after percent-decoding) that the template's own text
//!   doesn't have: not in one variable (`{+path}` as `../x`, wherever it
//!   sits, or as `&path=../x` after `?path=`, which a query parser reads
//!   as a second `path`), from two side by side (`{a}{b}` as `.` and `.`),
//!   or from a variable next to a dot (`.{a}` as `.`).
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

/// How many `.` and how many `..` segments a text has, as written and
/// then percent-decoded.
type Dots = [[usize; 2]; 2];

const NO_DOTS: Dots = [[0; 2]; 2];

/// What separates the segments of a path (`\` counts too: some servers
/// read it as `/`).
const PATH: &[char] = &['/', '\\'];
/// What separates the pieces of one variable's value: a path's
/// separators, and a query's (`&`, `;`, `=`), since a server can read a
/// variable that follows `?name=` with a query parser.
const PIECES: &[char] = &['/', '\\', '&', ';', '='];

/// Why a URI doesn't fit a template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Misfit {
    /// It doesn't have the template's shape.
    Shape,
    /// It has the shape, but a variable holds whitespace or a control
    /// character unencoded.
    Unencoded,
    /// It has the shape, but would make a `.` or `..` segment the
    /// template's own text doesn't have.
    DotSegment,
}

impl Misfit {
    /// What's wrong, for someone who wrote a URI with the template's shape.
    pub(crate) fn describe(self) -> &'static str {
        match self {
            Self::Shape => "it doesn't have the template's shape",
            Self::Unencoded => {
                "a variable holds a space or another whitespace or control character unencoded (percent-encode it: a space is `%20`)"
            }
            Self::DotSegment => {
                "a variable makes a `.` or `..` segment, which could reach outside the template"
            }
        }
    }
}

/// An approved resource template.
pub(crate) struct Template {
    /// `None` when the template uses an expression this doesn't support.
    pattern: Option<(Regex, Vec<Variable>)>,
    /// The `.` and `..` segments of the template's own text (its
    /// expressions left out): a matching URI may have those and no more.
    dots: Dots,
}

impl Template {
    pub(crate) fn parse(template: &str) -> Self {
        let mut source = String::from("^");
        // The template's text, each expression replaced by `{}`, which
        // can't be part of a dot segment.
        let mut literal = String::new();
        let mut variables = Vec::new();
        let mut rest = template;
        while let Some(open) = rest.find('{') {
            source.push_str(&regex::escape(&rest[..open]));
            literal.push_str(&rest[..open]);
            literal.push_str("{}");
            let Some(close) = rest[open..].find('}') else {
                return Self::unsupported();
            };
            let expression = &rest[open + 1..open + close];
            let (variable, group) = match expression.chars().next() {
                Some('+') => (Variable::Reserved, "([^?#]*)"),
                Some(c) if c.is_ascii_alphanumeric() || c == '_' || c == '%' => {
                    (Variable::Simple, "([^/?#]*)")
                }
                _ => return Self::unsupported(),
            };
            source.push_str(group);
            variables.push(variable);
            rest = &rest[open + close + 1..];
        }
        source.push_str(&regex::escape(rest));
        source.push('$');
        literal.push_str(rest);
        Self {
            pattern: Regex::new(&source).ok().map(|regex| (regex, variables)),
            dots: dot_segments(&literal, PATH),
        }
    }

    /// A template that matches nothing.
    fn unsupported() -> Self {
        Self {
            pattern: None,
            dots: NO_DOTS,
        }
    }

    #[cfg(test)]
    pub(crate) fn matches(&self, uri: &str) -> bool {
        self.check(uri).is_ok()
    }

    /// Whether `uri` fits the template, and if not, why.
    pub(crate) fn check(&self, uri: &str) -> Result<(), Misfit> {
        let Some((regex, variables)) = &self.pattern else {
            return Err(Misfit::Shape);
        };
        let Some(captures) = regex.captures(uri) else {
            return Err(Misfit::Shape);
        };
        let values: Vec<&str> = (1..=variables.len())
            .map(|group| captures.get(group).map_or("", |value| value.as_str()))
            .collect();
        for (variable, raw) in variables.iter().zip(&values) {
            let decoded = percent_decode(raw);
            let fits = match variable {
                Variable::Simple => !decoded.contains(['/', '\\', '?', '#']),
                Variable::Reserved => !decoded.contains(['?', '#']),
            };
            if !fits {
                return Err(Misfit::Shape);
            }
        }
        if values
            .iter()
            .any(|raw| raw.chars().any(|c| c.is_control() || c.is_whitespace()))
        {
            return Err(Misfit::Unencoded);
        }
        // A dot segment of its own counts wherever the variable sits, after
        // literal text too (`?path={+path}` as `../x`), and so does a dot
        // piece between query delimiters (`?path={+path}` as `&path=..`).
        if values
            .iter()
            .any(|raw| dot_segments(raw, PIECES) != NO_DOTS)
        {
            return Err(Misfit::DotSegment);
        }
        // Counted over the whole URI too: two variables, or a variable and
        // a literal dot, can make a segment neither makes alone.
        let found = dot_segments(uri, PATH);
        let within = found
            .iter()
            .flatten()
            .zip(self.dots.iter().flatten())
            .all(|(found, allowed)| found <= allowed);
        if within {
            Ok(())
        } else {
            Err(Misfit::DotSegment)
        }
    }
}

/// How many `.` and `..` segments `text` has, split at `separators`, as
/// written and percent-decoded.
fn dot_segments(text: &str, separators: &[char]) -> Dots {
    let count = |text: &str| {
        let mut dots = [0; 2];
        for segment in text.split(separators) {
            match segment {
                "." => dots[0] += 1,
                ".." => dots[1] += 1,
                _ => {}
            }
        }
        dots
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
    fn a_variable_after_literal_text_cannot_be_a_dot_segment_either() {
        for (template, uri) in [
            (
                "res://files/read?path={+path}",
                "res://files/read?path=../secret.txt",
            ),
            (
                "res://files/read?path={+path}",
                "res://files/read?path=notes/%2e%2e/%2E%2E/secret.txt",
            ),
            ("docs://page-{+p}", "docs://page-../x"),
            ("res://get?name={name}", "res://get?name=.."),
            ("res://get?name={name}", "res://get?name=%2e"),
            // A query parser reads a second `path` (or `name`), and some
            // keep the last one or drop the empty first.
            (
                "res://files/read?path={+path}",
                "res://files/read?path=&path=../secret.txt",
            ),
            ("res://get?name={name}", "res://get?name=x&name=.."),
            ("res://get?name={name}", "res://get?name=x;name=.."),
            ("res://get?name={name}", "res://get?name=x%26name%3D.."),
        ] {
            assert_eq!(
                Template::parse(template).check(uri),
                Err(Misfit::DotSegment),
                "{template} {uri}"
            );
        }
        let query = Template::parse("res://files/read?path={+path}");
        assert!(query.matches("res://files/read?path=notes/today.md"));
        assert!(query.matches("res://files/read?path=a&b=c.d"));
    }

    #[test]
    fn no_variable_holds_a_space_or_a_control_character() {
        // URL parsers remove tabs and line breaks, and trim spaces and
        // control characters at either end, before resolving dot segments;
        // a server that trims text (Python's `strip`) trims Unicode
        // whitespace and controls too.
        for (template, uri) in [
            (
                "file:///home/u/project/{+path}",
                "file:///home/u/project/.\t./.ssh/id_rsa",
            ),
            (
                "file:///home/u/project/{+path}",
                "file:///home/u/project/.\r\n./.ssh/id_rsa",
            ),
            ("file:///docs/{name}", "file:///docs/.. "),
            ("file:///docs/{name}", "file:///docs/\x00.."),
            ("file:///docs/{name}", "file:///docs/..\x7f"),
            ("{+url}", " file:///etc/passwd"),
            ("file:///docs/{name}", "file:///docs/..\u{85}"),
            ("file:///docs/{name}", "file:///docs/..\u{a0}"),
            ("file:///docs/{name}", "file:///docs/\u{3000}.."),
            ("notes://{title}", "notes://Meeting notes"),
        ] {
            assert_eq!(
                Template::parse(template).check(uri),
                Err(Misfit::Unencoded),
                "{template} {uri:?}"
            );
        }
        // Encoded, they're ordinary characters; and the template's own
        // text may have them.
        let docs = Template::parse("file:///docs/{name}");
        assert!(docs.matches("file:///docs/My%20Notes.md"));
        let spaced = Template::parse("file:///My Docs/{name}");
        assert!(spaced.matches("file:///My Docs/notes.md"));
    }

    #[test]
    fn only_the_templates_literal_text_allows_dot_segments() {
        // The expression's name decodes to `a/./b`, but that isn't text the
        // URI has: `%` and `e` around the literal `2` make `%2e`, a `.`.
        let named = Template::parse("file:///x/{a%2F.%2Fb}2{c}");
        assert!(named.matches("file:///x/a2b"));
        assert!(!named.matches("file:///x/%2e"));
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
