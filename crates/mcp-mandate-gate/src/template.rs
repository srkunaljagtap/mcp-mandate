//! Matching resource URIs against an approved template (RFC 6570, level 1
//! and 2 forms), strictly enough that a variable can't climb out of the
//! place the template names.
//!
//! - `{var}` matches one path segment's worth of text: no `/`, `?` or `#`,
//!   even percent-encoded.
//! - `{+var}` may span segments, but no `?` or `#`.
//! - No variable holds whitespace, a control character or a character
//!   that shows as nothing (a zero-width space, U+FEFF) unencoded, ASCII
//!   or not: expanding a template encodes them, and URL parsers drop or
//!   trim some of them (`.\t.` becomes `..`) before they resolve the path,
//!   as do servers that trim text (`..` and a no-break space).
//! - Whatever the variables hold, the URI can't have a `.` or `..` segment
//!   (before or after percent-decoding, and with those characters trimmed
//!   off its ends, so `%20..` counts) that the template's own text doesn't
//!   have: not in one variable (`{+path}` as `../x`, wherever it sits, or
//!   as `&path=../x` after `?path=`, which a query parser reads as a
//!   second `path`), from two side by side (`{a}{b}` as `.` and `.`), or
//!   from a variable next to a dot (`.{a}` as `.`).
//! - No variable starts somewhere of its own: at `/` or `\` (before or
//!   after percent-decoding and trimming), or at a drive (`C:`), at its
//!   start or after a query delimiter (`&path=/etc/passwd`). A server that
//!   joins it to a folder would read that instead. Nor can a variable make
//!   an empty segment (`//`) in the URI's path that the template's own
//!   text doesn't have. A variable right after `scheme://` is exempt from
//!   this rule: it names the whole location already.
//! - `\` separates segments in all of these, as `/` does: some servers
//!   read it that way.
//! - A template without variables matches only itself.
//! - Any other expression (`{#x}`, `{.x}`, `{/x}`, `{;x}`, `{?x}`, `{&x}`)
//!   matches nothing: the gate can't tell what it would reach, so it fails
//!   closed.

use std::borrow::Cow;

use mcp_mandate_pin::is_hidden;
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
/// What separates a query's parameters, and a parameter's name from its
/// value.
const QUERY: &[char] = &['&', ';', '='];

/// Why a URI doesn't fit a template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Misfit {
    /// It doesn't have the template's shape.
    Shape,
    /// It has the shape, but a variable holds whitespace, a control
    /// character or a character that shows as nothing unencoded.
    Unencoded,
    /// It has the shape, but would make a `.` or `..` segment the
    /// template's own text doesn't have.
    DotSegment,
    /// It has the shape, but a variable starts at `/`, `\` or a drive, or
    /// makes an empty segment the template's own text doesn't have.
    Root,
}

impl Misfit {
    /// What's wrong, for someone who wrote a URI with the template's shape.
    pub(crate) fn describe(self) -> &'static str {
        match self {
            Self::Shape => "it doesn't have the template's shape",
            Self::Unencoded => {
                "a variable holds a space or another whitespace, control or invisible character unencoded (percent-encode it: a space is `%20`)"
            }
            Self::DotSegment => {
                "a variable makes a `.` or `..` segment, which could reach outside the template"
            }
            Self::Root => {
                "a variable starts with `/`, `\\` or a drive such as `C:`, or makes an empty `//` segment, which could reach outside the template"
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
    /// The empty segments in the path of the template's own text, as
    /// written and percent-decoded: a matching URI's path may have those
    /// and no more.
    empty: [usize; 2],
    /// Whether the first variable comes right after `scheme://`, where it
    /// names the whole location: it may start with `/` there, or make an
    /// empty segment.
    locates: bool,
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
        let before_first = template.find('{').map(|open| &template[..open]);
        Self {
            pattern: Regex::new(&source).ok().map(|regex| (regex, variables)),
            dots: dot_segments(&literal, PATH),
            empty: empty_segments(&literal),
            locates: before_first.is_some_and(is_scheme_and_slashes),
        }
    }

    /// A template that matches nothing.
    fn unsupported() -> Self {
        Self {
            pattern: None,
            dots: NO_DOTS,
            empty: [0; 2],
            locates: false,
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
        if values.iter().any(|raw| raw.chars().any(trimmable)) {
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
        if !within {
            return Err(Misfit::DotSegment);
        }
        // A variable that starts at a root replaces the folder a server
        // joins it to (`/etc/passwd`, `C:/Users`), and so does a second
        // parameter after a query delimiter (`?path=x&path=/etc/passwd`).
        if values
            .iter()
            .skip(usize::from(self.locates))
            .any(|raw| rooted(raw) || rooted(&percent_decode(raw)))
        {
            return Err(Misfit::Root);
        }
        // An empty segment is counted over the whole URI, like dot
        // segments: a variable can make one at its edge (`{+a}/x` as
        // `dir/`) or by being empty (`{a}/x` as nothing). A variable that
        // names the whole location is left out.
        let first = captures.get(1).filter(|_| self.locates);
        let counted = match first {
            Some(first) => Cow::Owned(format!(
                "{}{{}}{}",
                &uri[..first.start()],
                &uri[first.end()..]
            )),
            None => Cow::Borrowed(uri),
        };
        let found = empty_segments(&counted);
        if found
            .iter()
            .zip(&self.empty)
            .all(|(found, allowed)| found <= allowed)
        {
            Ok(())
        } else {
            Err(Misfit::Root)
        }
    }
}

/// Whether a server may trim `c` off the ends of a value: whitespace, a
/// control character, or a character that shows as nothing (U+FEFF, which
/// JavaScript's `trim` removes, among them).
fn trimmable(c: char) -> bool {
    c.is_whitespace() || c.is_control() || is_hidden(c)
}

/// How many `.` and `..` segments `text` has, split at `separators`, as
/// written and percent-decoded, each with what a server may trim taken off
/// its ends (` ..` counts as `..`).
fn dot_segments(text: &str, separators: &[char]) -> Dots {
    let count = |text: &str| {
        let mut dots = [0; 2];
        for segment in text.split(separators) {
            match segment.trim_matches(trimmable) {
                "." => dots[0] += 1,
                ".." => dots[1] += 1,
                _ => {}
            }
        }
        dots
    };
    [count(text), count(&percent_decode(text))]
}

/// How many empty segments (between two separators, and empty once what a
/// server may trim is taken off) the path of `text` has, before any `?` or
/// `#`, as written and percent-decoded. A query value may hold `//` (a URL,
/// say): only its start matters there, which [`rooted`] checks.
fn empty_segments(text: &str) -> [usize; 2] {
    let path = text.split(['?', '#']).next().unwrap_or_default();
    let count = |path: &str| {
        let mut segments = path.split(PATH);
        // The first and last have a separator on one side only.
        segments.next_back();
        segments
            .skip(1)
            .filter(|segment| segment.trim_matches(trimmable).is_empty())
            .count()
    };
    [count(path), count(&percent_decode(path))]
}

/// Whether `text`, or a piece of it after a query delimiter, starts at a
/// root of its own once what a server may trim is taken off: `/` or `\`
/// (`\\server\share` too), or a drive (`C:`).
fn rooted(text: &str) -> bool {
    text.split(QUERY).any(|piece| {
        let mut chars = piece.trim_start_matches(trimmable).chars();
        match (chars.next(), chars.next()) {
            (Some('/' | '\\'), _) => true,
            (Some(letter), Some(':')) => letter.is_ascii_alphabetic(),
            _ => false,
        }
    })
}

/// Whether `text` is a URI scheme followed by `://` (`file://`).
fn is_scheme_and_slashes(text: &str) -> bool {
    let Some(scheme) = text.strip_suffix("://") else {
        return false;
    };
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
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
        // whitespace and controls too, and JavaScript's `trim` trims U+FEFF.
        for (template, uri) in [
            ("file:///docs/{name}", "file:///docs/\u{feff}.."),
            ("file:///docs/{name}", "file:///docs/..\u{200b}"),
            ("file:///docs/{name}", "file:///docs/a\u{2060}b"),
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
    fn a_piece_that_is_a_dot_segment_once_trimmed_counts_as_one() {
        // A server that decodes a variable and then trims it reads each of
        // these as `..`.
        for (template, uri) in [
            (
                "file:///home/u/project/{+path}",
                "file:///home/u/project/%20../.ssh/id_rsa",
            ),
            (
                "file:///home/u/project/{+path}",
                "file:///home/u/project/..%C2%A0/.ssh/id_rsa",
            ),
            (
                "file:///home/u/project/{+path}",
                "file:///home/u/project/%E3%80%80../.ssh/id_rsa",
            ),
            (
                "file:///home/u/project/{+path}",
                "file:///home/u/project/%EF%BB%BF../.ssh/id_rsa",
            ),
            ("file:///docs/{name}", "file:///docs/%00.."),
            ("file:///docs/{name}", "file:///docs/.%E2%80%8B"),
            ("file:///docs/{dir}/{file}", "file:///docs/%20../.ssh"),
            ("res://get?name={name}", "res://get?name=x&name=..%09"),
            // Only the URI as a whole has it: `.` and an encoded space.
            ("file:///p/.{a}", "file:///p/.%20"),
            // `\` separates segments too, as written or encoded.
            (
                "file:///home/u/project/{+path}",
                "file:///home/u/project/a%5C..%5Cb",
            ),
            (
                "file:///home/u/project/{+path}",
                "file:///home/u/project/a\\%2e%2e\\b",
            ),
        ] {
            assert_eq!(
                Template::parse(template).check(uri),
                Err(Misfit::DotSegment),
                "{template} {uri}"
            );
        }
        // Inside a name, an encoded space is an ordinary character.
        let docs = Template::parse("file:///docs/{name}");
        assert!(docs.matches("file:///docs/..%20notes.md"));
        assert!(docs.matches("file:///docs/My%20Notes.md"));
    }

    #[test]
    fn no_variable_starts_somewhere_of_its_own() {
        // Joined to the folder a server serves, an absolute path or a
        // drive replaces it: Python's `os.path.join`, Rust's `Path::join`
        // and Node's `path.resolve` all return the second path.
        for (template, uri) in [
            (
                "file:///home/u/project/{+path}",
                "file:///home/u/project//etc/passwd",
            ),
            (
                "file:///home/u/project/{+path}",
                "file:///home/u/project/%2Fetc%2Fpasswd",
            ),
            (
                "file:///home/u/project/{+path}",
                "file:///home/u/project/%20/etc/passwd",
            ),
            (
                "file:///home/u/project/{+path}",
                "file:///home/u/project/C:/Users/u/.ssh/id_rsa",
            ),
            (
                "file:///home/u/project/{+path}",
                "file:///home/u/project/c:%5CUsers%5Cu",
            ),
            (
                "file:///home/u/project/{+path}",
                "file:///home/u/project/%43:/x",
            ),
            (
                "file:///home/u/project/{+path}",
                "file:///home/u/project/\\\\server\\share\\x",
            ),
            (
                "file:///home/u/project/{+path}",
                "file:///home/u/project/%5C%5Cserver%5Cshare",
            ),
            ("docs://pages/{id}", "docs://pages/C:secret"),
            (
                "res://files/read?path={+path}",
                "res://files/read?path=/etc/passwd",
            ),
            // A second parameter, to a query parser.
            (
                "res://files/read?path={+path}",
                "res://files/read?path=notes&path=/etc/passwd",
            ),
            (
                "res://files/read?path={+path}",
                "res://files/read?path=x;path=C:/x",
            ),
            ("res://get?name={name}", "res://get?name=x%26name%3DC:x"),
            // Only a variable right after `scheme://` names the location.
            (
                "https://{host}/api/{+path}",
                "https://example.com/api//etc/passwd",
            ),
            // Nor can a variable make an empty segment the template's own
            // text doesn't have, by being empty or at its edges.
            ("file:///base/{dir}/{+rest}", "file:///base//etc/passwd"),
            ("file:///p/{+a}/x", "file:///p/dir//x"),
            ("file:///p/{+a}/x", "file:///p/dir%2F/x"),
            ("file:///p/{+path}", "file:///p/a//b"),
            ("file:///p/{+path}", "file:///p/a%2F%2Fb"),
            ("file:///p/{+path}", "file:///p/a/%20/b"),
            ("file:///p/{+path}", "file:///p/a\\/b"),
        ] {
            assert_eq!(
                Template::parse(template).check(uri),
                Err(Misfit::Root),
                "{template} {uri}"
            );
        }
        for (template, uri) in [
            // Right after `scheme://`, a variable names the whole location
            // already.
            ("file://{+path}", "file:///etc/passwd"),
            ("https://{+url}", "https://example.com/a/b"),
            (
                "https://{host}/api/{+path}",
                "https://localhost:8080/api/v1/items",
            ),
            // A trailing slash makes no empty segment, and a URL in a
            // query value may hold `//`.
            ("file:///p/{+path}", "file:///p/dir/"),
            ("docs://pages/{id}", "docs://pages/"),
            (
                "res://fetch?url={+url}",
                "res://fetch?url=https://example.com/a//b",
            ),
            // A colon after more than one letter isn't a drive.
            ("file:///docs/{name}", "file:///docs/notes:v2.md"),
        ] {
            assert!(Template::parse(template).matches(uri), "{template} {uri}");
        }
        // Dot segments still count after `scheme://`.
        assert_eq!(
            Template::parse("file://{+path}").check("file:///etc/../x"),
            Err(Misfit::DotSegment)
        );
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
