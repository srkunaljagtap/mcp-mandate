//! Matching resource URIs against an approved template (RFC 6570, level 1
//! and 2 forms), strictly enough that a variable can't climb out of the
//! place the template names.
//!
//! - `{var}` matches one path segment's worth of text: no `/`, `?` or `#`,
//!   even percent-encoded.
//! - `{+var}` may span segments, but no `?` or `#`.
//! - No variable holds whitespace, a control character or U+FEFF
//!   unencoded, ASCII or not: expanding a template encodes them, and URL
//!   parsers drop or trim some of them (`.\t.` becomes `..`) before they
//!   resolve the path, as do servers that trim text (`..` and a no-break
//!   space, or U+FEFF, which JavaScript's `trim` takes off). Other
//!   characters that show as nothing (a zero-width joiner, a variation
//!   selector) belong to ordinary names and emoji, so they may appear; the
//!   rules below trim them off a segment's ends before they look at it.
//! - Whatever the variables hold, the URI can't have a `.` or `..` segment
//!   (before or after percent-decoding, and with those characters trimmed
//!   off its ends, so `%20..` counts) that the template's own text doesn't
//!   have: not in one variable (`{+path}` as `../x`, wherever it sits, or
//!   as `&path=../x` after `?path=`, which a query parser reads as a
//!   second `path`), from two side by side (`{a}{b}` as `.` and `.`), or
//!   from a variable next to a dot (`.{a}` as `.`).
//! - No variable starts somewhere of its own (before or after
//!   percent-decoding and trimming): at `/` or `\`, at its start or after a
//!   query delimiter (`&path=/etc/passwd`), or at a drive (`C:`), at the
//!   start of any of its segments (`docs/C:/Windows`, which a server that
//!   joins segment by segment reads as a drive). A server that joins it to
//!   a folder would read that instead. Nor can the variables make an empty
//!   segment (`//`) in the URI's path, or a segment at a drive, that the
//!   template's own text doesn't have (`{a}:{b}` as `C` and `x`).
//! - Where a variable sits can widen that. Right after `file://` it names
//!   the whole location (`file:///etc/passwd`), so none of it applies.
//!   Where a file URI's path starts (`file:///{+path}`,
//!   `file://localhost/{+path}`) the template names the whole filesystem,
//!   so the variable may start at a drive (`file:///C:/Users`).
//! - Only `http`, `https`, `ws`, `wss` and `file` URIs have a host, and no
//!   variable can change the one the template's own text names. Right
//!   after it (`https://api.example.com{+path}`, `https://{host}{+path}`)
//!   a variable is empty or starts with the path's own `/`, with no second
//!   one or drive after it (a file URI may have its drive there:
//!   `file://localhost/C:/Users`). Inside a host, with more of the host's
//!   own text after it (`https://api-{region}.example.com`,
//!   `https://{tenant}.example.com`), it holds only letters and digits
//!   (`münchen` too), `-`, `.` and `_`: URL parsers differ on what else
//!   ends a host (Node's legacy `url.parse` ends it at `;`, `|` or `%`), so
//!   percent-encoded host text is refused too. After the host's `:`
//!   (`https://localhost:{port}/api`) it is a port number. A variable that
//!   is the whole host, alone or with only a port after it
//!   (`https://{host}/api`, `http://{host}:{port}/mcp`), already lets the
//!   model choose it, as `https://{+url}` does, so only the rules above
//!   apply to it (an IPv6 address such as `[::1]` too).
//!   Other schemes have no host: a server may serve `docs://page-{+p}` or
//!   `docs://{+path}` from a folder, so `docs://page-/etc/passwd` and
//!   `docs:///etc/passwd` are refused.
//! - `\` separates segments in all of these, as `/` does: some servers
//!   read it that way.
//! - A template without variables matches only itself.
//! - Any other expression (`{#x}`, `{.x}`, `{/x}`, `{;x}`, `{?x}`, `{&x}`)
//!   matches nothing: the gate can't tell what it would reach, so it fails
//!   closed.

use mcp_mandate_pin::is_hidden;
use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Variable {
    Simple,
    Reserved,
}

/// Where a variable sits in its template, which decides where its text
/// may start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Place {
    /// Within the place the template names: not at `/`, `\` or a drive.
    Inside,
    /// Right after `file://`, where it names the whole location
    /// (`file:///etc/passwd`): anywhere.
    Location,
    /// Where a file URI's path starts (`file:///{+path}`,
    /// `file://localhost/{+path}`), so the template names the whole
    /// filesystem: at a drive too (`file:///C:/Users`).
    Drive,
    /// Right after a host (`https://api.example.com{+path}`): empty, or
    /// at the path's own first `/`, and with `drive` (a file URI) at a
    /// drive right after that.
    Path { drive: bool },
    /// Inside a host, with more of the host's own text after it
    /// (`https://api-{region}.example.com`): only what a host name holds.
    Host,
    /// After the host's `:` (`https://localhost:{port}`): a port number.
    Port,
}

/// The schemes whose URIs name a host after `//`, which a variable could
/// change. A server may serve any other scheme's URIs from a folder.
const HOST_SCHEMES: &[&str] = &["http", "https", "ws", "wss", "file"];

/// What ends a URI's host: where its path, query or fragment starts (`\`
/// too: URL parsers read it as `/` in these schemes).
const AFTER_HOST: &[char] = &['/', '\\', '?', '#'];

/// Whether a variable inside a host may hold `c`: a letter or a digit
/// (`münchen` too), `-`, `.` or `_`, as a host name does. URL parsers
/// differ on what else ends a host: all of them end it at `/`, `?` or `#`,
/// many at `\`, most at `:` (a port) or `@` (making what came before it a
/// user name), and Node's legacy `url.parse` at `%`, `;`, `'`, `"`, `<`,
/// `>`, `^`, `` ` ``, `{`, `|` and `}` too. As `%` isn't one, neither is
/// any percent-encoded text, so decoding it can add nothing.
fn in_host_name(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '-' | '.' | '_')
}

/// Whether `text`, a host's own text after a variable that has none
/// before it, is only a port: `:`, then digits (or none, where a variable
/// fills it: `{host}:{port}`).
fn only_port(text: &str) -> bool {
    text.strip_prefix(':')
        .is_some_and(|port| port.bytes().all(|byte| byte.is_ascii_digit()))
}

impl Place {
    /// Where the variable whose `{}` starts at `at` in `literal` (the
    /// template's text, each expression as `{}`) sits.
    fn of(literal: &str, at: usize) -> Self {
        let (before, after) = (&literal[..at], &literal[at + 2..]);
        // `host` is the text from `://` to the variable.
        let Some((scheme, host)) = before.split_once("://") else {
            return Self::Inside;
        };
        if !HOST_SCHEMES
            .iter()
            .any(|known| scheme.eq_ignore_ascii_case(known))
        {
            return Self::Inside;
        }
        let file = scheme.eq_ignore_ascii_case("file");
        if file && host.is_empty() {
            return Self::Location;
        }
        if file
            && host
                .strip_suffix('/')
                .is_some_and(|host| !host.contains(AFTER_HOST))
        {
            return Self::Drive;
        }
        if host.contains(AFTER_HOST) {
            return Self::Inside;
        }
        // The variable is in the host: what the template has after it
        // there decides what it is.
        let rest = after[..after.find(AFTER_HOST).unwrap_or(after.len())].replace("{}", "");
        if host.is_empty() && (rest.is_empty() || only_port(&rest)) {
            // The whole host, perhaps with a port after it, which the model
            // already chooses (`[::1]` too). A user name isn't one:
            // `https://{+user}:{pass}@example.com` names its host.
            Self::Inside
        } else if !rest.is_empty() {
            Self::Host
        } else if host.ends_with(':') {
            Self::Port
        } else {
            Self::Path { drive: file }
        }
    }
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
    /// character or U+FEFF unencoded.
    Unencoded,
    /// It has the shape, but would make a `.` or `..` segment the
    /// template's own text doesn't have.
    DotSegment,
    /// It has the shape, but a variable starts at `/`, `\` or a drive
    /// where its place doesn't allow it, or the URI has an empty segment
    /// or one at a drive that the template's own text doesn't have.
    Root,
    /// It has the shape, but a variable in or right after the URI's host
    /// could change that host.
    Host,
}

impl Misfit {
    /// What's wrong, for someone who wrote a URI with the template's shape.
    pub(crate) fn describe(self) -> &'static str {
        match self {
            Self::Shape => "it doesn't have the template's shape",
            Self::Unencoded => {
                "a variable holds a space or another whitespace or control character, or U+FEFF, unencoded (percent-encode it: a space is `%20`)"
            }
            Self::DotSegment => {
                "a variable makes a `.` or `..` segment, which could reach outside the template"
            }
            Self::Root => {
                "a variable starts with `/` or `\\`, or makes a segment that starts with a drive such as `C:` or an empty `//` segment, which could reach outside the template"
            }
            Self::Host => {
                "a variable could change the URI's host: right after the host it must be empty or start with `/`, within the host it can hold only letters, digits, `-`, `.` and `_` (nothing percent-encoded), and after the host's `:` it must be a port number"
            }
        }
    }
}

/// An approved resource template.
pub(crate) struct Template {
    /// `None` when the template uses an expression this doesn't support.
    pattern: Option<(Regex, Vec<(Variable, Place)>)>,
    /// The `.` and `..` segments of the template's own text (its
    /// expressions left out): a matching URI may have those and no more.
    dots: Dots,
    /// The empty segments in the path of the template's own text, as
    /// written and percent-decoded: a matching URI's path may have those
    /// and no more.
    empty: [usize; 2],
    /// The segments of the template's own text that start at a drive, as
    /// written and percent-decoded: a matching URI may have those and no
    /// more.
    drives: [usize; 2],
}

impl Template {
    pub(crate) fn parse(template: &str) -> Self {
        let mut source = String::from("^");
        // The template's text, each expression replaced by `{}`, which
        // can't be part of a dot segment or start a drive.
        let mut literal = String::new();
        // Each variable, and where its `{}` starts in `literal`.
        let mut variables = Vec::new();
        let mut rest = template;
        while let Some(open) = rest.find('{') {
            source.push_str(&regex::escape(&rest[..open]));
            literal.push_str(&rest[..open]);
            let at = literal.len();
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
            variables.push((variable, at));
            rest = &rest[open + close + 1..];
        }
        source.push_str(&regex::escape(rest));
        source.push('$');
        literal.push_str(rest);
        // A variable's place can depend on the text after it too
        // (`https://api-{region}.example.com`).
        let variables = variables
            .into_iter()
            .map(|(variable, at)| (variable, Place::of(&literal, at)))
            .collect();
        Self {
            pattern: Regex::new(&source).ok().map(|regex| (regex, variables)),
            dots: dot_segments(&literal, PATH),
            empty: empty_segments(&literal),
            drives: drives(&literal),
        }
    }

    /// A template that matches nothing.
    fn unsupported() -> Self {
        Self {
            pattern: None,
            dots: NO_DOTS,
            empty: [0; 2],
            drives: [0; 2],
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
        for ((variable, _), raw) in variables.iter().zip(&values) {
            let decoded = percent_decode(raw);
            let fits = match variable {
                Variable::Simple => !decoded.contains(['/', '\\', '?', '#']),
                Variable::Reserved => !decoded.contains(['?', '#']),
            };
            if !fits {
                return Err(Misfit::Shape);
            }
        }
        if values.iter().any(|raw| raw.chars().any(dropped)) {
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
        if !at_most(
            dot_segments(uri, PATH).as_flattened(),
            self.dots.as_flattened(),
        ) {
            return Err(Misfit::DotSegment);
        }
        // A variable that starts at a root replaces the folder a server
        // joins it to (`/etc/passwd`, `C:/Users`), and so does a second
        // parameter after a query delimiter (`?path=x&path=/etc/passwd`)
        // or a segment at a drive (`docs/C:/Windows`). One in or right
        // after a host could point the URI elsewhere (`@evil.example`).
        for ((_, place), raw) in variables.iter().zip(&values) {
            fits_place(raw, *place)?;
        }
        // Empty segments and drives are counted over the whole URI, like
        // dot segments: a variable can make an empty one at its edge
        // (`{+a}/x` as `dir/`) or by being empty (`{a}/x` as nothing), and
        // a drive next to the template's text (`{a}:{b}` as `C` and `x`).
        let mut counted = String::with_capacity(uri.len());
        let mut copied = 0;
        for (index, (_, place)) in variables.iter().enumerate() {
            let Some(value) = captures.get(index + 1) else {
                continue;
            };
            let (start, end) = match place {
                // It names the whole location: left out.
                Place::Location => (value.start(), value.end()),
                // It may start at a drive (`file:///{+path}`), or have one
                // right after the path's `/` (`file://localhost{+path}`):
                // `{}` there keeps that drive from counting.
                Place::Drive => (value.start(), value.start()),
                Place::Path { drive: true } if value.as_str().starts_with('/') => {
                    (value.start() + 1, value.start() + 1)
                }
                _ => continue,
            };
            counted.push_str(&uri[copied..start]);
            counted.push_str("{}");
            copied = end;
        }
        counted.push_str(&uri[copied..]);
        if at_most(&empty_segments(&counted), &self.empty)
            && at_most(&drives(&counted), &self.drives)
        {
            Ok(())
        } else {
            Err(Misfit::Root)
        }
    }
}

/// Whether each count in `found` is at most the one in `allowed`.
fn at_most(found: &[usize], allowed: &[usize]) -> bool {
    found
        .iter()
        .zip(allowed)
        .all(|(found, allowed)| found <= allowed)
}

/// Whether URL parsers drop `c` or trim it off a value's ends, or servers
/// that trim text do: whitespace, a control character, or U+FEFF (which
/// JavaScript's `trim` takes off).
fn dropped(c: char) -> bool {
    c.is_whitespace() || c.is_control() || c == '\u{feff}'
}

/// Whether a server may trim `c` off the ends of a value: what URL parsers
/// drop, or any other character that shows as nothing (some trim a
/// zero-width space too).
fn trimmable(c: char) -> bool {
    dropped(c) || is_hidden(c)
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
/// say): only its start matters there, which [`fits_place`] checks.
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

/// How many segments of `text` start at a drive once what a server may
/// trim is taken off their start, as written and percent-decoded.
fn drives(text: &str) -> [usize; 2] {
    let count = |text: &str| {
        text.split(PATH)
            .filter(|segment| is_drive(segment.trim_start_matches(trimmable)))
            .count()
    };
    [count(text), count(&percent_decode(text))]
}

/// Whether a variable's text fits where it sits: it doesn't change the
/// URI's host, and as written or percent-decoded it doesn't start
/// somewhere of its own that its place doesn't allow.
fn fits_place(raw: &str, place: Place) -> Result<(), Misfit> {
    let (raw, drive) = match place {
        Place::Inside => (raw, false),
        Place::Location => return Ok(()),
        Place::Drive => (raw, true),
        // Where the path starts: empty, or at the path's own first `/`.
        // A second one after it still counts, and so does a drive, except
        // in a file URI. Anything else would still be host
        // (`.evil.example`, `:8080`, `@evil.example`).
        Place::Path { drive } => match raw.strip_prefix('/') {
            Some(path) => (path, drive),
            None if raw.is_empty() => return Ok(()),
            None => return Err(Misfit::Host),
        },
        // Inside a host: only what a host name holds, which leaves out
        // `%`, so percent-decoding it changes nothing.
        Place::Host => {
            return if raw.chars().all(in_host_name) {
                Ok(())
            } else {
                Err(Misfit::Host)
            };
        }
        Place::Port => {
            return if raw.bytes().all(|byte| byte.is_ascii_digit()) {
                Ok(())
            } else {
                Err(Misfit::Host)
            };
        }
    };
    if starts_at_root(raw, drive) || starts_at_root(&percent_decode(raw), drive) {
        Err(Misfit::Root)
    } else {
        Ok(())
    }
}

/// Whether `text` starts at a root of its own once what a server may trim
/// is taken off: at `/` or `\` (`\\server\share` too), at its start or
/// after a query delimiter, or at a drive (`C:`), at the start of any of
/// its pieces, since a server that joins a path segment by segment reads
/// `docs/C:/Windows` as `C:Windows`. With `drive`, its first piece may be a
/// drive.
fn starts_at_root(text: &str, drive: bool) -> bool {
    text.split(QUERY)
        .any(|piece| piece.trim_start_matches(trimmable).starts_with(PATH))
        || text
            .split(PIECES)
            .skip(usize::from(drive))
            .any(|piece| is_drive(piece.trim_start_matches(trimmable)))
}

/// Whether `text` starts at a drive: an ASCII letter, then `:`.
fn is_drive(text: &str) -> bool {
    let mut chars = text.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic()) && chars.next() == Some(':')
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
            ("file:///docs/{name}", "file:///docs/a\u{feff}b"),
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
        // Other characters that show as nothing belong to ordinary names,
        // and no URL parser drops them: a red heart with the variation
        // selector most emoji are written with, a ZWJ sequence (woman and
        // laptop), a Persian word with a zero-width non-joiner, a word
        // joiner.
        for uri in [
            "file:///docs/\u{2764}\u{fe0f}.md",
            "file:///docs/\u{1f469}\u{200d}\u{1f4bb}.md",
            "file:///docs/\u{645}\u{6cc}\u{200c}\u{62e}\u{648}\u{627}\u{647}\u{645}.md",
            "file:///docs/a\u{2060}b",
        ] {
            assert!(docs.matches(uri), "{uri:?}");
        }
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
            // A character that shows as nothing is trimmed too, written
            // as it is.
            ("file:///docs/{name}", "file:///docs/..\u{200b}"),
            ("file:///docs/{name}", "file:///docs/\u{2060}."),
            (
                "file:///home/u/project/{+path}",
                "file:///home/u/project/\u{200c}..\u{fe0f}/.ssh/id_rsa",
            ),
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
            // Trimmed off first, whatever shows as nothing.
            (
                "file:///home/u/project/{+path}",
                "file:///home/u/project/\u{200b}/etc/passwd",
            ),
            // Only a variable right after `file://` names the whole
            // location: a server may serve another scheme's URIs from a
            // folder, and a drive-relative path (`C:x`) leaves it too.
            ("docs://{+path}", "docs:///etc/passwd"),
            ("docs://{+path}", "docs://%2Fetc%2Fpasswd"),
            ("docs://{+path}", "docs://C:/Users/u/.ssh/id_rsa"),
            ("docs://{+path}", "docs://notes//etc/passwd"),
            ("notes://{name}", "notes://C:x"),
            ("https://{+url}", "https:///etc/passwd"),
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
            // Right after `file://`, a variable names the whole location
            // already, a Windows one too.
            ("file://{+path}", "file:///etc/passwd"),
            ("file://{+path}", "file:///C:/Users/u/notes.txt"),
            ("FILE://{+path}", "FILE:///etc/passwd"),
            // Another scheme's first variable keeps to the rules, and a
            // web address or a host and port does.
            ("https://{+url}", "https://example.com/a/b"),
            (
                "https://{+url}",
                "https://attacker.example/c/q3-salary-review-notes",
            ),
            (
                "https://{host}/api/{+path}",
                "https://localhost:8080/api/v1/items",
            ),
            ("docs://{+path}", "docs://notes/today.md"),
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
        // Dot segments still count after `file://`.
        assert_eq!(
            Template::parse("file://{+path}").check("file:///etc/../x"),
            Err(Misfit::DotSegment)
        );
    }

    #[test]
    fn a_variable_after_file_slashes_or_a_host_starts_where_its_path_does() {
        // `file:///{+path}` names the whole filesystem, and a Windows file
        // URI starts the variable at a drive.
        for (template, uri) in [
            ("file:///{+path}", "file:///C:/Users/u/notes.txt"),
            ("file:///{+path}", "file:///c:/x"),
            ("file:///{+path}", "file:///home/u/notes.txt"),
            ("file:///{drive}/{+path}", "file:///C:/Users/u/notes.txt"),
            ("file:///{drive}:/{+path}", "file:///C:/Users/u/notes.txt"),
        ] {
            assert!(Template::parse(template).matches(uri), "{template} {uri}");
        }
        // Right after a host, a variable starts with the path's own `/`.
        for (template, uri) in [
            ("https://{host}{+path}", "https://example.com/v1/items"),
            ("https://{host}{+path}", "https://example.com/"),
            ("https://{host}{+path}", "https://example.com"),
            (
                "https://api.example.com{+path}",
                "https://api.example.com/v1/items",
            ),
            (
                "https://api.example.com:{port}{+path}",
                "https://api.example.com:8443/v1/items",
            ),
            ("file://localhost{+path}", "file://localhost/etc/passwd"),
        ] {
            assert!(Template::parse(template).matches(uri), "{template} {uri}");
        }
        for (template, uri) in [
            // A drive only where the variable starts, and no `/` or `\`
            // there: `\\server\share` is another machine.
            ("file:///{+path}", "file:////etc/passwd"),
            ("file:///{+path}", "file:///%2Fetc/passwd"),
            ("file:///{+path}", "file:///\\\\server\\share\\x"),
            ("file:///{+path}", "file:///C:/x/D:/y"),
            ("file:///{drive}/{+path}", "file:///C:/D:/y"),
            // Only after `file:///`.
            ("docs:///{+path}", "docs:///C:/x"),
            ("file:///docs/{+path}", "file:///docs/C:/x"),
            // One `/` after a host, with no root after it.
            (
                "https://api.example.com{+path}",
                "https://api.example.com//etc/passwd",
            ),
            (
                "https://api.example.com{+path}",
                "https://api.example.com/\\etc\\passwd",
            ),
            (
                "https://api.example.com{+path}",
                "https://api.example.com/C:/x",
            ),
            (
                "https://api.example.com{+path}",
                "https://api.example.com/%2Fetc/passwd",
            ),
            (
                "https://api.example.com{+path}",
                "https://api.example.com/%20/etc/passwd",
            ),
            ("https://{host}{+path}", "https://example.com//etc/passwd"),
            ("https://{host}{+path}", "https:///etc/passwd"),
        ] {
            assert_eq!(
                Template::parse(template).check(uri),
                Err(Misfit::Root),
                "{template} {uri}"
            );
        }
    }

    #[test]
    fn only_web_and_file_uris_have_a_host_to_follow() {
        // Another scheme's text after `://` is a name, not a host: a server
        // that serves these from a folder and reads the variable on its own
        // gets `/etc/passwd`.
        for (template, uri) in [
            ("docs://page-{+p}", "docs://page-/etc/passwd"),
            ("docs://page-{+p}", "docs://page-%2Fetc%2Fpasswd"),
            ("notes://n{+path}", "notes://n/etc/passwd"),
            ("docs://{a}{+b}", "docs://x/etc/passwd"),
        ] {
            assert_eq!(
                Template::parse(template).check(uri),
                Err(Misfit::Root),
                "{template} {uri}"
            );
        }
        assert!(Template::parse("docs://page-{+p}").matches("docs://page-intro/today.md"));
        // A web or file URI's path starts right after its host.
        for (template, uri) in [
            (
                "https://api.example.com{+path}",
                "https://api.example.com/v1/items",
            ),
            ("https://{host}{+path}", "https://example.com/v1/items"),
            (
                "http://api.example.com{+path}",
                "http://api.example.com/v1/items",
            ),
            (
                "wss://stream.example.com{+path}",
                "wss://stream.example.com/v1/feed",
            ),
            (
                "WS://stream.example.com{+path}",
                "WS://stream.example.com/v1/feed",
            ),
            ("file://localhost{+path}", "file://localhost/etc/passwd"),
        ] {
            assert!(Template::parse(template).matches(uri), "{template} {uri}");
        }
    }

    #[test]
    fn no_variable_changes_the_host() {
        for (template, uri) in [
            // Right after a host, the path must start: anything else is
            // still host, a user name (`@`) or a port.
            (
                "https://api.example.com{+path}",
                "https://api.example.com@evil.example/x",
            ),
            (
                "https://api.example.com{+path}",
                "https://api.example.com.evil.example/x",
            ),
            (
                "https://api.example.com{+path}",
                "https://api.example.com:8080/x",
            ),
            (
                "https://api.example.com{+path}",
                "https://api.example.com%40evil.example/x",
            ),
            (
                "https://api.example.com{+path}",
                "https://api.example.com%2Fetc/passwd",
            ),
            (
                "https://api.example.com{id}",
                "https://api.example.com.evil.example",
            ),
            ("file://localhost{+path}", "file://localhost.evil.example/x"),
            // Inside a host, nothing may end it before the template's own
            // text: Python's `urlsplit` reads the first one's host as
            // `evil.example`.
            (
                "https://{tenant}.example.com/v1",
                "https://evil.example:443.example.com/v1",
            ),
            (
                "https://{tenant}.example.com/v1",
                "https://evil.example%3A443.example.com/v1",
            ),
            (
                "https://{+tenant}.example.com/v1",
                "https://evil.example/.example.com/v1",
            ),
            (
                "https://api-{+region}.example.com/v1",
                "https://api-x.evil.example\\.example.com/v1",
            ),
            (
                "https://api-{region}.example.com/v1",
                "https://api-x@evil.example.example.com/v1",
            ),
            // After the host's `:`, only a port number.
            (
                "https://localhost:{port}/api",
                "https://localhost:80@evil.example/api",
            ),
            (
                "https://localhost:{port}/api",
                "https://localhost:80.evil.example/api",
            ),
            (
                "https://api.example.com:{port}{+path}",
                "https://api.example.com:8443@evil.example/x",
            ),
        ] {
            assert_eq!(
                Template::parse(template).check(uri),
                Err(Misfit::Host),
                "{template} {uri}"
            );
        }
        for (template, uri) in [
            ("https://api.example.com{+path}", "https://api.example.com"),
            ("https://api.example.com{+path}", "https://api.example.com/"),
            (
                "https://api-{region}.example.com/v1",
                "https://api-eu.example.com/v1",
            ),
            (
                "https://{tenant}.example.com/v1",
                "https://eu.acme.example.com/v1",
            ),
            ("https://localhost:{port}/api", "https://localhost:8080/api"),
            ("https://{host}:{port}/api", "https://example.com:8443/api"),
            // A variable that is the whole host lets the model choose it.
            ("https://{host}/api", "https://localhost:8080/api"),
            ("https://{host}/api", "https://user@example.com/api"),
        ] {
            assert!(Template::parse(template).matches(uri), "{template} {uri}");
        }
    }

    #[test]
    fn inside_a_host_a_variable_holds_only_a_host_names_characters() {
        // Node's legacy `url.parse` ends a host at each of these (at the
        // `%` of `%2e` or `%00` too), so a server that uses it reads the
        // first three hosts as `evil.example`.
        for (template, uri) in [
            (
                "https://{tenant}.example.com/v1",
                "https://evil.example;.example.com/v1",
            ),
            (
                "https://{tenant}.example.com/v1",
                "https://evil.example%2e.example.com/v1",
            ),
            (
                "https://{tenant}.example.com/v1",
                "https://evil.example|.example.com/v1",
            ),
            (
                "https://{tenant}.example.com/v1",
                "https://x%00.example.com/v1",
            ),
            (
                "https://api-{region}.example.com/v1",
                "https://api-x'.example.com/v1",
            ),
            (
                "https://api-{+region}.example.com/v1",
                "https://api-x%2Fevil.example.com/v1",
            ),
        ] {
            assert_eq!(
                Template::parse(template).check(uri),
                Err(Misfit::Host),
                "{template} {uri}"
            );
        }
        // Letters in any script, digits, `-`, `.` and `_` are fine.
        for (template, uri) in [
            (
                "https://{tenant}.example.com/v1",
                "https://münchen.example.com/v1",
            ),
            (
                "https://api-{region}.example.com/v1",
                "https://api-us-east-1.example.com/v1",
            ),
            (
                "https://{tenant}.example.com/v1",
                "https://eu_west.acme.example.com/v1",
            ),
        ] {
            assert!(Template::parse(template).matches(uri), "{template} {uri}");
        }
    }

    #[test]
    fn a_whole_host_with_only_a_port_after_it_is_the_models_to_choose() {
        // No host text before the variable and only a port after it: the
        // model chooses the host, an IPv6 address too.
        for (template, uri) in [
            ("http://{host}:{port}/mcp", "http://[::1]:8080/mcp"),
            ("http://{host}:{port}/mcp", "http://localhost:8080/mcp"),
            ("https://{host}:8443/api", "https://[::1]:8443/api"),
            (
                "https://{host}:{port}{+path}",
                "https://[::1]:8443/v1/items",
            ),
        ] {
            assert!(Template::parse(template).matches(uri), "{template} {uri}");
        }
        // Still within a host when the template names more of it after
        // the variable, and a user name before `@` isn't a port.
        for (template, uri) in [
            (
                "https://{tenant}.example.com/v1",
                "https://[::1].example.com/v1",
            ),
            (
                "https://{host}:8443.example.com/api",
                "https://[::1]:8443.example.com/api",
            ),
            (
                "https://{+user}:{pass}@example.com/",
                "https://evil.example/:x@example.com/",
            ),
        ] {
            assert_eq!(
                Template::parse(template).check(uri),
                Err(Misfit::Host),
                "{template} {uri}"
            );
        }
        // The port still takes only a number.
        assert_eq!(
            Template::parse("http://{host}:{port}/mcp").check("http://[::1]:80@evil.example/mcp"),
            Err(Misfit::Host)
        );
    }

    #[test]
    fn a_file_uri_with_a_host_may_start_its_path_at_a_drive() {
        // `file://localhost/C:/Users` is a Windows path, as
        // `file:///C:/Users` is.
        for (template, uri) in [
            (
                "file://localhost/{+path}",
                "file://localhost/C:/Users/u/notes.txt",
            ),
            (
                "file://localhost{+path}",
                "file://localhost/C:/Users/u/notes.txt",
            ),
            (
                "file://localhost/{+path}",
                "file://localhost/home/u/notes.txt",
            ),
            ("file://{host}/{+path}", "file:///C:/Users/u/notes.txt"),
            ("file://{host}{+path}", "file:///C:/Users/u/notes.txt"),
            (
                "file://{host}{+path}",
                "file://localhost/C:/Users/u/notes.txt",
            ),
        ] {
            assert!(Template::parse(template).matches(uri), "{template} {uri}");
        }
        // Only one drive, where the path starts, and no `/` or `\` there.
        for (template, uri) in [
            ("file://localhost/{+path}", "file://localhost/C:/x/D:/y"),
            ("file://localhost{+path}", "file://localhost/C:/x/D:/y"),
            ("file://localhost/{+path}", "file://localhost//etc/passwd"),
            ("file://localhost{+path}", "file://localhost//etc/passwd"),
            (
                "file://localhost/{+path}",
                "file://localhost/\\\\server\\share\\x",
            ),
            (
                "file://localhost/docs/{+path}",
                "file://localhost/docs/C:/x",
            ),
        ] {
            assert_eq!(
                Template::parse(template).check(uri),
                Err(Misfit::Root),
                "{template} {uri}"
            );
        }
    }

    #[test]
    fn no_segment_of_a_variable_starts_at_a_drive() {
        // A Windows server that joins a path segment by segment reads a
        // segment at a drive as that drive: `docs/C:/Windows` as
        // `C:Windows`, outside the folder.
        for (template, uri) in [
            (
                "file:///D:/project/{+path}",
                "file:///D:/project/docs/C:/Windows/win.ini",
            ),
            (
                "file:///D:/project/{+path}",
                "file:///D:/project/docs/c:%5CWindows%5Cwin.ini",
            ),
            (
                "file:///D:/project/{+path}",
                "file:///D:/project/docs\\C:\\Windows",
            ),
            (
                "file:///D:/project/{+path}",
                "file:///D:/project/docs%2FC:%2FWindows",
            ),
            (
                "file:///D:/project/{+path}",
                "file:///D:/project/docs/%43:/Windows",
            ),
            (
                "file:///D:/project/{+path}",
                "file:///D:/project/docs/%20C:/Windows",
            ),
            (
                "file:///D:/project/{+path}",
                "file:///D:/project/docs/\u{200b}C:/Windows",
            ),
            (
                "res://files/read?path={+path}",
                "res://files/read?path=docs/C:/x",
            ),
            // Nor can a variable make one next to the template's own text.
            ("file:///p/{a}:{b}", "file:///p/C:x"),
            ("file:///p/{a}%3A{b}", "file:///p/C%3Ax"),
        ] {
            assert_eq!(
                Template::parse(template).check(uri),
                Err(Misfit::Root),
                "{template} {uri}"
            );
        }
        // The template's own drive is fine, and so is a colon that makes
        // none.
        for (template, uri) in [
            (
                "file:///D:/project/{+path}",
                "file:///D:/project/docs/readme.md",
            ),
            (
                "file:///D:/project/{+path}",
                "file:///D:/project/docs/notes:v2.md",
            ),
            (
                "file:///D:/project/{+path}",
                "file:///D:/project/logs/12:30.txt",
            ),
            ("file:///p/{a}:{b}", "file:///p/ab:x"),
        ] {
            assert!(Template::parse(template).matches(uri), "{template} {uri}");
        }
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
