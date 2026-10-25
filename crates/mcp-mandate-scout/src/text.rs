//! Handling text written by the server: finding characters meant to hide
//! things, and making it safe to print.

/// Whether `c` is invisible or changes how text around it shows: zero-width
/// characters, direction overrides, Unicode "tag" characters, variation
/// selectors and the like. They can hide instructions from a person reading
/// a description while the model still reads them. The same characters the
/// pins file writes as escapes, so what Scout flags is what you'd see there.
pub(crate) fn is_hidden(c: char) -> bool {
    mcp_mandate_pin::is_hidden(c)
}

/// The terminal control characters in `text`: escapes, backspace, a
/// carriage return that doesn't end a line, and the like. A terminal acts
/// on them instead of showing them, so they can hide or overwrite text for
/// a person reading it while the model still reads it. Line breaks
/// (CRLF included) and tabs don't count.
pub(crate) fn control_characters(text: &str) -> Vec<char> {
    let mut found = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        let layout = c == '\n' || c == '\t' || (c == '\r' && chars.peek() == Some(&'\n'));
        if c.is_control() && !layout {
            found.push(c);
        }
    }
    found
}

/// `text` made safe for a terminal or a one-line comment: control and
/// hidden characters are shown as `\u{…}` escapes (a raw escape sequence
/// could rewrite the screen), and anything past `max` characters is cut.
pub fn printable(text: &str, max: usize) -> String {
    let mut out = String::new();
    for (count, c) in text.chars().enumerate() {
        if count == max {
            out.push('…');
            break;
        }
        if c.is_control() || is_hidden(c) {
            out.push_str(&c.escape_unicode().to_string());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_control_and_hidden_characters() {
        assert_eq!(printable("a\nb", 10), "a\\u{a}b");
        assert_eq!(printable("\u{1b}[2J", 10), "\\u{1b}[2J");
        assert_eq!(printable("x\u{200B}y", 10), "x\\u{200b}y");
        assert_eq!(printable("\u{E0041}", 10), "\\u{e0041}");
        // Every character that shows as nothing or steers layout, such as
        // a Mongolian variation selector or a musical format character.
        assert_eq!(
            printable("a\u{180B}b\u{1D173}c\u{FFF0}", 10),
            "a\\u{180b}b\\u{1d173}c\\u{fff0}"
        );
    }

    #[test]
    fn cuts_long_text() {
        assert_eq!(printable("abcdef", 3), "abc…");
        assert_eq!(printable("abc", 3), "abc");
    }

    #[test]
    fn ordinary_text_is_not_hidden() {
        assert!(!"Echoes the message — café, 日本語".chars().any(is_hidden));
    }

    #[test]
    fn finds_terminal_controls_but_not_line_breaks() {
        assert_eq!(
            control_characters("a\u{1b}[8mb\u{9b}c\u{8}d\re"),
            ['\u{1b}', '\u{9b}', '\u{8}', '\r']
        );
        assert!(control_characters("one\r\ntwo\nthree\tfour").is_empty());
    }
}
