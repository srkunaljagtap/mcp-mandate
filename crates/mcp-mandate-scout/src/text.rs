//! Handling text written by the server: finding characters meant to hide
//! things, and making it safe to print.

/// Whether `c` is invisible or changes text direction: zero-width
/// characters, direction overrides, Unicode "tag" characters and variation
/// selectors. They can hide instructions from a person reading a
/// description while the model still reads them.
pub(crate) fn is_hidden(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{17B4}'
            | '\u{17B5}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{E0000}'..='\u{E007F}'
            | '\u{E0100}'..='\u{E01EF}'
    )
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
}
