//! Splitting a typed REPL line into arguments.
//!
//! `clap` parses argument *vectors*; a shell is what normally produces one. Inside
//! the REPL there is no shell, so this does that job — and it has to, because the
//! commands being reused take values with spaces in them (`--label "backup in
//! safe"`, a path under `My Documents`).
//!
//! Deliberately a small subset of shell quoting: single quotes, double quotes, and
//! backslash escapes. No expansion of variables, globs, or `~`, because a REPL that
//! silently rewrote an argument would be worse than one that took it literally.

/// Split `line` into arguments, honouring quotes and backslash escapes.
///
/// Returns `Ok(vec![])` for a blank or comment-only line.
pub fn tokenize(line: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut have_token = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {
                if have_token {
                    tokens.push(std::mem::take(&mut current));
                    have_token = false;
                }
            }
            '#' if !have_token => break, // a comment runs to end of line
            '\'' => {
                have_token = true;
                // Single quotes are literal, as in a shell: a Windows path full of
                // backslashes can be pasted between them and survive intact.
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(c) => current.push(c),
                        None => return Err("unterminated ' quote".to_string()),
                    }
                }
            }
            '"' => {
                have_token = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            // Only the characters that need escaping are special;
                            // anything else keeps its backslash, so `"C:\Users"`
                            // means what it looks like.
                            Some(escaped @ ('"' | '\\')) => current.push(escaped),
                            Some(other) => {
                                current.push('\\');
                                current.push(other);
                            }
                            None => return Err("unterminated \" quote".to_string()),
                        },
                        Some(c) => current.push(c),
                        None => return Err("unterminated \" quote".to_string()),
                    }
                }
            }
            '\\' => {
                have_token = true;
                match chars.next() {
                    Some(escaped) => current.push(escaped),
                    None => return Err("line ends with a trailing backslash".to_string()),
                }
            }
            c => {
                have_token = true;
                current.push(c);
            }
        }
    }

    if have_token {
        tokens.push(current);
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(line: &str) -> Vec<String> {
        tokenize(line).unwrap()
    }

    #[test]
    fn splits_on_whitespace() {
        assert_eq!(
            split("kv get tokens github"),
            ["kv", "get", "tokens", "github"]
        );
        assert_eq!(split("   spaced   out  "), ["spaced", "out"]);
    }

    #[test]
    fn a_blank_line_produces_no_tokens() {
        assert!(split("").is_empty());
        assert!(split("    ").is_empty());
        assert!(split("\t\n").is_empty());
    }

    #[test]
    fn double_quotes_hold_a_value_together() {
        assert_eq!(
            split("enroll tokens --label \"backup in safe\""),
            ["enroll", "tokens", "--label", "backup in safe"]
        );
    }

    #[test]
    fn single_quotes_are_literal() {
        // The reason single quotes exist here: a pasted Windows path.
        assert_eq!(
            split(r"open 'C:\Users\me\vault.fido'"),
            ["open", r"C:\Users\me\vault.fido"]
        );
    }

    #[test]
    fn double_quotes_escape_only_what_needs_it() {
        assert_eq!(split(r#""a\"b""#), [r#"a"b"#]);
        assert_eq!(split(r#""a\\b""#), [r"a\b"]);
        // A backslash before anything else keeps its backslash, so a Windows path
        // in double quotes is not silently mangled.
        assert_eq!(split(r#""C:\Users\me""#), [r"C:\Users\me"]);
    }

    #[test]
    fn a_bare_backslash_escapes_the_next_character() {
        assert_eq!(split(r"a\ b"), ["a b"]);
    }

    #[test]
    fn quotes_can_be_empty_and_still_make_a_token() {
        // `--label ""` must reach clap as an empty argument, not vanish.
        assert_eq!(
            split(r#"enroll t --label """#),
            ["enroll", "t", "--label", ""]
        );
    }

    #[test]
    fn quotes_can_abut_unquoted_text() {
        assert_eq!(split(r#"--work-dir=/a" "b"#), ["--work-dir=/a b"]);
    }

    #[test]
    fn comments_are_dropped() {
        assert!(split("# just a note").is_empty());
        assert_eq!(split("stores # why not"), ["stores"]);
        // Only at the start of a token: a value may legitimately contain a hash.
        assert_eq!(
            split("kv set t name --value a#b"),
            ["kv", "set", "t", "name", "--value", "a#b"]
        );
    }

    #[test]
    fn unterminated_quotes_are_an_error_not_a_silent_truncation() {
        assert!(tokenize(r#"open "vault.fido"#).is_err());
        assert!(tokenize("open 'vault.fido").is_err());
        assert!(tokenize(r"open vault\").is_err());
    }
}
