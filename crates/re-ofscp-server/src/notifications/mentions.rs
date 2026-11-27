//! Who a message mentions (§10.1 *Mentions*, §5.3).
//!
//! A message's `mentions`, when present, are exactly the users it mentions,
//! and its text is not read. Otherwise mentions are parsed from
//! `content.text`: `@handle` or `@handle@domain`, case-insensitively and
//! lowercased, where the `@` follows no letter, digit, `_` or `@`, the
//! handle is the longest run of `[a-z0-9_-]`, and a bare `@handle` names a
//! user of this provider (which hosts the channel).
//!
//! Choices where §10.1 says nothing (docs/decisions/0023): a run that is no
//! valid handle (§2.2.1: 3 to 32 characters) mentions no one, rather than
//! being cut to fit; an `@` straight after the handle that does not start a
//! valid authority makes the whole reference no mention, rather than a
//! bare one, so a malformed `@handle@…` never notifies a local namesake.
//!
//! At most [`MAX_MENTIONS`] users are mentioned, the explicit list's bound:
//! a text of thousands of `@` references names only the first
//! [`MAX_MENTIONS`] distinct local users, so a message costs a bounded
//! amount of feed work however it is written.

use ofscp_core::{Actor, Authority};

use crate::messages::validate::MAX_MENTIONS;

/// The local handles `mentions` names, or `text` mentions when `mentions`
/// is absent, deduplicated, in order of first appearance, and at most
/// [`MAX_MENTIONS`] of them. Mentions of users of other providers are left
/// out (the feed is provider-local) and do not count toward the bound.
pub fn local_mentions(
    mentions: Option<&[Actor]>,
    text: Option<&str>,
    home: &Authority,
) -> Vec<String> {
    let actors = match mentions {
        Some(list) => list.to_vec(),
        None => parse(text.unwrap_or_default(), home),
    };
    let mut out: Vec<String> = Vec::new();
    for a in actors {
        if out.len() == MAX_MENTIONS {
            break;
        }
        if a.is_local_to(home) && !out.iter().any(|h| h == a.handle()) {
            out.push(a.handle().to_owned());
        }
    }
    out
}

fn is_handle_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// What may follow the `@` of a domain: a host name and an optional port.
fn is_domain_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':'
}

/// Every actor `text` mentions, in order, a bare `@handle` naming a user of
/// `home`.
pub fn parse(text: &str, home: &Authority) -> Vec<Actor> {
    let mut out = Vec::new();
    let mut prev: Option<char> = None;
    let mut iter = text.char_indices().peekable();
    while let Some((i, c)) = iter.next() {
        let starts = c == '@' && !prev.is_some_and(|p| p.is_alphanumeric() || p == '_' || p == '@');
        prev = Some(c);
        if !starts {
            continue;
        }
        let rest = &text[i + 1..];
        let handle_len = rest
            .find(|c: char| !is_handle_char(c))
            .unwrap_or(rest.len());
        if handle_len == 0 {
            continue;
        }
        let handle = rest[..handle_len].to_ascii_lowercase();
        let after = &rest[handle_len..];
        let (actor, consumed) = match after.strip_prefix('@') {
            Some(domain_text) => {
                let domain_len = domain_text
                    .find(|c: char| !is_domain_char(c))
                    .unwrap_or(domain_text.len());
                // A sentence's full stop is not part of the domain.
                let raw = domain_text[..domain_len].trim_end_matches(['.', ':']);
                let actor = Authority::canonicalize(&raw.to_ascii_lowercase())
                    .ok()
                    .and_then(|d| Actor::new(&handle, d).ok());
                (actor, handle_len + 1 + raw.len())
            }
            None => (Actor::new(&handle, home.clone()).ok(), handle_len),
        };
        out.extend(actor);
        // Skip what the reference spans; its last character is what the
        // next `@` follows.
        let end = i + 1 + consumed;
        while iter.peek().is_some_and(|(j, _)| *j < end) {
            if let Some((_, ch)) = iter.next() {
                prev = Some(ch);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> Authority {
        Authority::parse_canonical("providera.com").unwrap()
    }

    fn names(text: &str) -> Vec<String> {
        parse(text, &home())
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn bare_and_qualified_mentions() {
        assert_eq!(
            names("hi @bob and @carol@b.example!"),
            ["bob@providera.com", "carol@b.example"]
        );
        assert_eq!(names("@bob"), ["bob@providera.com"]);
        assert_eq!(names("(@bob)"), ["bob@providera.com"]);
    }

    #[test]
    fn an_at_after_a_word_character_is_no_mention() {
        assert!(names("mail bob@example.com now").is_empty());
        assert!(names("x_@bob").is_empty());
        assert!(names("9@bob").is_empty());
        assert!(names("é@bob").is_empty());
        // `@@bob`: the second `@` follows an `@`.
        assert!(names("@@bob").is_empty());
    }

    #[test]
    fn matching_is_case_insensitive_and_lowercased() {
        assert_eq!(names("@BoB"), ["bob@providera.com"]);
        assert_eq!(names("@Carol@B.Example"), ["carol@b.example"]);
    }

    #[test]
    fn the_handle_is_the_longest_run() {
        assert_eq!(names("@bob_smith-2's"), ["bob_smith-2@providera.com"]);
        assert_eq!(names("@bob."), ["bob@providera.com"]);
        // Not cut to a valid handle: no mention at all.
        assert!(names("@ab").is_empty());
        assert!(names(&format!("@{}", "a".repeat(33))).is_empty());
    }

    #[test]
    fn domains_take_ports_and_drop_a_trailing_full_stop() {
        assert_eq!(names("ask @dave@c.example:8443."), ["dave@c.example:8443"]);
        assert_eq!(names("ask @dave@c.example."), ["dave@c.example"]);
    }

    #[test]
    fn a_malformed_domain_mentions_no_one() {
        assert!(names("@bob@").is_empty());
        assert!(names("@bob@ there").is_empty());
        // The reference is skipped whole: `@b` inside is not read again.
        assert!(names("@bob@@b..").is_empty());
    }

    #[test]
    fn explicit_mentions_win_over_the_text() {
        let carol = Actor::parse_canonical("carol@providera.com").unwrap();
        let remote = Actor::parse_canonical("dave@b.example").unwrap();
        let list = [carol, remote];
        assert_eq!(
            local_mentions(Some(&list), Some("@bob"), &home()),
            ["carol"]
        );
        // An empty list is a list: nobody is mentioned.
        assert!(local_mentions(Some(&[]), Some("@bob"), &home()).is_empty());
        assert_eq!(
            local_mentions(None, Some("@bob @bob @dave@b.example"), &home()),
            ["bob"]
        );
    }

    #[test]
    fn parsed_mentions_are_deduplicated_then_capped() {
        // Thousands of references, as a 16 KiB text can hold.
        let text: String = (0..3000).map(|i| format!("@u{i:04} ")).collect();
        let got = local_mentions(None, Some(&text), &home());
        assert_eq!(got.len(), MAX_MENTIONS);
        assert_eq!(got[0], "u0000");
        assert_eq!(got[MAX_MENTIONS - 1], format!("u{:04}", MAX_MENTIONS - 1));

        // Repeats and users of other providers do not use up the bound.
        let mut text = "@bob ".repeat(500);
        text.push_str(&"@dave@b.example ".repeat(500));
        text.push_str("@carol");
        assert_eq!(local_mentions(None, Some(&text), &home()), ["bob", "carol"]);
    }
}
