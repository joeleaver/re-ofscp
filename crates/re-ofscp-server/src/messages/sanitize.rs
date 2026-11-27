//! The `text/html` allow-list of spec §5.3 *Content formats*, applied by
//! the provider before it stores a body (security requirement 8).
//!
//! The spec puts the duty to sanitize on every client that renders HTML.
//! The provider sanitizes too, with the same allow-list, so a client that
//! forgets cannot be handed script by this provider: what it stores is
//! already inert. Markdown is stored as sent: renderers MUST show its raw
//! HTML as text (§5.3), so there is nothing to strip.

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

/// The elements §5.3 keeps.
const TAGS: [&str; 33] = [
    "p",
    "br",
    "hr",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "strong",
    "b",
    "em",
    "i",
    "u",
    "s",
    "del",
    "sub",
    "sup",
    "code",
    "pre",
    "blockquote",
    "ul",
    "ol",
    "li",
    "a",
    "img",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
    "span",
];

/// The elements §5.3 removes together with their contents. Every other
/// element outside [`TAGS`] is removed and its text kept.
const DROPPED_WITH_CONTENT: [&str; 7] = [
    "script", "style", "iframe", "object", "embed", "template", "noscript",
];

/// The link schemes a client may make active (§5.3: `http`, `https`,
/// `mailto`, and `attachment:` references). An `href` with any other
/// scheme, or a relative one (a message has no base URL), is removed.
const SCHEMES: [&str; 4] = ["http", "https", "mailto", "attachment"];

static CLEANER: LazyLock<ammonia::Builder<'static>> = LazyLock::new(|| {
    let mut b = ammonia::Builder::empty();
    b.tags(HashSet::from(TAGS))
        .clean_content_tags(HashSet::from(DROPPED_WITH_CONTENT))
        .tag_attributes(HashMap::from([
            ("a", HashSet::from(["href"])),
            ("img", HashSet::from(["alt", "data-attachment"])),
            ("th", HashSet::from(["colspan", "rowspan"])),
            ("td", HashSet::from(["colspan", "rowspan"])),
        ]))
        .url_schemes(HashSet::from(SCHEMES))
        .url_relative(ammonia::UrlRelative::Deny)
        // ammonia would add `rel` to links, an attribute §5.3 does not keep.
        .link_rel(None)
        .strip_comments(true);
    b
});

/// `html` with only the §5.3 elements and attributes left.
pub fn sanitize_html(html: &str) -> String {
    CLEANER.clean(html).to_string()
}

#[cfg(test)]
mod tests {
    use super::sanitize_html;

    #[test]
    fn keeps_the_allowed_elements_and_attributes() {
        let html = r#"<h1>Title</h1><p>A <a href="https://x.example/">link</a> and <img data-attachment="att_1" alt="cap"></p><table><tbody><tr><td colspan="2">c</td></tr></tbody></table>"#;
        assert_eq!(sanitize_html(html), html);
    }

    #[test]
    fn removes_script_with_its_contents_and_other_elements_keeping_text() {
        assert_eq!(
            sanitize_html("<div>keep<script>alert(1)</script><style>p{}</style></div>"),
            "keep"
        );
        assert_eq!(
            sanitize_html("<iframe src=x>gone</iframe><noscript>gone</noscript>ok"),
            "ok"
        );
    }

    #[test]
    fn removes_every_attribute_off_the_list() {
        assert_eq!(
            sanitize_html(r#"<p style="x" class="c" id="i" onclick="e()">t</p>"#),
            "<p>t</p>"
        );
        assert_eq!(
            sanitize_html(r#"<img src="https://t.example/p.gif" data-attachment="a" onerror="x">"#),
            r#"<img data-attachment="a">"#
        );
    }

    #[test]
    fn keeps_only_active_link_schemes() {
        assert_eq!(
            sanitize_html(r#"<a href="javascript:alert(1)">x</a>"#),
            "<a>x</a>"
        );
        assert_eq!(sanitize_html(r#"<a href="/relative">x</a>"#), "<a>x</a>");
        assert_eq!(sanitize_html(r##"<a href="#frag">x</a>"##), "<a>x</a>");
        assert_eq!(
            sanitize_html(r#"<a href="mailto:a@b.example">x</a>"#),
            r#"<a href="mailto:a@b.example">x</a>"#
        );
        assert_eq!(
            sanitize_html(r#"<a href="attachment:att_2">x</a>"#),
            r#"<a href="attachment:att_2">x</a>"#
        );
    }
}
