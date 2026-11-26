use re_ofscp_types::Actor;
use re_ofscp_types::profile::{PresenceUpdate, PrivacyUpdate, ProfileUpdate};
use serde_json::{Value, json};

use super::*;

fn profile(body: Value) -> Result<ProfileChanges, Invalid> {
    profile_update(&serde_json::from_value::<ProfileUpdate>(body).unwrap())
}

fn privacy(body: Value, allow: &[Actor], deny: &[Actor]) -> Result<PrivacyChanges, Invalid> {
    privacy_update(
        &serde_json::from_value::<PrivacyUpdate>(body).unwrap(),
        allow,
        deny,
    )
}

fn presence(body: Value) -> Result<(), Invalid> {
    presence_update(&serde_json::from_value::<PresenceUpdate>(body).unwrap())
}

fn actor(s: &str) -> Actor {
    Actor::parse_canonical(s).unwrap()
}

fn meta() -> Value {
    json!({"schema": "https://example.org/s", "version": "1", "data": {"k": 1}})
}

#[test]
fn an_empty_patch_changes_nothing() {
    assert_eq!(profile(json!({})), Ok(ProfileChanges::default()));
}

#[test]
fn display_names_are_trimmed_and_bounded() {
    let c = profile(json!({"displayName": "  Jane Doe  "})).unwrap();
    assert_eq!(c.display_name.as_deref(), Some("Jane Doe"));
    for bad in [
        json!(""),
        json!("   "),
        json!("x".repeat(101)),
        json!("a\u{7}b"),
    ] {
        assert!(profile(json!({ "displayName": bad })).is_err(), "{bad}");
    }
    assert!(profile(json!({"displayName": "é".repeat(100)})).is_ok());
}

#[test]
fn avatars_can_only_be_removed_until_media_exists() {
    assert_eq!(
        profile(json!({"avatar": null})).unwrap().avatar.as_deref(),
        Some("")
    );
    let not_https = profile(json!({"avatar": "http://a.com/x.png"})).unwrap_err();
    assert!(not_https.0.contains("https"), "{not_https}");
    let not_hosted = profile(json!({"avatar": "https://a.com/x.png"})).unwrap_err();
    assert!(not_hosted.0.contains("POST /api/media"), "{not_hosted}");
}

#[test]
fn bios_allow_line_breaks_but_no_other_controls() {
    assert!(profile(json!({"bio": "line one\nline two\ttabbed"})).is_ok());
    assert!(profile(json!({"bio": ""})).is_ok());
    assert!(profile(json!({"bio": "bell\u{7}"})).is_err());
    assert!(profile(json!({"bio": "cr\r"})).is_err());
    assert!(profile(json!({"bio": "x".repeat(MAX_BIO_CHARS)})).is_ok());
    assert!(profile(json!({"bio": "x".repeat(MAX_BIO_CHARS + 1)})).is_err());
}

#[test]
fn metadata_is_checked() {
    assert!(profile(json!({"metadata": [meta()]})).is_ok());
    let bad_schema = json!({"schema": "http://x", "version": "1", "data": null});
    assert!(profile(json!({"metadata": [bad_schema]})).is_err());
    let relative = json!({"schema": "/s", "version": "1", "data": null});
    assert!(profile(json!({"metadata": [relative]})).is_err());
    let no_version = json!({"schema": "https://x", "version": "", "data": null});
    assert!(profile(json!({"metadata": [no_version]})).is_err());
    let many: Vec<Value> = (0..=MAX_METADATA_ENTRIES).map(|_| meta()).collect();
    assert!(profile(json!({ "metadata": many })).is_err());
    let big =
        json!({"schema": "https://x", "version": "1", "data": "x".repeat(MAX_METADATA_BYTES)});
    assert!(profile(json!({"metadata": [big]})).is_err());
}

#[test]
fn privacy_lists_are_canonicalized_and_deduplicated() {
    let c = privacy(
        json!({"allowList": ["jane@A.com", "jane@a.com", "bob@b.com:443"]}),
        &[],
        &[],
    )
    .unwrap();
    assert_eq!(c.allow, Some(vec![actor("jane@a.com"), actor("bob@b.com")]));
    assert_eq!(c.deny, None);
    for bad in ["jane", "Jane@a.com", "jane@", "@a.com", "jane@a.com/x"] {
        assert!(
            privacy(json!({ "denyList": [bad] }), &[], &[]).is_err(),
            "{bad}"
        );
    }
    let too_many: Vec<String> = (0..=MAX_LIST_ENTRIES)
        .map(|i| format!("u{i:03}@a.com"))
        .collect();
    assert!(privacy(json!({ "allowList": too_many }), &[], &[]).is_err());
}

#[test]
fn no_actor_may_end_up_on_both_lists() {
    let both = json!({"allowList": ["bob@b.com"], "denyList": ["bob@B.com"]});
    assert!(privacy(both, &[], &[]).is_err());
    // Against the stored list the request leaves in place.
    let bob = actor("bob@b.com");
    assert!(
        privacy(
            json!({"allowList": ["bob@b.com"]}),
            &[],
            std::slice::from_ref(&bob)
        )
        .is_err()
    );
    assert!(
        privacy(
            json!({"denyList": ["bob@b.com"]}),
            std::slice::from_ref(&bob),
            &[]
        )
        .is_err()
    );
    // Replacing both lists at once moves bob cleanly.
    let moved = json!({"allowList": [], "denyList": ["bob@b.com"]});
    assert!(privacy(moved, &[bob], &[]).is_ok());
    // Local bob and remote bob are different actors.
    let distinct = json!({"allowList": ["bob@a.com"], "denyList": ["bob@b.com"]});
    assert!(privacy(distinct, &[], &[]).is_ok());
}

#[test]
fn presence_cannot_be_set_offline_and_status_is_bounded() {
    assert!(presence(json!({"availability": "away", "status": "brb"})).is_ok());
    assert!(presence(json!({"availability": "online"})).is_ok());
    assert!(presence(json!({"availability": "offline"})).is_err());
    assert!(presence(json!({"availability": "dnd", "status": "a\nb"})).is_err());
    let long = "x".repeat(MAX_STATUS_CHARS + 1);
    assert!(presence(json!({"availability": "dnd", "status": long})).is_err());
    assert!(presence(json!({"availability": "dnd", "metadata": [meta()]})).is_ok());
}
