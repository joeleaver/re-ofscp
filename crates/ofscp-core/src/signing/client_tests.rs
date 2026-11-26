use base64::engine::general_purpose::STANDARD as B64;
use rand_core::OsRng;

use super::*;
use crate::signing::{decode_public_key, verify};

#[test]
fn generated_keys_sign_and_verify() {
    let key = DeviceKey::generate(&mut OsRng);
    let public = key.verifying_key();
    let sig = key.sign("hello");
    assert!(verify(&public, "hello", &sig));
    assert!(!verify(&public, "hellO", &sig));
    let again = DeviceKey::from_seed(&key.seed());
    assert_eq!(again.verifying_key(), public);
    assert_eq!(decode_public_key(&key.public_key_base64()), Ok(public));
}

#[test]
fn debug_hides_the_secret() {
    let key = DeviceKey::from_seed(&[7u8; 32]);
    let shown = format!("{key:?}");
    assert!(shown.contains(&key.public_key_base64()));
    assert!(!shown.contains(&B64.encode(*key.seed())));
    let signer = Signer {
        actor: &Actor::parse_canonical("alice@a.com").unwrap(),
        key_id: "dk_1",
        key: &key,
    };
    assert!(!format!("{signer:?}").contains(&B64.encode(*key.seed())));
}

#[test]
fn nonces_are_long_unique_base64url() {
    let a = generate_nonce(&mut OsRng);
    let b = generate_nonce(&mut OsRng);
    assert_ne!(a, b);
    assert_eq!(a.len(), 32);
    assert!(
        a.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    );
}

#[test]
fn timestamps_are_utc_seconds() {
    let t: jiff::Timestamp = "2026-01-01T12:00:00.789+02:00".parse().unwrap();
    assert_eq!(signing_timestamp(t), "2026-01-01T10:00:00Z");
}

#[test]
fn header_names_are_lowercase() {
    let key = DeviceKey::from_seed(&[1u8; 32]);
    let actor = Actor::parse_canonical("alice@a.com").unwrap();
    let a = Authority::parse_canonical("a.com").unwrap();
    let signer = Signer {
        actor: &actor,
        key_id: "dk_1",
        key: &key,
    };
    let request = Request {
        authority: &a,
        method: "GET",
        path: "/",
        query: None,
        body: b"",
    };
    let signed = signer
        .sign_request(&request, "2026-01-01T00:00:00Z", "n")
        .unwrap();
    for (name, _) in signed.pairs() {
        assert_eq!(name, name.to_ascii_lowercase());
    }
}

#[test]
fn a_signed_request_verifies_and_binds_every_part() {
    let key = DeviceKey::from_seed(&[3u8; 32]);
    let actor = Actor::parse_canonical("alice@a.com").unwrap();
    let signer = Signer {
        actor: &actor,
        key_id: "dk_1",
        key: &key,
    };
    let a = Authority::parse_canonical("a.com").unwrap();
    let request = Request {
        authority: &a,
        method: "POST",
        path: "/api/x",
        query: Some("b=2&a=1"),
        body: br#"{"hello":"world"}"#,
    };
    let ts = "2026-01-01T00:00:00Z";
    let headers = signer.sign_request(&request, ts, "nonce1").unwrap();
    assert_eq!(headers.actor, "alice@a.com");
    assert_eq!(
        headers.pairs()[5],
        (headers::SIGNATURE, headers.signature.as_str())
    );

    let check = |authority: &str, path: &str, digest: &str| {
        let canonical = CanonicalRequest {
            authority,
            method: "POST",
            path,
            query: Some("a=1&b=2"),
            timestamp: ts,
            nonce: "nonce1",
            content_digest: digest,
        }
        .render()
        .unwrap();
        verify(&key.verifying_key(), &canonical, &headers.signature)
    };
    assert!(check("a.com", "/api/x", &headers.content_digest));
    assert!(
        !check("b.com", "/api/x", &headers.content_digest),
        "authority is bound"
    );
    assert!(
        !check("a.com", "/api/y", &headers.content_digest),
        "path is bound"
    );
    assert!(
        !check("a.com", "/api/x", &content_digest(b"tampered")),
        "body is bound"
    );

    let again = signer.sign_request(&request, ts, "nonce2").unwrap();
    assert_ne!(again.signature, headers.signature, "nonce is bound");
}
