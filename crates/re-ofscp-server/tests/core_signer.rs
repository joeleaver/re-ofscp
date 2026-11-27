//! Round trip between the two halves of signing: headers produced by
//! `ofscp_core`'s client [`Signer`](ofscp_core::signing::Signer) are
//! accepted by the server's real verifier (§4.4.1, §4.5), and a body
//! changed after signing is refused.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::harness::*;
use ofscp_core::signing::{self as core, DeviceKey};
use re_ofscp_server::signing::StaticKeys;

const KEY_ID: &str = "dk_core_client";
const BODY: &str = r#"{"content":{"text":"hi","mime":"text/plain"}}"#;

/// A device key unrelated to the spec vector, so the test cannot pass by
/// reusing the vector's precomputed signature.
fn device_key() -> DeviceKey {
    DeviceKey::from_seed(&[42; 32])
}

fn harness_for(key: &DeviceKey) -> Harness {
    let keys = StaticKeys::default().with(alice(), KEY_ID, key.verifying_key());
    harness_with(Arc::new(keys), SIGNED_AT, limits(1000))
}

/// `POST PATH?foo=1` signed by the core client over `signed_body`, but
/// carrying `sent_body` (the two differ to model tampering in transit).
fn core_signed(key: &DeviceKey, nonce: &str, signed_body: &str, sent_body: &str) -> Request<Body> {
    let actor = alice();
    let authority = provider_a();
    let signer = core::Signer {
        actor: &actor,
        key_id: KEY_ID,
        key,
    };
    let request = core::Request {
        authority: &authority,
        method: "POST",
        path: PATH,
        query: Some("foo=1"),
        body: signed_body.as_bytes(),
    };
    let headers = signer
        .sign_request(&request, "2026-01-01T12:00:00Z", nonce)
        .expect("no component has a line break");
    let mut b = Request::post(format!("{PATH}?foo=1")).header("host", "providera.com");
    for (name, value) in headers.pairs() {
        b = b.header(name, value);
    }
    b.body(Body::from(sent_body.to_owned())).unwrap()
}

#[tokio::test]
async fn core_signer_request_is_accepted_by_the_server_verifier() {
    let key = device_key();
    let h = harness_for(&key);
    let req = core_signed(&key, "c0reN0nce-roundtrip-0001", BODY, BODY);
    let (status, _, text, _) = send(&h.app, req).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(text, format!("actor alice@providera.com {KEY_ID}"));
}

#[tokio::test]
async fn core_signer_request_with_tampered_body_is_refused() {
    let key = device_key();
    let h = harness_for(&key);
    let tampered = r#"{"content":{"text":"bye","mime":"text/plain"}}"#;
    let req = core_signed(&key, "c0reN0nce-roundtrip-0002", BODY, tampered);
    let (status, json, _, _) = send(&h.app, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["errorCode"], "bad_request");
}

#[tokio::test]
async fn core_signer_request_from_an_unregistered_key_is_refused() {
    let h = harness_for(&device_key());
    let other = DeviceKey::from_seed(&[7; 32]);
    let req = core_signed(&other, "c0reN0nce-roundtrip-0003", BODY, BODY);
    let (status, _, text, _) = send(&h.app, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{text}");
}
