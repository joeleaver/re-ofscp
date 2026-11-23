//! Byte-for-byte agreement with the spec's published conformance vectors.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use common::{spec_json, vector_key};
use re_ofscp_server::signing::canonical::{
    CanonicalRequest, content_digest, decode_public_key, sign, verify, ws_canonical_string,
};

/// `tests/signing-vector.json` (§4.4.2).
#[test]
fn request_signing_vector() {
    let v = spec_json("signing-vector.json");
    let key = vector_key(&v);
    let s = |p: &str| v.pointer(p).and_then(|x| x.as_str()).unwrap();

    // The seed derives the published public key.
    assert_eq!(
        B64.encode(key.verifying_key().to_bytes()),
        s("/key/public_key_base64")
    );

    // Body digest.
    let body = s("/request/body");
    assert_eq!(
        content_digest(body.as_bytes()),
        s("/headers/X-OFSCP-Content-Digest")
    );

    // Canonical string, byte for byte.
    let canonical = CanonicalRequest {
        authority: s("/request/authority"),
        method: s("/request/method"),
        path: s("/request/path"),
        query: Some(s("/request/query")),
        timestamp: s("/headers/X-OFSCP-Timestamp"),
        nonce: s("/headers/X-OFSCP-Nonce"),
        content_digest: s("/headers/X-OFSCP-Content-Digest"),
    }
    .render();
    assert_eq!(canonical, s("/canonical_string"));
    let lines: Vec<&str> = v["canonical_string_lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap())
        .collect();
    assert_eq!(canonical, lines.join("\n"));

    // Deterministic signature.
    let signature = sign(&key, &canonical);
    assert_eq!(signature, s("/expected/signature"));
    assert_eq!(
        format!("X-OFSCP-Signature: {signature}"),
        s("/expected/header")
    );

    // And it verifies with the published public key.
    let public = decode_public_key(s("/key/public_key_base64")).unwrap();
    assert!(verify(&public, &canonical, &signature));
    assert!(!verify(&public, &format!("{canonical}\n"), &signature));
}

/// `tests/ws-signing-vector.json` (§7.1).
#[test]
fn ws_authenticate_vector() {
    let v = spec_json("ws-signing-vector.json");
    let key = vector_key(&v);
    let s = |p: &str| v.pointer(p).and_then(|x| x.as_str()).unwrap();

    let canonical = ws_canonical_string(
        s("/challenge/authority"),
        s("/challenge/challengeNonce"),
        s("/challenge/timestamp"),
    );
    assert_eq!(canonical, s("/canonical_string"));
    assert_eq!(sign(&key, &canonical), s("/expected/signature"));

    // The vector agrees with the WS samples it cites.
    let challenge = spec_json("ws-auth-challenge.sample.json");
    assert_eq!(
        challenge["data"]["nonce"].as_str().unwrap(),
        s("/challenge/challengeNonce")
    );
    let auth = spec_json("ws-authenticate.sample.json");
    assert_eq!(
        auth["data"]["signature"].as_str().unwrap(),
        s("/expected/signature")
    );
    assert_eq!(
        auth["data"]["timestamp"].as_str().unwrap(),
        s("/challenge/timestamp")
    );
}
