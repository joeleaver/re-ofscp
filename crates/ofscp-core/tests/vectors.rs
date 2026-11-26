//! Byte-for-byte agreement with the spec's published conformance vectors:
//! request signing (§4.4.2), the WebSocket `authenticate` string (§7.1) and
//! the `dmId` example (§7.4).
//!
//! The spec is read from the sibling checkout `../ofscp` (`OFSCP_SPEC_DIR`
//! overrides). CI clones `lost-conn/ofscp` beside this repository. A missing
//! spec fails these tests; they never silently skip.

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ofscp_core::signing::{
    CanonicalRequest, content_digest, decode_public_key, encode_public_key, sign, verify,
    ws_canonical_string,
};
use ofscp_core::{Actor, dm_id};

fn spec_dir() -> PathBuf {
    std::env::var_os("OFSCP_SPEC_DIR").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../ofscp"),
        PathBuf::from,
    )
}

fn spec_file(relative: &str) -> String {
    let path = spec_dir().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {} ({e}); clone lost-conn/ofscp beside this repo or set OFSCP_SPEC_DIR",
            path.display()
        )
    })
}

fn spec_json(name: &str) -> serde_json::Value {
    serde_json::from_str(&spec_file(&format!("tests/{name}"))).unwrap()
}

/// The test signing key from a vector's `key.seed_hex`.
fn vector_key(v: &serde_json::Value) -> ed25519_dalek::SigningKey {
    let hex = v["key"]["seed_hex"].as_str().unwrap();
    let seed: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    ed25519_dalek::SigningKey::from_bytes(&seed.try_into().unwrap())
}

/// `tests/signing-vector.json` (§4.4.2).
#[test]
fn request_signing_vector() {
    let v = spec_json("signing-vector.json");
    let key = vector_key(&v);
    let s = |p: &str| v.pointer(p).and_then(|x| x.as_str()).unwrap();

    // The seed derives the published public key.
    assert_eq!(
        encode_public_key(&key.verifying_key()),
        s("/key/public_key_base64")
    );
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

    // And it verifies with the published public key.
    let public = decode_public_key(s("/key/public_key_base64")).unwrap();
    assert!(verify(&public, &canonical, s("/expected/signature")));
}

/// The `dmId` example in §7.4 of `docs/ofscp_spec.md`. The spec publishes no
/// JSON vector for it, so the example is read from the prose itself.
#[test]
fn dm_id_example() {
    let spec = spec_file("docs/ofscp_spec.md");
    let section = spec
        .split("#### Conversation id")
        .nth(1)
        .expect("the §7.4 Conversation id section");
    let field = |name: &str| {
        section
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .map(str::trim)
            .unwrap_or_else(|| panic!("no `{name}` line in the §7.4 example"))
    };
    let canonical = field("canonical string:");
    let want = field("dmId:");

    // The example writes the LF as the two characters `\n`, in quotes.
    let participants = canonical.trim_matches('"');
    let (first, second) = participants.split_once(r"\n").unwrap();
    let a = Actor::parse_canonical(first).unwrap();
    let b = Actor::parse_canonical(second).unwrap();
    assert_eq!(dm_id(&a, &b), want);
    assert_eq!(dm_id(&b, &a), want, "argument order is irrelevant");
}
