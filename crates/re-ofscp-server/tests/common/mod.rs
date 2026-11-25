//! Shared helpers for integration tests.
#![allow(dead_code)]

pub mod accounts;
pub mod admin;
pub mod harness;
pub mod key_setup;
pub mod remote_peer;
pub mod rhypedb;

use std::path::PathBuf;

/// The sibling `ofscp` spec checkout (`OFSCP_SPEC_DIR` overrides). CI clones
/// `lost-conn/ofscp` beside this repository. Missing → the test fails, never
/// silently skips.
pub fn spec_dir() -> PathBuf {
    std::env::var_os("OFSCP_SPEC_DIR").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../ofscp"),
        PathBuf::from,
    )
}

/// Read and parse a JSON file from the spec's `tests/` directory.
pub fn spec_json(name: &str) -> serde_json::Value {
    let path = spec_dir().join("tests").join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {} ({e}); clone lost-conn/ofscp beside this repo or set OFSCP_SPEC_DIR",
            path.display()
        )
    });
    serde_json::from_str(&text).unwrap()
}

/// Decode lowercase/uppercase hex.
pub fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The test signing key from the spec vectors.
pub fn vector_key(v: &serde_json::Value) -> ed25519_dalek::SigningKey {
    let seed: [u8; 32] = hex(v["key"]["seed_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

/// Where the spec's schemas say they live (their `$id` base).
const SCHEMA_ID_BASE: &str = "https://example.invalid/ofscp/schemas/v0.1/";

/// Resolves the spec's relative `$ref`s to files in the sibling checkout.
struct SpecRetriever;

impl jsonschema::Retrieve for SpecRetriever {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let rel = uri
            .as_str()
            .strip_prefix(SCHEMA_ID_BASE)
            .ok_or_else(|| format!("unexpected schema uri {uri}"))?;
        let path = spec_dir().join("schemas/v0.1").join(rel);
        Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
    }
}

/// A validator for `schemas/v0.1/<name>` from the spec checkout.
pub fn schema(name: &str) -> jsonschema::Validator {
    let path = spec_dir().join("schemas/v0.1").join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {} ({e})", path.display()));
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    jsonschema::options()
        .should_validate_formats(true)
        .with_retriever(SpecRetriever)
        .build(&value)
        .unwrap_or_else(|e| panic!("schema {name} does not compile: {e}"))
}

/// Panic with every validation error if `instance` does not match.
pub fn assert_valid(validator: &jsonschema::Validator, instance: &serde_json::Value) {
    let errors: Vec<String> = validator
        .iter_errors(instance)
        .map(|e| format!("{} at {}", e, e.instance_path()))
        .collect();
    assert!(errors.is_empty(), "{instance}\n{}", errors.join("\n"));
}
