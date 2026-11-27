//! Validating JSON against the spec's own schemas, read from the sibling
//! checkout `../ofscp` (`OFSCP_SPEC_DIR` overrides). A missing spec fails
//! the tests that use this; they never silently skip.

use std::path::PathBuf;

use serde_json::Value;

/// The spec checkout.
pub fn spec_dir() -> PathBuf {
    std::env::var_os("OFSCP_SPEC_DIR").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../ofscp"),
        PathBuf::from,
    )
}

/// The `$id` prefix of the spec's schemas, which their relative `$ref`s
/// resolve against.
const SCHEMA_ID_BASE: &str = "https://example.invalid/ofscp/schemas/v0.1/";

/// Resolves the schemas' relative `$ref`s to files in the spec checkout.
struct SpecRetriever;

impl jsonschema::Retrieve for SpecRetriever {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let rel = uri
            .as_str()
            .strip_prefix(SCHEMA_ID_BASE)
            .ok_or_else(|| format!("unexpected schema uri {uri}"))?;
        let path = spec_dir().join("schemas/v0.1").join(rel);
        Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
    }
}

/// The errors of `instance` against `schema` (named `label` in them), with
/// formats checked.
pub fn errors_against(label: &str, schema: &Value, instance: &Value) -> Vec<String> {
    let validator = jsonschema::options()
        .should_validate_formats(true)
        .with_retriever(SpecRetriever)
        .build(schema)
        .unwrap_or_else(|e| panic!("schema {label} does not compile: {e}"));
    validator
        .iter_errors(instance)
        .map(|e| format!("{label}: {e} at {}", e.instance_path()))
        .collect()
}
