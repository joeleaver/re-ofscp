//! `GET /.well-known/ofscp-provider`, the provider discovery document (§3.1).
//!
//! The document depends only on configuration, so it is built and
//! serialized once at startup, with a strong `ETag` over its exact bytes.
//! Capabilities state only what this provider implements today; each one
//! grows as its feature lands (docs/decisions/0007).

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_NONE_MATCH};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use re_ofscp_types::OFSCP_VERSION;
use re_ofscp_types::auth::RegistrationMode;
use re_ofscp_types::discovery::{
    Authentication, Capabilities, DiscoveryCapabilities, DiscoveryDocument, FederationCapabilities,
    ProviderInfo, RealtimeDelivery, Software,
};
use sha2::{Digest as _, Sha256};

use crate::{AppState, Config, Problem};

/// The discovery path (§3.1).
pub const PATH: &str = "/.well-known/ofscp-provider";

/// `Cache-Control` on the document: short, so a rotated provider key or a
/// changed registration mode reaches peers within minutes (as Forumall).
pub const CACHE_CONTROL_VALUE: &str = "public, max-age=300, must-revalidate";

/// Implementation name in `provider.software`.
pub const SOFTWARE_NAME: &str = "re-ofscp";

/// The document for `config`.
pub fn document(config: &Config) -> DiscoveryDocument {
    let base = format!("https://{}", config.domain);
    // A closed provider SHOULD omit the endpoint (§4.1.1). The
    // configuration only ever holds a known mode.
    let registration_endpoint = (config.registration == RegistrationMode::Open
        || config.registration == RegistrationMode::Invite)
        .then(|| format!("{base}/api/auth/register"));
    DiscoveryDocument {
        provider: ProviderInfo {
            domain: config.domain.clone(),
            protocol_version: OFSCP_VERSION.to_owned(),
            software: Software {
                name: SOFTWARE_NAME.to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
            contact: config.contact.clone(),
            authentication: Authentication {
                login_endpoint: format!("{base}/api/auth/login"),
                registration_endpoint,
                registration: Some(config.registration.clone()),
            },
            public_keys: config.provider_key.public_entries(),
        },
        // Every capability this provider has an answer for is stated
        // explicitly, even when the answer is "none".
        capabilities: Capabilities {
            // No message, channel or group APIs yet.
            message_types: Some(Vec::new()),
            tiers: Some(Vec::new()),
            metadata_schemas: None,
            limits: None,
            // No WebSocket endpoint yet (§8.5).
            federation: Some(FederationCapabilities {
                realtime_delivery: Some(RealtimeDelivery::None),
            }),
            discovery: Some(DiscoveryCapabilities {
                shares_known_providers: Some(false),
                discover_feed: Some(false),
            }),
        },
        endpoints: None,
    }
}

/// Why the document could not be prepared.
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    #[error("serializing the discovery document: {0}")]
    Json(#[from] serde_json::Error),
    #[error("discovery entity tag is not a header value: {0}")]
    EntityTag(#[from] axum::http::header::InvalidHeaderValue),
}

/// The serialized document and its entity tag.
#[derive(Debug, Clone)]
pub struct Published {
    body: Bytes,
    etag: HeaderValue,
}

impl Published {
    /// Serialize `config`'s document.
    pub fn new(config: &Config) -> Result<Self, PublishError> {
        let body = serde_json::to_vec(&document(config))?;
        let digest = Sha256::digest(&body);
        let tag = format!("\"{}\"", URL_SAFE_NO_PAD.encode(&digest[..16]));
        let etag = HeaderValue::from_str(&tag)?;
        Ok(Self {
            body: body.into(),
            etag,
        })
    }

    /// The entity tag, quoted.
    pub fn etag(&self) -> &HeaderValue {
        &self.etag
    }

    /// The JSON bytes served.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Whether `If-None-Match` names this representation (RFC 9110
    /// §13.1.2: weak comparison; `*` matches any).
    fn not_modified(&self, headers: &HeaderMap) -> bool {
        let ours = self.etag.as_bytes();
        headers
            .get_all(IF_NONE_MATCH)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .map(str::trim)
            .any(|tag| tag == "*" || tag.strip_prefix("W/").unwrap_or(tag).as_bytes() == ours)
    }
}

/// `GET /.well-known/ofscp-provider`.
pub async fn get(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let published = &state.discovery;
    let cache = HeaderValue::from_static(CACHE_CONTROL_VALUE);
    let etag = published.etag.clone();
    if published.not_modified(&headers) {
        return (
            StatusCode::NOT_MODIFIED,
            [(CACHE_CONTROL, cache), (ETAG, etag)],
        )
            .into_response();
    }
    Response::builder()
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .header(CACHE_CONTROL, cache)
        .header(ETAG, etag)
        .body(Body::from(published.body.clone()))
        .unwrap_or_else(|_| Problem::internal().into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(pairs: &'static [(&'static str, &'static str)]) -> Config {
        Config::from_lookup(|k| {
            pairs.iter().find(|(pk, _)| *pk == k).map_or_else(
                || match k {
                    "DOMAIN" => Some("Social.Example:8443".to_owned()),
                    "PROVIDER_SIGNING_KEY" => {
                        Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".to_owned())
                    }
                    _ => None,
                },
                |(_, v)| Some((*v).to_owned()),
            )
        })
        .unwrap()
    }

    #[test]
    fn invite_provider_advertises_endpoint_mode_and_key() {
        let c = config(&[]);
        let doc = document(&c);
        assert_eq!(doc.provider.domain.as_str(), "social.example:8443");
        let auth = &doc.provider.authentication;
        assert_eq!(
            auth.login_endpoint,
            "https://social.example:8443/api/auth/login"
        );
        assert_eq!(
            auth.registration_endpoint.as_deref(),
            Some("https://social.example:8443/api/auth/register")
        );
        assert_eq!(auth.registration, Some(RegistrationMode::Invite));
        assert_eq!(doc.provider.public_keys, c.provider_key.public_entries());
    }

    #[test]
    fn closed_provider_omits_the_registration_endpoint() {
        let doc = document(&config(&[("REGISTRATION", "closed")]));
        let auth = &doc.provider.authentication;
        assert_eq!(auth.registration_endpoint, None);
        assert_eq!(auth.registration, Some(RegistrationMode::Closed));
        let json = serde_json::to_value(&doc).unwrap();
        assert!(
            json["provider"]["authentication"]
                .get("registration_endpoint")
                .is_none()
        );
        assert_eq!(json["provider"]["authentication"]["registration"], "closed");
    }

    #[test]
    fn if_none_match_uses_weak_comparison() {
        let p = Published::new(&config(&[])).unwrap();
        let tag = p.etag().to_str().unwrap().to_owned();
        let check = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert(IF_NONE_MATCH, HeaderValue::from_str(v).unwrap());
            p.not_modified(&h)
        };
        assert!(check(&tag));
        assert!(check(&format!("W/{tag}")));
        assert!(check(&format!("\"other\", {tag}")));
        assert!(check("*"));
        assert!(!check("\"other\""));
        assert!(!p.not_modified(&HeaderMap::new()));
    }
}
