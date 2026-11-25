//! A local https "remote provider" for the outbound-client and remote-key
//! tests: a certificate authority made with rcgen, a leaf for `localhost`
//! and `127.0.0.1`, and programmable replies per path.
#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Bytes;
use ed25519_dalek::VerifyingKey;
use http_body_util::{Either, Full};
use hyper::body::{Body, Frame};
use hyper::{Request, Response};
use re_ofscp_server::outbound::{OutboundClient, OutboundConfig};
use re_ofscp_types::Authority;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::{assert_valid, schema};

/// What the peer answers on one path.
#[derive(Clone, Debug)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Wait this long before answering.
    pub delay: Duration,
    /// Send the body chunked, without a `Content-Length`.
    pub chunked: bool,
}

impl Reply {
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.into(),
            delay: Duration::ZERO,
            chunked: false,
        }
    }

    pub fn json(status: u16, value: &Value) -> Self {
        Self::new(status, value.to_string()).header("content-type", "application/json")
    }

    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    #[must_use]
    pub fn delayed(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    #[must_use]
    pub fn chunked(mut self) -> Self {
        self.chunked = true;
        self
    }
}

type Replies = Arc<Mutex<HashMap<String, Reply>>>;

/// The running peer. Stops when dropped.
pub struct RemotePeer {
    pub port: u16,
    /// The CA's certificate, to trust in clients.
    pub ca_der: Vec<u8>,
    replies: Replies,
    hits: Arc<Mutex<HashMap<String, usize>>>,
    total: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for RemotePeer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl RemotePeer {
    pub async fn start() -> Self {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "re-ofscp test CA");
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf =
            rcgen::CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
                .unwrap()
                .signed_by(&leaf_key, &issuer)
                .unwrap();

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone(), ca.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let replies: Replies = Arc::default();
        let hits: Arc<Mutex<HashMap<String, usize>>> = Arc::default();
        let total = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(serve(
            listener,
            acceptor,
            replies.clone(),
            hits.clone(),
            total.clone(),
        ));
        Self {
            port,
            ca_der: CertificateDer::as_ref(ca.der()).to_vec(),
            replies,
            hits,
            total,
            task,
        }
    }

    /// `localhost:{port}`.
    pub fn authority(&self) -> Authority {
        Authority::parse_canonical(&format!("localhost:{}", self.port)).unwrap()
    }

    /// `127.0.0.1:{port}`.
    pub fn ip_authority(&self) -> Authority {
        Authority::parse_canonical(&format!("127.0.0.1:{}", self.port)).unwrap()
    }

    pub fn set(&self, path: &str, reply: Reply) {
        self.replies.lock().unwrap().insert(path.to_owned(), reply);
    }

    /// Requests received on `path`.
    pub fn hits(&self, path: &str) -> usize {
        self.hits.lock().unwrap().get(path).copied().unwrap_or(0)
    }

    /// Requests received on any path.
    pub fn total_hits(&self) -> usize {
        self.total.load(Ordering::SeqCst)
    }

    /// Outbound settings trusting this peer's CA, with `allow` exempt from
    /// the address rule.
    pub fn config(&self, allow: Vec<Authority>) -> OutboundConfig {
        let mut config = OutboundConfig::new(allow);
        config.extra_roots = vec![self.ca_der.clone()];
        config
    }

    /// A client that may reach this peer (by name and by address).
    pub fn allowed_client(&self) -> OutboundClient {
        OutboundClient::new(&self.config(vec![self.authority(), self.ip_authority()])).unwrap()
    }

    /// A client trusting this peer's CA but applying the address rule.
    pub fn strict_client(&self) -> OutboundClient {
        OutboundClient::new(&self.config(Vec::new())).unwrap()
    }
}

async fn serve(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    replies: Replies,
    hits: Arc<Mutex<HashMap<String, usize>>>,
    total: Arc<AtomicUsize>,
) {
    loop {
        let Ok((tcp, _)) = listener.accept().await else {
            continue;
        };
        let (acceptor, replies, hits, total) = (
            acceptor.clone(),
            replies.clone(),
            hits.clone(),
            total.clone(),
        );
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(tcp).await else {
                return;
            };
            let service = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                let (replies, hits, total) = (replies.clone(), hits.clone(), total.clone());
                async move {
                    let path = req.uri().path().to_owned();
                    total.fetch_add(1, Ordering::SeqCst);
                    *hits.lock().unwrap().entry(path.clone()).or_default() += 1;
                    let reply = replies.lock().unwrap().get(&path).cloned();
                    let reply = reply.unwrap_or_else(|| Reply::new(404, ""));
                    tokio::time::sleep(reply.delay).await;
                    Ok::<_, Infallible>(respond(reply))
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                .await;
        });
    }
}

fn respond(reply: Reply) -> Response<Either<Full<Bytes>, Chunks>> {
    let body = if reply.chunked {
        Either::Right(Chunks(
            reply
                .body
                .chunks(1024)
                .map(Bytes::copy_from_slice)
                .collect(),
        ))
    } else {
        Either::Left(Full::new(Bytes::from(reply.body)))
    };
    let mut res = Response::builder().status(reply.status);
    for (k, v) in &reply.headers {
        res = res.header(k, v);
    }
    res.body(body).unwrap()
}

/// A body of unknown length (sent chunked).
pub struct Chunks(VecDeque<Bytes>);

impl Body for Chunks {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(self.0.pop_front().map(|b| Ok(Frame::data(b))))
    }
}

/// The user keys endpoint path for `handle`.
pub fn keys_path(handle: &str) -> String {
    format!("/.well-known/ofscp/users/{handle}/keys")
}

/// The discovery path.
pub const DISCOVERY_PATH: &str = "/.well-known/ofscp-provider";

fn b64(key: &VerifyingKey) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(key.as_bytes())
}

/// A keys response (§4.6), checked against the spec's schema.
pub fn keys_doc(actor: &str, keys: &[(&str, VerifyingKey)], cache_until: &str) -> Value {
    let doc = json!({
        "actor": actor,
        "keys": keys.iter().map(|(id, k)| json!({
            "key_id": id,
            "algorithm": "Ed25519",
            "public_key": b64(k),
            "created_at": "2026-01-01T00:00:00Z",
        })).collect::<Vec<_>>(),
        "cache_until": cache_until,
    });
    assert_valid(&schema("user-keys-response.json"), &doc);
    doc
}

/// A discovery document (§3.1, §8.1), checked against the spec's schema.
pub fn discovery_doc(domain: &str, keys: &[(&str, VerifyingKey)]) -> Value {
    let doc = json!({
        "provider": {
            "domain": domain,
            "protocolVersion": "0.1.0",
            "software": { "name": "test-peer", "version": "1.0.0" },
            "contact": "admin@example.com",
            "authentication": { "login_endpoint": format!("https://{domain}/api/auth/login") },
            "publicKeys": keys.iter().map(|(id, k)| json!({
                "key_id": id,
                "algorithm": "Ed25519",
                "public_key": b64(k),
            })).collect::<Vec<_>>(),
        },
        "capabilities": {},
    });
    assert_valid(&schema("provider-discovery.json"), &doc);
    doc
}
