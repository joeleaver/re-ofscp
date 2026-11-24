//! Sending admin API requests from the browser.
//!
//! Requests are same-origin, so the HttpOnly session cookie (scoped to
//! `/api/admin`) goes with them and the page never sees it. Mutations
//! carry the CSRF token, which only ever lives in memory
//! ([`crate::session::Session`]).

use rinch_http::{Credentials, Request, fetch_async};
use serde::de::DeserializeOwned;

use crate::logic::problem::{ApiError, decode, error_from};
use crate::logic::request::{ApiCall, CSRF_HEADER, Method};

/// A successful answer's body.
struct Body(Vec<u8>);

async fn send(call: ApiCall, csrf: Option<&str>) -> Result<Body, ApiError> {
    let mut request = match call.method {
        Method::Get => Request::get(call.url),
        Method::Post => Request::post(call.url),
        Method::Patch => Request::patch(call.url),
        Method::Delete => Request::delete(call.url),
    }
    .credentials(Credentials::SameOrigin)
    .header("Accept", "application/json, application/problem+json");
    if let Some(body) = &call.body {
        request = request
            .header("Content-Type", "application/json")
            .body_str(body);
    }
    if let Some(token) = csrf {
        request = request.header(CSRF_HEADER, token);
    }
    let response = fetch_async(request)
        .await
        .map_err(|e| ApiError::Network(e.to_string()))?;
    if response.ok() {
        Ok(Body(response.body))
    } else {
        Err(error_from(
            response.status,
            &response.body,
            response.header("retry-after"),
        ))
    }
}

/// Send `call` and decode its JSON answer.
pub async fn json<T: DeserializeOwned>(call: ApiCall, csrf: Option<&str>) -> Result<T, ApiError> {
    let body = send(call, csrf).await?;
    decode(&body.0)
}

/// Send `call`, whose answer has no body that matters (`204`).
pub async fn empty(call: ApiCall, csrf: Option<&str>) -> Result<(), ApiError> {
    send(call, csrf).await.map(|_| ())
}
