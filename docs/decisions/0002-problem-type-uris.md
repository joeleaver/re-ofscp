# 0002: Error responses: `errorCode` registry and per-provider `type` URIs

- **Status:** accepted
- **Date:** 2026-11-23
- **Spec:** §2.6, §7.3, from
  [lost-conn/ofscp#17](https://github.com/lost-conn/ofscp/pull/17) (merged)

## Context

The spec used to require `type` to be "a stable https URI" without saying
which one. Forumall used `https://ofscp.org/problems/…`, a domain nobody
owns. When asked, the oracle first passed the question to Joe and Seth. Joe
pushed back, since what a field contains is the spec's job to settle, and
the spec now does.

## Decision (as the spec now says)

- **`errorCode`:** every problem response carries one, from the §7.3
  registry: `bad_request`, `unauthorized`, `forbidden`, `not_found`,
  `conflict`, `subscription_limit` (409), `payload_too_large`,
  `too_many_requests`, `internal_error` and `service_unavailable`. Clients
  branch on `status` plus `errorCode`, never on `type`.
- **`type`:** set to `https://{our canonical DOMAIN}/problems/{errorCode}`,
  with the code verbatim (underscores included). `GET /problems/{code}`
  serves a plain-text description, as the spec says we SHOULD.
- **Extension codes:** these are allowed when paired with their status. We
  use `method_not_allowed` (405), `request_timeout` (408) and
  `unsupported_media_type` (415).

## Implementation

- **Where:** `crates/re-ofscp-server/src/problem.rs`.
- **How the URL gets our domain:** a `Problem` doesn't know the domain, so
  its `IntoResponse` sets the status and headers and stores itself in the
  response. The `problem::render` layer, installed once on the router, then
  writes the JSON body.
- **Unknown routes:** they return a `not_found` problem, and wrong methods
  return `method_not_allowed` (keeping `Allow`).
- **Framework errors:** the render layer also converts every *other* error
  response into a problem, such as axum's rejections for a bad path, a
  malformed JSON body, the wrong content type or a bad query. A 4xx keeps a
  bounded prefix of its text as `detail`. Axum's 422 becomes 400
  `bad_request`, and a 5xx becomes `internal_error` with no detail.
- **Tests:** `tests/problems.rs` validates real responses against the spec's
  `problem-details.json` schema, and checks that the schema really rejects
  the old shape.
