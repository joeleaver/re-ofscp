# 0011: A shared protocol core crate, `ofscp-core`

- **Status:** accepted
- **Date:** 2026-11-26

## Context

Two Rust codebases speak OFSCP: this provider, and Postrinch's OFSCP
client. Both need the same byte-exact pieces: canonical actors and
authorities (§2.2), the auth, device-key and discovery payloads (§3.1,
§4.1–§4.7), the `dmId` derivation (§7.4), and request signing (§4.4.2,
§7.1, §8.1). If each writes its own, they can drift apart, and a signature
that one side builds and the other cannot verify fails silently. The
security rules (identity is always `(handle, domain)`, security
requirement 1) would also have to be enforced twice.

These pieces already lived in two places in this repository:
`re-ofscp-types` (identifiers, payloads, `dmId`), mixed with types that
only this provider uses (the admin API, the federation policy, `Health`),
and `re-ofscp-server/src/signing/canonical.rs` (signing), which a client
cannot depend on without pulling in axum, tokio and rhypedb.

## Decision

- A new workspace crate, `crates/ofscp-core` (package `ofscp-core`),
  holds everything that is pure OFSCP protocol: the `actor`, `auth`,
  `discovery`, `dm` and `signing` modules.
- **What belongs in it:** code whose behaviour the spec fixes, that any
  provider or client needs, and that runs without I/O. **What does not:**
  anything needing this server's state or policy: the replay store, the
  clock, key lookup and caching, the federation policy, HTTP header
  parsing tied to a framework, rate limits, and anything re-ofscp-specific
  (admin, `Health`, provider key-id format).
- **Constraints**, enforced by CI: no tokio, no I/O, no clock reads (time
  is passed in), no `unwrap`/`expect`/panics outside tests, and it builds
  for `wasm32-unknown-unknown`. The dependencies are few and pinned in the
  workspace: serde, sha2, base64, ed25519-dalek and thiserror. It
  re-exports `SigningKey` and `VerifyingKey` so consumers use the same
  ed25519-dalek it was built against.
- **Errors are typed.** `IdentError` (actor and authority parsing) and
  `PublicKeyError` (base64 key decoding: bad base64, wrong length, not a
  curve point) are thiserror enums. There is no conversion that loses an
  actor's domain.
- **Vectors.** `crates/ofscp-core/tests/vectors.rs` reproduces the spec's
  signing and WebSocket-auth vectors (`tests/signing-vector.json`,
  `tests/ws-signing-vector.json`) and the §7.4 `dmId` example
  (read from `docs/ofscp_spec.md`) byte-for-byte, from the sibling spec
  checkout or `OFSCP_SPEC_DIR`. It fails, and never skips, when the spec is
  missing.
- **Compatibility in this repository.** `re-ofscp-types` re-exports the
  moved modules at their old paths (`re_ofscp_types::actor`, `::auth`,
  `::discovery`, `::dm`, and the root `Actor`, `Authority`, `IdentError`,
  `dm_id`, `is_valid_handle`). The server's `signing::canonical` re-exports
  `ofscp_core::signing`, and `signing::verify::headers` re-exports the
  header names. Existing code compiles unchanged, with one exception:
  `decode_public_key` now returns `Result<VerifyingKey, PublicKeyError>`
  rather than `Option`, and its four call sites were updated.
- **How it changes, and how others use it.** The crate stays in this
  repository. Every change goes through a re-ofscp pull request, with the
  same review and CI as the server. It is not published to crates.io.
  Outside consumers take it as a git dependency pinned to an exact commit
  and bump that pin deliberately (see `crates/ofscp-core/README.md`).

## Consequences

- One implementation of the canonical strings and identifiers. A spec
  change to them is made once, and both the provider and the client get it
  by bumping a pin.
- A change to `ofscp-core` can break a consumer outside this repository.
  Treat its public API as a published interface: breaking changes need a
  reason in the PR and a note for the consumers.
- The admin UI now builds ed25519-dalek, through `re-ofscp-types`. It is
  wasm-safe and the unused code is dropped at link time.
- Candidates for a later move, once a second consumer needs them: the
  RFC 3339 timestamp skew check (it would take `now` as an argument), the
  `Signer` enum (actor or provider) and the framework-free part of
  signing-header parsing. They stay in the server for now because they are
  tied to its replay-store and HTTP types.
