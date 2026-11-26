# 0012: ofscp-core grows the client side: ids, signing, strict identifiers

- **Status:** accepted
- **Date:** 2026-11-26
- **Builds on:** 0011 (the `ofscp-core` crate)

## Context

Postrinch built a fuller OFSCP core of its own (`postrinch-ofscp`, draft
joeleaver/postrinch#42): typed ids, a client signer, the REST wire types
and the WebSocket frames. Decision 0011 says one implementation of the
protocol should serve both the provider and the client, so that core is
being ported into `ofscp-core` in stacked pull requests:

1. ids and client signing (this record);
2. the REST wire types (`src/wire/`);
3. the WebSocket envelope, commands and events (`src/ws/`).

An independent review of `postrinch-ofscp` (findings 1–9 and three nits)
was addressed in the port, not copied over.

## Decision

- **Ids.** `LocalId` (`^[A-Za-z0-9_-]{1,128}$`), `ObjectUri` (an `https://`
  URL on a valid authority) and `ObjectRef` (either) live in `ids`. `DmId`
  is a typed `dmId` (`derive`, `parse`, serde), and `dm_id` now returns it
  rather than a `String`.
- **Identifiers deserialize strictly.** `Actor`, `Authority`, `ObjectUri`
  and `ObjectRef` refuse a non-canonical spelling when deserialized; the
  serde default never rewrites a value silently. §2.2 lets a receiver
  either refuse or convert, but fields such as a DM's `with` (§7.4) must be
  canonical byte for byte, and a provider has to be able to refuse them.
  Converting is an explicit, per-field opt-in:
  `#[serde(deserialize_with = "ofscp_core::actor::lenient::actor")]` (and
  `lenient::authority`), or `ObjectUri::canonicalize` /
  `Actor::canonicalize` when parsing by hand. (Review finding 3.)
- **Object URIs are checked.** The part after the authority may hold only
  RFC 3986 characters (unreserved, sub-delims, `:@/?#`, and `%` with two hex
  digits), so a space, a control character or an LF is refused. (Finding 8.)
- **Canonical strings refuse line breaks.** `CanonicalRequest::render` and
  `ws_canonical_string` return `Result<String, CanonicalError>` and refuse
  any component containing an LF. Without this, two different inputs could
  share one canonical string, and a signature over one would verify for
  the other. The verifier answers such a request as malformed signing
  headers. (Finding 9.)
- **Client signing reuses the one canonicalizer.** `DeviceKey`
  (`generate(rng)`, `from_seed`, `seed`, `verifying_key`,
  `public_key_base64`), `Signer { actor, key_id, key }` with
  `sign_request(&Request, timestamp, nonce) -> SignedHeaders` and
  `sign_ws_authenticate`, `generate_nonce(rng)` (192 bits, base64url) and
  `signing_timestamp(now)`. They call the existing `CanonicalRequest`,
  `sign` and `content_digest`; there is no second canonicalizer. A
  `DeviceKey`'s `Debug` shows only the public key, and `seed()` returns a
  `Zeroizing<[u8; 32]>` so the copy is wiped when dropped (review nit).
- **Header names stay lowercase.** `SignedHeaders::pairs` uses the
  lowercase `headers` constants: header names are case-insensitive, and
  `http::HeaderName::from_static` accepts only lowercase.
- **Public keys stay strict.** `decode_public_key` accepts only padded
  standard base64 of exactly 32 raw bytes, so an unpadded key and a DER
  `SubjectPublicKeyInfo` are refused (spec #28); both have explicit tests.
- **Randomness and time are passed in.** The RNG is a
  `rand_core::CryptoRngCore` (rand_core 0.6 without default features, the
  version ed25519-dalek 2 uses), so no consumer is forced to pull in
  `getrandom`; only the tests enable it for `OsRng`.
- **One timestamp type: `jiff::Timestamp`.** It is what Postrinch already
  uses, it parses and prints RFC 3339 (§2.5), and it builds for
  `wasm32-unknown-unknown` with `default-features = false` and only
  `alloc` and `serde`. Without `std`, `Timestamp::now()` does not exist, so
  the crate cannot read the clock even by accident. The wire types of the
  next pull request use it for every timestamp field. A timestamp with a
  non-UTC offset re-encodes in UTC (`Z`): same instant, different bytes.
  Every spec sample uses `Z`, so the samples still round-trip exactly.
- **`PROTOCOL_VERSION`** (`"0.1.0"`) lives in the core;
  `re_ofscp_types::OFSCP_VERSION` is defined from it.

## Consequences

- A breaking change for outside consumers of `ofscp-core`: `dm_id`
  returns `DmId`, `render`/`ws_canonical_string` return `Result`, and
  identifiers no longer canonicalize on deserialization. Postrinch, the
  only outside consumer, switches to `ofscp-core` as part of this port.
- A client that wants to accept loose spellings must say so field by
  field, which keeps the provider strict by default.
