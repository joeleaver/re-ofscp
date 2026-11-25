# 0007: Discovery document, provider signing key, and CORS

- **Status:** accepted
- **Date:** 2026-11-25
- **Spec:** §3.1 (discovery), §3.4 (CORS, settled in lost-conn/ofscp#11),
  §4.1.1 (registration modes, lost-conn/ofscp#18), §8.1 (provider signing
  identity); schema `schemas/v0.1/provider-discovery.json`

## Context

Forumall's browser client (served from `lostconnection.dev`) signs
requests to other providers and sends them cross-origin. Without CORS the
browser's preflight to us got `405`, so no signed cross-provider request
from it could reach us. Discovery (`/.well-known/ofscp-provider`) was also
missing; peers need it to check our identity, our registration mode, and
our provider signing keys.

## Decisions

### CORS (§3.4)

- One middleware (`src/cors.rs`), installed outside problem rendering and
  signature verification. It applies to every `/api/…` path except the
  admin API, and to every `/.well-known/ofscp…` path, whether or not a
  route exists there (a `404` from a cross-origin caller is still readable).
- A **preflight** (`OPTIONS` with `Origin` and
  `Access-Control-Request-Method`) is answered `204` before routing, with
  the spec's method and header lists, `Access-Control-Max-Age: 600`, and
  the response headers below. The requested method and headers are not
  checked: the browser compares them against the lists. `OPTIONS` without
  `Access-Control-Request-Method` is not a preflight and is routed as usual
  (`405`).
- **Every response** to a request with `Origin` on those paths, problems
  included, carries `Access-Control-Allow-Origin: *`,
  `Access-Control-Expose-Headers` (the allow list plus `retry-after` and
  `etag`) and `Vary: Origin`. `Access-Control-Allow-Credentials` is never
  sent.
- Responses to requests **without** `Origin` on those paths still carry
  `Vary: Origin`, so a shared cache (discovery is `public`) never serves a
  header-less copy to a browser.
- **Not applied** to `/api/admin` and `/api/admin/…` (matched by whole path
  segment, so `/api/administrators` is still an OFSCP path) or to `/admin`.
  The admin console uses a `SameSite=Strict` session cookie plus CSRF
  protection and stays same-origin (0005). A cross-origin preflight to it
  gets no `204` and no CORS headers, so browsers refuse the request.
  §3.4 literally says "every `/api/…`" endpoint. We read it with §3.2
  ("additional, non-standard endpoints … are out of scope"): the MUST
  covers the endpoints the spec defines, not a provider's own
  cookie-authenticated administration. This was raised with the OFSCP
  oracle (2026-11-25) as a spec clarification; if the spec settles the
  other way, the admin API moves off `/api/` rather than gaining CORS.

### Provider signing key (§8.1)

The schema requires `provider.publicKeys` with at least one entry
(`minItems: 1`), and §8.1 says every provider **MUST** publish one or more
Ed25519 signing keys. An empty list would make our discovery document
invalid for every reader, so we publish a real key.

- **Where it lives:** the `PROVIDER_SIGNING_KEY` secret, a 32-byte Ed25519
  seed in base64 (the same encoding as `ADMIN_SECRET_KEY`). It is
  **required**: the server refuses to start without a valid key. A secret
  keeps the private key out of the database and its backups. Forumall's
  approach, generating a key on first boot and storing it in the database,
  needs no operator step, but the private key then travels with every
  backup.
- **Key id:** `psk-` + unpadded base64url of the first 16 bytes of the
  SHA-256 of the public key. The same secret always publishes the same id,
  and a new secret always publishes a new one, so no second setting can
  drift out of step with the key.
- **`created_at`** is omitted (it is optional and the server cannot know
  when the secret was generated).
- **Our own signatures:** a provider-signed request naming this provider
  (`X-OFSCP-Provider` = `DOMAIN`) is verified against the published keys
  held in memory (`ProviderKey::published`, passed to the account
  resolver), never by fetching our own discovery document. An unknown key
  id is `401`.
- **Rotation (planned, not built):** nothing signs with the key yet, so
  replacing the secret is safe today. Once we send provider-signed requests
  (webhooks, §10), rotation becomes a window:
  1. Add an optional `PROVIDER_SIGNING_KEY_PREVIOUS` (a seed, like the
     current key). Its public half is published in `provider.publicKeys`
     after the current key and accepted by our own-signature check;
     outbound requests are signed with the current key only.
  2. To rotate: move the current seed to `PROVIDER_SIGNING_KEY_PREVIOUS`,
     set a new `PROVIDER_SIGNING_KEY`, deploy.
  3. Peers that cached the old document re-fetch on the unknown key id
     (§8.1). Any request signed with the old key and still in flight or
     queued for retry still verifies, because the old key is still
     published.
  4. After the longest retry horizon of anything signed with the old key
     (at least discovery's `max-age`, 300 s, plus the 300 s skew window),
     remove `PROVIDER_SIGNING_KEY_PREVIOUS` and deploy.

  `ProviderKey::published` already returns a list, so step 1 only adds an
  entry to it and to the discovery document.

### Discovery document (§3.1)

- Built from configuration and serialized **once at startup**; a strong
  `ETag` is the base64url of the first 16 bytes of the body's SHA-256.
  `If-None-Match` (weak comparison, lists and `*` honoured) gets `304`.
- `Cache-Control: public, max-age=300, must-revalidate`, as Forumall.
- `provider.domain` is the canonical authority from `DOMAIN`.
- `authentication.registration` is our mode (`invite` or `closed`, 0004).
  A closed provider omits `registration_endpoint` (§4.1.1 SHOULD).
- `contact` is required by the schema: `PROVIDER_CONTACT`, defaulting to
  `mailto:admin@{host of DOMAIN}`.
- `capabilities` states only what is implemented today: no message types
  and no tiers yet (empty lists, not omitted, so readers do not assume
  defaults), `federation.realtimeDelivery: "none"` (no WebSocket yet), and
  both optional discovery features `false`. Each grows as its feature
  lands. The deprecated `endpoints` section is not sent.
- The wire types live in `re-ofscp-types::discovery`, so reading remote
  discovery documents (§8.1 provider-signed verification) can reuse them.
