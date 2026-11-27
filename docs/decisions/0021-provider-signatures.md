# 0021: Provider-signed requests are refused on every route

- **Status:** accepted
- **Date:** 2026-11-27
- **Spec:** lost-conn/ofscp#42 (merged at spec `main` 8ffa97b): §4.5
  *Anonymous viewers* and *Restarts*, §5.5, §8 *Authorization*, §8.1, the
  §11 `401` row, the §12 checklist
- **Supersedes in part:** 0006 (provider discovery-key fetching), 0007
  (verifying our own provider signatures), 0008 (where the policy check
  sits for provider signers)

## Context

Until now a provider-signed request (`X-OFSCP-Provider`) was verified like
an actor's: the provider's key came from its discovery document
(`provider.publicKeys`) or, for this provider, from the key held in
memory. A verified provider then read public data as a viewer of its own
(`Viewer::Provider`), and every action route refused it with `403`.

lost-conn/ofscp#42 settles that a provider signature is accepted only on
a route that defines provider signers (§8.1), and v0.1 defines them only
on §10 receiving routes. A route that defines only user signatures does
not perform §8.1 step 2 and answers `401 unauthorized`.

**This provider has no §10 receiving route.** The router serves no
notification delivery, push or webhook endpoint. So no route here accepts
provider signatures, and the provider-verification path was dead weight
and attack surface.

## Decision

A provider-signed request is answered as follows, on every OFSCP route
(discovery, user keys and `/problems/*` included, since the signature
middleware covers them all):

1. **§4.5 steps 1–5 run first.** A missing or malformed header, a stale
   timestamp, or a bad digest gets the answer it always got (`401`/`400`).
2. **Step 4 (replay) is skipped for provider signers.** The nonce is never
   recorded (step 7 never runs), so checking it would only expose the
   warm-up `503` to a request whose signature will never be verified.
   §4.5 *Restarts*: the `503` is only for signatures that would actually
   be verified, so a provider signer gets its `401` or `403` during the
   warm-up too.
3. **The §8 deny check**, at the point §8.1 step 2 would begin: a denied
   provider gets `403 forbidden`.
4. **Otherwise `401 unauthorized`**, detail "this route does not accept
   provider signatures" (`VerifyError::ProviderSignature`). No discovery
   fetch, no signature check, no nonce recorded.

A provider signature is never an anonymous viewer: a public read that
would serve an unsigned request still gets `401` when provider-signed
(§4.5 *Anonymous viewers*, §5.5).

Two existing behaviours of the policy check carry over unchanged:

- **This provider's own authority** is always permitted by the policy, so
  a request signed as this provider gets `401`, not `403`.
- **An unknown policy** (not yet loaded) still answers `503` for a remote
  provider signer, as for an actor signer (0008). The policy must be known
  to tell `403` from `401`; answering `401` instead would tell a denied
  provider something the policy has not decided.

## What was removed

- Provider key resolution: `KeyResolver::resolve`/`reconfirm` take an
  `&Actor`; `Verified.actor` is an `Actor`, and `Authenticated::actor()`
  is infallible.
- The discovery-document key parser and the provider fetch budgets in
  `remote_keys` (`Source` is now an actor's user-keys endpoint only).
- `ProviderKeys`'s own-provider key set, and `Viewer::Provider` in
  `privacy`/`groups`.

ofscp-core's public API is unchanged: `Signer` (the header claim), the
signing primitives and the discovery wire types stay, since clients and
a future §10 route need them. When a §10 receiving route lands, it adds
provider verification back for that route alone.

## Conformance tracking

The repo has no conformance checklist (no `CONFORMANCE.md`) to update. The
§12 lines this change satisfies are covered by
`crates/re-ofscp-server/tests/provider_signers.rs`.
