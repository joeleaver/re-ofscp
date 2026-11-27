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
(discovery, user keys, `/problems/*` and the `/api/ws` upgrade included,
since the signature middleware covers them all):

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

### The restart warm-up comes after the deny check for actors too

§4.5 *Restarts* exempts every request "answered without verification",
naming "`403` for a denied signer". An actor signer whose provider the
policy denies is such a request, so the warm-up `503` must not reach it.
The HTTP verifier therefore splits step 4: `precheck` runs the replay
store's `check_unseen` (freshness, replay, quotas and capacity, no
warm-up), and `complete` applies the warm-up gate (`ReplayStore::warm_up`)
only after the digest (step 5) and the §8 deny check, just before the key
is resolved. A denied actor gets `403` during the warm-up, with no key
fetched and no nonce recorded; a bad digest still gets its `400` first
(§8 *Authorization*: "a digest `400` from those steps wins"). Only a
request whose signature will be verified meets the `503`.

The WebSocket `authenticate` handshake needs no reordering: §4.5
*Restarts* exempts it from the warm-up altogether, so its §8 deny check
(`ws_complete`, before any key fetch) answers `forbidden` during the
warm-up as at any other time.

### The WebSocket upgrade is a route like any other

The `/api/ws` upgrade used to sit outside the signature middleware, so an
upgrade carrying `X-OFSCP-Provider` was upgraded instead of refused. §7.1
says the handshake "is **not** signed", which describes the protocol (a
browser cannot set the headers), not an exemption for an upgrade that
does carry them. The spec is explicit that such a request is in scope:

- §4.5 *Anonymous viewers*: "A request that carries **any** `X-OFSCP-*`
  signature header is a signed request, and the checks above apply to it".
- §8 *Authorization*: the inbound policy "applies to every **signed**
  request, on every route", and "No route of this specification accepts
  provider-signed requests, so this applies on every route". `/api/ws` is
  a route of this specification (§7.1).
- "Over WebSocket, the same check applies to the `authenticate` actor"
  adds the in-socket check; it does not take the upgrade request out of
  "every route".

So the upgrade route now sits inside the signature middleware. An
unsigned upgrade passes through untouched and authenticates inside the
socket as before. A provider-signed upgrade gets `403` (denied) or `401`
before any socket is opened; an actor-signed one must verify like any
signed `GET` (a successful verification records its nonce and the socket
then runs the ordinary `authenticate` handshake).

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
