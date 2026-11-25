# 0006: Remote key resolution and outbound requests

- **Status:** accepted
- **Date:** 2026-11-25

## Context

A signed request from a remote actor (`alice@remote.example`) or a remote
provider (`X-OFSCP-Provider: remote.example`) can only be verified with keys
fetched from that remote: the user keys endpoint (§4.6) or the provider's
discovery document (`provider.publicKeys`, §8.1). Until now `NoRemoteKeys`
refused every remote signer.

Every such fetch goes to a host named by whoever sent the request, so it is
exactly the server-side request forgery surface of §8 "Outbound requests"
(CLAUDE.md security requirement 3). And every forged request can trigger one,
so fetching must be rate-limited, or this provider becomes an amplifier.

lost-conn/ofscp#19 and lost-conn/ofscp#20 (both merged) settled how the
outcome of a fetch maps to the verifier's answer. "A cached key" always
means a key from an entry that is **still unexpired at the moment it is
used** (#20): an expired entry never stands in for anything.

| Fetch outcome | Verifier answer |
|---|---|
| `200` with a valid list | use it; an empty list or no matching `key_id` → `401` |
| `404` (user keys only; for discovery a `404` is a failure, §8.1) | no key matches → `401` |
| anything else (network error including a name that does not resolve, timeout, `3xx`, `5xx`, `429`, other `4xx`, invalid body) | fetch failure: a matching cached key is used; otherwise `503 service_unavailable`, `Retry-After: 5` |
| re-fetch suppressed by a rate limit | a matching cached key is used; otherwise `503` with `Retry-After` = time until the fetch is allowed |
| our outbound rules refuse the fetch | a matching cached key is used; otherwise `401` |

## Decision

### Outbound HTTP (`src/outbound/`)

One client for every request to a host someone else chose. Later features
(discovery, peer lists, webhooks, push, DM forwarding) reuse it.

- **`https` only.** URLs are built by us from a canonical `Authority`; there is
  no way to ask for `http`.
- **Public addresses only.** A custom DNS resolver resolves the name and
  refuses the request if **any** resolved address is not publicly routable
  unicast; the client then connects only to the addresses it vetted (no
  re-resolution, so no check-then-connect race). A host that is an IP literal
  is never given to a resolver, so it is checked directly: the URL is parsed
  first and `url.host()` inspected, which also catches the WHATWG numeric
  forms (`2130706433`, `0x7f.1`) that the URL parser turns into IPv4.
- **Refused ranges:** loopback, unspecified, private, link-local, shared
  address space (`100.64.0.0/10`), documentation, benchmarking (`198.18.0.0/15`),
  IETF protocol assignments (`192.0.0.0/24`), multicast, broadcast and reserved
  (`240.0.0.0/4`); for IPv6 also unique-local (`fc00::/7`), link-local,
  site-local (`fec0::/10`), documentation (`2001:db8::/32`, `3fff::/20`),
  discard (`100::/64`), ORCHID, multicast, Teredo (`2001::/32`), 6to4
  (`2002::/16`), and anything that embeds an IPv4 address (IPv4-mapped
  `::ffff:0:0/96`, IPv4-compatible `::/96`, NAT64 `64:ff9b::/96` and
  `64:ff9b:1::/48`) is judged by the embedded address. Only `2000::/3` is
  considered global IPv6. Two refinements: within `2000::/3` the whole IETF
  protocol-assignments block `2001::/23` is refused (it holds Teredo,
  benchmarking `2001:2::/48` and both ORCHID ranges, and no OFSCP peer);
  and the local-use NAT64 prefix `64:ff9b:1::/48` (RFC 8215) is refused
  outright, because where its IPv4 address sits depends on the operator's
  prefix length, so it cannot be judged by an embedded address.
- **No redirects.** A `3xx` is a failed request.
- **Bounded:** 10 s total timeout, 5 s connect timeout, response bodies capped
  at 64 KiB (read incrementally; over the cap is a failure, never a
  truncation). No proxy from the environment. At most 64 outbound requests in
  flight process-wide.
- **TLS:** rustls with the bundled Mozilla roots (`webpki-roots`), so the
  trust store does not depend on what the jkbase runtime image ships.
- **Operator exception:** `OUTBOUND_ALLOW_HOSTS` (comma-separated
  authorities, canonicalized; matched as a whole authority, port included)
  skips the address check for those hosts only. Allowed hosts go through a
  second client whose resolver does not vet addresses, so the exception
  cannot leak to another port or host. It is for
  development and private peerings; https and every other rule still apply.
  Tests use it together with a test-only extra root certificate.

### Remote key resolver (`src/remote_keys/`)

Replaces `NoRemoteKeys` behind `ProviderKeys`' `remote` slot.

- **Sources.** A remote actor's keys come from
  `https://{domain}/.well-known/ofscp/users/{handle}/keys`; a remote
  provider's from `https://{authority}/.well-known/ofscp-provider`. Identity
  is the full `(handle, domain)` (security requirement 1).
- **Validation (lost-conn/ofscp#20).** A keys response must parse (`actor`,
  `keys` and an RFC 3339 `cache_until` present), and its `actor`, after
  `Actor::canonicalize`, must equal the actor we asked for. A discovery
  document's `provider.domain`, after `Authority::canonicalize`, must equal
  the authority we fetched, `:port` included when it is not 443; its
  `publicKeys` must be present and non-empty (the schema's `minItems: 1`).
  A value that does not canonicalize is invalid. (Only the domain part of an
  actor is converted; a handle is never lowercased, §2.2.1, so
  `Alice@remote.example` is invalid.) Every entry needs a non-empty `key_id`;
  Ed25519 entries need a valid 32-byte base64 key; entries with another
  `algorithm` are ignored (forward compatibility); a `key_id` that appears
  twice makes the whole document invalid. Anything else is an invalid body,
  so a fetch failure.
- **Caching.** User keys are cached until `min(cache_until, now + 1 h)` (the
  1 h cap bounds revocation latency, §4.7.1); a `cache_until` at or before
  now means the answer is not cached at all. Discovery is cached per
  `Cache-Control: max-age`, capped at 1 h, 5 minutes when there is no
  `max-age`, and not at all for `no-store`, `no-cache` or `max-age=0`. A
  user-keys `404` has no `cache_until`, so its `Cache-Control` decides in the
  same way. `404` and empty lists are cached (a key miss still re-fetches,
  below). An uncacheable answer replaces what was cached. Failures and
  refusals are never cached.
- **Single flight.** Concurrent lookups for the same source wait for one
  fetch and share its result.
- **Re-fetch on a miss (§4.6, #19).** The verifier first resolves normally.
  If the answer came from cache and the key is missing or the signature does
  not verify, it resolves again with `fresh = true`, which re-fetches. An
  answer that already came from a fetch made for this request is final: it
  is not fetched twice.
- **Rate limits.**
  - *Per source:* at most one `fresh` re-fetch per actor (or provider) per
    60 s. Expiry-driven fetches are not held to this; only failure re-fetches
    are, as #19 describes.
  - *Per remote domain:* a token bucket over **every** fetch to that host
    (burst 20, 30 per minute), so a stream of requests naming random handles
    or key ids at one domain cannot make us hammer it.
  - When a limit stops a fetch: an unexpired cached key with that `key_id`
    is still used; otherwise `503` with `Retry-After` until the fetch would
    be allowed.
- **Fetch failure:** an unexpired cached key with that `key_id` is still
  used; otherwise `503` with `Retry-After: 5`. Expiry is re-checked when the
  fallback is used, not when the lookup began: an entry can expire between
  the verifier's cached answer and its fresh call, or while the fetch is in
  flight (#20). Forumall falls back to stale cache; that is a known Forumall
  bug, not copied here.
- **Refused by our own outbound rules** (a non-public address, by IP
  literal or after resolving the name; operator-allowed hosts are never
  refused): the refusal only replaces a fetch (#20). An unexpired cached key
  with that `key_id` is still used; otherwise `401`, never `503`, since
  retrying cannot help. A refusal is never cached: the next time a fetch is
  needed, DNS is resolved again and the rules re-applied. An IP-literal host
  is refused before any rate limit is consulted, so it costs no token and
  never turns into a `503`; a *name* that resolves to a refused address is
  only discovered by a lookup, which does take a token. A name that fails to
  resolve at all (NXDOMAIN, SERVFAIL, timeout) is a network error, so a fetch
  failure (`503`), not a refusal.
- **Bounds:** at most 10 000 cached sources, 10 000 per-source re-fetch
  times and 10 000 fetches in flight; past that, expired entries go first,
  then the oldest (in flight: `503`, `Retry-After: 1`). The per-domain token
  buckets (the existing `RateLimiter`) hold at most 10 000 hosts; when full
  they drop idle buckets and otherwise refuse new hosts (fail closed: `503`,
  `Retry-After: 1`), rather than forget a host that is being limited.

### Verifier and `KeyResolver`

`KeyResolver::resolve` returns whether its answer came from cache, so the
verifier knows when a re-fetch is required. `KeyError` becomes
`Unresolvable` (`401`) and `Unavailable { retry_after }` (`503` with
`Retry-After`); the local account store's failures stay `503`.

## Not in this change

- **Federation allow/deny policy** (§8 Authorization: no outbound request of
  any kind to a denied provider). It needs its own admin surface; until it
  lands every public host is allowed. It belongs in the outbound client, so
  that one check covers every outbound feature.

## Consequences

- Remote users and providers can now authenticate to this provider.
- A remote provider that is down makes its users' requests fail with `503`
  once their cached keys expire, never silently succeed.
