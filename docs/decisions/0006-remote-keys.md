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
| anything else (network error including a name that does not resolve, timeout, `3xx`, `5xx`, `429`, other `4xx`, invalid body) | fetch failure: a matching cached key is used; otherwise `503 service_unavailable`, `Retry-After: 5` (or longer after a failed re-fetch, below) |
| fetch suppressed by a rate limit or budget | a matching cached key is used; otherwise `503` with `Retry-After` = time until the fetch is allowed |
| fetch not started because the target already has its cap of requests in flight | a matching cached key is used; otherwise `503`, `Retry-After: 5` |
| our outbound rules refuse the fetch, or the host is under a public suffix the PSL does not know | a matching cached key is used; otherwise `401` |

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
  flight process-wide, and at most 4 per target, grouped by registrable
  domain (below). A request over the per-target cap fails at once
  (`OutboundError::Busy`) rather than queueing, so a few hosts that stall
  every response until the timeout cannot hold all 64 slots and starve
  requests to everyone else. A caller that pays for a request (budgets,
  intervals) takes the slot first with `OutboundClient::reserve` and sends
  with `get_reserved`, so a busy target is refused before anything is paid.
- **Target groups.** Wherever the outbound rules count per target, a target
  is its host's **registrable domain** (eTLD+1 by the Public Suffix List, the
  `psl` crate, as the replay store's per-domain quotas already do), port
  dropped. So `victim.example:1` … `victim.example:65535` and
  `{n}.victim.example` behind wildcard DNS are one target. A host with no
  registrable domain (an IP literal, `localhost`, a bare public suffix) is
  its own group.
- **Ports.** Authorities may carry a port (§2.2), so fetches to non-443
  ports stay allowed; the port only never earns a separate limit.
- **TLS:** rustls with the bundled Mozilla roots (`webpki-roots`), so the
  trust store does not depend on what the jkbase runtime image ships.
- **Operator exception:** `OUTBOUND_ALLOW_HOSTS` (comma-separated
  authorities, canonicalized; matched as a whole authority, port included)
  skips the address check for those hosts only. Allowed hosts go through a
  second client whose resolver does not vet addresses, so the exception
  cannot leak to another port or host. The allowed host *names* (any
  port) are also exempt from the resolver's unknown-suffix refusal (below),
  since dev peers live on `localhost` or `*.test`; that exemption grants no
  address exception, and the name is still one target group. It is for
  development and private peerings; https and every other rule still apply.
  Tests use it together with a test-only extra root certificate.

### Remote key resolver (`src/remote_keys/`)

Replaces `NoRemoteKeys` behind `ProviderKeys`' `remote` slot.

- **Sources.** A remote actor's keys come from
  `https://{domain}/.well-known/ofscp/users/{handle}/keys`; a remote
  provider's from `https://{authority}/.well-known/ofscp-provider`. Identity
  is the full `(handle, domain)` (security requirement 1).
- **Validation (lost-conn/ofscp#20).** §4.6: a keys response is valid only
  if it matches the schema, so documents are validated strictly by
  `user-keys-response.json` and `provider-discovery.json`. A keys response
  must parse (`actor`, `keys` and an RFC 3339 `cache_until` present), and
  its `actor`, after
  `Actor::canonicalize`, must equal the actor we asked for. A discovery
  document's `provider.domain`, after `Authority::canonicalize`, must equal
  the authority we fetched, `:port` included when it is not 443; its
  `publicKeys` must be present and non-empty (the schema's `minItems: 1`).
  A value that does not canonicalize is invalid. (Only the domain part of an
  actor is converted; a handle is never lowercased, §2.2.1, so
  `Alice@remote.example` is invalid.) Every entry needs a non-empty `key_id`,
  `algorithm` exactly `"Ed25519"` (the schemas' only value: any other
  algorithm makes the document invalid) and a valid 32-byte base64
  `public_key`. User-key entries also need `created_at` (RFC 3339);
  discovery entries may omit it, but when present it must be an RFC 3339
  string (`null` is not "absent": it is invalid). A
  `key_id` that appears twice makes the whole document invalid. Anything
  else is an invalid body, so a fetch failure.
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
- **Unknown public suffixes.** A host whose public suffix is not on the
  PSL (`n1.zzqq`, `n2.zzqq`, …) is refused before anything else is planned
  or charged. The PSL's implicit `*` rule would make each such name a
  registrable domain, so a target group, of its own: requests naming them
  would each get a fresh per-target budget and fill the budgets' 10 000-key
  tables. Like an outbound refusal it answers `401`, costs no token, and is
  subject to #20 (an unexpired cached key is still used; in practice none
  is ever cached for such a host). IP literals have no suffix and are
  judged by the address rule instead; operator-allowed host names are
  exempt (above). The replay store groups by the same
  `registrable_group`, unchanged: a signer under an unknown suffix can no
  longer get a key verified, so it never reaches the replay store.
- **Rate limits.**
  - *Per source:* at most one `fresh` re-fetch per actor (or provider) per
    60 s. Expiry-driven fetches are not held to this; only failure re-fetches
    are, as #19 describes.
  - *Per target:* token buckets over **every** fetch to that target
    (registrable domain, see "Target groups"), so a stream of requests
    naming random handles, key ids, ports or subdomains at one domain cannot
    make us hammer it. Each target has four buckets, each burst 20, 30 per
    minute:
    - user-key fetches and provider-discovery fetches apart, so spam naming
      random handles at a domain cannot stop us from verifying that
      domain's provider;
    - each of those split into **known** sources and **first-time**
      lookups. A source is known when its last completed fetch returned a
      non-empty key list; it stops being known when a fetch returns an
      empty list or a user-keys `404` (failures and refusals change
      nothing). Only a known source's **expiry-driven** fetch (a lookup
      that is not `fresh` and finds no unexpired cache entry) uses the
      known bucket. Every other fetch uses the first-time bucket: sources
      never fetched or last seen empty or `404`, and **every `fresh`
      re-fetch** (a key miss), whatever the source's standing. Handles are
      public, so anyone can sign as `alice@victim.example` with a bogus
      key id and force a re-fetch for her; charged to the known bucket,
      three or four client addresses naming known users could keep it
      empty, and real users' expiry re-fetches would get `503`. An expiry
      fetch, by contrast, happens at most once per cache lifetime per
      source however often it is named, so no amount of spam can drain
      the known bucket faster than the peer's own documents expire.
      Requests naming random handles or subdomains, or bogus key ids of
      real users, can therefore only empty the first-time bucket: the
      peer's existing users keep verifying until and across expiry.
    - *Cost of keeping misses first-time:* a real user's key rotation is
      seen as a key miss, so its re-fetch competes in the first-time
      bucket. While that bucket is being emptied, a signature by the new
      key gets `503` until a token frees up (the 60 s per-source re-fetch
      interval and the client budget still apply as before), or until the
      cached document expires, when the expiry re-fetch (known bucket)
      brings the new key. Signatures by keys already cached keep working
      throughout. New users of the peer get `503` while the spam lasts
      too. We accept both: the alternative lets anyone who knows a peer's
      user list lock all of them out.
    - *Known sources are bounded per target group* (registrable domain):
      at most **500** per group and **10 000** in all. A group at its
      cap forgets its own source confirmed longest ago; a full table
      forgets the oldest source of the **largest** group (on a tie, the
      group that most recently gained a source, which is the one being
      filled). One domain's provider serving keys for any handle can
      therefore only cycle its own 500 entries, never push out another
      domain's known sources, and a group is only cut back while no other
      group is larger: with *k* groups filled by an attacker, a peer keeps
      its known sources up to 10 000 / (*k* + 1): all of its 500 unless
      the attacker fills 20 or more other registrable domains, each of
      whose 500 sources had to be fetched from the attacker's own client
      and first-time budgets.
      500 is far more sources than the known bucket could re-fetch in a
      short cache lifetime anyway (30 a minute); a peer with more active
      users than that sees its longest-unconfirmed ones charged as
      first-time, which degrades only to the first-time bucket, never to a
      refusal. A forgotten source is first-time until a fetch finds its
      keys again. All operations are O(log n) (per-group ordered maps and
      a ranking of groups by size).
    - *Cached documents are bounded the same way,* and for the same
      reason: with one global table evicting its oldest entry, a provider
      serving keys for any handle could have us cache 10 000 of its own
      documents and push out every peer's, after which each of the peer's
      users' next ordinary lookup costs an expiry fetch from the peer's
      known bucket, and is refused once that bucket is empty: the
      starvation the budgets exist to prevent. The cache holds at most
      **500** documents per target group and **10 000** in all. A group at
      its cap gives up its own expired document if it has one, else its
      own stored longest ago; a full cache gives up an expired document of
      any group if there is one, else the oldest of the largest group (on
      a tie, the one that most recently gained a document). The arithmetic
      is that of the known sources above: a peer keeps its cached
      documents unless an attacker fills 20 or more other registrable
      domains, each through its own client and first-time budgets. Both
      tables share one implementation (`remote_keys/grouped.rs`).
      Eviction only removes a document; it never extends another's life
      (#20), and it never touches the fetches in flight, so lookups keep
      joining a fetch under way whatever the cache holds.
  - *Per client:* a token bucket per client address (the same key as the
    login rate limits: the `CLIENT_IP_HEADER` entry our proxy appends, else
    the TCP peer; IPv6 by /64), burst 10, **10 per minute**. The signature
    layer passes the client to `KeyResolver::resolve` as a `Requester`.
    The rate is a third of a target bucket's refill, so one client can
    never keep any of a peer's buckets empty: at most it borrows ten of a
    burst of twenty, and the bucket refills three times faster than the
    client can spend. (At the earlier 30 per minute, equal to the target
    refill, one IPv4 address or IPv6 /64 could hold a peer's bucket empty
    indefinitely.) Ten fetches a minute is still far above what an honest
    client causes: a request needs at most two fetches (one normal, one
    re-fetch on a miss), and cache hits and joined fetches are free.
  - A fetch is charged to the target's and the client's bucket together,
    or to neither, and only when it is about to start: cache hits and
    lookups that join a fetch already under way cost nothing, and every
    other refusal (unknown suffix, re-fetch interval, in-flight table full,
    target busy) is decided before any bucket is touched. In particular a
    target already at its in-flight cap answers `503` (`Retry-After: 5`, or
    a matching unexpired cached key) without spending a token or starting
    the 60 s re-fetch interval, which would otherwise make the next lookup
    wait a minute for a fetch that never happened.
  - When a limit stops a fetch: an unexpired cached key with that `key_id`
    is still used; otherwise `503` with `Retry-After` until the fetch would
    be allowed.
  - *Trade-off:* the per-client bound is per source address, and the
    client rate (10 a minute) is a third of a target bucket's refill, so
    a handful of addresses (four are enough) can keep a peer's
    first-time buckets empty: new users of that peer, and key rotations
    of its existing users (see above), get `503`s until the spam stops or
    the rotated user's cached document expires. They cannot touch its
    known buckets, which only expiry-driven fetches use. Cached keys keep
    working meanwhile.
  - *What reaches a peer (§8):* the target buckets cap every fetch to one
    registrable domain at 4 × (burst 20 + 30 a minute) = a burst of
    **80** and **120 a minute** (2 a second) at most, all four buckets
    together, whatever the number of clients. Of that, only the two
    first-time buckets (a burst of 40, 60 a minute) can be driven by
    others at will; the known buckets follow the peer's own document
    lifetimes. These are small, cacheable `GET`s, so two a second at
    worst is negligible load for any HTTPS server, and lowering the rates
    would cost legitimate verification first (a busy peer's expiry
    re-fetches, new users arriving in bursts): we keep 20 / 30 per bucket.
- **Fetch failure:** an unexpired cached key with that `key_id` is still
  used; otherwise `503` with `Retry-After: 5`. When the failed fetch was a
  `fresh` re-fetch, it started the 60 s re-fetch interval, and a retry
  before that ends would only be refused by it: the answer is then
  `Retry-After` = max(5, time until the next re-fetch is allowed). Expiry
  is re-checked when the
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
  only discovered by a lookup, which does take tokens. A name that fails to
  resolve at all (NXDOMAIN, SERVFAIL, timeout) is a network error, so a fetch
  failure (`503`), not a refusal.
- **Bounds:** at most 10 000 per-source re-fetch times and 10 000
  fetches in flight; past that, expired re-fetch times go first, then the
  oldest (in flight: `503`, `Retry-After: 1`). Cached documents and known
  sources: at most 500 per target group and 10 000 in all, evicted as
  described under "Per target" (expired documents first, within the full
  group or, for a full cache, anywhere; then the oldest of the full group
  or of the largest group). Each set of token buckets (the existing `RateLimiter`:
  known and first-time user-key targets, known and first-time discovery
  targets, clients) holds at most 10 000 keys; when full it drops idle buckets and
  otherwise refuses new keys (fail closed: `503`, `Retry-After: 1`), rather
  than forget one that is being limited.

### Verifier and `KeyResolver`

`KeyResolver::resolve` returns whether its answer came from cache, so the
verifier knows when a re-fetch is required. It also takes the `Requester`
(the client's rate-limit key) that remote fetches are charged to; the
signature layer (`SignatureLayer`) derives it from the request the way the
login rate limits do. Resolvers that never fetch (`StaticKeys`, the local
account store) ignore it. `KeyError` becomes
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
