# 0006: Remote key resolution and outbound requests

- **Status:** accepted
- **Date:** 2026-11-25; revised 2026-11-25 (target groups by the PSL's
  ICANN section only; a per-/48 client tier)

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
  is its host's **registrable domain**: eTLD+1 by the **ICANN section** of
  the Public Suffix List (the `psl` crate; `crate::registrable`), port
  dropped. The replay store's per-domain quotas use the same grouping
  (0001). So `victim.example:1` … `victim.example:65535` and
  `{n}.victim.example` behind wildcard DNS are one target. A host with no
  registrable domain (an IP literal, `localhost`, a bare public suffix) is
  its own group; under a TLD the PSL does not list, the PSL's default `*`
  rule makes the TLD the suffix (such hosts are refused unless an operator
  allows them, below).
  - *Private-section suffixes are ignored.* The PSL's private section
    lists suffixes such as `workers.dev`, `vercel.app`, `github.io` or
    `duckdns.org`, under which anyone can create names for free, by the
    thousand and from a script. Read as public suffixes, each such name
    would be a target group of its own, and every table and budget kept
    per group would be open to a crowd of free groups: the eviction rule
    below cuts back the *largest* group, so 2 000 small attacker groups
    under `workers.dev` would each be smaller than a real peer's, and the
    peer, as the largest, would give way on every insert, losing its
    cached documents and known sources (then, through its first-time
    bucket, its users' verification). So all of `*.workers.dev` is the one
    group `workers.dev`, and a new group costs a separately registered
    ICANN domain.
  - *Cost:* independent providers hosted under one shared private suffix
    share one group: one per-target budget, one in-flight cap of 4, one
    replay quota, and one share of each table. A provider that wants its
    own needs its own registered domain, which any real deployment has
    anyway. Recorded in 0001 for the replay quota; confirmed by Joe.
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
  below), as *negatives* in a table of their own (see "Per target"). An
  uncacheable answer replaces what was cached. Failures and
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
  is ever cached for such a host). "Known" means known to the PSL's
  **ICANN section**: a name under a private-section suffix is known
  exactly when that suffix sits under a known ICANN suffix
  (`x.workers.dev` is, under `dev`), and then groups under its ICANN
  registrable domain like any other name (see "Target groups"). A private
  rule under an unlisted TLD does not make its names known. IP literals
  have no suffix and are judged by the address rule instead;
  operator-allowed host names are exempt (above). The replay store groups
  by the same `registrable_group`: a signer under an unknown suffix can
  no longer get a key verified, so it never reaches the replay store.
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
    - *Known sources are bounded overall and grouped by target group*
      (registrable domain): at most **10 000** in all, any number of them
      in one group while there is room, so a peer with thousands of
      active users keeps all of them known. A full table forgets a source
      of the **largest** group, the one confirmed longest ago (on a tie,
      the group that most recently gained a source); the inserting group
      gives up its own instead whenever no other group is larger than it,
      so a group is never cut back to make room for one that would then
      be bigger. One domain's provider serving keys for any handle can
      therefore grow only until it is the largest group, then cycles its
      own entries; it never pushes out a smaller domain's known sources.
      With *k* groups filled by an attacker, a peer keeps its known
      sources up to 10 000 / (*k* + 1).
      A forgotten source is first-time until a fetch finds its keys
      again, which degrades only to the first-time bucket, never to a
      refusal. (An earlier revision also capped each group at 500; a
      peer with more active users than that evicted its own users even
      while the table was mostly empty, so the per-group cap was
      dropped.) All operations are O(log n) (per-group ordered maps and a
      ranking of groups by size).
      - *What a group costs.* Each group is a separately registered ICANN
        domain (target groups ignore the PSL's private section, see
        "Target groups"; before that, a group was a free subdomain of
        `workers.dev` and the like, and *k* could be in the thousands at
        no cost). It also takes a provider there serving keys for any
        handle, and one first-time fetch per source it gets in: 10 000
        fetches to fill the table, charged to the attacker's own targets'
        first-time buckets (30 a minute per group, so many groups fill in
        parallel) and to its clients' buckets (10 a minute per IPv4
        address or IPv6 /64, and 50 a minute per IPv6 /48, below). Ten
        registered domains (about 900 fetches each, at 30 a minute) and
        about 35 IPv4 addresses (or 7 IPv6 /48s) could thus bring a peer
        down to about 900 known sources in about half an hour, and keep
        it there by re-confirming their own; more domains fill faster.
        That is the bound we accept: it degrades the peer's evicted users
        to the first-time bucket, never to a refusal by itself, and it
        costs real registrations that can be blocked by name once seen.
    - *Cached documents with keys are bounded the same way,* and for the
      same reason (and with the same cost per group, except that cached
      documents expire within an hour, so an attacker must keep re-fetching
      to hold its share): with one global table evicting its oldest entry, a
      provider serving keys for any handle could have us cache 10 000 of
      its own documents and push out every peer's, after which each of
      the peer's users' next ordinary lookup costs an expiry fetch from
      the peer's known bucket, and is refused once that bucket is empty:
      the starvation the budgets exist to prevent. The cache holds at
      most **10 000** documents, any number of one group while there is
      room. A full cache gives up an expired document of any group if
      there is one (an expired document is never used, #20), else the
      oldest of the largest group as above.
    - *Cached negatives (empty lists and user-keys `404`s) have a table of
      their own:* at most **100** per target group and **2 000** in all.
      Anyone can have us cache a negative for any domain by naming random
      handles at it, each fetch charged to the first-time bucket. Kept in
      the same table as documents, those negatives would fill the victim
      domain's share and each new one would evict one of its real users'
      documents, whose next lookup then costs a known-bucket fetch: the
      starvation above, reopened through the victim's own group. In a
      separate table a negative can only ever displace another negative.
      A group at its cap gives up its own expired negative if it has one,
      else its own oldest; a full table evicts as above. A negative
      pushed out costs at most one first-time fetch for a handle that has
      no keys. A source is in at most one of the two tables: storing a
      document drops its negative and vice versa, and an uncacheable
      answer drops both. Lookups consult both, on the same terms: only an
      unexpired entry is used (#20).
    - All four of the resolver's per-source tables (documents,
      negatives, known sources and the re-fetch times below) share one
      implementation (`remote_keys/grouped.rs`). Eviction only removes an
      entry; it never extends another's life (#20), and it never touches
      the fetches in flight, so lookups keep joining a fetch under way
      whatever the cache holds.
  - *Per client:* a token bucket per client address (the same key as the
    login rate limits: the `CLIENT_IP_HEADER` entry our proxy appends, else
    the TCP peer; IPv6 by /64), burst 10, **10 per minute**. An IPv6 client
    is also charged to a bucket for its **/48**, burst 50, **50 per
    minute** (five clients' worth): a /48 is the usual assignment to one
    site, and holds 65 536 /64s, each a fresh client key, so without it
    one subscriber could spend any number of client budgets. IPv4 clients
    (and IPv4-mapped IPv6) have no network bucket: an IPv4 address is
    already scarce. The `Requester` carries both keys
    (`client::client_keys_by`). The signature
    layer passes the client to `KeyResolver::resolve` as a `Requester`.
    The rate is a third of a target bucket's refill, so one client can
    never keep any of a peer's buckets empty: at most it borrows ten of a
    burst of twenty, and the bucket refills three times faster than the
    client can spend. (At the earlier 30 per minute, equal to the target
    refill, one IPv4 address or IPv6 /64 could hold a peer's bucket empty
    indefinitely.) Ten fetches a minute is still far above what an honest
    client causes: a request needs at most two fetches (one normal, one
    re-fetch on a miss), and cache hits and joined fetches are free.
  - A fetch is charged to the target's, the client's and (for IPv6) the
    client's /48 bucket together, or to none, and only when it is about to
    start: cache hits and lookups that join a fetch already under way cost
    nothing, and every other refusal (unknown suffix, re-fetch interval,
    in-flight table full, target busy) is decided before any bucket is
    touched. In particular a target already at its in-flight cap answers
    `503` (`Retry-After: 5`, or a matching unexpired cached key) without
    spending a token or starting the 60 s re-fetch interval, which would
    otherwise make the next lookup wait a minute for a fetch that never
    happened.
  - When a limit stops a fetch: an unexpired cached key with that `key_id`
    is still used; otherwise `503` with `Retry-After` until the fetch would
    be allowed.
  - *Trade-off:* the per-client bound is per source address, and the client
    rate (10 a minute) is a third of a target bucket's refill, so a handful
    of addresses (four IPv4 addresses, or one IPv6 /48, are enough) can keep
    a peer's first-time buckets empty: new users of that peer, and key
    rotations of its existing users (see above), get `503`s until the spam
    stops or the rotated user's cached document expires. They cannot touch
    its known buckets, which only expiry-driven fetches use. Cached keys
    keep working meanwhile.
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
- **Bounds:** at most 10 000 fetches in flight (past that, `503`,
  `Retry-After: 1`). At most 10 000 per-source re-fetch times, each expiring
  when its 60 s interval ends and grouped by target group like the cache:
  past that, an expired one goes first, then the oldest of the largest group
  (every operation O(log n)). Under a load of many groups' re-fetches, an
  unexpired re-fetch time can be evicted, and its source can then be
  re-fetched sooner than once per 60 s. Each such re-fetch is a `fresh` one,
  so is still charged to the target's first-time bucket (and the client's):
  the load on a peer stays within the first-time buckets' bound (above,
  "What reaches a peer"), whatever the table holds. Cached documents and
  known sources: at most 10 000 each, any number per group while there is
  room; cached negatives: at most 100 per target group and 2 000 in all; all
  evicted as described under "Per target": for negatives, a group at its cap
  gives up its own expired entry, else its own oldest, and only its own
  entries are considered; otherwise a full table gives up an expired entry
  of any group first, then the oldest of the largest group, or of the
  inserting group if none is larger. Each set of token buckets (the existing
  `RateLimiter`: known and first-time user-key targets, known and first-time
  discovery targets, clients, client /48s) holds at most 10 000 keys; when
  full it drops idle buckets and otherwise refuses new keys (fail closed:
  `503`, `Retry-After: 1`), rather than forget one that is being limited.

### Verifier and `KeyResolver`

`KeyResolver::resolve` returns whether its answer came from cache, so the
verifier knows when a re-fetch is required. It also takes the `Requester`
(the client's rate-limit key and, for IPv6, its /48) that remote fetches
are charged to; the
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
