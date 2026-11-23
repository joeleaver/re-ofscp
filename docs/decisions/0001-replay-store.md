# 0001: Replay store: expiry, quotas and warm-up after a restart

- **Status:** accepted
- **Date:** 2026-11-23
- **Spec:** §4.5 "Replay store (Normative)" and "Restarts", §7.1,
  §8 "Replay prevention". The restart and retention rules arrived in
  [lost-conn/ofscp#17](https://github.com/lost-conn/ofscp/pull/17) (merged).

## Context

§4.5 requires one replay store for the whole provider, covering every signed
surface:
- Entries are keyed by *(signer kind, key id, nonce)*.
- A nonce is recorded only after its signature verifies, by an atomic
  re-check and insert.
- Each nonce is kept until its `X-OFSCP-Timestamp` plus the skew window has
  passed.
- The store is bounded and fails closed with `503` when full.
- A store that doesn't persist must refuse signatures timestamped before
  `T0 + skew` (where `T0` is when the store began), with `503` and
  `Retry-After`. The WebSocket `authenticate` handshake is exempt.

## Decision

- **Implementation:** `crates/re-ofscp-server/src/replay/`. A `HashMap` of
  entries plus a min-heap of expiries, behind one `Mutex`, so re-checking and
  recording a nonce is a single atomic step. Key ids and nonces longer than
  256 bytes are refused at step 1.
- **Exact expiry:** a nonce expires at `signed_at + skew + 1`, one second
  after its timestamp stops being acceptable (step 3 accepts
  `now ≤ signed_at + skew`). An earlier flat rule, "600 s after receipt",
  dropped the nonce in the very second a timestamp 300 s ahead was still
  valid. The independent review found that bug, and a test now pins the
  boundary.
- **Pools:** local signers (actors of this provider) and remote signers fill
  two separate pools, `REPLAY_LOCAL_TOTAL` and `REPLAY_REMOTE_TOTAL` (default
  250 000 each). A full pool answers `503` with `Retry-After` (time until
  that pool's earliest expiry), but only for its own side, so remote traffic
  can never lock out local users, or vice versa. Nothing is evicted early.
- **Quotas:** each signer may hold `REPLAY_PER_SIGNER` live nonces (default
  6 000, about 10 signed requests/s sustained). Remote signers are also
  grouped by **registrable domain**, using the Public Suffix List with the
  port ignored and IP literals grouped by address. Each group may hold
  `REPLAY_PER_REMOTE_DOMAIN` (default 25 000). Over a quota, that signer or
  group gets `429 too_many_requests`, and `Retry-After` points to the latest
  of the earliest expiries among the quotas that refused.
  - Without registrable-domain grouping, one provider could use
    `a.evil.example`, `b.evil.example:8443` and so on as unlimited separate
    domains.
  - **Private suffixes count as separate domains.** The PSL includes its
    private section, so `alice.github.io` and `bob.duckdns.org` are each
    their own group. We keep that on purpose: independent OFSCP providers
    hosted under a shared suffix shouldn't share one quota. The cost is
    that free subdomains under such suffixes are cheap to obtain. About ten
    of them (each serving valid keys and signing validly) could fill the
    remote pool. Even then, the pools keep local users unaffected.
  - Filling the local pool takes about 40 local accounts at full rate. The
    defence there is rate-limited account creation, which is a requirement
    for the accounts PR.
- **Warm-up:** a store that began during second `T0` refuses signed HTTP
  requests timestamped **at or before** `T0 + skew`, with
  `503 service_unavailable` and `Retry-After`. "At" matters: a predecessor
  running in that same second accepted timestamps that also floor to
  `T0 + 300`. The WebSocket handshake is exempt, and callers must name the
  surface (`Surface::SignedRequest` or `Surface::WsHandshake`) so the
  exemption can't be applied by accident.
- **Cheap checks first:** steps 1–4 (headers, host, timestamp, replay) run
  before the body is read (`Verifier::precheck`, then `complete`), so a
  request that fails them costs no buffering. A signed body must arrive
  within 30 s (`408 request_timeout` otherwise).
- **One clock that never runs backwards:** the store keeps a high-water
  mark of every "now" it has been given, and makes each decision under its
  lock with `max(now, high_water)`: sweeping, a freshness re-check
  (`signed_at + skew ≥ now`, else `401`) and recording. `complete` also
  hands the store a fresh clock reading rather than the precheck's.
  - **Why:** two reviews found variants of the same race. A copy of a
    request with an older clock reading (from before its body arrived, or
    read just before it queued for the lock) could sweep less than a fresher
    caller already had. It would then miss its sibling's expired entry and
    record the same nonce a second time. An NTP step backwards had the same
    effect.
  - **Tests:** `slow_copy_cannot_record_with_a_stale_clock`,
    `a_stale_reading_cannot_resurrect_a_swept_nonce` and
    `a_wall_clock_stepped_back_does_not_reopen_nonces`.
  - **Cost:** if the clock steps *forward* and then back, timestamps valid
    on the corrected clock may be refused as expired until it catches up.
    That fails closed.
- **Host check:** step 2 compares the request's `Host` (never a forwarding
  header) with `DOMAIN`. The spec requires it, but security doesn't depend
  on it, because the canonical string always uses `DOMAIN`. It does assume
  jkbase's proxy passes `Host` through unchanged. **Check this on the first
  deploy:** if every signed request gets `401` with "request authority does
  not match", that's the cause.

## Consequences

- **The warm-up costs about five minutes per restart.** For roughly 300 s
  after each start or deploy, signed requests get `503` and clients re-sign
  and retry. That's conformant, but not good enough for an enterprise
  deployment.
- **Persistence comes next.** The spec says a provider SHOULD persist the
  store, which removes the warm-up. The rhypedb data layer is the next PR,
  and with it the store becomes write-through: each nonce is created in
  rhypedb, under a `@unique` key, before the request is accepted, and
  unexpired entries are reloaded at startup. The warm-up then applies only
  if that reload fails. `check` plus `record` is the seam that stays the
  same.
- **Single instance only:** persistence in rhypedb is also what would let
  more than one server process share the store.
