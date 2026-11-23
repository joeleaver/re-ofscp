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
  - **Cost:** if the wall clock jumps *forward* (an NTP step, or a VM
    resuming) and is then corrected, the store's clock stays ahead. Until
    real time catches up, every signed request timestamped before the
    store's clock minus the skew gets `401` Expired. That fails closed, but
    it's an outage, so the store logs a `WARN` once per episode when a
    reading is more than 5 s behind, and an `INFO` when the clock catches
    up. An independent review ran a fuzz test (600 000 random check/record
    operations, with the clock jumping ±650 s) and found no double accept.
- **Host check:** step 2 compares the request's `Host` (never a forwarding
  header) with `DOMAIN`. The spec requires it, but security doesn't depend
  on it, because the canonical string always uses `DOMAIN`. It does assume
  jkbase's proxy passes `Host` through unchanged. **Check this on the first
  deploy:** if every signed request gets `401` with "request authority does
  not match", that's the cause.

## Persistence (the ledger)

The spec says a provider SHOULD persist the store, and we do
(`replay/ledger.rs`, `ReplayNonce` in `schema.rhype`).

- **Write before accepting:** after the in-memory store records a nonce,
  it is written to rhypedb under a `@unique` key, SHA-256 over
  (kind, key-id length, key id, nonce), *before* the request is accepted.
  - A duplicate in the ledger is a replay (`401`).
  - An unreachable ledger fails closed with `503` and `Retry-After: 2`. The
    in-memory entry stays, so the nonce is burned either way, and the client
    re-signs.
- **Startup:** `AppState::restore_replay` reloads every live nonce, in
  pages, and only then ends the warm-up. If the ledger can't be read within
  30 s, the warm-up stays in force. That's safe, and it means one skew
  window of `503`s.
- **Cleanup:** a background task purges expired rows every 60 s, in
  bounded batches (1 000 rows per statement, at most 100 statements per
  run).
- **Purge by the store's clock, and save that clock first.** The purge uses
  the store's never-decreasing clock, and writes it to a `ReplayClock` row
  before deleting anything. At startup, `restore_replay` raises the new
  store's clock to the saved one before restoring.
  - **Why:** without this, a forward clock jump, then a purge, then a
    correction and a restart would bring back a nonce the purge had already
    deleted. The independent review confirmed that sequence, and
    `forward_clock_step_purge_then_restart_still_refuses_the_replay` pins it.
- **Expired rows are replaced in place.** A nonce reused after its window
  (§4.5 allows this) can hit a stale row that hasn't been purged yet.
  - **How:** that row is overwritten with one conditional update, matching
    `key` and `expires_at ≤ store clock`. There's never a moment without a
    row covering the identity; a delete-then-create could lose it to a crash
    or a failed create.
  - **Which clock:** expiries are judged by the store's clock (what
    `record` returns), not a raw wall-clock reading.
- **The clock only goes up.** The persisted clock is raised by a conditional
  update (`high_water < X`), so it can never be lowered.

## Consequences

- **Normal restarts are invisible.** With the ledger reachable at startup,
  nonces survive a restart and signed requests are served at once. The
  warm-up only applies when the ledger can't be read.
- **Each signed request costs one write.** That's a rhypedb write on
  loopback, done after verification, so only authenticated requests pay it.
- **Single instance only.** The in-memory store is still the source of
  atomicity, so this design doesn't extend to several server processes
  sharing one database. Scaling out would make the ledger's `@unique` create
  the atomic step, with the memory store as a cache in front of it.
