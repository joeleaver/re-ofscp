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
- **Global bound:** `REPLAY_CAPACITY`, default 500 000. When the store is
  full the answer is `503` with `Retry-After` (time until the earliest
  expiry). Nothing is evicted early.
- **Quotas:** a global bound alone would let one signer, or one hostile
  remote provider minting actors, fill the store and lock *everyone* out.
  So each signer may hold `REPLAY_PER_SIGNER` live nonces (default 6 000,
  about 10 signed requests/s sustained), and each *remote* signer domain
  `REPLAY_PER_REMOTE_DOMAIN` (default 50 000). Over its share, that signer
  gets `429 too_many_requests` with `Retry-After`, and everyone else carries
  on. Local users aren't grouped by domain, since they all share ours; their
  exposure is bounded by the per-signer cap and by a cap on device keys per
  user (with accounts).
- **Warm-up:** a store that began during second `T0` refuses signed HTTP
  requests timestamped **at or before** `T0 + skew`, with
  `503 service_unavailable` and `Retry-After`. "At" matters: a predecessor
  running in that same second accepted timestamps that also floor to
  `T0 + 300`. The WebSocket handshake is exempt, and callers must name the
  surface (`Surface::SignedRequest` or `Surface::WsHandshake`) so the
  exemption can't be applied by accident.
- **Cheap checks first:** steps 1–4 (headers, host, timestamp, replay) run
  before the body is read (`Verifier::precheck`, then `complete`), so a
  request that fails them costs no buffering.
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
