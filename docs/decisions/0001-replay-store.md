# 0001: Replay store, and its warm-up after a restart

- **Status:** accepted
- **Date:** 2026-11-23
- **Spec:** §4.5 "Replay store (Normative)", §7.1, §8 "Replay prevention";
  [lost-conn/ofscp#17](https://github.com/lost-conn/ofscp/pull/17) (open)
  adds the restart rule.

## Context

§4.5 requires a single replay store for the whole provider, covering every
signed surface. It is keyed by *(signer kind, key id, nonce)*. A nonce is
recorded only after its signature verifies, and the check-then-record step
must be atomic. The store must be bounded and must fail closed with `503`
when full. Nonces are kept for at least the skew window (RECOMMENDED ≥600 s).

An in-memory store forgets every nonce when the process restarts. Step 3
accepts timestamps up to 300 s *ahead* of local time. So a request recorded
just before a restart can carry a timestamp as late as 300 s *after* it, and
could be replayed during that time. (An earlier version of this record
refused only timestamps before startup. That left exactly this gap, which
the oracle's independent review caught.)

## Decision

- **Where it lives:** `crates/re-ofscp-server/src/replay.rs`. It is a
  `HashMap` plus an insertion-ordered expiry queue, behind one `Mutex`, so
  re-checking and recording a nonce is a single atomic step.
- **Retention:** 600 s, twice the 300 s skew. A nonce therefore outlives
  every moment its timestamp could still be accepted.
- **Capacity:** `REPLAY_CAPACITY`, default 500 000. When full, the server
  answers `503` with `Retry-After` set to when the oldest entry expires.
  Nothing is evicted early.
- **Size limits:** key ids and nonces longer than 256 bytes are rejected at
  step 1.
- **Warm-up:** a store that began at `T0` refuses every signed HTTP request
  timestamped before `T0 + 300`. The answer is `503 service_unavailable` with
  `Retry-After` (seconds until `T0 + 300`), not `401`: the request may be
  perfectly genuine, and the client should simply retry.
- **WebSocket exemption:** the `authenticate` handshake is exempt from the
  warm-up. Its nonce is a challenge the server issued for one connection,
  and it cannot outlive a restart. Callers must say which surface they are
  checking (`Surface::SignedRequest` or `Surface::WsHandshake`), so the
  exemption can't be applied by accident.

## Consequences

- **Every restart costs about five minutes.** For roughly 300 s after each
  start or deploy, signed requests get `503` and clients back off and retry.
  That's spec-conformant, but not good enough for an enterprise deployment.
- **Persistence comes with the rhypedb layer.** The spec says a provider
  SHOULD persist the store instead, and doing so removes the warm-up. The
  rhypedb data layer arrives with device keys (the next PR). At that point
  the store becomes write-through to rhypedb: a nonce is persisted before
  the request is accepted, and unexpired entries are reloaded at startup.
  The warm-up then applies only if the reload fails. `check` plus `record`
  is the seam that stays the same.
- **Single instance only:** persistence in rhypedb is also what would allow
  more than one server process later.
