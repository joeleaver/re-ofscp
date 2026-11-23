# 0001: In-memory replay store with a startup floor

- **Status:** accepted
- **Date:** 2026-11-23
- **Spec:** §4.5 "Replay store (Normative)", §7.1, §8 "Replay prevention"

## Context

§4.5 requires one provider-wide replay store that covers every signed surface.
It is keyed by *(signer kind, key id, nonce)*. A nonce is recorded only after
the signature verifies, atomically. The store must be bounded, and when it is
full it must fail closed with `503`. Nonces are kept for at least the skew
window (RECOMMENDED ≥600 s).

The spec doesn't say what happens across a restart. A purely in-memory store
forgets every nonce when the process restarts. A request captured just before
a deploy could then be replayed for up to the 300 s skew window afterwards.

## Decision

- **Where it lives:** `crates/re-ofscp-server/src/replay.rs`. It is a
  `HashMap` with an insertion-ordered expiry queue, behind one `Mutex`, so
  re-checking and inserting a nonce is a single atomic step.
- **Retention:** 600 s, twice the 300 s skew. A nonce therefore outlives every
  moment at which its timestamp would still be accepted.
- **Capacity:** `REPLAY_CAPACITY`, default 500 000. When the store is full,
  `record` refuses and the caller answers `503` with `Retry-After`, set to
  the time until the oldest entry expires. Nothing is ever evicted early.
- **Size limits:** key ids and nonces longer than 256 bytes are rejected at
  step 1, so a single entry's memory stays bounded.
- **Startup floor:** the store refuses any signature timestamped before the
  moment it was created. Anything signed before startup may have been
  recorded by the previous process, so the safe answer is to refuse it.

## Consequences

- **Cost of the floor:** right after a deploy, a client whose clock runs *n*
  seconds slow gets `401` for up to *n* seconds (at most 300). Clients
  re-sign and retry with a fresh timestamp, so the effect is brief. We accept
  it rather than accept replays.
- **Single instance only:** this works while re-ofscp runs as one process. If
  we ever scale out, the store has to move somewhere shared (rhypedb or
  similar). The `ReplayStore` API, `check` plus `record`, is the seam to
  replace.
- **Possible spec PR:** §4.5 could say that a store which loses state on
  restart must refuse signatures timestamped before the loss. That is
  implementation guidance rather than wire behaviour, so it's not urgent.
