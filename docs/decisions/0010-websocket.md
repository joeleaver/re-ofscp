# 0010: The WebSocket transport (§7.1)

- **Status:** accepted
- **Date:** 2026-11-26

## Context

§7.1 defines one WebSocket endpoint, `/api/ws`, carrying an
authentication handshake, then commands from the client and events from the
provider. This record covers the transport: the handshake, the envelope
and dispatch, errors and close codes, liveness and limits, subscriptions
and their continuous access checks, revocation, and shutdown. It does not
cover messaging, typing, presence or DMs. Those commands are still
answered `bad_request` (below) until their modules land.

The code is in `crates/re-ofscp-server/src/ws/`, with the signature half of
the handshake in `signing/ws.rs` and remote-key re-confirmation in
`remote_keys/reconfirm.rs`. The pure wire format (the envelope, close
codes, the `error` data and the handshake and subscription message data)
is `ofscp_core::ws`, shared with clients (decision 0011).

## Decisions

### Handshake

- On upgrade the provider sends `auth.challenge {nonce, expiresAt}`. The
  nonce is 24 random bytes in base64url, and `expiresAt` is now plus
  `auth_timeout` (10 s). Anything other than a valid `authenticate` before
  then gets `error`, then close `4001`. A frame over 8 KiB before
  authentication gets `1009`.
- `authenticate` is verified by the same `Verifier` as signed HTTP, under
  the §4.5 rules for the WS-auth canonical string. It uses the same
  provider-wide replay store, under its own surface (`Surface::WsHandshake`),
  namespaced by signer kind. The nonce is checked first and recorded only
  after the signature verifies. The spec's WS-auth vector reproduces
  byte-for-byte (`tests/ws.rs`).
- Identity is `(handle, domain)`. A remote actor's keys come from the
  remote key resolver (decision 0006), with fetches charged to the
  connecting client's address.
- **Federation policy** (§8.5, lost-conn/ofscp#25; decision 0008) is the
  first part of step 6, shared with signed HTTP (`Verifier::check_policy`):
  - a denied provider gets `error forbidden`, then `4001`, with no key
    fetched and no nonce recorded;
  - a policy not loaded yet gets `error service_unavailable`
    (`retryAfter` 5), then `4001`;
  - it is decided again once the connection is registered, just before
    `authenticated`, so a denial installed while the key was resolving
    gets `error forbidden` and `4001`, never an acknowledgement first.
- **A failed handshake always closes `4001`**, and its `error` says why:
  - `unauthorized` for a bad signature or an unknown key;
  - `service_unavailable` with `retryAfter` when keys could not be fetched
    or the replay store is full or warming up (§4.5 step 6 makes these 503,
    not 401);
  - `too_many_requests` for a rate limit.

  `4001` (not `4003`) tells the client its key was not revoked.
- Verification is bounded by `verify_timeout` (20 s), which gives
  `service_unavailable`. Then the per-actor and per-ICANN-group caps apply.
  Over a cap gets `error too_many_requests`, then `1013`.
- A local key revoked while its handshake was verifying is caught by an
  *access epoch*: revocations bump it, and a handshake that saw it change
  re-confirms its key once registered, closing `4003` if it is gone.

### Envelope and dispatch

- Client frames must have an `id` and a `type`; `data` must be an object
  for the commands we implement. `ts` is accepted but not required on
  commands. The oracle confirmed this: `ws/envelope.json` is wrong to
  require it there, and is being split so `ts` is required only on events.
  A command without an `id` gets `error bad_request` (no correlationId),
  or `4001` before authentication.
- **Unknown types are ignored** (§2.3). **Standard §7.1 commands we do not
  implement yet** get `error bad_request` ("unsupported command") with
  `correlationId`, so a client never waits on a reply that will not come.
- A malformed frame gets `error bad_request`, and the connection stays
  open. A binary frame closes with `1003`.
- A second `authenticate` gets `bad_request`.

### Close codes

§7.1 defines only `4001` and `4003`. For everything else we use the
standard codes:

| Code | When |
| --- | --- |
| `4001` | handshake failure; federation denial; a remote key that can no longer be confirmed |
| `4003` | the connection's device key was revoked, or its account was disabled (§4.7) |
| `1000` | heartbeat timeout ("idle"), or the client closed |
| `1001` | provider shutdown |
| `1002` | protocol error |
| `1003` | binary frame |
| `1008` | repeated command-rate abuse |
| `1009` | frame over the size limit |
| `1011` | an access re-check failed (fail closed), or an internal error |
| `1013` | a connection cap, or a slow consumer whose queue overflowed |

Forumall closes idle connections with `4001`, which a client would read as
an authentication failure. We use `1000` instead. The OFSCP oracle
confirmed this table (2026-11-26): `4001`/`4003` only for their table's
reasons, RFC 6455 codes otherwise. It is going into the spec as a SHOULD.

### Liveness and limits

- The provider sends `ping` every 30 s and closes `1000` after 60 s with no
  traffic (§7.1 RECOMMENDED values). It answers a client `ping` with `pong`
  echoing its `id`.
- Messages are capped at 64 KiB by the transport, as they arrive (`1009`
  beyond). The spec sets no limit (§2 only asks providers to define
  one); 64 KiB is far above any §7.1 command, and it is also the most
  buffered for a client that has not authenticated, after which
  anything over 8 KiB closes `1009`.
- Commands go through a token bucket (burst 40, then 20/s). Excess commands
  get `too_many_requests`; a client that keeps going past the burst is
  closed `1008`.
- Connection caps:
  - 10 000 in all;
  - 32 per client address (refused before the upgrade with `429`, or `503`
    when full or shutting down);
  - 16 per actor;
  - 1 000 per remote ICANN registrable group (the decision 0006 grouping);
  - 500 subscriptions per connection (`409 subscription_limit`).
- Each connection has a bounded outbound queue (256). A client that does
  not read is closed `1013`, without the backlog.

### Remote actors' keys (lost-conn/ofscp#20)

A connection holds its key with the lifetime of the answer that produced
it (`signing::Lifetime`). `ws::lease` decides when to re-confirm:

- **`Until(cache_until)`:** re-confirm from halfway to `cache_until` (at
  most 60 s ahead), and every 10 s while unconfirmed. If a completed fetch
  extends the entry, the lease extends with it. If `cache_until` passes
  without one, close `4001`.
- **`Uncached`:** re-confirm every 60 s; the first attempt that does not
  complete closes `4001`.
- **A completed fetch that no longer publishes the key** (dropped, a
  `404`, or the id now naming another key) closes `4003` at once. Failures,
  suppressed fetches and outbound refusals are never treated as revocation.
- **`Unbounded` (local accounts):** never re-confirmed. Revocation is
  pushed instead (below).

A connection wakes when its next attempt or `cache_until` is due, and at
least every 5 s, so an expiry is acted on within a second of it.
Re-confirmation is an expiry-driven fetch. It is single-flight per actor,
charged to the known budget, and not subject to the miss re-fetch interval.

### Federation policy on live connections

Each remote actor's connection selects on
`FederationPolicy::watch().until_denied(domain)` and closes `4001` when it
resolves, at once and whatever its key cache holds (§7.1). A denial
already in force when the connection registers resolves immediately, so a
policy change during the handshake cannot slip through.

### Local revocation

`Accounts` announces each revocation to synchronous `RevocationListener`s;
the WebSocket hub is one. Revoking a device key (including logout,
§4.7.2) closes the connections authenticated with that key with `4003`.
Disabling an account closes all of its connections with `4003`.

### Subscriptions and losing access

- Access goes through the `TopicAuthorizer` seam, which answers *effective
  read access* (security requirement 5). The default, `NoTopics`, answers
  unreadable for everything until the groups module implements it.
- `subscribe` acks `subscribed {channels}` with the readable topics.
  Unreadable ones get one `error not_found`, with `details.channels` and
  the command's `correlationId` (§11.3: indistinguishable from missing).
  An authorizer error gets `service_unavailable` the same way.
- `unsubscribe` acks every requested channel, with no `reason`.
- **Re-checks.** The subsystem that changed access calls
  `Hub::access_changed(Topics | Actor | All)`. A sweep every 5 minutes
  re-checks everything as a backstop. While re-checked, a subscription is
  *held*: events published meanwhile are queued, and they are:
  - delivered if access holds;
  - dropped if it is lost, followed by an unsolicited
    `unsubscribed {reason: "access_revoked"}`.

  An authorizer that cannot answer is retried after 1 s and 2 s, then the
  connection closes `1011`. It fails closed: access can no longer be
  vouched for.
- **Generations.** Each subscription gets a fresh generation when it is
  created, and a check acts only on the generation it checked: a slow
  re-check of a subscription the client has since dropped and made again
  can neither release nor end the new one.
- **Acknowledging.** `subscribe` sends its `subscribed` ack, and any
  replay, under the registry lock, for the granted topics that still
  exist then; their held events follow. A new topic that a re-check ended
  while `subscribe` was checking it is refused (`not_found`) rather than
  acknowledged; an existing one that ended was already told
  `unsubscribed access_revoked`.
- **Resume.** A subscription with `since` cursors is held from the start:
  - the ack names which topics are `truncated`;
  - then the `Timeline` seam's replay events follow;
  - then the held live events.

  A message may arrive twice across a resume, so clients dedupe by message
  id. The default `NoTimeline` truncates every resume, so clients backfill
  through REST history.

### Presence

The hub is the default `privacy::Liveness`: an actor is connected while it
has at least one authenticated connection. Profiles derives online/offline
from that (§7.5; decision 0009). Pushing `presence.update` events on
connect and disconnect comes with the presence commands (follow-ups).

### Shutdown

On SIGTERM the hub refuses new upgrades (`503`), closes every connection
with `1001` (flushing each queue first), and waits up to 5 s for them
before the HTTP server finishes its graceful shutdown.

## Follow-ups

- A `TopicAuthorizer` over the groups module's effective read access, and
  `access_changed` calls at its mutation points (joeleaver/re-ofscp#18).
- A `Timeline` over the message log, once messaging lands.
- Messaging, typing, presence (with `presence.update` on connect and
  disconnect) and DM commands, each replacing a
  `bad_request` "unsupported command".
- Cite the oracle's spec PR (close codes, envelope `ts`, `not_found` on
  subscribe) here and in code comments once it is open.
