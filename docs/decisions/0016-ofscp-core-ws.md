# 0016: The WebSocket frames in `ofscp-core::ws`

- **Status:** accepted
- **Date:** 2026-11-26
- **Builds on:** 0013 (the REST wire types), 0015 (the port plan; this is
  its pull request 3)

## Context

Postrinch's OFSCP session wrote the WebSocket layer (`postrinch-ofscp`'s
`ws`, Postrinch commit a125d35) and adapted it to `ofscp-core::wire`. It
brings the §7.1 envelope, the commands a client sends and the events a
provider sends into the shared core, so that Postrinch and this provider
read and write the same frames.

Spec main (`187acb9`) has `schemas/v0.1/ws/envelope.json` require `id`,
`type`, `ts` and `data` on every frame. lost-conn/ofscp#27 (open) splits it:
a base envelope with `ts` optional, a command envelope (`data` an object,
`ts` optional and ignored by providers) and an event envelope (`ts`
required). `data` stays required in both.

## Decision

- **Shape.** A frame decodes in two steps: `Envelope<T>::decode` reads the
  envelope, then `T: Body` decodes `data` by `type`. `Command` and `Event`
  are built by `ws_body!`, which gives each enum its `KINDS` and `kind()`.
  Close codes are `CLOSE_AUTH_FAILED` (4001) and `CLOSE_REVOKED` (4003).
- **Open, as §2.3 asks.** An unknown `type` decodes as `Other { kind, data }`
  and keeps its data. The payload structs ignore unknown fields. Call
  events (§9) land in `Other` until calls are implemented. An `Other` built
  by hand with a standard kind is sent under that kind and so decodes back
  as its variant, never as `Other`.
- **Every enumerated field is open too.** `TypingState` and `ReactionState`
  are `open_enum!`s, like the REST enums (0013): an unknown `state` is kept
  in `Other`, so a `channel.typing` with a future `"paused"` still decodes
  rather than failing as a whole.
- **A bad `data` keeps its envelope.** `DecodeError::Data` carries the
  frame's `id`, `kind` and `correlationId`, so a provider can answer with
  `error` whose `correlationId` is the command's `id` (§7.1).
- **`KINDS` track the spec.** `tests/ws_roundtrip.rs` compares
  `Command::KINDS` and `Event::KINDS` with `WsCommandType` and
  `WsEventType` in `schemas/v0.1/ws/types.json`, leaving out only the
  `call.*` events (a later wave).
- **Encoding is strict, decoding is lenient.**
  - `Envelope::encode` always writes `id`, `type`, `ts` and `data`, so every
    frame we send validates against spec main's envelope, and also against
    both envelopes of #27 (which tells providers to ignore a command's
    `ts`, so sending it is harmless).
  - The crate reads no clock, so `ts` is the caller's: `encode` fails with
    `EncodeError::MissingTs` when it is `None` rather than inventing a time.
  - A `data` of `null` (only an unknown frame received without `data`, or
    with `null`, can hold one) is written as `{}`. An object is the one form
    valid under every envelope schema, at main and in #27; main also
    allows `null`, but #27's command envelope does not.
  - Decoding requires only `id` and `type`. A missing `ts` reads as `None`
    (legal on commands under #27), and a missing `data` reads as `null`,
    which a standard type decodes as `{}` (`ping` and `pong`).
  - So an unknown frame round-trips exactly when it carried `ts` and an
    object `data`, which is every frame valid at spec main. One without
    them is re-sent in the valid form instead.
- **Fields the schemas leave out.** `Subscribed.truncated` is optional: the
  §7.1 resume prose recommends it, though `subscribed.json` does not list
  it. `Authenticate.timestamp` is the exact signed string, not a parsed
  time, so a re-encoded command still verifies.
- **`message.update`** carries `wire::MessageUpdate` flattened beside its
  ids (lost-conn/ofscp#24, a partial edit). **`groups.updated`** (§5.7)
  requires both `groups` and `removed`, as its schema does.
- **`presence.set`** reuses `wire::PresenceUpdate`, whose `metadata` is now
  an `Option` (see 0013): `ws-presence-set.sample.json` leaves it out
  while `presence-update-request.sample.json` sends `[]`, and both must
  re-encode as they came.
- **Conformance.** `tests/ws_roundtrip.rs` decodes every `ws-*` sample but
  the call signalling as a known command or event, re-encodes it to the
  same JSON, and validates the result against `ws/envelope.json` and the
  schema of its `type` (with `jsonschema`, a dev-dependency only). A
  listing test fails when the spec gains a `ws-*` sample no list covers.

## Answered by the OFSCP oracle (lost-conn/ofscp#27, head 194b3b2)

- **`ts` is always sent.** On commands a provider must not reject a
  missing `ts` and must ignore its value, so our lenient decode stands.
  If #27's command samples leave `ts` out, they decode but no longer
  re-encode byte-for-byte; the roundtrip test must then compare `ts` only
  where the sample has one, not drop the check.
- **The `data` key is always present, and `{}` is always safe.** A re-sent
  unknown frame passes a non-null `data` through untouched; only `null`
  (or no `data`) becomes `{}`. That is what `known_data` does.
- **How a provider answers bad frames** (the server, decision 0010, follows
  these; `tests/ws.rs` covers each):
  - a standard command whose `data` fails its schema: `error`
    `bad_request`, `correlationId` the command's `id`, connection kept;
  - a malformed `authenticate`: `error` `unauthorized` (401), then close
    4001 (the server answered `bad_request` before this change);
  - a command with no `id`: after sign-in, `bad_request` without a
    `correlationId`; before it, close 4001;
  - a standard command the provider does not implement: `bad_request`;
    only nonstandard types are ignored (§2.3).
- **A client never replies to an event it cannot read.** A malformed
  known event is a local `DecodeError::Data`, not a frame to answer.

## Consequences

- `Envelope::encode` returns `EncodeError`, not `serde_json::Error`.
- The server's WebSocket handler (decision 0010) still has its own frame
  types; moving it onto `ofscp_core::ws` is separate work.
