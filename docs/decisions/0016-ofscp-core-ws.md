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

lost-conn/ofscp#27 (merged; spec main `24af593`) settled the §7.1
envelope. `schemas/v0.1/ws/envelope.json` is now the base every frame
uses, requiring `id`, `type` and `data`. Two direction envelopes build on
it:

- `ws/command-envelope.json` (client→server): `data` must be an object;
  `ts` is optional, and a provider must not reject a command for lacking
  it and must ignore its value. The spec's command samples now leave `ts`
  out, and `ws-command-ts-ignored.sample.json` sends one that is not a
  time.
- `ws/event-envelope.json` (server→client): `ts` is required, an RFC 3339
  time.

`ping` and `pong`, which either party sends, use the base envelope (a
provider includes `ts` on its own). `ping.json` now requires an object
`data`.

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
- **A standard type needs an object `data`.** A frame of a standard type
  whose `data` is missing, `null`, an array or a scalar fails with
  `DecodeError::Data`, before serde sees it (serde would read a struct
  from an array field by field). §7.1 requires an object on every
  standard command, and a provider answers anything else with
  `bad_request`; every event schema requires one too. Before #27 a `ping`
  or `pong` without `data` decoded as empty; it no longer does.
- **`KINDS` track the spec.** `tests/ws_roundtrip.rs` compares
  `Command::KINDS` and `Event::KINDS` with `WsCommandType` and
  `WsEventType` in `schemas/v0.1/ws/types.json`, leaving out only the
  `call.*` events (a later wave).
- **Encoding is strict, decoding is lenient.**
  - `Envelope::encode` always writes `id`, `type`, `ts` and `data`, so every
    frame we send validates against the base, command and event envelopes
    alike. Sending `ts` on a command is harmless, since providers ignore
    it, and it keeps one encoder for both directions (and for `ping` and
    `pong`, which a provider must send with `ts`).
  - The crate reads no clock, so `ts` is the caller's: `encode` fails with
    `EncodeError::MissingTs` when it is `None` rather than inventing a time.
  - A `data` of `null` (only an unknown frame received without `data`, or
    with `null`, can hold one) is written as `{}`. An object is the one form
    valid under every envelope schema: the base envelope requires `data`,
    and the command envelope requires an object.
  - Decoding requires only `id` and `type` in the envelope. A `ts` that is
    missing, `null` or not an RFC 3339 string reads as `None` rather than
    failing the frame, because a provider must ignore a command's `ts`
    whatever it holds. (On an event a bad `ts` is the sender's fault; a
    client reading it as `None` loses nothing it could act on.) A missing
    `data` reads as `null`, which only an unknown type accepts.
  - So an unknown frame round-trips exactly when it carried `ts` and an
    object `data`. One without them is re-sent in the valid form instead.
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
  same JSON, and validates the result against the envelope of its
  direction and the schema of its `type` (with `jsonschema`, a
  dev-dependency only):
  - commands against `envelope.json` and `command-envelope.json`, events
    against `envelope.json` and `event-envelope.json`, and `ping`/`pong`
    (decoded both as a command and as an event) against all three;
  - `ts` is compared only where the sample has a valid one. A command
    sample without one (or with `ws-command-ts-ignored`'s) decodes with
    `ts` = `None` and is encoded with a fixed time; the rest of the frame
    must still match exactly;
  - the spec's invalid `ws-*` frames are checked as well: no `id` is
    `DecodeError::Envelope`, a `data` that is not an object is
    `DecodeError::Data` with the `id` to answer, and an event without `ts`
    is read but cannot be encoded (`MissingTs`). Each must still fail its
    schema, so the validator stays live;
  - listing tests fail when the spec gains a `ws-*` sample or invalid
    frame no list covers.

## The rules of lost-conn/ofscp#27 (merged, spec main `24af593`)

These were first answered by the OFSCP oracle on the open PR; they are
now spec text (§2.3, §7.1 *WebSocket message envelope*, *WebSocket message
types*, *Authentication*).

- **A command's `ts` is optional and ignored.** A provider must not reject
  a command for lacking `ts`, and must ignore its value. We always send
  one; we read any (see the lenient decode above).
- **`data` is required, and an object on every standard command.** A
  re-sent unknown frame passes a non-null `data` through untouched; only
  `null` (or no `data`) becomes `{}`, when `Envelope::encode` writes it.
- **How a provider answers bad frames** (the server, decision 0010, follows
  these; `crates/re-ofscp-server/tests/ws.rs` covers each):
  - a standard command other than `authenticate` whose `data` does not
    match its schema (an object missing, or of the wrong shape): `error`
    `bad_request`, `correlationId` the command's `id`, connection kept;
  - a malformed `authenticate` (its `data` included): `error`
    `unauthorized` (401), then close 4001;
  - a command with no `id`: after sign-in, `bad_request` without a
    `correlationId`; before it, close 4001;
  - a standard command the provider does not implement: `bad_request`
    with `correlationId`; only nonstandard types are ignored (§2.3).
- **A client never replies to an event it cannot read.** A malformed
  known event is a local `DecodeError::Data`, not a frame to answer.

## Consequences

- `Envelope::encode` returns `EncodeError`, not `serde_json::Error`.
- The #27 update changed behaviour, not signatures: `Envelope::decode` now
  refuses a standard type whose `data` is not an object (a `ping` without
  `data` included), and reads a `ts` that is not a time as `None` instead
  of failing with `DecodeError::Envelope`. Postrinch, which pins this
  crate, sees both on its next bump.
- The server's WebSocket handler (decision 0010) still has its own frame
  types; moving it onto `ofscp_core::ws` is separate work.
