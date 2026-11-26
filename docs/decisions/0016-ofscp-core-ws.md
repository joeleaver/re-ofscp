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
  events (§9) land in `Other` until calls are implemented.
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

## Open question for the OFSCP oracle

Should a sender always include `ts` and `data`, even where #27 lets a
command leave `ts` out, and is `{}` the right `data` for a re-sent unknown
frame that arrived without one? We do both, as the reading valid under
spec main and #27 alike. When #27 merges, its command samples without `ts`
will decode but no longer re-encode byte-for-byte; the roundtrip test
must then compare those leniently (or compare `ts` only when the sample
has one), not drop the check.

## Consequences

- `Envelope::encode` returns `EncodeError`, not `serde_json::Error`.
- The server's WebSocket handler (decision 0010) still has its own frame
  types; moving it onto `ofscp_core::ws` is separate work.
