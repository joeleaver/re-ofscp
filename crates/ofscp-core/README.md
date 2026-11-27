# ofscp-core

The shared protocol core of [OFSCP](https://github.com/lost-conn/ofscp):
the parts every implementation must get byte-for-byte right, written once.

- `actor`: actors (`handle@domain`) and provider authorities, with the
  canonical forms of spec §2.2. Identity is always the pair
  `(handle, domain)`; nothing here reduces an actor to a bare handle.
- `auth`, `discovery`: the sign-in and discovery payloads (§3.1,
  §4.1–§4.7, §8.1), re-exported from `wire`.
- `dm`: the typed `DmId` and its derivation (§7.4).
- `ids`: local ids, object URIs and refs (§2.2).
- `signing`: the §4.4.2 canonical request string, the content digest, the
  §7.1 WebSocket `authenticate` string, the signing header names, and
  Ed25519 sign/verify; and the client side: `DeviceKey`, `Signer`,
  `generate_nonce` and `signing_timestamp`.
- `wire`: the REST payloads of the whole spec (users, privacy, contacts,
  groups, invites, messages, DMs, follows, read markers, notifications,
  Web Push, discovery, problem details and the `errorCode` registry).
- `ws`: the WebSocket protocol (§7.1): the envelope, the commands a client
  sends, the events a provider sends, and the close codes. An unknown
  `type` is kept as `Other`. Frames are always sent with `ts` and `data`
  (the caller supplies `ts`), and read without them. See
  `docs/decisions/0016-ofscp-core-ws.md`.

Identifiers deserialize strictly: a non-canonical actor, authority or object
URI is refused. A field where §2.2 allows converting opts in with
`#[serde(deserialize_with = "ofscp_core::actor::lenient::actor")]`.
Timestamps are `jiff::Timestamp`, built without `std` so the crate cannot
read the clock.

Wire types ignore unknown fields (§2.3). Enumerations a provider answers
are open: an unknown value is kept in `Other`, and equality goes through
the wire string. Enumerations only a client sends are closed. Optional
fields are left out when `None`. See `docs/decisions/0013-ofscp-core-wire.md`.

The crate does no I/O, starts no async runtime, never reads a clock and
never draws randomness (time and a `rand_core::CryptoRngCore` are passed
in). It builds for `wasm32-unknown-unknown`. Its tests reproduce
the spec's signing, WebSocket-auth and `dmId` vectors byte-for-byte,
round-trip every REST sample, and round-trip every WebSocket sample and
validate the re-encoded frame against the spec's schemas. REST payloads the
spec shows only as a text example (the channel list, the reaction `PUT`
body) are round-tripped from that example and validated against a schema
built from the spec's own definitions. The spec is read from a sibling
`../ofscp` checkout (or `OFSCP_SPEC_DIR`).

## Users

- The [re-ofscp](https://github.com/joeleaver/re-ofscp) provider, in this
  repository.
- Postrinch's OFSCP client.

## Changes and versions

This crate lives in the re-ofscp repository, and every change to it goes
through a re-ofscp pull request, with the same review and CI as the server.
It is not published to crates.io. Consumers outside this repository take it
as a git dependency pinned to an exact commit, and bump that pin
deliberately:

```toml
ofscp-core = { git = "https://github.com/joeleaver/re-ofscp", rev = "<commit>" }
```

See `docs/decisions/0011-ofscp-core.md`, `0015-ofscp-core-client.md`,
`0013-ofscp-core-wire.md` and `0016-ofscp-core-ws.md` for why it exists
and what belongs in it.
