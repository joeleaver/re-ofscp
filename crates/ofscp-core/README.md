# ofscp-core

The shared protocol core of [OFSCP](https://github.com/lost-conn/ofscp):
the parts every implementation must get byte-for-byte right, written once.

- `actor`: actors (`handle@domain`) and provider authorities, with the
  canonical forms of spec §2.2. Identity is always the pair
  `(handle, domain)`; nothing here reduces an actor to a bare handle.
- `auth`: registration, login and device-key payloads (§4.1–§4.7).
- `discovery`: the provider discovery document (§3.1, §8.1).
- `dm`: the typed `DmId` and its derivation (§7.4).
- `ids`: local ids, object URIs and refs (§2.2).
- `signing`: the §4.4.2 canonical request string, the content digest, the
  §7.1 WebSocket `authenticate` string, the signing header names, and
  Ed25519 sign/verify; and the client side: `DeviceKey`, `Signer`,
  `generate_nonce` and `signing_timestamp`.

Identifiers deserialize strictly: a non-canonical actor, authority or object
URI is refused. A field where §2.2 allows converting opts in with
`#[serde(deserialize_with = "ofscp_core::actor::lenient::actor")]`.
Timestamps are `jiff::Timestamp`, built without `std` so the crate cannot
read the clock.

The crate does no I/O, starts no async runtime, never reads a clock and
never draws randomness (time and a `rand_core::CryptoRngCore` are passed
in). It builds for `wasm32-unknown-unknown`. Its tests reproduce
the spec's signing, WebSocket-auth and `dmId` vectors byte-for-byte, reading
them from a sibling `../ofscp` checkout (or `OFSCP_SPEC_DIR`).

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

See `docs/decisions/0011-ofscp-core.md` and `0015-ofscp-core-client.md` for why it exists and what belongs
in it.
