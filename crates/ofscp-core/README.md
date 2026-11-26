# ofscp-core

The shared protocol core of [OFSCP](https://github.com/lost-conn/ofscp):
the parts every implementation must get byte-for-byte right, written once.

- `actor`: actors (`handle@domain`) and provider authorities, with the
  canonical forms of spec §2.2. Identity is always the pair
  `(handle, domain)`; nothing here reduces an actor to a bare handle.
- `auth`: registration, login and device-key payloads (§4.1–§4.7).
- `discovery`: the provider discovery document (§3.1, §8.1).
- `dm`: the `dmId` derivation (§7.4).
- `signing`: the §4.4.2 canonical request string, the content digest, the
  §7.1 WebSocket `authenticate` string, the signing header names, and
  Ed25519 sign/verify.
- `ws`: the §7.1 WebSocket wire format: the message envelope, close
  codes, the §7.3 `error` event, and the handshake and subscription
  message data.

The crate does no I/O, starts no async runtime and never reads a clock (time
is passed in). It builds for `wasm32-unknown-unknown`. Its tests reproduce
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

See `docs/decisions/0011-ofscp-core.md` for why it exists and what belongs
in it.
