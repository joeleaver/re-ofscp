# re-ofscp: guidance for agents

re-ofscp is an **enterprise-grade OFSCP provider** written in Rust. It is hosted on jkbase, uses rhypedb as its database, and has a rinch web admin console for user management. It is a from-scratch implementation. It is *not* a port of Forumall.

## Sources of truth

- **The spec:** `~/dev/ofscp`, upstream at `lost-conn/ofscp`. Read `docs/ofscp_spec.md`. The JSON Schemas are in `schemas/v0.1`, and the samples and signing vectors are in `tests/`.
  - **Build against the open spec PRs, not just `main`.** These PRs write down behaviour the reference implementation already settled, and fix gaps in v0.1:
    - [lost-conn/ofscp#11](https://github.com/lost-conn/ofscp/pull/11) covers what Forumall already settled: identifier forms, handle grammar, CORS, the replay store, device-key endpoints, paging, "losing access", the effective-read-access rule, and tiers.
    - [lost-conn/ofscp#12](https://github.com/lost-conn/ofscp/pull/12): security hardening (contacts accept, replay store, outbound SSRF rules).
    - [lost-conn/ofscp#13](https://github.com/lost-conn/ofscp/pull/13): notifications, mentions, Web Push, nicknames, guest upgrade.
    - [lost-conn/ofscp#14](https://github.com/lost-conn/ofscp/pull/14): private groups are invite-only, and read markers use message ids.
    - [lost-conn/ofscp#15](https://github.com/lost-conn/ofscp/pull/15): DMs across devices (`to`, conversation pointers).
  - Where the spec is still ambiguous, choose the conservative, interoperable reading. Write the choice down in `docs/decisions/`, and propose a spec PR rather than diverging silently.
- **Reference implementation:** Forumall, at `~/dev/forumall` (a worktree is at `~/dev/forumall-wt`), upstream `lost-conn/forumall`. It's in Bun/TypeScript. Use it to check wire behaviour and to interoperate-test against. It's a reference, not a template, and it has known bugs; see the security list below.

## Layout

- `crates/re-ofscp-server` is the provider. `lib.rs` holds the router and everything testable; `main.rs` only wires config, logging and shutdown. The binary is `re-ofscp`, and jkbase's Rust buildpack launches it.
- `crates/re-ofscp-types` holds wire types shared with the admin UI. **It must have no I/O and no tokio**, because it also compiles for `wasm32-unknown-unknown`.
- `admin-web` is the rinch admin UI. It is **not** a root-workspace member: it has its own empty `[workspace]` and is built with `trunk`. jkbase builds it with `context = "."` so it can path-depend on `crates/re-ofscp-types`. It is served under `/admin` (`public_url = "/admin/"`).
- `schema.rhype` is the rhypedb schema; jkbase applies it on deploy. `tests/scaffold.rs` parses it with rhypedb's own parser, so a bad schema fails CI rather than the deploy.

## Platform facts (verified while scaffolding)

- **jkbase:**
  - Rust is a first-class server language. The buildpack runs `cargo build --release` and launches the workspace's single binary.
  - `[database]` provisions a managed rhypedb that the app reaches on **loopback**: `127.0.0.1:4201` for the binary protocol (`rhypedb-client`) and `127.0.0.1:4200` for HTTP. Backups and admin tokens are host-managed, so you never handle `RHYPEDB_ADMIN_TOKEN`.
  - The runtime clears the environment, so every env var the server reads is a `jkbase secret`.
  - `DOMAIN` is load-bearing: it must equal the public host, because OFSCP signatures bind the authority (§4.4.2).
  - The design docs are in `~/dev/jkbase/docs`, especially `managed-rhypedb-design.md` and `trunk-static-buildpack-design.md`.
  - **Unverified:** whether the jkbase builder honours `rust-toolchain.toml` (1.99.0 plus the wasm target). Check this on the first deploy.
- **rhypedb:**
  - The client is `rhypedb-client`, with the `async` feature giving `AsyncClient`. It speaks the binary protocol over TCP, and subscriptions are binary-TCP only.
  - Docs are in `~/dev/rhypedb/docs/src`: `schema.md`, `queries.md` and `migrations.md`.
  - `rhypedb-embed` runs an embedded engine. Consider it for fast integration tests, but it pulls in the heavy engine, so keep it a dev-dependency.
  - The relationship directives are `@inverse`, `@on_delete(remove|cascade|deny)`, `@unique` and `@indexed`.
- **rinch:**
  - **Load the `rinch:rinch` skill before writing any admin-web code.**
  - Use `rsx!` only, and wrap every `.get()` in `{|| …}`. Signals are `Copy`. For the web pattern, see `rinch-web::mount` and `~/dev/rinch/examples/ui-zoo-web`.
- **Pinning:** rinch and rhypedb are git dependencies pinned to exact commits, in `Cargo.toml` and `admin-web/Cargo.toml`. Bump them deliberately, in their own PRs. The toolchain is pinned to match rinch (1.99.0).

## Quality bar ("enterprise")

- **Checks:**
  - `cargo fmt`, `cargo clippy --all-targets -- -D warnings` and `cargo test` must pass. CI runs them plus `trunk build`.
  - No `unwrap`/`expect` outside tests and startup.
  - Errors are RFC 7807 problem+json (§2.6).
- **Conformance:**
  - Validate real responses against the spec's own JSON Schemas, referenced from the sibling `../ofscp` checkout. CI should clone `lost-conn/ofscp` beside the repo, as Forumall's CI does.
  - Reproduce the signing, WebSocket-auth and `dmId` vectors byte-for-byte.
  - Track coverage against the spec's §12 checklist, the way Forumall's `CONFORMANCE.md` does.
- **Operations:**
  - Structured JSON logs (`tracing`), `/api/health`, graceful shutdown, and rate limits on auth and federation ingest.
  - An audit log for admin actions.
  - Design schema migrations deliberately, using rhypedb's migrations.
- **Admin console:**
  - Role-based access, with provider admins kept distinct from group roles.
  - Every admin action goes through a server admin API (`/api/admin/*`) and is audited.
  - How the admin UI authenticates is an **open design decision**. One candidate is OFSCP device-key signing in the browser via WebCrypto Ed25519.

## Security requirements (learned from auditing the spec and Forumall)

Each of these was a real bug, or a gap a by-the-letter implementation would ship:

1. **Actor identity is `(handle, domain)`.** Never reduce `alice@remote` to a local `alice` for any lookup, authorization or storage decision (lost-conn/ofscp#10). Local-account endpoints reject remote signers.
2. **Replay store:**
   - Use one provider-wide store across all signed routes *and* the WebSocket handshake.
   - Namespace it by signer kind.
   - Record a nonce only **after** the signature verifies, atomically.
   - Bound the store, and fail closed with 503 when it's full.
3. **Outbound requests** (SSRF): every fetch to a host named by someone else must be https only, and every resolved address must be public. Don't follow redirects. Use timeouts and response-size caps, and rate-limit key re-fetches. This covers keys, discovery, peer lists, webhooks, push and DM forwarding.
4. **Federated contact `accept`** is valid only when `to` holds an *outgoing* pending request.
5. **Effective read access** is the stricter of the group tier and the channel tier, narrowed by `view`. Apply it on *every* surface: list, GET, history, replies, live subscribe, follows, discovery samples and notifications. Re-check it continuously, and end subscriptions with `unsubscribed {reason:"access_revoked"}`.
6. **Private groups are invite-only**, whatever their `joinPolicy`.
7. **Notifications never disclose** a message to someone who can't read the channel. That includes push previews.
8. **Article HTML** must be sanitized, or rendered only through a safe Markdown subset, by every client. Treat remote media URLs as untrusted.
9. **DMs need blocking and consent.** Spec v0.1 has neither, so design them here and propose them upstream.

## Workflow

- Work on a branch, open PRs to `main`, and keep CI green.
- When the work exposes a spec gap, open a spec PR on `lost-conn/ofscp` from the `joeleaver/ofscp` fork. You only have read access upstream.
