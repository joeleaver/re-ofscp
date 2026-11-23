# re-ofscp

An enterprise-grade server for the [Open Federated Social Communications Protocol (OFSCP)](https://github.com/lost-conn/ofscp), written in Rust.

- **Server:** Rust (axum + tokio), one binary: `re-ofscp`.
- **Database:** [rhypedb](https://github.com/joeleaver/rhypedb), an object database with first-class relationships. The schema is in [`schema.rhype`](schema.rhype).
- **Admin console:** a [rinch](https://github.com/joeleaver/rinch) web app for user management, compiled to WebAssembly with browser-native DOM.
- **Hosting:** [jkbase](https://github.com/joeleaver/jkbase). [`jkbase.toml`](jkbase.toml) deploys the server, a managed rhypedb, and the admin UI under `/admin`.

> **Status:** scaffold. The server answers `GET /api/health`. The protocol and the admin console are not built yet.

## Layout

| Path | What |
| --- | --- |
| `crates/re-ofscp-server` | The OFSCP provider: HTTP API, WebSocket and federation. Builds the `re-ofscp` binary. |
| `crates/re-ofscp-types` | Wire types shared by the server and the admin UI. Contains no I/O, so it also builds for wasm. |
| `admin-web` | The rinch admin UI, built with trunk. Admins sign in with their own accounts, separate from OFSCP users. It isn't a workspace member because it targets wasm32. |
| `schema.rhype` | The rhypedb schema, applied by jkbase on deploy. |
| `jkbase.toml` | The deployment manifest. |

## Develop

The toolchain is pinned in `rust-toolchain.toml` (Rust 1.99.0 with the wasm32 target).

```bash
# Server: build, lint, test
cargo build
cargo clippy --all-targets -- -D warnings
cargo test

# A local rhypedb (from a rhypedb checkout), loaded with this repo's schema
cargo run --release -p rhypedb-server -- --schema ../re-ofscp/schema.rhype --data-dir ./data

# Run the server against it
DOMAIN=localhost:8080 cargo run -p re-ofscp-server

# Admin UI (needs `cargo install trunk`)
cd admin-web && trunk serve
```

## Deploy

```bash
jkbase project create re-ofscp
jkbase secret set DOMAIN=<public host>
jkbase deploy
```

`DOMAIN` must be the public host that clients use, because OFSCP signatures bind to it (§4.4.2).

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
