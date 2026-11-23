# 0003: The rhypedb data layer

- **Status:** accepted
- **Date:** 2026-11-23

## Context

rhypedb is reached over its binary protocol (`rhypedb-client`, `AsyncClient`).
Three facts shape the data layer:

1. **No bind parameters.** Values travel inside the query text, so any value
   that came from a request is an injection risk unless it is escaped
   correctly every single time.
2. **No multi-statement transactions, and no compare-and-set.**
   - **What is atomic:** a `create` on a `@unique` field is an atomic
     "insert if absent", and a violation comes back as
     `engine error: unique constraint violated: Type.field = value`.
   - **What isn't:** a filtered `update` or `delete` doesn't apply its
     condition atomically. The filter selects ids first, then each id is
     written in its own transaction without re-checking the filter, and
     queries run in parallel (`rhypedb-query` executor at c73cc88).
   - **Consequence:** `T.filter(.x <= n).update(...)` can modify, or delete, a
     row that no longer matches by the time it is written. Code that needs a
     real conditional write has to serialize the competing paths itself, or
     rely on a `@unique` create.
3. **One connection serializes its queries,** and after an I/O error the
   client refuses further use (`Closed`). Reconnecting is the caller's job.

## Decision

- **Injection is impossible by construction.** `db::Ql` is the only way to
  build query text.
  - It accepts **static** text (`&'static str`, i.e. written in the source)
    and **typed literals** (`str`, `int`, `uint`, `bool`, `datetime`), which
    it renders and escapes.
  - A runtime string can enter a query only as an escaped literal, never as
    syntax.
  - Strings use rhypedb's two escapes, `\"` and `\\`. Every other character
    is literal inside quotes.
  - `tests/db.rs` round-trips hostile strings through a real server: query
    syntax, quotes, backslashes, newlines and emoji.
- **Errors are classified once.** `DbError` has four kinds:
  - `Unavailable`: connect or I/O failure, and the outcome of a write is
    unknown.
  - `Conflict`: a `@unique` violation, matched on the message's fixed
    *prefix* only (the rest echoes stored values). A test pins it against
    the real server.
  - `Query`: a rejected query, which means a bug.
  - `Decode`: an unexpected result shape or field type.
- **Pool:** `Db` keeps 4 lazily opened connections, used round-robin, with a
  2 s connect timeout and a 10 s query timeout.
  - **Database restarts:** a broken connection, or a failed connect, clears
    the *whole* pool, because a database restart leaves every connection
    stale. A connection idle for 5 s or more is pinged before reuse, so a
    restart while the app was quiet costs no query at all.
  - **Retries:** reads (`fetch`, `one`, `ping`) retry once on a fresh
    connection. Writes (`execute`, `write_one`) never retry after a failure
    mid-exchange, because the caller knows whether repeating one is safe. A
    connection found *already* closed before anything was sent is replaced,
    and the query sent once more, writes included.
  - **Cancellation-safe:** every round trip runs in its own task. A caller
    that is cancelled (a timeout, a disconnected HTTP client) can't abandon
    a half-finished exchange. Otherwise rhypedb-client would mark the
    connection dead and the next genuine write would fail; the independent
    review confirmed that bug, and
    `a_cancelled_query_does_not_poison_the_next_write` pins it.
- **Tests use the real thing.** Integration tests start the actual
  `rhypedb-server`, at the commit `Cargo.toml` pins, with the repository's
  own `schema.rhype`, in a temporary directory on free ports
  (`tests/common/rhypedb.rs`). `scripts/install-rhypedb.sh` installs it, CI
  caches it, and a missing binary fails the tests; it never skips them.

## Consequences

- **One failed write per restart, at most.** A database restart within 5 s
  of a connection's last use can still fail one write with `Unavailable`. It
  then clears the pool. For the replay ledger that means a single `503`, and
  the client re-signs and retries.
- **Prepared statements aren't used.** They take no parameters, and almost
  every query here differs in its literals. If profiling shows hot
  fixed-text queries, `Db` can prepare those per connection without
  changing callers.
