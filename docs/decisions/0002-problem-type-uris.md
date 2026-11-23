# 0002: Problem `type` URIs mirror Forumall; `errorCode` is the interop key

- **Status:** accepted. The shared base is pending a Joe and Seth decision.
- **Date:** 2026-11-23
- **Spec:** §2.6, §7.3; [lost-conn/ofscp#17](https://github.com/lost-conn/ofscp/pull/17) (open)

## Context

The spec requires `type` to be a stable https URI, but it names no base and
no list of values. A client that branched on `type` would behave differently
from one provider to the next.

## Decision

These points come from the OFSCP oracle's answer.

- **`errorCode` is the key clients use.** It will be REQUIRED, and it comes
  from a registered snake_case list keyed to the §7.3 status table:
  `bad_request`, `unauthorized`, `forbidden`, `not_found`, `conflict`,
  `payload_too_large`, `too_many_requests`, `internal_error` and
  `service_unavailable`. Clients branch on `status` plus `errorCode`, never
  on `type`. The WebSocket `error` event's `code` uses the same list.
- **`type` is opaque to clients.** We mint `https://ofscp.org/problems/<slug>`,
  the same base Forumall uses (`crates/re-ofscp-server/src/problem.rs`).

## Open question (needs Joe and Seth)

Should `https://ofscp.org/problems/<errorCode>` become the blessed shared base?
That only makes sense if someone owns ofscp.org. Until it's decided we keep
mirroring Forumall. That's harmless, and it already matches if the base is
blessed.
