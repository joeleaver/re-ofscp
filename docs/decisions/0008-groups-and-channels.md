# 0008: Groups, channels and effective read access

- **Status:** accepted
- **Date:** 2026-11-26
- **Spec:** §5.2 (Group), §5.2.1 (per-channel permissions), §5.5 (group and
  channel endpoints), §11, §11.1 (tiers), §11.3 (effective read access),
  §4.5 (anonymous viewers); open spec PR lost-conn/ofscp#26 (anonymous
  readers, hidden channels answered `404`), lost-conn/ofscp#14 (private
  groups are invite-only), lost-conn/ofscp#10 (actor identity); schemas
  `group.json`, `channel.json`, `tiers-response.json`
- **Security requirements:** 1 (identity is `(handle, domain)`),
  5 (effective read access everywhere), 6 (private groups invite-only)

## Context

Groups and channels are the first resources every later surface hangs off:
messages, history, replies, live subscriptions, follows, read markers,
notifications and discovery samples. All of them must apply the same read
rule, and must re-check it when it changes. Membership (§5.7), invites
(§5.6) and guests (§4.8) come later, but the rule must already be right
for them.

## Decisions

### One access module

- `src/groups/access.rs` is the only place that decides group and channel
  access. Its functions are pure: they take the caller's `Standing`
  (outsider, member with a role, or owner) and the group's and channel's
  policies *as they are now*. A surface asks again whenever something
  changes; nothing is cached.
- `Groups::read_group` and `Groups::read_channel` (`src/groups/ops.rs`) are
  the entry points for every surface. They load the rows, work out the
  standing, and apply the rule. Future surfaces call them rather than the
  store.
- **Effective read access (§11.3):** the group's tier must admit the
  caller, the channel's tier must admit the caller, and a channel `view`
  list, when present, must list the caller's role. `public` and
  `discoverable` admit anyone, anonymous viewers included; `private` and
  `group` admit members only. A channel tier can narrow its group's and
  never widen it.
- **`view` narrows (§5.2.1).** Only members hold roles, so a channel with
  `view` is members-only even under a `public` tier. The owner always
  passes.
- **Exact grants.** A permission lists roles exactly; there is no role
  hierarchy, so `manage: ["member"]` takes `manage` away from `admin`.
  Missing canonical actions get the §5.2 defaults (`post: [admin, member]`,
  `moderate: [admin]`, `manage: [admin]`), and the `Group` object carries
  that effective map.
- **Unknown roles fail closed.** A member whose role is neither canonical
  (`owner`, `admin`, `member`, `guest`) nor in the group's `roles`
  catalogue holds no permission.
- **Private groups are invite-only (requirement 6).** `join_gate` returns
  `InviteOnly` for a `private` group whatever its `joinPolicy`, ready for
  §5.7. The stored `joinPolicy` is kept when a group's tier changes to
  `private`, so changing the tier back restores it.

### Continuous re-checks

`Groups` broadcasts an `AccessChange` (group, channel, or one actor's
membership) after every change that can alter access: a group or channel
update or deletion, and adding, re-roling or removing a member. A live
surface (the WebSocket core) subscribes, re-runs `can_read_channel` for
what it holds, and ends a subscription with
`unsubscribed {reason:"access_revoked"}` when the answer turns false. A
receiver that lags must re-check everything it holds.

### Answers (§5.5, lost-conn/ofscp#26)

| Case | Answer |
| --- | --- |
| No such group (or a malformed id) | `404` |
| Group-level route (`GET`/`PATCH`/`DELETE` the group, list or create channels), group the caller cannot read (`private`/`group`, not a member; unsigned included) | `403` |
| Single-channel route (`GET`/`PATCH`/`DELETE`), channel the caller cannot read for any §11.3 reason, its group's tier included | `404`, the same body as a missing channel |
| Channel `PATCH`/`DELETE`: can read the channel but lacks `manage` | `403` |
| Channel `PATCH`/`DELETE`: a `manage` holder whom `view` leaves out | `404` (can't read it) |
| Group `PATCH`, channel create: lacks `manage` | `403` |
| Group `DELETE` by anyone but the owner | `403` |
| Unsigned mutation | `401` |
| Unsigned `GET` | anonymous viewer, never `401` |

The channel answers follow lost-conn/ofscp#26 (Joe's decision, via the
oracle), which is still open; the code cites it where the behaviour
depends on it. A `403` on a channel route would let an outsider tell real
channel ids from made-up ones. Later channel surfaces (history, replies,
subscribe, follows, read markers) get the same `404` by going through
`read_channel`. A channel listing omits
the channels the caller cannot read.

### Identity and signers

- Actors are compared and stored as canonical `handle@domain`
  (requirement 1). `alice@remote` is never the local `alice`: memberships,
  ownership and permission checks all use the full actor.
- Remote actors use every route exactly as local ones do, except group
  creation. `POST /api/groups` accepts local actors only (`403` for a
  remote signer): this provider hosts groups for its own users. That is
  provider policy; the spec does not require it.
- A provider signature reads as an anonymous viewer on `GET` routes and is
  refused (`403`) where a user must act.

### Storage (`schema.rhype`)

- Three types: `Group`, `Channel` and `Membership`. References are string
  columns (`Channel.group_id`, `Membership.group_id`, `Membership.actor`)
  with `@indexed`, not rhypedb links. At the pinned rhypedb commit
  (c73cc88) a link cannot be set inside `create`, and `.link` fails, so
  `@inverse`/`@on_delete` cannot be relied on yet. Cascades are done by
  the server (below). Revisit when rhypedb is bumped.
- `Membership.key` is `"{group_id} {actor}"`, `@unique`, so an actor has at
  most one membership per group without a transaction.
- The owner is `Group.owner`, not a `Membership` row. §5.7 must keep that
  rule: an ownership transfer creates a membership for the former owner
  and removes the new owner's.
- The fields only ever read back as a whole (description, permissions,
  roles, metadata; name, topic, tags, permissions, metadata for channels)
  are one JSON `doc` column. The fields queries filter on are their own
  columns.
- **Optimistic concurrency.** Each row has a `revision`. An update writes
  only where `revision` still matches, and retries from a fresh read (and
  a fresh authorization) up to five times, then answers `409`. Concurrent
  `PATCH`es of different fields both land. A `PATCH` that changes nothing
  writes nothing and keeps `updatedAt`.

### Deletion without transactions

- Deleting a group is two steps. First its `status` becomes `deleting`,
  which hides it from every read at once. Then its channels, memberships
  and row are purged, and an `AccessChange::Group` is announced.
- A sweeper task (`Groups::sweep_forever`, every 300 s, stopped at
  shutdown) finishes any purge a crash interrupted.
- A channel create re-checks that its group still exists after writing,
  and takes the channel back if not. The remaining case: a process dying
  between those two statements while the group is being deleted can leave
  an unreachable channel row. Nothing can read it (every read goes through
  an active group), and it costs one row.

### Limits

| Limit | Value |
| --- | --- |
| Groups per owner | 100 |
| Channels per group | 200 |
| Name | 100 characters, one line, not blank |
| Description | 2000 characters |
| Topic | 1000 characters |
| Tags | 16 per channel, 64 characters each, unique |
| Permission map | 32 actions, 32 roles per action, 64-character names |
| Role catalogue | 32 roles, unique names |
| Metadata | 16 objects, 16 KiB serialized; `schema` must be `https://`, `version` non-empty, `data` present |
| Path ids | `[A-Za-z0-9_-]{1,128}`, otherwise `404` |

Count limits are checked before a write and again after it, and a create
that finds itself over the limit takes back what it wrote. Concurrent
creates therefore never leave more than the limit, though a burst at the
limit may all be refused. A channel listing fetches up to twice the limit,
so channels about to be taken back cannot crowd real ones out.

### Requests

- A request field set to `null` is refused (`400`); absent means "leave
  as is" (`PATCH`) or "use the default" (create).
- Unknown request fields, `owner` included, are ignored (§2.3).
- A channel's `type` is required on create. A `PATCH` may repeat it but
  not change it (`400`).
- Defaults: a group is `private` with `joinPolicy: invite`; a channel is
  `private` (the spec's RECOMMENDED default).

### Tiers (§11.1)

`GET /api/tiers` lists the four canonical tiers with a name and
description, and discovery's `capabilities.tiers` lists their ids.

## Follow-ups

- An admin-console (read-only) group list. It needs admin API routes and
  admin-web pages, and fits the next admin-console unit.
- §5.7 membership, §5.6 invites and §4.8 guests, using the seams above:
  `Groups::add_member` / `set_role` / `remove_member` (each already
  announces its change) and `access::join_gate`.
- Switch the references to rhypedb links with `@on_delete(cascade)` once
  the pinned rhypedb supports linking on create.
