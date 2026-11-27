# 0014: Groups, channels and effective read access

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
update or deletion, and adding, re-roling or removing a member, including
when the write returns an error (it may have committed). A live
surface (the WebSocket core, through `ws::follow_groups`, which
`AppStateBuilder::build` starts, and
`ws::channels::GroupTopics`; decision 0010) subscribes, re-runs
`can_read_channel` for
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
oracle; merged as 7fa0817), which the code cites where the behaviour
depends on it. A `403` on a channel route would let an outsider tell real
channel ids from made-up ones, so every single-channel `404` (missing
group, unreadable group, missing or hidden channel) carries the same body.
Later channel surfaces (history, replies, subscribe, follows, read
markers) get the same `404` by going through `read_channel`. A channel
listing omits the channels the caller cannot read. Authorization comes
before body validation, so a caller without `manage` gets `403` whatever
it sends.

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
  with `@indexed`, not rhypedb links. At rhypedb c73cc88 a link could not
  be set inside `create`, and `.link` failed, so `@inverse`/`@on_delete`
  cannot be relied on yet. The bump to 7b78190 did not touch links (its
  changes are guarded writes, write rules and limited scans), so this
  stands until it is re-probed. Cascades are done by the server (below).
- `Membership.key` is `"{group_id} {actor}"`, `@unique`, so an actor has at
  most one membership per group without a transaction.
- The owner is `Group.owner`, not a `Membership` row. §5.7 keeps that
  rule: an ownership transfer creates a membership for the former owner
  and removes the new owner's (decision 0020, "Ownership transfer"). A membership can never hold the role
  `owner` (`add_member`/`set_role` refuse it, and the access rule grants
  such a row nothing), and the owner is never also a member.
- The fields only ever read back as a whole (description, permissions,
  roles, metadata; name, topic, tags, permissions, metadata for channels)
  are one JSON `doc` column. The fields queries filter on are their own
  columns.
- **Optimistic concurrency.** Each group and channel has a `revision`.
  An edit from revision `n` writes revision `n + 1` only while holding the
  claim on it (next section). It retries from a fresh read (and a fresh
  authorization) up to five times, then answers `409`. Concurrent
  `PATCH`es of different fields both land. A `PATCH` that changes nothing
  writes nothing and keeps `updatedAt`.

### Concurrency without compare-and-set

This section was written against rhypedb c73cc88, where filtered writes
were not compare-and-set: `X.filter(p).update(...)` evaluated `p` on a
snapshot, then wrote each matching object in its own transaction, which
did not re-check `p`. Since rhypedb 7b78190 (#59), pinned here and run by
production's managed server, a guarded write re-checks `p` on each object
inside that object's write transaction and skips objects that no longer
match (decision 0012, "Update"). The claims below stay correct under
that, and are kept until they are simplified in their own change; where
compare-and-set closes a gap they left, that is noted. The rule, per
guard:

- **Revisions: claims.** `GroupClaim` holds `@unique` keys
  `group:{id}:{revision}` and `channel:{id}:{revision}`. A `create` on a
  `@unique` field is atomic (16 concurrent creates of one key leave one
  row), so an edit first claims the revision it will write. It writes only
  if it created the claim; otherwise it backs off (20 ms × attempt) and
  retries from a fresh read. The filter on the old revision stays, to
  refuse a stale read. A claim is a lease of `LEASE_SECS` (120 s),
  stamped with the clock when it is claimed (not the request's time,
  which earlier attempts may have aged). Its holder writes once, right
  away, in one statement that is never retried; a write that loses a
  conflict wrote nothing, and the edit starts over. A holder whose write
  wrote nothing first releases its claim (deleting the row with that key
  and its own stamp; decision 0020), so that a retry which reads the same
  revision again does not find its own claim leased and wait it out. A claim that outlived
  its lease unused is taken to belong to a dead writer, and the next edit takes it over (by deleting exactly that
  row, by id, then claiming again; a row already gone is fine). The
  sweeper deletes expired claims. The design assumes that rhypedb applies
  the holder's one statement within the lease. The 10 s data-layer
  timeout does not enforce that: it is only the client socket's
  read/write timeout. It stops the client waiting, but it does not cancel
  the statement on the server. If the server sat on that statement for
  over 120 s, another edit could take the claim over and write the same
  revision, and the late statement would then undo that edit. At c73cc88
  nothing on this side could close that gap. Since 7b78190 the write's
  filter on the old revision is compare-and-set, so a late statement
  finds the revision moved on and writes nothing: the gap is closed.
- **Status guards need no claim.** Every status transition is one-way
  (`pending → active`, `active → deleting`), deletes are final, and no edit
  writes `status`. So a guarded update that runs after its guard stopped
  holding either writes the same thing again or finds the object gone.
  Edits (`PATCH`, `set_role`) never write `status`, so a group being
  deleted stays deleting. Membership roles are last-writer-wins.
- **Expiry vs. activation.** The sweeper's delete of pending rows older
  than `PENDING_TTL` could, in principle, meet a row that was activated
  after the sweeper's snapshot. A writer therefore activates only within
  `ACTIVATE_WITHIN` (300 s) of starting, and otherwise takes its row back
  and answers `409`. An expiry can only meet an activated row if one
  statement stalls for minutes.
- **Single-object writes retry.** A write that touches one object (by a
  `@unique` key) and loses a write-write conflict (`DbError::Contended`),
  or finds that the object it matched was deleted meanwhile
  (`DbError::Vanished`), wrote nothing. `Db::write_one_object` runs it
  again with its filter evaluated afresh. Profiles uses the same helper.
  The one exception is the write under a revision claim, which runs once
  (above).

### Deletion without transactions

- Deleting a group is two steps. First its `status` becomes `deleting`,
  which hides it from every read at once. Then an `AccessChange::Channel`
  is announced for each of its channel rows, and an `AccessChange::Group`
  for the group, before its channels, memberships and row are purged:
  once purged, a receiver could no longer find which channels the group
  had (decision 0010). If the channel rows cannot be read, the purge is
  left to the sweeper.
- A sweeper task (`Groups::sweep_forever`, every 300 s, stopped at
  shutdown) finishes any purge a crash interrupted.
- **No row outlives its group.** A channel or membership is written with
  `status: "pending"`, which every read ignores. Its writer then checks
  that the group is still active, and only then makes the row `active`
  (a conditional update on `pending`). A purge deletes the group's rows
  in either state. So whenever a purge runs relative to a create, either
  the create sees the group gone and takes its row back, or the purge
  deletes the row (pending or active), and the create's activation fails
  cleanly (`404`, or `409` to retry).
- A writer that dies or fails before confirming leaves a pending row. The
  sweeper deletes pending rows older than `PENDING_TTL` (600 s), so they
  never accumulate. A create slower than `ACTIVATE_WITHIN` takes its row
  back and answers `409` (see "Concurrency without compare-and-set").
- A sweeper pass carries on past a failed step (expiry, or one group's
  purge), logging it and leaving it for the next pass.
- `add_member` answers a pending membership (another add in flight, or a
  dead writer's row awaiting expiry) with `409` (retry), never with
  "already a member".

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
that finds itself over the limit takes back what it wrote. (One residual
case: a process that dies between writing a group and rechecking the
owner limit can leave that owner one group over it. The group is real and
usable, so it is not taken back later.) The channel
count includes pending rows, so it errs on the safe side; the group count
includes only active groups, so a deletion frees its place at once. Concurrent
creates therefore never leave more than the limit, though a burst at the
limit may all be refused. A channel listing fetches up to twice the limit,
so channels about to be taken back cannot crowd real ones out.

The channel count is a limited read: `Channel.filter(.group_id ==
g).limit(201)`, one past the limit, which is all the two checks need. A
filter on one indexed field followed by `.limit(N)` is pushed down to an
index scan. On rhypedb c73cc88 that scan stopped after N keys, *deleted
rows included*, so a limited count came back short by the number of
recently deleted channels and let creates past the limit; the count was
read whole instead. rhypedb 7b78190 (#61) counts only live rows toward
the limit, so the count is limited again. Two tests catch a regression:
`a_limited_index_scan_after_deletes_counts_only_live_rows` (tests/db.rs)
pins rhypedb's behaviour directly, and
`deleted_channels_never_make_room_past_the_limit` checks the channel
limit end to end. Filters that `AND` (or `OR`) two fields don't push a
limit down, so the listings and the owner count were exact throughout.

### Requests

- A request field set to `null` is refused (`400`); absent means "leave
  as is" (`PATCH`) or "use the default" (create).
- Unknown request fields, `owner` included, are ignored (§2.3).
- A channel's `type` is required on create. A `PATCH` may repeat it but
  not change it (`400`).
- Because `null` is refused, a `PATCH` cannot remove an optional field
  (`description`, `topic`, `tags`, `permissions`, `metadata`). It can set
  one to an empty value instead (`""`, `[]`, `{}`); an empty channel
  `permissions` map removes `view`. If the spec later defines `null` as
  "clear", that is where to change it.
- Defaults: a group is `private` with `joinPolicy: invite`; a channel is
  `private` (the spec's RECOMMENDED default).

### Tiers (§11.1)

`GET /api/tiers` lists the four canonical tiers with a name and
description, and discovery's `capabilities.tiers` lists their ids.

### Memberships for the visibility policy (§6.1, §6.5)

`Groups` implements profiles' `GroupMemberships` seam, and the app wires
it in by default (a test may override it). A user belongs to a group as
its owner or as an active member, and only active groups count.
`share_a_group` compares full actors, so `bob@b` never shares a group on
the strength of a local `bob`. `groups_visible_to` lists the subject's
groups that the viewer may read (§5.5: open tiers, or the viewer belongs),
as object URIs `https://{domain}/api/groups/{id}`. At most 1,000
memberships and owned groups are read per user. Past that, a lookup fails
closed: a group left out is neither shared nor listed.

## Follow-ups

- An admin-console (read-only) group list. It needs admin API routes and
  admin-web pages, and fits the next admin-console unit.
- §5.6 invites and §4.8 guests, using the seams above:
  `Groups::add_member` / `set_role` / `remove_member` (each already
  announces its change) and `access::join_gate`. §5.7 membership is built
  on them (decision 0020).
- Switch the references to rhypedb links with `@on_delete(cascade)` once
  the pinned rhypedb supports linking on create.
- rhypedb's limited index scan must count only live rows, as its type
  scan already does. Until it does, a limited single-field filter can
  return short. That affects other modules' limited reads too. For groups
  it only affects liveness: the sweeper's batches can come back short, and
  a purge run can stop early and leave the rest to the next run.
- Once the managed rhypedb re-checks filters at write time, the claims can
  go. Until then they are the design, not a stopgap.
