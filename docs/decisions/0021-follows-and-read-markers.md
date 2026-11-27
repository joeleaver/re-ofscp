# 0021: Follows and read markers

- **Status:** accepted
- **Date:** 2026-11-27
- **Spec:** §7.6 *Follows*, §7.7 *Read markers and unread counts*
  (lost-conn/ofscp#14, #16, #41), §2.2 (object URIs, canonical authority), §2.3
  (extension fields), §11.3 (effective read access); schemas
  `follow.json`, `follow-create-request.json`, `follows-response.json`,
  `read-markers-response.json`, `read-markers-update-request.json`,
  `ws/read-updated.json`
- **Security requirements:** 1 (identity is `(handle, domain)`), 3 (no
  outbound request to a host named by someone else), 5 (effective read
  access on every surface)

## Context

Forumall's web client builds its home feed from `GET /api/me/follows` and
its unread badges from `/api/me/read-markers`. Both are local-account
endpoints: per-user state kept by the user's home provider, read by all of
their devices.

## Decisions

### Follows (`src/follows/`)

| Route | Answers |
| --- | --- |
| `GET /api/me/follows` | `200` `{follows, metadata: []}`, oldest first, then by channel; `500` (logged) over the limit |
| `POST /api/me/follows` | `201` new follow; `200` already followed (the stored follow); `400`; `403` denied provider; `404` local channel missing or unreadable; `409` limit; `503` policy not loaded (remote channels only) |
| `DELETE /api/me/follows/{channelRef}` | `204` (also when there is none); `400` |

- **Order of checks.** A remote signer gets `403` first (requirement 1),
  then the request is read (`400`, recording nothing).
- **One follow per channel.** A channel reference is a bare local id or a
  channel object URI `https://{authority}/api/groups/{g}/channels/{c}`
  (nothing after the id). The authority is made canonical. A URI on this
  provider names a local channel, so it is stored as the bare id; a remote
  channel is stored as its canonical URI. Every spelling of a channel is
  therefore one row (`Follow.key = "{owner} {channel}"`, `@unique`), and
  `DELETE` accepts any spelling.
- **`groupId` is derived, never taken from the client.** `POST` checks that
  a `groupId` it is sent is a non-empty string, then ignores it. The
  response carries the group §7.6 says to derive: a local channel's own
  group id, or for a remote channel the group's object URI, which the
  channel URI names. A local channel URI that names a group other than the
  channel's own names no channel (`404`).
- **Effective read access (requirement 5).** Following a local channel
  needs read access to it now; a channel the caller cannot read answers
  `404` like a missing one (§11.3). The list re-checks every local follow:
  one whose channel the user can no longer read is left out but kept (it
  reappears if access returns); one whose channel is gone is pruned (§7.6
  allows pruning a stale pointer). A remote follow is a pointer the client
  dereferences at the channel's own provider, which enforces access there;
  this provider never contacts it (requirement 3).
- **Federation policy.** A new remote follow is refused (`403`) when the
  policy denies its provider, or `503` while the policy is not loaded (fail
  closed, decision 0008). Existing remote follows stay listed and can
  always be removed: the policy governs talking to a provider, not
  remembering one.
- **Limit.** `MAX_FOLLOWS_PER_ACTOR` = 1000, enforced by slots, as a
  limited invite's uses are (decision 0019). Each follow holds one of its
  owner's slots, `Follow.slot = "{owner} {i}"` with `i < 1000`, `@unique`.
  A create picks a free slot at random (so concurrent creates seldom pick
  the same one) and writes the follow; the `@unique` create is the one
  serialized step, so no two follows ever hold one slot and an owner never
  has more than 1000, however many creates race. A create that loses on
  the key (the same follow, made meanwhile) answers `200` with that follow;
  one that loses on the slot reads again and picks another. Nothing is
  ever counted, reserved or rolled back: a delete frees its slot with its
  row. This replaced a recount after the write that removed the request's
  own row when over the limit: that row could already have been answered
  `200` to a concurrent request for the same follow, and two creates at
  the limit could both roll back. With every slot taken, a new follow
  first prunes the user's local follows of channels they cannot read or
  that are gone, since the list hides those and the user could not remove
  them otherwise; with none to prune it answers `409`. A list over the
  limit (only a damaged store could hold one) is a logged `500`, never a
  partial list (as decision 0018).

### Read markers (`src/read_markers/`)

| Route | Answers |
| --- | --- |
| `GET /api/me/read-markers` | `200` `{scopes}`: every channel the user can read now in the groups they belong to |
| `PATCH /api/me/read-markers` | `200` `{scopes}`: the scopes that moved; `400` malformed body |

- **Scopes.** A scope is a channel the user can read in a group they
  belong to here. Direct-message scopes (`dmId`) join when §7.4 is
  implemented. Each entry carries `scopeId`, `unreadCount`, `groupId` and,
  once set, `lastReadMessageId`.
- **Markers are message ids (lost-conn/ofscp#14).** `lastReadMessageId` is
  required. A client's extra fields (Forumall still sends `lastReadSeq`)
  are ignored (§2.3). A request carries 1–100 markers.
- **Unknown scopes are ignored, never refused.** A marker for a scope that
  does not exist, that the user cannot read, or that is no local id, or one
  naming a message the scope does not hold, is skipped with `200`, and
  nothing is stored or reported. So `PATCH` reveals nothing about channels
  or messages the caller cannot read (requirement 5).
- **Forward only.** The stored marker keeps the message's creation
  ordinal `n` and `own`, the number of the user's messages at or before it
  (below). An update is a compare-and-set
  `filter(.key == k && .n < new).update(…)` writing both (atomic since
  rhypedb #59, decision 0012), or a create racing on the `@unique` key;
  either retries on a lost race. A marker behind or at the stored one
  changes nothing. Several markers for one scope in a request each apply;
  the scope is reported once, at its final state.
- **`read.updated`.** When any scope moved, the scopes that moved are sent
  to every connection of the user (`hub.send_to_actor`), the same entries
  the response holds. A request that moves nothing sends nothing.
- **Unread counts are exact (lost-conn/ofscp#41: "MUST be exact", never
  capped).** The messages created in the channel after the marker's
  message, tombstones and replies included (a deleted message keeps its
  place in history), minus the user's own. rhypedb has no count aggregate
  or ordered range scan, so counts are kept rather than computed:
  - every message has `n`, its 1-based creation ordinal in the channel,
    and `author_n`, its ordinal among its author's messages there;
  - the channel's log counts its messages (`ChannelLog.message_count`),
    and a `MessageTally` row per (channel, author) counts each author's;
  - a marker stores `n` and `own` (the user's messages with ordinal
    `≤ n`), so
    `unread = (message_count − n) − (tally − own)`, and with no marker
    `message_count − tally`.

  `GET` is bounded whatever the channels hold: batched point lookups of
  the markers, of the logs (twice) and of the user's tallies. A tally only
  changes while a create is pending on its channel's log (below), and
  every create moves `last_seq`, so where the two log reads agree and show
  nothing pending, the tally read between them agrees with the count. A
  channel where they do not is settled and read under its channel lock.
  `PATCH` finds `own` by a binary search over the user's `author_n`, each
  step a point lookup on `Message.apos = "{channel} {author} {author_n}"`
  (`@unique`): O(log) lookups. The groups the scopes come from are checked
  four at a time.
- **Taking ordinals (`messages/ordinals.rs`, `ops.rs`).** A create, under
  its channel's lock, takes its position and its ordinal in one
  compare-and-set on the log (`last_seq` and `message_count` together,
  requiring `counted == 1` and nothing pending), which also records it as
  pending (`pending_id`, `pending_author`). It then takes its author's
  ordinal by a compare-and-set on the tally and writes the message. It is
  then settled: once the message is written the pending mark is cleared;
  if the write failed (a duplicate `clientMessageId`, the channel closed
  meanwhile, a database error) its ordinals are given back by
  compare-and-set: the tally if no message holds the author's last
  ordinal, then the count. A settle that itself fails, or a process that
  stops part-way, leaves the mark, and the next create, marker or count in
  the channel settles it the same way, deciding by whether the message
  exists. Since one create is pending at a time and it holds the last
  ordinals, giving back is always exact, and ordinals stay dense. The
  provider runs as one process (decision 0005), whose channel lock makes
  creates take turns; the compare-and-sets keep each counter atomic
  regardless, and a second process's pending create makes a create answer
  `409` rather than guess.
- **Existing data: numbering on first use.** Messages and logs written
  before ordinals have none of the new fields. rhypedb reads an absent
  field as missing, and no filter comparison (`==`, `!=`, `== null`)
  matches it; `@unique` admits any number of objects without the field.
  So a create's compare-and-set (`counted == 1`) never matches a log from
  before, and `counted` absent is what marks a channel to number. The
  first create, marker update or count that meets one numbers it, under
  the channel's lock: it reads the channel's positions `1..=last_seq` in
  batches of 100 point lookups, gives each message in `seq` order its `n`,
  `author_n` and `apos`, sets each author's tally, and only then marks the
  log counted with `message_count`, by a compare-and-set that also
  requires `last_seq` unchanged (starting over if a position was taken).
  Every value written depends only on the messages stored, so a numbering
  cut short is redone by the next one, writing the same values, and
  concurrent readers wait on the lock and find it done. It runs lazily,
  not at startup, so a deploy does not wait on every channel and an idle
  channel is never touched; its cost, one pass over the channel, is paid
  once.
- **Cleanup.** When a channel is deleted, its markers and its authors'
  tallies are removed with its messages by the sweeper, in both of its
  purges, so a marker write racing the first purge is caught by the
  second. Follows of a deleted channel are
  pruned lazily (above).

### Storage (`schema.rhype`)

- `Follow` and `ReadMarker`, each keyed `@unique` by `"{owner} {target}"`
  and indexed by `owner` (and `ReadMarker.scope_id` for the purge).
  `Follow.slot` is `@unique` (above); `ReadMarker` holds `n` and `own`.
  Neither a canonical actor nor a local id or canonical URI holds a space,
  so the keys are unambiguous. Both types are new, so they need no
  migration.
- `MessageTally`: `key = "{channel} {author}"` (`@unique`), `channel_id`
  (`@indexed`, for the purge), `count`.
- New fields on existing types: `Message.n`, `Message.author_n`,
  `Message.apos` (`@unique`); `ChannelLog.counted`,
  `ChannelLog.message_count`, `ChannelLog.pending_id`,
  `ChannelLog.pending_author`. rhypedb applies these additive changes on
  reload; existing rows are numbered on first use (above) rather than by a
  migration, which would have to stop writers to stay exact.

## Interoperability notes

- Forumall's read-marker store still `PATCH`es `{scopeId, lastReadSeq}`
  without `lastReadMessageId`. Spec `main` requires the message id, so
  those requests get `400`; Forumall's client needs updating
  (lost-conn/ofscp#14). Reported to the oracle.
- Forumall's feed controller drops a local follow without `groupId`; this
  provider always sends one.
