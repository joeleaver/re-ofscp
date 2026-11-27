# 0022: Follows and read markers

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
| `GET /api/me/read-markers` | `200` `{scopes}`: every channel the user can read now in the groups they belong to; `503` + `Retry-After` (below) |
| `PATCH /api/me/read-markers` | `200` `{scopes}`: the scopes that moved; `400` malformed body; `503` + `Retry-After` (below) |

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
- **Deleted channels are not scopes.** Deleting a channel or its group
  closes the channel's logs before it removes the channel rows, so for a
  moment a reader can still list a channel whose log is closed. Its counts
  are gone with it (a closed log counts nothing), and it is no longer
  readable: `GET`, `PATCH` and `read.updated` leave it out, and `PATCH`
  stores no new marker there. The same goes for a channel with no log
  where the reader holds a marker (only a written channel has markers, and
  only a deleted one loses its log, when the sweeper drops it). Neither is
  ever a `500`.
- **`503`.** Answered with `Retry-After` when a request cannot be
  answered exactly yet and a retry will be: a write conflict that outlasted
  its retries or the database unreachable (`Retry-After: 1`, as for
  messages), or a channel from before ordinals still being numbered
  (`Retry-After: 5`, below).
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
  log either read finds closed is a deleted channel (above). A channel
  where they do not agree is settled and read under its channel lock.
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
  regardless. A create that, just after settling under its lock, still
  finds a create pending can only be meeting another process's: it takes
  no ordinal and answers `503` with `Retry-After: 1`, like every other
  transient write conflict on messages (`DbError::Contended`), since a
  retry once that create settles succeeds. `409` stays for conflicts a
  retry does not fix by itself (an edit racing an edit).
- **Existing data: numbering (`messages/numbering.rs`).** Messages and
  logs written before ordinals have none of the new fields. rhypedb reads
  an absent field as missing, and no filter comparison (`==`, `!=`,
  `== null`) matches it; `@unique` admits any number of objects without
  the field. So a create's compare-and-set (`counted == 1`) never matches
  a log from before, and `counted` absent is what marks a channel to
  number. Numbering reads the channel's positions `1..=last_seq` in
  batches of 100 point lookups, gives each message in `seq` order its `n`,
  `author_n` and `apos` (16 writes at a time, skipping messages that
  already hold the right values), sets each author's tally, and only then
  marks the log counted with `message_count`. Every value written depends
  only on the messages stored, so a numbering cut short is redone by the
  next one, writing the same values.
  - *Where it runs.* A background task started with the server (beside
    the messages sweeper) numbers every channel in one pass over the open
    logs, then numbers whatever requests hand it. Between the channels of
    that pass it numbers what requests handed over meanwhile, so a request
    waiting on a channel waits behind one channel's numbering, not the
    whole pass. A request (a create, a marker update, a count) that meets
    channels not yet numbered numbers them itself only within a budget of
    1,000 positions over every channel it meets; a channel past what is
    left of it is handed to the background task and the request answers
    `503` with `Retry-After: 5` until it is done.
  - *The pass reads key ranges, not offsets.* rhypedb rows come back in
    no set order and it has no ordered paging, so offset pages could skip
    a log whenever another closed mid-pass. The pass instead reads the
    open logs with `after < channel_id <= through` (string order), at most
    101 at a time. A read returning at most 100 returned all of that
    range; the pass numbers those and moves to the next range. A full read
    narrows `through` to the middle of the ids it returned and reads again,
    keeping the wider bound to return to. The ranges cover every id once,
    each read whole, so a log missed was closed (nothing to number) or
    opened since ordinals (counted from the start): nothing from before is
    skipped, and one pass suffices.
  - *No count is guessed, and no scope is dropped.* `GET` must list every
    readable channel with an exact `unreadCount` (§7.7), so leaving out a
    channel still being numbered would read as one the user cannot read;
    the whole answer is `503` instead, a wait of about one channel's
    numbering (above). `PATCH` finds every marker's point first, numbering
    within its budget, and moves no marker until all are found: a batch
    naming a channel still being numbered answers `503` with nothing
    stored, and its retry moves, reports and announces every scope
    together. (Moving the others and skipping that scope would drop a
    marker the user set, with no way in §7.7 to tell them; moving the
    others and then answering `503`, as first built, stored markers that
    no device heard of, since the retry finds them not moved.) A database
    failure while storing can still follow some moves; those are announced
    (`read.updated`) before the error is returned.
  - *Bounds.* A request does at most 10 batched reads (plus one per
    channel) and 1,000 writes numbering, over all its channels together,
    or none. It numbers under the channel's write lock (it settles a
    pending create there first, which needs that lock), so edits, deletes
    and reactions in that channel wait for it, within that budget. The
    background task is unbounded (one pass over each channel, once) but
    nothing waits on it: it takes only the channel's numbering lock, never
    its write lock, so edits, deletes and reactions in a long channel go
    on meanwhile; only creates there wait (with `503`), since a create
    needs the channel numbered. Every numbering of one channel takes turns
    under the numbering lock, and creates are refused until it is
    numbered, so no create runs beside a numbering.
  - *The final compare-and-set* marks the log counted only if no position
    was taken after the last one the numbering read (`last_seq`
    unchanged): such a position could hold a create's message, which the
    count must include. It does not restart the numbering, though. A
    position already read never gains a message later (a message is
    written only at the position its create took, and an edit or a delete
    moves `last_seq` without writing one), so the numbering keeps its
    count and tallies, reads only the positions taken since, and tries
    again. An edit landing between the reads and the compare-and-set costs
    one more batch; only a channel whose positions are taken faster than
    that, 32 times running, gives up (`503`, retried by the next request
    or pass).
  - Numbering lazily on first use alone, as first built, made the first
    request in a long channel do one write per message, one after another,
    under the channel lock; numbering at startup alone would leave
    channels unnumbered, and requests in them stuck, until the pass
    reached them. Both together keep requests bounded and every channel
    numbered soon after a deploy.
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
  reload; existing rows are numbered in place (above) rather than by a
  migration, which would have to stop writers to stay exact.

## Interoperability notes

- Forumall's read-marker store still `PATCH`es `{scopeId, lastReadSeq}`
  without `lastReadMessageId`. Spec `main` requires the message id, so
  those requests get `400`; Forumall's client needs updating
  (lost-conn/ofscp#14). Reported to the oracle.
- Forumall's feed controller drops a local follow without `groupId`; this
  provider always sends one.
