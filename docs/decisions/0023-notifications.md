# 0023: The notification feed, mentions and notification settings

- **Status:** accepted
- **Date:** 2026-11-27
- **Spec:** §10.1 *Notification feed & mentions*, §10.2 *Notification
  settings* (lost-conn/ofscp#13), §5.3 *Mentions*, §7.2 (paging, cursors),
  §11.3 (effective read access); schemas `notification.json`,
  `notifications-response.json`, `notifications-mark-response.json`,
  `notification-setting.json`, `notification-settings-response.json`,
  `ws/notification-created.json`
- **Security requirements:** 1 (local-account endpoints refuse remote
  signers), 5 (effective read access on every surface), 7 (notifications
  never disclose a message)

Web Push (§10.3) and the webhook endpoints of §10 are not part of this
decision.

## Decisions

### Endpoints (`src/notifications/routes.rs`)

All are signed local-account endpoints: a remote signer gets `403`, an
unsigned caller `401`.

| Route | Answers |
| --- | --- |
| `GET /api/me/notifications?type=&limit=&cursor=` | `200` `{items, counts, nextCursor?}`, newest first; `400` for a cursor this endpoint did not issue |
| `POST /api/me/notifications/seen` | `200` `{affected, counts}`; `400` |
| `POST /api/me/notifications/read` | `200` `{affected, counts}`; `400` |
| `GET /api/me/notification-settings` | `200` `{prefs}`, by scope type then id |
| `PUT /api/me/notification-settings` | `200` the stored setting; `400` |
| `DELETE /api/me/notification-settings?scopeType=&scopeId=` | `200` `{cleared}`; `400` |

- `limit` is read as §7.2 reads it (fractions round down, unusable values
  are the default) with §10.1's default 30 and maximum 100. An unknown
  `type` is ignored. The cursor is opaque (`n{position}`).
- `counts` always carries `message` (the schema lets it be omitted).
- `seen`/`read` take `{ids?}`; an empty body is `{}`. More than 500 ids
  (the whole kept feed), an id that is no local id, or a body that is not a
  JSON object is `400`. Ids that are not the caller's visible entries are
  ignored. `read` also sets `seenAt` where it is unset, and keeps an earlier
  one. `affected` is the number of rows a guarded update really changed, so
  a repeat is `0`.
- Settings: `scopeType` must be `group` or `channel`, `scopeId` a local id
  and `mode` one of the three; anything else is `400`. The group or channel
  need not exist (§10.2 allows not checking it, and checking would tell a
  caller whether a private channel exists). A user may hold 1000 settings;
  a `PUT` of a new scope past that is `400` (changing an existing one always
  works).

### Making entries (`src/notifications/create.rs`)

The messages module tells the feed of each **created** channel message
through the `Notify` seam (`src/messages/notify.rs`), from
`Messages::create` once `write_new` has returned a new message: edits,
deletes and `clientMessageId` retries make nothing. A failure anywhere is
logged; the message stands.

Candidates come in two sets, made separately:

- **Direct:** the local users the message mentions (at most 100, below)
  and the local author of its parent (a reply). The author controls how
  many there are, and the bound keeps it small, so these are made in the
  seam's future, which `create` runs in a task of its own and awaits
  outside the channel's lock: a dropped request still finishes it, and a
  client sees its mention and reply entries in place when the create
  answers.
- **`all`:** every user whose channel or group setting is `all`. Any
  local account may hold an `all` setting for any scope (§10.2; the scope
  is not checked, see *Endpoints*), so their number is not the author's to
  bound and the create must not wait on it. Once the direct entries are
  made, the seam's future only queues the message's id (*The background
  queue*, below), and only if its channel or group has an `all` setting
  at that moment (one query reading at most one row per scope). The
  entries are made later, off the request path. Because the direct
  entries are made before the id is queued, a direct candidate's entry is
  never beaten by a `message` entry; a turn skips everyone who already has
  an entry for the message (one batched lookup by `source_key`), so a
  direct candidate costs no feed position there either.

Each candidate gets at most one entry (a `@unique` `source_key`
`"{owner} {message_id}"` enforces it), of type mention, else reply, else
message, and only if, checked at that moment, in this order:

1. they are not the author;
2. they can read the channel (`Groups::readers_among`: the group and
   channel read once, every candidate's membership in one batched lookup,
   none when anyone may read the channel), so a mention never discloses a
   message to someone who could not read it;
3. their account exists and is active (`AccountStore::active_handles`, one
   batched lookup);
4. their effective mode (channel setting, else group setting, else
   `mentions`) is not `none`, and is `all` for a `message` entry
   (`SettingStore::effective_modes`, batched lookups by setting key).

Each check runs once over every candidate still standing, cheapest and
most selective first, so a candidate who fails one costs a share of one
batched lookup, not a query of their own. In a channel only members can
read, `all` settings held by non-members (throwaway accounts included)
are dropped at step 2. Only candidates who pass every check cost writes:
those are users who can read the channel and asked for every message,
and their entries are never skipped.

Each entry made is announced as `notification.created` `{notification}` to
the owner's connections (`Hub::send_to_actor`). Readability is read again
(one batched check) after the entries are written and just before the
events are sent, with nothing awaited between that read and the sends, so
access lost while the entries were written sends no event. The event
carries no counts. What remains is the time between that read and the
in-process send: a removal committed in it can still be followed by one
event. An entry left unsent stays stored and, like every entry, is not
listed, counted or marked while its channel is unreadable (*Reading the
feed*).

Feed order is the order entries were made (positions, below). A
`message` entry made in the background can therefore come after the
mention entry of a later message; `createdAt` is always the source
message's creation time.

### The background queue (`src/notifications/background.rs`, `all_mode.rs`)

Creates have no rate limit, and anyone may set `all` anywhere, so the
work they leave behind is queued under explicit bounds:

- **Ids, coalesced per channel.** The queue holds message ids, never
  message copies. Each channel with work has one entry holding its ids in
  arrival order (with its group's id).
- **Turns, round-robin.** At most 4 drainer tasks run. Each takes a turn:
  the channel at the front of the ready list and up to 64 of its ids. If
  more of that channel's ids wait, the channel goes to the back of the
  list. A channel is in at most one turn at a time, so its messages are
  handled in the order they were queued. That is the order their direct
  entries finished, which for messages created at the same moment need
  not be their order in the channel. A flood in one channel therefore delays another
  channel's entries by at most one turn per channel ahead of it, never by
  the length of the flood.
- **Bounds.** At most 256 ids wait per channel and 8192 in all; turns in
  progress hold at most 4 × 64 more. The queue's memory is bounded by
  those numbers, whatever is posted. A create waiting for room (below)
  still holds its own request's message until it queues; how many wait is
  bounded only by how many requests are in flight, which this provider
  does not cap.
- **When a bound is reached, nothing is dropped.** The create that would
  queue past it waits for room instead (it is woken when a turn takes ids
  out), and logs once that it waited. That is back-pressure on whoever
  posts faster than the queue drains: a flooded channel's own creates
  wait once its 256 are queued, while other channels still have room.
  Only when 8192 ids are queued across channels does every create that
  needs the queue wait. A create that needs no `all` entries never
  touches the queue and never waits.
- **One turn's work.** The scope's `all` owners are read once per turn
  (by key range, see *Storage*) and checked once (readable channel,
  active account, effective mode `all`). The turn's messages are then read
  again in one batched lookup: a message deleted since it was queued, or
  gone with its channel, gets no entries. Then, message by message in
  creation order, the checked owners other than its author and other than
  those who already have an entry for it get a `message` entry, and each
  entry is announced (below). A database failure is logged. One that hits
  the turn's setup loses that turn's entries; one that hits a single
  message loses that message's entries.
- **Settings racing a create.** The no-`all` check runs after the message
  is stored. An `all` setting stored after that check does not apply to
  the message, which is older than the setting. A turn reads the settings
  as they are when it runs, so a setting changed while the message waited
  applies as changed. If the check itself fails, the message is queued
  anyway.
- **Shutdown and crashes.** The queue lives in memory. Graceful shutdown
  waits up to 10 s for it to drain (`Notifications::flush`). Ids still
  queued after that, or at a crash, are lost: those messages get no
  `message` entries. Shutdown logs how many. Their mention and reply
  entries are unaffected, since the create made those before answering.
  Making the queue durable would mean a stored per-channel progress
  marker written on every turn and a scan on startup. For entries that
  are a convenience on top of the channel itself, that cost is not
  worthwhile.
- **Tests.** Tests wait with `Notifications::flush`, which returns once
  every id queued so far has been handled. `Background::hold` keeps work
  queued, so a test can check what was queued or change things before a
  turn runs.

### Mentions (`src/notifications/mentions.rs`)

A message's `mentions`, when present, are exactly who it mentions, and its
text is not read; an empty list mentions no one. Otherwise `content.text`
(of any MIME type) is parsed with §10.1's grammar. Mentions of users of
other providers create nothing: the feed is provider-local. Where §10.1 is
silent, the conservative reading:

- The `@` must not follow a Unicode letter or digit, `_` or `@`.
- A handle run that is not a valid handle (§2.2.1, 3 to 32 characters) is
  no mention; it is not cut down to fit.
- After `@handle@`, the domain is the run of `[A-Za-z0-9.:-]`, less a
  trailing `.` or `:` (a full stop ending the sentence), canonicalized
  (§2.2). If that is not a valid authority, the whole reference is no
  mention, never a bare `@handle`: a malformed qualified mention must not
  notify a local namesake.
- At most 100 users are mentioned (`MAX_MENTIONS`, the bound on the
  explicit list): references are deduplicated first, mentions of users of
  other providers are not counted, and the first 100 distinct local users
  in order of appearance are the ones mentioned. Without the cap, a 16 KiB
  text of `@abc @abd …` would name some 3,200 candidates, every one
  checked while the create waits.

### Reading the feed (`src/notifications/mod.rs`)

`GET`, its `counts`, and `seen`/`read` all work on the caller's *visible*
entries: those whose channel the caller can read now (`readable_among`,
security requirement 5). An entry about a channel they lost access to is
neither listed, counted nor marked, and is there again, unchanged, if
access comes back. A deleted channel's entries are purged by the messages
sweeper (both of its passes, as read markers are), with its channel-scoped
settings. Group-scoped settings of a deleted group are left for their
owner to clear: no sweeper pass sees deleted groups, and a stale setting
names an id that is never reused.

### Storage (`schema.rhype`, `src/notifications/store.rs`, `settings.rs`)

rhypedb has no ordering, counting or projection, so everything is bounded:

- **Positions.** Each user's entries are numbered by a compare-and-set
  counter (`NotificationFeed.last_n`); writers in this process take turns
  per user. Only the newest 500 positions are kept: a create deletes the
  rows below the window, and reads never look below it. A position whose
  write failed (or met an existing entry for the message) is a gap, so a
  feed holds at most 500 entries.
- **Reads.** A feed is read whole, with one query over the owner's indexed
  rows in the window (at most 500), and filtered, counted, sorted by
  position and paged in memory. Counts need every unseen entry anyway, and
  the readability filter would leave a page walk over positions full of
  gaps, so point lookups by position would gain nothing.
- **Marks.** `seen_at`/`read_at` are unix seconds, 0 while unset. A mark is
  an update guarded on the field being 0, batched over explicit ids (only
  visible entries are named), so its result is the rows really changed.
- **Settings.** One row per (owner, scope), keyed `"{owner} {scope_type}
  {scope_id}"`; a `PUT` is an upsert. A `DELETE` first claims the row with a
  guarded update (so of two racing clears exactly one reports `cleared:
  true`), then deletes it.
- **`all` settings of a scope** are listed by ranges of `owner`, which is
  unique within a scope (`src/db/key_range.rs`). rhypedb promises no order
  for a filter's results, so offset paging could skip or repeat rows.
  Instead each range `(after, through]` is read whole in one query (one
  snapshot); a range that comes back with more than 1000 rows is narrowed
  at the middle owner read and read again, as `Messages::number_all` walks
  channel logs. A row's owner never changes, so a setting that is `all`
  throughout the read lies in exactly one range and is always found,
  whatever else changes meanwhile; only a setting changed during the read
  may or may not be seen, as with any read racing a write.

### Latency

The create waits for its mention and reply entries: at most 101
candidates, checked in a few batched lookups, then one write sequence per
entry (16 at a time). After that it waits for one or two single-row
queries (is there an `all` setting?), plus the queue only while the queue
is full (*The background queue*). `message` entries are made after the
create has answered, normally within moments. A client that reads its
feed at once may not see them yet, and sees them in the order they were
made.
