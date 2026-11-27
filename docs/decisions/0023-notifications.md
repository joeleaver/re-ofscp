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
deletes and `clientMessageId` retries make nothing. The work runs in a task
of its own, which `create` awaits outside the channel's lock: a dropped
request still finishes it, and a client sees its entries in place when the
create answers. A failure there is logged; the message stands.

Candidates are the local users the message mentions, the local author of
its parent (a reply), and every user whose channel or group setting is
`all`. Each candidate gets at most one entry (a `@unique` `source_key`
`"{owner} {message_id}"` enforces it), of type mention, else reply, else
message, and only if, checked at that moment:

1. they are not the author;
2. their effective mode (channel setting, else group setting, else
   `mentions`) is not `none`, and is `all` for a `message` entry;
3. their account exists and is active;
4. they can read the channel (`Groups::readable_channel`), so a mention
   never discloses a message to someone who could not read it.

Each entry made is announced as `notification.created` `{notification}` to
the owner's connections (`Hub::send_to_actor`).

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
- **`all` settings of a scope** are listed by offset paging over the
  scope's indexed rows, 1000 per page. Up to 1000 such settings the list is
  one snapshot. Past that, a setting of the same scope changed or removed
  while the pages are read can shift a row into a page already read, and
  that user gets no `message` entry for that one message. Mentions and
  replies never depend on this list.

### Latency

The create waits for its entries, which for a channel with many `all`
users is many small reads (16 candidates at a time). This keeps the feed
consistent with what the author's client saw. If it becomes a problem the
seam can stop awaiting the task without changing anything else.
