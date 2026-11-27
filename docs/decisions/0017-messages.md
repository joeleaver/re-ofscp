# 0017: Channel messages, history and live delivery

- **Status:** accepted
- **Date:** 2026-11-27
- **Spec:** §5.3 (messages, content formats), §5.8 (attachments),
  §7.1 (WebSocket messaging commands, timeline events, typing, resume),
  §7.2 (REST messages, reactions, paging), §11.3 (effective read access);
  schemas `message*.json`, `reaction*.json`, `messages-page.json`,
  `ws/*.json`
- **Security requirements:** 1 (identity is `(handle, domain)`),
  5 (effective read access on every surface), 8 (article HTML sanitized)
- **Oracle questions:** Q1–Q7 below, sent and answered 2026-11-27. The
  oracle confirmed every default except Q5 (typing also needs a post
  grant, with Joe deciding), and settled Q2 (the `Reaction` branch of
  `TimelineItem` will be narrowed away) and Q3 (replay sends current
  state). The clarifications are lost-conn/ofscp#37. Spec `reference.provider`: lost-conn/ofscp#34
  (300f6fa).

## Context

Channels (decision 0014) existed with nothing in them. This record covers
the message log: storing messages and reactions, the REST endpoints, the
WebSocket commands, live fan-out and resume. DMs (§7.3) and the media
upload endpoints (§5.8 `POST /api/media`) are separate work.

The code is in `crates/re-ofscp-server/src/messages/`, with the WebSocket
half in `ws/message_commands.rs`, `ws/typing.rs` and `ws/live.rs`.

## Decisions

### One timeline per channel

- Each channel has a `ChannelLog` row (`schema.rhype`) holding `last_seq`
  and a `state` (`open` or `closed`). Every timeline event (a create, an
  edit or a delete) takes the next position by a compare-and-set on
  `last_seq` that also requires `state == open`. A position is the string
  `"{channel}:{seq}"`, `@unique` on its row.
- Within this process, writers to one channel take turns under a
  per-channel lock (`locks.rs`). The lock also orders fan-out, so readers
  see a channel's events in position order. Across processes, the
  compare-and-set alone orders positions; it is retried up to 32 times.
- A message keeps its creation position. An edit or a delete is a
  `TimelineEvent` row at its own, later position, so a resume replays an
  edit made to an old message (Q3, confirmed).
- Replies have their own sequence per parent message, and reactions their
  own sequence per message.
- A reply's `reference.provider` (lost-conn/ofscp#34) must be absent or
  this provider's canonical authority, since the parent is in the same
  channel; anything else is `400`, and so is a non-canonical spelling or
  `null` (ofscp-core's `Authority` refuses both). Stored references
  serialize without `provider`, which means the same thing.

### Cursors

- A cursor is a one-letter tag plus a position: `t{n}` for channel
  history and timeline events, `r{n}` for replies, `x{n}` for reactions.
  A cursor with another endpoint's tag is `400`, since cursors are valid
  only on the endpoint that issued them (§7.2).
- Live timeline events carry the `t` cursor of their position, in the
  same space as REST history, so either one works as `since` or `cursor`
  (Q3, confirmed).
- Positions are sparse. An edit's or delete's position holds no message,
  and a write that failed after taking its position leaves a gap. A page
  asks for batches of exact positions until it is full, the sequence
  ends, or it has looked at 2,000 positions; a page cut short still
  carries `nextCursor`. `limit` defaults to 50 and is clamped to 100.

### Reactions are not timeline items (Q2, confirmed)

`defs/messaging.json`'s `TimelineItem` allows a `Reaction`, but §7.1 names
only `message.created/updated/deleted` as timeline events. History and
replies return messages only (tombstones included). Reactions are read
through `GET …/reactions`, and `reaction.added/removed` carry no cursor
and are not replayed.

### Edits

- Only the author may edit, inside the edit window: 1 hour for a chat
  message, 24 hours for a memo, no limit for an article (§7.1 leaves this
  to providers).
- An edit is a partial `MessageUpdate`. An empty update is `400`, and so
  is one carrying only article fields (`title`, `summary`, `cover`) on a
  message that is not an article (lost-conn/ofscp#31). `tags` apply to
  every type.
- Concurrent edits never lose a field. In this process they take turns
  under the channel's lock, and each is built from the message as read
  under it. Across processes, an edit is a compare-and-set on the
  message's `revision`, and the one that lost the race is `409`.
- An edit or delete that finds its channel's log closed after writing
  its event takes the event back and answers `404`, as a create does.

### Deletes and tombstones (Q1, Q6, confirmed)

- The author, or a member allowed the group's `moderate` action (the owner
  always), may delete. Channel permissions have no moderate key.
- A delete keeps the row as a tombstone: `deleted: true`, the body
  cleared, the id kept. The schema requires `content`, so a tombstone
  carries `{mime: "text/plain", text: ""}`, as Forumall does.
- On a tombstone: `GET` returns it with `200`; an edit is `404`; adding a
  reaction is `404`; removing one is `204`; a second delete is `204` and
  fans out nothing.
- Visibility comes first (§7.1): someone who cannot read the channel gets
  `404` for every one of these, even its author.

### No-op commands over the WebSocket (Q4, Q7, confirmed)

A command that changes nothing fans out nothing. The requester alone gets
the answer as it stands, correlated, without a `cursor` (it is not a
timeline event), so that a client waiting on its `correlationId` never
waits forever:

- a repeated `clientMessageId`: the existing message, as
  `message.created` (§7.1 *Idempotency*);
- deleting a deleted message: `message.deleted`;
- adding a reaction already held: `reaction.added`;
- removing a reaction not held: `reaction.removed`.

When something does change, the requesting connection gets exactly one
copy with the `correlationId`, whether it is subscribed or not. If it is
subscribed, that copy is its subscribed copy, not a second one.

### Typing (Q5, as answered)

- `typing.start` and `typing.stop` need effective read access. A missing
  or unreadable channel is `not_found` (§11.3).
- They also need a `post:<type>` grant for some type, custom types
  included (`groups::access::may_post_any`: the group's `post`, or any
  channel `post:<type>` entry that grants). A reader who may post nothing
  gets `forbidden` (`403`). A reply-restricted poster may type.
- There is no answer on success.
- `channel.typing` goes to every reader subscribed to the channel, the
  typer's own connections included.
- A start holds for 6 s unless refreshed. A stop is sent only for a
  channel with an active start (on `typing.stop`, on expiry, and when the
  connection ends), so a dropped connection never leaves an indicator on.
- Typing is never stored or replayed.

### Access at publish (closes decision 0010's window)

`ws::live::HubFanout` delivers each event, under the channel's lock and
after the event's commit, only to the subscribers who can read the channel
at that moment. It reads the group, the channel and those subscribers'
memberships afresh. A revoking change committed before the event is
therefore seen even if its follower has not yet held the subscription. If
the read fails, the event goes to no subscriber (fail closed), and they
backfill through history. `a_revoked_reader_gets_nothing_before_its_subscription_is_held`
removes a member with no announcement, so no follower ever runs, and
checks that nothing is delivered.

### Resume

`messages::MessageTimeline` is the hub's `Timeline`. `since` replays the
positions after the cursor with each message as it stands now: a message
created and later deleted replays as `message.created` (the tombstone)
then `message.deleted`. A resume is truncated (and the client backfills
through REST) when the cursor is not a `t` cursor, the channel is gone or
unreadable, the cursor is ahead of the log, or more than 200 positions
have passed.

### Deleting a channel or group

Deleting a channel or group first closes its logs, so no new position
can be taken. The sweeper (every 60 s) purges a closed channel's messages,
events and reactions, then purges again 15 minutes later. The second
purge catches a write that took its position just before the close and
landed after the first purge. A writer that sees its log closed after
writing also removes its own row.

### Bodies and limits

- `text/html` is sanitized with §5.3's allow-list (`ammonia`) before it
  is stored, so this provider never hands out script, even to a client
  that forgets to sanitize. Markdown is stored as sent, because renderers
  must show its raw HTML as text.
- Text is limited to 16 KiB, and article content to 256 KiB, both checked
  before and after sanitizing. Other limits: titles 300 characters,
  summaries 1,000; 32 tags of 64 bytes each; 100 mentions;
  32 attachments; a `clientMessageId` of 128 bytes; reaction keys and
  unicode 64 bytes each, a reaction image 2,048; REST bodies 512 KiB.
- **Attachments:** the upload endpoints are not built yet, so the provider
  runs `NoUploads`, which hosts nothing. Under §5.8 every attachment from
  a local author is refused `400`. A remote author's attachments get only
  the checks for attachments this provider does not host (https,
  `expiresAt`). The media module will replace `NoUploads` through
  `AppStateBuilder::uploads`.

### Anonymous readers

The read routes (history, a single message, replies, reactions) accept
unsigned and provider-signed requests as an anonymous viewer (§4.5,
decision 0014). Every write needs an actor's signature. Remote actors
use every route exactly as local ones do, by their full `handle@domain`
(§8.2).

## Follow-ups

- Media uploads (§5.8), replacing `NoUploads`.
- Notifications and mentions (§10.1). Mentions are validated and stored
  but notify no one yet.
- Re-check against lost-conn/ofscp#37's final text once it merges.
