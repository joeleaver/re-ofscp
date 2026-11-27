# 0021: Follows and read markers

- **Status:** accepted
- **Date:** 2026-11-27
- **Spec:** §7.6 *Follows*, §7.7 *Read markers and unread counts*
  (lost-conn/ofscp#14, #16), §2.2 (object URIs, canonical authority), §2.3
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
- **Limit.** `MAX_FOLLOWS_PER_ACTOR` = 1000. At the limit, a new follow
  first prunes the user's local follows of channels they cannot read or that
  are gone, since the list hides those and the user could not remove them
  otherwise; with none to prune it answers `409`. Two concurrent creates
  that each saw room are caught by a recount after the write, which removes
  its own row and answers `409`. A list over the limit is a logged `500`,
  never a partial list (as decision 0018).

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
  position (`seq`). An update is a compare-and-set
  `filter(.key == k && .seq < new).update(…)` (atomic since rhypedb #59,
  decision 0012), or a create racing on the `@unique` key; either retries
  on a lost race. A marker behind or at the stored one changes nothing.
  Several markers for one scope in a request each apply; the scope is
  reported once, at its final state.
- **`read.updated`.** When any scope moved, the scopes that moved are sent
  to every connection of the user (`hub.send_to_actor`), the same entries
  the response holds. A request that moves nothing sends nothing.
- **Unread counts.** The messages after the marker that the user did not
  write. A deleted message keeps its place in history as a tombstone and
  counts. rhypedb has no count aggregate or ordered range scan, so a count
  reads the positions after the marker in batches of point lookups (as
  paging does). It is bounded: past 100 messages, or after scanning 1000
  positions (edits and deletes take positions too), the entry reports
  `unreadCount` as the bound reached and adds the extension field
  `unreadCountCapped: true` (§2.3), meaning "at least this many". Clients
  that do not know the field show a large badge, which is the right
  reading. The question of a spec-level cap was put to the OFSCP oracle;
  until it answers, this extension is the conservative choice.
- **Cleanup.** When a channel is deleted, its markers are removed with its
  messages by the sweeper, in both of its purges, so a marker write racing
  the first purge is caught by the second. Follows of a deleted channel are
  pruned lazily (above).

### Storage (`schema.rhype`)

Two new types, `Follow` and `ReadMarker`, each keyed `@unique` by
`"{owner} {target}"` and indexed by `owner` (and `ReadMarker.scope_id` for
the purge). Neither a canonical actor nor a local id or canonical URI
holds a space, so the key is unambiguous. Both types are new, so no
migration is needed (rhypedb applies additive changes on reload).

## Interoperability notes

- Forumall's read-marker store still `PATCH`es `{scopeId, lastReadSeq}`
  without `lastReadMessageId`. Spec `main` requires the message id, so
  those requests get `400`; Forumall's client needs updating
  (lost-conn/ofscp#14). Reported to the oracle.
- Forumall's feed controller drops a local follow without `groupId`; this
  provider always sends one.
