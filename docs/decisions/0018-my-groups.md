# 0018: My groups: the group list and membership pointers

- **Status:** accepted
- **Date:** 2026-11-27
- **Spec:** §5.7 *My groups: membership pointers at home*, §2.2 (object
  URIs, canonical authority), §8 *Authorization*, §7.1 *Close codes*;
  schemas `group-pointer.json`, `group-pointer-request.json`,
  `group-pointers-response.json`, `ws/groups-updated.json`
- **Security requirements:** 1 (identity is `(handle, domain)`), 3 (no
  outbound request to a host named by someone else)

## Context

A user joins a remote group by signing straight to that group's provider,
so their home provider does not learn of it. §5.7 has the home provider
keep the user's group list: its own memberships, plus pointers the user's
clients record for remote groups. Every device reads the list, and hears
of changes through `groups.updated`.

## Decisions

### Endpoints (`src/my_groups/`)

| Route | Answers |
| --- | --- |
| `GET /api/me/groups` | `200` `{groups, metadata: []}`: hosted entries, then pointers, each sorted by URI |
| `PUT /api/me/groups/{groupRef}` | `200` entry; `400`; `403` denied provider; `404` hosted group, not a member; `409` pointer limit; `503` policy not loaded |
| `DELETE /api/me/groups/{groupRef}` | `204` (also when there is none); `400`; `409` hosted group the caller belongs to |

- **Order of checks.** A remote or provider signer gets `403` first (a
  local-account endpoint, requirement 1), then the request is read (`400`,
  recording nothing), then the federation policy is applied to the group's
  provider (`403`, or `503` while the policy is not loaded: fail closed,
  as everywhere else, decision 0008).
- **`{groupRef}`.** The router decodes the segment exactly once. It must be
  `https://{authority}/api/groups/{id}` with nothing after the id (no
  query, fragment, trailing slash or further segments) and a valid local id.
  The authority is converted to canonical form (`ObjectUri::canonicalize`:
  lowercase, no trailing dot, no `:443`) before anything compares or stores
  it. A bare local id is refused: a pointer names a group across providers.
- **Body.** Empty, or a JSON object. A `role` that is not a string (`null`
  included) is `400`, as §5.7 requires. A string the `Role` schema refuses
  (empty), or no group could define (longer than 64 characters, or holding
  whitespace or controls, the rule for role names in `groups::validate`),
  is `400` too. Unknown fields are ignored (§2.3).
- **`PUT` replaces.** A `PUT` with no `role` records the pointer with no
  hint, clearing an earlier one. A `PUT` that changes nothing writes
  nothing, keeps `updatedAt` and emits nothing.
- **No contact with the group's provider** (§5.7, requirement 3). Nothing
  here makes an outbound request.
- **`DELETE` ignores the federation policy.** Removing a pointer to a
  provider that is now denied must still work, so a user can clean up.
  `GET` lists such pointers too: they are the user's own records, and the
  policy governs talking to that provider, not remembering it.

### Hosted groups are derived, never stored

A `PUT` or `DELETE` whose authority is this provider never touches the
pointer table. `PUT` answers the caller's entry (`404` if they do not
belong), and `DELETE` answers `409` to a member or the owner (they leave
with `POST /api/groups/{id}/leave`) and `204` to anyone else.

An entry's `role` is `owner` for the group's owner (`Group.owner`, not a
`Membership` row) and the membership's role otherwise. Its `updatedAt` is
`Membership.updated_at` or `Group.owner_since`, columns that the
membership branch adds and that are written on a role change or a
transfer. Where one is absent (old rows, or before that branch lands) the
entry dates from `joined_at` or the group's `created_at`. The reads are in
`groups/listing.rs`, so they stay with the rest of the group storage.

### Bounds

- **Pointers:** at most 1,000 per user (`MAX_POINTERS_PER_ACTOR`). A `PUT`
  of a new pointer beyond it is `409 conflict` (the state is the problem,
  and deleting a pointer fixes it). The count is checked before the create
  and again after it, and a create that finds the user over the limit
  takes its row back, as for groups (decision 0014). Changing or removing
  an existing pointer always works.
- **Hosted memberships:** `MAX_MEMBERSHIPS_PER_ACTOR` (1,000), and owned
  groups are bounded by `MAX_GROUPS_PER_OWNER`. `GET` must list every
  group, so it reads one row more than the limit, and a user over it gets
  `500` (logged) rather than a list with some left out. Joins have to
  enforce the limit for that never to happen; that check belongs to the
  membership seams (`add_member`), on the membership branch.

### Storage (`schema.rhype`)

`GroupPointer { key @unique, owner @indexed, group, role, updated_at }`.
`key` is `"{owner} {group}"`. Neither part can hold a space, so one actor
has at most one pointer per group without a transaction. An empty `role`
means no hint (a recorded hint is never empty). A role change is a
guarded update on the old role, which is compare-and-set since rhypedb #59
(decision 0012). If another writer changed the row first, the `PUT` re-reads
and tries again (up to five times, then `409`).

### `groups.updated`

- **Pointer writes** send their event from the request, to every
  connection of the user, with the entry in `groups` or the URI in
  `removed`. One user's pointer writes, with their events, are serialized
  by an in-process lock (64 stripes by actor). So the events reach the
  user's devices in the order the writes landed, and the read-before-delete
  that decides whether a `DELETE` removed anything cannot race a `PUT`.
  rhypedb's `delete` returns no rows, so it cannot say what it removed.
  The provider runs as one process. If it ever runs several, the data stays
  correct through the unique key and the guarded update, but events could
  cross between processes.
- **Hosted memberships** change inside `Groups`, which broadcasts an
  `AccessChange` after every membership write (decision 0014).
  `my_groups::events::follow` subscribes:
  - `Member { group, actor }` for a **local** actor (a remote member's list
    lives at their own home provider): that actor's entry is read afresh
    and sent as changed, or as removed when there is none. A fresh read
    makes ordering and duplicates harmless, because the last event always
    carries the state at the time.
  - `Group { group }` for a group no longer active (being deleted, or
    gone): every member row still there, and the owner, is handled as
    above. A change to an active group's settings changes no entry.
  - `Channel` changes are ignored.
  - Actors with no live connection are skipped. The change committed before
    it was announced, so a client that connects later reads it.
- **Group deletion** now names every member, and the owner, as a `Member`
  change before the purge (`ops::delete_group`), the same way it already
  names channels, because the purge removes the rows a receiver would read.
  If the members cannot be read, the purge is left to the sweeper, so the
  `Group` change's receiver still finds the rows.
- **Ownership transfer** (membership branch) announces `Member` for both
  the old and the new owner after `Group.owner` has changed, so the fresh
  read gives `owner` and the old owner's new role.
- **Spurious events.** A failed membership write is announced too
  (decision 0014: it may have committed). The fresh read then reports the
  entry as it is, which can be a `removed` for a group the user was never
  in. Clients treat a removal of an entry they do not hold as a no-op.

### Nothing is dropped quietly (lag)

The broadcast is bounded (1,024 per receiver). One task only moves changes
into a coalescing set and does no I/O, and a second task resolves them, so
a burst collapses instead of lagging. Changes can still be lost: the
receiver lags anyway, or the set passes 65,536 distinct changes, or an
entry cannot be read or encoded. The spec has no way to say "your list
changed in ways I cannot name". Resending the full list as `groups` cannot
express removals, so it would leave a client holding groups it has left.

Instead, the affected connections get an `error` (`too_many_requests`,
`429`), and are then closed with `1013`. That is every local connection
when the lost change cannot be named, or the one member's connections when
only their entry failed. This is the close §7.1 already defines for events
a provider could not deliver to a slow consumer, and this provider already
uses it that way (decision 0010). Nothing missed while disconnected is
replayed, so a reconnecting client re-reads `GET /api/me/groups`. The close
is costly but rare, and it never leaves a list silently wrong.

## Consequences

- Clients get one list for all their devices, with live updates. A pointer
  stays unchecked by design: a wrong one misleads only its owner's list.
- The `updatedAt` of a hosted entry moves on a role change or transfer only
  once the membership branch's columns are written. Before that it is the
  join or creation time.
- If the provider ever runs as several processes, the pointer lock must
  become a shared one, or event order between devices weakens (data stays
  correct).
