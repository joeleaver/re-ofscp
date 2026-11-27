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
| `GET /api/me/groups` | `200` `{groups, metadata: []}`: hosted entries, then pointers, each sorted by URI; `500` (logged) over a bound |
| `PUT /api/me/groups/{groupRef}` | `200` entry; `400`; `403` denied provider; `404` hosted group, not a member; `409` pointer limit; `503` policy not loaded (remote groups only) |
| `DELETE /api/me/groups/{groupRef}` | `204` (also when there is none); `400`; `409` hosted group the caller belongs to |

- **Order of checks.** A remote or provider signer gets `403` first (a
  local-account endpoint, requirement 1), then the request is read (`400`,
  recording nothing). A group hosted here is then answered at once: it
  involves no other provider, so no federation policy, and it works even
  before the policy has loaded. For any other group the federation policy
  is applied to its provider (`403`, or `503` while the policy is not
  loaded: fail closed, as everywhere else, decision 0008).
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
`Membership.updated_at` (written on a role change, decision 0020) or
`Group.owner_since` (written by an ownership transfer). Where one is absent
(old rows, or a creator who still owns the group) the entry dates from
`joined_at` or the group's `created_at`. The reads are in
`groups/listing.rs`, so they stay with the rest of the group storage.

### Bounds

- **Pointers:** at most 1,000 per user (`MAX_POINTERS_PER_ACTOR`). A `PUT`
  of a new pointer beyond it is `409 conflict` (the state is the problem,
  and deleting a pointer fixes it). The count is checked before the create
  and again after it, and a create that finds the user over the limit
  takes its row back, as for groups (decision 0014). Changing or removing
  an existing pointer always works.
- **Hosted memberships:** at most `MAX_MEMBERSHIPS_PER_ACTOR` (1,000, in
  `groups/mod.rs`) per actor, owned groups aside, enforced in
  `Groups::add_member`, the seam every join goes through. An existing
  member is answered first (`Ok(false)`, whatever the count). Then the
  active memberships are counted before the write, and again once the
  new one is active; a join that finds the actor over the limit takes its
  row back. Either way the join is `403 forbidden` (provider policy, like
  the owned-group limit). From the activation on, every exit announces
  the change (`Groups::settle_join`), errors included: an activation that
  failed may have committed, and a join whose activation or recount failed
  is taken back (announced again), so no group list misses a membership
  that may exist. Owned
  groups are bounded by `MAX_GROUPS_PER_OWNER`.
- **No partial lists.** `GET` must list every group, so it reads one row
  more than each bound (owned groups, memberships, pointers). A list that
  finds the extra row is `500` (logged), never a list with some left out.
  The writes above make that unreachable; the check keeps a bug or a
  manual database edit from turning into a silently short list.

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
- **Hosted memberships** change inside `Groups`. Besides the bounded
  `AccessChange` broadcast (decision 0014), which live subscriptions
  follow, `Groups` tells every registered `MembershipListener` of each
  membership change, synchronously, from the write that made it
  (`Groups::on_membership`; `member_changed` calls both). A listener
  cannot lag, however many changes one operation makes. The group list
  registers one (`my_groups::events::follow`) and never reads the
  broadcast. The listener does no I/O. It keeps a change only for a
  **local** actor (a remote member's list lives at their own home
  provider) with a **live connection** (the change committed before it was
  announced, so a client that connects later reads it). Each is a
  `(group, actor)` key in a coalescing set. A second task resolves each
  key: the actor's entry is read afresh and sent as changed, or as
  removed when there is none. A fresh read makes ordering and duplicates
  harmless, because the last event always carries the state at the time.
- **Group deletion** (`groups/ending.rs`). The purge removes the
  membership rows through which a member's list is found, so each
  membership is first **ended**: a new `ended` status, invisible to every
  read. That happens in pages of 500, each one guarded write,
  `Membership.filter(.group_id == g && .status == "active").limit(500)
  .update({status: "ended"})`. It returns exactly the rows it wrote
  (compare-and-set per object since rhypedb #59, decision 0012), and
  those members are named to the listeners. A short page may have lost
  rows to a race (`.limit` picks before the re-check), so the loop ends
  only when a plain read finds no active row; only then does
  `delete_group` purge. Otherwise (a failed page, or five pages in a row
  that ended nothing while rows remained) the purge is left to the
  sweeper. Its `finish_deletion` names every `ended` row again (offset
  paging: ended rows never change, and `remove_member` leaves them alone,
  so the pages are stable), because a failed page may have committed
  without anyone being named. It then ends the rest, names the owner, and
  purges. The owner is named by `delete_group` as soon as the group is
  hidden. Nothing per member goes on the broadcast: the WebSocket
  follower re-checks subscriptions per channel, and `delete_group`
  already names every channel and the group. So a group of any size
  cannot overflow the broadcast and force a full re-check. (rhypedb's
  limited index scans counted deleted rows before 7b78190 #61; the pinned
  commit has the fix, so `limit` pages are exact.)
- **Ownership transfer** (membership branch) announces `Member` for both
  the old and the new owner after `Group.owner` has changed, so the fresh
  read gives `owner` and the old owner's new role.
- **Spurious events.** A failed membership write is announced too
  (decision 0014: it may have committed). The fresh read then reports the
  entry as it is, which can be a `removed` for a group the user was never
  in. Clients treat a removal of an entry they do not hold as a no-op.

### Nothing is dropped quietly

The listener cannot lag. Changes can still be lost in two ways, and the
spec has no way to say "your list changed in ways I cannot name".
Resending the full list as `groups` cannot express removals, so it would
leave a client holding groups it has left. Instead, only the actor the
lost change concerns loses their connections, never anyone else (an
earlier draft closed every local connection, `1013`, when the broadcast
lagged, which a single large group's deletion could trigger):

- **The coalescing set is full** (65,536 distinct waiting changes,
  `AppStateBuilder::group_list_backlog`, which tests set to `0`). That is
  an outbound overflow, as from a slow consumer, so the §7.1 close
  applies: an `error` `too_many_requests` (`429`) with
  `details.retryAfter` (5 seconds, as the backlog drains at database
  speed), then `1013`. This provider already uses that close for a slow
  consumer (decision 0010). A key already waiting always fits: it
  coalesces.
- **The entry cannot be read or encoded.** That is the provider's
  fault, not the client's, so the close is not a slow-consumer one: an
  `error` `internal_error` (`500`), then `1011`.

Nothing missed while disconnected is replayed, so a reconnecting client
re-reads `GET /api/me/groups`. The close is rare, and it never leaves a
list silently wrong.

## Consequences

- Clients get one list for all their devices, with live updates. A pointer
  stays unchecked by design: a wrong one misleads only its owner's list.
- The `updatedAt` of a hosted entry moves on a role change or a transfer.
  Rows written before those columns existed date from the join or the
  group's creation.
- If the provider ever runs as several processes, the pointer lock must
  become a shared one, or event order between devices weakens (data stays
  correct).
