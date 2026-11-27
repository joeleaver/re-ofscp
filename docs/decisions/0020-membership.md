# 0020: Group membership

- **Status:** accepted. The spec-gap defaults below were confirmed by the
  OFSCP oracle on 2026-11-27 and are in the spec as lost-conn/ofscp#35;
  stale join requests are lost-conn/ofscp#39.
- **Date:** 2026-11-27
- **Spec:** §5.7 (join, leave, members, role changes, kicks, nicknames,
  `member.updated`, join requests), §5.5 (`Group.membership`), §7.2
  (paging), §8.2 (remote members, the channel join alias), §11 (private
  tiers); schemas `member.json`, `join-request.json`, `group.json`,
  `ws/member-updated.json`
- **Security requirements:** 1 (identity is `(handle, domain)`),
  5 (access re-checked on every membership change), 6 (private groups are
  invite-only), 7 (no event to someone who cannot read the channel)
- **Builds on:** 0014 (groups, the owner as `Group.owner`, pending rows,
  revision claims), 0010 (live re-checks, the commit→hold window)

## Context

Decision 0014 left membership minimal: seams to add, re-role and remove a
`Membership` row. §5.7 adds the HTTP surface. It also leaves gaps: where
the owner sits in a member list, who may read the list, repeated joins,
and how ownership changes hands. rhypedb has no multi-object
transactions and no `ORDER BY`.

## Decisions

### Defaults for the spec's gaps

1. **The owner is a member.** The list shows the owner as
   `{user, role: "owner", joinedAt}`. The order is provider-defined but
   stable for paging. Here it is `(joinedAt, user)`, backward (newest
   first) by default. **An ownership transfer changes no one's
   `joinedAt`** (lost-conn/ofscp#35): the creator's is the group's
   `createdAt`, the new owner keeps the one their membership had
   (`Group.owner_joined_at`), and the former owner's new row is written
   with the one they held as owner.
2. **The list is for members.** A signed non-member gets `403`, even for a
   `public` group, and an unsigned request gets `401`. We don't use
   §5.7's MAY to leave hidden members (§6 `membershipVisibility`) out of a
   group's own member list: every member sees every member. Exposing a
   public group's list to non-members would be one function
   (`roster::outsiders_may_list`).
3. **Repeated joins.**
   - A join to a `request` group that already has a pending request from
     the caller answers `202` with that request.
   - After a deny, the next join makes a new request.
   - Approving someone who is already a member answers `200` with their
     `Member`.
4. **Leaving.** A caller who is not a member gets `404`, and the owner
   gets `409` (§5.7).
5. **Approve and deny** are not bound by the subset rule. The approved
   role is always `member`.
6. **Stale join requests** (lost-conn/ofscp#39; confirmed by Joe via the
   oracle 2026-11-27). A change of tier or `joinPolicy` keeps pending
   requests. While the effective join policy is `invite` (the policy, or
   a tier such as `private` that makes the group invite-only), approve
   answers `409` ("the group no longer takes join requests") and leaves
   the request pending. That check comes before the already-a-member
   `200`. Deny works under any policy; under `open` (or `request` again)
   approve admits as usual.
7. **A member has no pending request.** Becoming a member by any path
   (`add_member`: an open join, an approval, an invitation) deletes the
   actor's pending request, and a request written just as its asker
   became a member is taken back (the join answers `200`). So in practice
   approve never meets an already-member; the `200` case stays for the
   race.
8. **`member.updated`** is sent only when a role or `displayNameOverride`
   changes, never for joins, leaves or no-op writes. Both parties of a
   transfer get one.

### The surface

- Every route needs a user signature. Unsigned is `401` and a provider
  signature is `403`. Remote signers act exactly as local ones.
- A `{userRef}` resolves to a full actor (`profiles::user_ref::resolve_actor`):
  - a bare handle is a local user;
  - an actor or user URI names anyone, local or remote.

  So `alice` and `alice@providerb.example` are different members. A
  malformed reference is `404`.
- The channel alias `POST .../channels/{c}/join` (§8.2) answers exactly as
  the group join, whatever `c` names.
- Authorization comes before body validation (0014). The routes parse a
  body but hand its error to the operation, which answers it (`400`) only
  once the caller is authorized; a caller lacking permission gets
  `403`/`404` whatever it sends. For a role change the checks run in this
  order:
  1. `manage`;
  2. the role exists (canonical or catalogued), else `400`;
  3. `owner` routes to a transfer;
  4. acting on the owner (`409` for the owner, `403` for others);
  5. the target exists (`404`);
  6. the subset rule on the current role, then on the requested role.
- **The subset rule** is `access::may_act_on`. A role's permission set is
  the actions in the group's effective permission map that list it. The
  owner holds every action, and an unknown role holds none. The caller
  must hold a superset of the target's set.
- **Nicknames** are trimmed, at most 64 characters, and blank clears
  them. The owner has no row, so the owner's nickname is
  `Group.owner_display_name`. It is not part of the group's revision.
- **Join messages** are at most 500 characters (provider policy).
- **Limits.**
  - A group holds at most 10,000 members (`MAX_MEMBERS_PER_GROUP`).
  - An actor holds at most 1,000 memberships (`MAX_MEMBERSHIPS_PER_ACTOR`;
    `GET /api/me/groups` lists them all).
  - A group has at most 1,000 pending requests.

  Each limit is checked before the write and counted again after it. A
  write found over a limit takes itself back (`403`). A row left for a
  group's owner by a transfer is not a membership: it counts neither
  toward the group's members nor toward the actor's memberships.
- **A transfer** gives the new owner an owned group and the former owner
  a membership, so it checks `MAX_GROUPS_PER_OWNER` for the one and
  `MAX_MEMBERSHIPS_PER_ACTOR` for the other just before its commit
  (`403`). It cannot take itself back after committing; a group create or
  a join by the same actor racing it recounts after its own write and
  backs out instead, so only a create or join whose recount ran before
  the commit can overshoot, by one.
- `GET /api/groups/{g}` adds the caller's own `membership` and is sent
  `Cache-Control: private, no-cache`, since the body differs per caller.

### Paging

rhypedb cannot order, so the member and request lists are read whole and
sorted in memory. The group limits above keep that bounded.

- A cursor is opaque base64url of `"{list scope}\n{at}\n{id}"`. A cursor
  from another list or group is `400`.
- `limit` is lenient (§7.2): it defaults to 50, is clamped to 100, and a
  bad value falls back to the default.
- `nextCursor` is present only when more items follow.
- `prevCursor` marks the first item, and is sent only when items lie
  before it.
- The request list has the same `{items, page}` shape, ordered by
  `(requestedAt, id)`.

### Join requests

- `JoinRequest` rows exist only while their request is pending. Approve
  and deny delete them, and a group purge deletes them too.
- `key` (`@unique`, `"{group} {actor}"`) holds at most one pending request
  per actor.
- A request written while the group was being deleted is taken back.

### Ownership transfer

A transfer from owner A to member B touches three objects: B's old
membership, A's new one, and the group. Each attempt runs, under one
transfer id (`xfr_…`; `groups/transfer.rs`):

1. **Mark B's row** with the transfer id (`Membership.transfer_id`),
   `404` if B has no active membership.
2. **Read the group** afresh (finishing any earlier transfer), and check
   the limits above.
3. **Write A's row**: an active `admin` membership with A's nickname and
   A's `joinedAt`, and no mark. While A owns the group every read and
   count ignores it (standing checks the owner first), so a crash here
   changes nothing anyone sees.
4. **Check B's row** is still active. This comes after the read in
   step 2, which is what lets a removal fence the transfer (below).
5. **Commit**: one compare-and-set of the group under the next revision's
   claim, guarded on the revision, the owner and the owner's nickname as
   read in step 2. It sets `owner = B`, B's nickname and `joinedAt` as the
   owner's, and `transfer_from = A`, `transfer_id`. Both A and B are
   announced (`AccessChange::Member`) even if the write errored.
6. **Finish**: if B's row (found by key *and* transfer id) holds a
   nickname other than the group's, carry it to the group, guarded on the
   group still carrying the transfer id; delete the row carrying the id;
   clear `transfer_from`/`transfer_id`.

Recovery and races:

- Every membership change first finishes a marked transfer
  (`Groups::settled_group`), and so does each sweeper pass.
- **A late finisher never deletes a newer row.** It deletes only the row
  carrying its transfer id. A later transfer away from B resets B's row
  with no mark, and a rejoin writes a fresh row with none. Finishing
  never writes A's row, so it cannot undo B demoting or kicking A.
- **Nicknames.** The owner's nickname is not part of the revision, so the
  commit guards on it instead. At rhypedb 7b78190 an absent field matches
  neither `== null` nor `!= null`, while an explicit `null` matches
  `== null`. So a group is created with an explicit `null`, and the
  commit guards on the nickname read in step 2, or on `== null` when it
  reads none and the field is present. A nickname A sets after step 2
  fails the commit, and the retry carries it to A's row. A group created
  before this change may have no field at all. Its commit cannot guard on
  it, and the transfer writes nothing to make it present, because such a
  write could clobber a nickname A sets at that moment. There, the
  update of A's prepared row (next sentence) is the only thing that keeps
  a racing nickname. A nickname write by A also updates a
  row prepared for A. A nickname B sets on their old row after step 4 is
  carried over by step 6. B's own write, seeing that B now owns the group,
  finishes the transfer first and then writes the group, so no finisher
  still running overwrites it.
- **Leaving during a transfer** (`groups/removal.rs`). Removing a member
  (leave or kick) first makes the row `leaving` in one guarded write,
  which answers the row as it was. A `leaving` row is no membership, can't
  be marked, and fails step 4. If that row carried a mark, the remover
  fences the group: it bumps the revision (claim plus compare-and-set,
  guarded on the owner) so that a transfer that passed step 4, having
  read an older revision, can no longer commit. Then it deletes the row.
  If the transfer committed first, B owns the group: the row is made
  active again for the finisher, and the removal answers `409`. A row
  without a mark can't be the target of a transfer that still commits,
  because any transfer that passed step 4 marked it first. The sweeper
  deletes `leaving` rows a crashed remover left (older than
  `PENDING_TTL`).
- A stray owner row left by an attempt that lost or crashed is ignored
  while its actor owns the group, and the next transfer from them resets
  it.

### `member.updated` and the commit→hold window

Decision 0010's window is closed the way decision 0017 closed it for
messages: `Hub::member_updated` delivers through `Hub::publish_to_readers`,
once per channel of the group (`GroupStore::channel_ids`). That reads the
group, the channel and the subscribers' memberships afresh after the
change's commit and delivers only to those who can read the channel now.
An event published just after a revoking commit therefore never reaches
the revoked subscriber, whether or not the group follower has applied the
change yet. It publishes `{groupId, member}` this way and also sends it
to the member's own connections. Every membership
change still announces `AccessChange::Member`, so leaving, kicks and
demotions end subscriptions with `access_revoked`.

## Consequences

- A stray owner row can exist. Every membership read and count ignores
  it, and `GET /api/me/groups` skips rows where the actor owns the group.
- A leave or kick of someone a transfer has marked bumps the group's
  revision. The revision is internal, so the only cost is a retry for a
  group edit racing it.
- Reading a whole list costs time proportional to the group's size. If a
  limit grows, rhypedb ordering or a materialized order will be needed.
