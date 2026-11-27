# 0019: Group invites

- **Status:** accepted. The validation defaults and the redeem order are
  in the spec since lost-conn/ofscp#35 (merged, fb0c064); token secrecy,
  the list without tokens and the deleted-channel answer since
  lost-conn/ofscp#40 (merged, e94447d).
- **Date:** 2026-11-27
- **Spec:** §5.6 (invites and join links, as clarified by
  lost-conn/ofscp#35 and lost-conn/ofscp#40), §5.7 (the subset rule), §4.8
  (guests), §7.2 (paging), §11 (private tiers); schemas `invite.json`,
  `invite-create-request.json`, `invite-create-response.json`
- **Security requirements:** 1 (identity is `(handle, domain)`),
  6 (private groups are invite-only)
- **Builds on:** 0012 (serialize with `@unique`), 0014 (groups),
  0017 (membership: `add_member`, the subset rule, paging), 0004 (account
  invite tokens)

## Context

§5.6 lets a group `manage`r mint a join link carrying a secret token.
Redeeming it joins the group with the invite's role, whatever the group's
`joinPolicy`, and it is the only way into a private group (§11). The spec
leaves open what an invite may grant, what happens when a member redeems
one, and how uses are counted. rhypedb has no multi-object transactions.

## Decisions

### Creating an invite (`POST /api/groups/{g}/invites`)

The caller must hold `manage`; that is checked before the body is even
parsed (0014), so a caller without it gets `403` whatever they send and
learns nothing from how a body would be judged. Then:

1. **Role.**
   - It defaults to `member`.
   - `owner` is `400`: ownership is only ever transferred.
   - A role that is neither canonical nor in the group's `roles` is `400`.
2. **The subset rule binds the role** (§5.7): `perms(role) ⊆
   perms(creator)`, or `403`. An admin cannot mint a link to a role
   holding a permission the admin lacks.
3. **`channelId`** must name an active channel of the group, or `400`.
4. **`grantsGuest: true`** is `400`. This provider offers no guest
   accounts (§4.8 lets a provider decline them), and the problem detail
   says so. `false` and absent are the same.
5. **Bounds (provider policy).**
   - `maxUses` is in `1..=1000`. Absent means unlimited.
   - `expiresAt` must be in the future and at most a year ahead. Absent
     means it never expires.
6. **A group holds at most 50 invites**, counting expired ones until the
   sweeper deletes them. The count runs before the write and again after
   it, and a write found over the limit takes itself back (`403`), as
   for members (0017).

The response is `201` with the `Invite`, including `token`
(`invite-create-response.json`; ofscp-core's `InviteCreateResponse`,
whose `token` is required).

### Tokens

A token is `gi_` followed by 256 random bits (base64url) from the OS
CSPRNG (`getrandom`), well past the 128 bits §5.6 requires. It is a bearer
secret, so the provider:

- stores only its SHA-256 (`GroupInvite.token_hash`, `@unique`), as §5.6
  recommends: a presented token is digested and looked up;
- never logs it. `Invite`'s `Debug` redacts it. The request span and the
  signed-request rejection log pass paths through `logpath::loggable`,
  which turns `/api/invites/{token}/…` into a placeholder;
- returns it exactly once, in the create's response.

A token of the wrong shape (another prefix, or longer than 128 characters)
is `404` without a lookup.

### Listing (`GET /api/groups/{g}/invites`)

- Needs `manage`.
- Expired invites are left out.
- The list is paged per §7.2 by `(createdAt, id)`, newest first by default,
  in the same `{items, page}` shape as the member and request lists.
- **Items carry no `token`.** It is not stored, so it cannot be listed,
  and §5.6 lets a provider omit it from every `Invite` but the create's
  (lost-conn/ofscp#40). Each item is a valid `Invite` (`invite.json`).
  This is the same choice the admin API made for account invites (0004),
  where the token is shown once. A manager who needs the link again makes
  a new invite and revokes the old one.
  - In ofscp-core, `Invite.token` is therefore `Option<String>`, skipped
    when absent. This is a breaking change for its users (Postrinch).
  - The alternative was sealing tokens with a server-held key so the list
    could return them. That needs a new required secret, and it widens
    what a stolen key exposes.

### Revoking (`DELETE /api/groups/{g}/invites/{i}`)

- Needs `manage`, and answers `204`.
- An id the group does not have is `404`.
- The invite row is deleted first, then its use slots (below). A
  redemption that takes a slot after the delete finds the invite gone,
  gives the slot back and answers `404`. So no use begun after a
  revocation admits anyone.

### Redeeming (`POST /api/invites/{token}/redeem`)

The request must be signed by a user, local or remote. Unsigned is `401`
and a provider signature is `403`. A remote `alice@providerb.example`
redeems as herself, so she and a local `alice` are different members.

The invite is checked first, whoever the caller is (§5.6,
lost-conn/ofscp#35). The checks run in this order:

1. An unknown, revoked or expired token, or one whose group is gone or
   being deleted, is `404`.
2. A limited invite whose slots are all taken is `409`. Members and the
   owner get this too.
3. **Only for a valid invite: someone who already belongs, the owner
   included, gets `200` with their current role.** No use is taken, and
   their role is never changed, whether the invite's role is higher or
   lower.
4. **The invite must still grant its role, or `403`.** That means:
   - the role still exists;
   - its creator still holds `manage`;
   - the role is within the creator's permissions (the subset rule
     again).

   So an admin who is demoted or removed leaves no link behind that
   outranks them. If they are restored, the link works again. §5.6 allows
   `403` for "provider/group policy forbids". This is provider policy
   rather than part of the invite's validity, so it comes after the
   membership check, and a member is still answered `200`.
5. If the invite is limited, the redemption takes a use slot (below).
   When the last slot went to a concurrent redemption, the answer is
   `409`.
6. The caller joins with the invite's role through `Groups::add_member`.
   So the member and membership limits, the pending-row protocol, the
   take-back of a join over the limit, the `AccessChange::Member`
   announcement and `groups.updated` (0018) all apply exactly as for any
   join. A pending join request of the caller's is resolved by the join
   (deleted, as approval does), not left for a reviewer.
   This works for `private` groups and `invite`/`request` policies, which
   is what an invite is for.

The response is `200 {groupId, channelId?, role}`:

- `role` is the caller's role as read back after the join.
- `channelId` is the invite's channel when it has one and that channel
  still exists (lost-conn/ofscp#35, #40), in the already-a-member answer
  too. A deleted channel does not void the invite: the caller still joins
  the group, and the answer omits `channelId`.

### Counting uses without transactions

The question is how two concurrent redemptions of a `maxUses: 1` invite
are kept from both joining. Following 0012, a limited invite's uses are
**slot rows**:

- Each slot is a `GroupInviteUse` whose `@unique` `slot` is
  `"{inviteId} {n}"`, for `n < maxUses`.
- A redemption reads the slots taken, then creates the first free one.
  On a `Conflict` (another redemption won that slot) it tries the next.
  When every slot is taken, it answers `409`.
- A create that lost a write conflict (`Contended`) wrote nothing, so the
  same slot is tried again, as for any one-object write. Moving on would
  have answered `409` with a slot still free. A conflict that outlasts
  the retries is a server error, never a `409`.
- Slots are only created and deleted, never updated.

A redemption that took a slot but did not join gives the slot back by
deleting it. That covers:

- `add_member` failing (for example, the group is full);
- finding the caller already a member (a concurrent redemption or join);
- finding the invite revoked.

If the process dies, or the database fails, between taking a slot and
giving it back, the use stays consumed. That error is in the safe
direction: an invite can only ever admit fewer people than it allows,
never more. Each slot records its actor and time, so a consumed use can
always be accounted for.

Leaving a group does not return the use. `maxUses` counts redemptions,
not current members.

An **unlimited** invite has no limit to defend, so it takes no slot.

**`uses` is a display counter on the invite row, for every invite.** It
is bumped after each join by an update guarded on the old value. Since
rhypedb #59 that update is compare-and-set per object, so concurrent bumps
all count. A bump loses only to another bump that landed, and it retries
up to 64 times. A bump that gives up, or fails, is logged and costs
nothing else: `uses` may then read one low, while the slots still enforce
`maxUses` exactly. The list reads this counter, so it is one bounded read
of at most 50 rows. Counting slot rows instead would read up to 50,000
(50 invites of 1,000 uses).

### Guests (`POST /api/invites/{token}/guest`)

Since lost-conn/ofscp#35, a guest would always join with role `guest`,
and the invite's `role` applies only to `/redeem`. This endpoint is
nevertheless always `403`, whether or not the request is signed and whatever
the token (confirmed by the oracle). Guests are optional (§4.8), and no
invite here can carry `grantsGuest: true`.

### Cleanup

- A group's purge deletes its invites and their slots (`purge_group`).
  An invite written while the group was being deleted finds the group
  gone and takes itself back.
- Each sweeper pass deletes up to 500 expired invites, with their slots.
  An invite without `expiresAt` has no such field. It never matches
  `.expires_at <= now`, so it is never swept.
- A slot left behind by a failure between a revocation's two deletes is
  inert, because invite ids are never reused. It goes with its group.

## Consequences

- A manager cannot recover a lost link. They make a new invite and revoke
  the old one.
- Listing reads at most 50 invite rows and no slots. Its `uses` is a
  display count that a failed bump can leave low; the limit itself never
  depends on it.
- A crash mid-redemption can burn a use of a limited invite.
