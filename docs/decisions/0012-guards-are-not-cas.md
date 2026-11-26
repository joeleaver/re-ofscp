# 0012: Guarded updates are not compare-and-set; serialize with `@unique`

- **Status:** accepted
- **Date:** 2026-11-26

## Context

rhypedb (pinned c73cc88, and the jkbase-managed production server) has no
multi-statement transactions. Decision 0003 already noted that a filtered
write does not apply its condition atomically. A probe in the profiles
work (PR #16) showed what that means in practice:

- `T.filter(.k == v && .guard == old).update({...})` evaluates the filter on
  a snapshot, then updates each matching object in its own transaction,
  which re-reads the object by id and **never re-checks the predicate**.
- So two concurrent updates guarded on the same old value can **both**
  match and **both** apply, with no error. Two racers did so in about one
  round in five.
- A concurrent write that does overlap on the same object may instead
  fail with `engine error: write conflict` (`DbError::Contended`). Nothing
  of that object was written.
- A write naming an object id that no longer exists fails with
  `engine error: object not found: …` (`DbError::NotFound`). This includes
  a filtered `delete` whose snapshot named a row someone else deleted
  first: the statement stops there.
- A `create` on a `@unique` field **is** atomic: of 32 concurrent creates
  of one key, exactly one succeeds. The others get `Conflict` (or,
  occasionally, `Contended`, after which a retry gets `Conflict`).

Several call sites used a guard as if it were compare-and-set. The
security-relevant ones: TOTP code replay protection (`totp_last_step <
step`), the admin credential epoch (`credential_epoch == e`), the
single-use account invite (`used == false`), and the replay ledger's
expired-row overwrite (`expires_at <= now`) and persisted clock
(`high_water < X`).

## Decision

**The rule.** A filter guard only narrows which rows a write touches. It
never decides a race. When the outcome of concurrent writers matters (who
wins, and that only one does), serialize them with a `@unique` create,
and let only the creator proceed. Don't rely on an in-process lock for
it either: it does nothing across processes, and two processes briefly
overlap during a deploy.

**The pattern (a claim).**

1. Name exactly what the writers compete for, as a key: a step, an epoch,
   a token, a revision. Put the key in a `@unique` field of a row that is
   only ever created and deleted, never updated.
2. Do every check that needs no serialization first (the code verifies,
   the password matches). A claim made before that would let anyone burn
   the key.
3. Create the claim. `Conflict` means someone else holds it: you lost.
   `Contended` means nothing was written: look again, then retry.
4. Only the creator performs the guarded write. It may keep its guard, now
   uncontested. A write that finds the row no longer matching means it
   was stale: report that, and drop the claim if it guards nothing.
5. Give a claim an expiry when its holder could die before finishing (a
   lease). An expired claim may be taken over: delete it **by id**, so a
   fresh claim made meanwhile is untouched, then create again. Treat
   `NotFound` and `Contended` on that delete as "someone else deleted it".
6. Purge expired claims in the background. Because claims are never
   updated, a filter over them (`expires_at <= now`) is exact, and a
   purge never deletes a live one.

For a value that must only go up (a clock), use the same idea: create a
new row per value, take the maximum when reading, and delete only rows
below a value whose row exists.

**Leave a guard alone, with a comment saying why, when the race is
harmless:** the write is idempotent and one-way (`revoked == false` →
`true`), all racers write the same value, or the loser's effect cannot
grant anything (a role landing on an admin who was just disabled).

### Where it is applied

- **TOTP codes** (`admin/claims.rs`, `AdminClaim`). After a code verifies,
  its step is claimed as `totp-step:{username}:{step}` before the sign-in
  (or the enrollment confirmation) is accepted. A duplicate means the code
  was used: refused. Claims live for a day (a code verifies for 90 s), and
  `Admin.totp_last_step` stays as the highest used step, so a code older
  than that is refused even after its claim is purged.
- **Credential epochs** (`AdminClaim`, `epoch:{username}:{epoch}`). A
  password change, a TOTP confirmation and a TOTP reset each move the
  admin from epoch `e` to `e + 1`, and each first claims `e + 1` with a
  120 s lease. Before, a password change and a reset read at the same
  epoch could both apply and both stamp `e + 1`, so the reset would not
  end the session the password change had just re-stamped. The lease is
  longer than the data layer's 10 s query timeout, so a holder's update
  cannot still be running when the lease is taken over.
- **TOTP enrollment.** `confirm_totp` changes the secret and the epoch, so
  it is serialized by the epoch claim (and its code by a step claim).
  `set_totp_pending` stays unserialized: a pending secret left beside an
  enrolled one, or surviving a reset, grants nothing. Only a confirmation
  reads it, and it enrolls exactly the secret its caller proved a code for.
- **Account invites and registration** (`accounts/pending.rs`,
  `accounts/invites.rs`). Two serialization points, in this order: the
  handle, then the invite.
  - **The handle first.** A registration creates the `User` row before
    touching the invite, with `pending: true`, the invite's hash and a
    random `pending_key`. Handles are `@unique`, so of any registrations
    (with any invites) and admin creates of one handle, exactly one holds
    it. A loser gets `409` and **its invite is untouched**: it can still
    register another handle. (Before, the handle was only looked up before
    redeeming, holding nothing: two invites racing for one handle both
    redeemed, one account create won, and the other invite was left
    redeemed for a handle someone else owned, burned for good.)
  - **Then the invite** (`InviteRedemption`, `@unique` on the token hash,
    recording the handle). The holder of the pending row redeems the invite
    for its handle, then marks it used (`used: true, used_by`). The
    redemption is never updated, deleted or taken over, so the invite can
    only ever make an account with that handle, and that handle holds at
    most one account: **one invite makes at most one account**, however
    requests race, stall or crash. A `Conflict` on the redemption reads it:
    another handle means the invite is spent, so the registration discards
    its pending row and answers `403 invite_required`; the same handle goes
    on.
    - **Why not a leased invite claim.** An earlier revision used an
      `InviteClaim` with a 120 s lease that a later registration could take
      over. A holder that stalled past the lease before its `used == false`
      update could then race the taker's; neither is compare-and-set, so
      both could make an account. A redemption that is never released has
      no such window.
  - **Then activation, decided by a settlement.** A pending row ends in
    exactly one of two ways, recorded by an `AccountSettlement` row,
    `@unique` on the row's `pending_key`, never updated or deleted:
    `activate` (created only by a registration whose redemption names the
    row's handle; then `pending` is set to false) or `discard` (then the row
    may be deleted by id; object ids are never reused). The outcomes
    exclude each other, so a row being activated is never deleted, and a
    discarded row is never activated, however late either write lands.
    Activation writes only `pending: false`, and nothing sets it back or
    writes it otherwise, so a late or repeated activation cannot undo a
    disable (which writes `status`).
  - **Pending rows are invisible.** `AccountStore::find_user` (login,
    key lookup and registration, `/.well-known/ofscp/users/*/keys`, admin
    disable, federation key resolution), and profiles (so discovery and
    every profile surface) treat a pending row as no account. The admin
    listings show it with the status `pending`. Its password cannot be
    used, and it has no keys, as a bootstrap token is issued only for an
    activated account.
  - **Meeting a pending row.** A create (registration or admin) that hits
    `Conflict` reads the holder:
    - an account: `409`;
    - settled `activate`: an account whose holder crashed before
      activating; the create finishes the activation, and it is taken;
    - settled `discard`: deleted, and the create retried;
    - unsettled and made with the creator's **own invite**: joinable. A
      registration that proves the row's password (Argon2 verify) joins it:
      it redeems for the same handle and activates the same row, so a
      retried or duplicated request finishes the registration rather than
      racing it. Another password is a rival: `409`.
    - unsettled, another invite (or an admin), and **live**: `409`;
      **stale** (older than `PENDING_LEASE_SECS`, 300 s): settled `discard`
      and deleted, and the create retried. The lease is fairness, not
      safety: the settlement decides every race, so a stalled holder racing
      a reclaimer either activates (the reclaimer then finds it taken) or
      finds it discarded (`409`).
  - **Crash and failure windows.** Each fails closed:
    - *After the pending create, before redeeming:* the invite is
      unredeemed and usable for any handle. The same handle, invite and
      password finish it at once; anything else waits for the lease, then
      reclaims the handle.
    - *After redeeming, before marking used:* the invite still reads
      `used == false`, but every read that calls an invite usable (the
      admin list, the outstanding-invite cap, registration's own redeem)
      also checks for a redemption, and revoking it reports it used. Every
      other handle is refused; its own handle resumes.
    - *After marking used, before activating:* the invite reads used by
      that handle. Registration's `used_by` check refuses every other
      handle, and lets the same handle on only while it has no account;
      a pending row is not one, so the retry joins it.
    - *After settling `activate`, before activating:* the next create
      meeting the row finishes it. The account then exists with the
      password of the request that settled it.
    - *A stalled request whose row was reclaimed:* it finds its row
      discarded and answers `409`. It reads the settlement before redeeming,
      so normally its invite stays unredeemed; only a discard landing
      between that read and the redemption leaves the invite spent on a
      handle someone else now owns (the admin issues a new one).
  - **`used` is a mirror** of the redemption, written only by requests
    holding it (all with the same handle), so its guard (`expires_at >
    now`) decides nothing. Registration needs no in-process lock.
- **Replay ledger** (`replay/ledger.rs`). Rows are now never updated.
  - **Expired-row reuse:** §4.5 permits reusing a nonce after its window.
    The ledger now persists the clock (at least `now`), deletes the
    expired row by id, and creates a new one. Concurrent reusers compete
    in the `@unique` create, so exactly one is recorded. Before, the
    in-place guarded overwrite let all of them succeed: a replay accepted
    across processes. Within one process the in-memory store already let
    only one through. Losing the row to a crash before the create is
    harmless: the persisted clock keeps the old use expired, exactly as
    for a purge, and the new use has not been accepted yet.
  - **Purge:** since no row is ever revived in place, a purge can no
    longer delete a row just made live, and the in-process purge gate is
    gone.
  - **Clock:** `ReplayClock` holds one row per persisted value
    (`replay@{secs}`); the clock is the highest, and rows below it are
    pruned. rhypedb has no sort, and reading with `offset` pages while a
    prune deletes rows can skip the highest (the rest shift into a page
    already read). Each statement reads a snapshot, and every snapshot
    holds the highest row, so the read raises a floor instead: a page
    that is not full holds every row above the floor; a full one raises
    the floor to its maximum, logs that pruning lags, and the next
    statement reads only rows above it. Before, two writers could pass `high_water < X` and leave the
    lower value. The first deployments' single `"replay"` row is read like
    any other row and pruned once a higher value is written, so no
    migration step is needed.
  - **What a lost race would have broken.** Nonce replay acceptance, as
    above. The warm-up is unaffected: it depends only on whether the
    ledger can be read at startup. The nonce is still recorded atomically
    and only after the signature verifies (the in-memory store, under its
    lock, then the `@unique` create; CLAUDE.md security requirement 2).

### Reviewed and left alone

- `DeviceKey` revocation (`revoked == false`): idempotent and one-way.
- `RegistrationInvite` revocation (`expires_at > now`): all racers write
  the same expiry, and a redemption racing it is an in-flight registration.
- `Admin.set_role` (`status == active`): a role landing on an admin just
  disabled grants nothing.
- `profiles::update_profile` (`status == active`): a change landing on an
  account just disabled is never served.
- `FederationSetting` mode: last-writer-wins by design, no guard, serialized
  in-process; a first-write race across processes meets the `@unique` name.
- `Admin.totp_last_step` raise: advisory, as above.

## Consequences

- **New types and fields, added only.** `AdminClaim`, `InviteRedemption`
  and `AccountSettlement` are new types, and `User.pending`,
  `User.invite_hash` and `User.pending_key` new optional fields (absent on
  existing accounts, which read as not pending); rhypedb applies added
  types and fields without a migration (its `migrations.md`).
  `ReplayClock` is unchanged in shape; only how its rows are used changed.
- **A credential change or sign-in costs one more write** (the claim), and
  an expired-row reuse two more (the clock and the delete). These are rare
  paths or ones already doing several writes.
- **A crash mid-change blocks that admin's next credential change** for up
  to 120 s, until the lease expires.
- **An invite redeemed by a request that crashed or failed before making
  its account** is spent on that handle: only a registration for that
  handle can finish it. A registration's own crash holds its handle for
  up to `PENDING_LEASE_SECS` (300 s) against rivals; its own retry, with
  the same password, finishes at once.
- **Settlements and redemptions are never deleted.** One small row each
  per registration, which invites already bound. A purge would need its
  own design (a settlement may be deleted only once its row is gone or
  activated, and a redemption never while its invite is live).
- **Handles are never reused, and any future account delete must deal
  with redemptions.** The invite bound relies on a handle holding at most
  one account, ever: an invite redeemed for a handle could make a second
  account there if its account were deleted. A future account deletion
  must therefore keep the handle reserved (or mark every redemption naming
  it as spent, and invites used, before freeing it), and must leave
  pending rows to the settlement protocol rather than deleting them by
  filter.
- **New code that needs a conditional write follows the pattern.** Code
  review rejects a guard used as compare-and-set. Example: a
  revision-guarded PATCH (`If-Match: rev`) claims `{object}:{rev + 1}`
  before writing revision `rev + 1`.
- **If rhypedb ever re-checks the predicate inside each object's
  transaction,** guards become real compare-and-set. The claims stay
  correct, and could then be simplified, deliberately, in their own PR.
