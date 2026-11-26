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
- **Account invites** (`InviteClaim`, `@unique` on the token hash). Only
  the claim's creator marks the invite used. Release marks the invite
  unused, then deletes the claim. Registration's in-process lock stays,
  for its release-before-anyone-looks ordering.
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
    pruned. Before, two writers could pass `high_water < X` and leave the
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
  the same expiry, and a claim racing it is an in-flight registration.
- `Admin.set_role` (`status == active`): a role landing on an admin just
  disabled grants nothing.
- `profiles::update_profile` (`status == active`): a change landing on an
  account just disabled is never served.
- `FederationSetting` mode: last-writer-wins by design, no guard, serialized
  in-process; a first-write race across processes meets the `@unique` name.
- `Admin.totp_last_step` raise: advisory, as above.

## Consequences

- **New types, added only.** `AdminClaim` and `InviteClaim` are new types;
  rhypedb applies added types without a migration (its `migrations.md`).
  `ReplayClock` is unchanged in shape; only how its rows are used changed.
- **A credential change or sign-in costs one more write** (the claim), and
  an expired-row reuse two more (the clock and the delete). These are rare
  paths or ones already doing several writes.
- **A crash mid-change blocks that admin's next credential change** for up
  to 120 s, until the lease expires.
- **An invite claimed by a request that crashed before marking it used**
  stays unclaimable while it still lists as usable. An owner revokes it
  and issues another, as for a registration that crashed after the claim
  before this change.
- **New code that needs a conditional write follows the pattern.** Code
  review rejects a guard used as compare-and-set. Example: a
  revision-guarded PATCH (`If-Match: rev`) claims `{object}:{rev + 1}`
  before writing revision `rev + 1`.
- **If rhypedb ever re-checks the predicate inside each object's
  transaction,** guards become real compare-and-set. The claims stay
  correct, and could then be simplified, deliberately, in their own PR.
