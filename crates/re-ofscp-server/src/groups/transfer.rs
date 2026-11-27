//! Ownership transfer (§5.7: `PATCH .../members/{userRef}` with role
//! `owner`), crash- and race-safe without multi-object transactions
//! (docs/decisions/0020, "Ownership transfer").
//!
//! The owner is `Group.owner`, never a membership row, so handing group `g`
//! from owner A to member B touches three objects: B's old membership, A's
//! new one, and the group. Each attempt, under one transfer id:
//!
//! 1. **Marks B's row** with the transfer id (`404` if B has no active
//!    membership). Removing B meanwhile sees the mark and fences the group
//!    (`removal.rs`).
//! 2. **Reads the group** afresh, and checks the limits B and A would
//!    exceed (`403`).
//! 3. **Writes A's row**: an active `admin` membership carrying A's
//!    nickname and `joinedAt`, with no mark. While A owns `g` it is ignored
//!    by every read and count, so a crash here leaves nothing wrong.
//! 4. **Checks B's row** is still active, after the read in step 2.
//! 5. **Commits**: one compare-and-set of the group under the next
//!    revision's claim, guarded on the revision, the owner and the owner's
//!    nickname read in step 2 (when that field was ever written). It sets `owner = B`, B's nickname and
//!    `joinedAt` as the owner's, and `transfer_from`/`transfer_id`.
//! 6. **Finishes** ([`Groups::finish_transfer`]): carries a nickname B set
//!    on their old row meanwhile to the group, deletes the row carrying
//!    this transfer's id, and clears the marker. Until then B's row is
//!    ignored, because B is the owner. Every membership change finishes a
//!    marked transfer first ([`Groups::settled_group`]), and so does the
//!    sweeper.
//!
//! Finishing deletes only a row carrying its transfer's id, never one
//! written since (a later transfer away from B resets B's row with no
//! mark), and never writes A's row, so it cannot undo a later change to A.

use re_ofscp_types::Actor;

use super::access::{Standing, roles};
use super::claims;
use super::member_ops::{
    NO_MEMBER, Updated, joined_unix, owner_joined_at, owner_member, row_member,
};
use super::model::{Handover, StoredGroup};
use super::ops::{GroupError, UPDATE_ATTEMPTS, announce_unless, lost_claim};
use super::{Groups, MAX_GROUPS_PER_OWNER, MAX_MEMBERS_PER_GROUP, MAX_MEMBERSHIPS_PER_ACTOR};
use crate::db::DbError;
use crate::db::doc::new_id;

const NOT_OWNER: &str = "only the owner may transfer ownership";
const TARGET_OWNS_TOO_MANY: &str = "that member owns the most groups this provider allows";
const OWNER_IN_TOO_MANY: &str =
    "you are a member of the most groups this provider allows, so you could not stay in this one";

/// How many times step 3 rewrites a row that vanished under it.
const PREPARE_ATTEMPTS: usize = 3;

impl Groups {
    /// Hand `group` from its owner `actor` to member `target`. Answers the
    /// new owner, then the former owner (now an `admin`); handing the
    /// group to its owner changes nothing.
    pub(super) async fn transfer_ownership(
        &self,
        actor: &Actor,
        standing: &Standing,
        group: &StoredGroup,
        target: &Actor,
    ) -> Result<Vec<Updated>, GroupError> {
        if *standing != Standing::Owner {
            return Err(GroupError::Forbidden(NOT_OWNER));
        }
        if target == actor {
            return Ok(vec![Updated {
                member: owner_member(group)?,
                changed: false,
            }]);
        }
        let gid = &group.id;
        let transfer_id = new_id("xfr_")?;
        for attempt in 1..=UPDATE_ATTEMPTS {
            // Step 1.
            if self
                .store
                .mark_transfer(gid, target, &transfer_id)
                .await?
                .is_none()
            {
                return Err(GroupError::NotFound(NO_MEMBER));
            }
            // Step 2.
            let group = self.settled_group(gid).await?;
            if group.owner != *actor {
                return Err(GroupError::Forbidden(NOT_OWNER));
            }
            self.check_transfer_limits(&group, target).await?;
            // The commit guards on the owner's nickname, unless it was never
            // written (a group from before it was written at creation),
            // which no filter matches; then only the nickname write's own
            // update of A's row (step 3) keeps it.
            let guard_nickname = group.owner_display_name.is_some()
                || self.store.owner_display_name_is_null(gid).await?;
            // Steps 3 and 4.
            self.prepare_former_owner(&group).await?;
            let to = self
                .store
                .member(gid, target)
                .await?
                .ok_or(GroupError::NotFound(NO_MEMBER))?;
            // Step 5. The lease runs from the clock at claiming.
            let next = claims::group_key(gid, group.revision.saturating_add(1));
            if !self.store.claim(&next, self.now()).await? {
                lost_claim(attempt).await;
                continue;
            }
            let written = self
                .store
                .transfer_owner(
                    &group,
                    guard_nickname,
                    &Handover {
                        to: target,
                        display_name: to.display_name.as_deref(),
                        joined_at: joined_unix(&to)?,
                        transfer_id: &transfer_id,
                    },
                    self.now(),
                )
                .await;
            // A failed write may have committed: both standings changed.
            announce_unless(&written, Option::is_none, || {
                self.member_changed(gid, actor);
                self.member_changed(gid, target);
            });
            let Some(handed) = written? else {
                continue;
            };
            // Step 6, then answer the group as finished (the nickname may
            // have been carried over).
            self.finish_transfer(&handed).await?;
            let now = self.store.group(gid).await?.unwrap_or(handed);
            let mut updated = vec![Updated {
                member: owner_member(&now)?,
                changed: true,
            }];
            if let Some(former) = self.store.member(gid, actor).await? {
                updated.push(Updated {
                    member: row_member(&former)?,
                    changed: true,
                });
            }
            return Ok(updated);
        }
        Err(GroupError::Conflict("the group kept changing; retry"))
    }

    /// The limits a transfer of `group` to `target` must respect (`403`):
    /// `target` gains an owned group, and the owner gains a membership.
    /// Checked before the commit; a group create or a join by the same
    /// actor racing it recounts after its own write and backs out.
    async fn check_transfer_limits(
        &self,
        group: &StoredGroup,
        target: &Actor,
    ) -> Result<(), GroupError> {
        let cap = MAX_GROUPS_PER_OWNER;
        if self.store.owned_count(target, cap + 1).await? >= cap {
            return Err(GroupError::Forbidden(TARGET_OWNS_TOO_MANY));
        }
        // `group` itself is not counted: its owner's row is no membership.
        if self.membership_count(&group.owner).await? >= MAX_MEMBERSHIPS_PER_ACTOR {
            return Err(GroupError::Forbidden(OWNER_IN_TOO_MANY));
        }
        Ok(())
    }

    /// Step 3: give the owner of `group` the active `admin` membership they
    /// will hold once it is handed on, with their nickname and their
    /// `joinedAt` (unchanged by the transfer, lost-conn/ofscp#35), and no
    /// transfer mark. A row already there (an earlier attempt's, or one a
    /// past transfer left) is reset to match.
    async fn prepare_former_owner(&self, group: &StoredGroup) -> Result<(), GroupError> {
        let owner = &group.owner;
        let nickname = group.owner_display_name.as_deref();
        let joined_at = owner_joined_at(group)?;
        for _ in 0..PREPARE_ATTEMPTS {
            // A new row is written at the clock's time, so it ages as any
            // pending row does; its `joinedAt` is set once it is active.
            self.write_member(
                &group.id,
                owner,
                roles::ADMIN,
                nickname,
                MAX_MEMBERS_PER_GROUP,
                self.now(),
            )
            .await?;
            if self
                .store
                .reset_former_owner_row(
                    &group.id,
                    owner,
                    roles::ADMIN,
                    nickname,
                    joined_at,
                    self.now(),
                )
                .await?
                .is_some()
            {
                return Ok(());
            }
            // A late finisher of a transfer to the owner removed the row
            // between the two writes: write it again.
        }
        Err(GroupError::Conflict(
            "the former owner's membership kept changing; retry",
        ))
    }

    /// Step 6: finish the transfer `group` records, if any. Idempotent, and
    /// safe to run late or twice (see the module docs). Announces both
    /// parties.
    pub(super) async fn finish_transfer(&self, group: &StoredGroup) -> Result<(), DbError> {
        let Some(transfer) = &group.transfer else {
            return Ok(());
        };
        let (gid, owner, id) = (&group.id, &group.owner, &transfer.id);
        if let Some(row) = self.store.transferred_member(gid, owner, id).await? {
            // A nickname the new owner set on their row after the transfer
            // read it. Guarded on the marker, so never after finishing.
            if row.display_name != group.owner_display_name {
                self.store
                    .carry_owner_display_name(gid, owner, id, row.display_name.as_deref())
                    .await?;
            }
            self.store.remove_transferred_member(gid, owner, id).await?;
        }
        self.store.clear_transfer(gid, id).await?;
        self.member_changed(gid, &transfer.from);
        self.member_changed(gid, owner);
        Ok(())
    }

    /// Finish every transfer a crash left unfinished (the sweeper's step).
    /// A failure is logged and left for the next pass.
    pub(super) async fn finish_transfers(&self) -> Result<usize, DbError> {
        let mut finished = 0;
        for group in self.store.unfinished_transfers().await? {
            match self.finish_transfer(&group).await {
                Ok(()) => finished += 1,
                Err(e) => {
                    tracing::warn!(group = %group.id, error = %e, "finishing an ownership transfer failed");
                }
            }
        }
        Ok(finished)
    }
}
