//! Ending a membership (the §5.7 seam behind leave and kick), safe against
//! an ownership transfer to the same member running at the same time
//! (docs/decisions/0020, "Leaving during a transfer").
//!
//! A transfer to member B marks B's row, reads the group, checks B's row is
//! still active, and commits with a compare-and-set on the revision it read
//! (`transfer.rs`). Removing B therefore goes:
//!
//! 1. **Retire** B's row: one guarded write makes it `leaving`, which is no
//!    longer a membership, and answers the row as it was at that instant.
//!    From here on no transfer can mark B nor pass its check.
//! 2. If the row carried a transfer's mark, **fence** the group: move it to
//!    its next revision under that revision's claim, guarded on the owner.
//!    A transfer that passed its check read an older revision, so it can no
//!    longer commit. If one committed first, B owns the group: the row is
//!    made active again (the transfer's finisher removes it) and the
//!    answer is `409`.
//! 3. **Delete** the row, guarded on it still being the `leaving` row step
//!    1 wrote (its status and stamp), so a removal that stalled until the
//!    sweeper removed the row never deletes a row a rejoin wrote since.
//!
//! With no active row at step 1, a pending one (a join still being
//! recorded) is deleted instead.
//!
//! A row without a mark at step 1 cannot be the target of a transfer that
//! still commits: any transfer that checked it had marked it first.

use re_ofscp_types::Actor;

use super::Groups;
use super::claims;
use super::ops::{GroupError, UPDATE_ATTEMPTS, lost_claim};

const TRANSFERRED_FIRST: &str = "an ownership transfer to this member completed first";

impl Groups {
    /// End a membership (the §5.7 seam), pending or active; a no-op if
    /// there is none. `409` if an ownership transfer to `actor` committed
    /// first (they own the group now) or the group kept changing while
    /// this made sure no transfer could. Announces the change.
    pub async fn remove_member(&self, group_id: &str, actor: &Actor) -> Result<(), GroupError> {
        let removed = self.retire_and_remove(group_id, actor).await;
        // Once, whatever happened: even a failed write may have committed,
        // and a spurious announcement costs only a re-check.
        self.member_changed(group_id, actor);
        removed
    }

    /// Steps 1 to 3.
    async fn retire_and_remove(&self, group_id: &str, actor: &Actor) -> Result<(), GroupError> {
        let retired_at = self.now();
        let Some(retired) = self
            .store
            .retire_member(group_id, actor, retired_at)
            .await?
        else {
            return Ok(self.store.delete_pending_member(group_id, actor).await?);
        };
        if retired.transfer_id.is_some()
            && let Err(e) = self.fence_transfer(group_id, actor).await
        {
            // The fence's error is the answer. A row left `leaving` is no
            // membership, and the sweeper deletes it after `PENDING_TTL`.
            if let Err(restore) = self.store.restore_member(group_id, actor, retired_at).await {
                tracing::warn!(group = %group_id, member = %actor, error = %restore,
                    "putting back a membership after a failed removal failed");
            }
            return Err(e);
        }
        Ok(self
            .store
            .delete_retired_member(group_id, actor, retired_at)
            .await?)
    }

    /// Step 2: make sure no transfer of `group_id` to `actor` prepared
    /// before now can commit. `409` if one already has.
    async fn fence_transfer(&self, group_id: &str, actor: &Actor) -> Result<(), GroupError> {
        for attempt in 1..=UPDATE_ATTEMPTS {
            let Some(group) = self.store.group(group_id).await? else {
                // Gone or being deleted: nothing can commit.
                return Ok(());
            };
            if group.owner == *actor {
                return Err(GroupError::Conflict(TRANSFERRED_FIRST));
            }
            let next = claims::group_key(&group.id, group.revision.saturating_add(1));
            let claimed_at = self.now();
            if !self.store.claim(&next, claimed_at).await? {
                lost_claim(attempt).await;
                continue;
            }
            if self.store.fence(&group).await?.is_some() {
                return Ok(());
            }
            // Wrote nothing: free the revision for the retry (claims.rs).
            self.store.release(&next, claimed_at).await?;
        }
        Err(GroupError::Conflict("the group kept changing; retry"))
    }
}
