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
//! 3. **Delete** the row.
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
        let retired = self
            .store
            .retire_member(group_id, actor, self.now())
            .await?;
        if retired.is_some_and(|m| m.transfer_id.is_some())
            && let Err(e) = self.fence_transfer(group_id, actor).await
        {
            self.store.restore_member(group_id, actor).await?;
            return Err(e);
        }
        Ok(self.store.remove_member(group_id, actor).await?)
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
            if !self.store.claim(&next, self.now()).await? {
                lost_claim(attempt).await;
                continue;
            }
            if self.store.fence(&group).await?.is_some() {
                return Ok(());
            }
        }
        Err(GroupError::Conflict("the group kept changing; retry"))
    }
}
