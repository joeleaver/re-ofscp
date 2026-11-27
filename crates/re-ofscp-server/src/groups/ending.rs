//! Ending a deleted group's memberships before its purge (spec §5.7 *My
//! groups*; docs/decisions/0018).
//!
//! Group lists find a member through their `Membership` row, which the
//! purge removes, so every membership is ended first and its member named
//! to the [`super::MembershipListener`]s. That happens in pages, however
//! many members the group has: each page is one guarded write that marks
//! up to [`MEMBERS_PAGE`] active rows `ended` and returns exactly those
//! rows (compare-and-set per object since rhypedb #59, decision 0012), so
//! each member is named by the write that ended them. Nothing goes on the
//! bounded [`super::AccessChange`] broadcast: live subscriptions are
//! covered by the group and channel changes `delete_group` already sends.
//!
//! An ended row is invisible to every read (they all want `active`), and
//! no other write touches it (`remove_member` leaves it), so a deletion the
//! sweeper finishes can name every ended row again: a page whose write
//! failed may still have committed without anyone being named.

use re_ofscp_types::Actor;
use serde::Deserialize;

use super::Groups;
use super::store::{GroupStore, status};
use crate::db::{DbError, Ql};
use rhypedb_client::Row;

/// Memberships ended, or read, per page.
pub(super) const MEMBERS_PAGE: usize = 500;
/// Pages in a row that may end nothing while active rows remain (each lost
/// a race with another write to the rows it picked) before the rest is
/// left to the sweeper.
const STALLED_PAGES: usize = 5;

#[derive(Deserialize)]
struct ActorRow {
    actor: String,
}

fn actors(group_id: &str, rows: Vec<Row<ActorRow>>) -> Result<Vec<Actor>, DbError> {
    rows.into_iter()
        .map(|r| {
            Actor::parse_canonical(&r.data.actor)
                .map_err(|_| DbError::Decode(format!("group {group_id}: bad member")))
        })
        .collect()
}

impl GroupStore {
    /// End up to [`MEMBERS_PAGE`] active memberships of `group_id`; the
    /// members whose row this write ended.
    async fn end_members_page(&self, group_id: &str) -> Result<Vec<Actor>, DbError> {
        let q = Ql::new("Membership.filter(.group_id == ")
            .str(group_id)
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(").limit(")
            .uint(MEMBERS_PAGE as u64)
            .raw(").update({ status: ")
            .str(status::ENDED)
            .raw(" })");
        actors(group_id, self.db.write_many::<ActorRow>(&q).await?)
    }

    /// Whether `group_id` still has an active membership.
    async fn has_active_member(&self, group_id: &str) -> Result<bool, DbError> {
        let q = Ql::new("Membership.filter(.group_id == ")
            .str(group_id)
            .raw(" && .status == ")
            .str(status::ACTIVE)
            .raw(").limit(1)");
        Ok(!self.db.fetch::<ActorRow>(&q).await?.is_empty())
    }

    /// Up to [`MEMBERS_PAGE`] ended members of `group_id`, from `offset`.
    /// Ended rows never change until the purge, so offset paging is stable.
    async fn ended_members_page(
        &self,
        group_id: &str,
        offset: usize,
    ) -> Result<Vec<Actor>, DbError> {
        let q = Ql::new("Membership.filter(.group_id == ")
            .str(group_id)
            .raw(" && .status == ")
            .str(status::ENDED)
            .raw(").offset(")
            .uint(offset as u64)
            .raw(").limit(")
            .uint(MEMBERS_PAGE as u64)
            .raw(")");
        actors(group_id, self.db.fetch::<ActorRow>(&q).await?)
    }
}

impl Groups {
    /// End every active membership of `group_id`, which is being deleted,
    /// naming each member to the listeners as its page is written. `true`
    /// once a read finds no active membership left; `false` when pages kept
    /// ending nothing although some remained (other writes kept winning the
    /// rows), which leaves the rest, and the purge, to the sweeper.
    pub(super) async fn end_memberships(&self, group_id: &str) -> Result<bool, DbError> {
        let mut stalled = 0;
        loop {
            let ended = self.store.end_members_page(group_id).await?;
            for actor in &ended {
                self.tell_listeners(group_id, actor);
            }
            // A full page may have more behind it; a short one may have
            // lost rows to a race, so only a read says whether any remain.
            if ended.len() == MEMBERS_PAGE {
                stalled = 0;
                continue;
            }
            if !self.store.has_active_member(group_id).await? {
                return Ok(true);
            }
            if ended.is_empty() {
                stalled += 1;
                if stalled >= STALLED_PAGES {
                    return Ok(false);
                }
            } else {
                stalled = 0;
            }
        }
    }

    /// Finish deleting `group_id` (the sweeper): name every membership
    /// ended so far again, end the rest, name the owner, then purge.
    pub(super) async fn finish_deletion(&self, group_id: &str) -> Result<(), DbError> {
        let mut offset = 0;
        loop {
            let page = self.store.ended_members_page(group_id, offset).await?;
            for actor in &page {
                self.tell_listeners(group_id, actor);
            }
            offset += page.len();
            if page.len() < MEMBERS_PAGE {
                break;
            }
        }
        if !self.end_memberships(group_id).await? {
            return Err(DbError::Contended(format!(
                "group {group_id}: memberships kept changing while they were ended"
            )));
        }
        if let Some(group) = self.store.group_owner(group_id).await? {
            self.tell_listeners(group_id, &group.owner);
        }
        self.store.purge_group(group_id).await
    }
}
