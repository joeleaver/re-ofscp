//! Joining a group (§5.7 `POST .../join`, and its §8.2 channel alias) and
//! the join requests of `request`-policy groups (list, approve, deny).
//! Local and remote callers are treated alike: identity is the full actor
//! (§2.2).

use re_ofscp_types::Actor;
use re_ofscp_types::wire::{JoinRequest, Member, Paged};

use super::access::{self, JoinGate, Standing, actions, roles};
use super::model::StoredGroup;
use super::ops::{GroupError, NO_GROUP};
use super::paging::{self, PageQuery, SortKey};
use super::requests::StoredRequest;
use super::validate::Invalid;
use super::{Caller, Groups, MAX_PENDING_REQUESTS_PER_GROUP};

/// Longest join-request message, in characters (provider policy; §5.7
/// sets none).
pub const MAX_JOIN_MESSAGE: usize = 500;

const INVITE_ONLY: &str = "this group is joined by invitation only";
const NO_LONGER_REQUESTS: &str = "the group no longer takes join requests";
const NOT_REVIEWER: &str = "you may not review this group's join requests";
const NO_REQUEST: &str = "no such join request";
const TOO_MANY_REQUESTS: &str =
    "this group has the most pending join requests this provider allows";

/// What a join did (§5.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Joined {
    /// `200`: already a member (the owner included).
    Already(Member),
    /// `201`: became a member (an `open` group).
    Member(Member),
    /// `202`: a request is pending (a `request` group), new or earlier.
    Requested(JoinRequest),
}

/// A join request's message as stored: `None` when absent or blank, `400`
/// when longer than [`MAX_JOIN_MESSAGE`] characters. Kept as sent
/// otherwise.
pub fn join_message(raw: Option<&str>) -> Result<Option<String>, Invalid> {
    let Some(m) = raw.filter(|m| !m.trim().is_empty()) else {
        return Ok(None);
    };
    if m.chars().count() > MAX_JOIN_MESSAGE {
        return Err(Invalid(format!(
            "`message` is longer than {MAX_JOIN_MESSAGE} characters"
        )));
    }
    Ok(Some(m.to_owned()))
}

impl Groups {
    /// `POST /api/groups/{groupId}/join`. `message` is the optional
    /// request body's, or why the body is malformed. It is validated once
    /// the caller is known to be let in or to be a member already (`400`),
    /// as every route validates its body only after authorizing; a caller
    /// refused by an invite-only group gets `403` whatever they sent. It is
    /// stored only for a `request` group.
    pub async fn join(
        &self,
        actor: &Actor,
        group_id: &str,
        message: Result<Option<&str>, Invalid>,
    ) -> Result<Joined, GroupError> {
        let group = self.settled_group(group_id).await?;
        if let Some(m) = self.member_of(&group, actor).await? {
            join_message(message?)?;
            return Ok(Joined::Already(m));
        }
        let gate = access::join_gate(&group.policy());
        if gate == JoinGate::InviteOnly {
            return Err(GroupError::Forbidden(INVITE_ONLY));
        }
        let message = join_message(message?)?;
        if gate == JoinGate::Open {
            return self.join_open(&group, actor).await;
        }
        self.request_to_join(&group, actor, message.as_deref())
            .await
    }

    async fn join_open(&self, group: &StoredGroup, actor: &Actor) -> Result<Joined, GroupError> {
        let added = self
            .add_member(&group.id, actor, roles::MEMBER, self.now())
            .await?;
        // Re-read the group: the owner's nickname, or an ownership change.
        let now = self.settled_group(&group.id).await?;
        let member = self
            .member_of(&now, actor)
            .await?
            .ok_or(GroupError::Conflict(
                "the membership changed meanwhile; retry",
            ))?;
        Ok(if added {
            Joined::Member(member)
        } else {
            Joined::Already(member)
        })
    }

    /// The caller's pending request, recording one if there is none
    /// (default 3 of docs/decisions/0020: a repeated join answers the
    /// earlier request). A group at its limit of pending requests refuses
    /// more (`403`), counted again after the write as for memberships.
    async fn request_to_join(
        &self,
        group: &StoredGroup,
        actor: &Actor,
        message: Option<&str>,
    ) -> Result<Joined, GroupError> {
        let gid = &group.id;
        if let Some(r) = self.store.pending_request_of(gid, actor).await? {
            return Ok(Joined::Requested(r.to_wire()?));
        }
        let cap = MAX_PENDING_REQUESTS_PER_GROUP;
        if self.store.request_count(gid, cap).await? >= cap {
            return Err(GroupError::Forbidden(TOO_MANY_REQUESTS));
        }
        let created = match self
            .store
            .create_request(gid, actor, message, self.now())
            .await?
        {
            Some(r) => {
                // Of concurrent requests past the limit, each finds the
                // excess and takes itself back.
                if self.store.request_count(gid, cap + 1).await? > cap {
                    self.store.delete_request(&r.id).await?;
                    return Err(GroupError::Forbidden(TOO_MANY_REQUESTS));
                }
                r
            }
            // A concurrent join recorded it first.
            None => {
                self.store
                    .pending_request_of(gid, actor)
                    .await?
                    .ok_or(GroupError::Conflict(
                        "the join request changed meanwhile; retry",
                    ))?
            }
        };
        // A request must not outlive its group: one written after the
        // group's purge began would never be purged.
        let Some(now) = self.store.group(gid).await? else {
            self.store.delete_request(&created.id).await?;
            return Err(GroupError::NotFound(NO_GROUP));
        };
        // Nor its asker's joining by another path (an approval of an
        // earlier request, an invitation) since the check in `join`.
        if let Some(m) = self.member_of(&now, actor).await? {
            self.store.delete_request(&created.id).await?;
            return Ok(Joined::Already(m));
        }
        Ok(Joined::Requested(created.to_wire()?))
    }

    /// The group, if `actor` may review its join requests (`manage` or
    /// `moderate`).
    async fn reviewing(&self, actor: &Actor, group_id: &str) -> Result<StoredGroup, GroupError> {
        let group = self.settled_group(group_id).await?;
        let standing: Standing = self.standing(&Caller::Actor(actor.clone()), &group).await?;
        let policy = group.policy();
        if !access::may(&standing, &policy, actions::MANAGE)
            && !access::may(&standing, &policy, actions::MODERATE)
        {
            return Err(GroupError::Forbidden(NOT_REVIEWER));
        }
        Ok(group)
    }

    /// `GET /api/groups/{groupId}/requests`: the pending requests, paged
    /// per §7.2 by `(requestedAt, id)`, newest first by default.
    pub async fn list_requests(
        &self,
        actor: &Actor,
        group_id: &str,
        query: &PageQuery,
    ) -> Result<Paged<JoinRequest>, GroupError> {
        let group = self.reviewing(actor, group_id).await?;
        let rows = self
            .store
            .requests(&group.id, MAX_PENDING_REQUESTS_PER_GROUP)
            .await?;
        let items = rows
            .iter()
            .map(|r| Ok((request_key(r), r.to_wire()?)))
            .collect::<Result<Vec<_>, GroupError>>()?;
        Ok(paging::page(
            &format!("requests {}", group.id),
            items,
            query,
        )?)
    }

    /// `POST /api/groups/{groupId}/requests/{requestId}/approve`: the
    /// requester becomes a `member` (default 5 of docs/decisions/0020: no
    /// subset rule, and always that role). Someone already a member is
    /// answered as they are. A group that is joined by invitation only now
    /// (it became private, or its policy `invite`) admits no one this way:
    /// `409`, the request kept (security requirement 6; confirmed by Joe
    /// via the oracle 2026-11-27, spec PR pending). Under `open` it still
    /// admits.
    pub async fn approve_request(
        &self,
        actor: &Actor,
        group_id: &str,
        request_id: &str,
    ) -> Result<Member, GroupError> {
        let group = self.reviewing(actor, group_id).await?;
        let request = self
            .store
            .request(&group.id, request_id)
            .await?
            .ok_or(GroupError::NotFound(NO_REQUEST))?;
        if access::join_gate(&group.policy()) == JoinGate::InviteOnly {
            return Err(GroupError::Conflict(NO_LONGER_REQUESTS));
        }
        let added = self
            .add_member(&group.id, &request.actor, roles::MEMBER, self.now())
            .await?;
        // The gate again, after the write: a switch to invite-only that
        // landed after the check above must not admit (as a join recounts
        // its limits after writing). The new member is taken back.
        let now = self.settled_group(&group.id).await?;
        if added && access::join_gate(&now.policy()) == JoinGate::InviteOnly {
            self.remove_member(&group.id, &request.actor).await?;
            return Err(GroupError::Conflict(NO_LONGER_REQUESTS));
        }
        self.store.delete_request(&request.id).await?;
        self.member_of(&now, &request.actor)
            .await?
            .ok_or(GroupError::Conflict(
                "the membership changed meanwhile; retry",
            ))
    }

    /// `POST /api/groups/{groupId}/requests/{requestId}/deny`: the request
    /// is dropped; the requester may ask again.
    pub async fn deny_request(
        &self,
        actor: &Actor,
        group_id: &str,
        request_id: &str,
    ) -> Result<(), GroupError> {
        let group = self.reviewing(actor, group_id).await?;
        let request = self
            .store
            .request(&group.id, request_id)
            .await?
            .ok_or(GroupError::NotFound(NO_REQUEST))?;
        Ok(self.store.delete_request(&request.id).await?)
    }
}

fn request_key(r: &StoredRequest) -> SortKey {
    SortKey {
        at: r.requested_at,
        id: r.id.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_messages_are_optional_and_bounded() {
        assert_eq!(join_message(None), Ok(None));
        assert_eq!(join_message(Some("   ")), Ok(None));
        assert_eq!(join_message(Some(" hi ")), Ok(Some(" hi ".to_owned())));
        let at_limit = "ü".repeat(MAX_JOIN_MESSAGE);
        assert_eq!(join_message(Some(&at_limit)), Ok(Some(at_limit.clone())));
        assert!(join_message(Some(&format!("{at_limit}!"))).is_err());
    }
}
