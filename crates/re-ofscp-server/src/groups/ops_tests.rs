//! Unit tests for the announcements group writes make: a write that fails
//! may have committed, so it is announced as if it had.

use std::sync::Arc;

use re_ofscp_types::{Actor, Authority};
use tokio::sync::broadcast::error::TryRecvError;

use super::*;
use crate::db::{Db, DbConfig};
use crate::groups::MembershipListener;
use crate::signing::SystemClock;

fn actor(s: &str) -> Actor {
    Actor::parse_canonical(s).unwrap()
}

/// Groups over a database nothing listens on: every query fails, as a
/// write whose reply was lost after the commit would.
fn unreachable() -> Groups {
    Groups::new(
        Authority::parse_canonical("providera.com").unwrap(),
        // Port 9 (discard): refused at once.
        Arc::new(Db::new(DbConfig::new("127.0.0.1:9"))),
        Arc::new(SystemClock),
    )
}

#[test]
fn only_a_write_known_to_change_nothing_goes_unannounced() {
    let announced = |written: Result<bool, ()>| {
        let mut announced = false;
        announce_unless(&written, |set| !set, || announced = true);
        announced
    };
    assert!(announced(Ok(true)));
    assert!(!announced(Ok(false)));
    assert!(announced(Err(())));
}

#[tokio::test]
async fn a_failed_membership_removal_is_announced() {
    let groups = unreachable();
    let mut changes = groups.subscribe_changes();
    let bob = actor("bob@remote.example");
    let err = groups.remove_member("grp_1", &bob).await.unwrap_err();
    assert!(matches!(err, GroupError::Db(_)), "{err:?}");
    assert_eq!(
        changes.try_recv(),
        Ok(AccessChange::Member {
            group_id: "grp_1".into(),
            actor: bob,
        })
    );
    assert_eq!(changes.try_recv(), Err(TryRecvError::Empty));
}

#[tokio::test]
async fn a_failed_role_change_is_announced() {
    let groups = unreachable();
    let mut changes = groups.subscribe_changes();
    let bob = actor("bob@providera.com");
    let err = groups.set_role("grp_1", &bob, "member").await.unwrap_err();
    assert!(matches!(err, GroupError::Db(_)), "{err:?}");
    assert_eq!(
        changes.try_recv(),
        Ok(AccessChange::Member {
            group_id: "grp_1".into(),
            actor: bob,
        })
    );
}

/// A membership listener that records every change it is told of.
#[derive(Default)]
struct Recorder(std::sync::Mutex<Vec<(String, Actor)>>);

impl MembershipListener for Recorder {
    fn membership_changed(&self, group_id: &str, actor: &Actor) {
        self.0
            .lock()
            .unwrap()
            .push((group_id.to_owned(), actor.clone()));
    }
}

/// Settle a join whose activation answered `activated`, over a database
/// that fails every query (so the recount and the take-back fail too):
/// the answer, then how many member changes the broadcast carried and the
/// listener was told of.
async fn settle(activated: Result<(), GroupError>) -> (GroupError, usize, usize) {
    let groups = unreachable();
    let recorder = Arc::new(Recorder::default());
    groups.on_membership(recorder.clone());
    let mut changes = groups.subscribe_changes();
    let bob = actor("bob@providera.com");
    let err = groups
        .settle_join("grp_1", &bob, activated)
        .await
        .unwrap_err();
    let want = AccessChange::Member {
        group_id: "grp_1".into(),
        actor: bob.clone(),
    };
    let mut broadcast = 0;
    while let Ok(change) = changes.try_recv() {
        assert_eq!(change, want);
        broadcast += 1;
    }
    let told = recorder.0.lock().unwrap().clone();
    assert!(
        told.iter().all(|(g, a)| g == "grp_1" && *a == bob),
        "{told:?}"
    );
    (err, broadcast, told.len())
}

#[tokio::test]
async fn a_failed_activation_is_announced_and_taken_back() {
    // The activation's write may have committed although it failed.
    let lost = GroupError::Db(DbError::Contended("reply lost".into()));
    let (err, broadcast, told) = settle(Err(lost)).await;
    assert!(matches!(err, GroupError::Db(_)), "{err:?}");
    // Once for the join, once for the take-back (whose write failed too).
    assert_eq!((broadcast, told), (2, 2));
}

#[tokio::test]
async fn a_failed_recount_after_activation_is_announced_and_taken_back() {
    let (err, broadcast, told) = settle(Ok(())).await;
    assert!(matches!(err, GroupError::Db(_)), "{err:?}");
    assert_eq!((broadcast, told), (2, 2));
}
