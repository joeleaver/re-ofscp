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
async fn a_dropped_join_still_settles_and_announces() {
    // The client goes away once the join's activation is under way: the
    // request's future is dropped unpolled. The activation (which may
    // have committed, as its failure here may have) is still settled,
    // announced and taken back, by its own task.
    let groups = unreachable();
    let recorder = Arc::new(Recorder::default());
    groups.on_membership(recorder.clone());
    let mut changes = groups.subscribe_changes();
    let bob = actor("bob@providera.com");
    drop(groups.finish_join("grp_1", &bob));
    let settled = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while recorder.0.lock().unwrap().len() < 2 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(settled.is_ok(), "the dropped join was never settled");
    let want = AccessChange::Member {
        group_id: "grp_1".into(),
        actor: bob.clone(),
    };
    // Once for the join, once for the take-back.
    assert_eq!(changes.try_recv(), Ok(want.clone()));
    assert_eq!(changes.try_recv(), Ok(want));
    let told = recorder.0.lock().unwrap().clone();
    assert_eq!(told, vec![("grp_1".to_owned(), bob.clone()); 2]);
}

#[tokio::test]
async fn an_awaited_join_answers_its_settled_result() {
    let groups = unreachable();
    let bob = actor("bob@providera.com");
    let err = groups.finish_join("grp_1", &bob).await.unwrap_err();
    assert!(matches!(err, GroupError::Db(_)), "{err:?}");
}

#[tokio::test]
async fn a_failed_recount_after_activation_is_announced_and_taken_back() {
    let (err, broadcast, told) = settle(Ok(())).await;
    assert!(matches!(err, GroupError::Db(_)), "{err:?}");
    assert_eq!((broadcast, told), (2, 2));
}
