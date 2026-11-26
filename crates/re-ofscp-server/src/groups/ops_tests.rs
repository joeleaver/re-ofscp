//! Unit tests for the announcements group writes make: a write that fails
//! may have committed, so it is announced as if it had.

use std::sync::Arc;

use re_ofscp_types::{Actor, Authority};
use tokio::sync::broadcast::error::TryRecvError;

use super::*;
use crate::db::{Db, DbConfig};
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
