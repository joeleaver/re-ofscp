use std::sync::Arc;

use re_ofscp_types::Actor;
use re_ofscp_types::profile::Visibility;

use super::seams::RelFuture;
use super::*;

fn actor(s: &str) -> Actor {
    Actor::parse_canonical(s).unwrap()
}

/// Relationships where exactly the listed pairs share a group or are
/// contacts (either order), or every lookup fails.
struct Fake {
    groups: Vec<(Actor, Actor)>,
    contacts: Vec<(Actor, Actor)>,
    fail: bool,
}

fn related(pairs: &[(Actor, Actor)], a: &Actor, b: &Actor) -> bool {
    pairs
        .iter()
        .any(|(x, y)| (x == a && y == b) || (x == b && y == a))
}

impl GroupMemberships for Fake {
    fn share_a_group<'a>(&'a self, a: &'a Actor, b: &'a Actor) -> RelFuture<'a, bool> {
        let r = if self.fail {
            Err(RelError("down".into()))
        } else {
            Ok(related(&self.groups, a, b))
        };
        Box::pin(async move { r })
    }

    fn groups_visible_to<'a>(&'a self, _: &'a Actor, _: &'a Viewer) -> RelFuture<'a, Vec<String>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

impl Contacts for Fake {
    fn are_contacts<'a>(&'a self, a: &'a Actor, b: &'a Actor) -> RelFuture<'a, bool> {
        let r = if self.fail {
            Err(RelError("down".into()))
        } else {
            Ok(related(&self.contacts, a, b))
        };
        Box::pin(async move { r })
    }
}

fn rel(fake: Fake) -> Relationships {
    let fake = Arc::new(fake);
    Relationships {
        groups: fake.clone(),
        contacts: fake,
    }
}

fn jane() -> Actor {
    actor("jane@a.com")
}

/// `bob@a.com` (local) and `bob@b.com` (remote) are two different actors.
fn local_bob() -> Actor {
    actor("bob@a.com")
}

fn remote_bob() -> Actor {
    actor("bob@b.com")
}

async fn admits(
    visibility: Visibility,
    allow: &[Actor],
    deny: &[Actor],
    viewer: &Viewer,
    r: &Relationships,
) -> bool {
    Policy {
        visibility,
        allow,
        deny,
    }
    .admits(&jane(), viewer, r)
    .await
    .unwrap()
}

const ALL: [Visibility; 5] = [
    Visibility::Public,
    Visibility::Authenticated,
    Visibility::SharedGroups,
    Visibility::Contacts,
    Visibility::Nobody,
];

fn none() -> Relationships {
    Relationships::default()
}

#[tokio::test]
async fn the_subject_always_sees_their_own_data() {
    let me = Viewer::Actor(jane());
    for v in ALL {
        assert!(admits(v, &[], &[jane()], &me, &none()).await, "{v:?}");
    }
}

#[tokio::test]
async fn tiers_without_lists() {
    let anon = Viewer::Anonymous;
    let user = Viewer::Actor(remote_bob());
    let r = none();
    // (tier, anonymous, an unrelated user)
    let table = [
        (Visibility::Public, true, true),
        (Visibility::Authenticated, false, true),
        (Visibility::SharedGroups, false, false),
        (Visibility::Contacts, false, false),
        (Visibility::Nobody, false, false),
    ];
    for (v, a, u) in table {
        assert_eq!(admits(v, &[], &[], &anon, &r).await, a, "{v:?} anonymous");
        assert_eq!(admits(v, &[], &[], &user, &r).await, u, "{v:?} user");
    }
}

#[tokio::test]
async fn shared_groups_and_contacts_use_the_relationships_by_full_actor() {
    // Jane shares a group with remote bob@b.com and is a contact of local
    // bob@a.com. Neither relationship leaks to the other bob.
    let r = rel(Fake {
        groups: vec![(jane(), remote_bob())],
        contacts: vec![(local_bob(), jane())],
        fail: false,
    });
    let remote = Viewer::Actor(remote_bob());
    let local = Viewer::Actor(local_bob());
    assert!(admits(Visibility::SharedGroups, &[], &[], &remote, &r).await);
    assert!(!admits(Visibility::SharedGroups, &[], &[], &local, &r).await);
    assert!(admits(Visibility::Contacts, &[], &[], &local, &r).await);
    assert!(!admits(Visibility::Contacts, &[], &[], &remote, &r).await);
}

#[tokio::test]
async fn deny_beats_allow_and_both_beat_the_tier() {
    let r = none();
    let remote = Viewer::Actor(remote_bob());
    // Allow overrides even `nobody`.
    assert!(admits(Visibility::Nobody, &[remote_bob()], &[], &remote, &r).await);
    // Deny overrides even `public`.
    assert!(!admits(Visibility::Public, &[], &[remote_bob()], &remote, &r).await);
    // In both: deny wins.
    assert!(
        !admits(
            Visibility::Public,
            &[remote_bob()],
            &[remote_bob()],
            &remote,
            &r
        )
        .await
    );
}

#[tokio::test]
async fn lists_match_the_full_actor_never_the_bare_handle() {
    let r = none();
    // Local bob is allowed; remote bob@b.com is not, and vice versa.
    let remote = Viewer::Actor(remote_bob());
    let local = Viewer::Actor(local_bob());
    assert!(!admits(Visibility::Nobody, &[local_bob()], &[], &remote, &r).await);
    assert!(admits(Visibility::Nobody, &[local_bob()], &[], &local, &r).await);
    assert!(admits(Visibility::Public, &[], &[local_bob()], &remote, &r).await);
    assert!(!admits(Visibility::Public, &[], &[local_bob()], &local, &r).await);
}

#[tokio::test]
async fn lists_never_apply_to_anonymous_viewers() {
    let r = none();
    assert!(
        !admits(
            Visibility::Nobody,
            &[remote_bob()],
            &[],
            &Viewer::Anonymous,
            &r
        )
        .await
    );
    assert!(
        admits(
            Visibility::Public,
            &[],
            &[remote_bob()],
            &Viewer::Anonymous,
            &r
        )
        .await
    );
}

#[tokio::test]
async fn a_failed_lookup_is_an_error_not_an_admission() {
    let r = rel(Fake {
        groups: vec![],
        contacts: vec![],
        fail: true,
    });
    let viewer = Viewer::Actor(remote_bob());
    for v in [Visibility::SharedGroups, Visibility::Contacts] {
        let result = Policy {
            visibility: v,
            allow: &[],
            deny: &[],
        }
        .admits(&jane(), &viewer, &r)
        .await;
        assert!(result.is_err(), "{v:?}");
    }
    // Tiers and lists that need no lookup still answer.
    assert!(admits(Visibility::Public, &[], &[], &viewer, &r).await);
    assert!(admits(Visibility::Contacts, &[remote_bob()], &[], &viewer, &r).await);
}
