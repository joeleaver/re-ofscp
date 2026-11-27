//! Unit tests for the access rule: the full tier × tier × standing × `view`
//! matrix of §11.3, permission grants, and the join gate.

use super::*;

fn group(tier: Tier) -> GroupPolicy {
    GroupPolicy::new(tier, JoinPolicy::Open, PermissionMap::new(), None)
}

fn channel(tier: Tier, view: Option<&[&str]>) -> ChannelPolicy {
    ChannelPolicy {
        tier,
        permissions: view.map(|v| {
            PermissionMap::from([(
                actions::VIEW.to_owned(),
                v.iter().map(|r| (*r).to_owned()).collect(),
            )])
        }),
    }
}

fn member(role: &str) -> Standing {
    Standing::Member(role.to_owned())
}

fn open(t: Tier) -> bool {
    matches!(t, Tier::Public | Tier::Discoverable)
}

/// §11.3 written out independently: rule 1 (group tier), rule 2 (channel
/// tier), rule 3 (`view`, owner passes, listed role passes).
fn expected(standing: &Standing, g: Tier, c: Tier, view: Option<&[&str]>) -> bool {
    let is_member = !matches!(standing, Standing::Outsider);
    let rule1 = open(g) || is_member;
    let rule2 = open(c) || is_member;
    let rule3 = match (view, standing) {
        (None, _) => true,
        (Some(_), Standing::Owner) => true,
        (Some(v), Standing::Member(r)) => v.contains(&r.as_str()),
        (Some(_), Standing::Outsider) => false,
    };
    rule1 && rule2 && rule3
}

#[test]
fn effective_read_access_matrix() {
    let standings = [
        Standing::Outsider,
        member(roles::GUEST),
        member(roles::MEMBER),
        member(roles::ADMIN),
        Standing::Owner,
    ];
    let views: [Option<&[&str]>; 4] = [
        None,
        Some(&[]),
        Some(&[roles::ADMIN]),
        Some(&[roles::MEMBER, roles::GUEST]),
    ];
    let mut cases = 0;
    for g in Tier::ALL {
        for c in Tier::ALL {
            for view in views {
                for s in &standings {
                    let got = can_read_channel(s, &group(g), &channel(c, view));
                    assert_eq!(
                        got,
                        expected(s, g, c, view),
                        "group {g:?}, channel {c:?}, view {view:?}, {s:?}"
                    );
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 4 * 4 * 4 * 5);
}

#[test]
fn a_public_channel_in_a_members_only_group_is_members_only() {
    for g in [Tier::Private, Tier::Group] {
        let c = channel(Tier::Public, None);
        assert!(!can_read_channel(&Standing::Outsider, &group(g), &c));
        assert!(can_read_channel(&member(roles::GUEST), &group(g), &c));
    }
}

#[test]
fn view_overrides_a_public_channel_tier() {
    let g = group(Tier::Public);
    let c = channel(Tier::Public, Some(&[roles::ADMIN]));
    assert!(!can_read_channel(&Standing::Outsider, &g, &c));
    assert!(!can_read_channel(&member(roles::MEMBER), &g, &c));
    assert!(can_read_channel(&member(roles::ADMIN), &g, &c));
    assert!(can_read_channel(&Standing::Owner, &g, &c));
}

#[test]
fn an_unknown_role_holds_nothing() {
    let g = GroupPolicy::new(
        Tier::Group,
        JoinPolicy::Invite,
        PermissionMap::from([(actions::MANAGE.to_owned(), vec!["moderator".to_owned()])]),
        None,
    );
    let c = channel(Tier::Group, Some(&["moderator"]));
    let moderator = member("moderator");
    assert!(!may(&moderator, &g, actions::MANAGE));
    assert!(!can_read_channel(&moderator, &g, &c));
    // Declared in the catalogue, the same role holds what it is listed for.
    let declared = GroupPolicy::new(
        Tier::Group,
        JoinPolicy::Invite,
        g.permissions.clone(),
        Some(&[RoleDefinition {
            name: "moderator".into(),
            label: None,
            color: None,
        }]),
    );
    assert!(may(&moderator, &declared, actions::MANAGE));
    assert!(can_read_channel(&moderator, &declared, &c));
}

#[test]
fn permissions_are_exact_with_no_inheritance() {
    let g = GroupPolicy::new(
        Tier::Public,
        JoinPolicy::Open,
        PermissionMap::from([(actions::MANAGE.to_owned(), vec![roles::MEMBER.to_owned()])]),
        None,
    );
    assert!(may(&member(roles::MEMBER), &g, actions::MANAGE));
    // Listing `member` does not grant `admin`.
    assert!(!may(&member(roles::ADMIN), &g, actions::MANAGE));
    assert!(may(&Standing::Owner, &g, actions::MANAGE));
    assert!(may(&Standing::Owner, &g, "members.set-nickname"));
    // Reading never implies posting.
    assert!(!may(&Standing::Outsider, &g, actions::POST));
    assert!(can_read_group(&Standing::Outsider, &g));
}

#[test]
fn defaults_fill_only_missing_canonical_actions() {
    let p = effective_permissions(PermissionMap::from([
        (actions::POST.to_owned(), vec![roles::MEMBER.to_owned()]),
        ("pin".to_owned(), vec![roles::ADMIN.to_owned()]),
    ]));
    assert_eq!(p[actions::POST], vec![roles::MEMBER]);
    assert_eq!(p[actions::MODERATE], vec![roles::ADMIN]);
    assert_eq!(p[actions::MANAGE], vec![roles::ADMIN]);
    assert_eq!(p["pin"], vec![roles::ADMIN]);
    let g = group(Tier::Group);
    assert!(may(&member(roles::MEMBER), &g, actions::POST));
    assert!(!may(&member(roles::GUEST), &g, actions::POST));
    assert!(!may(&member(roles::MEMBER), &g, actions::MANAGE));
    assert!(may(&member(roles::ADMIN), &g, actions::MANAGE));
}

#[test]
fn private_groups_are_invite_only_whatever_their_join_policy() {
    for policy in [JoinPolicy::Open, JoinPolicy::Request, JoinPolicy::Invite] {
        let g = GroupPolicy::new(Tier::Private, policy, PermissionMap::new(), None);
        assert_eq!(join_gate(&g), JoinGate::InviteOnly, "{policy:?}");
    }
    let gate = |t, p| join_gate(&GroupPolicy::new(t, p, PermissionMap::new(), None));
    assert_eq!(gate(Tier::Group, JoinPolicy::Open), JoinGate::Open);
    assert_eq!(gate(Tier::Public, JoinPolicy::Request), JoinGate::Request);
    assert_eq!(
        gate(Tier::Discoverable, JoinPolicy::Invite),
        JoinGate::InviteOnly
    );
}

#[test]
fn a_membership_claiming_the_owner_role_holds_nothing() {
    let mut perms = PermissionMap::new();
    perms.insert("manage".into(), vec!["owner".into()]);
    let g = GroupPolicy::new(Tier::Group, JoinPolicy::Invite, perms, None);
    let impostor = member("owner");
    assert!(!may(&impostor, &g, actions::MANAGE));
    assert!(may(&Standing::Owner, &g, actions::MANAGE));
    let only_owner = channel(Tier::Group, Some(&["owner"]));
    assert!(!can_read_channel(&impostor, &g, &only_owner));
    assert!(can_read_channel(&Standing::Owner, &g, &only_owner));
}

fn perms(entries: &[(&str, &[&str])]) -> ChannelPolicy {
    ChannelPolicy {
        tier: Tier::Public,
        permissions: Some(
            entries
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.iter().map(|r| (*r).to_owned()).collect()))
                .collect(),
        ),
    }
}

#[test]
fn posting_uses_the_channel_entry_for_the_type_else_the_group_post() {
    let g = group(Tier::Public);
    let plain = channel(Tier::Public, None);
    // Group defaults: post = admin, member.
    assert!(may_post(&member("member"), &g, &plain, "memo"));
    assert!(!may_post(&member("guest"), &g, &plain, "message"));
    assert!(!may_post(&Standing::Outsider, &g, &plain, "message"));
    assert!(may_post(&Standing::Owner, &g, &plain, "article"));

    let c = perms(&[("post:article", &["admin"]), ("post:message", &["guest"])]);
    assert!(!may_post(&member("member"), &g, &c, "article"));
    assert!(may_post(&member("admin"), &g, &c, "article"));
    // Exact membership: listing guest does not grant member.
    assert!(may_post(&member("guest"), &g, &c, "message"));
    assert!(!may_post(&member("member"), &g, &c, "message"));
    // memo is not listed: the group's post applies.
    assert!(may_post(&member("member"), &g, &c, "memo"));
    assert!(may_post(&Standing::Owner, &g, &c, "article"));
}

#[test]
fn reacting_defaults_to_every_reader_and_otherwise_is_exact() {
    let g = group(Tier::Public);
    assert!(may_react(
        &Standing::Outsider,
        &g,
        &channel(Tier::Public, None)
    ));
    let c = perms(&[("react", &["member"])]);
    assert!(may_react(&member("member"), &g, &c));
    assert!(!may_react(&member("admin"), &g, &c));
    assert!(!may_react(&Standing::Outsider, &g, &c));
    assert!(may_react(&Standing::Owner, &g, &c));
}

#[test]
fn reply_only_restricts_listed_roles_but_never_the_owner() {
    let g = group(Tier::Public);
    let c = perms(&[
        ("replyOnly", &["member", "guest"]),
        ("replyOnlyTo", &["memo"]),
    ]);
    let to = ReplyRule::RepliesOnly {
        to: Some(vec!["memo".to_owned()]),
    };
    assert_eq!(reply_rule(&member("member"), &g, &c), to);
    assert_eq!(reply_rule(&member("guest"), &g, &c), to);
    assert_eq!(reply_rule(&member("admin"), &g, &c), ReplyRule::Free);
    assert_eq!(reply_rule(&Standing::Owner, &g, &c), ReplyRule::Free);
    assert_eq!(reply_rule(&Standing::Outsider, &g, &c), ReplyRule::Free);
    let bare = perms(&[("replyOnly", &["member"])]);
    assert_eq!(
        reply_rule(&member("member"), &g, &bare),
        ReplyRule::RepliesOnly { to: None }
    );
    assert_eq!(
        reply_rule(&member("member"), &g, &channel(Tier::Public, None)),
        ReplyRule::Free
    );
}
