use super::*;

fn limits() -> Limits {
    Limits {
        max_connections: 5,
        per_client: 3,
        per_actor: 2,
        per_remote_group: 2,
        max_subscriptions: 2,
        outbound_queue: 4,
        held_max: 2,
    }
}

fn local() -> Authority {
    Authority::parse_canonical("a.example").unwrap()
}

fn actor(s: &str) -> Actor {
    Actor::parse_canonical(s).unwrap()
}

fn text(s: &str) -> Arc<str> {
    Arc::from(s)
}

fn drain(rx: &mut mpsc::Receiver<Arc<str>>) -> Vec<String> {
    let mut out = Vec::new();
    while let Ok(t) = rx.try_recv() {
        out.push(t.to_string());
    }
    out
}

#[test]
fn caps_per_client_actor_and_remote_group() {
    let r = Registry::new(limits(), local());
    let a = r.admit("c1").unwrap().id;
    let b = r.admit("c1").unwrap().id;
    let c = r.admit("c1").unwrap().id;
    assert_eq!(r.admit("c1").unwrap_err(), Refused::Client);
    let d = r.admit("c2").unwrap().id;
    let e = r.admit("c3").unwrap().id;
    assert_eq!(r.admit("c4").unwrap_err(), Refused::Full);

    let alice = actor("alice@a.example");
    r.authenticate(a, &alice, "k1").unwrap();
    r.authenticate(b, &alice, "k2").unwrap();
    assert_eq!(r.authenticate(c, &alice, "k3"), Err(Refused::Actor));

    // Remote providers under one registrable domain share a cap.
    r.authenticate(c, &actor("bob@x.remote.example"), "k")
        .unwrap();
    r.authenticate(d, &actor("carol@y.remote.example"), "k")
        .unwrap();
    let dave = actor("dave@z.remote.example");
    assert_eq!(r.authenticate(e, &dave, "k"), Err(Refused::Group));
    r.remove(c);
    r.authenticate(e, &dave, "k").unwrap();

    for id in [a, b, d, e] {
        r.remove(id);
    }
    assert!(r.is_empty());
    r.admit("c1").unwrap();
}

#[test]
fn fan_out_respects_include_and_holds() {
    let r = Registry::new(limits(), local());
    let Admitted {
        id,
        shared: _shared,
        events: mut rx,
    } = r.admit("c").unwrap();
    r.authenticate(id, &actor("alice@a.example"), "k").unwrap();
    let include = Some(Arc::new(HashSet::from(["message.created".to_owned()])));
    assert_eq!(
        r.hold_new(id, &["ch".to_owned()], include),
        Some(vec![true])
    );
    r.publish("ch", "message.created", &text("held"));
    r.publish("ch", "reaction.added", &text("filtered"));
    assert!(drain(&mut rx).is_empty(), "held while access is checked");
    r.release(id, "ch");
    assert_eq!(drain(&mut rx), ["held"]);
    r.publish("ch", "message.created", &text("live"));
    assert_eq!(drain(&mut rx), ["live"]);
    r.publish("other", "message.created", &text("not subscribed"));
    assert!(drain(&mut rx).is_empty());
}

#[test]
fn a_revoked_hold_drops_what_it_kept() {
    let r = Registry::new(limits(), local());
    let Admitted {
        id,
        shared: _shared,
        events: mut rx,
    } = r.admit("c").unwrap();
    let alice = actor("alice@a.example");
    r.authenticate(id, &alice, "k").unwrap();
    r.hold_new(id, &["ch".to_owned()], None).unwrap();
    r.release(id, "ch");
    let held = r.hold_matching(&AccessChange::Actor(alice));
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].topic, "ch");
    r.publish("ch", "message.created", &text("after the change"));
    assert!(r.unsubscribe(id, "ch"));
    assert!(drain(&mut rx).is_empty(), "nothing leaks after revocation");
    r.publish("ch", "message.created", &text("later"));
    assert!(drain(&mut rx).is_empty());
    assert!(!r.unsubscribe(id, "ch"));
}

#[test]
fn hold_matching_selects_by_topic_actor_or_all() {
    let r = Registry::new(limits(), local());
    let Admitted { id: a, .. } = r.admit("c").unwrap();
    let Admitted { id: b, .. } = r.admit("c").unwrap();
    let Admitted { id: unauth, .. } = r.admit("c").unwrap();
    r.authenticate(a, &actor("alice@a.example"), "k").unwrap();
    r.authenticate(b, &actor("bob@a.example"), "k").unwrap();
    for (id, t) in [(a, "x"), (a, "y"), (b, "y")] {
        r.hold_new(id, &[t.to_owned()], None).unwrap();
        r.release(id, t);
    }
    let _ = unauth;
    let topics = |held: Vec<Held>| {
        let mut v: Vec<_> = held.into_iter().map(|h| (h.conn, h.topic)).collect();
        v.sort();
        v
    };
    assert_eq!(
        topics(r.hold_matching(&AccessChange::Topics(vec!["y".into()]))),
        [(a, "y".to_owned()), (b, "y".to_owned())]
    );
    assert_eq!(
        topics(r.hold_matching(&AccessChange::Actor(actor("bob@a.example")))),
        [(b, "y".to_owned())]
    );
    assert_eq!(r.hold_matching(&AccessChange::All).len(), 3);
}

#[test]
fn the_subscription_cap_is_all_or_none() {
    let r = Registry::new(limits(), local());
    let Admitted { id, .. } = r.admit("c").unwrap();
    r.authenticate(id, &actor("alice@a.example"), "k").unwrap();
    assert_eq!(r.hold_new(id, &["a".to_owned()], None), Some(vec![true]));
    assert_eq!(
        r.hold_new(id, &["b".to_owned(), "c".to_owned()], None),
        None
    );
    assert_eq!(
        r.hold_new(id, &["a".to_owned(), "b".to_owned()], None),
        Some(vec![false, true])
    );
}

#[test]
fn slow_consumers_and_overfull_holds_close_1013() {
    let r = Registry::new(limits(), local());
    let Admitted {
        id,
        shared,
        events: _rx,
    } = r.admit("c").unwrap();
    r.authenticate(id, &actor("alice@a.example"), "k").unwrap();
    r.hold_new(id, &["ch".to_owned()], None).unwrap();
    for _ in 0..2 {
        r.publish("ch", "message.created", &text("kept"));
    }
    assert_eq!(shared.closing(), None);
    r.publish("ch", "message.created", &text("one too many"));
    assert_eq!(shared.closing().map(|c| c.code), Some(close::TRY_AGAIN));

    let Admitted {
        id,
        shared,
        events: _rx,
    } = r.admit("c").unwrap();
    let bob = actor("bob@a.example");
    r.authenticate(id, &bob, "k").unwrap();
    for _ in 0..4 {
        r.send_to_actor(&bob, &text("queued"));
    }
    assert_eq!(shared.closing(), None);
    r.send_to_actor(&bob, &text("over the queue"));
    assert_eq!(shared.closing().map(|c| c.code), Some(close::TRY_AGAIN));
}

#[test]
fn force_close_by_key_actor_remote_policy_and_shutdown() {
    let r = Registry::new(limits(), local());
    let alice = actor("alice@a.example");
    let Admitted {
        id: a1,
        shared: s1,
        events: _r1,
    } = r.admit("c").unwrap();
    let Admitted {
        id: a2,
        shared: s2,
        events: _r2,
    } = r.admit("c").unwrap();
    let Admitted {
        id: rm,
        shared: s3,
        events: _r3,
    } = r.admit("d").unwrap();
    r.authenticate(a1, &alice, "k1").unwrap();
    r.authenticate(a2, &alice, "k2").unwrap();
    r.authenticate(rm, &actor("bob@b.example"), "k1").unwrap();
    let revoked = Close::new(close::REVOKED, "revoked");
    assert_eq!(r.close_actor(&alice, Some("k1"), revoked), 1);
    assert_eq!(s1.closing(), Some(revoked));
    assert_eq!(s2.closing(), None);
    // A remote actor sharing the handle and key id is someone else.
    assert_eq!(s3.closing(), None);
    // The first close request wins.
    r.close_all(Close::new(close::GOING_AWAY, "bye"));
    assert_eq!(s1.closing(), Some(revoked));
    assert_eq!(s2.closing().map(|c| c.code), Some(close::GOING_AWAY));
    assert_eq!(r.admit("e").unwrap_err(), Refused::ShuttingDown);
}
