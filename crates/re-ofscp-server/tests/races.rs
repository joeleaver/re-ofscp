//! Concurrent writers against a real rhypedb-server: every race that a
//! filter guard alone would lose (rhypedb's filtered updates are not
//! compare-and-set, docs/decisions/0012) has exactly one winner. Account
//! invites and registrations race in `invite_races.rs`.

mod common;

use std::sync::Arc;

use common::races::{Any, RACERS, db, race, winners};
use common::rhypedb::RhypeServer;
use re_ofscp_server::admin::claims::{self, Claims};
use re_ofscp_server::admin::{Admin, AdminStore, NewAdmin};
use re_ofscp_server::db::Ql;
use re_ofscp_server::replay::ledger::RhypeLedger;
use re_ofscp_server::replay::{LedgerError, NonceLedger, SignerKind, StoredNonce};
use re_ofscp_types::admin::AdminRole;

const NOW: i64 = 2_000_000_000;

async fn admin(store: &AdminStore, username: &str) -> Admin {
    store
        .create(
            NewAdmin {
                username,
                password_hash: "$argon2id$placeholder",
                role: AdminRole::Owner,
                password_change_required: false,
                created_by: "setup",
            },
            NOW,
        )
        .await
        .unwrap()
}

/// The same TOTP code, carried by many concurrent sign-ins: accepted once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_totp_step_is_used_exactly_once_under_concurrency() {
    let server = RhypeServer::start();
    let store = AdminStore::new(db(&server));
    admin(&store, "alice").await;
    let step = NOW / 30;
    for round in 0..4 {
        let step = step + round;
        let results = race(|_| {
            let store = store.clone();
            async move { store.use_totp_step("alice", step, NOW).await.unwrap() }
        })
        .await;
        assert_eq!(winners(&results), 1, "round {round}: {results:?}");
    }
    let alice = store.find("alice").await.unwrap().unwrap();
    assert_eq!(alice.totp_last_step, step + 3);
    // Used once, refused ever after (while its claim lives).
    assert!(!store.use_totp_step("alice", step, NOW + 60).await.unwrap());
    // Another admin's same step is a different claim.
    admin(&store, "bob1").await;
    assert!(store.use_totp_step("bob1", step, NOW).await.unwrap());
}

/// Many concurrent confirmations of one pending secret: one enrolls, and the
/// epoch moves once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn totp_enrollment_is_confirmed_exactly_once() {
    let server = RhypeServer::start();
    let store = AdminStore::new(db(&server));
    admin(&store, "alice").await;
    assert!(store.set_totp_pending("alice", "sealed-1").await.unwrap());
    let read = store.find("alice").await.unwrap().unwrap();
    let results = race(|i| {
        let (store, read) = (store.clone(), read.clone());
        async move {
            store
                .confirm_totp(&read, 100 + i as i64, NOW)
                .await
                .unwrap()
        }
    })
    .await;
    assert_eq!(winners(&results), 1, "{results:?}");
    let after = store.find("alice").await.unwrap().unwrap();
    assert_eq!(after.totp_secret, "sealed-1");
    assert_eq!(after.totp_pending, "");
    assert_eq!(after.credential_epoch, read.credential_epoch + 1);
    // Enrolled: a new pending secret is refused.
    assert!(!store.set_totp_pending("alice", "sealed-2").await.unwrap());
}

/// Password changes and TOTP resets read at one epoch, all at once: exactly
/// one applies, so no change's session survives another's epoch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_credential_change_per_epoch_under_concurrency() {
    let server = RhypeServer::start();
    let store = AdminStore::new(db(&server));
    admin(&store, "alice").await;
    assert!(store.set_totp_pending("alice", "sealed-1").await.unwrap());
    let pending = store.find("alice").await.unwrap().unwrap();
    assert!(store.confirm_totp(&pending, 1, NOW).await.unwrap());
    for round in 0..3 {
        let read = store.find("alice").await.unwrap().unwrap();
        let results = race(|i| {
            let (store, read) = (store.clone(), read.clone());
            async move {
                if i % 2 == 0 {
                    let hash = format!("$argon2id$new-{i}");
                    store.set_password(&read, &hash, NOW).await.unwrap()
                } else {
                    store.reset_totp(&read, NOW).await.unwrap()
                }
            }
        })
        .await;
        assert_eq!(winners(&results), 1, "round {round}: {results:?}");
        let after = store.find("alice").await.unwrap().unwrap();
        assert_eq!(after.credential_epoch, read.credential_epoch + 1);
        // The winner's change, and only it, landed.
        let winner = results.iter().position(|w| *w).unwrap();
        if winner % 2 == 0 {
            assert_eq!(after.password_hash, format!("$argon2id$new-{winner}"));
            assert_eq!(after.totp_secret, read.totp_secret);
        } else {
            assert_eq!(after.password_hash, read.password_hash);
            assert_eq!(after.totp_secret, "");
        }
    }
}

/// A change whose writer died holding the epoch claim blocks the next epoch
/// only until the lease ends; then it is taken over.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_abandoned_epoch_claim_is_taken_over_after_its_lease() {
    let server = RhypeServer::start();
    let db = db(&server);
    let store = AdminStore::new(db.clone());
    let claims = Claims::new(db.clone());
    let alice = admin(&store, "alice").await;
    let key = claims::epoch_key("alice", alice.credential_epoch + 1);
    assert!(
        claims
            .claim(&key, "alice", NOW + claims::EPOCH_LEASE_SECS, NOW)
            .await
            .unwrap()
    );
    assert!(
        !store
            .set_password(&alice, "$argon2id$x", NOW + 1)
            .await
            .unwrap()
    );
    let later = NOW + claims::EPOCH_LEASE_SECS;
    let results = race(|_| {
        let (store, alice) = (store.clone(), alice.clone());
        async move {
            store
                .set_password(&alice, "$argon2id$y", later)
                .await
                .unwrap()
        }
    })
    .await;
    assert_eq!(winners(&results), 1, "{results:?}");
    let after = store.find("alice").await.unwrap().unwrap();
    assert_eq!(after.credential_epoch, 1);
    assert_eq!(after.password_hash, "$argon2id$y");
    // A stale reader cannot reuse the epoch once its claim is purged: the
    // update finds the epoch moved on.
    store
        .purge_claims(later + claims::EPOCH_LEASE_SECS)
        .await
        .unwrap();
    assert!(
        !store
            .set_password(&alice, "$argon2id$z", later + 999)
            .await
            .unwrap()
    );
    assert_eq!(
        store.find("alice").await.unwrap().unwrap().password_hash,
        "$argon2id$y"
    );
}

/// Expired claims are purged; live ones stay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn purging_claims_keeps_live_ones() {
    let server = RhypeServer::start();
    let db = db(&server);
    let store = AdminStore::new(db.clone());
    admin(&store, "alice").await;
    assert!(store.use_totp_step("alice", 1, NOW).await.unwrap());
    assert!(store.use_totp_step("alice", 2, NOW + 10).await.unwrap());
    store
        .purge_claims(NOW + claims::TOTP_CLAIM_SECS)
        .await
        .unwrap();
    let left = db.fetch::<Any>(&Ql::new("AdminClaim")).await.unwrap();
    assert_eq!(left.len(), 1);
}

fn nonce(nonce: &str, expires: i64) -> StoredNonce {
    StoredNonce {
        kind: SignerKind::Actor,
        signer: "a@b.example".into(),
        domain: "b.example".into(),
        key_id: "dk_1".into(),
        nonce: nonce.into(),
        signed_at: expires - 301,
        expires,
    }
}

fn accepted(results: &[Result<(), LedgerError>]) -> usize {
    for r in results {
        assert!(
            matches!(r, Ok(()) | Err(LedgerError::Duplicate)),
            "a racer failed: {r:?}"
        );
    }
    results.iter().filter(|r| r.is_ok()).count()
}

/// One nonce persisted by many ledgers at once (as by several processes,
/// past any in-memory store): recorded once, every other copy a replay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_nonce_is_recorded_exactly_once_by_racing_ledgers() {
    let server = RhypeServer::start();
    let ledgers: Vec<Arc<RhypeLedger>> = (0..RACERS)
        .map(|_| Arc::new(RhypeLedger::new(db(&server))))
        .collect();
    let ls = &ledgers;
    let persist_all = |n: StoredNonce, now: i64| {
        race(move |i| {
            let (l, n) = (ls[i].clone(), n.clone());
            async move { l.persist(&n, now).await }
        })
    };
    let results = persist_all(nonce("fresh", NOW + 300), NOW).await;
    assert_eq!(accepted(&results), 1, "{results:?}");

    // Reused after its window (§4.5 permits it) while the stale row is
    // still there: again exactly one reuse is recorded.
    let results = persist_all(nonce("fresh", NOW + 900), NOW + 600).await;
    assert_eq!(accepted(&results), 1, "{results:?}");
    let live = ledgers[0].load(NOW + 600).await.unwrap().nonces;
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].expires, NOW + 900);
    // The reuse persisted the clock first, so the deleted use stays expired
    // after a restart.
    assert!(ledgers[0].load(0).await.unwrap().clock.unwrap() >= NOW + 300);
}

/// Purges by many ledgers with different clocks, at once: the persisted
/// clock ends at the highest, never lower.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_persisted_replay_clock_never_goes_down_under_racing_purges() {
    let server = RhypeServer::start();
    let ledgers: Vec<Arc<RhypeLedger>> = (0..RACERS)
        .map(|_| Arc::new(RhypeLedger::new(db(&server))))
        .collect();
    for round in 0..3i64 {
        let base = NOW + round * 1_000;
        let results = race(|i| {
            let l = ledgers[i].clone();
            async move { l.purge(base + i as i64).await }
        })
        .await;
        assert!(results.iter().all(Result::is_ok), "{results:?}");
        let clock = ledgers[0].load(0).await.unwrap().clock;
        assert_eq!(clock, Some(base + RACERS as i64 - 1), "round {round}");
    }
    // Pruned down to the highest row (a few may remain from the race).
    ledgers[0].purge(NOW + 10_000).await.unwrap();
    let db = db(&server);
    let rows = db.fetch::<Any>(&Ql::new("ReplayClock")).await.unwrap();
    assert_eq!(rows.len(), 1);
}

/// The persisted clock is the highest row even when there are more rows
/// than one read returns and purges prune them while readers read (an
/// `offset` page could skip the highest row once a prune shifted the rest).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_replay_clock_is_read_whole_while_rows_are_pruned() {
    let server = RhypeServer::start();
    let db = db(&server);
    // Rows created out of order, more than several pages of two.
    for v in [5i64, 1, 9, 3, 7, 2, 8, 4, 6, 0] {
        let q = Ql::new("ReplayClock.create({ name: ")
            .str(&format!("replay@{}", NOW + v))
            .raw(", high_water: ")
            .unix_seconds(NOW + v)
            .raw(" })");
        db.execute(&q).await.unwrap();
    }
    let reader = RhypeLedger::with_page_size(db.clone(), 2);
    assert_eq!(reader.load(0).await.unwrap().clock, Some(NOW + 9));
    // Readers with small pages race writers that raise and prune.
    let readers: Vec<_> = (0..RACERS)
        .map(|i| (i, Arc::new(RhypeLedger::with_page_size(db.clone(), 2))))
        .collect();
    let rs = &readers;
    let results = race(move |i| {
        let (n, l) = (rs[i].0, rs[i].1.clone());
        async move {
            if n % 2 == 0 {
                l.purge(NOW + 10 + n as i64).await.map(|()| None)
            } else {
                l.load(0).await.map(|r| r.clock)
            }
        }
    })
    .await;
    for r in &results {
        // Every reader saw at least the highest row there from the start.
        let clock = r.as_ref().unwrap();
        assert!(clock.is_none_or(|c| c >= NOW + 9), "{results:?}");
    }
    let last = NOW + 10 + RACERS as i64 - 2;
    assert_eq!(reader.load(0).await.unwrap().clock, Some(last));
}
