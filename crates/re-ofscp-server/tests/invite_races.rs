//! Account invites and registrations racing against a real rhypedb-server
//! (docs/decisions/0012): one invite makes at most one account, the handle
//! is decided before the invite is touched, and a pending registration is
//! settled exactly once, however requests race, stall or crash.

mod common;

use std::sync::Arc;

use common::races::{Any, RACERS, db, race, winners};
use common::rhypedb::RhypeServer;
use re_ofscp_server::accounts::invites::InviteStore;
use re_ofscp_server::accounts::pending::{self, Held};
use re_ofscp_server::accounts::{
    AccountStore, PENDING_LEASE_SECS, PendingAccount, RegisterError, Revoked, Settlement,
    StoreError, User,
};
use re_ofscp_server::db::{Db, Ql};
use re_ofscp_server::profiles::ProfileStore;
use serde::Deserialize;

const NOW: i64 = 2_000_000_000;

/// Registration's serialized part, as `Accounts::register` runs it once the
/// invite, handle and password are checked. `password` stands in for its
/// hash, and proving it is comparing the two.
async fn register(
    invites: &InviteStore,
    accounts: &AccountStore,
    hash: &str,
    handle: &str,
    password: &str,
    now: i64,
) -> Result<User, RegisterError> {
    let held = match accounts
        .create_pending(handle, handle, password, hash, now)
        .await?
    {
        Held::Created(p) => p,
        Held::Joinable(p, stored) if stored == password => p,
        Held::Joinable(..) => return Err(RegisterError::HandleTaken),
    };
    pending::complete(accounts, invites, hash, &held, now).await
}

/// [`register`], as whether it made (or joined) the account. Refusals are
/// `false`; anything else fails the test.
async fn made(
    invites: &InviteStore,
    accounts: &AccountStore,
    hash: &str,
    handle: &str,
    password: &str,
    now: i64,
) -> bool {
    match register(invites, accounts, hash, handle, password, now).await {
        Ok(u) => {
            assert_eq!(u.handle, handle);
            true
        }
        Err(RegisterError::HandleTaken | RegisterError::InviteRequired) => false,
        Err(e) => panic!("{e}"),
    }
}

#[derive(Deserialize)]
struct PendingFlag {
    handle: String,
    #[serde(default)]
    pending: Option<bool>,
}

/// Accounts made (pending registrations are not accounts).
async fn accounts_made(db: &Db) -> usize {
    db.fetch::<PendingFlag>(&Ql::new("User"))
        .await
        .unwrap()
        .iter()
        .filter(|r| r.data.pending != Some(true))
        .count()
}

/// The rows (pending or not) holding `handle`.
async fn rows_for(db: &Db, handle: &str) -> Vec<Option<bool>> {
    db.fetch::<PendingFlag>(&Ql::new("User.filter(.handle == ").str(handle).raw(")"))
        .await
        .unwrap()
        .into_iter()
        .map(|r| {
            assert_eq!(r.data.handle, handle);
            r.data.pending
        })
        .collect()
}

async fn new_invite(invites: &InviteStore, hash: &str) {
    invites
        .create(hash, None, "owner", NOW, NOW + 3_600)
        .await
        .unwrap();
}

/// A distinct invite hash for `n`.
fn invite_hash(n: usize) -> String {
    format!("{n:064x}")
}

/// A registration that crashed right after holding `handle`.
async fn stranded(accounts: &AccountStore, hash: &str, handle: &str, now: i64) -> PendingAccount {
    match accounts
        .create_pending(handle, handle, "pw", hash, now)
        .await
        .unwrap()
    {
        Held::Created(p) => p,
        Held::Joinable(..) => panic!("{handle} was already pending"),
    }
}

/// One single-use invite presented by many registrations at once, each for
/// its own handle: redeemed once, one account. It stays spent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_invite_is_redeemed_exactly_once_under_concurrency() {
    let server = RhypeServer::start();
    let db = db(&server);
    let invites = Arc::new(InviteStore::new(db.clone()));
    let accounts = Arc::new(AccountStore::new(db.clone()));
    let hash = "a".repeat(64);
    new_invite(&invites, &hash).await;
    for round in 0..2 {
        let results = race(|i| {
            let (invites, accounts, hash) = (invites.clone(), accounts.clone(), hash.clone());
            async move {
                let handle = format!("r{round}user{i}");
                made(&invites, &accounts, &hash, &handle, "pw", NOW + 1).await
            }
        })
        .await;
        let expected = usize::from(round == 0);
        assert_eq!(winners(&results), expected, "round {round}");
    }
    assert_eq!(accounts_made(&db).await, 1);
    assert!(invites.find_usable(&hash, NOW + 2).await.unwrap().is_none());
    assert!(invites.list_usable(NOW + 2, 10).await.unwrap().is_empty());
    let rows = db.fetch::<Any>(&Ql::new("InviteRedemption")).await.unwrap();
    assert_eq!(rows.len(), 1);
}

/// Many registrations on one invite, several per handle, so redeemers race
/// resumers of the same redemption: still exactly one account.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_32_way_race_on_one_invite_makes_one_account() {
    let server = RhypeServer::start();
    let db = db(&server);
    let invites = Arc::new(InviteStore::new(db.clone()));
    let accounts = Arc::new(AccountStore::new(db.clone()));
    for round in 0..4u8 {
        let hash = char::from(b'b' + round).to_string().repeat(64);
        new_invite(&invites, &hash).await;
        let results = race(|i| {
            let (invites, accounts, hash) = (invites.clone(), accounts.clone(), hash.clone());
            async move {
                // Several racers per handle, each with its own password, so
                // none may join another's registration.
                let handle = format!("r{round}user{}", i % 4);
                made(
                    &invites,
                    &accounts,
                    &hash,
                    &handle,
                    &format!("pw{i}"),
                    NOW + 1,
                )
                .await
            }
        })
        .await;
        assert_eq!(winners(&results), 1, "round {round}: {results:?}");
        assert_eq!(accounts_made(&db).await, usize::from(round) + 1);
    }
}

/// The original redeemer stalls (past any lease), while others arrive: one
/// for another handle is refused, one for the same handle resumes. Then
/// both go on to create the account: one account, and the invite stays
/// spent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stalled_redeemer_cannot_let_a_second_account_through() {
    let server = RhypeServer::start();
    let db = db(&server);
    let invites = InviteStore::new(db.clone());
    let accounts = AccountStore::new(db.clone());
    let hash = "f".repeat(64);
    new_invite(&invites, &hash).await;
    // A redeems, then stalls before creating its account.
    assert!(invites.redeem(&hash, "alice", NOW).await.unwrap());
    let later = NOW + 600;
    assert!(!invites.redeem(&hash, "bob", later).await.unwrap());
    // B, for the same handle, resumes; both create the account at once.
    assert!(invites.redeem(&hash, "alice", later).await.unwrap());
    let create = |at| accounts.create_user("alice", "alice", "$argon2id$placeholder", at);
    let (a, b) = tokio::join!(create(NOW), create(later));
    assert_eq!(
        usize::from(a.is_ok()) + usize::from(b.is_ok()),
        1,
        "{a:?} {b:?}"
    );
    assert!(matches!(a.err().or(b.err()), Some(StoreError::HandleTaken)));
    // Still spent on alice: no other handle gets through, now or later.
    assert!(!made(&invites, &accounts, &hash, "carol", "pw", later + 1).await);
    assert_eq!(accounts_made(&db).await, 1);
}

/// A request that crashed after redeeming, before marking the invite used
/// or making the account: the invite reads spent everywhere (it is not
/// listed, and revoking it says used), refuses every other handle, and the
/// same handle can still finish.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_redemption_stranded_by_a_crash_fails_closed_but_resumes_its_handle() {
    let server = RhypeServer::start();
    let db = db(&server);
    let invites = InviteStore::new(db.clone());
    let accounts = AccountStore::new(db.clone());
    let hash = "g".repeat(64);
    new_invite(&invites, &hash).await;
    let spare = "h".repeat(64);
    new_invite(&invites, &spare).await;
    let q = Ql::new("InviteRedemption.create({ token_hash: ")
        .str(&hash)
        .raw(", handle: \"dave\", redeemed_at: ")
        .unix_seconds(NOW)
        .raw(" })");
    db.execute(&q).await.unwrap();
    let live = invites.find_live(&hash, NOW + 1).await.unwrap().unwrap();
    assert_eq!(live.used_by, None, "marking used is what the crash skipped");
    assert!(invites.find_usable(&hash, NOW + 1).await.unwrap().is_none());
    let listed = invites.list_usable(NOW + 1, 1).await.unwrap();
    assert_eq!(listed.len(), 1, "fetched past the redeemed one");
    assert_eq!(listed[0].token_hash, spare);
    assert!(!made(&invites, &accounts, &hash, "erin", "pw", NOW + 1).await);
    assert!(made(&invites, &accounts, &hash, "dave", "pw", NOW + 2).await);
    let live = invites.find_live(&hash, NOW + 3).await.unwrap().unwrap();
    assert_eq!(live.used_by.as_deref(), Some("dave"));
    assert_eq!(invites.revoke(&hash, NOW + 3).await.unwrap(), Revoked::Used);
    assert_eq!(accounts_made(&db).await, 1);
}

/// Many invites racing for one handle: the handle goes to one, and every
/// other invite is untouched, so it registers another handle.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invites_racing_for_one_handle_leave_the_losers_usable() {
    let server = RhypeServer::start();
    let db = db(&server);
    let invites = Arc::new(InviteStore::new(db.clone()));
    let accounts = Arc::new(AccountStore::new(db.clone()));
    for round in 0..3usize {
        let base = round * RACERS;
        for i in 0..RACERS {
            new_invite(&invites, &invite_hash(base + i)).await;
        }
        let handle = format!("wanted{round}");
        let results = race(|i| {
            let (invites, accounts, handle) = (invites.clone(), accounts.clone(), handle.clone());
            async move {
                let hash = invite_hash(base + i);
                made(&invites, &accounts, &hash, &handle, "pw", NOW + 1).await
            }
        })
        .await;
        assert_eq!(winners(&results), 1, "round {round}: {results:?}");
        assert_eq!(rows_for(&db, &handle).await, vec![Some(false)]);
        for (i, won) in results.iter().enumerate() {
            let hash = invite_hash(base + i);
            let usable = invites.find_usable(&hash, NOW + 2).await.unwrap();
            assert_eq!(usable.is_some(), !won, "round {round} invite {i}");
            if !won {
                let other = format!("r{round}spare{i}");
                assert!(made(&invites, &accounts, &hash, &other, "pw", NOW + 2).await);
            }
        }
    }
    assert_eq!(accounts_made(&db).await, 3 * RACERS);
}

/// An admin creating a handle while registrations race for it: one of
/// them gets it, and the invites that lost are untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_admin_create_races_registrations_for_one_handle() {
    let server = RhypeServer::start();
    let db = db(&server);
    let invites = Arc::new(InviteStore::new(db.clone()));
    let accounts = Arc::new(AccountStore::new(db.clone()));
    for round in 0..4usize {
        let base = round * RACERS;
        for i in 1..RACERS {
            new_invite(&invites, &invite_hash(base + i)).await;
        }
        let handle = format!("contested{round}");
        let results = race(|i| {
            let (invites, accounts, handle) = (invites.clone(), accounts.clone(), handle.clone());
            async move {
                if i == 0 {
                    match accounts.create_user(&handle, &handle, "pw", NOW + 1).await {
                        Ok(_) => true,
                        Err(StoreError::HandleTaken) => false,
                        Err(e) => panic!("{e}"),
                    }
                } else {
                    let hash = invite_hash(base + i);
                    made(&invites, &accounts, &hash, &handle, "pw", NOW + 1).await
                }
            }
        })
        .await;
        assert_eq!(winners(&results), 1, "round {round}: {results:?}");
        assert_eq!(rows_for(&db, &handle).await.len(), 1);
        for (i, won) in results.iter().enumerate().skip(1) {
            let usable = invites
                .find_usable(&invite_hash(base + i), NOW + 2)
                .await
                .unwrap();
            assert_eq!(usable.is_some(), !won, "round {round} invite {i}");
        }
    }
}

/// A registration that crashed after holding its handle is invisible as
/// an account, keeps the handle from rivals while live, and is reclaimed
/// once stale; the request that stalled then finds its row gone, and its
/// invite (never redeemed) still works.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stranded_pending_registration_is_invisible_and_reclaimed_when_stale() {
    let server = RhypeServer::start();
    let db = db(&server);
    let invites = InviteStore::new(db.clone());
    let accounts = AccountStore::new(db.clone());
    let profiles = ProfileStore::new(db.clone());
    let (first, rival) = (invite_hash(1), invite_hash(2));
    new_invite(&invites, &first).await;
    new_invite(&invites, &rival).await;
    let held = stranded(&accounts, &first, "gina", NOW).await;

    assert_eq!(accounts.find_user("gina").await.unwrap(), None);
    assert!(profiles.profile("gina").await.unwrap().is_none());
    let summary = accounts.summary("gina").await.unwrap().unwrap();
    assert_eq!(summary.status, "pending");
    let listed = accounts.search(Some("gina"), 10).await.unwrap();
    assert_eq!(listed, vec![summary]);
    assert_eq!(accounts_made(&db).await, 0);

    // Live: rivals are refused, and the rival invite is untouched.
    let live = NOW + PENDING_LEASE_SECS - 1;
    assert!(!made(&invites, &accounts, &rival, "gina", "pw", live).await);
    assert!(matches!(
        accounts.create_user("gina", "gina", "pw", live).await,
        Err(StoreError::HandleTaken)
    ));
    assert!(invites.find_usable(&rival, live).await.unwrap().is_some());

    // Stale: the rival takes the handle; the stalled request cannot.
    let stale = NOW + PENDING_LEASE_SECS;
    assert!(made(&invites, &accounts, &rival, "gina", "pw", stale).await);
    assert_eq!(
        pending::complete(&accounts, &invites, &first, &held, stale).await,
        Err(RegisterError::HandleTaken)
    );
    assert_eq!(rows_for(&db, "gina").await, vec![Some(false)]);
    assert!(invites.find_usable(&first, stale).await.unwrap().is_some());
    assert!(made(&invites, &accounts, &first, "hank", "pw", stale).await);
    assert_eq!(accounts_made(&db).await, 2);
}

/// A registration that crashed after settling its row to activate, before
/// activating it. A retry with its invite and password joins and finishes
/// it; any other create meeting the row finishes it and finds it taken.
/// Either way, long past the lease, it is never discarded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_registration_settled_to_activate_is_finished_not_discarded() {
    let server = RhypeServer::start();
    let db = db(&server);
    let invites = InviteStore::new(db.clone());
    let accounts = AccountStore::new(db.clone());
    let later = NOW + 10 * PENDING_LEASE_SECS;
    for (n, handle) in [(1, "ivy"), (3, "jay")] {
        let (own, rival) = (invite_hash(n), invite_hash(n + 1));
        new_invite(&invites, &own).await;
        new_invite(&invites, &rival).await;
        let held = stranded(&accounts, &own, handle, NOW).await;
        assert!(invites.redeem(&own, handle, NOW).await.unwrap());
        let won = accounts.settle(&held.key, Settlement::Activate, NOW).await;
        assert_eq!(won.unwrap(), Settlement::Activate);
        assert_eq!(accounts.find_user(handle).await.unwrap(), None);
        if handle == "ivy" {
            assert!(made(&invites, &accounts, &own, handle, "pw", later).await);
        } else {
            assert!(!made(&invites, &accounts, &rival, handle, "pw", later).await);
            assert!(accounts.find_user(handle).await.unwrap().is_some());
        }
        assert!(invites.find_usable(&rival, later).await.unwrap().is_some());
        assert_eq!(rows_for(&db, handle).await, vec![Some(false)]);
    }
    // Once it is an account, it is simply taken, invite or not.
    assert!(!made(&invites, &accounts, &invite_hash(1), "ivy", "pw", later).await);
}

/// The original request stalled after redeeming, past the lease, finishes
/// while rivals reclaim its row: one of them makes the account, never two.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stalled_registration_and_stale_reclaimers_make_one_account() {
    let server = RhypeServer::start();
    let db = db(&server);
    let invites = Arc::new(InviteStore::new(db.clone()));
    let accounts = Arc::new(AccountStore::new(db.clone()));
    for round in 0..4usize {
        let base = round * RACERS;
        for i in 0..RACERS {
            new_invite(&invites, &invite_hash(base + i)).await;
        }
        let handle = format!("stalled{round}");
        let original = invite_hash(base);
        let held = Arc::new(stranded(&accounts, &original, &handle, NOW).await);
        assert!(invites.redeem(&original, &handle, NOW).await.unwrap());
        let at = NOW + PENDING_LEASE_SECS;
        let results = race(|i| {
            let (invites, accounts, handle) = (invites.clone(), accounts.clone(), handle.clone());
            let (held, original) = (held.clone(), original.clone());
            async move {
                if i == 0 {
                    match pending::complete(&accounts, &invites, &original, &held, at).await {
                        Ok(_) => true,
                        Err(RegisterError::HandleTaken) => false,
                        Err(e) => panic!("{e}"),
                    }
                } else {
                    let hash = invite_hash(base + i);
                    made(&invites, &accounts, &hash, &handle, "rival", at).await
                }
            }
        })
        .await;
        assert_eq!(winners(&results), 1, "round {round}: {results:?}");
        assert_eq!(rows_for(&db, &handle).await, vec![Some(false)]);
        for (i, won) in results.iter().enumerate().skip(1) {
            let usable = invites
                .find_usable(&invite_hash(base + i), at)
                .await
                .unwrap();
            assert_eq!(usable.is_some(), !won, "round {round} invite {i}");
        }
        // The original invite is spent on the handle either way.
        assert!(invites.find_usable(&original, at).await.unwrap().is_none());
    }
    assert_eq!(accounts_made(&db).await, 4);
}

/// One registration sent many times at once (same invite, handle and
/// password): copies that meet it pending join it, later ones find the
/// account made (`409`, as for any retry after success). One account.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn duplicated_requests_join_one_registration() {
    let server = RhypeServer::start();
    let db = db(&server);
    let invites = Arc::new(InviteStore::new(db.clone()));
    let accounts = Arc::new(AccountStore::new(db.clone()));
    let hash = invite_hash(7);
    new_invite(&invites, &hash).await;
    let results = race(|_| {
        let (invites, accounts, hash) = (invites.clone(), accounts.clone(), hash.clone());
        async move { register(&invites, &accounts, &hash, "jules", "pw", NOW + 1).await }
    })
    .await;
    let joined = results.iter().filter(|r| r.is_ok()).count();
    assert!(joined >= 1, "{results:?}");
    assert!(
        results
            .iter()
            .all(|r| matches!(r, Ok(_) | Err(RegisterError::HandleTaken))),
        "{results:?}"
    );
    assert_eq!(rows_for(&db, "jules").await, vec![Some(false)]);
    let settled = db
        .fetch::<Any>(&Ql::new("AccountSettlement"))
        .await
        .unwrap();
    assert_eq!(settled.len(), 1);
}
