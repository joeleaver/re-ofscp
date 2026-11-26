//! The federation allow/deny policy (spec §8 *Authorization* as settled by
//! lost-conn/ofscp#25, §4.5 step 6, §8.1 step 2, §4.6 "No fetch is
//! allowed", §7.1, §8.5; docs/decisions/0008).
//!
//! [`FederationPolicy`] holds the policy in force, in memory, for the hot
//! paths that consult it:
//!
//! * the verifier, which answers `403` `forbidden` to a signer whose
//!   provider is denied, at the start of §4.5 step 6 (after the replay
//!   *check* and the digest, before any key is resolved, so a denied
//!   request never records a nonce and never uses a cached key);
//! * the remote key resolver, which neither fetches nor answers from its
//!   cache for a denied provider;
//! * the outbound client, which refuses every request to a denied
//!   provider, whoever asks and whatever stored state names it.
//!
//! The policy never applies to this provider's own authority (local
//! signers and requests to itself are not federation): a policy built
//! with [`FederationPolicy::unloaded_for`] always permits it, even before
//! it loads, on every path that consults it.
//!
//! Until the stored policy has been read ([`store::PolicyStore::load`])
//! the policy is *unknown*, and every federation decision fails closed
//! as a temporary refusal (`503`, outbound requests not sent), never as
//! "denied" (`403` would tell a peer it is blocked) nor as "open" (an
//! allowlist provider would federate with anyone after a restart).
//!
//! **WebSocket close `4001` (§7.1).** A connection authenticated as a
//! remote actor must close with `4001` at once when that actor's provider
//! becomes denied, and §8.5 makes the same check at `authenticate` a MUST
//! (an `error` event, then `4001`). [`FederationPolicy::watch`] is the
//! seam: the connection task selects on [`PolicyWatch::until_denied`] for
//! its actor's domain beside its socket, and closes `4001` when it
//! resolves. The same check at `authenticate` time is
//! [`FederationPolicy::decide`].

pub mod rules;
pub mod store;

use std::sync::Arc;

use re_ofscp_types::Authority;
use tokio::sync::watch;

pub use self::rules::{Rule, RuleSet, Snapshot};

/// `Retry-After` while the policy is not yet loaded.
pub const UNKNOWN_RETRY_SECS: u64 = 5;

/// What the policy says about a remote provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Federation is permitted.
    Permitted,
    /// Federation is denied: `403` inbound, no request outbound.
    Denied,
    /// The policy has not been loaded yet: fail closed, temporarily.
    Unknown,
}

/// The policy in force. Cheap to share (`Arc`); every reader sees each
/// [`install`](Self::install) at once.
#[derive(Debug)]
pub struct FederationPolicy {
    current: watch::Sender<Option<Arc<Snapshot>>>,
    /// This provider's own authority, never subject to the policy.
    own: Option<Authority>,
}

impl FederationPolicy {
    /// A policy not loaded yet (every decision [`Decision::Unknown`]).
    pub fn unloaded() -> Self {
        Self {
            current: watch::Sender::new(None),
            own: None,
        }
    }

    /// The provider `own`'s policy, not loaded yet: every decision is
    /// [`Decision::Unknown`] except about `own`, which is always permitted.
    pub fn unloaded_for(own: Authority) -> Self {
        Self {
            current: watch::Sender::new(None),
            own: Some(own),
        }
    }

    /// A loaded policy: `snapshot`.
    pub fn with(snapshot: Snapshot) -> Self {
        Self {
            current: watch::Sender::new(Some(Arc::new(snapshot))),
            own: None,
        }
    }

    /// A loaded, open policy (federate with everyone), for clients and
    /// tests that have no stored policy.
    pub fn open() -> Self {
        Self::with(Snapshot::default())
    }

    /// The policy in force, if loaded.
    pub fn snapshot(&self) -> Option<Arc<Snapshot>> {
        self.current.borrow().clone()
    }

    /// Put `snapshot` in force, waking every [`PolicyWatch`].
    pub fn install(&self, snapshot: Snapshot) {
        self.current.send_replace(Some(Arc::new(snapshot)));
    }

    /// The policy's verdict on the remote provider `authority`.
    pub fn decide(&self, authority: &Authority) -> Decision {
        decide(
            self.own.as_ref(),
            self.current.borrow().as_deref(),
            authority,
        )
    }

    /// Follow policy changes (the §7.1 `4001` seam, see the module docs).
    pub fn watch(&self) -> PolicyWatch {
        PolicyWatch {
            current: self.current.subscribe(),
            own: self.own.clone(),
        }
    }
}

fn decide(own: Option<&Authority>, snapshot: Option<&Snapshot>, authority: &Authority) -> Decision {
    if own == Some(authority) {
        return Decision::Permitted;
    }
    match snapshot {
        None => Decision::Unknown,
        Some(s) if s.permits(authority) => Decision::Permitted,
        Some(_) => Decision::Denied,
    }
}

/// A receiver of policy changes, from [`FederationPolicy::watch`].
#[derive(Debug, Clone)]
pub struct PolicyWatch {
    current: watch::Receiver<Option<Arc<Snapshot>>>,
    own: Option<Authority>,
}

impl PolicyWatch {
    /// Resolve once the policy in force denies `authority`: at once if it
    /// already does, else at the first change that denies it. An unknown
    /// policy does not count as denying (the policy is unknown only before
    /// its first load). Never resolves if the policy is dropped (the
    /// provider is shutting down).
    pub async fn until_denied(&mut self, authority: &Authority) {
        // `is_ok` drops the borrow at once, so the future stays `Send`.
        let own = self.own.as_ref();
        let denied = self
            .current
            .wait_for(|s| decide(own, s.as_deref(), authority) == Decision::Denied)
            .await
            .is_ok();
        if !denied {
            std::future::pending::<()>().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use re_ofscp_types::federation::{FederationMode, RuleList, RuleScope};

    use super::*;

    fn a(s: &str) -> Authority {
        Authority::parse_canonical(s).unwrap()
    }

    fn denying(value: &str) -> Snapshot {
        let mut s = Snapshot {
            mode: FederationMode::Denylist,
            ..Snapshot::default()
        };
        s.deny.insert(Rule {
            id: "r1".to_owned(),
            list: RuleList::Deny,
            scope: RuleScope::Domain,
            value: value.to_owned(),
            note: String::new(),
            created_by: "owner".to_owned(),
            created_at: 0,
        });
        s
    }

    #[test]
    fn decisions_follow_the_installed_snapshot() {
        let p = FederationPolicy::unloaded();
        assert_eq!(p.decide(&a("x.example")), Decision::Unknown);
        assert!(p.snapshot().is_none());
        p.install(denying("evil.example"));
        assert_eq!(p.decide(&a("a.evil.example")), Decision::Denied);
        assert_eq!(p.decide(&a("good.example")), Decision::Permitted);
        assert_eq!(
            FederationPolicy::open().decide(&a("evil.example")),
            Decision::Permitted
        );
    }

    #[test]
    fn the_providers_own_authority_is_always_permitted() {
        let own = a("re-ofscp.example");
        let p = FederationPolicy::unloaded_for(own.clone());
        assert_eq!(p.decide(&own), Decision::Permitted);
        assert_eq!(p.decide(&a("other.example")), Decision::Unknown);
        // Even an empty allowlist, or a domain rule above it, spares it.
        p.install(Snapshot {
            mode: FederationMode::Allowlist,
            ..Snapshot::default()
        });
        assert_eq!(p.decide(&own), Decision::Permitted);
        assert_eq!(p.decide(&a("other.example")), Decision::Denied);
        p.install(denying("example"));
        assert_eq!(p.decide(&own), Decision::Permitted);
    }

    #[tokio::test]
    async fn a_watch_never_resolves_for_the_providers_own_authority() {
        let own = a("re-ofscp.example");
        let p = FederationPolicy::unloaded_for(own.clone());
        p.install(Snapshot {
            mode: FederationMode::Allowlist,
            ..Snapshot::default()
        });
        let mut w = p.watch();
        let r = tokio::time::timeout(Duration::from_millis(50), w.until_denied(&own)).await;
        assert!(r.is_err(), "this provider is never denied to itself");
    }

    #[tokio::test]
    async fn a_watch_resolves_when_its_provider_becomes_denied() {
        let p = Arc::new(FederationPolicy::unloaded());
        let mut w = p.watch();
        let evil = a("chat.evil.example");
        let waiting = tokio::spawn(async move { w.until_denied(&evil).await });

        // Loading an open policy, and denying someone else, change nothing.
        p.install(Snapshot::default());
        p.install(denying("other.example"));
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiting.is_finished());

        p.install(denying("evil.example"));
        tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("the watch resolves")
            .unwrap();
    }

    #[tokio::test]
    async fn a_watch_on_an_already_denied_provider_resolves_at_once() {
        let p = FederationPolicy::with(denying("evil.example"));
        let mut w = p.watch();
        tokio::time::timeout(Duration::from_secs(1), w.until_denied(&a("evil.example")))
            .await
            .expect("already denied");
    }

    #[tokio::test]
    async fn a_watch_never_resolves_once_the_policy_is_gone() {
        let p = FederationPolicy::open();
        let mut w = p.watch();
        drop(p);
        let r = tokio::time::timeout(
            Duration::from_millis(50),
            w.until_denied(&a("evil.example")),
        )
        .await;
        assert!(r.is_err(), "a dropped policy is not a denial");
    }
}
