use anyhow::Context;
use re_ofscp_server::{AppState, Config, router};
use tracing_subscriber::EnvFilter;

/// How long startup waits for the replay ledger and the federation policy
/// before serving (both keep retrying in the background after that).
const STARTUP_WAIT: std::time::Duration = std::time::Duration::from_secs(30);
/// How long shutdown waits for the notification queue to drain.
const NOTIFICATION_DRAIN: std::time::Duration = std::time::Duration::from_secs(10);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .json()
        .init();

    let config = Config::from_env().context("loading configuration")?;
    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .with_context(|| format!("binding {}", config.bind))?;
    tracing::info!(domain = %config.domain, bind = %config.bind, "re-ofscp listening");

    if !config.outbound_allow_hosts.is_empty() {
        let hosts: Vec<&str> = config
            .outbound_allow_hosts
            .iter()
            .map(|a| a.as_str())
            .collect();
        tracing::warn!(
            hosts = %hosts.join(","),
            "OUTBOUND_ALLOW_HOSTS is set: these peers may be on internal addresses"
        );
    }
    // Local accounts' keys come from rhypedb; remote signers' keys are
    // fetched through the SSRF-safe outbound client (docs/decisions/0006).
    let state = AppState::builder(config)
        .build()
        .context("building application state")?;
    // The managed database may not be listening yet. The replay restore
    // retries until it loads (ending the warm-up then) and the federation
    // policy load likewise; serving waits for both, together, up to
    // STARTUP_WAIT, then starts while they keep trying.
    let deadline = tokio::time::Instant::now() + STARTUP_WAIT;
    let (restored_tx, restored_rx) = tokio::sync::oneshot::channel();
    let replay = tokio::spawn(state.clone().maintain_replay(restored_tx));
    let stop_replay = replay.abort_handle();
    // A panic after startup stopped waiting would otherwise go unlogged.
    tokio::spawn(async move {
        if let Err(e) = replay.await
            && e.is_panic()
        {
            tracing::error!(
                error = %e,
                "replay maintenance panicked: the ledger purge has stopped, and an \
                 unfinished restore leaves the warm-up to run its course"
            );
        }
    });
    let wait_replay = async {
        match tokio::time::timeout_at(deadline, restored_rx).await {
            // The outcome is logged by the restore itself.
            Ok(Ok(_)) => {}
            Ok(Err(_)) => tracing::error!(
                "replay restore task ended without a result; signed requests get 503 \
                 for one skew window"
            ),
            Err(_) => tracing::warn!(
                "replay ledger not restored yet; serving in warm-up while the restore retries"
            ),
        }
    };
    // Federation stays refused (503, nothing sent) until the policy loads.
    let load_policy = async {
        match tokio::time::timeout_at(deadline, state.load_federation()).await {
            Ok(Ok(())) => {
                tracing::info!("federation policy loaded");
                None
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "federation policy unavailable at startup; retrying");
                Some(tokio::spawn(state.federation.clone().load_until_loaded()))
            }
            Err(_) => {
                tracing::warn!("federation policy load timed out at startup; retrying");
                Some(tokio::spawn(state.federation.clone().load_until_loaded()))
            }
        }
    };
    let ((), load_policy) = tokio::join!(wait_replay, load_policy);
    if state.admins.enabled() {
        tracing::info!("admin console enabled");
        if state.config.admin_loopback_http {
            tracing::warn!(
                "ADMIN_LOOPBACK_HTTP is on: the admin console also accepts http://{} \
                 (local development only)",
                state.config.domain
            );
        }
    } else {
        tracing::warn!("ADMIN_SECRET_KEY is not set; the admin API is off");
    }
    let purge_sessions = tokio::spawn(
        state
            .admins
            .clone()
            .purge_expired_forever(std::sync::Arc::new(re_ofscp_server::signing::SystemClock)),
    );
    let sweep_groups = tokio::spawn(state.groups.clone().sweep_forever());
    let sweep_messages = tokio::spawn(state.messages.clone().sweep_forever());
    // Channels from before message ordinals, numbered in the background
    // (docs/decisions/0022).
    let number_messages = tokio::spawn(state.messages.clone().number_forever());
    let ws_recheck = tokio::spawn(state.ws.clone().recheck_forever());
    let hub = state.ws.clone();
    let notifications = state.notifications.clone();
    let app = router(state);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_signal().await;
        // Upgraded sockets are not drained by axum: close them first.
        hub.shutdown().await;
    })
    .await?;
    // Messages the drained requests queued for their `message` feed
    // entries (docs/decisions/0023), given a bounded time; what is still
    // queued after it is lost, and counted here.
    if tokio::time::timeout(NOTIFICATION_DRAIN, notifications.flush())
        .await
        .is_err()
    {
        tracing::warn!(
            messages = notifications.background().unfinished(),
            "shutting down with messages whose `message` notification entries were not made"
        );
    }
    ws_recheck.abort();
    stop_replay.abort();
    if let Some(task) = load_policy {
        task.abort();
    }
    purge_sessions.abort();
    sweep_groups.abort();
    sweep_messages.abort();
    number_messages.abort();
    Ok(())
}

/// Resolve on Ctrl-C or SIGTERM so in-flight requests drain before exit.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { () = ctrl_c => {}, () = term => {} }
    tracing::info!("shutting down");
}
