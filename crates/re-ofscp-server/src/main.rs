use anyhow::Context;
use re_ofscp_server::{AppState, Config, router};
use tracing_subscriber::EnvFilter;

/// How long startup waits for the replay ledger before serving in warm-up.
const RESTORE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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
    match tokio::time::timeout(RESTORE_TIMEOUT, state.restore_replay()).await {
        Ok(Ok(n)) => tracing::info!(restored = n, "replay store restored from the ledger"),
        Ok(Err(e)) => tracing::warn!(
            error = %e,
            "replay ledger unavailable at startup; signed requests get 503 for one skew window"
        ),
        Err(_) => tracing::warn!(
            "replay ledger restore timed out; signed requests get 503 for one skew window"
        ),
    }
    // Federation stays refused (503, nothing sent) until the policy loads.
    let load_policy = match tokio::time::timeout(RESTORE_TIMEOUT, state.load_federation()).await {
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
    };
    let purge = tokio::spawn(state.clone().purge_ledger_forever());
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
            .purge_sessions_forever(std::sync::Arc::new(re_ofscp_server::signing::SystemClock)),
    );
    let sweep_groups = tokio::spawn(state.groups.clone().sweep_forever());
    let ws_recheck = tokio::spawn(state.ws.clone().recheck_forever());
    let hub = state.ws.clone();
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
    ws_recheck.abort();
    purge.abort();
    if let Some(task) = load_policy {
        task.abort();
    }
    purge_sessions.abort();
    sweep_groups.abort();
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
