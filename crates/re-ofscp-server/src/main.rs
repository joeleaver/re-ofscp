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

    // Local accounts' keys come from rhypedb. Remote signers are refused
    // until the SSRF-safe remote resolver lands.
    let state = AppState::builder(config).build();
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
    let app = router(state);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    purge.abort();
    purge_sessions.abort();
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
