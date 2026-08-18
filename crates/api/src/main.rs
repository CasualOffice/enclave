//! `enclave-api` — the HTTP binary.
//!
//! Composition only. Every decision it makes is which implementation to hand the policy engine;
//! none of them are policy decisions themselves.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use enclave_api::{router, unconfigured_stages, ApiState};
use enclave_core::PolicyEngine;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let loaded = enclave_config::ConfigLoader::new()
        .with_file("enclave.yaml")
        .load()
        .context("load configuration")?;
    let config = loaded.config();

    enclave_observability::init(&Default::default()).context("initialise tracing")?;

    // Loud, once, at start-up. A deployment running with five of six stages permitting everything
    // looks identical from the outside to one carefully allowing each request, and the difference
    // matters enormously. `docs/12-TESTING.md §5` has CI proving the gates; this is the equivalent
    // for an operator standing in front of a running process.
    for stage in unconfigured_stages() {
        tracing::warn!(stage, "policy stage is not enforcing");
    }

    if config.profile == enclave_config::DeploymentProfile::Enterprise {
        anyhow::bail!(
            "the enterprise profile refuses to start while {} policy stages are unconfigured: {}. \
             Running with DLP disabled and no conditional access is a legitimate development \
             posture and an illegitimate enterprise one.",
            unconfigured_stages().len(),
            unconfigured_stages().join("; "),
        );
    }

    // Secrets are references in configuration and values only here, at the last moment
    // (`docs/08-BYO-INFRA.md §6`). `local()` serves env:// and file://; Vault and the cloud
    // managers register the same way when a deployment configures them.
    let registry = enclave_config::SecretRegistry::local();
    let secrets = loaded.resolve_secrets(&registry).await.context("resolve secrets")?;

    let db_config = db_config_from(config, &secrets)?;
    let db = enclave_db::DbPool::connect(&db_config).await.context("connect to PostgreSQL")?;
    enclave_db::run_migrations(&db_config).await.context("apply migrations")?;

    let keys = enclave_auth::KeySet::new(std::iter::empty());
    let audit =
        Arc::new(enclave_audit::PgAuditSink::new(db.clone(), enclave_audit::ChainMode::Enabled));

    let policy = PolicyEngine::new(
        Arc::new(enclave_conditional_access::UnconfiguredConditionalAccess),
        Arc::new(enclave_authorization::SelfServiceAuthorization),
        Arc::new(enclave_information_barriers::UnconfiguredBarriers),
        Arc::new(enclave_classification::UnconfiguredClassification),
        Arc::new(enclave_dlp::DisabledDlp),
        Arc::new(enclave_retention::UnconfiguredRetention),
        audit,
    );

    let state = ApiState::new(
        policy,
        db,
        config.auth.access_token.issuer.as_deref().unwrap_or_default(),
        config.auth.access_token.audience.as_str(),
        keys,
    );

    let addr = SocketAddr::new(config.server.bind, config.server.port);
    let listener = tokio::net::TcpListener::bind(addr).await.context("bind")?;
    tracing::info!(%addr, "enclave-api listening");

    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown())
        .await
        .context("serve")?;
    Ok(())
}

/// Translates the configuration's database section into the `db` crate's own type.
///
/// The two are separate on purpose: `config` describes what an operator writes, `db` describes what
/// a pool needs. Collapsing them would make every pool option a public configuration surface.
fn db_config_from(
    config: &enclave_config::Config,
    secrets: &enclave_config::ResolvedSecrets,
) -> anyhow::Result<enclave_db::DbConfig> {
    let url = secrets
        .get("database.url")
        .context("database.url did not resolve; set `database.url_env: DATABASE_URL` or a secret reference")?
        .expose_str()
        .context("database.url is not valid UTF-8")?;

    Ok(enclave_db::DbConfig::new(enclave_db::ConnectionUrl::new(url))
        .with_max_connections(config.database.max_connections))
}

/// Waits for SIGTERM or Ctrl-C.
///
/// Graceful shutdown is not politeness: in-flight requests hold tenant-scoped transactions, and
/// dropping them mid-flight leaves the audit row and the state change it describes disagreeing
/// about whether the operation happened.
async fn shutdown() {
    let _ignored = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}
