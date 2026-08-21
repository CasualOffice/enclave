//! `enclave-scheduler` — the binary. Composes configuration, the pool and the cadence.
//!
//! `ENC-584` gives this process its first job: the nightly storage-quota reconciliation
//! (`docs/04-DATA-MODEL.md §16`, `plans/M4-GOVERNANCE.md` D31). The pass itself is
//! [`enclave_db::reconcile_storage`]; the loop is [`enclave_scheduler::run_storage_reconciliation`];
//! this file only decides *where the credentials come from* and *when to stop*.
//!
//! # The platform credential is required, and the refusal is deliberate
//!
//! Reconciliation walks every tenant, and the query that produces a tenant list cannot itself be
//! tenant-scoped — that is `plans/M0-FOUNDATIONS.md` D3's third legitimate cross-tenant caller.
//! Without `database.platform_url` this process would loop over nothing, forever, reporting healthy:
//! drift would stop being detected and the only symptom would be a metric that never moved.
//! `crates/worker/src/main.rs` refuses for the same reason and names it the same way.

use anyhow::Context as _;
use enclave_scheduler::{Stop, STORAGE_RECONCILIATION_INTERVAL};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let loaded = enclave_config::ConfigLoader::new()
        .with_file("enclave.yaml")
        .load()
        .context("load configuration")?;
    let config = loaded.config();

    enclave_observability::init(&Default::default()).context("initialise tracing")?;

    // Secrets are references in configuration and values only here, at the last moment
    // (`docs/08-BYO-INFRA.md §6`), exactly as in the API and worker binaries.
    let registry = enclave_config::SecretRegistry::local();
    let secrets = loaded.resolve_secrets(&registry).await.context("resolve secrets")?;

    let db_config = db_config_from(config, &secrets)?;
    let db = enclave_db::DbPool::connect(&db_config).await.context("connect to PostgreSQL")?;

    anyhow::ensure!(
        db.has_platform_access(),
        "the scheduler needs `database.platform_url` — the DSN of the BYPASSRLS role — because the \
         query that produces a tenant list cannot itself be scoped to a tenant. Without it this \
         process would reconcile nothing while reporting healthy. See \
         migrations/0002_rls_policies.sql, which grants `SELECT ON tenants TO enclave_platform` for \
         exactly this enumerator."
    );

    // Migrations are **not** run here. The API and the worker each apply them at start-up and take
    // sqlx's advisory lock while they do; a third process doing the same buys nothing and adds a
    // contender to a rolling deploy. `docs/11-OPERATIONS.md §3` puts the expand phase before any of
    // them in any case.

    let stop = Stop::new();
    let signals = {
        let stop = stop.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            tracing::info!("shutdown signal received; finishing the current pass");
            stop.stop();
        })
    };

    tracing::info!("enclave-scheduler starting");
    let passes =
        enclave_scheduler::run_storage_reconciliation(&db, STORAGE_RECONCILIATION_INTERVAL, &stop)
            .await;
    tracing::info!(passes, "enclave-scheduler stopped");

    // Nothing waits on the handler any more; leaving it registered keeps a task alive holding a
    // signal stream after the process has decided to exit.
    signals.abort();

    // After the loop has returned, never before: `DbPool::close` waits for checked-out connections,
    // and the loop only returns between transactions.
    db.close().await;
    Ok(())
}

/// The database configuration, assembled from resolved secret references.
///
/// The same shape `crates/worker/src/main.rs` uses. It is repeated rather than shared because the
/// alternative is a dependency from one binary crate to another to obtain fifteen lines of
/// plumbing, and the two will diverge the moment either grows a knob the other does not want.
fn db_config_from(
    config: &enclave_config::Config,
    secrets: &enclave_config::ResolvedSecrets,
) -> anyhow::Result<enclave_db::DbConfig> {
    let url = secrets
        .get("database.url")
        .context(
            "database.url did not resolve; set `database.url_env: DATABASE_URL` or a secret \
             reference",
        )?
        .expose_str()
        .context("database.url is not valid UTF-8")?;

    let mut db_config = enclave_db::DbConfig::new(enclave_db::ConnectionUrl::new(url))
        .with_max_connections(config.database.max_connections);

    if let Some(platform) = secrets.get("database.platform_url") {
        let platform = platform.expose_str().context("database.platform_url is not valid UTF-8")?;
        db_config = db_config.with_platform_url(enclave_db::ConnectionUrl::new(platform));
    }

    Ok(db_config)
}

/// Waits for SIGTERM or Ctrl-C.
///
/// SIGTERM as well as Ctrl-C because it is the one that actually arrives: every container runtime
/// sends it, and a process that ignored it would be waited out and then `SIGKILL`ed — mid-pass,
/// which is the case [`Stop`] exists to avoid.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            // A process that cannot register the handler must still be interruptible; losing
            // SIGTERM is worse reported than silently downgraded to a hang.
            Err(error) => {
                tracing::warn!(%error, "could not install the SIGTERM handler; Ctrl-C only");
                let _ignored = tokio::signal::ctrl_c().await;
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ignored = tokio::signal::ctrl_c().await;
    }
}
