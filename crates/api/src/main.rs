//! `enclave-api` — the HTTP binary.
//!
//! Composition only. Every decision it makes is which implementation to hand the policy engine;
//! none of them are policy decisions themselves.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use enclave_api::{metrics_listener, router, unconfigured_stages, ApiState, Delivery, Edge};
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
    let unenforcing = unenforcing_stages();
    for stage in &unenforcing {
        tracing::warn!(stage, "policy stage is not enforcing");
    }

    if config.profile == enclave_config::DeploymentProfile::Enterprise && !unenforcing.is_empty() {
        anyhow::bail!(
            "the enterprise profile refuses to start while {} policy stages are unconfigured: {}. \
             Running with DLP disabled and no conditional access is a legitimate development \
             posture and an illegitimate enterprise one.",
            unenforcing.len(),
            unenforcing.join("; "),
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

    // Conditional access decides from each tenant's **stored** rules (`ENC-590`). It replaces
    // `UnconfiguredConditionalAccess`, which allowed everything, and it is wired unconditionally:
    // a tenant with no rules gets the same answer through the same code, so a deployment that adds
    // its first rule does not also change which implementation is running.
    //
    // Zone definitions come from `enclave.yaml` and are shared by every tenant on the host, because
    // a zone names *this deployment's* networks. The same key builds the `Edge` below, which is why
    // both are read from `config` here rather than one being derived from the other: a zone map the
    // edge resolved `NetworkContext::zones` from must be the map a rule naming that zone is
    // evaluated against.
    let conditional_access = enclave_conditional_access::TenantConditionalAccess::new(
        db.clone(),
        enclave_conditional_access::ZoneMap::from_config(&config.conditional_access.zones),
    );
    tracing::info!(
        cache_ttl_secs = conditional_access.cache_ttl().as_secs(),
        "conditional access is reading tenant rules; a tightened rule applies everywhere within \
         the cache TTL"
    );

    let policy = PolicyEngine::new(
        Arc::new(conditional_access),
        Arc::new(enclave_authorization::SelfServiceAuthorization),
        Arc::new(enclave_information_barriers::UnconfiguredBarriers),
        Arc::new(enclave_classification::UnconfiguredClassification),
        Arc::new(enclave_dlp::DisabledDlp),
        Arc::new(enclave_retention::UnconfiguredRetention),
        audit,
    );

    // The one place a client address is established (`ENC-583`). An empty `server.trusted_proxies`
    // means the socket peer *is* the client address and `X-Forwarded-For` is not read at all —
    // correct for a direct deployment and wrong behind a load balancer, so it is said out loud.
    let edge = Edge::from_config(config);
    if edge.trusts_no_proxy() {
        tracing::info!(
            "server.trusted_proxies is empty: every client address is its socket peer and \
             X-Forwarded-For is ignored. Behind a reverse proxy, configure it or conditional \
             access will see the proxy's address on every request"
        );
    }

    let state = ApiState::new(
        policy,
        db,
        config.auth.access_token.issuer.as_deref().unwrap_or_default(),
        config.auth.access_token.audience.as_str(),
        keys,
    )
    .with_edge(edge);

    // Delivery, and the same treatment the policy stages get above. `ENC-170`: the router used to
    // register download and preview without either dependency, so both answered `500` in the binary
    // while every integration test passed. It now takes them, so the gap would be a compile error —
    // and what a deployment without them gets is a documented refusal it was warned about, rather
    // than an error nobody can explain.
    let delivery = Delivery::unconfigured();
    for capability in delivery.unconfigured_capabilities() {
        tracing::warn!(capability, "delivery capability is not configured");
    }

    // The metrics listener, if one is configured, on its own socket — see `serve_metrics`.
    //
    // `metrics.api_port`, not `server.metrics_port`: the old key was read by this binary *and* by
    // the worker, so one `enclave.yaml` on one host asked both to bind the same socket and
    // whichever started second died here with `Address already in use` (`ENC-566`). An unmigrated
    // file is refused at load rather than starting with the exposition silently off —
    // `enclave_config::validate::check_relocated_keys`.
    if let Some(addr) = config.metrics.api_addr() {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("bind metrics listener on {addr}"))?;
        tracing::info!(%addr, "metrics listening");
        tokio::spawn(metrics_listener::serve(listener, shutdown()));
    } else {
        tracing::debug!("metrics.api_port is unset; no metrics endpoint is served");
    }

    let addr = SocketAddr::new(config.server.bind, config.server.port);
    let listener = tokio::net::TcpListener::bind(addr).await.context("bind")?;
    tracing::info!(%addr, "enclave-api listening");

    // `into_make_service_with_connect_info`, not a bare router: without it axum attaches no
    // `ConnectInfo`, `Edge` cannot see a peer address, and every request would resolve to
    // `NetworkContext::unknown` — which refuses every network rule rather than leaking, but refuses
    // them for the wrong reason and would be diagnosed as a policy bug.
    axum::serve(
        listener,
        router(state, delivery).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown())
    .await
    .context("serve")?;
    Ok(())
}

/// The prefix of [`unconfigured_stages`]'s entry for the stage this binary now wires.
const CONDITIONAL_ACCESS_STAGE: &str = "conditional_access";

/// The policy stages still permitting everything **after this binary's wiring**.
///
/// [`unconfigured_stages`] is a fixed list in `crates/api/src/state.rs` describing the stages as
/// `ApiState` finds them, and `ENC-590` makes one of them untrue: conditional access is wired to
/// `TenantConditionalAccess` above and decides from stored rules. The list is filtered here rather
/// than edited there because that file is held by another change in flight; `ENC-601` is the row
/// for deriving the list from what was actually wired, which is the shape that cannot go stale.
///
/// Filtering rather than hard-coding the remainder is deliberate: the entry has to be *found* to be
/// removed, so a rename in `state.rs` fails `the_conditional_access_stage_is_no_longer_unconfigured`
/// instead of silently filtering nothing.
fn unenforcing_stages() -> Vec<&'static str> {
    unconfigured_stages()
        .iter()
        .copied()
        .filter(|stage| !stage.starts_with(CONDITIONAL_ACCESS_STAGE))
        .collect()
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

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// The proof that the stage is *wired*, at the one place wiring happens.
    ///
    /// `docs/12-TESTING.md §1.2`: an assertion about an absence passes for free, and
    /// "conditional_access is not in this list" is exactly that shape — it holds against a filter
    /// that removes everything, against a list that was never populated, and against a
    /// `starts_with` that no longer matches anything. So all three controls are asserted: the entry
    /// **was** there before filtering, exactly one entry was removed, and the stages that really
    /// are still stubs are still announced.
    ///
    /// What this cannot assert is that `main` hands the engine the real type rather than the stub:
    /// a binary's `main` is not callable from a test. That the two agree is held by the compiler
    /// instead — `unenforcing_stages` and the `PolicyEngine::new` call are in this one file, and
    /// `TenantConditionalAccess` is named there. The behavioural proof that the wired type decides
    /// anything is `crates/conditional_access/tests/stored_rules.rs`, which drives it through the
    /// `dyn ConditionalAccessService` the engine holds.
    #[test]
    fn the_conditional_access_stage_is_no_longer_unconfigured() {
        let before = unconfigured_stages();
        let after = unenforcing_stages();

        assert!(
            before.iter().any(|stage| stage.starts_with(CONDITIONAL_ACCESS_STAGE)),
            "the entry this filter removes is no longer in the list; the filter is a no-op and the \
             start-up banner would be reporting a stage that is wired"
        );
        assert_eq!(
            before.len() - after.len(),
            1,
            "exactly one entry belongs to the conditional-access stage"
        );
        assert!(
            !after.iter().any(|stage| stage.starts_with(CONDITIONAL_ACCESS_STAGE)),
            "conditional access decides from stored rules and must not be announced as unconfigured"
        );
        // The positive control: the stages that really are stubs are still announced, so this does
        // not pass against a filter that emptied the list.
        assert!(after.iter().any(|stage| stage.starts_with("dlp")));
        assert!(after.iter().any(|stage| stage.starts_with("retention")));
    }
}
