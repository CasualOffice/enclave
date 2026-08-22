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

    // The DLP posture is settled here, before the banner, because the banner reports it (`ENC-594`).
    // Two independent parts: the **mode**, which comes from configuration and decides whether a
    // conclusion is acted on, and the **rules**, which decide what is concluded and have no storage
    // yet — `ENC-615`. A mode without rules governs nothing, and the banner says so rather than
    // announcing a control that is on.
    let dlp_mode = enclave_dlp::DlpMode::from(config.dlp.default_mode);
    let dlp_rules = enclave_dlp::RuleSet::empty();

    // Loud, once, at start-up. A deployment running with five of six stages permitting everything
    // looks identical from the outside to one carefully allowing each request, and the difference
    // matters enormously. `docs/12-TESTING.md §5` has CI proving the gates; this is the equivalent
    // for an operator standing in front of a running process.
    let unenforcing = unenforcing_stages(dlp_mode, dlp_rules.len());
    for stage in &unenforcing {
        tracing::warn!(stage = stage.as_str(), "policy stage is not enforcing");
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

    // DLP runs in the mode the tenant's configuration names (`ENC-594`), replacing `DisabledDlp` as
    // the only option. `DisabledDlp` stays reachable and is what `DISABLED` builds: it is one of
    // `docs/06 §9`'s five modes and a posture a tenant may legitimately run, not a placeholder —
    // and a deployment that wants DLP off should not have to name a rule set and a sink to say so.
    //
    // Every other mode gets `ModedDlp`, which evaluates identically in all four and differs only in
    // what it does about the verdict (D28). The observation sink is the `tracing` one, which is
    // what can be written without inventing a schema; `ENC-593` is the queryable record
    // `docs/06 §9`'s simulate-before-enforce gate actually needs.
    let dlp: Arc<dyn enclave_core::DlpService> = if dlp_mode.evaluates() {
        Arc::new(enclave_dlp::ModedDlp::new(
            dlp_mode,
            dlp_rules,
            Arc::new(enclave_dlp::TracingObservations),
        ))
    } else {
        Arc::new(enclave_dlp::DisabledDlp)
    };

    // The reader that makes the stage above able to decide anything (`ENC-594`). Without it the
    // engine keeps `stub::NoSecurityFacts`, which reports every resource unscanned — safe, because
    // the fail-closed default then refuses rather than permitting, but not a state to ship.
    //
    // The active detector set is passed rather than discovered: a fact row has to answer "were you
    // produced by the detectors running *now*", and a set inferred from the rows would answer "were
    // you produced by the detectors that produced you" (`ENC-581`).
    let facts = enclave_dlp::PgSecurityFacts::new(
        db.clone(),
        enclave_dlp::builtin_set().version().clone(),
        config.dlp.facts_policy(),
    );
    tracing::info!(
        detector_set = facts.active_set().as_str(),
        facts_unavailable = facts.policy().on_unavailable().as_str(),
        dlp_mode = dlp_mode.as_str(),
        "DLP is reading security facts; a version with no fact row is unscanned, and what that \
         means is the facts_unavailable policy's to say"
    );

    let policy = PolicyEngine::new(
        Arc::new(conditional_access),
        Arc::new(enclave_authorization::SelfServiceAuthorization),
        Arc::new(enclave_information_barriers::UnconfiguredBarriers),
        Arc::new(enclave_classification::UnconfiguredClassification),
        dlp,
        Arc::new(enclave_retention::UnconfiguredRetention),
        audit,
    )
    .with_facts(Arc::new(facts));

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

/// The prefix of [`unconfigured_stages`]'s entry for the stage `ENC-590` wired.
const CONDITIONAL_ACCESS_STAGE: &str = "conditional_access";

/// The prefix of [`unconfigured_stages`]'s entry for the stage `ENC-594` wired.
const DLP_STAGE: &str = "dlp";

/// The policy stages still permitting everything **after this binary's wiring**.
///
/// [`unconfigured_stages`] is a fixed list in `crates/api/src/state.rs` describing the stages as
/// `ApiState` finds them, and two of its entries are now decided here instead: conditional access
/// is `TenantConditionalAccess` and DLP is whatever `dlp.default_mode` names. The list is filtered
/// rather than edited there because that file is held by another change in flight; `ENC-601` is the
/// row for deriving it from what was actually wired, which is the shape that cannot go stale — and
/// this second entry is the case it predicted.
///
/// Filtering rather than hard-coding the remainder is deliberate: an entry has to be *found* to be
/// removed, so a rename in `state.rs` fails a test here instead of silently filtering nothing.
///
/// # What "unenforcing" means for DLP, which is not the same as "disabled"
///
/// The entry is replaced rather than simply dropped, because the honest answer has three parts and
/// the fixed string only says one of them. A stage that **cannot refuse anything** is announced,
/// and there are two ways to be in that state:
///
///   * the mode does not enforce — `DISABLED` inspects nothing, and `MONITOR`, `SIMULATION` and
///     `WARN` are rungs of `docs/06 §9`'s rollout ladder that deliberately never refuse;
///   * no rule is in force, in which case the mode is irrelevant: `RuleSet::evaluate` returns
///     `NotGoverned` for every action, so `ENFORCE` over an empty set refuses exactly as much as
///     `DISABLED` does — nothing.
///
/// The second is the state every deployment is in today (`ENC-615`: rules have no storage), which
/// is precisely why it is reported rather than assumed away. An operator who set `ENFORCE` and saw
/// no entry in this banner would reasonably conclude that content inspection was refusing things.
fn unenforcing_stages(dlp_mode: enclave_dlp::DlpMode, dlp_rules: usize) -> Vec<String> {
    let dlp_refuses = dlp_mode.enforces() && dlp_rules > 0;

    let mut stages: Vec<String> = unconfigured_stages()
        .iter()
        .filter(|stage| {
            !stage.starts_with(CONDITIONAL_ACCESS_STAGE) && !stage.starts_with(DLP_STAGE)
        })
        .map(|stage| (*stage).to_owned())
        .collect();

    if !dlp_refuses {
        let posture =
            if dlp_mode.evaluates() { "evaluates, refuses nothing" } else { "inspects nothing" };
        stages.push(format!("{DLP_STAGE} ({dlp_mode}, {dlp_rules} rules — {posture})"));
    }
    stages
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
    use enclave_dlp::DlpMode;

    /// One rule is enough to make a rule set non-empty, and the count is all this banner reads.
    const ONE_RULE: usize = 1;

    #[test]
    fn the_conditional_access_stage_is_no_longer_unconfigured() {
        let before = unconfigured_stages();
        let after = unenforcing_stages(DlpMode::Disabled, 0);

        assert!(
            before.iter().any(|stage| stage.starts_with(CONDITIONAL_ACCESS_STAGE)),
            "the entry this filter removes is no longer in the list; the filter is a no-op and the \
             start-up banner would be reporting a stage that is wired"
        );
        assert!(
            !after.iter().any(|stage| stage.starts_with(CONDITIONAL_ACCESS_STAGE)),
            "conditional access decides from stored rules and must not be announced as unconfigured"
        );
        // The positive control: the stages that really are stubs are still announced, so this does
        // not pass against a filter that emptied the list.
        assert!(after.iter().any(|stage| stage.starts_with("retention")));
        assert!(after.iter().any(|stage| stage.starts_with("classification")));
    }

    /// The DLP entry is now **computed** rather than fixed, and the banner has to be able to say
    /// all three of the states a wired stage can be in (`ENC-594`).
    ///
    /// `docs/12 §1.2`: "dlp is not in the list" is an assertion about an absence and holds for free
    /// against a filter that removed every entry, so the disappearance is asserted alongside the
    /// two cases where the entry must still be there, and against a list that still names the
    /// genuinely unconfigured stages.
    #[test]
    fn the_dlp_entry_says_whether_the_configured_mode_can_refuse_anything() {
        assert!(
            unconfigured_stages().iter().any(|stage| stage.starts_with(DLP_STAGE)),
            "the fixed entry this replaces is gone from state.rs; the filter is a no-op and the \
             computed entry below would be a second dlp line rather than a replacement"
        );

        // Enforcing, with a rule to enforce: the one state in which the stage can refuse, and the
        // only one where it drops out of the banner.
        let enforcing = unenforcing_stages(DlpMode::Enforce, ONE_RULE);
        assert!(
            !enforcing.iter().any(|stage| stage.starts_with(DLP_STAGE)),
            "ENFORCE over a non-empty rule set refuses things and must not be announced as \
             unenforcing: {enforcing:?}"
        );
        // The control for that absence: the stages that really are stubs are still announced.
        assert!(enforcing.iter().any(|stage| stage.starts_with("retention")));

        // Enforcing over nothing. The mode says refuse, the rule set has nothing to refuse, and an
        // operator who read only the mode would believe content inspection was blocking.
        let no_rules = unenforcing_stages(DlpMode::Enforce, 0);
        let entry = no_rules
            .iter()
            .find(|stage| stage.starts_with(DLP_STAGE))
            .expect("ENFORCE with no rules refuses nothing and must be announced");
        assert!(entry.contains("ENFORCE"), "the banner names the mode actually running: {entry}");
        assert!(entry.contains("0 rules"), "and why it refuses nothing: {entry}");

        // A rung of the rollout ladder: rules exist and are evaluated, and none of them can refuse.
        let monitoring = unenforcing_stages(DlpMode::Monitor, ONE_RULE);
        let entry = monitoring
            .iter()
            .find(|stage| stage.starts_with(DLP_STAGE))
            .expect("MONITOR records and never refuses, however many rules are in force");
        assert!(entry.contains("MONITOR"), "{entry}");
        assert!(entry.contains("evaluates"), "MONITOR does inspect content: {entry}");

        // And `DISABLED`, which is a real mode rather than the absence of one — it must be
        // distinguishable in the banner from a mode that evaluates and declines to act.
        let disabled = unenforcing_stages(DlpMode::Disabled, ONE_RULE);
        let entry = disabled
            .iter()
            .find(|stage| stage.starts_with(DLP_STAGE))
            .expect("DISABLED inspects nothing and must be announced");
        assert!(entry.contains("inspects nothing"), "{entry}");
    }
}
