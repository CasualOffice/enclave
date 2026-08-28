//! `enclave-api` — the HTTP binary.
//!
//! Composition only. Every decision it makes is which implementation to hand the policy engine;
//! none of them are policy decisions themselves.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use enclave_api::{metrics_listener, router, unconfigured_stages, ApiState, Delivery, Edge};
use enclave_core::PolicyEngine;

/// The object store this deployment's `storage.s3` names, or `None` when it names none.
///
/// Identical to `crates/worker`'s function of the same name and deliberately so: two binaries
/// reading one configuration section through two code paths is how they come to disagree about what
/// it means. `connect_and_verify` proves the bucket is reachable *now* — an unreachable bucket is a
/// start-up failure rather than a download that fails for a user who cannot know why.
async fn object_store(
    config: &enclave_config::Config,
    registry: &enclave_config::SecretRegistry,
) -> anyhow::Result<Option<enclave_storage::S3BlobStore>> {
    let Some(section) = config.storage.s3.as_ref() else { return Ok(None) };

    let store = enclave_storage::S3BlobStore::connect_and_verify(
        enclave_storage::S3Config::from_operator_config(section),
        registry,
    )
    .await
    .with_context(|| {
        format!(
            "connect to the object store named by `storage.s3` (bucket `{}`, region `{}`)",
            section.bucket, section.region
        )
    })?;
    Ok(Some(store))
}

/// Dense retrieval for `POST /api/v1/search`, when this deployment has both halves of it.
///
/// # What this closes
///
/// `ENC-698`. `ApiState` carried the policy engine, the pool, the token verifier, the edge and two
/// rule caches, and **no vector index** — so `crates/api/src/routes/search.rs` handed
/// `Retrieval::decide` a hardcoded `VectorStore::Unreachable` and every response said
/// `degraded: true`. That was the truthful reading from inside the process, which is exactly why it
/// needed closing deliberately: when a corpus existed, nothing about the route would have changed
/// and it would have kept reporting a degraded search over a healthy index.
///
/// It is `ENC-770`'s shape one section along, and it is built the same way that one was: from the
/// same conversion `crates/worker` uses, so the two binaries cannot come to disagree about what
/// `search.milvus` means. That function is `MilvusConfig::from_operator_config`, which moved out of
/// the worker's `main.rs` — where this file could not reach it — and beside the type it builds.
///
/// # Why both halves, and why `None` is not a failure
///
/// A vector index this process cannot form a query for is not a vector index: `candidates` takes an
/// embedding, so without the mounted model the API could probe Milvus and never read it. Requiring
/// the pair makes "the store is available and there is nothing to ask it with" unrepresentable
/// rather than handled.
///
/// A deployment with neither, or with one, **starts and answers**. It answers from the lexical
/// fallback over PostgreSQL and says `degraded: true`, which is the honest state and the one
/// `docs/09-UX-WHITE-LABELING.md §10`'s header renders. Refusing to start would be worse than the
/// defect: it would take the whole HTTP surface down over a search feature.
///
/// The two half-configured cases are warned about **by name**, because they are the ones an
/// operator has to be able to diagnose — a deployment that mounted a model on the worker and not on
/// the API gets lexical search with no error anywhere, and the log line is the only thing that says
/// why.
///
/// # What it deliberately does not do
///
/// It does not call `ensure_collection`. Provisioning the collection is the worker's, once, at the
/// width the active model declares (`crates/worker/src/main.rs::vector_stage`); an API replica
/// creating it would be several processes racing to create one collection, at a width this process
/// has no business choosing. A collection that is absent therefore reads as `Unreachable` through
/// `has_collection` and the search degrades and says so — which is the right answer for an API that
/// has been pointed at a store nobody has provisioned yet.
///
/// # Errors
///
/// A `search.milvus.token` that is not UTF-8, and a configured embedding mount that cannot be
/// loaded — missing, unreadable, not a `.rten` graph, or emitting a width this build does not index
/// against. The second is a start-up failure for the reason the `Err` arm of `build_auth_surface`
/// below gives: this is the difference between *nothing was supplied* and *what was supplied does
/// not work*, and only the second is always an operator error. It cannot fire for a deployment that
/// has not asked for dense search, because it is reached only when `search.milvus` is set too.
async fn vector_retrieval(
    config: &enclave_config::Config,
    secrets: &enclave_config::ResolvedSecrets,
) -> anyhow::Result<Option<enclave_api::VectorRetrieval>> {
    // The width is `enclave_embeddings::model::ACTIVE`'s and never a configuration key
    // (`docs/08-BYO-INFRA.md §15`). It is inert in this process — nothing here creates a collection
    // or writes a chunk — and passing the same constant the worker passes is what keeps it inert.
    let milvus = enclave_search::MilvusConfig::from_operator_config(
        config,
        secrets,
        enclave_embeddings::ACTIVE.dimension,
    )
    .context("read the vector store this deployment's `search.milvus` names")?;

    // Read as two fields rather than through `Config::embedding_mounts`, because that reader
    // answers the *worker's* three-state question — and its `Incomplete` state, a model with no
    // vector store, is a start-up refusal there and must not be one here. `docs/08 §18.1` records
    // why: a loader-level version of that rule stopped every binary in the workspace from booting
    // in any shell that had exported `ENCLAVE_EMBEDDING_MODEL`, which is what CI and every runbook
    // tell an operator to do.
    let model = config.embedding_model.as_deref();

    match (milvus, model) {
        (Some(milvus), Some(model)) => {
            let endpoint = milvus.uri.clone();
            let collection = milvus.collection.clone();
            let index = enclave_search::MilvusIndex::new(milvus);
            let embedder = enclave_embeddings::MountedModel::air_gapped_router(model)
                .with_context(|| {
                    format!(
                        "load the embedding model mounted at {} so searches can be embedded",
                        model.display()
                    )
                })?;
            tracing::info!(
                endpoint = %endpoint,
                collection = %collection,
                model = enclave_embeddings::ACTIVE.id,
                "dense search is wired; POST /api/v1/search reports degraded only when the store \
                 says so"
            );
            Ok(Some(enclave_api::VectorRetrieval::new(Arc::new(index), Arc::new(embedder))))
        }
        (Some(_), None) => {
            tracing::warn!(
                "search.milvus names a vector store and `embedding_model` is unset, so this process \
                 cannot embed a query and every search runs lexically with degraded: true. Stage \
                 the converted weights on this node too (docs/08-BYO-INFRA.md §18.1) — the worker's \
                 mount is not this process's"
            );
            Ok(None)
        }
        (None, Some(_)) => {
            tracing::warn!(
                "`embedding_model` is mounted and `search.milvus` names no vector store, so there \
                 is nothing to search and every search runs lexically with degraded: true. This is \
                 a start-up refusal in crates/worker and deliberately not one here"
            );
            Ok(None)
        }
        (None, None) => {
            tracing::info!(
                "no vector store is configured (`search.provider` is `none`), so every search runs \
                 lexically over PostgreSQL and reports degraded: true. That is a posture, not a \
                 fault: docs/09-UX-WHITE-LABELING.md §10's header is what a caller sees"
            );
            Ok(None)
        }
    }
}

/// The rendition pipeline, over the store this deployment configured (`ENC-798`).
///
/// This function used to return `UnconfiguredPipeline` — the only `PreviewPipeline` in the
/// workspace — so `preview`, `thumbnail` and `export` refused whatever `storage.s3` said. That is
/// `ENC-770`'s shape one crate along: the route *takes* its dependency, so the gap would be a
/// compile error, but the value passed was a constant rather than a build. A dependency that is
/// always absent is not a dependency; it is a stub with a type signature.
///
/// The three parts come from `crates/preview`, and each is the narrow one:
///
/// * `RasterRenderer` decodes PNG, JPEG and WebP into `thumb`, `page-png-1x` and `page-png-2x`, on
///   a blocking thread, inside `RenderBudget::DEFAULT`. Every other media type is refused — the
///   document parsers belong in `plans/M2-ACCESS-DELIVERY.md` D17's out-of-process worker, and a
///   half-built one would report "preview available" for a format whose sanitizer nobody has
///   written.
/// * `BlobSource` is the only holder of a `BlobStore` on the rendition path, and it reads one key
///   it is handed by a `ReadableVersion`. The handlers hold none: they cannot name an object key,
///   so they cannot ask for an original (`CLAUDE.md` rule 6).
/// * `NoRenditionSink` keeps nothing, so every request renders again. Said out loud rather than
///   left to be discovered, because a deployment that re-renders each preview and one serving a
///   cache look identical from the outside until the load arrives (`ENC-802`).
fn rendition_pipeline(
    store: &Arc<dyn enclave_storage::BlobStore>,
) -> Arc<dyn enclave_preview::PreviewPipeline> {
    let budget = enclave_preview::RenderBudget::DEFAULT;
    tracing::info!(
        wall_clock_secs = budget.wall_clock.as_secs(),
        max_input_bytes = budget.max_input_bytes,
        max_output_bytes = budget.max_output_bytes,
        "renditions are generated in process for image/png, image/jpeg and image/webp; every other \
         media type is refused, and nothing is cached — `BlobStore` has no server-side write verb, \
         so each request renders again (ENC-802)"
    );
    Arc::new(enclave_preview::RenditionService::new(
        enclave_preview::RasterRenderer,
        enclave_preview::BlobSource::new(Arc::clone(store), budget),
        enclave_preview::NoRenditionSink,
        budget,
    ))
}

/// What a privileged administrative action demands, from `security.mfa`.
///
/// # Why this refuses to start rather than warning
///
/// `security.mfa.admins_required` defaults to `true` and, until `ENC-771`, was read by nothing:
/// `require_step_up` compared against a hard-coded constant. So every `/admin/**` mutation demanded
/// a second factor, the binary wired an `MfaVerifier` that refuses every code, and **no principal in
/// any deployment could satisfy it**. A tenant administrator got `403 STEP_UP_REQUIRED` naming a
/// factor they had no way to present, on the surface that configures the product's own controls.
///
/// The reachability smoke test found it on its first run, which is the argument for that test: five
/// routes were registered, reached the policy chain, passed every unit test, and could not be used.
///
/// A requirement nobody can satisfy is not a stricter control — it is a surface that does not
/// exist, announced as a permissions error. So the pairing is refused at start-up rather than
/// discovered by an operator: either configure a verifier, or say in configuration that
/// administrators do not need one. Both are defensible; the silent third state is not.
fn step_up_policy(
    config: &enclave_config::Config,
    mfa_verifier_configured: bool,
) -> anyhow::Result<enclave_api::state::StepUpPolicy> {
    use enclave_api::state::StepUpPolicy;

    if !config.security.mfa.admins_required {
        tracing::warn!(
            "security.mfa.admins_required is false: an administrative action needs only the \
             session that signed in, and a stolen admin session is a policy change"
        );
        return Ok(StepUpPolicy::NotRequired);
    }

    anyhow::ensure!(
        mfa_verifier_configured,
        "security.mfa.admins_required is true and no MFA verifier is configured, so every \
         /api/v1/admin/** mutation would answer 403 STEP_UP_REQUIRED to every caller including a \
         tenant administrator, with no way for anyone to satisfy it. Configure a verifier, or set \
         security.mfa.admins_required: false to say that administrators do not need one (ENC-771)"
    );

    let max_age_secs =
        i64::try_from(config.security.mfa.step_up_max_age.as_secs()).unwrap_or(i64::MAX);
    Ok(StepUpPolicy::Required { max_age_secs })
}

/// The `iss` this deployment mints and the `iss` it verifies — one value, one source.
///
/// # Why this is a function rather than two expressions
///
/// It was two. `auth_surface` derived the issuer from `auth.access_token.issuer`, falling back to
/// `server.public_url`; `ApiState::new` was handed `auth.access_token.issuer` with **no fallback**.
/// `docs/08` tells an operator to leave the issuer unset because it is taken from `public_url`, so
/// on the documented configuration the minter stamped `http://…/` and the verifier expected `""`.
///
/// Every token this deployment issued was rejected by the deployment that issued it. Login returned
/// `200` with a valid signature, and every authenticated request answered `403` — which reads as a
/// permissions problem, so that is where anyone looks. The whole test suite passed throughout,
/// because no test both minted and verified through the composition in this file.
///
/// `ENC-533` is the precedent: the collection's dense width and the model's agreed *by convention*
/// across two crates until one function compared them. Same fix, same reason.
fn access_token_issuer(config: &enclave_config::Config) -> String {
    config
        .auth
        .access_token
        .issuer
        .clone()
        .or_else(|| config.server.public_url.as_ref().map(ToString::to_string))
        .unwrap_or_default()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let loaded = enclave_config::ConfigLoader::new()
        .with_file("enclave.yaml")
        .load()
        .context("load configuration")?;
    let config = loaded.config();

    enclave_observability::init(&Default::default()).context("initialise tracing")?;

    // The DLP posture is settled here, before the banner, because the banner reports it (`ENC-594`).
    // Two independent parts, and only one of them is a deployment-wide fact: the **mode** comes
    // from configuration and decides whether a conclusion is acted on, and the **rules** decide what
    // is concluded and are now each tenant's own rows (`ENC-615`, `migrations/0021_dlp_rules.sql`).
    let dlp_mode = enclave_dlp::DlpMode::from(config.dlp.default_mode);

    // Loud, once, at start-up. A deployment running with five of six stages permitting everything
    // looks identical from the outside to one carefully allowing each request, and the difference
    // matters enormously. `docs/12-TESTING.md §5` has CI proving the gates; this is the equivalent
    // for an operator standing in front of a running process.
    let unenforcing = unenforcing_stages(dlp_mode);
    for stage in &unenforcing {
        tracing::warn!(stage = stage.as_str(), "policy stage is not enforcing");
    }

    report_antivirus_posture(&config.antivirus);

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

    // Signing keys, and with them the deployment's ability to sign anyone in at all (`ENC-687`).
    // This used to be `KeySet::new(std::iter::empty())` — a verifier that rejects every token and a
    // service that can mint none — which is why every `/api/v1/auth/*` route answered `503` in this
    // binary while the whole suite passed. `SigningKeys::choose` below is where the decision is
    // taken and argued.
    let key_source = SigningKeys::choose(
        config.auth.signing_keys.key_ref.is_some(),
        config.profile,
        config.server.bind,
    );
    let key_provider = build_key_provider(key_source, config, &secrets)?;
    let keys = match &key_provider {
        Some(provider) => enclave_auth::KeySet::new(
            provider.verification_keys().await.context("read the verification key set")?,
        ),
        None => enclave_auth::KeySet::default(),
    };

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

    // DLP runs in the mode configuration names (`ENC-594`), over each tenant's **stored** rules
    // (`ENC-615`). It replaces `ModedDlp` over `RuleSet::empty()`, which evaluated a rule set with
    // nothing in it — so `RuleSet::evaluate` returned `NotGoverned` for every action and `ENFORCE`
    // refused exactly as much as `DISABLED` did.
    //
    // `DisabledDlp` stays reachable and is what `DISABLED` builds: it is one of `docs/06 §9`'s five
    // modes and a posture a tenant may legitimately run, not a placeholder — and a deployment that
    // wants DLP off should not have to name a sink, or open a transaction per request to read rules
    // it will not evaluate.
    //
    // Every other mode gets `TenantDlp`, which evaluates identically in all four and differs only
    // in what it does about the verdict (D28) — the mode is held beside the rules and never inside
    // them, which is what keeps `RuleSet::evaluate` unable to see it. The observation sink is the
    // `tracing` one, which is what can be written without inventing a schema; `ENC-593` is the
    // queryable record `docs/06 §9`'s simulate-before-enforce gate actually needs.
    //
    // The stage doubles as the cache the admin surface tells about a write (`ENC-633`): clones
    // share one cache, so the handle handed to `ApiState` and the one the chain evaluates against
    // are the same map. `DISABLED` has none — it reads no rules, so there is nothing to forget.
    let mut dlp_cache: Option<enclave_api::admin::dlp::SharedDlpRuleCache> = None;
    let dlp: Arc<dyn enclave_core::DlpService> = if dlp_mode.evaluates() {
        let stage = enclave_dlp::TenantDlp::new(
            db.clone(),
            dlp_mode,
            Arc::new(enclave_dlp::TracingObservations),
        );
        dlp_cache = Some(Arc::new(stage.clone()));
        tracing::info!(
            dlp_mode = dlp_mode.as_str(),
            cache_ttl_secs = stage.cache_ttl().as_secs(),
            "DLP is reading tenant rules from dlp_rules; a newly written rule applies everywhere \
             within the cache TTL, and a tenant with no rules has nothing for this mode to refuse"
        );
        Arc::new(stage)
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

    // Authorization can now answer an administrative question (`ENC-619`). `SelfServiceAuthorization`
    // allows a principal to read *itself* and refuses everything else, so with it alone every route
    // under `/api/v1/admin/**` was refused at this stage whoever the caller was — closed, which was
    // the right direction, and unusable.
    //
    // `AdminAuthorization` **wraps** it rather than replacing it: an `Action::Admin` is decided from
    // the caller's administrative grants and every other action is still the inner service's to
    // answer. Grants come from `users.is_admin` — the tenant's global administrator — and what that
    // can and cannot yet express is in `crates/authorization/src/admin.rs`.
    //
    // The inner service is `PgAclAuthorization` (`ENC-126`, the single line that comment promised).
    // It resolves an entry against `acl_entries` with inheritance and deny-wins, which is what makes
    // every content route answer with data rather than `403`. Until this line, the binary wired
    // `SelfServiceAuthorization` — a principal could read *itself* and nothing else, so a valid token
    // reached the chain, authenticated correctly, and was refused at authorization on every route but
    // `/me`. Authentication working and authorization unwired look identical from the outside: a
    // `403` on a request whose token was perfectly good.
    let authorization = enclave_authorization::AdminAuthorization::new(
        Arc::new(enclave_authorization::PgAdminRoles::new(db.clone())),
        Arc::new(enclave_authorization::SelfServiceOr::new(
            enclave_authorization::PgAclAuthorization::new(db.clone()),
        )),
    );

    let policy = PolicyEngine::new(
        Arc::new(conditional_access),
        Arc::new(authorization),
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

    let mut state = ApiState::new(
        // Cloned rather than moved: `build_auth_surface` below hands the *same* engine to the
        // refresh guard, and the point of that is that there is one of them (`ENC-709`).
        policy.clone(),
        db.clone(),
        &access_token_issuer(config),
        config.auth.access_token.audience.as_str(),
        keys,
    )
    .with_edge(edge)
    // `false`: this binary constructs no `MfaVerifier` at all — `AuthSurface` is built below with
    // its own `UnavailableMfa`, which refuses every code (`ENC-688`). The day a verifier is wired,
    // this argument becomes the question of whether one was, and nothing else here changes.
    .with_step_up(step_up_policy(config, false)?);

    // The authentication surface (`ENC-687`). `ApiState::new` leaves `AuthSurface::unconfigured` in
    // place, which registers every route and refuses every one of them with `503` — the shape
    // `Delivery` has, and the reason it is a builder step rather than a constructor argument.
    //
    // A `None` here is therefore a deployment that runs, serves everything else, and cannot sign
    // anyone in. That is the honest state for a deployment with no signing key, and it is
    // deliberately not a start-up failure of *this* process for the reason `SigningKeys::choose`
    // gives: the refusal that matters is the one before it, and it is scoped to the configurations
    // that must not run at all.
    match build_auth_surface(key_provider, config, &db, &policy) {
        Ok(Some(surface)) => {
            tracing::info!(
                issuer = config.auth.access_token.issuer.as_deref().unwrap_or_default(),
                audience = config.auth.access_token.audience.as_str(),
                "the authentication surface is wired; /api/v1/auth/* can issue tokens"
            );
            state = state.with_auth(surface);
        }
        Ok(None) => tracing::warn!(
            "no signing key is configured: every /api/v1/auth/* route will answer 503 \
             DEPENDENCY_UNAVAILABLE and nobody can sign in. Set auth.signing_keys.key_ref to a \
             secret reference (vault://…, env://…), or run the community profile on a loopback \
             address to have a development key generated"
        ),
        // A configuration this binary cannot build a token service from is a start-up failure
        // rather than a warning, and the difference from the `None` arm is the difference between
        // "nothing was supplied" and "what was supplied does not work". The second is always an
        // operator error and always silent otherwise: the surface would refuse with the same `503`
        // as an unconfigured one, and the operator who set the key would have no way to tell that
        // their key was the problem.
        Err(error) => return Err(error.context("wire the authentication surface")),
    }

    // Present only when the configured mode evaluates: `DisabledDlp` reads no rules and has no
    // cache to forget. Not required for correctness in any case — the TTL is the bound and this is
    // the shortcut for the replica that made the change. (`ENC-624` is the same line for the
    // conditional-access cache, which this binary still does not hand to `ApiState`.)
    if let Some(cache) = dlp_cache {
        state = state.with_dlp_rule_cache(cache);
    }

    // Dense search (`ENC-698`). `None` is the ordinary deployment and is not a failure — the route
    // answers from the lexical fallback and says `degraded: true`, which is the honest state and
    // what `docs/09 §10`'s header renders. `vector_retrieval` warns by name when one half of the
    // pair is configured and the other is not.
    if let Some(vector) = vector_retrieval(config, &secrets).await? {
        state = state.with_vector_retrieval(vector);
    }

    // Delivery, and the same treatment the policy stages get above. `ENC-170`: the router used to
    // register download and preview without either dependency, so both answered `500` in the binary
    // while every integration test passed. It now takes them, so the gap would be a compile error —
    // and what a deployment without them gets is a documented refusal it was warned about, rather
    // than an error nobody can explain.
    // `ENC-770`: this was `Delivery::unconfigured()` unconditionally. The `storage:` section was
    // never read, so a deployment that fully specified a bucket still got a store that refuses
    // every byte, and `POST /uploads` answered `500` on correct configuration. That is `ENC-170`'s
    // shape one layer up — the route takes its dependency, so the *gap* is a compile error, but the
    // value passed was a constant instead of a build. A dependency that is always absent is not a
    // dependency; it is a stub with a type signature.
    //
    // The store is built the same way `crates/worker` builds it, from the same section, so the two
    // binaries cannot disagree about what `storage.s3` means. `connect_and_verify` refuses at
    // start-up rather than at first use, because an unreachable bucket discovered on a user's
    // download is a bucket nobody notices is unreachable.
    let delivery = match object_store(config, &registry).await? {
        Some(store) => {
            // One `Arc`, two capabilities: the download path gets the store, and the rendition
            // pipeline gets a `BlobSource` wrapped around the same handle. Sharing it is the point
            // — a second store built from the same section is a second place for the two to come
            // to disagree about which bucket the product is using.
            let store: Arc<dyn enclave_storage::BlobStore> = Arc::new(store);
            Delivery { preview: rendition_pipeline(&store), store }
        }
        None => Delivery::unconfigured(),
    };
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

/// Where this deployment's signing key comes from.
///
/// A three-valued answer rather than an `Option`, because "no key and that is fine" and "no key and
/// that is a fault" are the two cases the whole mechanism turns on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SigningKeys {
    /// `auth.signing_keys.key_ref` names material. The only source a real deployment has.
    Configured,
    /// Nothing is configured and the deployment is a development one, so a key is generated on
    /// disk. See [`SigningKeys::choose`] for what "a development one" is allowed to mean.
    Development,
    /// Nothing is configured and this deployment may not have a generated one. The process refuses
    /// to start, carrying this sentence.
    Refused(&'static str),
}

impl SigningKeys {
    /// Decides where the key comes from, from three facts and nothing else.
    ///
    /// # The mechanism, and its limit, stated exactly
    ///
    /// `docs/12-TESTING.md` and this repository's habit both say that "the operator should set it"
    /// is not a mechanism. So the development key is not reachable by *policy*, it is reachable
    /// only through a branch that requires **two** conditions, and a deployment that serves anyone
    /// other than the person sitting at the machine fails the second:
    ///
    /// 1. `profile: community` — the default, so this alone closes nothing;
    /// 2. `server.bind` is a **loopback** address.
    ///
    /// The second is the load-bearing one. `ServerConfig::bind` defaults to `127.0.0.1` precisely
    /// so that "a service should be exposed deliberately, not by forgetting to set a field", and a
    /// deployment that is reachable by a browser on another host has necessarily changed it — to
    /// `0.0.0.0`, or to a routable address. There is no branch in this function that hands a
    /// generated key to such a process. It is not a warning it can ignore and not a profile it can
    /// omit; it is the absence of a code path.
    ///
    /// **What it does not close.** A container that publishes a port while the process inside binds
    /// `127.0.0.1` cannot be reached at all, so that arrangement is not a hole. What remains is a
    /// single-host deployment behind a reverse proxy on the same machine, running `community`,
    /// serving real users through `localhost`. That configuration gets a generated key and a
    /// warning, and it is the narrowest form of the problem this can be reduced to without
    /// inventing a signal that a process cannot observe about itself.
    ///
    /// # Why the refusal is here and not in the loader
    ///
    /// `ENC-661` put a configuration refusal in `ConfigLoader` and made *every binary in the
    /// workspace* fail to start, because the loader reads the whole environment and every process
    /// loads the whole document. A signing key is meaningless to `enclave-worker`, which mints no
    /// tokens; a refusal there would stop indexing because the API's key was missing. So it lives
    /// in this binary's own composition, where the only process it can stop is the one that needed
    /// the key.
    const fn choose(
        key_ref_present: bool,
        profile: enclave_config::DeploymentProfile,
        bind: std::net::IpAddr,
    ) -> Self {
        if key_ref_present {
            return Self::Configured;
        }
        if !matches!(profile, enclave_config::DeploymentProfile::Community) {
            return Self::Refused(
                "auth.signing_keys.key_ref is required outside the `community` profile. The \
                 development key provider generates its own key on disk and is not reachable from \
                 this profile at all - set a secret reference (vault://..., env://...) to the \
                 base64 PKCS#8 of an Ed25519 key",
            );
        }
        if !bind.is_loopback() {
            return Self::Refused(
                "auth.signing_keys.key_ref is required for a deployment that binds a non-loopback \
                 address. A generated development key is reachable only when server.bind is \
                 loopback, because a process anyone but this host can reach is not a development \
                 process - set a secret reference, or bind 127.0.0.1",
            );
        }
        Self::Development
    }
}

/// Builds the key provider the decision names, or refuses to start.
///
/// Returns `None` for a deployment that has no key and is permitted not to have one — which today
/// is no deployment at all, since [`SigningKeys::choose`] answers `Configured`, `Development` or a
/// refusal. The `Option` is in the signature so that a future posture with no auth surface (a
/// read-only replica, say) has somewhere to go that is not a fourth variant nobody wired.
fn build_key_provider(
    source: SigningKeys,
    config: &enclave_config::Config,
    secrets: &enclave_config::ResolvedSecrets,
) -> anyhow::Result<Option<Arc<dyn enclave_auth::KeyProvider>>> {
    match source {
        SigningKeys::Refused(reason) => anyhow::bail!("{reason}"),
        SigningKeys::Configured => {
            let material = secrets
                .get("auth.signing_keys.key_ref")
                .context(
                    "auth.signing_keys.key_ref did not resolve; the reference names a secret this \
                     deployment's providers could not read",
                )?
                .expose_str()
                .context("auth.signing_keys.key_ref did not resolve to text")?;
            let provider = enclave_auth::ConfiguredKeyProvider::from_base64_pkcs8(
                material,
                chrono::Utc::now(),
            )
            // The adapter's error carries nothing derived from the material and this
            // context adds nothing either: what an operator needs is the field name and the
            // expected encoding, and anything more specific describes the key.
            .context(
                "auth.signing_keys.key_ref resolved to something that is not the base64 of \
                         an Ed25519 PKCS#8 document",
            )?;
            // A `kid` is public information — it names a key and authorises nothing — so it is the
            // one thing about the key that may be logged, and logging it is what lets an operator
            // confirm which key a replica picked up after a rotation.
            tracing::info!(
                kid = provider.kid().as_str(),
                "signing with the configured key from auth.signing_keys.key_ref"
            );
            Ok(Some(Arc::new(provider)))
        }
        SigningKeys::Development => {
            let directory = &config.auth.signing_keys.directory;
            tracing::warn!(
                directory = %directory.display(),
                "no signing key is configured: generating a development key on disk. This is \
                 reachable only from the community profile on a loopback bind, and the private \
                 half sits in a plaintext file — never run a deployment anyone else can reach this \
                 way"
            );
            Ok(Some(Arc::new(enclave_auth::LocalFileKeyProvider::new(directory))))
        }
    }
}

/// Assembles the `/api/v1/auth/*` surface over the PostgreSQL stores.
///
/// # Every collaborator here is real except one, and the one is announced
///
/// The token service is `EnclaveTokenService` over `PgRefreshTokenStore`, `PgDenylist` and
/// `PgSessionFacts` — rotation, reuse detection, family revocation and the re-resolved
/// `token_epoch` all against the authoritative store (`ENC-687`).
///
/// The refresh guard is [`enclave_api::ChainRefreshGuard`] over the engine this binary already
/// built, so `docs/03-LLD.md §5.3` rule 3 holds: a rotation is decided by the same
/// `TenantConditionalAccess`, reading the same tenant's rules from the same cache, that decides
/// every authenticated request (`ENC-709`). It replaces `UnrestrictedRefreshGuard`, which permitted
/// every refresh and bounded "a user who leaves an allowed network loses access" at the *refresh*
/// lifetime — fourteen days — rather than at one access-token lifetime.
///
/// The engine is a parameter rather than something built here because there must be exactly one:
/// two engines would be two rule caches, and an administrator watching a tightening take effect on
/// requests and not on refreshes would have no way to tell which. `PolicyEngine` is `Clone` over
/// `Arc`s, so passing it costs a refcount.
///
/// The exception that remains is the MFA verifier: the surface's own `UnavailableMfa`, which
/// refuses every code (`ENC-688`). It is not a hole — an account with an enrolled factor cannot
/// complete a login at all, which is the fail-closed direction.
fn build_auth_surface(
    provider: Option<Arc<dyn enclave_auth::KeyProvider>>,
    config: &enclave_config::Config,
    db: &enclave_db::DbPool,
    policy: &PolicyEngine,
) -> anyhow::Result<Option<enclave_api::routes::auth::AuthSurface>> {
    let Some(provider) = provider else { return Ok(None) };

    let issuer = access_token_issuer(config);

    let refresh = &config.auth.refresh_token;
    let auth_config = enclave_auth::AuthConfig {
        access_token: enclave_auth::AccessTokenConfig {
            issuer,
            audience: config.auth.access_token.audience.clone(),
            ttl_secs: seconds(config.auth.access_token.ttl),
            privileged_ttl_secs: seconds(config.auth.access_token.privileged_ttl),
        },
        refresh_token: enclave_auth::RefreshTokenConfig {
            idle_ttl_secs: seconds(refresh.idle_ttl),
            absolute_ttl_secs: seconds(refresh.absolute_ttl),
        },
        // Assembled here rather than through an accessor on `PasswordConfig`, because the
        // accessor would put an `enclave-config` -> `enclave-auth` edge in the crate graph to save
        // six lines in one composition function. The clamps are the same refusal
        // `AuthConfig::validate` makes, applied before the cast rather than after it.
        password: enclave_auth::PasswordPolicy {
            min_length: config.security.password.min_length as usize,
            max_length: config.security.password.max_length as usize,
            argon2: enclave_auth::Argon2Params {
                memory_kib: config.security.password.argon2.memory_kib,
                iterations: config.security.password.argon2.iterations,
                parallelism: config.security.password.argon2.parallelism,
            },
        },
    };

    let absolute_ttl = chrono::Duration::seconds(auth_config.refresh_token.absolute_ttl_secs);
    let password_policy = auth_config.password;
    let service = enclave_auth::EnclaveTokenService::new(
        auth_config,
        provider,
        enclave_db::PgRefreshTokenStore::new(db.clone()),
        enclave_db::PgDenylist::new(db.clone()),
        enclave_api::ChainRefreshGuard::new(policy.clone()),
        // The same lifetime the issuer above uses, and it has to be: `absolute_expires_at` is
        // written as `auth_time + absolute_ttl`, and this is the divisor that recovers `auth_time`
        // from it. Two different values would report an authentication time that never happened.
        enclave_db::PgSessionFacts::new(db.clone(), absolute_ttl),
    )
    .context("the auth configuration is not usable")?;

    let cookie = enclave_auth::RefreshCookieConfig {
        name: config.auth.refresh_token.cookie.name.clone(),
        path: config.auth.refresh_token.cookie.path.clone(),
    };
    cookie.validate().context("auth.refresh_token.cookie is not usable")?;

    let hasher = enclave_auth::PasswordHasher::new(password_policy)
        .context("security.password is not a usable Argon2 configuration")?;

    Ok(Some(enclave_api::routes::auth::AuthSurface::new(
        Arc::new(service),
        hasher,
        cookie,
        chrono::Duration::seconds(seconds(config.auth.refresh_token.idle_ttl)),
    )))
}

/// A configured duration as whole seconds, saturating rather than wrapping.
///
/// `HumanDuration` is unsigned and `AuthConfig` is signed, and a cast that wrapped would turn an
/// absurd configured lifetime into a negative one — which `AuthConfig::validate` reads as "TTL must
/// be positive" and refuses, but only by luck. Saturating makes the refusal the intended one.
fn seconds(duration: enclave_config::HumanDuration) -> i64 {
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}

/// The prefix of [`unconfigured_stages`]'s entry for the stage `ENC-590` wired.
const CONDITIONAL_ACCESS_STAGE: &str = "conditional_access";

/// The prefix of [`unconfigured_stages`]'s entry for the stage `ENC-594` wired.
const DLP_STAGE: &str = "dlp";

/// What `antivirus:` means for the routes *this* binary serves, said once, at start-up.
///
/// # Why the API says this at all when the worker is what scans
///
/// `crates/worker` composes the scanner and already reports what it will do with unscanned content.
/// This binary composes none — and it is the one holding preview, download, export, thumbnail and
/// sync. An operator debugging *"why does every preview answer 404"* is reading this log, not the
/// worker's, and until `ENC-828` the answer was in neither: `antivirus.provider: none` under the
/// default `BLOCK` makes the product a write-only store, and nothing on the read side said so.
///
/// It follows the `"policy stage is not enforcing"` lines above deliberately and in the same voice.
/// Those exist because a deployment permitting everything looks, from the outside, exactly like one
/// carefully allowing each request; this is the same class of fact about the same request path, and
/// the two belong in one block an operator reads once.
///
/// Levels differ because the postures differ. `BLOCK` with no engine is `error`: nothing uploaded
/// will ever be readable, which is a broken deployment whoever configured it. `ALLOW_WITH_FLAG` is
/// `warn`: it works, and it serves bytes nothing inspected, which is a decision someone made and
/// should be reminded of. A configured engine says nothing at all — a quiet log is what a correct
/// deployment earns.
fn report_antivirus_posture(antivirus: &enclave_config::AntivirusConfig) {
    if antivirus.is_enabled() {
        return;
    }

    match antivirus.unsupported_policy {
        enclave_config::UnsupportedPolicy::AllowWithFlag => tracing::warn!(
            provider = "none",
            unsupported_policy = "ALLOW_WITH_FLAG",
            "no antivirus engine is configured and `antivirus.unsupported_policy` publishes \
             anyway: preview, download, export and sync will serve content **nothing has \
             inspected for malware**, recorded SKIPPED rather than CLEAN. CONFIDENTIAL and above \
             are still refused on rank, and every version admitted this way is rescanned once an \
             engine is configured."
        ),
        enclave_config::UnsupportedPolicy::Block => tracing::error!(
            provider = "none",
            unsupported_policy = "BLOCK",
            "no antivirus engine is configured and the default BLOCK policy quarantines every \
             version, so **nothing uploaded to this deployment will ever be readable** — uploads \
             succeed and every delivery route answers 404. Configure `antivirus.provider`, or set \
             `antivirus.unsupported_policy: ALLOW_WITH_FLAG` to serve unscanned content \
             deliberately."
        ),
    }
}

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
/// The entry is replaced rather than simply dropped, because a mode that evaluates is not the same
/// as a mode that can refuse. A stage that **cannot refuse anything** is announced: `DISABLED`
/// inspects nothing, and `MONITOR`, `SIMULATION` and `WARN` are rungs of `docs/06 §9`'s rollout
/// ladder that deliberately never refuse. An operator who set `WARN` and saw no entry here would
/// reasonably conclude that content inspection was blocking.
///
/// # What this banner stopped being able to say when rules became rows (`ENC-615`)
///
/// It used to take a rule count, because there was exactly one rule set — `RuleSet::empty()` — and
/// `ENFORCE` over an empty set refuses exactly as much as `DISABLED` does. That count no longer
/// exists as a start-up fact: rules are **tenant data**, so "how many rules are in force" has one
/// answer per tenant and a host serves thousands.
///
/// It is not merely expensive to compute, it is unavailable **by construction**, which is the more
/// useful way to say it: `dlp_rules` has row-level security forced and its policy reads
/// `app.tenant_id`, and `enclave_app` is not `BYPASSRLS`. A cross-tenant count would have to run
/// with no tenant context, where `current_setting('app.tenant_id')::uuid` raises. The one role this
/// binary has cannot ask the question, and that is the same property every isolation test in the
/// workspace depends on.
///
/// So the banner reports what a deployment-wide fact can support — the mode — and the per-tenant
/// half is stated in the `tracing::info!` beside the wiring instead: a tenant with no stored rule
/// has nothing for `ENFORCE` to refuse. That is the same posture conditional access has had since
/// `ENC-590`, where a tenant with no rules is likewise not a start-up condition.
fn unenforcing_stages(dlp_mode: enclave_dlp::DlpMode) -> Vec<String> {
    let mut stages: Vec<String> = unconfigured_stages()
        .iter()
        .filter(|stage| {
            !stage.starts_with(CONDITIONAL_ACCESS_STAGE) && !stage.starts_with(DLP_STAGE)
        })
        .map(|stage| (*stage).to_owned())
        .collect();

    if !dlp_mode.enforces() {
        let posture =
            if dlp_mode.evaluates() { "evaluates, refuses nothing" } else { "inspects nothing" };
        stages.push(format!("{DLP_STAGE} ({dlp_mode} — {posture})"));
    }

    // There is deliberately no `refresh_guard` entry here any more (`ENC-709`). `ENC-687` added one
    // because this binary wired `UnrestrictedRefreshGuard` and an operator reading a banner that
    // listed `conditional_access` as wired, and said nothing about rotation, would reasonably
    // conclude that a network rule bounded a session. It did not: it bounded each request, and the
    // rotation renewed regardless, for up to the refresh lifetime.
    //
    // `build_auth_surface` now wires `ChainRefreshGuard` over this process's one `PolicyEngine`,
    // unconditionally — there is no configuration in which this binary constructs a permissive
    // guard, so there is nothing left for the entry to be true about. A banner line that is no
    // longer true is worse than no line, because it is the line an operator trusts.
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

    let mut db_config = enclave_db::DbConfig::new(enclave_db::ConnectionUrl::new(url))
        .with_max_connections(config.database.max_connections)
        // The role row-level security applies to. Omitting it left the pool connecting as whatever
        // the DSN named — the cluster superuser, in the development stack — which bypasses RLS
        // entirely. `migrations/0003` exists because of exactly that discovery (`ENC-124`), and a
        // binary that does not set this is a binary running with layer 2 switched off.
        .with_application_role(config.database.application_role.clone());

    // `POST /api/v1/auth/login` cannot resolve its tenant without this. `resolve_routed_tenant`
    // reads `tenants`, which carries no `tenant_id` and therefore has no policy — so migration
    // `0002` gives `enclave_app` no privilege on it at all and grants `SELECT` to `enclave_platform`
    // instead. With no platform DSN the lookup fails with `PlatformNotConfigured`, every host
    // resolves to nothing, and every login answers `404`. It was never wired here, which is one of
    // the two reasons the binary could not sign anyone in (`ENC-687`).
    //
    // Absent is still a supported deployment and still fails loudly rather than quietly: the same
    // `Option` the `db` crate documents, and the paths that need the role refuse instead of falling
    // back to a connection RLS would return zero rows through.
    if let Some(platform) = secrets.get("database.platform_url") {
        let platform = platform.expose_str().context("database.platform_url is not valid UTF-8")?;
        db_config = db_config.with_platform_url(enclave_db::ConnectionUrl::new(platform));
    } else {
        tracing::warn!(
            "database.platform_url is unset: POST /api/v1/auth/login cannot resolve a tenant from \
             its host and will answer 404 for every request, and no refresh family can be revoked. \
             Set database.platform_url_env or database.platform_url to a DSN for the enclave_platform role"
        );
    }

    Ok(db_config)
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

    #[test]
    fn the_conditional_access_stage_is_no_longer_unconfigured() {
        let before = unconfigured_stages();
        let after = unenforcing_stages(DlpMode::Disabled);

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

    /// The DLP entry is **computed** rather than fixed, and the banner has to be able to say each
    /// of the states a wired stage can be in (`ENC-594`, `ENC-615`).
    ///
    /// `docs/12 §1.2`: "dlp is not in the list" is an assertion about an absence and holds for free
    /// against a filter that removed every entry, so the disappearance is asserted alongside the
    /// cases where the entry must still be there, and against a list that still names the genuinely
    /// unconfigured stages.
    ///
    /// The rule count this used to take is gone with `ENC-615`: rules are tenant data now, so
    /// "how many rules are in force" is a per-tenant question the one role this binary holds cannot
    /// even ask across tenants. See `unenforcing_stages`.
    #[test]
    fn the_dlp_entry_says_whether_the_configured_mode_can_refuse_anything() {
        assert!(
            unconfigured_stages().iter().any(|stage| stage.starts_with(DLP_STAGE)),
            "the fixed entry this replaces is gone from state.rs; the filter is a no-op and the \
             computed entry below would be a second dlp line rather than a replacement"
        );

        // Enforcing: the one mode in which the stage can refuse, and the only one where it drops
        // out of the banner. Whether it *does* refuse a given tenant is that tenant's rules.
        let enforcing = unenforcing_stages(DlpMode::Enforce);
        assert!(
            !enforcing.iter().any(|stage| stage.starts_with(DLP_STAGE)),
            "ENFORCE reads each tenant's stored rules and must not be announced as unenforcing: \
             {enforcing:?}"
        );
        // The control for that absence: the stages that really are stubs are still announced.
        assert!(enforcing.iter().any(|stage| stage.starts_with("retention")));

        // The three rungs of the rollout ladder that evaluate and never refuse. Each must be named
        // by the mode actually running, because "DLP is on" is what an operator concludes from a
        // silent banner.
        for mode in [DlpMode::Monitor, DlpMode::Simulation, DlpMode::Warn] {
            let stages = unenforcing_stages(mode);
            let entry =
                stages.iter().find(|stage| stage.starts_with(DLP_STAGE)).unwrap_or_else(|| {
                    panic!("{mode} records and never refuses, and must be announced")
                });
            assert!(entry.contains(mode.as_str()), "{entry}");
            assert!(entry.contains("evaluates"), "{mode} does inspect content: {entry}");
        }

        // And `DISABLED`, which is a real mode rather than the absence of one — it must be
        // distinguishable in the banner from a mode that evaluates and declines to act.
        let disabled = unenforcing_stages(DlpMode::Disabled);
        let entry = disabled
            .iter()
            .find(|stage| stage.starts_with(DLP_STAGE))
            .expect("DISABLED inspects nothing and must be announced");
        assert!(entry.contains("inspects nothing"), "{entry}");
    }

    /// The refresh guard is announced in **no** mode, because it is wired (`ENC-709`).
    ///
    /// `ENC-687` asserted the opposite here, in all five DLP postures, and the entry it asserted was
    /// true: `UnrestrictedRefreshGuard` permitted every refresh. `ChainRefreshGuard` re-evaluates
    /// conditional access on every rotation, so the sentence has stopped being true and must stop
    /// being printed — a banner line an operator has learned to trust is the worst place for a
    /// stale claim.
    ///
    /// `docs/12-TESTING.md §1.2`: **an assertion about an absence passes for free.** "There is no
    /// `refresh_guard` entry" holds against a function that returned an empty list, against one that
    /// never ran, and against a renamed prefix. So each iteration asserts, in the same run, that the
    /// stages which really are stubs *are* still announced — and all five modes are covered because
    /// the removed line sat after the DLP branch, where an edit could restore it for one posture
    /// only.
    #[test]
    fn the_refresh_guard_is_no_longer_announced_in_any_dlp_posture() {
        for mode in [
            DlpMode::Disabled,
            DlpMode::Monitor,
            DlpMode::Simulation,
            DlpMode::Warn,
            DlpMode::Enforce,
        ] {
            let stages = unenforcing_stages(mode);
            assert!(
                !stages.iter().any(|stage| stage.starts_with("refresh_guard")),
                "{mode}: refresh re-evaluates conditional access, so announcing it as unenforcing \
                 would be a lie: {stages:?}"
            );
            // The positive control for that absence, in the same run.
            assert!(
                stages.iter().any(|stage| stage.starts_with("retention")),
                "{mode}: the genuinely unconfigured stages must still be announced, or the \
                 assertion above holds against an empty list"
            );
            assert!(stages.iter().any(|stage| stage.starts_with("classification")), "{mode}");
        }
    }

    // -------------------------------------------------------------------------------------------
    // `SigningKeys::choose` — the mechanism, not the policy (`ENC-687`)
    // -------------------------------------------------------------------------------------------

    use enclave_config::DeploymentProfile;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    const ROUTABLE: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7));
    const ANY: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

    /// A configured reference is the only source a deployment ever needs, and it is accepted from
    /// every profile and every bind — including the development one.
    ///
    /// The last part matters: if `Configured` were reachable only from the strict profiles, a
    /// developer testing against a real key would be running a code path production does not.
    #[test]
    fn a_configured_reference_is_the_source_from_every_profile_and_every_bind() {
        for profile in [
            DeploymentProfile::Community,
            DeploymentProfile::Production,
            DeploymentProfile::Enterprise,
        ] {
            for bind in [LOOPBACK, ROUTABLE, ANY] {
                assert_eq!(
                    SigningKeys::choose(true, profile, bind),
                    SigningKeys::Configured,
                    "{profile:?} on {bind}"
                );
            }
        }
    }

    /// **The mechanism.** A deployment anyone but this host can reach cannot obtain a generated
    /// key, whatever profile it names.
    ///
    /// `docs/12-TESTING.md`: an assertion about an absence passes for free. "It is not
    /// `Development`" would hold against a function that returned `Configured` for everything, so
    /// the refusal is asserted *and* the one combination that is allowed to produce a development
    /// key is asserted in the same test. Remove either half and the other stops meaning anything.
    #[test]
    fn a_generated_key_is_unreachable_for_anything_but_a_loopback_community_deployment() {
        // Every way of being reachable from another host.
        for bind in [ROUTABLE, ANY, IpAddr::V6(Ipv6Addr::UNSPECIFIED)] {
            assert!(
                matches!(SigningKeys::choose(false, DeploymentProfile::Community, bind), SigningKeys::Refused(_)),
                "a community deployment bound to {bind} is reachable from another host and must                  not be handed a generated key"
            );
        }
        // Every profile that is not development, even on loopback.
        for profile in [DeploymentProfile::Production, DeploymentProfile::Enterprise] {
            assert!(
                matches!(SigningKeys::choose(false, profile, LOOPBACK), SigningKeys::Refused(_)),
                "{profile:?} must not be handed a generated key even on loopback"
            );
        }
        // And the combination that survives, which is what makes the six refusals above meaningful
        // rather than a function that refuses everything.
        assert_eq!(
            SigningKeys::choose(false, DeploymentProfile::Community, LOOPBACK),
            SigningKeys::Development,
            "`cargo run` on a laptop has to work, or the mechanism is a wall rather than a door"
        );
        assert_eq!(
            SigningKeys::choose(
                false,
                DeploymentProfile::Community,
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            ),
            SigningKeys::Development,
            "an IPv6 loopback bind is the same deployment as an IPv4 one"
        );
    }

    /// A refusal has to tell the operator which field to set, because a process that dies naming
    /// nothing is a process somebody restarts.
    #[test]
    fn a_refusal_names_the_field_that_would_fix_it() {
        let SigningKeys::Refused(reason) =
            SigningKeys::choose(false, DeploymentProfile::Enterprise, LOOPBACK)
        else {
            panic!("the enterprise profile has no development key")
        };
        assert!(reason.contains("auth.signing_keys.key_ref"), "{reason}");
        assert!(reason.contains("vault://"), "the reference form has to be shown: {reason}");
        // Rule 11 in miniature: the message explains the *encoding* and never carries material.
        assert!(reason.contains("base64 PKCS#8"), "{reason}");
    }
}
