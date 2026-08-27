//! `enclave-cli reclaim-uploads` — the repair pass for `ENC-787`.
//!
//! # What is wrong, and why nothing else fixes it
//!
//! Before `ENC-691` closed the completion path, `POST /uploads/{id}/complete` wrote `SCANNING` and
//! stopped: no `files` row, no `file_versions` row, and a `#[must_use]` handoff nothing consumed. A
//! session left that way is collected by **nothing**. The antivirus pass queues on
//! `file_versions.av_status` and there is no version to find; `enclave_uploads::reap_expired` claims
//! `CREATED` and `UPLOADING` only, because `UploadState::Scanning` answers `false` to
//! `holds_staged_bytes`; and the storage quota was never charged, so no counter is wrong in a way
//! anyone would notice. What is left is an object in the bucket that nothing will ever read and
//! nothing is accounting for, indefinitely.
//!
//! `ENC-691` stops new ones being made. It does not clear the ones already there, and this is what
//! clears them.
//!
//! # Why a command an operator types, and not a background loop
//!
//! Because that is what the defect is. Since `ENC-691` the version is committed in the *same
//! transaction* that writes `SCANNING`, so a new strand is unrepresentable rather than merely
//! unlikely — what remains is a **historical backlog**, in whatever databases were running before
//! that landed. A backlog is repaired once, by somebody who then reads the report.
//!
//! It is also the honest place to put it today. `enclave_uploads::reap_expired` has existed since M1
//! and **no binary calls it either** (`ENC-806`): `crates/scheduler` runs only the storage
//! reconciliation, and the worker's six passes do not include a reaper. Adding a standing sweep here
//! would mean composing a tenant enumerator and an object store into a process that has neither, and
//! it would leave the ordinary reaper — the one with the larger backlog — still unwired. That is a
//! row, not a side effect of this one.
//!
//! # `--dry-run` is the default posture, not a courtesy
//!
//! `ENC-787`'s own text asks for a pass that *"reports what it found rather than deletes quietly"*.
//! This one prints every candidate — id, name, key, how long it has been claiming to scan — before
//! it is asked to destroy anything, and `--dry-run` stops there. An operator running a destructive
//! repair against a database they did not build should be able to see the list first.

use anyhow::Context as _;
use chrono::{Duration, Utc};
use enclave_core::TenantId;
use enclave_db::TenantScoped;
use enclave_uploads::UploadRepository;
use sqlx::Row as _;

use crate::cli::ReclaimUploadsArgs;
use crate::connect::Target;

/// Resolves the tenant by slug, as `set-password` does and for its reason: an operator has the
/// hostname in front of them, and a UUID typed from another terminal is how a repair runs against
/// the wrong tenant.
const SELECT_TENANT: &str =
    "SELECT id FROM tenants WHERE slug = $1 AND deleted_at IS NULL AND status <> 'DELETING'";

/// Runs the command.
///
/// # Errors
///
/// A tenant that does not resolve, a deployment with no `storage.s3` section or an unreachable
/// bucket, and connection or statement failures.
pub(crate) async fn run(
    target: &Target,
    config: Option<&std::path::Path>,
    args: &ReclaimUploadsArgs,
) -> anyhow::Result<()> {
    let idle_for =
        Duration::try_hours(i64::from(args.idle_hours)).context("--idle-hours is out of range")?;

    println!("target:     {}", target.summary());
    println!("tenant:     {}", args.tenant);
    println!("idle for:   at least {} hour(s)", args.idle_hours);
    println!("limit:      {}", args.limit);
    println!("mode:       {}", if args.dry_run { "dry run" } else { "reclaim" });
    println!();

    let mut conn = target.connect().await?;
    let tenant_row = sqlx::query(SELECT_TENANT)
        .bind(&args.tenant)
        .fetch_optional(&mut conn)
        .await
        .context("look up the tenant")?
        .with_context(|| {
            format!(
                "no live tenant with the slug `{}`. Check it against `SELECT slug FROM tenants`",
                args.tenant
            )
        })?;
    let tenant = TenantId::from_uuid(tenant_row.get("id"));
    drop(conn);

    let now = Utc::now();
    let idle_since = now - idle_for;
    let pool = target.pool().await?;

    // The listing runs in a transaction of its own, and that transaction is **rolled back**. It
    // takes `FOR UPDATE SKIP LOCKED`, so holding it open across the report would lock every
    // candidate against the completion path for as long as an operator takes to read — and on a dry
    // run there is nothing to commit in any case.
    let mut tx = TenantScoped::begin(&pool, tenant).await.context("open a tenant transaction")?;
    let candidates = UploadRepository::claim_stranded(
        &mut tx,
        tenant,
        idle_since,
        i64::try_from(args.limit).unwrap_or(i64::MAX),
    )
    .await
    .context("claim stranded sessions")?;

    if candidates.is_empty() {
        println!("nothing to reclaim: no SCANNING session in `{}` is stranded.", args.tenant);
        println!();
        println!(
            "a session is stranded only when it has been SCANNING since before {} *and* no \
             file_versions row names its staged key. A session with a version behind it belongs to \
             antivirus and is deliberately not collected — its staged key IS the version's \
             object_key, so releasing it would delete a live file's only copy.",
            idle_since.to_rfc3339()
        );
        tx.rollback().await.context("roll back the listing")?;
        pool.close().await;
        return Ok(());
    }

    println!("found {} stranded session(s):", candidates.len());
    println!();
    for session in &candidates {
        let record = session.record();
        println!("  {}  {}", record.id, record.name);
        println!("      staged:      {}", record.staged.as_str());
        println!("      scanning since: {}", record.updated_at.to_rfc3339());
        println!("      no file_versions row names that key");
    }
    println!();

    // Rolled back whether or not the repair runs. The claim above was a *look*; the reclaim below
    // takes its own claim, in its own transaction, which is what keeps the lock held for the
    // duration of the deletes rather than for the duration of the report.
    tx.rollback().await.context("roll back the listing")?;

    if args.dry_run {
        println!("dry run: nothing was deleted. Re-run without --dry-run to reclaim these.");
        pool.close().await;
        return Ok(());
    }

    let store = object_store(config).await?;

    let mut tx = TenantScoped::begin(&pool, tenant).await.context("open a tenant transaction")?;
    let report =
        enclave_uploads::reclaim_stranded(&mut tx, &store, tenant, now, idle_for, args.limit)
            .await
            .context("reclaim stranded sessions")?;
    tx.commit().await.context("commit the reclaim")?;

    println!("found:      {}", report.found);
    println!("reclaimed:  {}  (staged object deleted, session EXPIRED)", report.reclaimed);
    println!("deferred:   {}  (left for the next run)", report.deferred);
    if report.deferred > 0 {
        println!();
        println!(
            "note:       a deferred session kept its bytes *and* its SCANNING row on purpose — the \
             row is only marked once the delete has succeeded, because a row marked EXPIRED before \
             the delete would never be claimed again and its object would be orphaned for good."
        );
    }
    if report.is_full(args.limit) {
        println!();
        println!("note:       the batch was full; run this again to continue.");
    }

    pool.close().await;
    Ok(())
}

/// The object store `storage.s3` names.
///
/// Composed exactly as `crates/api/src/main.rs` and `crates/worker/src/main.rs` compose it —
/// `connect_and_verify`, so an unreachable bucket is a refusal here rather than a repair that
/// reports having released bytes it never touched.
async fn object_store(
    config: Option<&std::path::Path>,
) -> anyhow::Result<enclave_storage::S3BlobStore> {
    let path = config.context(
        "reclaiming needs the object store, so it needs a configuration file: pass \
         `--config enclave.yaml`. The database alone is not enough — the staged bytes live in the \
         bucket, and a repair that marked rows EXPIRED without deleting them would leave exactly \
         the orphans it is meant to collect.",
    )?;

    let loaded = enclave_config::ConfigLoader::new()
        .with_file(path)
        .load()
        .with_context(|| format!("could not load configuration from {}", path.display()))?;
    let config = loaded.config();

    let section = config.storage.s3.as_ref().context(
        "this deployment configures no `storage.s3` section, so there is no bucket to release \
         staged bytes from",
    )?;

    let registry = enclave_config::SecretRegistry::local();
    enclave_storage::S3BlobStore::connect_and_verify(
        enclave_storage::S3Config::from_operator_config(section),
        &registry,
    )
    .await
    .with_context(|| {
        format!(
            "connect to the object store named by `storage.s3` (bucket `{}`, region `{}`)",
            section.bucket, section.region
        )
    })
}
