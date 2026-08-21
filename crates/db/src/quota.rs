//! The per-tenant stored-byte quota — `ENC-584`, `plans/M4-GOVERNANCE.md` D31, `docs/04 §16.1`.
//!
//! # The shape, and the shape it is not
//!
//! `crates/sharing/src/redeem.rs` writes out the wrong shape for the share-link download budget,
//! and it is the same wrong shape here:
//!
//! ```text
//! let quota = read(tenant)?;                       // used = 9 GB, limit = 10 GB
//! if quota.used + size > quota.limit {             // 9 + 0.5 < 10, so: fine
//!     return Err(QuotaExceeded);
//! }
//! insert_version(size)?;
//! increment(tenant, size)?;                        // used = 9.5 GB
//! ```
//!
//! Ten uploads arriving together all read `9`, all conclude there is room, and the tenant ends at
//! 14 GB against a 10 GB limit. Nothing in that code looks wrong and every sequential test of it
//! passes, which is why D31 exists: **the limit goes in the `WHERE` clause of the charging
//! statement, and a zero-row result is the refusal.** [`CHARGE_SQL`] is that statement.
//!
//! The `CHECK` constraint in `migrations/0018` is the backstop, not the guard. It turns a mistake
//! in [`CHARGE_SQL`] — a dropped predicate, an `OR` where an `AND` belonged — into a failed
//! transaction rather than an exceeded quota.
//!
//! # Charge before the bytes, in the caller's transaction
//!
//! [`charge_storage`] takes a [`TenantScoped`] rather than a pool, exactly as
//! `enclave_sharing::redeem` takes a connection, and for the same reason: it must not be
//! committable separately from the write it bounds. Charge, insert the `file_versions` row, commit
//! both — or commit neither. A charge that committed on its own would leak quota on every failed
//! upload; a version row that committed on its own would be bytes nobody paid for.
//!
//! # Reads, deletes and exports are never quota-blocked
//!
//! D31 is emphatic and `plans/M4-GOVERNANCE.md`'s exit criteria repeat it: *a tenant over quota
//! that cannot delete anything cannot get back under it, and one that cannot export cannot leave.*
//!
//! That is enforced here by construction rather than by discipline. [`charge_storage`] is the only
//! function in this module that can refuse, and it is the only one whose statement carries a bound
//! in its `WHERE` clause. [`Released`] has **no** refusal variant, so "this delete was refused for
//! quota" is not a value that can be constructed; [`storage_quota`] is a plain `SELECT`. A future
//! export path that wanted to consult the quota would find nothing here that answers "no".
//!
//! # Quotas notify before they refuse
//!
//! `plans/M4-GOVERNANCE.md §2`. The crossing of `soft_limit_pct` is decided *inside*
//! [`CHARGE_SQL`], by the same row lock the charge serialises on, and stamped on the row — so it is
//! announced once rather than once per replica, and it survives a restart.
//! [`Admitted::crossed_soft_limit`] is the only edge on which a caller notifies.
//!
//! Enforcement mode is the other half of the same idea: `MONITOR` counts, `WARN` counts and
//! notifies, `BLOCK` counts, notifies and refuses. A control that cannot be turned on gradually
//! will be turned on carelessly, or not at all.
//!
//! # Reconciliation, and the window
//!
//! `plans/M4-GOVERNANCE.md §5` names the hard part: *"Two numbers for one fact. The nightly job
//! must be able to correct without a window in which writes are refused on a stale figure."*
//!
//! The window is created by writing an **absolute** figure, and there is no arrangement of an
//! absolute write that avoids it:
//!
//! * measure, then assign — every charge that commits in between is erased, and the tenant is
//!   under-counted by exactly the traffic it took during the job;
//! * lock the row, then measure, then assign — nothing is erased, and every charge blocks for the
//!   length of a full-table sum. That is the refusal window with a different name, and on the
//!   largest tenant, which is the one most likely to be near its limit;
//! * measure, then assign only if the row has not moved — the job livelocks on exactly the busy
//!   tenants whose figure is worth correcting.
//!
//! So nothing here writes an absolute figure. [`OBSERVE_SQL`] reads the recorded counter and the
//! measured sum **in one statement, therefore in one snapshot**; because [`CHARGE_SQL`] runs in the
//! same transaction as the `file_versions` insert it pays for, a snapshot sees both or neither, and
//! the pair is consistent by construction rather than by timing. The difference is the drift.
//! [`CORRECT_SQL`] then applies it *relatively* — `used_bytes = used_bytes + drift` — in one
//! instantaneous statement.
//!
//! Nothing is locked while the sum runs. Charges that commit between the observation and the
//! correction keep their full effect, because both are additive. Drift is a property of the
//! snapshot it was measured in, and a later legitimate charge does not invalidate it: it is the
//! *error*, not the balance. The residue is that drift arising after the snapshot waits for the
//! next run, which is what a nightly job promises in any case.
//!
//! # What "actual" means, and what it does not
//!
//! `docs/04 §16` reconciles against `SUM(file_versions.size_bytes)`, and [`OBSERVE_SQL`] does
//! exactly that. That is the authority for *what this deployment asked the object store to hold*,
//! and it is deliberately not a listing of the bucket: `docs/12-TESTING.md §1.1` draws the line at
//! testing our integration rather than a third party's correctness, and the same line applies to
//! reconciling against one. A divergence between `file_versions` and the store itself is a
//! storage-layer question with a different owner and a different remedy — orphaned objects, not a
//! wrong bill.
//!
//! Every version except `FAILED` counts, including versions of soft-deleted files. Bytes in the
//! recycle bin are bytes the deployment is storing and paying for; a quota that stopped counting
//! them would make the trash an unmetered tier. `FAILED` is the one status that asserts the bytes
//! are *not* held.

use enclave_core::id::TenantId;
use sqlx::Row as _;

use crate::ids::sql;
use crate::pool::DbPool;
use crate::tenant::TenantScoped;
use crate::tenants::active_tenants;
use crate::DbError;

/// How hard a quota is being applied — rollout, not severity.
///
/// `plans/M4-GOVERNANCE.md §2`: a control that cannot be turned on gradually will be turned on
/// carelessly, or not at all. An administrator moves a tenant `MONITOR` → `WARN` → `BLOCK` against
/// real traffic, and only the last one can refuse anything.
///
/// The strings match `storage_quotas.enforcement`'s `CHECK` exactly; they are the same vocabulary
/// and a second spelling would guarantee a mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Enforcement {
    /// Count only. Never notifies, never refuses.
    Monitor,
    /// Count and announce the soft limit. Never refuses.
    Warn,
    /// Count, announce, and refuse a charge that would cross the limit.
    Block,
}

impl Enforcement {
    /// The value as `storage_quotas.enforcement` spells it.
    #[must_use]
    pub const fn as_sql(self) -> &'static str {
        match self {
            Self::Monitor => "MONITOR",
            Self::Warn => "WARN",
            Self::Block => "BLOCK",
        }
    }

    /// Whether this mode is allowed to refuse a write.
    #[must_use]
    pub const fn refuses(self) -> bool {
        matches!(self, Self::Block)
    }

    fn from_sql(value: &str) -> Result<Self, DbError> {
        match value {
            "MONITOR" => Ok(Self::Monitor),
            "WARN" => Ok(Self::Warn),
            "BLOCK" => Ok(Self::Block),
            // Not a `RowNotFound`, and not a default: an unrecognised mode means the migration's
            // `CHECK` and this enum have diverged, and guessing `BLOCK` would refuse every write in
            // the deployment while guessing `MONITOR` would enforce nothing in it.
            _ => Err(DbError::InvalidConfig {
                field: "storage_quotas.enforcement",
                problem: "is not one of MONITOR, WARN or BLOCK",
            }),
        }
    }
}

/// A tenant's stored-byte quota as the row currently holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageQuota {
    /// What the tenant is sold, in bytes.
    pub limit_bytes: i64,
    /// What the tenant is using, in bytes.
    pub used_bytes: i64,
    /// The acknowledged part of `used_bytes` sitting above `limit_bytes`.
    ///
    /// Not headroom — see `migrations/0018_storage_quotas.sql`. A tenant carrying an overshoot is
    /// refused by [`charge_storage`] just as one exactly at its limit is; the column exists so that
    /// an over-limit state can be *recorded* under a `CHECK` that otherwise forbids it.
    pub overshoot_bytes: i64,
    /// The percentage of `limit_bytes` at which administrators are told.
    pub soft_limit_pct: i32,
    /// How hard the quota is being applied.
    pub enforcement: Enforcement,
}

impl StorageQuota {
    /// Bytes remaining before a charge would be refused. Never negative.
    ///
    /// Computed from `limit_bytes` alone, deliberately: `overshoot_bytes` is an acknowledgement,
    /// not an allowance, and adding it here is the one-line change that would silently hand extra
    /// room to exactly the tenants already over their limit.
    #[must_use]
    pub const fn headroom_bytes(&self) -> i64 {
        let remaining = self.limit_bytes - self.used_bytes;
        if remaining > 0 {
            remaining
        } else {
            0
        }
    }

    /// Whether usage has reached `soft_limit_pct` of the limit.
    #[must_use]
    pub const fn is_over_soft_limit(&self) -> bool {
        self.used_bytes.saturating_mul(100)
            >= self.limit_bytes.saturating_mul(self.soft_limit_pct as i64)
    }

    fn from_row(row: &sqlx::postgres::PgRow) -> Result<Self, DbError> {
        Ok(Self {
            limit_bytes: row.try_get("limit_bytes").map_err(DbError::Query)?,
            used_bytes: row.try_get("used_bytes").map_err(DbError::Query)?,
            overshoot_bytes: row.try_get("overshoot_bytes").map_err(DbError::Query)?,
            soft_limit_pct: row.try_get("soft_limit_pct").map_err(DbError::Query)?,
            enforcement: Enforcement::from_sql(
                row.try_get::<String, _>("enforcement").map_err(DbError::Query)?.as_str(),
            )?,
        })
    }
}

/// A charge that was accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admitted {
    /// The quota as it stands *after* this charge.
    pub quota: StorageQuota,
    /// Whether this charge is the one that crossed `soft_limit_pct`.
    ///
    /// True for exactly one charge per crossing, decided inside [`CHARGE_SQL`] under the row lock,
    /// and stamped on the row — so two replicas charging concurrently do not both announce it, and
    /// a restart does not announce it again. The caller raises the notification;
    /// `plans/M4-GOVERNANCE.md §2` is why there is one to raise before anything is refused.
    pub crossed_soft_limit: bool,
}

/// A charge that was refused because the tenant is at its limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused {
    /// The quota, unchanged — this charge moved nothing.
    pub quota: StorageQuota,
    /// What was asked for.
    pub requested_bytes: i64,
}

/// The outcome of [`charge_storage`].
///
/// `#[must_use]` for the same reason `PolicyDecision` is (`CLAUDE.md` rule 8): the refusal *is* the
/// enforcement. A caller that dropped this value would insert the `file_versions` row anyway, and
/// the quota would be a number in a table rather than a control.
#[must_use = "a refused charge must fail the write it bounds; dropping this value lets the write \
              proceed and the quota enforces nothing"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charged {
    /// There was room, and the counter now includes this charge.
    Admitted(Admitted),
    /// There was not, and nothing was moved.
    Refused(Refused),
    /// This tenant has no quota row, so nothing is metered and nothing is refused.
    ///
    /// A missing row means *unmetered*, never *refused*: a quota is a billing control, and
    /// defaulting an unconfigured tenant to zero bytes would make provisioning order the difference
    /// between a working deployment and a read-only one. The cost is that a deleted row disables
    /// enforcement silently, which is why `enclave_app` holds no `DELETE` on the table and why
    /// [`StorageReconciliation::unmetered`] counts these every night.
    Unmetered,
}

impl Charged {
    /// Whether the write this charge bounds may proceed.
    #[must_use]
    pub const fn is_admitted(&self) -> bool {
        matches!(self, Self::Admitted(_) | Self::Unmetered)
    }

    /// The refusal, if this is one.
    #[must_use]
    pub const fn refused(&self) -> Option<&Refused> {
        match self {
            Self::Refused(refused) => Some(refused),
            _ => None,
        }
    }
}

impl From<Refused> for enclave_core::Error {
    /// `QUOTA_EXCEEDED`, carrying the limit rather than the usage.
    ///
    /// `docs/05-API.md §5` renders a capacity quota as `403` — waiting does not fix it — and the
    /// limit is what a caller can act on. The *usage* is deliberately not in the error: it is a
    /// number that moves, and an error body quoting it invites a client to retry against a figure
    /// that was true one round trip ago.
    fn from(refused: Refused) -> Self {
        Self::QuotaExceeded {
            quota: enclave_core::QuotaKind::StorageBytes,
            limit: refused.quota.limit_bytes,
        }
    }
}

/// The outcome of [`release_storage`].
///
/// **There is no refusal variant, and that is the type-level form of D31's second half.** A delete
/// that could be refused for quota is a tenant that cannot get back under its limit, and an export
/// that could be refused is a tenant that cannot leave. Neither is representable here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Released {
    /// The release was recorded; the quota now stands as given.
    Recorded(StorageQuota),
    /// This tenant has no quota row, so there was nothing to release against.
    Unmetered,
}

/// The recorded counter and the measured truth, read in one snapshot.
///
/// The two fields are only comparable because they came from [`OBSERVE_SQL`], which is one
/// statement: two `SELECT`s in one `READ COMMITTED` transaction take *two* snapshots, and a charge
/// committing between them would make the drift the difference between two different instants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    /// What `storage_quotas.used_bytes` said.
    pub recorded_bytes: i64,
    /// What `SUM(file_versions.size_bytes)` said, in the same snapshot.
    pub measured_bytes: i64,
}

impl Observation {
    /// How wrong the counter is, signed: positive means the write path under-counted.
    ///
    /// Signed on purpose. `abs()` would hide the direction, and the directions have opposite
    /// consequences — under-counting means a tenant is storing bytes it was not charged for, and
    /// over-counting means a tenant is being refused writes it has room for.
    #[must_use]
    pub const fn drift_bytes(&self) -> i64 {
        self.measured_bytes - self.recorded_bytes
    }

    /// Whether the counter and the measurement agree, which is the expected result.
    #[must_use]
    pub const fn agrees(&self) -> bool {
        self.drift_bytes() == 0
    }
}

/// What one tenant's reconciliation did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Corrected {
    /// The drift that was applied, signed.
    pub drift_bytes: i64,
    /// The quota after the correction.
    pub quota: StorageQuota,
}

/// What a whole nightly pass did.
///
/// Reported rather than logged per tenant: drift is a defect indicator (`docs/04 §16` — "drift
/// indicates a bug in the write path"), and a defect indicator is worth a number an operator can
/// alert on rather than a line somebody has to notice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StorageReconciliation {
    /// Tenants examined.
    pub examined: usize,
    /// Tenants whose counter disagreed with the measurement.
    pub drifted: usize,
    /// The sum of the absolute drifts applied, in bytes.
    pub total_drift_bytes: i64,
    /// Tenants with no quota row at all.
    ///
    /// Counted because a missing row is unmetered rather than refused: this is the number that
    /// makes "enforcement was quietly switched off for a tenant" visible, and the only one that
    /// would.
    pub unmetered: usize,
}

/// The charging statement. `plans/M4-GOVERNANCE.md` D31; `migrations/0008`'s shape.
///
/// Four things are load-bearing:
///
/// 1. **The limit is in the `WHERE` clause.** That makes the read and the write one operation, so
///    concurrent uploads serialise on the row lock instead of all observing the same stale figure.
///    Under `READ COMMITTED` a contender whose row was updated while it waited re-evaluates this
///    predicate against the *new* row, which is exactly what makes the last one over the line fail.
/// 2. **`RETURNING` gives this caller's figure.** A `SELECT` afterwards would report whatever a
///    concurrent charge had reached by then.
/// 3. **The bound is `limit_bytes` alone.** `overshoot_bytes` widens the `CHECK` constraint so that
///    an over-limit state can be recorded; adding it here would hand extra room to precisely the
///    tenants that are over.
/// 4. **The soft-limit crossing is decided here.** Under the same row lock, stamped on the row,
///    so it fires once — not once per replica and not again after a restart.
const CHARGE_SQL: &str = "
UPDATE storage_quotas
   SET used_bytes = used_bytes + $2,
       soft_limit_notified_at = CASE
           WHEN enforcement <> 'MONITOR'
            AND soft_limit_notified_at IS NULL
            AND (used_bytes + $2) * 100 >= limit_bytes * soft_limit_pct
           THEN now()
           ELSE soft_limit_notified_at
       END,
       updated_at = now()
 WHERE tenant_id = $1
   AND (enforcement <> 'BLOCK' OR used_bytes + $2 <= limit_bytes)
 RETURNING used_bytes,
           limit_bytes,
           overshoot_bytes,
           soft_limit_pct,
           enforcement,
           (soft_limit_notified_at IS NOT NULL AND soft_limit_notified_at = now())
               AS crossed_soft_limit
";

/// The release. **No bound in the `WHERE` clause, and that absence is the feature.**
///
/// `GREATEST(used_bytes - $2, 0)` rather than `used_bytes - $2`: the column carries
/// `CHECK (used_bytes >= 0)`, and an over-release — a double purge, a release for bytes a bug never
/// charged — would abort the transaction. Aborting a *delete* on a quota-accounting error is the
/// hostage situation D31 forbids, arrived at by a different road, so the statement saturates
/// instead. The clamp is not silent: it is drift, and the nightly reconciliation is what reports
/// it.
///
/// `overshoot_bytes` shrinks with usage — `LEAST(overshoot, excess)` — so a tenant that deletes its
/// way back under the limit does not leave a widened `CHECK` behind it.
const RELEASE_SQL: &str = "
UPDATE storage_quotas
   SET used_bytes = GREATEST(used_bytes - $2, 0),
       overshoot_bytes = GREATEST(
           LEAST(overshoot_bytes, GREATEST(used_bytes - $2, 0) - limit_bytes), 0),
       soft_limit_notified_at = CASE
           WHEN GREATEST(used_bytes - $2, 0) * 100 < limit_bytes * soft_limit_pct
           THEN NULL
           ELSE soft_limit_notified_at
       END,
       updated_at = now()
 WHERE tenant_id = $1
 RETURNING used_bytes, limit_bytes, overshoot_bytes, soft_limit_pct, enforcement
";

const READ_SQL: &str = "
SELECT used_bytes, limit_bytes, overshoot_bytes, soft_limit_pct, enforcement
  FROM storage_quotas
 WHERE tenant_id = $1
";

/// Provisioning, a limit change and an enforcement change, in one statement.
///
/// One statement because the three cannot be separated safely: raising enforcement to `BLOCK` for a
/// tenant already over its limit, or lowering the limit below current usage, both produce a row the
/// `CHECK` forbids unless the overshoot is acknowledged in the *same* statement. Splitting them
/// into "set the limit" and "then fix the overshoot" is a window in which the row cannot be written
/// at all.
///
/// `overshoot_bytes` is recomputed from the new limit rather than accumulated, so it is always
/// exactly the excess — an acknowledgement of what is, not a credit that accrues.
const CONFIGURE_SQL: &str = "
INSERT INTO storage_quotas (tenant_id, limit_bytes, soft_limit_pct, enforcement, updated_at)
VALUES ($1, $2, $3, $4, now())
ON CONFLICT (tenant_id) DO UPDATE
   SET limit_bytes = EXCLUDED.limit_bytes,
       soft_limit_pct = EXCLUDED.soft_limit_pct,
       enforcement = EXCLUDED.enforcement,
       overshoot_bytes = GREATEST(storage_quotas.used_bytes - EXCLUDED.limit_bytes, 0),
       soft_limit_notified_at = CASE
           WHEN storage_quotas.used_bytes * 100
                < EXCLUDED.limit_bytes * EXCLUDED.soft_limit_pct
           THEN NULL
           ELSE storage_quotas.soft_limit_notified_at
       END,
       updated_at = now()
 RETURNING used_bytes, limit_bytes, overshoot_bytes, soft_limit_pct, enforcement
";

/// The counter and the truth, in **one** statement and therefore one snapshot.
///
/// Splitting this into two `SELECT`s is the defect this constant exists to prevent: under
/// `READ COMMITTED` each statement takes its own snapshot, so a charge committing between them
/// would appear in one number and not the other, and the difference — which is about to be written
/// back as a correction — would be a real upload rather than drift.
///
/// `::BIGINT` because `SUM(bigint)` is `numeric` in PostgreSQL, and decoding it as an `i64` fails
/// at runtime rather than at compile time.
///
/// `status <> 'FAILED'` and no `deleted_at` predicate: see the module header.
const OBSERVE_SQL: &str = "
SELECT q.used_bytes AS recorded_bytes,
       COALESCE((SELECT SUM(v.size_bytes)
                   FROM file_versions v
                  WHERE v.tenant_id = q.tenant_id
                    AND v.status <> 'FAILED'), 0)::BIGINT AS measured_bytes
  FROM storage_quotas q
 WHERE q.tenant_id = $1
";

/// The correction — **relative, never absolute**. The module header argues why at length.
///
/// `used_bytes = used_bytes + $2` preserves every charge that committed since the observation,
/// because both are additive. An `= $2` here is the whole bug: it would erase them, and the tenant
/// would be under-counted by exactly the traffic it took while the job ran.
///
/// `overshoot_bytes` is reset to the true excess, because reconciliation is the statement that
/// establishes truth: a tenant that has come back under its limit stops carrying a widened `CHECK`,
/// and one that is genuinely over gets an acknowledgement large enough for the figure to be
/// written at all.
const CORRECT_SQL: &str = "
UPDATE storage_quotas
   SET used_bytes = GREATEST(used_bytes + $2, 0),
       overshoot_bytes = GREATEST(GREATEST(used_bytes + $2, 0) - limit_bytes, 0),
       last_drift_bytes = $2,
       reconciled_at = now(),
       soft_limit_notified_at = CASE
           WHEN GREATEST(used_bytes + $2, 0) * 100 < limit_bytes * soft_limit_pct
           THEN NULL
           ELSE soft_limit_notified_at
       END,
       updated_at = now()
 WHERE tenant_id = $1
 RETURNING used_bytes, limit_bytes, overshoot_bytes, soft_limit_pct, enforcement
";

/// Reads the tenant's quota. Never refuses anything; a read path may call this freely.
///
/// # Errors
///
/// Query failures. A tenant with no quota row is `Ok(None)`, not an error — see
/// [`Charged::Unmetered`].
pub async fn storage_quota(tx: &mut TenantScoped) -> Result<Option<StorageQuota>, DbError> {
    let tenant = tx.tenant_id();
    let row = sqlx::query(READ_SQL)
        .bind(sql(tenant))
        .fetch_optional(&mut **tx)
        .await
        .map_err(DbError::Query)?;
    row.as_ref().map(StorageQuota::from_row).transpose()
}

/// Charges `bytes` against the tenant's stored-byte quota, refusing if there is no room.
///
/// Call this **inside the transaction that writes the `file_versions` row**, before the row is
/// written, and commit both together. See the module header.
///
/// # Errors
///
/// Query failures, and [`DbError::InvalidConfig`] if `bytes` does not fit PostgreSQL's `bigint`.
pub async fn charge_storage(tx: &mut TenantScoped, bytes: u64) -> Result<Charged, DbError> {
    let bytes = as_bigint(bytes)?;
    let tenant = tx.tenant_id();

    let row = sqlx::query(CHARGE_SQL)
        .bind(sql(tenant))
        .bind(bytes)
        .fetch_optional(&mut **tx)
        .await
        .map_err(DbError::Query)?;

    match row {
        Some(row) => Ok(Charged::Admitted(Admitted {
            quota: StorageQuota::from_row(&row)?,
            crossed_soft_limit: row.try_get("crossed_soft_limit").map_err(DbError::Query)?,
        })),
        // Zero rows has two causes — the quota refused, or there is no quota row — and the caller
        // has to tell them apart. This second read is safe precisely because the decision has
        // already been made: the `UPDATE` above was the authority, it moved nothing, and this
        // `SELECT` only decides which *kind* of "nothing happened" to report. It cannot admit a
        // charge, so it cannot over-issue, which is the property a check-then-write lacks.
        None => match storage_quota(tx).await? {
            Some(quota) => Ok(Charged::Refused(Refused { quota, requested_bytes: bytes })),
            None => Ok(Charged::Unmetered),
        },
    }
}

/// Returns `bytes` to the tenant's quota, on a purge or a hard delete.
///
/// Cannot refuse. See [`Released`].
///
/// # Errors
///
/// Query failures, and [`DbError::InvalidConfig`] if `bytes` does not fit PostgreSQL's `bigint`.
pub async fn release_storage(tx: &mut TenantScoped, bytes: u64) -> Result<Released, DbError> {
    let bytes = as_bigint(bytes)?;
    let tenant = tx.tenant_id();

    let row = sqlx::query(RELEASE_SQL)
        .bind(sql(tenant))
        .bind(bytes)
        .fetch_optional(&mut **tx)
        .await
        .map_err(DbError::Query)?;

    match row {
        Some(row) => Ok(Released::Recorded(StorageQuota::from_row(&row)?)),
        None => Ok(Released::Unmetered),
    }
}

/// Creates or updates the tenant's quota — the administrative path.
///
/// # Errors
///
/// Query failures, and [`DbError::InvalidConfig`] if `limit_bytes` does not fit a `bigint` or
/// `soft_limit_pct` is outside 1–100.
pub async fn configure_storage_quota(
    tx: &mut TenantScoped,
    limit_bytes: u64,
    soft_limit_pct: i32,
    enforcement: Enforcement,
) -> Result<StorageQuota, DbError> {
    let limit_bytes = as_bigint(limit_bytes)?;
    if !(1..=100).contains(&soft_limit_pct) {
        return Err(DbError::InvalidConfig {
            field: "storage_quotas.soft_limit_pct",
            problem: "is outside 1..=100, so no charge could ever cross it",
        });
    }
    let tenant = tx.tenant_id();

    let row = sqlx::query(CONFIGURE_SQL)
        .bind(sql(tenant))
        .bind(limit_bytes)
        .bind(soft_limit_pct)
        .bind(enforcement.as_sql())
        .fetch_one(&mut **tx)
        .await
        .map_err(DbError::Query)?;

    StorageQuota::from_row(&row)
}

/// Reads the counter and measures the truth, in one snapshot.
///
/// Takes no locks and blocks no writer, which is the first half of why the nightly job has no
/// refusal window.
///
/// # Errors
///
/// Query failures. A tenant with no quota row is `Ok(None)`.
pub async fn observe_storage(tx: &mut TenantScoped) -> Result<Option<Observation>, DbError> {
    let tenant = tx.tenant_id();
    let row = sqlx::query(OBSERVE_SQL)
        .bind(sql(tenant))
        .fetch_optional(&mut **tx)
        .await
        .map_err(DbError::Query)?;

    row.map(|row| {
        Ok(Observation {
            recorded_bytes: row.try_get("recorded_bytes").map_err(DbError::Query)?,
            measured_bytes: row.try_get("measured_bytes").map_err(DbError::Query)?,
        })
    })
    .transpose()
}

/// Applies an observation's drift as a **relative** correction.
///
/// May be called in a different transaction from [`observe_storage`], and normally is: that is the
/// second half of why there is no refusal window. Charges committed in between keep their effect.
///
/// # Errors
///
/// Query failures. A tenant with no quota row is `Ok(None)`.
pub async fn correct_storage(
    tx: &mut TenantScoped,
    observation: Observation,
) -> Result<Option<Corrected>, DbError> {
    let tenant = tx.tenant_id();
    let drift = observation.drift_bytes();

    let row = sqlx::query(CORRECT_SQL)
        .bind(sql(tenant))
        .bind(drift)
        .fetch_optional(&mut **tx)
        .await
        .map_err(DbError::Query)?;

    row.as_ref()
        .map(|row| Ok(Corrected { drift_bytes: drift, quota: StorageQuota::from_row(row)? }))
        .transpose()
}

/// The nightly pass: reconcile every active tenant's stored-byte counter.
///
/// This is the job `docs/02-HLD.md §4` assigns to the scheduler and `docs/04 §16` describes; the
/// scheduler binary owns the *cadence*, and this owns what one run does.
///
/// One transaction per tenant, and two per tenant that drifted — the observation and the correction
/// are deliberately **not** in one transaction, because a single transaction spanning both would
/// hold the observation's snapshot across the correction for no benefit. Each tenant is independent:
/// a failure on one is returned, and the tenants already reconciled keep their corrections, because
/// each committed on its own.
///
/// # Errors
///
/// [`DbError::PlatformNotConfigured`] when no cross-tenant credential is configured — a refusal,
/// never an empty pass — and any query failure. See [`active_tenants`].
pub async fn reconcile_storage(pool: &DbPool) -> Result<StorageReconciliation, DbError> {
    let tenants = active_tenants(pool).await?;
    let mut report = StorageReconciliation::default();

    for tenant in tenants {
        report.examined += 1;
        match reconcile_one(pool, tenant).await? {
            None => report.unmetered += 1,
            Some(corrected) if corrected.drift_bytes != 0 => {
                report.drifted += 1;
                report.total_drift_bytes =
                    report.total_drift_bytes.saturating_add(corrected.drift_bytes.saturating_abs());
                tracing::warn!(
                    tenant = %tenant,
                    drift_bytes = corrected.drift_bytes,
                    used_bytes = corrected.quota.used_bytes,
                    "storage quota drift corrected; non-zero drift is a defect in the write path"
                );
            }
            Some(_) => {}
        }
    }

    Ok(report)
}

/// One tenant's observation and correction. `None` when the tenant has no quota row.
async fn reconcile_one(pool: &DbPool, tenant: TenantId) -> Result<Option<Corrected>, DbError> {
    let mut read = TenantScoped::begin(pool, tenant).await?;
    let observed = observe_storage(&mut read).await?;
    // Committed rather than dropped: the observation is read-only, and leaving the transaction to
    // be rolled back by `Drop` would hold its snapshot until the handle went out of scope — which
    // is the whole thing this design is arranged to avoid holding.
    read.commit().await?;

    let Some(observation) = observed else { return Ok(None) };

    let mut write = TenantScoped::begin(pool, tenant).await?;
    let corrected = correct_storage(&mut write, observation).await?;
    write.commit().await?;
    Ok(corrected)
}

/// A byte count on its way into a `bigint` column.
///
/// An error rather than a saturation: a charge silently clamped to `i64::MAX` would refuse every
/// subsequent write in the tenant, and one clamped the other way would be free storage.
fn as_bigint(bytes: u64) -> Result<i64, DbError> {
    i64::try_from(bytes).map_err(|_| DbError::InvalidConfig {
        field: "storage quota byte count",
        problem: "does not fit PostgreSQL's bigint",
    })
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// Just the `WHERE` clause of a statement — everything between `WHERE` and `RETURNING`.
    ///
    /// The `RETURNING` list has to be excluded rather than left in, and finding that out cost two
    /// failing tests: both statements *return* `limit_bytes` and `overshoot_bytes`, so a scan of
    /// "everything after WHERE" reports a bound in a statement that has none. `docs/12 §1.2` warns
    /// about exactly this class — a source-scanning test whose needle appears somewhere innocent —
    /// and here it failed loudly rather than passing for the wrong reason, which is the good
    /// direction for that mistake to go.
    fn where_clause(statement: &str) -> &str {
        let (_head, tail) = statement.split_once(" WHERE ").expect("the statement has a WHERE");
        tail.split_once(" RETURNING ").map_or(tail, |(clause, _returning)| clause).trim()
    }

    /// The two statements that decide whether the quota is a control or a number in a table.
    ///
    /// Nearly free, and it says so: it compiles nothing and asserts about strings. It is here
    /// because the behavioural proofs need a database and this does not, so a developer who moves
    /// the limit out of the `WHERE` clause — the exact `plans/M4-GOVERNANCE.md` D31 defect — finds
    /// out from `cargo test` rather than from a tenant's bill.
    #[test]
    fn the_limit_is_in_the_charging_statements_where_clause_and_nowhere_else() {
        let where_clause = where_clause(CHARGE_SQL);
        assert!(
            where_clause.contains("used_bytes + $2 <= limit_bytes"),
            "the limit left the WHERE clause, which makes the charge a check-then-write: {CHARGE_SQL}"
        );
        assert!(
            !where_clause.contains("overshoot_bytes"),
            "overshoot_bytes is an acknowledgement, not headroom; it must not widen the charge"
        );
    }

    /// D31's second half, read out of the statement that has to honour it.
    #[test]
    fn the_release_statement_carries_no_bound_at_all() {
        let where_clause = where_clause(RELEASE_SQL);
        assert!(
            !where_clause.contains("limit_bytes"),
            "a delete that consults the limit is a tenant that cannot get back under it: \
             {RELEASE_SQL}"
        );
        assert_eq!(
            where_clause, "tenant_id = $1",
            "the release must be bounded by the tenant and by nothing else"
        );
    }

    /// The relative correction, which is the whole answer to the reconciliation window.
    #[test]
    fn the_correction_is_relative_rather_than_an_assignment() {
        assert!(
            CORRECT_SQL.contains("used_bytes = GREATEST(used_bytes + $2, 0)"),
            "an absolute assignment erases every charge committed since the observation, which is \
             the window plans/M4-GOVERNANCE.md §5 names: {CORRECT_SQL}"
        );
    }

    /// One statement, therefore one snapshot. Two `SELECT`s would be two.
    #[test]
    fn the_observation_reads_both_numbers_in_one_statement() {
        assert_eq!(
            OBSERVE_SQL.matches("SELECT").count(),
            2,
            "the inner SUM is a subquery, not a \
             second statement: {OBSERVE_SQL}"
        );
        assert!(OBSERVE_SQL.contains("::BIGINT"), "SUM(bigint) is numeric and must be cast");
    }

    #[test]
    fn enforcement_round_trips_through_the_spelling_the_check_constraint_uses() {
        for mode in [Enforcement::Monitor, Enforcement::Warn, Enforcement::Block] {
            assert_eq!(Enforcement::from_sql(mode.as_sql()).expect("known mode"), mode);
        }
        assert!(Enforcement::from_sql("ENFORCE").is_err(), "an unknown mode must not default");
        assert!(Enforcement::from_sql("block").is_err(), "the vocabulary is upper case");
    }

    #[test]
    fn only_block_refuses() {
        assert!(!Enforcement::Monitor.refuses());
        assert!(!Enforcement::Warn.refuses());
        assert!(Enforcement::Block.refuses());
    }

    #[test]
    fn headroom_ignores_the_acknowledged_overshoot() {
        // The one-line change this guards against: `limit + overshoot - used`, which hands extra
        // room to exactly the tenants that are already over.
        let over = StorageQuota {
            limit_bytes: 100,
            used_bytes: 150,
            overshoot_bytes: 50,
            soft_limit_pct: 80,
            enforcement: Enforcement::Block,
        };
        assert_eq!(over.headroom_bytes(), 0);

        let under = StorageQuota { used_bytes: 40, overshoot_bytes: 0, ..over };
        assert_eq!(under.headroom_bytes(), 60);
    }

    #[test]
    fn the_soft_limit_is_a_percentage_of_the_limit_not_of_the_overshoot() {
        let quota = StorageQuota {
            limit_bytes: 1000,
            used_bytes: 799,
            overshoot_bytes: 0,
            soft_limit_pct: 80,
            enforcement: Enforcement::Block,
        };
        assert!(!quota.is_over_soft_limit());
        assert!(StorageQuota { used_bytes: 800, ..quota }.is_over_soft_limit());
    }

    #[test]
    fn drift_keeps_its_sign() {
        let under_counted = Observation { recorded_bytes: 10, measured_bytes: 25 };
        assert_eq!(under_counted.drift_bytes(), 15);
        assert!(!under_counted.agrees());

        let over_counted = Observation { recorded_bytes: 25, measured_bytes: 10 };
        assert_eq!(over_counted.drift_bytes(), -15);

        assert!(Observation { recorded_bytes: 7, measured_bytes: 7 }.agrees());
    }

    #[test]
    fn a_refusal_becomes_quota_exceeded_carrying_the_limit() {
        let refused = Refused {
            quota: StorageQuota {
                limit_bytes: 1024,
                used_bytes: 1024,
                overshoot_bytes: 0,
                soft_limit_pct: 80,
                enforcement: Enforcement::Block,
            },
            requested_bytes: 1,
        };
        let error: enclave_core::Error = refused.into();
        assert!(matches!(
            error,
            enclave_core::Error::QuotaExceeded {
                quota: enclave_core::QuotaKind::StorageBytes,
                limit: 1024
            }
        ));
        // A capacity quota, so `403` rather than `429`: waiting does not fix it.
        assert_eq!(error.status_code(), 403);
    }

    #[test]
    fn an_unmetered_tenant_is_admitted_rather_than_refused() {
        assert!(Charged::Unmetered.is_admitted());
        assert!(Charged::Unmetered.refused().is_none());
    }

    #[test]
    fn a_byte_count_beyond_bigint_is_refused_rather_than_clamped() {
        assert!(as_bigint(u64::MAX).is_err());
        assert_eq!(as_bigint(0).expect("zero fits"), 0);
        #[allow(clippy::cast_sign_loss)]
        let max = i64::MAX as u64;
        assert_eq!(as_bigint(max).expect("i64::MAX fits"), i64::MAX);
    }
}
