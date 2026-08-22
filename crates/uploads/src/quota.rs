//! The reserve-time storage-quota preflight — **advisory by construction**.
//!
//! # What this is for
//!
//! `docs/05-API.md §8`: *"`POST /uploads` runs the full policy chain before issuing URLs, including
//! quota and file-type checks, so a rejected upload never consumes bandwidth."*
//! `docs/10-SYNC-AND-EDITING.md §5` says the same from the device's side: *"Quota is checked at
//! `reserve`, so a device does not upload gigabytes to be rejected at commit."*
//!
//! Both are statements about **bandwidth**, not about capacity. Neither asks the quota to be
//! decided here, and it is not.
//!
//! # Why it cannot be the enforcement, and why the type says so
//!
//! The enforcement is one statement — `enclave_db::charge_storage`, run inside the transaction that
//! inserts the `file_versions` row, with the limit in its `WHERE` clause and a zero-row result as
//! the refusal (`plans/M4-GOVERNANCE.md` D31). A check here followed by a write there is precisely
//! the check-then-write D31 exists to forbid: ten sessions created together all read the same
//! figure, all conclude there is room, and the tenant ends up over its limit with nothing in the
//! code looking wrong.
//!
//! So [`Preflight`] has **no admitting variant**. The best answer it can give is
//! [`Preflight::NotRefused`], and "this upload was admitted by the quota" is not a value that can
//! be constructed from this module — the same technique `enclave_db::Released` uses to make "this
//! delete was refused for quota" unrepresentable.
//!
//! # When the bytes become chargeable, and what that leaves open
//!
//! **At version commit, not at reservation and not at upload completion.** `ENC-584`'s nightly
//! reconciliation defines truth as `SUM(file_versions.size_bytes) WHERE status <> 'FAILED'`, so a
//! charge raised against a staged object — one with no version row — is drift by that definition,
//! and the first reconciliation pass would subtract it. A reservation would also need a release on
//! every expiry, abort and crash, and `storage_quotas` has one counter and no reservation column:
//! the release that was missed would look exactly like a tenant that had stored the bytes.
//!
//! What that leaves open is stated rather than hidden: a tenant can open many sessions at once and
//! only be refused when each one commits. Three things bound it, and none of them is this
//! function — `UploadLimits`' per-file ceiling, the session TTL with `crate::reaper`, and the fact
//! that staged bytes cost nothing permanent because nothing publishes them. The bytes a tenant
//! *keeps* are refused at the one statement that can refuse.

use enclave_db::{storage_quota, TenantScoped};

use crate::error::Result;

/// What a preflight concluded. **There is no `Admitted` variant, and that absence is the design.**
///
/// See the module header: an admitting preflight would be half of a check-then-write, and the
/// charge at commit is the only thing entitled to say yes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a refused preflight must fail the upload before any URL is issued"]
pub enum Preflight {
    /// Nothing in the quota refuses this upload **at this instant**.
    ///
    /// Not a reservation, not a promise, and not a defence against a concurrent session taking the
    /// same headroom. Two uploads that each fit can both reach here and only one commit.
    NotRefused,
    /// The declared size does not fit in the headroom the tenant has left.
    Refused {
        /// The configured limit, which is what a client can act on.
        limit_bytes: i64,
    },
    /// The tenant has no quota row, so nothing is metered and nothing is refused.
    Unmetered,
}

/// Reads the tenant's quota and refuses an upload that already cannot fit.
///
/// A `SELECT` and nothing else: it moves no counter, takes no lock and reserves no capacity. Only
/// `BLOCK` can produce a [`Preflight::Refused`] — `MONITOR` and `WARN` promise not to refuse
/// (`plans/M4-GOVERNANCE.md §2`), and a preflight that refused under them would turn the gradual
/// rollout into an abrupt one at exactly the surface users see first.
///
/// Headroom is `limit_bytes - used_bytes`, never `+ overshoot_bytes`: an acknowledged overshoot is
/// a record of an over-limit state, not an allowance, and adding it here would hand extra room to
/// precisely the tenants that are already over.
///
/// # Errors
///
/// Database failures. A tenant with no quota row is [`Preflight::Unmetered`], not an error.
pub async fn preflight(tx: &mut TenantScoped, declared_size: u64) -> Result<Preflight> {
    let Some(quota) = storage_quota(tx).await? else {
        return Ok(Preflight::Unmetered);
    };

    if !quota.enforcement.refuses() {
        return Ok(Preflight::NotRefused);
    }

    // Saturating rather than erroring: a declared size beyond `i64` cannot fit any limit, and
    // `i64::MAX` compares the same way the real figure would. The charge at commit does error on
    // it, because there it is a number about to be written.
    let declared = i64::try_from(declared_size).unwrap_or(i64::MAX);
    if declared > quota.headroom_bytes() {
        return Ok(Preflight::Refused { limit_bytes: quota.limit_bytes });
    }
    Ok(Preflight::NotRefused)
}

// There are no unit tests here on purpose. Every claim this module makes is either a property of
// the type — which the compiler checks and a test would only restate — or a statement about what a
// live quota row does, which needs a database. Both live in `tests/sessions.rs`, including the one
// that makes the design visible: two sessions that each fit the same headroom are *both* issued,
// because a pass here is not a reservation. `docs/12 §1.2` — a test that cannot fail is a claim.
