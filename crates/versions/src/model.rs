//! The version record, and the closed vocabularies its columns hold.
//!
//! Every enumeration here mirrors a `CHECK` constraint in
//! `migrations/0006_versions_and_uploads.sql` (`docs/04-DATA-MODEL.md §8`) — same members, same
//! spellings. A test at the bottom of this file asserts the sets against the constraint text, so a
//! migration that adds a status and a Rust enumeration that does not know it cannot both be green.
//!
//! # What a [`FileVersion`] deliberately does not decide
//!
//! Whether it may be *served*. That question has exactly one answer, [`FileVersion::is_readable`],
//! and its SQL twin [`READABLE_PREDICATE`]; every read path filters on the predicate rather than
//! reasoning about the fields (`plans/M1-CONTENT-CORE.md` D13, `CLAUDE.md` rule 9). Two spellings
//! of one rule is already one too many, which is why they sit next to each other here with a test
//! that keeps them in step.

use core::fmt;

use chrono::{DateTime, Utc};
use enclave_core::{FileId, TenantId, UnknownVariant, UserId, Uuid, VersionId};

/// Generates a closed vocabulary that mirrors a database `CHECK` constraint.
///
/// The same macro `crates/files/src/model.rs` uses, copied for the reason given there:
/// `enclave_core`'s equivalent is private to that crate. What matters is that `as_str` and
/// `from_str` come from one list, so a hand-written parser cannot fall a variant behind its writer.
macro_rules! db_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident { $( $(#[$vmeta:meta])* $variant:ident => $wire:literal ),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $( $(#[$vmeta])* $variant ),+
        }

        impl $name {
            /// The stored form, exactly as the `CHECK` constraint spells it.
            #[must_use]
            pub const fn as_str(&self) -> &'static str {
                match self { $( Self::$variant => $wire ),+ }
            }

            /// Every variant, so a test can assert the Rust set against the constraint's set
            /// rather than trusting that both were updated together.
            #[must_use]
            pub const fn all() -> &'static [Self] {
                &[ $( Self::$variant ),+ ]
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl core::str::FromStr for $name {
            type Err = UnknownVariant;

            fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
                match s {
                    $( $wire => Ok(Self::$variant), )+
                    other => Err(UnknownVariant::new(stringify!($name), other)),
                }
            }
        }
    };
}

db_enum! {
    /// Where a version sits in the pipeline of `docs/03-LLD.md §15` (`file_versions.status`).
    ///
    /// A state, not a flag (`plans/M1-CONTENT-CORE.md` D13). Nothing in this crate accepts a
    /// status from a caller: [`crate::VersionService::commit`] always writes
    /// [`VersionStatus::Scanning`], because a version that has just been committed has by
    /// definition not been scanned, and `CLAUDE.md` rule 9 does not have a fast path.
    pub enum VersionStatus {
        /// The row exists; its bytes do not yet.
        Pending => "PENDING",
        /// The bytes are staged and antivirus has not finished. No read path serves this.
        Scanning => "SCANNING",
        /// Scanned clean; text extraction, renditions and indexing are still running.
        Processing => "PROCESSING",
        /// Servable. The only status a read path accepts, and only together with an `av_status`
        /// [`READABLE_PREDICATE`] admits — [`AvStatus::Clean`], or [`AvStatus::Skipped`] when the
        /// tenant's `unsupported_policy` published content nothing inspected.
        Available => "AVAILABLE",
        /// Antivirus found something. The row stays so that its owner can be told why.
        Quarantined => "QUARANTINED",
        /// Processing failed terminally.
        Failed => "FAILED",
    }
}

db_enum! {
    /// The antivirus verdict (`file_versions.av_status`).
    ///
    /// Separate from [`VersionStatus`] rather than folded into it because a rescan can change the
    /// verdict of a version that is already `AVAILABLE`, and because "not scanned yet" and "scanned
    /// and clean" are different enough that collapsing them is how an unscanned file gets served.
    pub enum AvStatus {
        /// Not scanned yet.
        Pending => "PENDING",
        /// Scanned, nothing found.
        Clean => "CLEAN",
        /// Scanned, something found.
        Infected => "INFECTED",
        /// Deliberately not scanned — the engine is disabled for this deployment, or it could not
        /// open this container (`docs/08-BYO-INFRA.md`). Distinct from `CLEAN` and permanently so:
        /// nobody looked. It is kept distinct rather than collapsed *because* such a version can be
        /// served under `ALLOW_WITH_FLAG` — it is what the flag on the version is, what the
        /// signature-update sweep in `crates/worker` keys on to re-offer it, and what stops
        /// unscanned content becoming indistinguishable from scanned content forever after.
        Skipped => "SKIPPED",
        /// The scan itself failed. Also not `CLEAN`, for the same reason.
        Error => "ERROR",
    }
}

db_enum! {
    /// Where a version sits in a content-approval workflow (`file_versions.approval_state`).
    ///
    /// Nullable in the schema: libraries without approval leave it `NULL` rather than inventing a
    /// state, which is why this appears as `Option<ApprovalState>` on the record.
    pub enum ApprovalState {
        /// Visible only to its author.
        Draft => "DRAFT",
        /// Submitted, awaiting a decision.
        Pending => "PENDING",
        /// Approved for the library's readers.
        Approved => "APPROVED",
        /// Rejected.
        Rejected => "REJECTED",
    }
}

/// The `WHERE` fragment that decides whether a version may be served.
///
/// A macro because `concat!` takes only literals, and the point of having this at all is that the
/// content query splices *this text* rather than a retyped copy of it: "no read path serves
/// unscanned content" is then one definition away from being checked instead of one review away
/// from being forgotten. The column names are unqualified; every statement in this crate reads
/// `file_versions` unaliased. `#[macro_export]`ed so that a crate outside this one splices the
/// definition into its own `const` instead of retyping it — `crates/sync` did retype it, and only
/// a test comparing the two texts stood between that copy and silent drift (`ENC-828`).
///
/// # Why `SKIPPED` is admitted beside `CLEAN` (`ENC-828`, half of `ENC-646`)
///
/// `status` already carries the antivirus **policy decision**, and `av_status` carries the
/// **verdict**. Those are different questions and this predicate asks both, which is why it is two
/// conditions rather than one. `AVAILABLE` is written by exactly one statement in the workspace —
/// `crates/worker/src/antivirus.rs`'s `RECORD_SQL`, from `Target::of`, and only for
/// [`VersionDisposition::Publish`](enclave_antivirus::VersionDisposition::Publish). So the pair
/// `AVAILABLE`/`SKIPPED` cannot arise except from `docs/06-SECURITY-DLP-ACCESS.md §6.2`'s
/// `ALLOW_WITH_FLAG`, which an operator writes down: content nothing inspected, that the tenant
/// asked to have published anyway, and that is still refused at `CONFIDENTIAL` and above on rank
/// alone (`ScanPolicy::blocks_unsupported`). Refusing it *here* did not make the deployment safer;
/// it made `ALLOW_WITH_FLAG` a no-op with a misleading name, and made a deployment with no scanner
/// a write-only store — uploads succeeded and nothing could ever be read back.
///
/// What is **not** admitted, and the distinction is the whole of `CLAUDE.md` rule 9:
///
/// * `PENDING` — nobody has answered yet. `ALLOW_AND_RESCAN` publishes `AVAILABLE`/`PENDING`, and
///   that half of `ENC-646` stays refused: it is a version whose scan has not *completed*, which
///   is the clause rule 9 spells out.
/// * `ERROR` — the scan failed. Not a decision to publish unscanned content, a failure to make one.
/// * `INFECTED` — quarantined, and `status` says so too.
/// * Any `av_status` at all while `status` is `SCANNING`, `PROCESSING`, `QUARANTINED`, `PENDING`
///   or `FAILED`. "No read path serves `SCANNING` content" is unchanged and untouchable.
#[macro_export]
macro_rules! readable_predicate {
    () => {
        "status = 'AVAILABLE' AND av_status IN ('CLEAN', 'SKIPPED')"
    };
}

pub(crate) use readable_predicate;

/// The same fragment as a value — the SQL twin of [`FileVersion::is_readable`], exported so a
/// caller writing its own read path can splice the one definition rather than invent a second.
pub const READABLE_PREDICATE: &str = readable_predicate!();

/// The rule itself, over the two columns and nothing else.
///
/// [`FileVersion::is_readable`] is this function applied to a record, and every other caller in the
/// workspace that has a `(status, av_status)` pair in hand — `crates/worker`'s antivirus pass most
/// of all — asks *this* rather than restating `status == AVAILABLE && av == CLEAN`. The restatement
/// is what hid `ENC-828`: the pass's own test wrote the rule out a second time, so it agreed with
/// the predicate for as long as both were wrong together, and a cross-product sweep over it proved
/// nothing.
///
/// [`FileVersion`] is `#[non_exhaustive]`, so a crate outside this one cannot build a record to ask
/// with; that is the practical reason this is a free function and not only a method.
#[must_use]
pub const fn is_readable_pair(status: VersionStatus, av_status: AvStatus) -> bool {
    matches!(status, VersionStatus::Available)
        && matches!(av_status, AvStatus::Clean | AvStatus::Skipped)
}

/// A version number, as the pair `docs/04-DATA-MODEL.md §8` stores it.
///
/// One type rather than two loose `i32`s because the two are meaningless apart and trivially
/// transposable: `(major, minor)` and `(minor, major)` are the same call signature. Ordering is
/// derived and the field order is deliberate — `major` first, so `1.9 < 2.0` falls out of the
/// derive rather than out of a hand-written comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VersionNumber {
    /// Published version. Incremented by a major commit; the only number a library in `MAJOR`
    /// versioning mode ever shows.
    pub major: i32,
    /// Draft within a major version. Zero for a major commit.
    pub minor: i32,
}

impl VersionNumber {
    /// The number every file's first version carries, whichever bump was asked for.
    pub const FIRST: Self = Self { major: 1, minor: 0 };

    /// Builds a number.
    #[must_use]
    pub const fn new(major: i32, minor: i32) -> Self {
        Self { major, minor }
    }

    /// Whether this is a published version rather than a draft.
    #[must_use]
    pub const fn is_major(&self) -> bool {
        self.minor == 0
    }
}

impl fmt::Display for VersionNumber {
    /// Renders as `2.1`, which is the form `docs/05-API.md` puts on the wire and the form a user
    /// sees in the history panel.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// Which number the next version takes.
///
/// The choice belongs to the library's `versioning_mode` (`docs/04-DATA-MODEL.md §7`), which is
/// read by the handler, not here: this crate is handed the decision rather than making it, for the
/// same reason it makes no authorization decision (`plans/M1-CONTENT-CORE.md` D11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VersionBump {
    /// `n.0` — the next published version.
    Major,
    /// `n.m+1` — a draft against the current major.
    Minor,
}

impl VersionBump {
    /// Whether this bump increments the major number.
    ///
    /// Bound into the numbering statement as a single boolean, so that one SQL string serves both
    /// bumps. Two strings would be two query plans and two places for the numbering rule to drift.
    #[must_use]
    pub const fn is_major(&self) -> bool {
        matches!(self, Self::Major)
    }
}

/// The antivirus columns, kept together.
///
/// Grouped because they are only ever meaningful as a set — a verdict without an engine and a
/// signature version is not evidence of anything, and `docs/06-SECURITY-DLP-ACCESS.md` requires the
/// engine and signature version to be recorded alongside the verdict so an old clean result can be
/// re-judged when a signature database moves on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvScan {
    /// The verdict.
    pub status: AvStatus,
    /// Which engine produced it.
    pub engine: Option<String>,
    /// The signature database version it was produced against.
    pub signature_version: Option<String>,
    /// When.
    pub scanned_at: Option<DateTime<Utc>>,
}

impl AvScan {
    /// The state every freshly committed version starts in: nobody has looked yet.
    #[must_use]
    pub const fn unscanned() -> Self {
        Self { status: AvStatus::Pending, engine: None, signature_version: None, scanned_at: None }
    }
}

db_enum! {
    /// Where a version's bytes physically live, and therefore how long fetching them takes
    /// (`file_versions.storage_tier`, `migrations/0032`).
    ///
    /// **Orthogonal to [`VersionStatus`], and that separation is the design** (`ENC-946`).
    /// `VersionStatus` answers *"is this content processed and safe to serve"* — it is the column
    /// `CLAUDE.md` rule 9 is about. This answers *"how long will it take"*. A version that is
    /// clean, scanned, approved and cold is `AVAILABLE` **and** [`StorageTier::Archived`].
    ///
    /// Folding the two together would make an archived version indistinguishable from a
    /// quarantined one at every `status = 'AVAILABLE'` predicate in the workspace, so archiving
    /// content would silently make it look infected — and rule 9's column would start carrying a
    /// latency fact, leaving no way to tell which of its values are safety and which are speed.
    pub enum StorageTier {
        /// Immediately readable. Every version written before `migrations/0032`, and every new one.
        Hot => "HOT",
        /// A transition to cold storage has been requested and the provider has not confirmed it.
        ///
        /// Read paths refuse from here rather than from [`StorageTier::Archived`]: the provider may
        /// move the object at any point after accepting the request, and the window between *asked*
        /// and *confirmed* is exactly when a mint produces a URL that fails at the object store —
        /// outside this product, as an opaque error the caller cannot act on.
        Archiving => "ARCHIVING",
        /// Cold. The bytes exist and are not immediately retrievable.
        Archived => "ARCHIVED",
        /// A rehydration has been requested and the bytes are not back yet.
        ///
        /// A state to poll, never a request that blocks. The product is designed for **slow**
        /// rehydration — S3 Glacier Deep Archive is measured in hours — because a design that
        /// assumes minutes breaks on the slow provider, and one that assumes hours degrades to
        /// minutes without changing shape.
        Restoring => "RESTORING",
    }
}

impl StorageTier {
    /// Whether bytes at this tier can be fetched now.
    ///
    /// Only [`StorageTier::Hot`]. An exhaustive match with no `_` arm, so a fifth tier has to be
    /// classified rather than silently joining the readable side — the direction of that mistake is
    /// a signed URL minted for bytes that are not there.
    #[must_use]
    pub const fn is_immediately_readable(self) -> bool {
        match self {
            Self::Hot => true,
            Self::Archiving | Self::Archived | Self::Restoring => false,
        }
    }
}

/// One row of `file_versions`.
///
/// Immutable in the database once [`VersionStatus::Available`], for the five columns that make up
/// its content identity — `object_key`, `checksum_sha256`, `size_bytes`, `major`, `minor`. That is
/// enforced by a trigger rather than by this type, because a Rust type can only bind the code that
/// goes through it (`plans/M1-CONTENT-CORE.md` D12).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileVersion {
    /// The version's identifier. UUIDv7, so it is also its creation order.
    pub id: VersionId,
    /// The owning tenant, carried on the record as well as in every query predicate.
    pub tenant_id: TenantId,
    /// The file this is a version of.
    pub file_id: FileId,
    /// The object-store key holding the bytes.
    ///
    /// Globally unique by `uq_version_object`, not merely unique per tenant: two rows naming one
    /// object is the way a purge for one tenant deletes another tenant's bytes.
    pub object_key: String,
    /// Which storage profile the object lives in.
    ///
    /// A bare [`Uuid`] because `enclave_core::id` has no `StorageProfileId` newtype yet and
    /// inventing one here would put a second, incompatible type in the workspace the day the
    /// storage crate defines the real one. `crates/libraries` and `crates/workspaces` carry the
    /// same column the same way, for the same reason; see the crate documentation for the note
    /// handed to the integrator.
    pub storage_profile_id: Uuid,
    /// Size of the object in bytes. Frozen once `AVAILABLE`.
    pub size_bytes: i64,
    /// Lowercase hex SHA-256 of the content. Frozen once `AVAILABLE` — a checksum that can be
    /// rewritten afterwards is not evidence of anything.
    pub checksum_sha256: String,
    /// The media type recorded at commit.
    pub mime_type: String,
    /// Where this sits in the file's history.
    pub number: VersionNumber,
    /// Pipeline state.
    pub status: VersionStatus,
    /// Antivirus verdict and its provenance.
    pub av: AvScan,
    /// Content-approval state, or `None` in a library without approval.
    pub approval_state: Option<ApprovalState>,
    /// How the object is encrypted. Free text rather than an enumeration because the column has no
    /// `CHECK` constraint to mirror — the vocabulary belongs to `docs/08-BYO-INFRA.md §7`, and
    /// mirroring a constraint that does not exist would be inventing one here.
    pub encryption_mode: String,
    /// A **reference** to the key, never a key: `vault://…` or `env://…` (`CLAUDE.md` rule 11).
    pub encryption_key_ref: Option<String>,
    /// Who committed it.
    pub created_by: UserId,
    /// When.
    pub created_at: DateTime<Utc>,
    /// The check-in comment, as the user typed it.
    pub comment: Option<String>,
    /// Where the bytes live, and therefore how fast they can be fetched (`ENC-946`).
    pub storage_tier: StorageTier,
    /// When rehydration was last requested, kept after it completes.
    ///
    /// Not cleared on success: how long the last restore took is the only evidence a deployment has
    /// that its archive tier is behaving, and clearing it destroys that evidence at the moment it
    /// becomes useful.
    pub restore_requested_at: Option<DateTime<Utc>>,
}

impl FileVersion {
    /// Whether this version may be served to a caller who is otherwise authorized.
    ///
    /// The Rust twin of [`READABLE_PREDICATE`], and the only place this crate answers the question.
    /// Both conditions are load-bearing: `AVAILABLE` alone would serve a row whose rescan came back
    /// `INFECTED` before the status was moved, and an `av_status` alone would serve one that is
    /// still having its renditions built.
    ///
    /// The `SKIPPED` arm is the one an editor is most likely to read as a mistake. It is not — see
    /// [`READABLE_PREDICATE`]'s documentation for why `status` carrying the policy decision is what
    /// makes it sound, and why `PENDING` and `ERROR` are *not* here beside it. The two spellings
    /// are asserted to accept the same rows over the whole `VersionStatus` × `AvStatus`
    /// cross-product, in this file against a literal table and in `crates/versions/tests` against a
    /// real PostgreSQL query using the spliced predicate.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        is_readable_pair(self.status, self.av.status)
    }

    /// The default encryption mode, matching the column's `DEFAULT 'PROVIDER'`.
    pub const DEFAULT_ENCRYPTION_MODE: &'static str = "PROVIDER";
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use core::str::FromStr as _;

    /// The migration this crate's vocabularies mirror, read at compile time.
    ///
    /// Reading the file rather than restating its `CHECK` lists is the whole point: a restated list
    /// is a second copy that can drift, and this test exists to catch drift.
    const MIGRATION: &str = include_str!("../../../migrations/0006_versions_and_uploads.sql");

    #[test]
    fn every_status_the_check_constraint_allows_has_a_rust_variant() {
        for status in VersionStatus::all() {
            assert!(
                MIGRATION.contains(&format!("'{}'", status.as_str())),
                "{status} is not in the migration"
            );
        }
        // And the other direction: the constraint's list, taken from the migration text.
        let line = MIGRATION
            .lines()
            .find(|l| l.contains("status") && l.contains("CHECK (status IN"))
            .expect("the status CHECK constraint");
        for spelling in line.split('\'').skip(1).step_by(2) {
            assert!(
                VersionStatus::from_str(spelling).is_ok(),
                "the migration allows `{spelling}` and VersionStatus does not"
            );
        }
    }

    /// `migrations/0032` adds the tier vocabulary; this is the same drift check for it.
    const TIER_MIGRATION: &str = include_str!("../../../migrations/0032_storage_tier.sql");

    #[test]
    fn every_storage_tier_the_check_constraint_allows_has_a_rust_variant() {
        for tier in StorageTier::all() {
            assert!(
                TIER_MIGRATION.contains(&format!("'{}'", tier.as_str())),
                "{tier} is not in migrations/0032"
            );
        }
        let line = TIER_MIGRATION
            .lines()
            .find(|l| l.contains("CHECK (storage_tier IN"))
            .expect("the storage_tier CHECK constraint");
        for spelling in line.split('\'').skip(1).step_by(2) {
            assert!(
                StorageTier::from_str(spelling).is_ok(),
                "the migration allows `{spelling}` and StorageTier does not; a tier the decoder \
                 cannot read refuses the row, so a version stored with it becomes unreadable"
            );
        }
    }

    /// Exactly one tier is immediately readable, and it is `HOT`.
    ///
    /// The assertion is on the **count** as well as the value, and that is the point. Checking only
    /// that `Hot` is readable passes against an implementation where every tier is; checking only
    /// that `Archived` is not passes against one where none is. A fifth tier added without thought
    /// fails this, which is what the exhaustive match in `is_immediately_readable` is for — the
    /// direction of that mistake is a signed URL minted for bytes that are in Glacier.
    #[test]
    fn exactly_one_tier_can_be_read_without_asking_for_it_back() {
        let readable: Vec<_> =
            StorageTier::all().iter().filter(|t| t.is_immediately_readable()).collect();
        assert_eq!(
            readable,
            vec![&StorageTier::Hot],
            "the set of immediately-readable tiers must be exactly [HOT]; it is {readable:?}"
        );
    }

    #[test]
    fn every_av_status_the_check_constraint_allows_has_a_rust_variant() {
        let line = MIGRATION
            .lines()
            .find(|l| l.contains("CHECK (av_status IN"))
            .expect("the av_status CHECK constraint");
        for spelling in line.split('\'').skip(1).step_by(2) {
            // The `DEFAULT 'PENDING'` on the same line is also a member, so this is safe.
            assert!(
                AvStatus::from_str(spelling).is_ok(),
                "the migration allows `{spelling}` and AvStatus does not"
            );
        }
        assert_eq!(AvStatus::all().len(), 5);
    }

    #[test]
    fn every_approval_state_the_check_constraint_allows_has_a_rust_variant() {
        let line = MIGRATION
            .lines()
            .find(|l| l.contains("CHECK (approval_state IN"))
            .expect("the approval_state CHECK constraint");
        for spelling in line.split('\'').skip(1).step_by(2) {
            assert!(
                ApprovalState::from_str(spelling).is_ok(),
                "the migration allows `{spelling}` and ApprovalState does not"
            );
        }
    }

    /// The Rust half of the twin, over the whole cross-product, against a table written out.
    ///
    /// The SQL half is `crates/versions/tests/versions.rs::the_two_spellings_of_readable_agree_
    /// against_a_real_database`, which runs the spliced predicate over the same thirty rows in
    /// PostgreSQL. Two hand-picked cases are what let `ENC-828` survive: `AVAILABLE`/`SKIPPED` is
    /// exactly the pair neither half happened to name.
    #[test]
    fn the_two_spellings_of_readable_agree() {
        assert!(READABLE_PREDICATE.contains(VersionStatus::Available.as_str()));
        assert!(READABLE_PREDICATE.contains(AvStatus::Clean.as_str()));
        assert!(READABLE_PREDICATE.contains(AvStatus::Skipped.as_str()));
        // And not by admitting the vocabulary wholesale: the three that must stay out, stay out.
        for refused in [AvStatus::Pending, AvStatus::Infected, AvStatus::Error] {
            assert!(
                !READABLE_PREDICATE.contains(refused.as_str()),
                "{refused} reached the predicate; rule 9's `SCANNING` clause is next"
            );
        }

        let base = FileVersion {
            id: VersionId::new_v7(),
            tenant_id: TenantId::new_v7(),
            file_id: FileId::new_v7(),
            object_key: "k".to_owned(),
            storage_profile_id: Uuid::now_v7(),
            size_bytes: 1,
            checksum_sha256: "abc".to_owned(),
            mime_type: "application/pdf".to_owned(),
            number: VersionNumber::FIRST,
            status: VersionStatus::Available,
            av: AvScan { status: AvStatus::Clean, ..AvScan::unscanned() },
            approval_state: None,
            encryption_mode: FileVersion::DEFAULT_ENCRYPTION_MODE.to_owned(),
            encryption_key_ref: None,
            created_by: UserId::new_v7(),
            created_at: Utc::now(),
            comment: None,
            storage_tier: StorageTier::Hot,
            restore_requested_at: None,
        };
        assert!(base.is_readable());

        // Neither half is sufficient on its own, and the expectation is written out as a literal
        // table rather than recomputed from the same `matches!` the function uses — a test that
        // re-derives the answer agrees with any implementation, including the wrong one.
        for status in VersionStatus::all() {
            for av in AvStatus::all() {
                let candidate = FileVersion {
                    status: *status,
                    av: AvScan { status: *av, ..AvScan::unscanned() },
                    ..base.clone()
                };
                let expected = matches!(
                    (status, av),
                    (VersionStatus::Available, AvStatus::Clean)
                        | (VersionStatus::Available, AvStatus::Skipped)
                );
                assert_eq!(candidate.is_readable(), expected, "{status}/{av}");
            }
        }
    }

    /// `CLAUDE.md` rule 9, stated as the property rather than as a list, so that a future member
    /// added to either vocabulary has to be placed deliberately.
    ///
    /// The first clause — *nothing is `AVAILABLE` before antivirus completes* — is held by
    /// `crates/worker`, which is the only writer of `AVAILABLE`. The clause this file can hold is
    /// the second: **no read path serves `SCANNING` content**, for any antivirus verdict whatever.
    #[test]
    fn no_scanning_version_is_readable_whatever_its_verdict() {
        let base_status = VersionStatus::Scanning;
        for av in AvStatus::all() {
            let version = FileVersion {
                id: VersionId::new_v7(),
                tenant_id: TenantId::new_v7(),
                file_id: FileId::new_v7(),
                object_key: "k".to_owned(),
                storage_profile_id: Uuid::now_v7(),
                size_bytes: 1,
                checksum_sha256: "abc".to_owned(),
                mime_type: "application/pdf".to_owned(),
                number: VersionNumber::FIRST,
                status: base_status,
                av: AvScan { status: *av, ..AvScan::unscanned() },
                approval_state: None,
                encryption_mode: FileVersion::DEFAULT_ENCRYPTION_MODE.to_owned(),
                encryption_key_ref: None,
                created_by: UserId::new_v7(),
                created_at: Utc::now(),
                comment: None,
                storage_tier: StorageTier::Hot,
                restore_requested_at: None,
            };
            assert!(!version.is_readable(), "SCANNING/{av} was served");
        }
        // The positive control, without which the assertion above holds of a function that answers
        // `false` for everything — which is what `READABLE_PREDICATE` did for `ENC-641`'s four
        // milestones, correctly and invisibly.
        let served = FileVersion {
            id: VersionId::new_v7(),
            tenant_id: TenantId::new_v7(),
            file_id: FileId::new_v7(),
            object_key: "k".to_owned(),
            storage_profile_id: Uuid::now_v7(),
            size_bytes: 1,
            checksum_sha256: "abc".to_owned(),
            mime_type: "application/pdf".to_owned(),
            number: VersionNumber::FIRST,
            status: VersionStatus::Available,
            av: AvScan { status: AvStatus::Skipped, ..AvScan::unscanned() },
            approval_state: None,
            encryption_mode: FileVersion::DEFAULT_ENCRYPTION_MODE.to_owned(),
            encryption_key_ref: None,
            created_by: UserId::new_v7(),
            created_at: Utc::now(),
            comment: None,
            storage_tier: StorageTier::Hot,
            restore_requested_at: None,
        };
        assert!(served.is_readable(), "ALLOW_WITH_FLAG buys no availability at all — ENC-828");
    }

    #[test]
    fn a_freshly_committed_version_is_never_readable() {
        // `CLAUDE.md` rule 9 as a property of the constructors rather than of remembering.
        assert_eq!(AvScan::unscanned().status, AvStatus::Pending);
        assert_ne!(AvScan::unscanned().status, AvStatus::Clean);
    }

    #[test]
    fn version_numbers_order_by_major_first() {
        assert!(VersionNumber::new(1, 9) < VersionNumber::new(2, 0));
        assert!(VersionNumber::new(2, 0) < VersionNumber::new(2, 1));
        assert_eq!(VersionNumber::FIRST.to_string(), "1.0");
        assert!(VersionNumber::FIRST.is_major());
        assert!(!VersionNumber::new(1, 1).is_major());
    }

    #[test]
    fn a_bump_is_a_single_boolean_on_the_wire_to_sql() {
        assert!(VersionBump::Major.is_major());
        assert!(!VersionBump::Minor.is_major());
    }
}
