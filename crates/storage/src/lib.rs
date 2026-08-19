//! `enclave-storage` — object storage for versions and renditions.
//!
//! Infrastructure provider — the [`BlobStore`] trait plus its implementations, and no domain
//! logic. See `docs/02-HLD.md §4` for where this crate sits in the architecture.
//!
//! # What this crate is
//!
//! * [`BlobStore`] — the seven-member trait from `docs/08-BYO-INFRA.md §2`, verbatim.
//! * [`PublicAccessCheck`] — the startup self-check `§3` requires, as a **supertrait** of
//!   `BlobStore` so no provider can omit it and it stays reachable through `&dyn BlobStore`.
//! * [`ObjectKey`] — the canonical key layout of `docs/02-HLD.md §7`, built and parsed in one
//!   place so it cannot drift per call site.
//! * [`S3BlobStore`] — one implementation covering AWS S3, MinIO, Ceph, R2, Wasabi and B2.
//!
//! # What this crate is not
//!
//! **It makes no authorization decision, and it does not know what a file is.** It does not read
//! the database, it has no `list` operation, and it never decides whether a caller may have an
//! object's bytes — the policy chain does that in the handler, before a service is reached
//! (`plans/M1-CONTENT-CORE.md` D11). What this crate does own is the guarantee that a key is
//! canonical and carries a visible tenant, and the guarantee that the bucket is not readable by
//! the world.
//!
//! # The three properties worth knowing before using it
//!
//! 1. **Startup refuses a public bucket.** [`S3BlobStore::connect_and_verify`] runs
//!    [`PublicAccessCheck::verify_not_public`] and will not return a store that failed it. Read
//!    [`public_access`] for why an inconclusive result is also a failure.
//! 2. **Signed URLs are not single-use, and the store says so.** No S3-compatible backend can
//!    invalidate a pre-signed URL before it expires, so
//!    [`StoreCapabilities::single_use_signed_urls`] is `false` and the compensating control is
//!    `plans/M1-CONTENT-CORE.md` D14 — one URL per authorized request, minted at the last moment,
//!    never cached, short TTL. A TTL above the configured ceiling is refused rather than clamped.
//! 3. **Credentials are references.** [`S3Config`] holds
//!    [`SecretRef`](enclave_config::SecretRef)s, and `aws-config` is deliberately not a dependency,
//!    so this process has no ambient AWS identity to fall back on if a reference fails to resolve
//!    (`CLAUDE.md` rule 11).
//!
//! # Dependencies pinned here rather than in the workspace
//!
//! `aws-sdk-s3`, `aws-smithy-http-client`, `aws-smithy-runtime-api`, `aws-smithy-types` and
//! `bytes` are pinned in this crate's `Cargo.toml`; none is in `[workspace.dependencies]`. They
//! belong in the workspace table as soon as a second crate needs them — `preview`'s
//! `RenditionStore` is the expected one — so that two crates cannot end up on different versions
//! of the same client.

pub mod blob_store;
pub mod error;
pub mod key;
pub mod model;
pub mod public_access;
pub mod s3;
mod unconfigured;

pub use blob_store::BlobStore;
pub use error::{Result, StorageError};
pub use key::{KeyError, ObjectKey};
pub use model::{
    ByteRange, ByteStream, CompletedPart, MultipartLimits, ObjectMeta, PartTarget,
    StoreCapabilities, Support, UploadRequest, UploadSession, UploadTarget,
};
pub use public_access::{
    Probe, ProbeResult, PublicAccessCheck, PublicAccessError, PublicAccessReport, Verdict,
};
pub use s3::{S3BlobStore, S3Config, S3Flavor};
pub use unconfigured::UnconfiguredBlobStore;
