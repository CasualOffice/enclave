//! The S3-compatible provider.
//!
//! `docs/08-BYO-INFRA.md §3` lists generic S3, AWS S3, MinIO, Ceph, Cloudflare R2, Wasabi and
//! Backblaze B2 as initial providers. They are one implementation here, because they are one
//! protocol; the differences that matter are the endpoint, the addressing style and which
//! administrative APIs exist, and those are [`S3Config`] fields rather than separate code paths.

mod anonymous;
mod config;
mod self_check;
mod store;

pub use config::{S3Config, S3Flavor};
pub use store::S3BlobStore;
