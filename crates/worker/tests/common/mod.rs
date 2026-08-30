//! The fixtures the content passes' tests share: PDFs assembled byte by byte, a blob store that
//! records what was read, and a file with one version in a chosen antivirus state.
//!
//! The PDFs are assembled rather than committed, for the reason `crates/indexing/tests/pdf.rs`
//! gives about its own builders: a binary fixture is content nobody reviews in a diff, and one
//! whose expected text is a claim about a file rather than something the test constructed.
//!
//! Shared rather than copied because a fixture builder duplicated across two files is two things to
//! keep in step, and the day they disagree the test that is wrong is the one nobody re-read. The
//! store and the version fixture moved here with `ENC-613`, when the scan pass became the third
//! binary that needed both.

// Each test binary includes the whole module and uses part of it.
#![allow(dead_code)]

use std::sync::Mutex;

use async_trait::async_trait;
use chrono::Utc;
use core::time::Duration;
use enclave_core::{FileId, TenantId, UserId, VersionId};
use enclave_storage::{
    BlobStore, ByteRange, ByteStream, MultipartLimits, ObjectMeta, PublicAccessCheck,
    PublicAccessError, PublicAccessReport, Result as StorageResult, StoreCapabilities, Support,
    UploadRequest, UploadSession,
};
use enclave_testing::content::Spine;
use sqlx::PgConnection;
use url::Url;
use uuid::Uuid;

/// One US-Letter page whose content stream is `content`, with Helvetica available as `/F1`.
///
/// The cross-reference table is written properly, with real byte offsets. PDFium would rebuild a
/// broken one, which is precisely why it is not left broken — a test whose input only works because
/// the parser repaired it is a test of the repair.
pub(crate) fn one_page_pdf(content: &str) -> Vec<u8> {
    let objects = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R \
         >> >> /Contents 4 0 R >>"
            .to_owned(),
        format!("<< /Length {} >>\nstream\n{content}\nendstream", content.len()),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_owned(),
    ];

    let mut pdf = Vec::from(&b"%PDF-1.4\n"[..]);
    let mut offsets = Vec::new();
    for (index, body) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", index + 1).as_bytes());
    }

    let startxref = pdf.len();
    pdf.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    for offset in &offsets {
        pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{startxref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    pdf
}

/// A page carrying two very large words, so what OCR reads is not a question about font sizes.
pub(crate) fn page_of_words() -> Vec<u8> {
    one_page_pdf("BT /F1 96 Tf 60 560 Td (INVOICE) Tj 0 -160 Td (TOTAL) Tj ET")
}

/// A page with nothing drawn on it.
pub(crate) fn blank_page() -> Vec<u8> {
    one_page_pdf("")
}

/// Records every key it is asked to read, and serves the same bytes for all of them.
///
/// The recording is the point: "the scanning version's bytes were never fetched" is only checkable
/// from the store's side, and it is the assertion `CLAUDE.md` rule 9 needs on both content passes.
#[derive(Default)]
pub(crate) struct RecordingStore {
    body: Vec<u8>,
    reads: Mutex<Vec<String>>,
}

impl RecordingStore {
    pub(crate) fn new(body: &str) -> Self {
        Self { body: body.as_bytes().to_vec(), reads: Mutex::new(Vec::new()) }
    }

    /// The same store over bytes that are not text — a PDF, for the OCR tests.
    pub(crate) fn of_bytes(body: Vec<u8>) -> Self {
        Self { body, reads: Mutex::new(Vec::new()) }
    }

    pub(crate) fn reads(&self) -> Vec<String> {
        self.reads.lock().expect("the lock is not poisoned").clone()
    }
}

#[async_trait]
impl PublicAccessCheck for RecordingStore {
    async fn verify_not_public(
        &self,
    ) -> core::result::Result<PublicAccessReport, PublicAccessError> {
        Ok(PublicAccessReport { bucket: "test".to_owned(), endpoint: None, probes: Vec::new() })
    }
}

#[async_trait]
impl BlobStore for RecordingStore {
    fn capabilities(&self) -> StoreCapabilities {
        StoreCapabilities {
            // No cold tier: this double serves from memory (`ENC-946`).
            storage_tiers: Support::No,
            backend: "recording-stub",
            multipart: Some(MultipartLimits {
                min_part_bytes: 5 * 1024 * 1024,
                max_part_bytes: 5 * 1024 * 1024 * 1024,
                max_parts: 10_000,
            }),
            signed_urls: true,
            single_use_signed_urls: false,
            max_signed_url_ttl: Duration::from_secs(900),
            versioning: Support::Unknown,
            object_lock: Support::Unknown,
            server_side_encryption: Support::Unknown,
            range_reads: true,
            server_side_copy: true,
        }
    }

    async fn create_upload(&self, _request: UploadRequest) -> StorageResult<UploadSession> {
        unreachable!("a content pass never uploads")
    }

    async fn complete_upload(&self, _session: &UploadSession) -> StorageResult<ObjectMeta> {
        unreachable!("a content pass never uploads")
    }

    async fn signed_download(&self, _key: &str, _ttl: Duration) -> StorageResult<Url> {
        // Not merely unimplemented: a signed URL for an *original* has no business being minted on
        // an indexing or scanning path, and a panic here would name that if one ever appeared.
        unreachable!("a content pass never mints a download URL")
    }

    async fn read_range(&self, key: &str, _range: ByteRange) -> StorageResult<ByteStream> {
        self.reads.lock().expect("the lock is not poisoned").push(key.to_owned());
        let body = self.body.clone();
        let length = body.len() as u64;
        Ok(ByteStream::new(
            futures::stream::once(async move { Ok(bytes::Bytes::from(body)) }),
            Some(length),
        ))
    }

    async fn copy(&self, _from: &str, _to: &str) -> StorageResult<()> {
        unreachable!("a content pass never copies")
    }

    async fn delete(&self, _key: &str) -> StorageResult<()> {
        unreachable!("a content pass never deletes")
    }
}

/// A file with one version, in the given antivirus state and of the given media type.
pub(crate) async fn a_file(
    conn: &mut PgConnection,
    tenant: TenantId,
    owner: UserId,
    status: &str,
    av_status: &str,
    mime_type: &str,
) -> (FileId, VersionId) {
    let (spine, version) =
        a_file_on_a_spine(conn, tenant, owner, status, av_status, mime_type).await;
    (spine.file, version)
}

/// The same file, with the spine it hangs on.
///
/// The vector tests need the workspace and library as well, because those are columns of the store
/// record and a record naming the wrong library is one the query-time narrowing silently excludes.
pub(crate) async fn a_file_on_a_spine(
    conn: &mut PgConnection,
    tenant: TenantId,
    owner: UserId,
    status: &str,
    av_status: &str,
    mime_type: &str,
) -> (Spine, VersionId) {
    let spine = Spine::new(tenant);
    spine.insert(&mut *conn, owner, Utc::now()).await.expect("spine");
    let version = a_version(conn, tenant, &spine, owner, status, av_status, mime_type).await;
    (spine, version)
}

/// One more version of a file that already exists.
///
/// Separate from [`a_file_on_a_spine`] because facts are per **version**: a test that needs two
/// versions of one file is asserting exactly that, and it cannot do so with a helper that creates a
/// file each time.
pub(crate) async fn a_version(
    conn: &mut PgConnection,
    tenant: TenantId,
    spine: &Spine,
    owner: UserId,
    status: &str,
    av_status: &str,
    mime_type: &str,
) -> VersionId {
    let id = Uuid::now_v7();
    // The version number is derived rather than fixed, so a test can write a *second* version of
    // one file — which is the only way to assert that facts are per version and not per file.
    // `uq_version_number` is what catches a helper that hard-codes `1.0`, and it did.
    sqlx::query(
        "INSERT INTO file_versions
           (id, tenant_id, file_id, object_key, storage_profile_id, size_bytes, checksum_sha256,
            mime_type, major, minor, status, av_status, created_by, created_at)
         VALUES ($1, $2, $3, $4, $5, 12, 'deadbeef', $6, 1,
                 COALESCE((SELECT max(v.minor) + 1 FROM file_versions v
                            WHERE v.tenant_id = $2 AND v.file_id = $3 AND v.major = 1), 0),
                 $7, $8, $9, $10)",
    )
    .bind(id)
    .bind(tenant.as_uuid())
    .bind(spine.file.as_uuid())
    .bind(format!("objects/{id}"))
    .bind(Uuid::nil())
    .bind(mime_type)
    .bind(status)
    .bind(av_status)
    .bind(owner.as_uuid())
    .bind(Utc::now())
    .execute(&mut *conn)
    .await
    .expect("version");

    VersionId::from(id)
}
