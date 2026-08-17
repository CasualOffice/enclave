//! Ed25519 signing keys and the provider abstraction around them (`docs/03-LLD.md §5.5`, D5).
//!
//! # Why a trait from day one
//!
//! There is exactly one interesting question about signing keys: where does the private half live?
//! In production it lives in Vault or a KMS and never enters this process's address space in
//! plaintext for longer than a signature takes. In development it has to live somewhere a
//! contributor can get it working in a minute. Those are different implementations of one contract,
//! and the contract has to exist before the first one is written — retrofitting it means the
//! development shape leaks into the production one.
//!
//! [`LocalFileKeyProvider`] therefore generates its keys on first use rather than reading committed
//! ones. Design decision D5 puts it bluntly: throwaway keys get copied into production more often
//! than anyone admits, so there must be no key in the repository to copy.
//!
//! # The overlap window
//!
//! Rotation is overlapping, not atomic. A new key is published in [`KeyStatus::Pending`], starts
//! signing at `activates_at`, and the key it replaced stays verifiable in [`KeyStatus::Retiring`]
//! until `retires_at` — one full access-plus-refresh lifetime later. [`KeySet::verification_key`]
//! is where that window is enforced, and enforcing it is test K2.

use core::fmt;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::KeyProviderError;

/// Length of an Ed25519 public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Where a signing key is in its lifecycle. The strings match the `signing_keys.status` `CHECK`
/// constraint in `docs/04-DATA-MODEL.md §6`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyStatus {
    /// Published in JWKS but not yet signing. This state is the propagation delay: clients cache
    /// JWKS, so a key that starts signing the instant it is created signs tokens that some clients
    /// cannot yet verify.
    Pending,
    /// Currently signing.
    Active,
    /// No longer signing; still verifying, until `retires_at`.
    Retiring,
    /// Past its window. Neither signs nor verifies, and is not published.
    Retired,
}

impl KeyStatus {
    /// Whether a key in this state may still verify a signature.
    ///
    /// [`KeyStatus::Pending`] counts. During the propagation delay two nodes can disagree by
    /// seconds about whether a key has activated, and refusing to verify a token a peer just
    /// signed would turn a rotation into an outage. What must *not* count is
    /// [`KeyStatus::Retired`] — that is the whole point of retiring a key, and it is test K2.
    #[must_use]
    pub const fn verifies(self) -> bool {
        matches!(self, Self::Pending | Self::Active | Self::Retiring)
    }

    /// Whether a key in this state is published at `/.well-known/jwks.json`.
    #[must_use]
    pub const fn published(self) -> bool {
        self.verifies()
    }
}

/// A signing key's identifier — the `kid` header and JWKS field.
///
/// Derived from the public key rather than assigned, so that the same key has the same identifier
/// in the database, in a JWKS document and on disk, with nothing to keep in sync. It is public
/// information: a `kid` names a key, it does not authorise anything, which is why reading one out
/// of an untrusted token header is safe while reading `alg` from the same header is not.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyId(String);

impl KeyId {
    /// Derives the identifier for a public key: the first 128 bits of its SHA-256, base64url.
    ///
    /// Truncated because a `kid` only has to distinguish keys within one deployment, and it is
    /// repeated in the header of every token ever issued.
    #[must_use]
    pub fn derive(public_key: &[u8; PUBLIC_KEY_LEN]) -> Self {
        let digest = Sha256::digest(public_key);
        Self(URL_SAFE_NO_PAD.encode(&digest[..16]))
    }

    /// Wraps a `kid` lifted from an unverified token header.
    ///
    /// Named for where the value came from, and deliberately not `From<String>`. A `kid` is only
    /// ever a lookup key into a set we built ourselves, so a hostile one produces a miss and
    /// nothing else — but the name is here so that nobody later uses one of these as a filename, a
    /// URL fragment or a query parameter without noticing it is attacker-controlled.
    #[must_use]
    pub fn from_untrusted(kid: String) -> Self {
        Self(kid)
    }

    /// The identifier as it appears on the wire.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The public half of a signing key, plus the lifecycle facts a verifier needs.
///
/// Everything on this type is publishable — it is precisely what `/.well-known/jwks.json` exposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicSigningKey {
    /// The key's identifier.
    pub kid: KeyId,
    /// Raw Ed25519 public key bytes.
    pub public_key: [u8; PUBLIC_KEY_LEN],
    /// Lifecycle state.
    pub status: KeyStatus,
    /// When this key starts signing.
    pub activates_at: DateTime<Utc>,
    /// When the overlap window closes and the key stops verifying. `None` for a key with no
    /// retirement scheduled.
    pub retires_at: Option<DateTime<Utc>>,
}

impl PublicSigningKey {
    /// Whether this key may verify a signature at `now`.
    ///
    /// Note what is *not* checked: `activates_at`. A token cannot have been signed before its key
    /// existed, so refusing to verify one because a clock disagrees about activation adds no
    /// security and creates a rotation outage. The retirement boundary is the one that matters,
    /// because a key past it may have been decommissioned or disclosed.
    #[must_use]
    pub fn usable_at(&self, now: DateTime<Utc>) -> bool {
        self.status.verifies() && self.retires_at.is_none_or(|at| now < at)
    }

    /// The `jsonwebtoken` decoding key for this public key.
    ///
    /// Built on demand rather than cached: it is a 32-byte copy, and caching it would mean holding
    /// a type whose family (`Ed`) is the only thing standing between us and an algorithm-confusion
    /// bug, in a place where it could be swapped.
    #[must_use]
    pub fn decoding_key(&self) -> jsonwebtoken::DecodingKey {
        jsonwebtoken::DecodingKey::from_ed_der(&self.public_key)
    }
}

/// A signing key including its private half.
///
/// The private material is PKCS#8 DER in a [`Zeroizing`] buffer, and [`fmt::Debug`] is implemented
/// by hand so that no derive, no `{:?}` in a tracing macro and no panic message can print it.
pub struct PrivateSigningKey {
    public: PublicSigningKey,
    pkcs8_der: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for PrivateSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateSigningKey")
            .field("kid", &self.public.kid)
            .field("status", &self.public.status)
            .field("pkcs8_der", &"<redacted>")
            .finish()
    }
}

impl PrivateSigningKey {
    /// Generates a fresh keypair that is immediately active.
    ///
    /// # Errors
    ///
    /// [`KeyProviderError::Malformed`] if the generated key cannot be encoded as PKCS#8, which in
    /// practice cannot happen and is reported rather than panicked on because this crate forbids
    /// panicking paths in production code.
    pub fn generate(now: DateTime<Utc>) -> Result<Self, KeyProviderError> {
        let signing = SigningKey::generate(&mut rand::rngs::OsRng);
        Self::from_signing_key(&signing, KeyStatus::Active, now, None)
    }

    /// Wraps an existing `ed25519-dalek` key with lifecycle metadata.
    ///
    /// # Errors
    ///
    /// [`KeyProviderError::Malformed`] if PKCS#8 encoding fails.
    pub fn from_signing_key(
        signing: &SigningKey,
        status: KeyStatus,
        activates_at: DateTime<Utc>,
        retires_at: Option<DateTime<Utc>>,
    ) -> Result<Self, KeyProviderError> {
        let der = signing.to_pkcs8_der().map_err(|_| KeyProviderError::Malformed)?;
        let public_key = signing.verifying_key().to_bytes();
        Ok(Self {
            public: PublicSigningKey {
                kid: KeyId::derive(&public_key),
                public_key,
                status,
                activates_at,
                retires_at,
            },
            pkcs8_der: Zeroizing::new(der.as_bytes().to_vec()),
        })
    }

    /// Reconstructs a key from stored PKCS#8 DER.
    ///
    /// # Errors
    ///
    /// [`KeyProviderError::Malformed`] if the bytes are not an Ed25519 PKCS#8 document.
    pub fn from_pkcs8_der(
        der: &[u8],
        status: KeyStatus,
        activates_at: DateTime<Utc>,
        retires_at: Option<DateTime<Utc>>,
    ) -> Result<Self, KeyProviderError> {
        let signing = SigningKey::from_pkcs8_der(der).map_err(|_| KeyProviderError::Malformed)?;
        Self::from_signing_key(&signing, status, activates_at, retires_at)
    }

    /// The publishable half.
    #[must_use]
    pub const fn public(&self) -> &PublicSigningKey {
        &self.public
    }

    /// This key's identifier.
    #[must_use]
    pub const fn kid(&self) -> &KeyId {
        &self.public.kid
    }

    /// The `jsonwebtoken` encoding key.
    ///
    /// Returned by value and not stored, so the private DER has exactly one owner — the
    /// [`Zeroizing`] buffer in this struct — and is wiped when this key is dropped.
    #[must_use]
    pub fn encoding_key(&self) -> jsonwebtoken::EncodingKey {
        jsonwebtoken::EncodingKey::from_ed_der(&self.pkcs8_der)
    }

    /// The PKCS#8 DER encoding, for a provider that needs to persist it.
    ///
    /// Deliberately returns the guarded buffer rather than a `Vec`, so a caller cannot accidentally
    /// take a copy that outlives the wipe.
    #[must_use]
    pub const fn pkcs8_der(&self) -> &Zeroizing<Vec<u8>> {
        &self.pkcs8_der
    }
}

/// The keys a verifier will accept, indexed by `kid`.
///
/// A snapshot, not a live view. Verification happens on the hot path and must not do I/O
/// (`docs/03-LLD.md §5.1`), so the API layer refreshes this periodically and swaps it in.
#[derive(Debug, Clone, Default)]
pub struct KeySet {
    keys: BTreeMap<KeyId, PublicSigningKey>,
}

impl KeySet {
    /// Builds a set from whatever the provider published.
    #[must_use]
    pub fn new(keys: impl IntoIterator<Item = PublicSigningKey>) -> Self {
        Self { keys: keys.into_iter().map(|k| (k.kid.clone(), k)).collect() }
    }

    /// The key that may verify a signature under `kid` at `now`, if any.
    ///
    /// **This is test K2.** Returning `None` for a key past its overlap window is the only thing
    /// that makes retirement mean anything; a lookup that ignored `retires_at` would leave every
    /// key ever generated valid forever.
    #[must_use]
    pub fn verification_key(&self, kid: &KeyId, now: DateTime<Utc>) -> Option<&PublicSigningKey> {
        self.keys.get(kid).filter(|key| key.usable_at(now))
    }

    /// Every key in the set, including ones that are no longer usable.
    pub fn iter(&self) -> impl Iterator<Item = &PublicSigningKey> {
        self.keys.values()
    }

    /// How many keys the set holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the set is empty — which for a verifier means every token will be rejected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Where signing key material comes from.
///
/// Async because the production implementations are network calls to Vault or a KMS. The signing
/// path calls [`KeyProvider::active_signing_key`] per issuance rather than caching a key, so that a
/// compromised key stops being used the moment it stops being active; the *verification* path uses
/// a cached [`KeySet`] instead, because it runs on every request and may not do I/O.
#[async_trait]
pub trait KeyProvider: Send + Sync + fmt::Debug {
    /// The key to sign new tokens with.
    ///
    /// # Errors
    ///
    /// [`KeyProviderError::NoActiveKey`] when rotation has left nothing active. Signing with a
    /// retiring key instead would be the wrong recovery: it would extend the life of a key we have
    /// already decided to stop using.
    async fn active_signing_key(&self) -> Result<PrivateSigningKey, KeyProviderError>;

    /// Every key a verifier should accept, and every key JWKS should publish.
    ///
    /// # Errors
    ///
    /// Implementation-specific storage failures.
    async fn verification_keys(&self) -> Result<Vec<PublicSigningKey>, KeyProviderError>;
}

/// On-disk index of the development key set.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyIndex {
    keys: Vec<KeyIndexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyIndexEntry {
    kid: KeyId,
    status: KeyStatus,
    activates_at: DateTime<Utc>,
    retires_at: Option<DateTime<Utc>>,
}

/// A file-backed [`KeyProvider`] for development (D5).
///
/// Keys live in a directory named by configuration — `deploy/config/dev-keys/` in the dev stack,
/// which is git-ignored — and are **generated on first use**. Nothing is read from the repository,
/// because there is nothing in the repository to read.
///
/// # Not for production
///
/// Private keys sit in plaintext files, and reads are synchronous. Both are acceptable on a
/// laptop and neither is acceptable in a deployment; the `enterprise` profile check in the `config`
/// crate is expected to refuse this provider. It is named `Local*` rather than `Default*` so that
/// nobody reaches for it by accident.
#[derive(Debug)]
pub struct LocalFileKeyProvider {
    directory: PathBuf,
}

impl LocalFileKeyProvider {
    const INDEX_FILE: &'static str = "index.json";

    /// Points the provider at a directory. Nothing is read or created until first use.
    #[must_use]
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self { directory: directory.into() }
    }

    fn index_path(&self) -> PathBuf {
        self.directory.join(Self::INDEX_FILE)
    }

    fn key_path(&self, kid: &KeyId) -> PathBuf {
        // `kid` is base64url of a digest, so it contains no path separators and cannot traverse.
        self.directory.join(format!("{kid}.pkcs8.der"))
    }

    /// Reads the index, generating a first key if the directory holds none.
    ///
    /// Synchronous file I/O inside an async trait method. That is a deliberate, documented
    /// exception rather than an oversight: this provider exists for development, the work is a
    /// handful of small local reads, and the alternative — pulling a runtime dependency into this
    /// crate so a dev-only adapter can be non-blocking — would cost more than it buys.
    fn load_or_initialise(&self) -> Result<KeyIndex, KeyProviderError> {
        let path = self.index_path();
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| KeyProviderError::Malformed),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => self.initialise(),
            Err(err) => Err(KeyProviderError::Storage(err)),
        }
    }

    /// Generates the first key and writes it out.
    fn initialise(&self) -> Result<KeyIndex, KeyProviderError> {
        std::fs::create_dir_all(&self.directory).map_err(KeyProviderError::Storage)?;
        let now = Utc::now();
        let key = PrivateSigningKey::generate(now)?;
        write_private(&self.key_path(key.kid()), key.pkcs8_der())?;

        let index = KeyIndex {
            keys: vec![KeyIndexEntry {
                kid: key.kid().clone(),
                status: KeyStatus::Active,
                activates_at: now,
                retires_at: None,
            }],
        };
        let encoded = serde_json::to_vec_pretty(&index).map_err(|_| KeyProviderError::Malformed)?;
        std::fs::write(self.index_path(), encoded).map_err(KeyProviderError::Storage)?;
        Ok(index)
    }
}

/// Writes private key material with owner-only permissions where the platform has them.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), KeyProviderError> {
    std::fs::write(path, bytes).map_err(KeyProviderError::Storage)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        // Set after writing rather than via a mode on create: the window is a few microseconds on
        // a developer machine, and doing it this way keeps the code portable.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(KeyProviderError::Storage)?;
    }
    Ok(())
}

#[async_trait]
impl KeyProvider for LocalFileKeyProvider {
    async fn active_signing_key(&self) -> Result<PrivateSigningKey, KeyProviderError> {
        let index = self.load_or_initialise()?;
        let entry = index
            .keys
            .iter()
            .find(|e| e.status == KeyStatus::Active)
            .ok_or(KeyProviderError::NoActiveKey)?;
        let der = std::fs::read(self.key_path(&entry.kid)).map_err(KeyProviderError::Storage)?;
        let der = Zeroizing::new(der);
        PrivateSigningKey::from_pkcs8_der(&der, entry.status, entry.activates_at, entry.retires_at)
    }

    async fn verification_keys(&self) -> Result<Vec<PublicSigningKey>, KeyProviderError> {
        let index = self.load_or_initialise()?;
        let mut out = Vec::with_capacity(index.keys.len());
        for entry in &index.keys {
            let der =
                std::fs::read(self.key_path(&entry.kid)).map_err(KeyProviderError::Storage)?;
            let der = Zeroizing::new(der);
            let key = PrivateSigningKey::from_pkcs8_der(
                &der,
                entry.status,
                entry.activates_at,
                entry.retires_at,
            )?;
            out.push(key.public().clone());
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal, not a
    // production hazard. The workspace warns on these constructs for non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use chrono::Duration;

    /// A scratch directory that removes itself. Enough for a dev-provider test; not worth a
    /// dependency.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("enclave-auth-keys-{tag}-{}", uuid::Uuid::new_v4()));
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _cleanup = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_kid_is_derived_from_the_public_key_and_is_stable() {
        let key = PrivateSigningKey::generate(Utc::now()).expect("generate");
        let again = KeyId::derive(&key.public().public_key);
        assert_eq!(key.kid(), &again);
        assert_eq!(key.kid().as_str().len(), 22, "128 bits, base64url, unpadded");
    }

    #[test]
    fn private_material_never_appears_in_debug_output() {
        let key = PrivateSigningKey::generate(Utc::now()).expect("generate");
        let rendered = format!("{key:?}");
        assert!(rendered.contains("<redacted>"));
        // The first bytes of the DER header would appear as decimal numbers in a derived Debug.
        assert!(!rendered.contains(&format!("{}", key.pkcs8_der()[0])));
    }

    #[test]
    fn k2_a_retired_key_stops_verifying_after_the_overlap_window() {
        let now = Utc::now();
        let key = PrivateSigningKey::generate(now).expect("generate");
        let mut public = key.public().clone();
        public.status = KeyStatus::Retiring;
        public.retires_at = Some(now + Duration::hours(24));

        let set = KeySet::new([public.clone()]);
        assert!(
            set.verification_key(&public.kid, now + Duration::hours(23)).is_some(),
            "inside the overlap window a retiring key must still verify"
        );
        assert!(
            set.verification_key(&public.kid, now + Duration::hours(24)).is_none(),
            "K2: at the retirement instant the key stops verifying"
        );
        assert!(set.verification_key(&public.kid, now + Duration::hours(25)).is_none());
    }

    #[test]
    fn k2_a_fully_retired_key_never_verifies() {
        let now = Utc::now();
        let key = PrivateSigningKey::generate(now).expect("generate");
        let mut public = key.public().clone();
        public.status = KeyStatus::Retired;
        public.retires_at = None; // no scheduled retirement; status alone must be enough

        let set = KeySet::new([public.clone()]);
        assert!(set.verification_key(&public.kid, now).is_none());
    }

    #[test]
    fn a_pending_key_verifies_so_that_rotation_is_not_an_outage() {
        let now = Utc::now();
        let key = PrivateSigningKey::generate(now).expect("generate");
        let mut public = key.public().clone();
        public.status = KeyStatus::Pending;
        public.activates_at = now + Duration::minutes(5);

        let set = KeySet::new([public.clone()]);
        assert!(set.verification_key(&public.kid, now).is_some());
    }

    #[tokio::test]
    async fn the_dev_provider_generates_keys_on_first_use_and_reuses_them() {
        let dir = TempDir::new("firstuse");
        let provider = LocalFileKeyProvider::new(&dir.0);

        let first = provider.active_signing_key().await.expect("first use generates");
        let second = provider.active_signing_key().await.expect("second use reuses");
        assert_eq!(first.kid(), second.kid(), "a second call must not mint a new key");

        let published = provider.verification_keys().await.expect("publish");
        assert_eq!(published.len(), 1);
        assert_eq!(&published[0].kid, first.kid());
    }

    #[tokio::test]
    async fn the_dev_provider_writes_owner_only_key_files() {
        let dir = TempDir::new("perms");
        let provider = LocalFileKeyProvider::new(&dir.0);
        let key = provider.active_signing_key().await.expect("generate");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let meta = std::fs::metadata(provider.key_path(key.kid())).expect("stat");
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
        #[cfg(not(unix))]
        let _ = key;
    }
}
