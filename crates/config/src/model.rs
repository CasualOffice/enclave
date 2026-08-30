//! The configuration model.
//!
//! Shapes follow the example in `docs/08-BYO-INFRA.md §15` — that document is authoritative for what
//! an operator writes, and this module is only its typed form. Two rules apply throughout:
//!
//! * every struct implements [`Default`], because the defaults layer of the precedence chain
//!   (`docs/03-LLD.md §21`) *is* those impls, and `#[serde(default)]` fills unset fields from them;
//! * every field that names a credential is a [`SecretRef`], so an inline value is a type error
//!   before it is a validation error (CLAUDE.md rule 11).
//!
//! Sections not modelled yet (embedding, preview, sync, mcp, quotas, identity, mail) are
//! deliberately *not* rejected: they land in later milestones, and an operator who writes a
//! complete file today should not be blocked. They are still scanned for inline credentials, which
//! is the part that matters for security.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use enclave_core::{ClassificationRank, FactsPolicy, FactsUnavailable};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::duration::HumanDuration;
use crate::secret_ref::{SecretRef, SecretScheme};

/// What this deployment is expected to be capable of (`docs/08-BYO-INFRA.md §19`).
///
/// The profile is a *promise* made to the operator, and validation enforces it: an enterprise
/// deployment that quietly ran without antivirus would still call itself enterprise in the admin
/// UI, in the SOC 2 evidence pack, and in the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentProfile {
    /// Single node, local filesystem or MinIO, embedded ClamAV. The default, because a developer
    /// running `cargo run` must not be held to enterprise requirements.
    #[default]
    Community,
    /// Horizontally scaled, HA data services.
    Production,
    /// Multi-AZ with BYO infrastructure; the strictest validation rules apply.
    Enterprise,
}

impl DeploymentProfile {
    /// Whether the strict startup requirements of `docs/08-BYO-INFRA.md §19` apply.
    #[must_use]
    pub const fn is_enterprise(&self) -> bool {
        matches!(self, Self::Enterprise)
    }
}

/// The whole configuration, after all four layers have been applied.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Which capability promises this deployment makes.
    pub profile: DeploymentProfile,
    /// HTTP listener and proxy trust. Read by `enclave-api`; a worker has no such listener.
    pub server: ServerConfig,
    /// Where each process serves its Prometheus exposition.
    pub metrics: MetricsConfig,
    /// PostgreSQL — the authoritative store.
    pub database: DatabaseConfig,
    /// Object storage for versions and renditions.
    pub storage: StorageConfig,
    /// The vector store behind hybrid search.
    pub search: SearchConfig,
    /// Redis, used for caching and rate limiting.
    pub redis: RedisConfig,
    /// NATS JetStream, the outbox destination.
    pub events: EventsConfig,
    /// Token issuance and rotation.
    pub auth: AuthConfig,
    /// Password, MFA and fail-closed behaviour.
    pub security: SecurityConfig,
    /// Named trusted network zones, which conditional-access rules refer to by name.
    pub conditional_access: ConditionalAccessConfig,
    /// Data-loss prevention.
    pub dlp: DlpConfig,
    /// Audit trail.
    pub audit: AuditConfig,
    /// Malware scanning.
    pub antivirus: AntivirusConfig,

    /// Directory holding the mounted OCR model weights, or `None` to run no OCR at all.
    ///
    /// **What a deployment gets when this is absent:** exactly what every deployment gets today. A
    /// scanned, text-free document produces no text, the manifest records `FAILED` with
    /// `no_text_extracted`, and the file is visibly unsearchable rather than invisibly empty. That
    /// is the documented absence `plans/M3-DISCOVERY.md` D24 asks for, and it is why the default is
    /// `None` rather than a path that might exist: a deployment that has not staged the weights has
    /// not decided to run OCR, and inventing a default path for it would turn a decision into a
    /// filesystem accident.
    ///
    /// **Mounted rather than shipped, and the reason is licensing** — `crates/indexing/src/ocr.rs`
    /// argues it at length. The published `ocrs` weights are CC-BY-SA-4.0, which `deny.toml`'s
    /// permissive-only allowlist excludes and which `cargo deny` structurally cannot see, because
    /// the crate is permissive and weights are not a crate. The operator obtains and stages them;
    /// we redistribute nothing.
    ///
    /// **This is a path, not a secret, and therefore deliberately not a
    /// [`SecretRef`].** CLAUDE.md rule 11 is about *credentials* — a value that grants access to
    /// something. A mount point grants nothing: it is the same class as `antivirus.endpoint`, which
    /// is likewise a plain `String` with "not a secret — a host and port" written beside it. Making
    /// it a `SecretRef` would put a directory name behind a Vault round trip, and would leave
    /// `secret_refs()` reporting a resolution failure for a filesystem that is simply not mounted.
    /// It is therefore **not** listed in [`Config::secret_refs`], and that omission is a decision
    /// rather than an oversight.
    ///
    /// **Why this is a top-level key and not `indexing.ocr_models`.** The loader derives an
    /// environment override from the field path (`crates/config/src/loader.rs`), so a nested field
    /// would be spelled `ENCLAVE_INDEXING__OCR_MODELS` — while CI's "Fetch the OCR models" step,
    /// `crates/indexing/tests/ocr.rs` and every runbook already say `ENCLAVE_OCR_MODELS`. Two
    /// spellings for one directory is the drift this repository keeps finding in other forms: the
    /// two agree until someone changes one of them, and the symptom is a deployment that believes
    /// OCR is on. At the top level the two spellings are one spelling.
    pub ocr_models: Option<PathBuf>,

    /// Directory holding the mounted PDFium shared library, or `None` to rasterise no PDF page.
    ///
    /// The directory, not the file: `pdfium-render` derives the platform's library name
    /// (`libpdfium.so`, `pdfium.dll`, `libpdfium.dylib`) from it, and naming the file here would
    /// make one configuration file wrong on two of the three platforms.
    ///
    /// **What a deployment gets when this is absent:** `NoPageImages`
    /// (`crates/indexing/src/ocr.rs`) — no page of any PDF is rasterised, so an OCR retry over a
    /// scanned PDF recovers nothing and the manifest keeps saying `FAILED`. Absent, never refused:
    /// a deployment that mounted no rasteriser has made no finding about anybody's document.
    ///
    /// Mounted rather than vendored for a different reason than the weights: 7 MB of shared object
    /// per platform, content nobody reviews in a diff, invisible to `cargo deny` because it is not
    /// a crate. The version is an **ABI pair** with the `pdfium_7881` feature in the workspace
    /// manifest — `pdfium-render` resolves every export eagerly at `dlopen`, so a mismatched
    /// library fails loudly at the mount rather than subtly at render.
    ///
    /// A path and not a secret, for the reason given on [`ocr_models`](Self::ocr_models); and a
    /// top-level key so that this field and `ENCLAVE_PDFIUM` are one spelling.
    pub pdfium: Option<PathBuf>,

    /// Directory holding the mounted embedding model, or `None` to embed nothing (`ENC-661`).
    ///
    /// It holds `model.rten` and `tokenizer.json` — the converted `bge-m3` weights
    /// (`plans/M3-DISCOVERY.md` Q14) and the vocabulary they were trained against.
    /// `docs/08-BYO-INFRA.md §18.1` gives the conversion, reproducibly, because
    /// `crates/embeddings` loads `.rten` and BAAI publishes ONNX.
    ///
    /// **What a deployment gets when this is absent:** exactly what every deployment got before
    /// `ENC-661`. No [`VectorStage`](../../enclave_worker/indexing/struct.VectorStage.html) is
    /// built, text still reaches `chunk_text` so lexical search works, and
    /// `index_manifests.embedding_model` records `""` — which `BuildVersions` documents as the
    /// honest value for a deployment where nothing has embedded. Dense retrieval returns nothing,
    /// and the worker says so once at start-up rather than leaving it to be inferred from an empty
    /// collection.
    ///
    /// **Mounted rather than shipped**, and here the reason is size rather than licensing:
    /// `bge-m3` is 2.2 GB, and `docs/08-BYO-INFRA.md §18` covers air-gapped installs where a
    /// multi-gigabyte layer on every image pull is a real cost. `crates/embeddings/src/mounted.rs`
    /// carries the argument, and `crates/indexing/src/ocr.rs` carries the stronger, licensing-based
    /// version of it for the OCR weights.
    ///
    /// **A path, not a secret**, for the reason argued on [`ocr_models`](Self::ocr_models), and
    /// therefore deliberately absent from [`Config::secret_refs`]. **A top-level key**, also for
    /// that field's reason: the loader derives an environment override from the field path, so a
    /// nested `embedding.local.model` would be spelled `ENCLAVE_EMBEDDING__LOCAL__MODEL` while
    /// CI, `crates/embeddings/tests/mounted.rs` and every runbook say `ENCLAVE_EMBEDDING_MODEL`.
    /// Two spellings for one directory is the drift this repository keeps finding in other forms.
    pub embedding_model: Option<PathBuf>,
}

impl Config {
    /// Every secret reference in the configuration, paired with the dotted field path it came from.
    ///
    /// The path is what makes a resolution failure diagnosable ("`database.url` could not be read")
    /// and is the key under which the resolved value is stored, so no caller has to remember which
    /// provider a value came from.
    #[must_use]
    pub fn secret_refs(&self) -> Vec<(String, SecretRef)> {
        let mut refs = Vec::new();
        let mut push = |path: &str, value: Option<SecretRef>| {
            if let Some(value) = value {
                refs.push((path.to_owned(), value));
            }
        };
        push("database.url", self.database.url_ref());
        push("database.platform_url", self.database.platform_url_ref());
        push("redis.url", self.redis.url_ref());
        push("events.nats_url", self.events.nats_url_ref());
        push("auth.signing_keys.key_ref", self.auth.signing_keys.key_ref.clone());
        push("security.password.pepper", self.security.password.pepper.clone());
        // Object-storage credentials are enrolled here as well as being read by
        // `enclave_storage::S3BlobStore::connect`, so that an unresolvable key is reported at
        // startup, by field path, alongside every other unresolvable reference — rather than as
        // the first upload's provider error. The mount *paths* above are deliberately not here;
        // these are genuine credentials and the distinction is argued on `Config::ocr_models`.
        if let Some(s3) = self.storage.s3.as_ref() {
            push("storage.s3.access_key_id", Some(s3.access_key_id.clone()));
            push("storage.s3.secret_access_key", Some(s3.secret_access_key.clone()));
            push("storage.s3.session_token", s3.session_token.clone());
        }
        if let Some(milvus) = self.search.milvus.as_ref() {
            push("search.milvus.token", milvus.token.clone());
        }
        refs
    }

    /// What this deployment has staged for OCR over a scanned PDF.
    ///
    /// A tri-state rather than an `Option<(…, …)>`, and that is the whole reason this accessor
    /// exists. Collapsing "neither is set" and "one is set" into one `None` is the shape D24 keeps
    /// warning about: an operator who mounted the weights and forgot the rasteriser would get
    /// silence, and every scanned PDF in the corpus would index as empty while the configuration
    /// file said OCR was on.
    ///
    /// Read by [`check_mounts`](crate::validate::check_mounts), which refuses startup on
    /// [`Incomplete`](OcrMounts::Incomplete), and by the worker that builds the stage. One function
    /// so the two cannot disagree about what "configured" means.
    #[must_use]
    pub fn ocr_mounts(&self) -> OcrMounts<'_> {
        match (self.ocr_models.as_deref(), self.pdfium.as_deref()) {
            (None, None) => OcrMounts::Absent,
            (Some(models), Some(pdfium)) => OcrMounts::Mounted { models, pdfium },
            (Some(_), None) => OcrMounts::Incomplete { present: "ocr_models", missing: "pdfium" },
            (None, Some(_)) => OcrMounts::Incomplete { present: "pdfium", missing: "ocr_models" },
        }
    }

    /// What this deployment has staged for embedding, and whether it has anywhere to put the
    /// result (`ENC-661`).
    ///
    /// A tri-state for [`ocr_mounts`](Self::ocr_mounts)' reason: collapsing "nothing is configured"
    /// and "half of it is" into one `None` gives an operator who staged 2.2 GB of weights a
    /// perfectly quiet deployment that embeds nothing, while the configuration file says embedding
    /// is on.
    ///
    /// # Why the pair is asymmetric, unlike the OCR one
    ///
    /// The two OCR mounts are two halves of one capability, so either without the other is a
    /// mistake in both directions. This pair is not symmetric, and pretending it were would refuse
    /// every deployment that exists today:
    ///
    /// * **A model with no vector store is a mistake.** There is nowhere for the vectors to go —
    ///   `VectorStage` takes a `VectorWriter` and `MilvusIndex` is the only one — so the stage
    ///   cannot be built and the weights are loaded, resident and unused. That is
    ///   [`Incomplete`](EmbeddingMounts::Incomplete).
    /// * **A vector store with no model is the ordinary case**, and it is
    ///   [`Absent`](EmbeddingMounts::Absent). `search.milvus` has purposes that have nothing to do
    ///   with embedding: it is what the coverage probe takes its census through, and it is where
    ///   the query side reads candidates from. Its presence is not a claim that this deployment
    ///   embeds.
    ///
    /// # Where the middle state is acted on, and why it is not here
    ///
    /// By `enclave_worker::embedding::MountedEmbedder::from_config`, and **not** by a startup
    /// validator in [`crate::validate`] beside [`check_mounts`](crate::validate::check_mounts).
    /// That is a correction rather than an omission: the first version of `ENC-661` did put it
    /// there, and `crates/config/tests/ambient_environment.rs` caught what it did.
    ///
    /// [`ConfigLoader`](crate::ConfigLoader) reads the **whole process environment**, and
    /// `ENCLAVE_EMBEDDING_MODEL` is what CI and every runbook tell an operator to export. A shell
    /// with the model staged and no vector store therefore made *every* binary in the workspace
    /// refuse to start — `enclave-api` included, which has no vector stage and no opinion about
    /// one. That is `ENC-544`'s failure reached through a validator instead of a variable name,
    /// and `ENC-566`'s too: one key, read by two binaries, only one of which can act on it.
    ///
    /// The worker still refuses, loudly, naming both keys. The process that refuses is now the one
    /// that would have embedded.
    #[must_use]
    pub fn embedding_mounts(&self) -> EmbeddingMounts<'_> {
        match (self.embedding_model.as_deref(), self.search.milvus.is_some()) {
            (None, _) => EmbeddingMounts::Absent,
            (Some(model), true) => EmbeddingMounts::Mounted { model },
            (Some(_), false) => {
                EmbeddingMounts::Incomplete { present: "embedding_model", missing: "search.milvus" }
            }
        }
    }
}

/// What a deployment has staged for embedding.
///
/// See [`Config::embedding_mounts`] for why the middle state is spelled out and why this pair is
/// asymmetric where [`OcrMounts`] is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbeddingMounts<'a> {
    /// No embedding model is configured — the default, and nothing embeds.
    ///
    /// Not a degradation to notice: text still reaches `chunk_text`, lexical search still works,
    /// and `index_manifests.embedding_model` honestly records `""`.
    Absent,
    /// A model is mounted and there is a vector store to write to. The path has **not** been
    /// checked to exist; that happens at the mount, which is the only place that can tell "absent"
    /// from "present and unloadable".
    Mounted {
        /// Directory holding `model.rten` and `tokenizer.json`.
        model: &'a Path,
    },
    /// A model with nowhere to put its vectors. Refused at startup — the field names are
    /// `&'static str` so a message built from them can never carry a configured value.
    Incomplete {
        /// The key that was set.
        present: &'static str,
        /// The key that was not.
        missing: &'static str,
    },
}

/// The state of the two volumes OCR over a scanned PDF needs.
///
/// See [`Config::ocr_mounts`] for why the middle state is spelled out rather than folded into the
/// absent one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcrMounts<'a> {
    /// Neither volume is configured — the default, and no OCR runs.
    ///
    /// Not a degradation to notice: a textless document is recorded `FAILED` with
    /// `no_text_extracted`, which is a surface somebody reads.
    Absent,
    /// Both volumes are configured. The paths have **not** been checked to exist; that happens at
    /// the mount, which is the only place that can tell "absent" from "present and unloadable".
    Mounted {
        /// Directory holding `text-detection.rten` and `text-recognition.rten`.
        models: &'a Path,
        /// Directory holding the platform's PDFium shared library.
        pdfium: &'a Path,
    },
    /// One half without the other. Refused at startup — the field names are `&'static str` so a
    /// message built from them can never carry a configured value.
    Incomplete {
        /// The key that was set.
        present: &'static str,
        /// The key that was not.
        missing: &'static str,
    },
}

/// HTTP listener, public identity and proxy trust.
///
/// **`enclave-api` only.** Nothing here describes the worker, which serves no HTTP API and has no
/// bind address, public URL or proxies to trust. That asymmetry is why the metrics listener moved
/// out of this struct and into [`MetricsConfig`] (`ENC-566`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Address to bind. Defaults to loopback rather than `0.0.0.0`: a service should be exposed
    /// deliberately, not by forgetting to set a field.
    pub bind: IpAddr,
    /// TCP port.
    pub port: u16,
    /// The URL clients reach this deployment on, used for token issuer, cookie domain and links in
    /// mail. `None` means "derive from bind and port", which is only sane in development.
    pub public_url: Option<Url>,
    /// Networks whose forwarding headers may be believed, and how many hops each strips.
    ///
    /// Empty by default. An empty list means the peer address is the client address — the only safe
    /// assumption when nothing is known, because trusting `X-Forwarded-For` from an untrusted peer
    /// lets any client claim any source IP and defeat conditional access
    /// (`docs/06-SECURITY-DLP-ACCESS.md`).
    pub trusted_proxies: Vec<TrustedProxy>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 8080,
            public_url: None,
            trusted_proxies: Vec::new(),
        }
    }
}

/// Where each process serves its Prometheus exposition (`docs/11-OPERATIONS.md §10.1`).
///
/// # Why this is its own section rather than a field on [`ServerConfig`]
///
/// It used to be `server.metrics_port`, and both binaries read it. One `enclave.yaml` on one host
/// therefore asked the API and the worker to bind the *same* socket, and whichever started second
/// died with `Address already in use` — at start-up, because the bind is a `?` (`ENC-566`). The
/// monitoring stack had already worked around it: `deploy/monitoring/prometheus.yml` scrapes 9464
/// for the API and 9465 for the worker, two ports the configuration had no way to express.
///
/// `server.*` was also simply the wrong home. A worker serves no HTTP API, so it has no `bind`, no
/// `public_url` and no `trusted_proxies`; reading its listener out of the API's section made a
/// worker inherit three fields that mean nothing to it.
///
/// # Why one section with two ports rather than two process sections
///
/// One [`bind`](Self::bind), because that is the security-relevant field — this exposition carries
/// `tenant_id` labels and is unauthenticated by design, so which interface it faces must be one
/// decision and not two that can drift apart. Two ports, named for the process that binds each,
/// because a single file is read by both processes and the two numbers belong side by side: what
/// `ENC-566` cost was precisely that nothing in the file showed the two listeners were related.
///
/// **Equal ports are not refused.** In a per-pod deployment the API and the worker do not share a
/// port namespace and `9464` for both is correct (`docs/11-OPERATIONS.md §3.1`). Refusing equality
/// here would break that deployment to protect the single-host one, so the shape makes the
/// difference expressible and the operator chooses. On one host, give them different ports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricsConfig {
    /// Address both listeners bind. Defaults to loopback, and should stay there unless the scraper
    /// is on another host and the network between them is trusted.
    ///
    /// **This is not an authenticated endpoint and never will be.** The exposition carries
    /// `tenant_id` labels — which tenants exist, how much each searches, how far behind each one's
    /// invalidation is. That is customer data in aggregate, and the policy-routing allowlist says
    /// in its own words that an unauthenticated endpoint "must never include a detail that
    /// identifies a tenant or a resource". A socket of its own is what lets an operator place it on
    /// a private interface while the API faces the world, without either a policy exemption that
    /// would be wrong or an authentication scheme Prometheus would have to be taught.
    pub bind: IpAddr,

    /// Port `enclave-api` serves its exposition on, or `None` to serve none.
    ///
    /// `None` by default: a deployment that has not thought about where this port goes should not
    /// have it open.
    pub api_port: Option<u16>,

    /// Port `enclave-worker` serves its exposition on, or `None` to serve none.
    ///
    /// `None` by default, and the cost of leaving it unset is worth stating: the coverage probe's
    /// gauges are process-wide statics published by whichever process ran the pass, so a worker
    /// with no socket publishes them into a registry nothing scrapes. That reads as zero forever,
    /// which is indistinguishable from healthy, and `SearchIndexCoverageUnreported` cannot clear.
    pub worker_port: Option<u16>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            // Off unless a deployment asks for it. The exposition carries tenant labels, so a port
            // nobody chose to open is a port that should not be open.
            api_port: None,
            worker_port: None,
        }
    }
}

impl MetricsConfig {
    /// The socket `enclave-api` should serve on, if any.
    #[must_use]
    pub fn api_addr(&self) -> Option<std::net::SocketAddr> {
        self.api_port.map(|port| std::net::SocketAddr::new(self.bind, port))
    }

    /// The socket `enclave-worker` should serve on, if any.
    #[must_use]
    pub fn worker_addr(&self) -> Option<std::net::SocketAddr> {
        self.worker_port.map(|port| std::net::SocketAddr::new(self.bind, port))
    }
}

/// One trusted reverse-proxy network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedProxy {
    /// The network whose forwarded headers are believed.
    pub cidr: IpNetwork,
    /// How many proxy hops sit in front of the application for this network. Counting hops rather
    /// than taking the left-most `X-Forwarded-For` entry is what stops a client from prepending a
    /// forged address.
    pub hops: u8,
}

/// Conditional access (`docs/06-SECURITY-DLP-ACCESS.md §7`).
///
/// # Why only the zones live here
///
/// An administrator writes *rules* in the admin console, against the tenant they administer, and
/// they are tenant data rather than deployment configuration — one `enclave.yaml` serves every
/// tenant on a host, so a rule in it would apply to all of them.
///
/// Zone *definitions* are the part that is genuinely about the deployment: which networks the
/// corporate egress, the VPN concentrator and the datacenter actually occupy is a fact about where
/// this installation runs, and it is the same fact the load balancer and the firewall are
/// configured with. Naming them here lets a rule say "Corporate India" instead of a prefix, which
/// is what makes a rule reviewable and what makes renumbering a network one edit instead of many.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ConditionalAccessConfig {
    /// The named zones. Empty by default: with none defined, every address is outside every zone
    /// and any rule requiring a trusted network refuses. That is the fail-closed direction — a
    /// deployment that has not said where its trusted networks are has not got any.
    pub zones: Vec<NetworkZoneConfig>,
}

/// One named trusted network zone (`docs/06-SECURITY-DLP-ACCESS.md §7.2`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkZoneConfig {
    /// The name rules refer to, e.g. `Corporate India`.
    pub name: String,
    /// The networks inside it. An empty list contains no address rather than every address: a
    /// half-written zone must not become one that admits everyone, because the rules naming it are
    /// the ones that grant access.
    pub networks: Vec<IpNetwork>,
}

/// Object storage for versions and renditions (`docs/08-BYO-INFRA.md §3`).
///
/// # Why this section is here and `enclave_storage::S3Config` is not
///
/// `enclave-storage` depends on `enclave-config`, so the type an operator writes cannot live in
/// the crate that builds a client from it without a dependency cycle. Three ways out were on the
/// table and this is the one taken:
///
/// * **Invert the dependency** — `enclave-config` gains `enclave-storage`, and with it
///   `aws-sdk-s3`. Every crate in the workspace depends on `enclave-config`, so every crate would
///   compile the S3 SDK to read a password policy. Refused on that alone.
/// * **Keep the subtree untyped** — a `serde_yaml::Value` handed to `enclave-storage` to
///   deserialize at composition time. No duplication, and it costs the property this crate is
///   built around: `ConfigLoader::load` reports *every* problem in one pass, and a typo in
///   `storage.s3` would instead surface later, one at a time, in a binary's start-up sequence.
/// * **A config-side struct plus a conversion in `enclave-storage`** — this one, and the same
///   shape `db_config_from` in `crates/api/src/main.rs` already uses for the database. Its doc
///   comment states the principle: `config` describes what an operator writes, the provider crate
///   describes what a client needs, and collapsing them makes every client knob a public
///   configuration surface.
///
/// So [`S3StorageConfig`] is deliberately **smaller** than `enclave_storage::S3Config`. It carries
/// what an operator decides — which bucket, where, with which credential, and how long a signed URL
/// may live — and not `multipart_threshold_bytes` or `part_size_bytes`, which are S3 protocol
/// pacing with no correctness content and are exactly the "every knob becomes configuration" the
/// separation exists to avoid. The conversion lives in `enclave-storage`, in one place, so the two
/// shapes meet once; `crates/storage/src/s3/config.rs` holds it and the test that proves the
/// documented example round-trips.
///
/// [`S3Flavor`] is **not** duplicated. It is a word an operator types (`flavor: minio`), and a
/// vocabulary spelled in two crates is two spellings waiting to disagree, so it is defined here and
/// re-exported by `enclave-storage`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    /// Which provider this deployment uses.
    ///
    /// `none` by default, and the default is a refusal rather than a fallback: with no store
    /// configured `enclave-worker` does not schedule the indexing pass at all. Pointing a pass at a
    /// store that cannot answer would be worse than not running one — `enclave_indexing::claim`
    /// commits before the first byte is read, so every tick would move a batch of manifests into a
    /// working state and increment the `attempts` budget that quarantines genuinely poisoned
    /// documents, then fail. A deployment whose only problem was a missing bucket would end up with
    /// a corpus of files nothing will retry.
    pub provider: StorageProvider,

    /// The S3-compatible bucket, when [`provider`](Self::provider) is `s3`.
    ///
    /// Set without `provider: s3`, or `provider: s3` without this, is refused at startup naming the
    /// key that is missing — see `enclave_config::validate::check_storage`. Silence in either
    /// direction is the failure mode `check_mounts` was written for one section along: a
    /// configuration file that says storage is configured and a deployment that indexes nothing.
    pub s3: Option<S3StorageConfig>,
}

/// Which object-storage provider a deployment uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageProvider {
    /// No object storage. The default; see [`StorageConfig::provider`] for why that is a refusal
    /// and not a degradation.
    #[default]
    None,
    /// Anything speaking the S3 API — AWS S3, MinIO, Ceph, R2, Wasabi, B2. Which one is
    /// [`S3StorageConfig::flavor`].
    S3,
}

/// What an operator writes to point this deployment at one S3-compatible bucket.
///
/// Every field that names a credential is a [`SecretRef`], so a YAML file holding a literal key
/// fails to deserialize — `CLAUDE.md` rule 11 enforced by the type rather than by review. There is
/// no field here that *can* hold a key.
///
/// `deny_unknown_fields`, unlike the sections around it, and for a specific reason: the costly typo
/// in this block is a silent one. `force_path_style` instead of `path_style` leaves addressing at
/// its default, which produces a DNS failure against a self-hosted endpoint that reads as a network
/// problem; `secret_key` instead of `secret_access_key` would be a missing required field, which is
/// already loud. The strict form makes both loud.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3StorageConfig {
    /// The bucket holding versions and renditions.
    pub bucket: String,

    /// The region to sign for. Required even against MinIO, which ignores it but still expects the
    /// signature to be computed over one; `us-east-1` is the conventional answer there.
    pub region: String,

    /// Endpoint override. Absent uses the provider's AWS endpoint; set it for MinIO, Ceph, R2 and
    /// anything else self-hosted.
    #[serde(default)]
    pub endpoint: Option<Url>,

    /// Path-style addressing (`{endpoint}/{bucket}/{key}`) rather than virtual-host
    /// (`{bucket}.{endpoint}/{key}`).
    ///
    /// Defaults to `true`: virtual-host addressing needs per-bucket DNS, which a self-hosted MinIO
    /// or Ceph does not have, so the default that works everywhere is path style and AWS
    /// deployments turn it off.
    #[serde(default = "default_true")]
    pub path_style: bool,

    /// Reference to the access key id — `vault://…`, `env://…`. Never a literal.
    pub access_key_id: SecretRef,

    /// Reference to the secret access key. Never a literal.
    pub secret_access_key: SecretRef,

    /// Reference to a session token, for deployments using temporary credentials.
    #[serde(default)]
    pub session_token: Option<SecretRef>,

    /// Default life of a signed URL, used when a caller does not specify one.
    ///
    /// Five minutes: long enough for a browser to start a download on a slow connection, short
    /// enough that a URL captured from a log or a referrer header is worthless by the time it is
    /// read. No S3-compatible backend can invalidate a pre-signed URL before it expires, so this
    /// number *is* the control (`plans/M1-CONTENT-CORE.md` D14).
    #[serde(default = "default_signed_url_ttl")]
    pub signed_url_ttl: HumanDuration,

    /// Ceiling on any signed URL, whatever a caller asks for. A TTL above it is refused, never
    /// clamped.
    #[serde(default = "default_max_signed_url_ttl")]
    pub max_signed_url_ttl: HumanDuration,

    /// Which S3-compatible backend this is; selects the startup self-check probes.
    #[serde(default)]
    pub flavor: S3Flavor,
}

/// Which S3-compatible backend a bucket lives on.
///
/// Not cosmetic: it selects which public-access self-check probes are even attempted. MinIO does
/// not implement `GetPublicAccessBlock` or `GetBucketPolicyStatus`, and running them there produces
/// a page of "not implemented" noise in the startup log that trains an operator to ignore the log.
///
/// Defined here rather than in `enclave-storage` because it is a word an operator types; that crate
/// re-exports it, so `enclave_storage::S3Flavor` remains the name every caller already used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum S3Flavor {
    /// Amazon S3 itself. Every probe is available.
    #[default]
    Aws,
    /// MinIO. Bucket policy and ACL probes work; the AWS-only ones do not.
    Minio,
    /// Anything else speaking the S3 API — Ceph, R2, Wasabi, B2. Only the probes that are part of
    /// the core API are attempted.
    Generic,
}

/// The vector store behind hybrid search (`docs/08-BYO-INFRA.md §10`).
///
/// Modelled for the same reason and in the same shape as [`StorageConfig`]: `enclave-search` owns
/// `MilvusConfig`, which holds an SDK `ConsistencyLevel` and a *resolved* token, and it does not
/// depend on this crate. The conversion is one function in `crates/worker/src/main.rs`, beside
/// `db_config_from`.
///
/// **The embedding width is not here, and its absence is the point.** `MilvusConfig::dimension` is
/// fixed when the collection is created, and a mismatch does not error at either end: Milvus
/// accepts vectors of the width it was made with and the model emits the width it was trained at,
/// so the symptom is silently degraded retrieval and the correction is re-embedding every chunk of
/// every tenant (`docs/07-SEARCH-INDEXING.md §9`). A configurable width is a way to write that
/// mistake down. It is read from `enclave_embeddings::model::ACTIVE.dimension` instead.
///
/// The query-side keys `docs/08-BYO-INFRA.md §15` also lists — `default_mode`, `dense`, `sparse`,
/// `bm25`, `overfetch_factor`, `denylist_degrade_threshold` — are **not** modelled here yet, and
/// are ignored rather than rejected exactly like the sections that are wholly unmodelled. Both
/// documents say which keys are read.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SearchConfig {
    /// Which vector store this deployment uses.
    ///
    /// `none` by default, and again a refusal rather than a fallback: with no store the coverage
    /// probe is not scheduled. A census pointed at a URI nobody configured fails, every tenant
    /// counts `unreadable`, and the gauges an operator reads report a fleet-wide outage that is
    /// really a missing configuration key. No series at all is the legible absence, and
    /// `SearchIndexCoverageUnreported` is written to catch it.
    pub provider: SearchProvider,

    /// The Milvus endpoint, when [`provider`](Self::provider) is `milvus`. Refused at startup if
    /// one is set without the other, as with [`StorageConfig::s3`].
    pub milvus: Option<MilvusSettings>,
}

/// Which vector store a deployment uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SearchProvider {
    /// No vector store. Search stays lexical-only and says so; see [`SearchConfig::provider`].
    #[default]
    None,
    /// Milvus, the only implementation there is.
    Milvus,
}

/// What an operator writes to point this deployment at a Milvus cluster.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MilvusSettings {
    /// gRPC endpoint, e.g. `http://milvus:19530`.
    pub uri: Url,

    /// Reference to the `user:password` token, for a cluster that authenticates. Absent for the
    /// unauthenticated development stack. A [`SecretRef`], never a literal.
    #[serde(default)]
    pub token: Option<SecretRef>,

    /// Collection to read and write. Absent takes the one `docs/07-SEARCH-INDEXING.md §4` names,
    /// which is what every deployment should use; the key exists so a migration between two
    /// collections has somewhere to point.
    #[serde(default)]
    pub collection: Option<String>,
}

/// PostgreSQL connection settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    /// Reference to the DSN. A `SecretRef` and not a `String`, because a DSN embeds a password.
    pub url: Option<SecretRef>,
    /// The `url_env: DATABASE_URL` spelling used in `docs/08-BYO-INFRA.md §15`, kept so a
    /// documented file loads unchanged. Equivalent to `url: env://DATABASE_URL`.
    pub url_env: Option<String>,
    /// Reference to the DSN of the **`BYPASSRLS`** role, for the three cross-tenant paths
    /// `enclave_db::DbPool::platform_connection` names — the migration runner, the outbox
    /// publisher, and the scheduler's tenant enumerator.
    ///
    /// Absent by default, and the default is the safe one: with nothing here there is no
    /// row-level-security bypass anywhere in the process, and the code paths that need one refuse
    /// to start rather than falling back. A deployment that runs the worker has to set it, because
    /// the query producing a tenant list cannot itself be scoped to a tenant.
    ///
    /// A `SecretRef` for the same reason `url` is: a DSN embeds a password, and this one's is the
    /// most valuable in the deployment.
    pub platform_url: Option<SecretRef>,
    /// The `platform_url_env: DATABASE_PLATFORM_URL` spelling, matching [`Self::url_env`].
    pub platform_url_env: Option<String>,
    /// Upper bound on pooled connections.
    pub max_connections: u32,
    /// Connections kept warm.
    pub min_connections: u32,
    /// How long a checkout may wait before failing.
    pub acquire_timeout: HumanDuration,
    /// Server-side statement timeout, so one pathological query cannot hold a pool slot forever.
    pub statement_timeout: HumanDuration,
    /// The non-owner role the application connects as, so row-level security applies to it
    /// (`plans/M0-FOUNDATIONS.md` D3).
    pub application_role: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: None,
            url_env: None,
            platform_url: None,
            platform_url_env: None,
            max_connections: 50,
            min_connections: 1,
            acquire_timeout: HumanDuration::from_secs(10),
            statement_timeout: HumanDuration::from_secs(30),
            application_role: "enclave_app".to_owned(),
        }
    }
}

impl DatabaseConfig {
    /// The effective DSN reference, preferring the explicit `url` over the `url_env` shorthand.
    ///
    /// Returns `None` when neither is set *or* when `url_env` names something that is not a valid
    /// environment variable; the latter is already reported as a validation problem, so silently
    /// dropping it here cannot hide anything.
    #[must_use]
    pub fn url_ref(&self) -> Option<SecretRef> {
        env_ref(self.url.as_ref(), self.url_env.as_deref())
    }

    /// The effective `BYPASSRLS` DSN reference, or `None` when this deployment configured none.
    ///
    /// `None` is a refusal for whoever needs it, never a fallback to [`Self::url_ref`]. Falling
    /// back would hand a cross-tenant caller a connection that row-level security *does* apply to
    /// with no tenant context set, which reads as "zero rows everywhere" — an empty tenant list, an
    /// idle worker, and nothing reporting a problem.
    #[must_use]
    pub fn platform_url_ref(&self) -> Option<SecretRef> {
        env_ref(self.platform_url.as_ref(), self.platform_url_env.as_deref())
    }
}

/// Redis connection settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RedisConfig {
    /// Reference to the Redis URL, which may embed credentials.
    pub url: Option<SecretRef>,
    /// The `url_env` spelling from `docs/08-BYO-INFRA.md §15`.
    pub url_env: Option<String>,
    /// Upper bound on pooled connections.
    pub pool_size: u32,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self { url: None, url_env: None, pool_size: 16 }
    }
}

impl RedisConfig {
    /// The effective Redis URL reference.
    #[must_use]
    pub fn url_ref(&self) -> Option<SecretRef> {
        env_ref(self.url.as_ref(), self.url_env.as_deref())
    }
}

/// NATS JetStream settings for the transactional outbox publisher.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct EventsConfig {
    /// Reference to the NATS URL, which may embed credentials.
    pub nats_url: Option<SecretRef>,
    /// The `nats_url_env` spelling from `docs/08-BYO-INFRA.md §15`.
    pub nats_url_env: Option<String>,
    /// Stream name.
    pub stream: String,
    /// How many outbox rows one publish pass claims. Bounded so a backlog is drained steadily
    /// rather than in one transaction that holds locks for minutes.
    pub publish_batch: u32,
}

impl Default for EventsConfig {
    fn default() -> Self {
        Self { nats_url: None, nats_url_env: None, stream: "vault".to_owned(), publish_batch: 256 }
    }
}

impl EventsConfig {
    /// The effective NATS URL reference.
    #[must_use]
    pub fn nats_url_ref(&self) -> Option<SecretRef> {
        env_ref(self.nats_url.as_ref(), self.nats_url_env.as_deref())
    }
}

/// Token issuance, rotation and signing.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    /// Short-lived bearer tokens.
    pub access_token: AccessTokenConfig,
    /// Long-lived rotating refresh tokens.
    pub refresh_token: RefreshTokenConfig,
    /// Where signing keys come from and how often they roll.
    pub signing_keys: SigningKeysConfig,
}

/// Access-token issuance (`docs/03-LLD.md §5`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AccessTokenConfig {
    /// Signature algorithm. A closed enum, and never read from a token header — that is the K8
    /// algorithm-confusion defence and it belongs in configuration, not in the token.
    pub algorithm: SigningAlgorithm,
    /// Lifetime of an ordinary access token. Short by design: revocation of a bearer token is
    /// approximate, so the window is the real control.
    pub ttl: HumanDuration,
    /// Lifetime for privileged sessions, shorter still.
    pub privileged_ttl: HumanDuration,
    /// `iss` claim. Defaults to `None` so it is taken from `server.public_url` rather than being
    /// silently wrong.
    pub issuer: Option<String>,
    /// `aud` claim.
    pub audience: String,
}

impl Default for AccessTokenConfig {
    fn default() -> Self {
        Self {
            algorithm: SigningAlgorithm::EdDsa,
            ttl: HumanDuration::from_secs(600),
            privileged_ttl: HumanDuration::from_secs(300),
            issuer: None,
            audience: "enclave-api".to_owned(),
        }
    }
}

/// Supported JWT signature algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SigningAlgorithm {
    /// Ed25519. The only supported choice: it has no parameter that can be weakened, and a closed
    /// set of one makes downgrade attacks structurally impossible.
    #[default]
    #[serde(rename = "EdDSA")]
    EdDsa,
}

/// Refresh-token rotation (`docs/03-LLD.md §5`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RefreshTokenConfig {
    /// How long a refresh token survives without use.
    pub idle_ttl: HumanDuration,
    /// Hard upper bound regardless of use, so a stolen family cannot live forever.
    pub absolute_ttl: HumanDuration,
    /// Whether presenting a refresh token consumes it and issues a successor. On by default;
    /// turning it off removes the only signal that makes reuse detection possible.
    pub rotation: bool,
    /// What happens when a consumed token is presented again.
    pub reuse_detection: ReuseDetection,
    /// Cookie carrying the refresh token.
    pub cookie: CookieConfig,
}

impl Default for RefreshTokenConfig {
    fn default() -> Self {
        Self {
            idle_ttl: HumanDuration::from_secs(14 * 86_400),
            absolute_ttl: HumanDuration::from_secs(90 * 86_400),
            rotation: true,
            reuse_detection: ReuseDetection::RevokeFamily,
            cookie: CookieConfig::default(),
        }
    }
}

/// Response to a replayed refresh token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReuseDetection {
    /// Revoke the whole token family. The default: a replay means either the client or the
    /// attacker holds a copy, and there is no way to tell which, so both must lose the session.
    #[default]
    RevokeFamily,
    /// Revoke only the replayed token. Weaker; offered because some legacy clients race their own
    /// refreshes.
    RevokeToken,
    /// Record and allow. Diagnostics only — never appropriate in production.
    LogOnly,
}

/// Refresh cookie attributes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CookieConfig {
    /// Cookie name.
    pub name: String,
    /// `SameSite` attribute.
    pub same_site: SameSite,
    /// Path scope. Narrow by default so the refresh token is not attached to every API call and
    /// therefore not exposed to every handler.
    pub path: String,
    /// `Secure` attribute. On by default; the loader does not relax it for development, because a
    /// development default that disables it has a way of reaching production.
    pub secure: bool,
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            name: "enclave_rt".to_owned(),
            same_site: SameSite::Strict,
            path: "/api/v1/auth".to_owned(),
            secure: true,
        }
    }
}

/// `SameSite` cookie attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SameSite {
    /// Never sent cross-site. The default.
    #[default]
    Strict,
    /// Sent on top-level navigations.
    Lax,
    /// Sent cross-site; requires `Secure`.
    None,
}

/// Where JWT signing keys come from (`plans/M0-FOUNDATIONS.md` D5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SigningKeysConfig {
    /// Reference to the key material — `vault://…`, `env://…`, `file://…`. **Never a literal**
    /// (`CLAUDE.md` rule 11), which is why the type is a [`SecretRef`] and not a `String`: there is
    /// no field here that *can* hold a key.
    ///
    /// The resolved value is standard base64 of an Ed25519 PKCS#8 DER document, which is the one
    /// encoding `enclave_auth::ConfiguredKeyProvider` accepts. That type argues why it is one
    /// encoding and not two.
    ///
    /// `None` is a **development** posture and only a development one. `crates/api/src/main.rs`
    /// builds `LocalFileKeyProvider` over [`Self::directory`] in that case, and it can only do so
    /// for a `community` profile bound to a loopback address — see `SigningKeys::choose` there for
    /// the mechanism and for exactly what it does and does not close off. Every other deployment
    /// with nothing here refuses to start.
    pub key_ref: Option<SecretRef>,
    /// Where the **development** key provider keeps the key it generates on first run.
    ///
    /// Read only when [`Self::key_ref`] is absent, and only by the branch that is reachable in a
    /// `community` profile. It is a path and not a secret reference because it names a directory
    /// rather than a value; the directory must be outside the repository or git-ignored, and
    /// `deploy/config/dev-keys/` — the default — is the latter.
    ///
    /// Nothing is read from the repository, because nothing is committed to it: the provider
    /// generates its first key on demand and writes it `0600`.
    pub directory: PathBuf,
    /// How often a new signing key is introduced.
    pub rotation_interval: HumanDuration,
    /// How long the retired key stays in the JWKS so tokens signed just before rotation still
    /// verify.
    pub overlap: HumanDuration,
}

impl Default for SigningKeysConfig {
    fn default() -> Self {
        Self {
            key_ref: None,
            directory: PathBuf::from("deploy/config/dev-keys"),
            rotation_interval: HumanDuration::from_secs(90 * 86_400),
            overlap: HumanDuration::from_secs(86_400),
        }
    }
}

/// Password hashing, MFA and fail-closed behaviour.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Password policy and hashing parameters.
    pub password: PasswordConfig,
    /// Multi-factor requirements.
    pub mfa: MfaConfig,
    /// What to do when the privileged-token denylist cannot be reached. Failing closed means an
    /// outage locks admins out; failing open means a revoked admin token keeps working. The first
    /// is an incident, the second is a breach.
    pub privileged_denylist_failure: FailureMode,
}

/// Password policy and Argon2id parameters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PasswordConfig {
    /// Minimum length.
    pub min_length: u32,
    /// Maximum length, bounded so a very long password cannot be used to make hashing a denial of
    /// service.
    pub max_length: u32,
    /// Whether to check candidate passwords against a breach corpus.
    pub breach_check: bool,
    /// Argon2id cost parameters.
    pub argon2: Argon2Config,
    /// Optional secret mixed into every password hash, held outside the database so a database dump
    /// alone is not enough to mount an offline attack.
    pub pepper: Option<SecretRef>,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            min_length: 12,
            max_length: 128,
            breach_check: true,
            argon2: Argon2Config::default(),
            pepper: None,
        }
    }
}

/// Argon2id cost parameters (`docs/08-BYO-INFRA.md §15`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Argon2Config {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Time cost.
    pub iterations: u32,
    /// Lanes.
    pub parallelism: u32,
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self { memory_kib: 65_536, iterations: 3, parallelism: 4 }
    }
}

/// Multi-factor requirements.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct MfaConfig {
    /// Whether administrators must hold a second factor.
    pub admins_required: bool,
    /// How recently a step-up must have happened for a privileged action to proceed.
    pub step_up_max_age: HumanDuration,
}

impl Default for MfaConfig {
    fn default() -> Self {
        Self { admins_required: true, step_up_max_age: HumanDuration::from_secs(900) }
    }
}

/// Behaviour when a control's inputs are unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailureMode {
    /// Deny. The default everywhere in this file: a control that cannot evaluate has not allowed.
    #[default]
    FailClosed,
    /// Allow. Must be chosen explicitly, and shows up in a config diff when it is.
    FailOpen,
}

/// Data-loss prevention (`docs/06-SECURITY-DLP-ACCESS.md §9`, `§12`).
///
/// # Why `enabled` is gone
///
/// It used to sit beside `default_mode`, and the two could contradict each other — `enabled: false`
/// with `default_mode: ENFORCE` had no defined answer. `DISABLED` is one of `docs/06 §9`'s five
/// modes rather than the absence of a mode, so the setting is the mode, and
/// [`AntivirusProvider::None`] is the precedent: one key, with a "no" value, and an `is_enabled()`
/// accessor for the code that only wants the boolean.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DlpConfig {
    /// The mode DLP runs in for policies that do not name their own.
    pub default_mode: DlpMode,
    /// What to do when the security facts a rule needs are missing or stale (`docs/06 §12`).
    pub facts_unavailable: FactsUnavailablePolicy,
    /// The rank at which this tenant's labels become `RESTRICTED`.
    ///
    /// A configured number rather than the constant 50 because ranks are tenant-defined
    /// (`enclave_core::ClassificationRank`), and D27 makes `FAIL_CLOSED` mandatory at and above it
    /// whatever `facts_unavailable` says. Raising it is a widening of that escalation, and putting
    /// it in configuration is what makes the widening appear in a diff.
    pub restricted_at: i32,
}

impl Default for DlpConfig {
    fn default() -> Self {
        Self {
            default_mode: DlpMode::Monitor,
            facts_unavailable: FactsUnavailablePolicy::FailClosed,
            restricted_at: ClassificationRank::RESTRICTED.get(),
        }
    }
}

impl DlpConfig {
    /// Whether DLP inspects content at all.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        !matches!(self.default_mode, DlpMode::Disabled)
    }

    /// The tenant policy `enclave_core::FactsSnapshot::require` is evaluated under.
    ///
    /// Both halves of `FactsPolicy` come from this one accessor so that a deployment cannot end up
    /// with the mode from configuration and the boundary from a default — which would silently
    /// move where D27's mandatory escalation applies.
    #[must_use]
    pub fn facts_policy(&self) -> FactsPolicy {
        FactsPolicy::from_tenant_config(
            self.facts_unavailable.into(),
            ClassificationRank::new(self.restricted_at),
        )
    }
}

/// What happens when the security facts a rule needs are missing or stale (`docs/06 §12`).
///
/// # Why this is not [`FailureMode`]
///
/// Two reasons, and the second is the load-bearing one.
///
/// The spellings differ: `docs/06 §12` names these `FAIL_CLOSED` and **`FAIL_OPEN_AUDIT`**, and the
/// suffix is not decoration — the mode is "allow, record a high-visibility audit event, and enqueue
/// a priority rescan", so a key spelled `FAIL_OPEN` would promise an operator something weaker than
/// what happens and something stronger than what `FailureMode::FailOpen` means elsewhere.
///
/// And this is the only route into `enclave_core::FactsUnavailable`, which deliberately implements
/// neither `Deserialize` nor `FromStr` (D27): there must be no path from bytes on the wire to a
/// value of it, so that a *request* cannot carry an override even as a field somebody meant to
/// ignore. Configuration is not the wire, so the deserializable half lives here and converts. The
/// duplication is the price of that guarantee, and `the_two_spellings_of_facts_unavailable_agree`
/// is what stops the two drifting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FactsUnavailablePolicy {
    /// Deny the sensitive action and explain that scanning is in progress. The default, and
    /// mandatory for `RESTRICTED` and for external sharing whatever this says.
    #[default]
    FailClosed,
    /// Allow, record a high-visibility audit event, and enqueue a priority rescan.
    FailOpenAudit,
}

impl From<FactsUnavailablePolicy> for FactsUnavailable {
    fn from(value: FactsUnavailablePolicy) -> Self {
        match value {
            FactsUnavailablePolicy::FailClosed => Self::FailClosed,
            FactsUnavailablePolicy::FailOpenAudit => Self::FailOpenAudit,
        }
    }
}

/// How a tenant's DLP policy is being run (`docs/06-SECURITY-DLP-ACCESS.md §9`).
///
/// The operator-facing half of `enclave_dlp::DlpMode`. Five values, not two: the earlier
/// `monitor`/`enforce` pair could not express the rollout `plans/M4-GOVERNANCE.md §2` is built
/// around — *a control that cannot be turned on gradually will be turned on carelessly, or not at
/// all* — and `docs/06 §9` requires simulation before enforcement for any `BLOCK` or `QUARANTINE`
/// policy, which needs `SIMULATION` to be a value somebody can write down.
///
/// The canonical spellings are `docs/06 §9`'s uppercase ones. The lowercase aliases are kept
/// because they are what the earlier two-value key accepted, and refusing to load a file over the
/// case of a word it has always used is a worse outcome than accepting both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DlpMode {
    /// No content inspection at any enforcement point.
    #[serde(alias = "disabled")]
    Disabled,
    /// Record matches, allow the action. The default, so a new deployment does not block work
    /// before its rules have been tuned.
    #[default]
    #[serde(alias = "monitor")]
    Monitor,
    /// Evaluate exactly as `ENFORCE` would and record what it would have done, without doing it.
    #[serde(alias = "simulation")]
    Simulation,
    /// Apply the obligations matches demand, but never refuse.
    #[serde(alias = "warn")]
    Warn,
    /// Block on match.
    #[serde(alias = "enforce")]
    Enforce,
}

/// Audit trail (`docs/08-BYO-INFRA.md §14`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    /// Whether audit events are written at all. Disabling it is refused in the enterprise profile.
    pub enabled: bool,
    /// Whether each event carries the hash of its predecessor, making retroactive edits detectable.
    pub hash_chain: bool,
    /// Where periodic chain anchors are published, if anywhere. An anchor outside the system is
    /// what makes the chain evidence rather than self-assertion.
    pub external_anchor: Option<Url>,
    /// How long audit events are retained.
    pub retention_days: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self { enabled: true, hash_chain: true, external_anchor: None, retention_days: 400 }
    }
}

/// Malware scanning (`docs/08-BYO-INFRA.md §9`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AntivirusConfig {
    /// Which engine. `none` is refused in the enterprise profile.
    pub provider: AntivirusProvider,
    /// Engine endpoint, e.g. a `clamd` address. Not a secret — a host and port.
    pub endpoint: Option<String>,
    /// The `endpoint_env` spelling from `docs/08-BYO-INFRA.md §15`.
    pub endpoint_env: Option<String>,
    /// Objects larger than this are not scanned inline.
    pub max_scan_bytes: u64,
    /// How deep to descend into archives before treating them as unscannable.
    pub archive_depth: u32,
    /// Per-object scan timeout.
    pub timeout: HumanDuration,
    /// What to do with an object when the scanner is unreachable. `HOLD` keeps the file in
    /// `SCANNING`, which is the only state consistent with "nothing is `AVAILABLE` before antivirus
    /// completes" (CLAUDE.md rule 9).
    pub unavailable_policy: UnavailablePolicy,
    /// What to do with content no engine inspected — `BLOCK` or `ALLOW_WITH_FLAG`.
    ///
    /// `ALLOW_WITH_FLAG` is what makes a deployment with `provider: none` usable. It does **not**
    /// reach `CONFIDENTIAL` and above: `ScanPolicy::blocks_unsupported` refuses those on rank
    /// regardless of this key, so the setting buys availability for ordinary content and changes
    /// nothing for the content that matters most.
    #[serde(default)]
    pub unsupported_policy: UnsupportedPolicy,
}

impl AntivirusConfig {
    /// The effective engine address, preferring `endpoint` over the `endpoint_env` shorthand.
    ///
    /// **`endpoint_env` was declared, documented and read by nothing** (`ENC-952`). `docs/08 §15`
    /// specifies the spelling, `enclave.yaml` ships it, `README.md` tells an operator to
    /// `export CLAMD_ADDR=…` — and `ClamavScanner::new` reads `endpoint`, which nothing populated
    /// from it. The consequence is not subtle: `enclave-worker` refuses to start with
    /// *"antivirus.endpoint is required"* on a deployment configured exactly as documented, and
    /// since the worker is what moves `av_status`, **nothing in that deployment ever becomes
    /// `AVAILABLE`**.
    ///
    /// Read directly from the environment rather than through a [`SecretRef`], unlike
    /// [`DatabaseConfig::url_ref`] beside it. That is deliberate and follows the field's own
    /// documentation: an engine address is *"not a secret — a host and port"*, so routing it
    /// through the secret provider would require a provider to be configured before antivirus can
    /// start, and would put a non-secret in the one place `CLAUDE.md` rule 11 reserves for secrets.
    ///
    /// An `endpoint_env` naming an unset variable returns [`None`], which the scanner reports as
    /// the missing-endpoint error it already has. A blank value is treated as unset for the same
    /// reason the scanner trims: `export CLAMD_ADDR=` is an operator who meant to set it.
    #[must_use]
    pub fn endpoint_ref(&self) -> Option<String> {
        if let Some(endpoint) = self.endpoint.as_deref().map(str::trim).filter(|e| !e.is_empty()) {
            return Some(endpoint.to_owned());
        }
        let name = self.endpoint_env.as_deref()?;
        std::env::var(name).ok().map(|value| value.trim().to_owned()).filter(|v| !v.is_empty())
    }
}

impl Default for AntivirusConfig {
    fn default() -> Self {
        Self {
            provider: AntivirusProvider::Clamav,
            endpoint: None,
            endpoint_env: None,
            max_scan_bytes: 2_147_483_648,
            archive_depth: 5,
            timeout: HumanDuration::from_secs(120),
            unavailable_policy: UnavailablePolicy::Hold,
            unsupported_policy: UnsupportedPolicy::Block,
        }
    }
}

impl AntivirusConfig {
    /// Whether any scanning happens. Used by profile validation, and by read paths that must refuse
    /// to serve unscanned content.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        !matches!(self.provider, AntivirusProvider::None)
    }
}

/// Antivirus engine selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AntivirusProvider {
    /// Embedded `libclamav` or `clamd` over TCP or socket.
    #[default]
    Clamav,
    /// Enterprise ICAP gateway.
    Icap,
    /// Vendor HTTP scanning API.
    Http,
    /// Explicitly disabled. Spelled out rather than expressed as `enabled: false` so that turning
    /// scanning off is a visible, greppable choice in the configuration diff.
    None,
}

/// What to do with content no scanner inspected.
///
/// `docs/06-SECURITY-DLP-ACCESS.md §6.2`, and the one setting that decides whether a deployment
/// running `antivirus.provider: none` can serve anything at all.
///
/// This key did not exist until now, and its absence was deliberate: `ScanPolicy::from_config`
/// pinned `BLOCK` on the argument that a control expressed as a configuration default is a control
/// somebody turns off — the shape `ENC-157` removed from `preview.watermark_cache`. The counter-
/// argument, which the repo owner made and which decides it, is that a developer on a machine with
/// no scanner available is not choosing to weaken a control; they are choosing to run the product
/// at all, and a setting they cannot express is one they route around by other means.
///
/// So the key exists in every profile. What stands between it and a silent production bypass is not
/// its absence but its noise, and `ENC-828` is what makes the noise the *only* thing standing there:
/// until then this key changed nothing at all, because `enclave_versions::READABLE_PREDICATE`
/// refused `SKIPPED` and `ALLOW_WITH_FLAG` published versions no delivery route would serve. It now
/// does what it says. What remains is:
///
/// * both binaries log at start-up, at **error** level under `BLOCK` and **warn** under
///   `ALLOW_WITH_FLAG`, what this deployment will do with unscanned content;
/// * `CONFIDENTIAL` and above are refused on rank alone, whatever this key says
///   (`ScanPolicy::blocks_unsupported`), so the setting never reaches the content the rule exists
///   to protect;
/// * a version admitted this way is recorded `SKIPPED` and **never** `CLEAN`, so it stays
///   distinguishable from scanned content forever and is re-offered automatically the moment a
///   scanning engine answers, rather than left to be rediscovered;
/// * the `enterprise` profile refuses `provider: none` outright (`docs/08-BYO-INFRA.md §19`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnsupportedPolicy {
    /// Refuse it. The default, and what `CONFIDENTIAL` and above always get regardless.
    #[default]
    Block,
    /// Publish it, marked unscanned, so a later signature update revisits it.
    AllowWithFlag,
}

/// What to do when the scanner is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnavailablePolicy {
    /// Keep the object in `SCANNING` until a scanner is reachable.
    #[default]
    Hold,
    /// Publish and rescan later. Trades a malware window for availability; must be chosen.
    AllowAndRescan,
}

const fn default_true() -> bool {
    true
}

/// Five minutes; see [`S3StorageConfig::signed_url_ttl`].
fn default_signed_url_ttl() -> HumanDuration {
    HumanDuration::from_secs(5 * 60)
}

/// One hour. The ceiling exists for multipart uploads, whose parts are signed once and used over
/// the life of the transfer.
fn default_max_signed_url_ttl() -> HumanDuration {
    HumanDuration::from_secs(60 * 60)
}

/// Prefer an explicit reference, otherwise interpret a `*_env` field as `env://NAME`.
fn env_ref(explicit: Option<&SecretRef>, env_name: Option<&str>) -> Option<SecretRef> {
    if let Some(reference) = explicit {
        return Some(reference.clone());
    }
    let name = env_name?;
    SecretRef::new(SecretScheme::Env, name, None::<String>).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use enclave_core::Exposure;

    /// `antivirus.endpoint_env` is read (`ENC-952`).
    ///
    /// **It was declared, documented and read by nothing.** `docs/08 §15` specifies the spelling,
    /// `enclave.yaml` ships `endpoint_env: "CLAMD_ADDR"`, `README.md` tells an operator to export
    /// it — and `ClamavScanner::new` read `endpoint`, which nothing populated from it. The result
    /// is not a degraded feature: `enclave-worker` refuses to start with *"antivirus.endpoint is
    /// required"* on a deployment configured exactly as documented, and the worker is what moves
    /// `av_status`, so **nothing in that deployment ever becomes `AVAILABLE`**.
    ///
    /// All four arms are asserted because each is a different way to get this wrong, and three of
    /// them look harmless: an explicit `endpoint` must still win (otherwise adding the shorthand
    /// silently changes deployments that never used it), an unset variable must read as absent
    /// rather than as an empty address the scanner would try to connect to, and a blank export must
    /// too — `export CLAMD_ADDR=` is an operator who meant to set it.
    #[test]
    fn the_antivirus_endpoint_env_shorthand_is_actually_read() {
        // A name no other test uses: these run in one process and the environment is shared.
        const VAR: &str = "ENCLAVE_TEST_ENC952_CLAMD";

        let mut config =
            AntivirusConfig { endpoint_env: Some(VAR.to_owned()), ..Default::default() };

        std::env::remove_var(VAR);
        assert_eq!(
            config.endpoint_ref(),
            None,
            "an endpoint_env naming an unset variable is absent, not an empty address"
        );

        std::env::set_var(VAR, "   ");
        assert_eq!(
            config.endpoint_ref(),
            None,
            "a blank export is an operator who meant to set it, and connecting to \"\" would \
             report a connect error that says nothing useful"
        );

        std::env::set_var(VAR, " clamd.internal:3310 ");
        assert_eq!(
            config.endpoint_ref(),
            Some("clamd.internal:3310".to_owned()),
            "this is the whole defect: the shorthand every document tells an operator to use was \
             read by nothing, and the worker refused to start"
        );

        config.endpoint = Some("explicit:3310".to_owned());
        assert_eq!(
            config.endpoint_ref(),
            Some("explicit:3310".to_owned()),
            "an explicit endpoint wins, or introducing the shorthand changes the behaviour of \
             deployments that never used it"
        );

        std::env::remove_var(VAR);
    }

    #[test]
    fn defaults_are_the_safe_choice() {
        let config = Config::default();
        assert_eq!(config.profile, DeploymentProfile::Community);
        assert_eq!(config.server.bind, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(config.server.trusted_proxies.is_empty());
        assert!(config.auth.refresh_token.rotation);
        assert_eq!(config.auth.refresh_token.reuse_detection, ReuseDetection::RevokeFamily);
        assert!(config.auth.refresh_token.cookie.secure);
        assert_eq!(config.security.privileged_denylist_failure, FailureMode::FailClosed);
        assert_eq!(config.dlp.facts_unavailable, FactsUnavailablePolicy::FailClosed);
        assert_eq!(config.dlp.default_mode, DlpMode::Monitor);
        assert!(config.dlp.is_enabled(), "MONITOR inspects content; it simply does not refuse");
        assert_eq!(config.dlp.restricted_at, ClassificationRank::RESTRICTED.get());
        assert!(config.audit.enabled);
        assert!(config.audit.hash_chain);
        assert!(config.antivirus.is_enabled());
        assert_eq!(config.antivirus.unavailable_policy, UnavailablePolicy::Hold);
        assert_eq!(config.ocr_mounts(), OcrMounts::Absent);

        // Deny by default for both providers. `enclave-worker` keys off these: with no store it
        // does not schedule the indexing pass at all, rather than scheduling one whose `claim`
        // commits before the read that will fail and burns the `attempts` budget on every file it
        // touches. `None` here is the difference between a legible absence and a poisoned corpus.
        assert_eq!(config.storage.provider, StorageProvider::None);
        assert!(config.storage.s3.is_none());
        assert_eq!(config.search.provider, SearchProvider::None);
        assert!(config.search.milvus.is_none());

        // The exposition is unauthenticated and carries tenant labels, so a deployment that never
        // chose a port must not have one open — on either process.
        assert_eq!(config.metrics.api_port, None);
        assert_eq!(config.metrics.worker_port, None);
    }

    #[test]
    fn the_two_mount_keys_are_spelled_the_way_the_environment_spells_them() {
        // The whole reason these are top-level keys. The loader derives an environment override
        // from the field path, so a nested `indexing.ocr_models` would be reachable only as
        // `ENCLAVE_INDEXING__OCR_MODELS` — while CI's fetch steps, `crates/indexing/tests/{ocr,pdf}.rs`
        // and the runbook in `docs/11` all say `ENCLAVE_OCR_MODELS` and `ENCLAVE_PDFIUM`. Two
        // spellings for one directory is the drift; this asserts there is one.
        //
        // Deliberate violation: renaming either field, or nesting it under a section, fails this
        // test by name — the derived path no longer matches the variable CI sets.
        let loaded = crate::ConfigLoader::new()
            .with_env([
                ("ENCLAVE_OCR_MODELS", "/mnt/enclave/ocr-models"),
                ("ENCLAVE_PDFIUM", "/mnt/enclave/pdfium/lib"),
            ])
            .load()
            .unwrap();

        assert_eq!(
            loaded.config().ocr_mounts(),
            OcrMounts::Mounted {
                models: Path::new("/mnt/enclave/ocr-models"),
                pdfium: Path::new("/mnt/enclave/pdfium/lib"),
            }
        );
    }

    #[test]
    fn half_a_mount_is_reported_as_half_a_mount_and_never_as_none() {
        // The tri-state's reason for existing. Folding this into `Absent` would give an operator who
        // staged the weights and forgot PDFium exactly the silence D24 is about.
        let models = Config { ocr_models: Some(PathBuf::from("/mnt/m")), ..Config::default() };
        assert_eq!(
            models.ocr_mounts(),
            OcrMounts::Incomplete { present: "ocr_models", missing: "pdfium" }
        );

        let pdfium = Config { pdfium: Some(PathBuf::from("/mnt/p")), ..Config::default() };
        assert_eq!(
            pdfium.ocr_mounts(),
            OcrMounts::Incomplete { present: "pdfium", missing: "ocr_models" }
        );
    }

    #[test]
    fn the_embedding_mount_is_spelled_the_way_the_environment_spells_it() {
        // The same argument as the two OCR keys above, applied before a second spelling can exist:
        // `crates/embeddings/tests/mounted.rs`, `crates/worker/tests/embedding_mount.rs`, CI's fetch
        // step and `docs/08 §18.1` all say `ENCLAVE_EMBEDDING_MODEL`, and a nested
        // `embedding.local.model` would be reachable only as `ENCLAVE_EMBEDDING__LOCAL__MODEL`.
        //
        // Deliberate violation: renaming the field, or nesting it under a section, fails this test
        // by name — the derived path stops matching the variable everything else sets.
        let loaded = crate::ConfigLoader::new()
            .with_env([
                ("ENCLAVE_EMBEDDING_MODEL", "/mnt/enclave/bge-m3"),
                ("ENCLAVE_SEARCH__PROVIDER", "milvus"),
                ("ENCLAVE_SEARCH__MILVUS__URI", "http://milvus:19530"),
            ])
            .load()
            .unwrap();

        assert_eq!(
            loaded.config().embedding_mounts(),
            EmbeddingMounts::Mounted { model: Path::new("/mnt/enclave/bge-m3") }
        );
    }

    #[test]
    fn a_model_with_nowhere_to_put_its_vectors_is_reported_as_half_a_mount() {
        // `ENC-661`. The operator staged 2.2 GB of weights against `search.provider: none`: nothing
        // fails, no stage is built, and dense search has always returned nothing. `Absent` here
        // would be that silence.
        let model =
            Config { embedding_model: Some(PathBuf::from("/mnt/bge-m3")), ..Config::default() };
        assert_eq!(
            model.embedding_mounts(),
            EmbeddingMounts::Incomplete { present: "embedding_model", missing: "search.milvus" }
        );
    }

    #[test]
    fn a_vector_store_without_a_model_is_the_ordinary_deployment_and_not_a_problem() {
        // The asymmetry with `ocr_mounts`, asserted rather than left to the doc comment — and it is
        // the assertion that stops this check refusing every deployment that exists today.
        // `search.milvus` is what the coverage probe takes its census through and what the query
        // side reads candidates from; its presence is not a claim that anything embeds.
        //
        // Without this test, an implementation that reported `Incomplete` in both directions would
        // satisfy the one above and break every existing configuration.
        let store = Config {
            search: SearchConfig {
                provider: SearchProvider::Milvus,
                milvus: Some(MilvusSettings {
                    uri: "http://milvus:19530".parse().unwrap(),
                    token: None,
                    collection: None,
                }),
            },
            ..Config::default()
        };
        assert_eq!(store.embedding_mounts(), EmbeddingMounts::Absent);

        // And the default — neither — is `Absent` too, which is what every deployment has.
        assert_eq!(Config::default().embedding_mounts(), EmbeddingMounts::Absent);
    }

    #[test]
    fn a_mount_path_is_not_treated_as_a_credential() {
        // The positive control for the classification argued in the field documentation: these are
        // paths, not secrets, so they are neither `SecretRef`s nor listed in `secret_refs()`, and
        // the inline-credential scanner must stay quiet on them. If it did not, a perfectly ordinary
        // configuration file would refuse to start.
        let yaml = "
ocr_models: /var/lib/enclave/ocr-models
pdfium: /var/lib/enclave/pdfium/lib
database:
  url_env: DATABASE_URL
";
        let loaded =
            crate::ConfigLoader::new().without_env().with_yaml("t.yaml", yaml).load().unwrap();
        let refs = loaded.config().secret_refs();
        assert_eq!(
            refs.iter().map(|(path, _)| path.as_str()).collect::<Vec<_>>(),
            vec!["database.url"],
            "a mount path was enrolled as a secret reference"
        );
    }

    #[test]
    fn documented_env_shorthands_become_references() {
        let yaml = "
database:
  url_env: DATABASE_URL
redis:
  url_env: REDIS_URL
events:
  nats_url_env: NATS_URL
";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.database.url_ref().unwrap().to_string(), "env://DATABASE_URL");
        assert_eq!(config.redis.url_ref().unwrap().to_string(), "env://REDIS_URL");
        assert_eq!(config.events.nats_url_ref().unwrap().to_string(), "env://NATS_URL");
    }

    #[test]
    fn an_explicit_reference_wins_over_the_shorthand() {
        let yaml = "
database:
  url: vault://workspace/db#dsn
  url_env: DATABASE_URL
";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.database.url_ref().unwrap().to_string(), "vault://workspace/db#dsn");
    }

    #[test]
    fn secret_refs_are_enumerated_with_their_paths() {
        let yaml = "
database:
  url_env: DATABASE_URL
  platform_url_env: DATABASE_PLATFORM_URL
security:
  password:
    pepper: vault://workspace/password#pepper
auth:
  signing_keys:
    key_ref: vault://workspace/jwt#ed25519
";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let refs = config.secret_refs();
        let paths: Vec<&str> = refs.iter().map(|(path, _)| path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                "database.url",
                "database.platform_url",
                "auth.signing_keys.key_ref",
                "security.password.pepper"
            ]
        );
    }

    /// The `BYPASSRLS` DSN is a secret, is absent by default, and never borrows the ordinary one.
    ///
    /// Three assertions rather than one, because the failure modes differ and only the first is
    /// caught by the enumeration above. A `platform_url` that fell back to `url` would hand the
    /// tenant enumerator a pool row-level security applies to, with no tenant context — which
    /// returns zero rows, so the worker would idle while every health check stayed green.
    #[test]
    fn the_platform_dsn_is_absent_by_default_and_never_falls_back() {
        assert!(DatabaseConfig::default().platform_url_ref().is_none());

        let yaml = "
database:
  url_env: DATABASE_URL
";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.database.url_ref().is_some(), "the ordinary DSN is set");
        assert!(
            config.database.platform_url_ref().is_none(),
            "a deployment that configured no BYPASSRLS role must get None, not the app DSN"
        );
    }

    /// The `storage:` block of `docs/08-BYO-INFRA.md §15`, parsed field for field.
    ///
    /// The document is authoritative for what an operator writes and this module is only its typed
    /// form, so a spelling that appears there and not here is a file that documents a key nothing
    /// reads. That is not hypothetical: `deploy/config/enclave.example.yaml` carried
    /// `access_key_env`, `secret_key_env` and `force_path_style` for three milestones, and every one
    /// of them loaded silently because the whole section was ignored.
    #[test]
    fn the_documented_storage_section_parses_field_for_field() {
        let yaml = "
storage:
  provider: s3
  s3:
    bucket: enclave-content
    region: eu-west-1
    endpoint: https://s3.eu-west-1.amazonaws.com
    flavor: aws
    path_style: false
    access_key_id: vault://workspace/s3#access_key_id
    secret_access_key: vault://workspace/s3#secret_access_key
    signed_url_ttl: 5m
    max_signed_url_ttl: 1h
";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.storage.provider, StorageProvider::S3);

        let s3 = config.storage.s3.unwrap();
        assert_eq!(s3.bucket, "enclave-content");
        assert_eq!(s3.region, "eu-west-1");
        assert_eq!(s3.endpoint.unwrap().host_str(), Some("s3.eu-west-1.amazonaws.com"));
        assert_eq!(s3.flavor, S3Flavor::Aws);
        assert!(!s3.path_style);
        assert_eq!(s3.signed_url_ttl.as_secs(), 300);
        assert_eq!(s3.max_signed_url_ttl.as_secs(), 3600);
    }

    /// An S3 secret access key written as a literal is a **type** error, not a validation one.
    ///
    /// `CLAUDE.md` rule 11 enforced by the model rather than by the heuristic scanner: there is no
    /// field on [`S3StorageConfig`] that can hold a key, so the deserializer refuses before
    /// `scan_for_inline_secrets` is asked to have an opinion. That matters because the scanner is
    /// entropy-based and deliberately generous — a short or low-entropy key would slip past it.
    ///
    /// Deliberate violation: relaxing either credential field to `String` makes this parse, and the
    /// test fails by name.
    #[test]
    fn a_literal_s3_credential_does_not_deserialize() {
        let literal = "
storage:
  provider: s3
  s3:
    bucket: enclave-content
    region: us-east-1
    access_key_id: env://S3_ACCESS_KEY_ID
    secret_access_key: wJalrXUtnFEMIK7MDENGbPxRfiCY
";
        let err = serde_yaml::from_str::<Config>(literal).unwrap_err();
        assert!(err.to_string().contains("scheme"), "got: {err}");
        assert!(
            !err.to_string().contains("wJalrXUtnFEMIK"),
            "the offending value must never be echoed: {err}"
        );

        // A low-entropy key the scanner would wave through, refused just the same.
        let short = literal.replace("wJalrXUtnFEMIK7MDENGbPxRfiCY", "minioadmin");
        assert!(serde_yaml::from_str::<Config>(&short).is_err());
    }

    /// The costly typo in the `s3:` block is the silent one, so unknown keys are refused there.
    ///
    /// `force_path_style` was the real spelling in `deploy/config/enclave.example.yaml`.
    /// Ignored, it leaves `path_style` at its default and produces a DNS failure against a
    /// self-hosted endpoint that reads as a network problem — a day of debugging for a key nobody
    /// parsed.
    ///
    /// The *outer* section stays permissive on purpose, which the second half asserts: `§15` also
    /// documents `storage.profile`, naming a row in the per-tenant `storage_profiles` table that no
    /// migration creates yet, and an operator's complete file must still load.
    #[test]
    fn a_typo_inside_the_s3_block_is_refused_and_an_unmodelled_sibling_is_not() {
        let typo = "
storage:
  provider: s3
  s3:
    bucket: enclave-content
    region: us-east-1
    force_path_style: true
    access_key_id: env://S3_ACCESS_KEY_ID
    secret_access_key: env://S3_SECRET_ACCESS_KEY
";
        let err = serde_yaml::from_str::<Config>(typo).unwrap_err();
        assert!(err.to_string().contains("force_path_style"), "got: {err}");

        let reserved = "
storage:
  profile: tenant-default
  provider: s3
  s3:
    bucket: enclave-content
    region: us-east-1
    access_key_id: env://S3_ACCESS_KEY_ID
    secret_access_key: env://S3_SECRET_ACCESS_KEY
";
        let config: Config = serde_yaml::from_str(reserved).unwrap();
        assert_eq!(config.storage.provider, StorageProvider::S3);
    }

    /// The embedding width is not a key, and writing one is refused rather than ignored.
    ///
    /// `MilvusConfig::dimension` is fixed when the collection is created and a mismatch errors at
    /// neither end — Milvus accepts the width it was made with, the model emits the width it was
    /// trained at — so a wrong number here is silently degraded retrieval and a fleet-wide
    /// re-embed to correct. An operator who writes `dimension: 768` must find out at start-up.
    ///
    /// Deliberate violation: dropping `deny_unknown_fields` from [`MilvusSettings`] makes this
    /// parse, and the test fails by name.
    #[test]
    fn the_embedding_width_is_not_a_configuration_key() {
        let yaml = "
search:
  provider: milvus
  milvus:
    uri: http://milvus:19530
    dimension: 768
";
        let err = serde_yaml::from_str::<Config>(yaml).unwrap_err();
        assert!(err.to_string().contains("dimension"), "got: {err}");
    }

    /// The storage and search credentials are enrolled by field path, and nothing else new is.
    ///
    /// Enrolment is what makes an unresolvable S3 key a start-up failure that names
    /// `storage.s3.access_key_id`, rather than a provider error on the first upload. The list is
    /// asserted whole so that a field added to either section without a `secret_refs` entry — the
    /// way a credential goes unchecked — fails here.
    #[test]
    fn storage_and_search_credentials_are_enrolled_with_their_paths() {
        let yaml = "
database:
  url_env: DATABASE_URL
storage:
  provider: s3
  s3:
    bucket: enclave-content
    region: us-east-1
    access_key_id: env://S3_ACCESS_KEY_ID
    secret_access_key: vault://workspace/s3#secret
    session_token: env://S3_SESSION_TOKEN
search:
  provider: milvus
  milvus:
    uri: http://milvus:19530
    token: vault://workspace/milvus#token
";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let refs = config.secret_refs();
        let paths: Vec<&str> = refs.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                "database.url",
                "storage.s3.access_key_id",
                "storage.s3.secret_access_key",
                "storage.s3.session_token",
                "search.milvus.token",
            ]
        );

        // The optional halves are optional: absent means absent, never an empty reference that
        // would fail to resolve and take the process down with it.
        let minimal: Config = serde_yaml::from_str(
            "
storage:
  provider: s3
  s3:
    bucket: b
    region: r
    access_key_id: env://A
    secret_access_key: env://B
",
        )
        .unwrap();
        let refs = minimal.secret_refs();
        let paths: Vec<&str> = refs.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(paths, vec!["storage.s3.access_key_id", "storage.s3.secret_access_key"]);
    }

    /// Both metrics ports are off by default, and they are two fields rather than one.
    ///
    /// The default matters as much as the split: the exposition is unauthenticated and carries
    /// tenant labels, so a deployment that never chose a port must not have one open.
    #[test]
    fn the_metrics_listeners_are_two_ports_and_both_are_closed_by_default() {
        let metrics = MetricsConfig::default();
        assert_eq!(metrics.api_port, None);
        assert_eq!(metrics.worker_port, None);
        assert_eq!(metrics.api_addr(), None);
        assert_eq!(metrics.worker_addr(), None);
        assert_eq!(metrics.bind, IpAddr::V4(Ipv4Addr::LOCALHOST));

        let config: Config = serde_yaml::from_str(
            "
metrics:
  bind: 10.0.0.7
  api_port: 9464
  worker_port: 9465
",
        )
        .unwrap();
        assert_eq!(
            config.metrics.api_addr().unwrap().to_string(),
            "10.0.0.7:9464",
            "the API's socket"
        );
        assert_eq!(
            config.metrics.worker_addr().unwrap().to_string(),
            "10.0.0.7:9465",
            "the worker's, which used to be the same socket"
        );
    }

    #[test]
    fn unmodelled_sections_do_not_fail_the_parse() {
        // Whole sections land in later milestones; an operator's complete file must still load.
        let yaml = "
storage:
  profile: tenant-default
mcp:
  enabled: true
";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config, Config::default());
    }

    /// The two spellings of `facts_unavailable` are one vocabulary, held in two types for D27's
    /// sake. A test rather than a comment, because the whole point of the duplication is that the
    /// compiler cannot check it.
    #[test]
    fn the_two_spellings_of_facts_unavailable_agree() {
        for (configured, domain) in [
            (FactsUnavailablePolicy::FailClosed, FactsUnavailable::FailClosed),
            (FactsUnavailablePolicy::FailOpenAudit, FactsUnavailable::FailOpenAudit),
        ] {
            assert_eq!(FactsUnavailable::from(configured), domain);
            // `docs/06 §12` names them, and an audit row records them; the YAML key an operator
            // writes must be the same string.
            let yaml = serde_yaml::to_string(&configured).expect("serialize");
            assert!(
                yaml.trim().trim_matches('\'').ends_with(domain.as_str()),
                "the configured spelling {yaml:?} is not the documented {}",
                domain.as_str()
            );
        }
    }

    /// `restricted_at` is where D27's mandatory escalation applies, and it must survive the trip
    /// from YAML into the type the chain actually consults.
    #[test]
    fn the_facts_policy_is_built_from_both_configured_keys() {
        let yaml = "
dlp:
  default_mode: SIMULATION
  facts_unavailable: FAIL_OPEN_AUDIT
  restricted_at: 30
";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.dlp.default_mode, DlpMode::Simulation);

        let policy = config.dlp.facts_policy();
        assert_eq!(policy.on_unavailable(), FactsUnavailable::FailOpenAudit);
        // The boundary moved with the key: a rank of 30 is now RESTRICTED for this tenant, and 29
        // is not. Asserted through the predicate rather than through a getter, because the
        // predicate is what decides a request.
        let read = enclave_core::Action::File(enclave_core::FileAction::ContentRead);
        assert!(policy.is_forced_closed(
            read,
            Some(ClassificationRank::new(30)),
            Exposure::Internal
        ));
        assert!(!policy.is_forced_closed(
            read,
            Some(ClassificationRank::new(29)),
            Exposure::Internal
        ));

        // And the default is not silently substituted when the key is absent.
        let bare: Config = serde_yaml::from_str("dlp:\n  default_mode: ENFORCE\n").unwrap();
        assert_eq!(bare.dlp.restricted_at, ClassificationRank::RESTRICTED.get());
    }

    /// `DISABLED` is a mode, not the absence of one, and it is the only one that turns DLP off.
    #[test]
    fn disabled_is_the_only_mode_that_stops_dlp_evaluating() {
        for (mode, enabled) in [
            (DlpMode::Disabled, false),
            (DlpMode::Monitor, true),
            (DlpMode::Simulation, true),
            (DlpMode::Warn, true),
            (DlpMode::Enforce, true),
        ] {
            let dlp = DlpConfig { default_mode: mode, ..DlpConfig::default() };
            assert_eq!(dlp.is_enabled(), enabled, "{mode:?}");
        }
    }

    /// Every mode `docs/06 §9` names must be writable, in both the documented spelling and the one
    /// the two-value key used to accept.
    #[test]
    fn every_documented_dlp_mode_parses_in_either_case() {
        for (written, expected) in [
            ("DISABLED", DlpMode::Disabled),
            ("MONITOR", DlpMode::Monitor),
            ("SIMULATION", DlpMode::Simulation),
            ("WARN", DlpMode::Warn),
            ("ENFORCE", DlpMode::Enforce),
            ("disabled", DlpMode::Disabled),
            ("monitor", DlpMode::Monitor),
            ("simulation", DlpMode::Simulation),
            ("warn", DlpMode::Warn),
            ("enforce", DlpMode::Enforce),
        ] {
            let yaml = format!("dlp:\n  default_mode: {written}\n");
            let config: Config = serde_yaml::from_str(&yaml).expect(written);
            assert_eq!(config.dlp.default_mode, expected, "{written}");
        }

        // The control: a value that is not a mode is refused rather than defaulted to MONITOR.
        // Without this, every assertion above would also pass against a lenient deserializer.
        assert!(serde_yaml::from_str::<Config>("dlp:\n  default_mode: mostly\n").is_err());
    }

    #[test]
    fn documented_enum_spellings_parse() {
        let yaml = "
profile: enterprise
auth:
  access_token:
    algorithm: EdDSA
  refresh_token:
    reuse_detection: REVOKE_FAMILY
    cookie:
      same_site: strict
antivirus:
  provider: none
  unavailable_policy: HOLD
dlp:
  default_mode: monitor
security:
  privileged_denylist_failure: FAIL_CLOSED
";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.profile, DeploymentProfile::Enterprise);
        assert_eq!(config.auth.access_token.algorithm, SigningAlgorithm::EdDsa);
        assert!(!config.antivirus.is_enabled());
    }

    #[test]
    fn trusted_proxies_parse_as_cidr_and_hops() {
        let yaml = "
server:
  trusted_proxies:
    - cidr: 10.20.0.0/16
      hops: 1
";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.server.trusted_proxies.len(), 1);
        assert_eq!(config.server.trusted_proxies[0].hops, 1);
        assert_eq!(config.server.trusted_proxies[0].cidr.to_string(), "10.20.0.0/16");
    }
}
