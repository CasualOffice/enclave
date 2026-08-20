//! The Milvus-backed candidate generator.
//!
//! # What this module is, in one line
//!
//! It turns a query embedding into `Vec<Candidate>` and stops. It is the fake in
//! `tests/postfilter.rs` made real, and it is deliberately no more privileged than that fake was:
//! [`crate::PostFilter::confirm`] runs on its output exactly as it runs on a hand-written `Vec`,
//! and there is no argument anywhere below that changes what the post-filter checks.
//!
//! Read [`crate::vector`] for what this client's pre-filter is allowed to be wrong about. The short
//! form: everything, in the permissive direction, with no consequence — and `acl_tokens` never
//! appear in an expression it emits.
//!
//! # Why the filter is a template and not a `format!`
//!
//! Milvus filters are an expression language, and the values interpolated into one here are a
//! tenant id and a library id set. Building the string with `format!` would make a boolean
//! expression out of values that arrive from a request context, and the failure mode is not
//! hypothetical politeness about injection: an expression that parses differently than intended
//! silently *widens* the scan, and a widened scan is only ever caught by the post-filter — which is
//! to say, never observed. [`build_filter`] emits `{placeholder}` and passes values as templates,
//! so a malformed identifier is a rejected request rather than a differently-shaped one.
//!
//! # Reachability is probed; a failed query is not a probe
//!
//! [`crate::degraded`] draws the line this module has to respect. A single timed-out or failed
//! search is an error — it becomes [`SearchError::VectorIndex`] and the search fails, because an
//! outage returned as "no matches" is a search that lies confidently. What engages degraded mode is
//! [`MilvusIndex::reachability`], a state question answered by a cheap probe, and the answer to
//! that question on failure is [`VectorStore::Unreachable`] rather than an error.
//!
//! The probe is `has_collection`, which covers both conditions `crate::degraded` names: the
//! connection cannot be made, and the collection is not there to load. An **absent** collection
//! therefore degrades rather than erroring, which is right for a fresh install — lexical results
//! flagged `degraded: true` beat a 503 while somebody runs the provisioning step.
//!
//! ## Two failure modes of this probe, stated rather than discovered
//!
//! It cannot distinguish *down* from *up but refusing*: a server returning permission errors reads
//! as unreachable. That errs toward degraded mode, which costs recall and never correctness, and it
//! is the side to err on.
//!
//! It also cannot see a collection that exists and is **empty or wrong** — a botched rebuild, a
//! tenant that was never indexed. That is not this probe's job and it must not become it: a
//! `has_collection` answers a question about the server, and asking it to answer a question about
//! the contents would put a per-tenant aggregate in front of every request. The separate signal is
//! [`IndexCensus`], implemented below and compared against `index_manifests` by `crate::health` in
//! a background loop.
//!
//! There is no circuit breaker in front of this yet, so the probe reconnects inline and every
//! request during an outage pays `connect_timeout` once. Keep that timeout short. The write lock
//! held across the reconnect is not incidental — it collapses a thundering herd of connect attempts
//! into one, which is the behaviour a breaker would eventually provide anyway.

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use enclave_core::FileId;
use milvus::v2 as sdk;
use sdk::prelude::{
    CollectionSchema, ConnectConfig, ConsistencyLevel, DataType, FieldSchema, IndexParam,
    IndexType, MetricType, SearchResults, SearchVectors,
};
use tokio::sync::RwLock;

use crate::degraded::VectorStore;
use crate::error::SearchError;
use crate::health::IndexCensus;
use crate::postfilter::Candidate;
use crate::vector::{field, VectorIndex, VectorQuery, COLLECTION};

/// HNSW parameters from `docs/07-SEARCH-INDEXING.md §4`.
const HNSW_M: &str = "32";
/// HNSW parameters from `docs/07-SEARCH-INDEXING.md §4`.
const HNSW_EF_CONSTRUCTION: &str = "256";

/// The similarity the dense index is built for.
///
/// Cosine because it is what sentence-embedding models are trained against, and because it is the
/// one choice that survives a model whose vectors are not unit-normalised. It must match the model
/// (`plans/M3-DISCOVERY.md` Q14 has not settled which model), and a mismatch does not fail — it
/// ranks badly, which is the kind of defect that gets attributed to the embeddings for a month.
const DENSE_METRIC: MetricType = MetricType::Cosine;

/// Inner product for the learned-sparse side of the hybrid, which is how sparse scores compose.
const SPARSE_METRIC: MetricType = MetricType::Ip;

/// UUIDs are 36 characters; the headroom is for the day one of these becomes a prefixed form.
const ID_LENGTH: u32 = 64;
/// `chunk_id` is deterministic per `(version, chunker, ordinal)` and so is longer than a bare id.
const CHUNK_ID_LENGTH: u32 = 128;
/// Filenames, and the boosted lexical field cut from them.
const TITLE_LENGTH: u32 = 1024;
/// Chunk body. Sized above any chunk `plans/M3-DISCOVERY.md` Q13 is likely to choose; a chunk that
/// exceeds this is truncated by the server, which loses text silently, so Q13 must land under it.
const TEXT_LENGTH: u32 = 8192;
/// Token arrays. Generous because a token set that overflows its capacity is rejected at insert
/// time, and an insert that fails is a file that is silently unfindable.
const TOKEN_CAPACITY: u32 = 512;
/// One ACL or barrier token.
const TOKEN_LENGTH: u32 = 128;
/// Deep-link fields.
const PATH_LENGTH: u32 = 1024;

/// Where the store is and how patiently to wait for it.
///
/// `token` is a resolved secret, not a reference: `CLAUDE.md` rule 11 governs what may sit in a
/// YAML file, and by the time a value reaches this struct it has already been dereferenced from
/// `vault://…`. The [`std::fmt::Debug`] implementation redacts it, because a config struct is the
/// thing that ends up in a panic message.
#[derive(Clone)]
pub struct MilvusConfig {
    /// gRPC endpoint.
    pub uri: String,
    /// `user:password`, already resolved. `None` for an unauthenticated development stack.
    pub token: Option<String>,
    /// How long a connection attempt may take before the store counts as unreachable.
    ///
    /// Short on purpose: with no circuit breaker in front, this is paid per request while the store
    /// is down, and a long timeout turns an outage that degraded mode handles gracefully into one
    /// that exhausts the request budget first.
    pub connect_timeout: Duration,
    /// Per-attempt RPC deadline.
    pub rpc_timeout: Duration,
    /// How long [`MilvusIndex::ensure_collection`] waits for the collection to load.
    ///
    /// Much longer than [`Self::rpc_timeout`] because it covers building indexes over whatever is
    /// already in the collection, not one round trip. This is provisioning, which happens once at
    /// start-up and has no user waiting on it; a short deadline here turns a large tenant's cold
    /// start into a start-up failure.
    pub load_timeout: Duration,
    /// The collection to read. Defaults to `docs/07 §4`'s.
    pub collection: String,
    /// Embedding width, set by the model.
    ///
    /// **This must be `enclave_embeddings::model::ACTIVE.dimension`** — 1024, for `bge-m3`, which
    /// is Q14's answer. It is not defaulted here and this crate does not depend on `embeddings`, so
    /// nothing enforces the agreement at compile time; the caller that builds the collection is
    /// responsible for reading it from there rather than typing a number.
    ///
    /// Why that matters more than an ordinary config field: the width is fixed when the collection
    /// is *created*. A mismatch does not error at either end — Milvus accepts vectors of the width
    /// it was created with, and the model emits the width it was trained at — so the failure is a
    /// dimension error at insert if you are lucky, and silently degraded retrieval if you are not.
    /// Correcting it afterwards means a new collection and every chunk of every tenant re-embedded
    /// (`docs/07 §9`).
    ///
    /// `ENC-533` tracks making this a compile-time agreement, once a crate exists that depends on
    /// both and can hold the assertion without a dependency invented for the purpose.
    pub dimension: u32,
    /// Partition-key partitions.
    ///
    /// Too few and two tenants share a partition, so one tenant's scan touches the other's vectors
    /// — a cost, and not a correctness problem, because the post-filter is what makes cross-tenant
    /// results impossible and `tests/postfilter.rs` S5 proves it. Too many and the collection's
    /// fixed memory overhead grows for tenants that hold nothing.
    pub partitions: i64,
    /// Read consistency.
    ///
    /// [`ConsistencyLevel::Bounded`] in production: the index is stale by construction between an
    /// ACL write and an index write (`docs/07 §6`), so paying for a strong read of a candidate
    /// generator buys precision in the one place it cannot help.
    ///
    /// It is configurable for a specific reason rather than for symmetry. A test that inserts and
    /// then searches under `Bounded` fails intermittently, and an intermittently failing search
    /// test is one somebody eventually marks `#[ignore]` — which `CLAUDE.md` forbids for exactly
    /// these tests. The knob removes the pressure.
    pub consistency: ConsistencyLevel,
}

impl MilvusConfig {
    /// A configuration pointing at `uri` with the defaults above.
    #[must_use]
    pub fn new(uri: impl Into<String>, dimension: u32) -> Self {
        Self {
            uri: uri.into(),
            token: None,
            connect_timeout: Duration::from_secs(2),
            rpc_timeout: Duration::from_secs(10),
            load_timeout: Duration::from_secs(300),
            collection: COLLECTION.to_owned(),
            dimension,
            partitions: 64,
            consistency: ConsistencyLevel::Bounded,
        }
    }
}

impl std::fmt::Debug for MilvusConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MilvusConfig")
            .field("uri", &self.uri)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .field("connect_timeout", &self.connect_timeout)
            .field("rpc_timeout", &self.rpc_timeout)
            .field("load_timeout", &self.load_timeout)
            .field("collection", &self.collection)
            .field("dimension", &self.dimension)
            .field("partitions", &self.partitions)
            .field("consistency", &self.consistency)
            .finish()
    }
}

/// A handle to the vector store that exists whether or not the store does.
///
/// Constructing one performs no I/O, which is what lets a node start while Milvus is down and serve
/// degraded results instead of failing its readiness check — `plans/M3-DISCOVERY.md` D25 is a
/// contract about the response, and a process that will not boot cannot honour it.
pub struct MilvusIndex {
    config: MilvusConfig,
    session: RwLock<Option<sdk::ClientV2>>,
}

impl std::fmt::Debug for MilvusIndex {
    /// Reports whether a session is currently held rather than the client itself, which has no
    /// `Debug` and whose interesting state is exactly that one bit.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MilvusIndex")
            .field("config", &self.config)
            .field("connected", &self.session.try_read().map(|held| held.is_some()).ok())
            .finish()
    }
}

impl MilvusIndex {
    /// Builds a handle. Touches nothing.
    #[must_use]
    pub fn new(config: MilvusConfig) -> Self {
        Self { config, session: RwLock::new(None) }
    }

    /// The configuration this handle was built with.
    #[must_use]
    pub const fn config(&self) -> &MilvusConfig {
        &self.config
    }

    /// Returns a live client, connecting if there is not one.
    ///
    /// `None` means the store could not be reached — a state, deliberately not a `Result`, so that
    /// the two callers have to decide separately what an unreachable store means to them.
    async fn session(&self) -> Option<sdk::ClientV2> {
        if let Some(client) = self.session.read().await.clone() {
            return Some(client);
        }

        // The write lock spans the connect: see the module documentation on the thundering herd.
        let mut held = self.session.write().await;
        if let Some(client) = held.clone() {
            return Some(client);
        }

        let mut config = ConnectConfig::new()
            .uri(self.config.uri.clone())
            .connect_timeout(self.config.connect_timeout)
            .rpc_timeout(self.config.rpc_timeout);
        if let Some(token) = self.config.token.clone() {
            config = config.token(token);
        }

        let client = sdk::ClientV2::new(&config).await.ok()?;
        *held = Some(client.clone());
        Some(client)
    }

    /// Forgets the current session so the next call reconnects.
    ///
    /// Called when a probe fails. Without it a client cached before the store went away keeps being
    /// handed out, and `reachability` reports the health of a connection nobody can use.
    async fn forget_session(&self) {
        *self.session.write().await = None;
    }

    /// Creates the collection of `docs/07-SEARCH-INDEXING.md §4` if it is absent, and verifies its
    /// partition key if it is present.
    ///
    /// The verification is the part worth having. A collection created by hand, by an older
    /// revision of this code, or by a restore from a differently-shaped backup can be missing the
    /// partition key — in which case every tenant's query scans every tenant's vectors. That is a
    /// cost defect and not a leak, because the post-filter is what makes cross-tenant results
    /// impossible, but it is a cost defect that is invisible until somebody profiles it, so it
    /// fails loudly here instead.
    ///
    /// Idempotent: running it against a correct collection is a `has_collection` and a describe.
    ///
    /// # Errors
    ///
    /// An unreachable store, a rejected DDL, or a collection whose partition key is not
    /// [`field::TENANT_ID`].
    pub async fn ensure_collection(&self) -> Result<(), SearchError> {
        let client = self
            .session()
            .await
            .ok_or(SearchError::VectorIndex { operation: "connect", retryable: true })?;

        let exists = client
            .has_collection(
                sdk::request::collection::HasCollectionRequest::builder()
                    .collection_name(self.config.collection.clone())
                    .build()
                    .map_err(|_| invalid_request("has_collection"))?,
            )
            .await
            .map_err(|error| failed("has_collection", &error))?
            .exists();

        if !exists {
            client
                .create_collection(
                    sdk::request::collection::CreateCollectionRequest::builder()
                        .collection_name(self.config.collection.clone())
                        .schema(collection_schema(self.config.dimension))
                        .num_partitions(self.config.partitions)
                        .index_params(index_params())
                        .build()
                        .map_err(|_| invalid_request("create_collection"))?,
                )
                .await
                .map_err(|error| failed("create_collection", &error))?;
        }

        // Loaded synchronously, and on the already-exists path too. `create_collection` starts the
        // load as an unawaited follow-up, so returning here without waiting would leave a window
        // where `reachability` reports `Available` — the collection exists — and every search
        // against it fails because it is not in query-node memory. Loading an already-loaded
        // collection is a no-op, which is what makes running this on every start cheap.
        client
            .load_collection(
                sdk::request::collection::LoadCollectionRequest::builder()
                    .collection_name(self.config.collection.clone())
                    .sync(true)
                    .timeout_ms(self.config.load_timeout.as_millis().try_into().unwrap_or(i64::MAX))
                    .build()
                    .map_err(|_| invalid_request("load_collection"))?,
            )
            .await
            .map_err(|error| failed("load_collection", &error))?;

        match self.partition_key().await? {
            Some(ref name) if name == field::TENANT_ID => Ok(()),
            _ => Err(SearchError::VectorCollection {
                reason: "the collection's partition key is not `tenant_id`",
            }),
        }
    }

    /// The partition-key field the server says the collection has, read back rather than assumed.
    ///
    /// `None` when no field is marked, which is the shape a collection created without a partition
    /// key has.
    ///
    /// # Errors
    ///
    /// An unreachable store, or a describe that fails.
    pub async fn partition_key(&self) -> Result<Option<String>, SearchError> {
        let client = self
            .session()
            .await
            .ok_or(SearchError::VectorIndex { operation: "connect", retryable: true })?;

        let described = client
            .describe_collection(
                sdk::request::collection::DescribeCollectionRequest::builder()
                    .collection_name(self.config.collection.clone())
                    .build()
                    .map_err(|_| invalid_request("describe_collection"))?,
            )
            .await
            .map_err(|error| failed("describe_collection", &error))?;

        Ok(described
            .description()
            .get_schema()
            .get_fields()
            .iter()
            .find(|schema| schema.is_partition_key())
            .map(|schema| schema.get_name().to_owned()))
    }
}

#[async_trait]
impl VectorIndex for MilvusIndex {
    async fn candidates(&self, query: VectorQuery<'_>) -> Result<Vec<Candidate>, SearchError> {
        let client = self
            .session()
            .await
            .ok_or(SearchError::VectorIndex { operation: "connect", retryable: true })?;

        let (filter, templates) = build_filter(&query);
        let request = sdk::request::dql::SearchRequest::builder()
            .collection_name(self.config.collection.clone())
            .vector_field(field::DENSE_VECTOR)
            .vectors(SearchVectors::Float(vec![query.embedding.to_vec()]))
            .filter(filter)
            .filter_templates(templates)
            .output_fields([field::FILE_ID, field::TEXT])
            .limit(i64::from(query.budget))
            .consistency_level(self.config.consistency)
            .build()
            .map_err(|_| invalid_request("search"))?;

        let response = client.search(request).await.map_err(|error| failed("search", &error))?;
        decode(response.results())
    }

    async fn reachability(&self) -> VectorStore {
        let Some(client) = self.session().await else {
            return VectorStore::Unreachable;
        };

        let request = sdk::request::collection::HasCollectionRequest::builder()
            .collection_name(self.config.collection.clone())
            .build();
        let Ok(request) = request else {
            // A request this module built itself does not validate. Nothing about the store is
            // known, and claiming it is available on the strength of a bug here would engage the
            // vector path against a client that cannot form a query.
            return VectorStore::Unreachable;
        };

        match client.has_collection(request).await {
            Ok(response) if response.exists() => VectorStore::Available,
            Ok(_) => VectorStore::Unreachable,
            Err(_) => {
                self.forget_session().await;
                VectorStore::Unreachable
            }
        }
    }
}

#[async_trait]
impl IndexCensus for MilvusIndex {
    /// Counts this tenant's chunks with a server-side `count(*)`.
    ///
    /// Server-side because the alternative — paging entities back to count them — turns a health
    /// probe into a scan of the collection, and the probe would then be the most expensive thing
    /// the process does. `crate::health` calls this on an interval, per tenant, and never inside a
    /// request.
    ///
    /// The expression constrains the partition key, so the count is of one tenant's partition and
    /// not of the collection. That is not an isolation control — nothing here is, see
    /// [`crate::vector`] — but it is the difference between a signal and a number: a census that
    /// counted every tenant's chunks would report a healthy total for a tenant whose own chunks are
    /// all gone, which is precisely the failure this exists to catch.
    ///
    /// Read at the configured consistency, which is [`ConsistencyLevel::Bounded`] in production. A
    /// count that lags a few seconds behind the newest inserts cannot move a signal whose threshold
    /// is half the collection.
    async fn chunks(&self, tenant: enclave_core::TenantId) -> Result<u64, SearchError> {
        let client = self
            .session()
            .await
            .ok_or(SearchError::VectorIndex { operation: "connect", retryable: true })?;

        let (filter, templates) = census_filter(tenant);
        let request = sdk::request::dql::QueryRequest::builder()
            .collection_name(self.config.collection.clone())
            .filter(filter)
            .filter_templates(templates)
            .output_fields([COUNT_STAR])
            .consistency_level(self.config.consistency)
            .build()
            .map_err(|_| invalid_request("count"))?;

        let response = client.query(request).await.map_err(|error| failed("count", &error))?;
        Ok(response.results().get_row_count())
    }
}

/// The aggregate output field Milvus recognises. Not a field on the collection, which is why it is
/// not in [`field`].
const COUNT_STAR: &str = "count(*)";

/// The census expression: one tenant's partition, and nothing else.
///
/// Separate from [`build_filter`] rather than sharing it, because the two answer different
/// questions and coupling them would make a narrowing added for retrieval quietly narrow the health
/// signal too — a census that skipped a library the caller cannot see would report that library's
/// chunks as missing.
fn census_filter(tenant: enclave_core::TenantId) -> (String, HashMap<String, serde_json::Value>) {
    let filter = format!("{} == {{tenant}}", field::TENANT_ID);
    let templates =
        HashMap::from([("tenant".to_owned(), serde_json::Value::from(tenant.to_string()))]);
    (filter, templates)
}

/// Builds the filter expression and its template values.
///
/// Returns them together because they are meaningless apart — an expression naming `{libraries}`
/// with no binding for it is rejected by the server, and the pairing is what makes that
/// unconstructible here.
fn build_filter(query: &VectorQuery<'_>) -> (String, HashMap<String, serde_json::Value>) {
    let mut clauses = Vec::with_capacity(3);
    let mut templates = HashMap::with_capacity(3);

    // The partition key. Milvus routes to a single partition only when the expression constrains
    // it, so this clause is what makes `num_partitions` do anything at all. It is not the tenant
    // isolation control — see `crate::vector`.
    clauses.push(format!("{} == {{tenant}}", field::TENANT_ID));
    templates.insert("tenant".to_owned(), serde_json::Value::from(query.tenant.to_string()));

    let libraries = query.prefilter.libraries();
    if !libraries.is_empty() {
        clauses.push(format!("{} in {{libraries}}", field::LIBRARY_ID));
        let values: Vec<serde_json::Value> =
            libraries.iter().map(|library| serde_json::Value::from(library.to_string())).collect();
        templates.insert("libraries".to_owned(), serde_json::Value::Array(values));
    }

    if let Some(ceiling) = query.prefilter.ceiling() {
        clauses.push(format!("{} <= {{ceiling}}", field::CLASSIFICATION_RANK));
        templates.insert("ceiling".to_owned(), serde_json::Value::from(ceiling.get()));
    }

    (clauses.join(" and "), templates)
}

/// Turns one search response into candidates, keeping the best chunk of each file.
///
/// A file is chunked, so a search over chunks proposes the same file several times. Passing those
/// duplicates through would resolve one file's permissions five times, and — worse — make
/// [`crate::DropCounts::proposed`] a count of chunks while `drop_ratio` is read as a fraction of
/// documents. The exit criteria tune over-fetch from that ratio, so a metric that means something
/// else is a metric that tunes the wrong number.
///
/// Order is preserved from the server's ranking; the first sighting of a file is its best-scoring
/// chunk, so the first-wins rule below is also the highest-score rule.
fn decode(results: &SearchResults) -> Result<Vec<Candidate>, SearchError> {
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut seen: std::collections::HashSet<FileId> = std::collections::HashSet::new();

    for single in results.iter() {
        let scores = single.get_scores();
        let rows = single.rows().map_err(|_| SearchError::MalformedRow {
            column: "results",
            reason: "the server's columns disagree on row count",
        })?;

        for row in rows {
            let file_id: FileId = row
                .get_str(field::FILE_ID)
                .map_err(|_| SearchError::MalformedRow {
                    column: "file_id",
                    reason: "missing or not a varchar",
                })?
                .parse()
                .map_err(|_| SearchError::MalformedRow {
                    column: "file_id",
                    reason: "not a uuid",
                })?;

            if !seen.insert(file_id) {
                continue;
            }

            let score = *scores.get(row.index()).ok_or(SearchError::MalformedRow {
                column: "score",
                reason: "fewer scores than rows",
            })?;

            // A chunk with no text is a legitimate state — a metadata-only update writes scalars
            // and vectors — so an absent excerpt is `None` and not a decode failure. Whether it is
            // *disclosed* is the post-filter's `ContentRead` question, which is asked either way.
            let excerpt = row.get_str(field::TEXT).ok().map(str::to_owned);

            candidates.push(Candidate { file_id, score, excerpt });
        }
    }

    Ok(candidates)
}

/// The collection schema of `docs/07-SEARCH-INDEXING.md §4`.
///
/// `tenant_id` carries the partition key, which is the field ordering in that table made
/// structural: it is first after the primary key because every query constrains it.
#[must_use]
pub fn collection_schema(dimension: u32) -> CollectionSchema {
    CollectionSchema::new()
        .add_field(
            FieldSchema::new()
                .name(field::CHUNK_ID)
                .data_type(DataType::VarChar)
                .max_length(CHUNK_ID_LENGTH)
                // Deterministic per `(version, chunker, ordinal)`, so re-indexing the same version
                // upserts in place rather than accumulating a second copy of every chunk. An
                // auto-generated key would make a reindex a duplication.
                .primary_key(true)
                .auto_id(false),
        )
        .add_field(
            FieldSchema::new()
                .name(field::TENANT_ID)
                .data_type(DataType::VarChar)
                .max_length(ID_LENGTH)
                .partition_key(true),
        )
        .add_field(required_varchar(field::WORKSPACE_ID, ID_LENGTH))
        .add_field(required_varchar(field::LIBRARY_ID, ID_LENGTH))
        .add_field(required_varchar(field::FILE_ID, ID_LENGTH))
        .add_field(required_varchar(field::VERSION_ID, ID_LENGTH))
        .add_field(required_varchar(field::CHUNK_TYPE, ID_LENGTH))
        .add_field(varchar(field::TITLE, TITLE_LENGTH))
        .add_field(required_varchar(field::TEXT, TEXT_LENGTH))
        .add_field(
            FieldSchema::new()
                .name(field::DENSE_VECTOR)
                .data_type(DataType::FloatVector)
                .dimension(dimension),
        )
        .add_field(
            FieldSchema::new().name(field::SPARSE_VECTOR).data_type(DataType::SparseFloatVector),
        )
        .add_field(FieldSchema::new().name(field::CLASSIFICATION_RANK).data_type(DataType::Int32))
        .add_field(token_array(field::ACL_TOKENS))
        .add_field(token_array(field::BARRIER_TOKENS))
        .add_field(FieldSchema::new().name(field::ACL_EPOCH).data_type(DataType::Int64))
        .add_field(required_varchar(field::MIME_TYPE, ID_LENGTH))
        .add_field(varchar(field::LANGUAGE, ID_LENGTH))
        .add_field(FieldSchema::new().name(field::PAGE_NUMBER).data_type(DataType::Int32))
        .add_field(varchar(field::SHEET_NAME, TITLE_LENGTH))
        .add_field(varchar(field::SECTION_PATH, PATH_LENGTH))
        .add_field(FieldSchema::new().name(field::MODIFIED_TIMESTAMP).data_type(DataType::Int64))
}

/// The indexes of `docs/07-SEARCH-INDEXING.md §4`.
///
/// The scalar indexes are not decoration. Without them the pre-filter's `tenant_id` and
/// `library_id` clauses are evaluated by scanning, which turns the narrowing that was supposed to
/// bound the scan into a second full pass over it.
fn index_params() -> Vec<IndexParam> {
    vec![
        IndexParam::new()
            .field_name(field::DENSE_VECTOR)
            .index_type(IndexType::Hnsw)
            .metric_type(DENSE_METRIC)
            .extra_params(HashMap::from([
                ("M".to_owned(), HNSW_M.to_owned()),
                ("efConstruction".to_owned(), HNSW_EF_CONSTRUCTION.to_owned()),
            ])),
        IndexParam::new()
            .field_name(field::SPARSE_VECTOR)
            .index_type(IndexType::SparseInvertedIndex)
            .metric_type(SPARSE_METRIC),
        scalar_index(field::TENANT_ID),
        scalar_index(field::WORKSPACE_ID),
        scalar_index(field::LIBRARY_ID),
        scalar_index(field::FILE_ID),
        scalar_index(field::CLASSIFICATION_RANK),
    ]
}

fn scalar_index(name: &str) -> IndexParam {
    IndexParam::new().field_name(name).index_type(IndexType::Inverted)
}

/// A field that may genuinely be absent: no sheet name, no detected language, no title.
///
/// Nullable rather than an empty-string sentinel, which would make "absent" and "empty" the same
/// value so that a filter written against one silently matches the other.
///
/// Use [`required_varchar`] for anything that identifies the chunk or narrows a search. There were
/// once not two helpers, and every VarChar built by one went through this one, so `file_id`,
/// `library_id`, `version_id`, `chunk_type`, `mime_type` and the chunk's own `text` were all
/// nullable. (`chunk_id` and `tenant_id` escaped it only because the primary key and the partition
/// key are spelled out above.)
///
/// A chunk with a NULL `file_id` is the bad one: the post-filter confirms candidates by resolving
/// their file against PostgreSQL, and a candidate naming no file cannot be resolved — so it is
/// dropped, silently, as though the search had simply not found it. That fails closed, which is why
/// it would have gone unnoticed; it is still a chunk that was indexed, costs storage, and can never
/// be returned to anyone.
fn varchar(name: &str, length: u32) -> FieldSchema {
    FieldSchema::new().name(name).data_type(DataType::VarChar).max_length(length).nullable(true)
}

/// A field every chunk has: its identity, its containers, its body.
///
/// Not nullable, so that a chunk missing one is refused by the server at insert rather than stored
/// and skipped at query time.
fn required_varchar(name: &str, length: u32) -> FieldSchema {
    FieldSchema::new().name(name).data_type(DataType::VarChar).max_length(length)
}

fn token_array(name: &str) -> FieldSchema {
    FieldSchema::new()
        .name(name)
        .data_type(DataType::Array)
        .element_type(DataType::VarChar)
        .max_capacity(TOKEN_CAPACITY)
        .max_length(TOKEN_LENGTH)
}

/// A request this module built failed the SDK's own validation.
///
/// Not retryable, and not carrying the SDK's message: a validation failure quotes the offending
/// parameter, which for a search is the filter expression, which holds the tenant and library
/// identifiers. `CLAUDE.md` rule 10 keeps those out of a log line, and the fixed operation name is
/// what an operator actually needs to find the call site.
const fn invalid_request(operation: &'static str) -> SearchError {
    SearchError::VectorIndex { operation, retryable: false }
}

/// Classifies an SDK failure, keeping the operation and discarding the message.
///
/// Same reason as [`invalid_request`]: a server error's display can echo the expression that
/// provoked it.
fn failed(operation: &'static str, error: &sdk::error::Error) -> SearchError {
    // Transport, deadline and exhausted-retry failures are the ones where trying again can work.
    // A server rejection, a conversion failure or a malformed response will fail identically the
    // second time, and marking those retryable turns one bad request into several.
    let retryable = matches!(
        error,
        sdk::error::Error::Grpc(_)
            | sdk::error::Error::Timeout(_)
            | sdk::error::Error::Cancelled(_)
            | sdk::error::Error::RetryExhausted { .. }
    );
    SearchError::VectorIndex { operation, retryable }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::{ClassificationRank, LibraryId, TenantId};

    use super::*;
    use crate::vector::Prefilter;

    fn query<'a>(
        tenant: TenantId,
        prefilter: &'a Prefilter,
        embedding: &'a [f32],
    ) -> VectorQuery<'a> {
        VectorQuery { tenant, embedding, budget: 200, prefilter }
    }

    /// The assertion this module exists to keep true.
    ///
    /// `acl_tokens` is a field on the collection — the indexer writes it, `docs/07 §4` lists it —
    /// and the whole design turns on nothing *reading* it as a permission. A filter clause naming
    /// it would be a second place where visibility is decided, stale by construction, trusted by
    /// nobody who wrote it and by everybody who reads the query plan afterwards.
    ///
    /// This is a string assertion rather than a type one because the tempting change is a string:
    /// one more `clauses.push` that measures well on a benchmark.
    #[test]
    fn no_filter_this_module_emits_ever_mentions_acl_tokens() {
        let tenant = TenantId::new_v7();
        let embedding = [0.0_f32; 4];

        let prefilters = [
            Prefilter::unnarrowed(),
            Prefilter::resolved_from_postgres(vec![LibraryId::new_v7()], None),
            Prefilter::resolved_from_postgres(Vec::new(), Some(ClassificationRank::new(2))),
            Prefilter::resolved_from_postgres(
                vec![LibraryId::new_v7(), LibraryId::new_v7()],
                Some(ClassificationRank::new(5)),
            ),
        ];

        for prefilter in &prefilters {
            let (filter, templates) = build_filter(&query(tenant, prefilter, &embedding));
            assert!(
                !filter.contains(field::ACL_TOKENS),
                "the pre-filter consulted the index about permissions: {filter}"
            );
            assert!(
                !templates.contains_key(field::ACL_TOKENS),
                "an acl_tokens binding reached the server: {templates:?}"
            );
            assert!(
                !filter.contains(field::BARRIER_TOKENS),
                "barriers are enforced in the policy chain, not here: {filter}"
            );
        }
    }

    #[test]
    fn every_filter_constrains_the_partition_key() {
        // Without this clause Milvus cannot route to one partition and scans them all. It is a
        // cost assertion, not a safety one — see the module documentation — but it is the whole
        // reason `num_partitions` is configurable.
        let tenant = TenantId::new_v7();
        let embedding = [0.0_f32; 4];
        let all = Prefilter::unnarrowed();

        let (filter, templates) = build_filter(&query(tenant, &all, &embedding));
        assert_eq!(filter, "tenant_id == {tenant}");
        assert_eq!(
            templates.get("tenant"),
            Some(&serde_json::Value::from(tenant.to_string())),
            "the tenant was interpolated somewhere other than the template binding"
        );
    }

    #[test]
    fn narrowing_appears_only_when_postgres_supplied_it() {
        let tenant = TenantId::new_v7();
        let embedding = [0.0_f32; 4];
        let (first, second) = (LibraryId::new_v7(), LibraryId::new_v7());
        let narrowed = Prefilter::resolved_from_postgres(
            vec![first, second],
            Some(ClassificationRank::new(3)),
        );

        let (filter, templates) = build_filter(&query(tenant, &narrowed, &embedding));
        assert_eq!(
            filter,
            "tenant_id == {tenant} and library_id in {libraries} and classification_rank <= \
             {ceiling}"
        );
        assert_eq!(
            templates.get("libraries"),
            Some(&serde_json::Value::Array(vec![
                serde_json::Value::from(first.to_string()),
                serde_json::Value::from(second.to_string()),
            ])),
            "the library set reached the server in a different order or shape than it was given"
        );
        assert_eq!(templates.get("ceiling"), Some(&serde_json::Value::from(3)));
    }

    /// `docs/07 §4`: one Milvus partition key per tenant.
    ///
    /// Asserted against the schema this module builds rather than against a live server, so that it
    /// holds on a machine that cannot run Milvus — which is where the mistake gets made, because
    /// the integration test that would have caught it is the one marked `#[ignore]`.
    #[test]
    fn tenant_id_is_the_partition_key_and_it_is_the_only_one() {
        let schema = collection_schema(768);
        let keys: Vec<&str> = schema
            .get_fields()
            .iter()
            .filter(|field| field.is_partition_key())
            .map(|field| field.get_name())
            .collect();
        assert_eq!(keys, vec![field::TENANT_ID]);
    }

    #[test]
    fn the_schema_is_the_one_docs_07_section_4_defines() {
        // Names, because the decoder and the indexer address fields by name and a typo here is a
        // runtime failure against a live server and nothing earlier.
        let schema = collection_schema(768);
        let names: Vec<&str> = schema.get_fields().iter().map(|field| field.get_name()).collect();
        assert_eq!(
            names,
            vec![
                field::CHUNK_ID,
                field::TENANT_ID,
                field::WORKSPACE_ID,
                field::LIBRARY_ID,
                field::FILE_ID,
                field::VERSION_ID,
                field::CHUNK_TYPE,
                field::TITLE,
                field::TEXT,
                field::DENSE_VECTOR,
                field::SPARSE_VECTOR,
                field::CLASSIFICATION_RANK,
                field::ACL_TOKENS,
                field::BARRIER_TOKENS,
                field::ACL_EPOCH,
                field::MIME_TYPE,
                field::LANGUAGE,
                field::PAGE_NUMBER,
                field::SHEET_NAME,
                field::SECTION_PATH,
                field::MODIFIED_TIMESTAMP,
            ]
        );

        let primary: Vec<&str> = schema
            .get_fields()
            .iter()
            .filter(|field| field.is_primary_key())
            .map(|field| field.get_name())
            .collect();
        assert_eq!(primary, vec![field::CHUNK_ID]);
        assert_eq!(
            schema
                .get_fields()
                .iter()
                .find(|field| field.get_name() == field::DENSE_VECTOR)
                .map(FieldSchema::get_dimension),
            Some(768)
        );
    }

    #[test]
    fn the_indexes_cover_every_field_the_pre_filter_constrains() {
        let params = index_params();
        let indexed: Vec<&str> = params.iter().map(|param| param.get_field_name()).collect();
        for constrained in [field::TENANT_ID, field::LIBRARY_ID, field::CLASSIFICATION_RANK] {
            assert!(
                indexed.contains(&constrained),
                "{constrained} is filtered on but has no scalar index, so the narrowing scans"
            );
        }
        assert!(indexed.contains(&field::DENSE_VECTOR));
        assert!(indexed.contains(&field::SPARSE_VECTOR));
    }

    /// The census counts *one tenant's* chunks, and the clause that makes that true is one line.
    ///
    /// Without it the count is of the whole collection, and a tenant whose partition was wiped
    /// reads as fully stocked on the strength of everybody else's data — the exact failure
    /// `crate::health` exists to catch, restored by deleting a clause. The live proof is
    /// `tests/milvus.rs::a_census_counts_only_the_tenant_it_was_asked_about`; this is the cheap
    /// echo of it that runs on a machine with no Milvus.
    #[test]
    fn the_census_expression_constrains_the_tenant_and_asks_for_a_count() {
        let tenant = TenantId::new_v7();
        let (filter, templates) = census_filter(tenant);
        assert_eq!(filter, "tenant_id == {tenant}");
        assert_eq!(
            templates.get("tenant"),
            Some(&serde_json::Value::from(tenant.to_string())),
            "the tenant was interpolated somewhere other than the template binding"
        );
        assert_eq!(COUNT_STAR, "count(*)", "the aggregate the SDK recognises, spelled exactly");
        assert!(
            !filter.contains(field::ACL_TOKENS),
            "a health probe has no business naming a permission field"
        );
    }

    #[test]
    fn a_token_is_never_rendered_by_debug() {
        // A config struct is what ends up in a panic message and a startup log line.
        let mut config = MilvusConfig::new("http://127.0.0.1:19530", 768);
        config.token = Some(format!("root:{}", "hunter2"));
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("hunter2"), "the Milvus token reached a log line: {rendered}");
        assert!(rendered.contains("REDACTED"));
    }
}
