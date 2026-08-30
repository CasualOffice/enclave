# 08 — BYO Infrastructure & Configuration

> **Status:** Draft · **Version:** 2.7 · **Owner:** Platform Engineering · **Last updated:** 2026-08-30
> **Authoritative for:** provider traits, BYO infrastructure, configuration model and precedence.

## 1. Principle

The platform must not force an enterprise to use platform-owned storage, secrets, mail, vector
database, embedding, LLM or antivirus infrastructure. Business logic depends on provider traits; no domain
crate references a cloud SDK.

## 2. Provider interfaces

| Trait | Crate | Purpose |
|---|---|---|
| `BlobStore` | `storage` | Object storage for versions and renditions |
| `SecretProvider` | `secrets` | Resolve secret references |
| `KeyProvider` | `secrets` | Signing and envelope-encryption keys |
| `MailProvider` | `mail` | Outbound email |
| `VectorStore` | `search` | Vector/hybrid retrieval |
| `EmbeddingProvider` | `embeddings` | Text embeddings, classification-routed |
| `LlmProvider` | `ai` | Chat/completion for RAG answers, summarization, auto-classification |
| `AntivirusScanner` | `antivirus` | Malware scanning of ingested content |
| `RenditionStore` | `preview` | Cached preview artifacts |
| `IdentityProvider` | `identity` | External authentication and directory sync |

```rust
#[async_trait]
pub trait BlobStore: Send + Sync {
    async fn create_upload(&self, request: UploadRequest) -> Result<UploadSession>;
    async fn complete_upload(&self, session: &UploadSession) -> Result<ObjectMeta>;
    async fn signed_download(&self, key: &str, ttl: Duration) -> Result<Url>;
    async fn read_range(&self, key: &str, range: ByteRange) -> Result<ByteStream>;
    async fn copy(&self, from: &str, to: &str) -> Result<()>;
    async fn delete(&self, key: &str) -> Result<()>;
    fn capabilities(&self) -> StoreCapabilities;   // multipart, single-use URLs, object lock
}

#[async_trait]
pub trait SecretProvider: Send + Sync {
    async fn read(&self, reference: &SecretRef) -> Result<SecretValue>;
    async fn health(&self) -> Result<()>;
}

#[async_trait]
pub trait KeyProvider: Send + Sync {
    async fn sign(&self, kid: &str, payload: &[u8]) -> Result<Vec<u8>>;
    async fn public_key(&self, kid: &str) -> Result<Vec<u8>>;
    async fn wrap_data_key(&self, key_ref: &str, dek: &[u8]) -> Result<Vec<u8>>;
    async fn unwrap_data_key(&self, key_ref: &str, wrapped: &[u8]) -> Result<Vec<u8>>;
}

#[async_trait]
pub trait MailProvider: Send + Sync {
    async fn send(&self, message: OutboundMail) -> Result<DeliveryId>;
    async fn verify(&self) -> Result<()>;          // admin "test connection"
}

#[async_trait]
pub trait VectorStore: Send + Sync {
    async fn upsert_chunks(&self, tenant: TenantId, chunks: Vec<IndexedChunk>) -> Result<()>;
    async fn update_metadata(&self, tenant: TenantId, updates: Vec<ChunkMetadataUpdate>) -> Result<()>;
    async fn search(&self, ctx: &SearchSecurityContext, request: SearchRequest) -> Result<Vec<SearchHit>>;
    async fn delete_file_version(&self, tenant: TenantId, file: FileId, version: VersionId) -> Result<()>;
    async fn delete_by_library(&self, tenant: TenantId, library: LibraryId) -> Result<()>;
}

#[async_trait]
pub trait EmbeddingProvider: Send + Sync {
    async fn embed(&self, classification: Classification, texts: &[String]) -> Result<Vec<Vec<f32>>>;
    fn model_id(&self) -> &str;
    fn dimensions(&self) -> usize;
    fn residency(&self) -> Residency;              // LOCAL, REGION(x), EXTERNAL
}

#[async_trait]
pub trait LlmProvider: Send + Sync {
    async fn complete(&self, request: LlmRequest) -> Result<LlmResponse>;
    async fn stream(&self, request: LlmRequest) -> Result<BoxStream<'_, Result<LlmDelta>>>;
    fn model_id(&self) -> &str;
    fn context_window(&self) -> usize;
    fn residency(&self) -> Residency;
    fn capabilities(&self) -> LlmCapabilities;   // streaming, tool use, json mode, vision
}

#[async_trait]
pub trait AntivirusScanner: Send + Sync {
    async fn scan(&self, stream: ByteStream, hint: ScanHint) -> Result<ScanVerdict>;
    async fn engine_info(&self) -> Result<EngineInfo>;
}
```

`SearchSecurityContext` is constructed entirely server-side:

```rust
pub struct SearchSecurityContext {
    pub tenant_id: TenantId,
    pub accessible_libraries: Vec<LibraryId>,
    pub allowed_barriers: Vec<String>,
    pub maximum_classification: i32,
    pub denylisted_files: Vec<FileId>,
}
```

`EmbeddingProvider::residency()` is what makes classification routing enforceable rather than
advisory — the `embeddings` crate refuses a `LOCAL_ONLY` classification on a provider that does not
report `Residency::Local`.

## 3. BYO object storage

Initial providers: local filesystem, generic S3-compatible, AWS S3, MinIO, Ceph, Cloudflare R2,
Wasabi, Backblaze B2 (S3 API). Later: Azure Blob, Google Cloud Storage.

Recommended scope: a tenant-level storage profile, with an optional workspace- or library-level
profile for regulated deployments.

Requirements for any provider used in production:

- server-side encryption at rest;
- pre-signed URL support with a configurable short TTL;
- multipart upload for large files;
- versioning or object-lock where records/legal hold are used;
- a bucket that is **not** publicly readable, verified by a startup self-check.

## 3A. Archival and cold storage (`ENC-946`)

A store may or may not have a colder tier. `StoreCapabilities.storage_tiers` reports it, and the two
verbs — `BlobStore::archive` and `BlobStore::request_restore` — default to
`StorageError::Unsupported` so a backend that cannot do this **says so** rather than accepting the
call and changing nothing.

**Refusing is the whole point.** The tempting alternative is to succeed, move nothing, and let the
caller record the version as archived. That produces a deployment where content is *marked*
unavailable while sitting in the hot bucket at hot prices, and every read path refuses it — a cost
saving that does not happen and an outage that does. It is the `UnconfiguredRetention` mistake in
another crate: a control that reports success and enforces nothing.

| Backend | `storage_tiers` | Why |
|---|---|---|
| AWS S3 (no endpoint override) | `Yes` | Glacier and Deep Archive, with `RestoreObject` |
| MinIO, Ceph, R2, any endpoint override | `No` | accepts a storage-class header, has nowhere colder, implements no `RestoreObject` |
| Unconfigured | `No` | nothing is configured, so nothing is supported |

**This one capability is inferred from configuration rather than probed**, and the exception to §2's
rule is stated rather than hidden. There is no cheap probe for *"does this backend implement
`RestoreObject`"* — the only way to find out is to archive an object and try, a test that costs a
retrieval and cannot run at connect time. So an endpoint override is read as an S3-compatible
backend and no override as real AWS. The inference fails in one direction only, and it is the safe
one: a compatible backend that did grow Glacier semantics is reported `No` and its archive surface
refuses. Under-reporting costs a feature; over-reporting marks content unavailable that never moved
and cannot be brought back.

Archiving is `CopyObject` onto itself with a `DEEP_ARCHIVE` storage class — S3 has no
`SetStorageClass` — leaving `metadata_directive` at `COPY`, because `REPLACE` silently drops the
content type every read path uses to decide how to render the bytes. Restoring is `RestoreObject`
at the `Bulk` tier: Deep Archive offers no `Expedited` at all, `Standard` is materially dearer per
request, and the product already promises a rehydration measured in hours.

**In practice most content reaches a cold tier through a bucket lifecycle rule, not through these
verbs.** That is the deployment shape this release supports best: `docs/04 §12A`'s column is what
the product reads, every byte path is honest about it, and `POST /files/{id}/rehydrate` is the way
back. Reconciling the column against the store's actual storage class is `ENC-947`.

## 4. Storage profile

```text
storage_profiles
  id
  tenant_id
  provider                 s3 | minio | ceph | r2 | wasabi | b2 | local | azure | gcs
  name
  endpoint
  bucket
  region
  path_style               bool
  credential_reference     secret_ref, never a literal
  encryption_config        provider | kms:{key_ref} | envelope
  options                  JSON
  residency_region
  enabled
```

Raw credentials are never returned to clients, never logged, and never written to
`config_versions`. Admin UI shows a masked fingerprint and a "test connection" result.

## 5. Least privilege

Storage credentials should grant only `GetObject`, `PutObject`, `DeleteObject`, `AbortMultipartUpload`,
`ListBucket` on the configured prefix — never account-wide administration. The admin UI documents the
minimal IAM policy per provider and the startup self-check reports anything broader than expected.

## 6. BYO Vault / secret manager

Supported: environment variables, Docker secrets, Kubernetes secrets, HashiCorp Vault, AWS Secrets
Manager, Azure Key Vault, GCP Secret Manager.

Configuration holds references, never values:

```yaml
smtp:
  password:
    secret_ref: "vault://workspace/smtp#password"
```

Reference syntax: `{scheme}://{path}#{field}`. Schemes: `env`, `file`, `k8s`, `vault`, `awssm`,
`azkv`, `gcpsm`.

Secrets are cached in memory with a lease-aware TTL, zeroized on drop, and never written to disk,
traces or logs. On provider outage, cached values continue to be used within their lease; new fetches
fail closed.

### 6.1 Vault use cases

Database credentials, S3 credentials, SMTP password, LDAP bind password, OIDC/SAML client secrets,
webhook signing secrets, JWT signing keys, encryption keys, integration API tokens, and the optional
password pepper.

## 7. BYO KMS and encryption

Three modes:

| Mode | Key custody | Use |
|---|---|---|
| `PROVIDER` | Storage provider | Default; simplest operationally |
| `KMS` | Customer KMS (AWS KMS, Azure Key Vault, GCP KMS, Vault Transit) | Customer-controlled keys, revocable |
| `ENVELOPE` | Application-generated DEK wrapped by a customer KEK | Maximum control; the platform never holds an unwrapped long-lived key |

In `ENVELOPE` mode a per-version data key is generated, used to encrypt the object, wrapped by the
tenant KEK via `KeyProvider::wrap_data_key`, and stored in `file_versions.encryption_key_ref`.
Revoking the KEK renders content unreadable — including to the operator, which is the point. That
consequence is stated plainly in the admin UI before the mode can be enabled.

Data residency must consider object storage, database, backups, Milvus, preview artifacts,
embeddings and logs. A residency setting that only covers primary storage is a false claim.

## 8. BYO SMTP

Generic SMTP with STARTTLS or implicit TLS, and compatible services (SES SMTP, SendGrid SMTP,
Mailgun SMTP, on-prem relays).

Admin features: test connection, send test email, custom CA bundle, certificate validation toggle
(off requires an explicit acknowledgement), sender name/address, reply-to, white-label templates,
per-tenant rate caps.

## 9. BYO antivirus

| Provider | Mode |
|---|---|
| `clamav` | Embedded `libclamav` or `clamd` over TCP/socket |
| `icap` | Enterprise ICAP gateway (Symantec, McAfee, Trend Micro) |
| `http` | Vendor HTTP scanning API |
| `none` | Explicitly disabled — refused in `enterprise` deployment profile |

Configuration declares the maximum object size to scan, archive depth, timeout, and the
`unavailable_policy` (`HOLD` or `ALLOW_AND_RESCAN`). See `06-SECURITY-DLP-ACCESS.md §6`.

## 10. BYO Milvus / vector store

Supported: platform-operated Milvus, customer-operated Milvus, and the provider abstraction for
future vector stores.

High-security tenants may be pinned to a dedicated Milvus database, collection or cluster. The
`VectorStore` trait is deliberately narrow so an alternative implementation is a contained piece of
work, not a rewrite.

## 11. BYO embedding provider

Options: local model, customer-hosted inference endpoint, OpenAI-compatible endpoint, approved cloud
AI provider.

Classification-aware routing:

```text
RESTRICTED           -> local / internal model only
HIGHLY_CONFIDENTIAL  -> approved enterprise endpoint
CONFIDENTIAL         -> approved enterprise endpoint
INTERNAL / PUBLIC    -> any approved provider
```

Changing the embedding model changes `index_manifests.embedding_model` and triggers a full reindex
of affected content (`07-SEARCH-INDEXING.md §9`). The admin UI states the estimated reindex cost
before the change is applied.

## 12. BYO LLM (bring your own model)

Generative features — RAG answers, summarization, auto-classification suggestions, metadata
extraction — run through `LlmProvider`. No feature calls a vendor SDK directly, and no vendor is
assumed.

### 12.1 Supported provider kinds

| Kind | Examples | Residency |
|---|---|---|
| `local` | vLLM, Ollama, llama.cpp, TGI running in-cluster or on tenant GPUs | `LOCAL` |
| `openai_compatible` | Any `/v1/chat/completions` endpoint — customer-hosted or third-party gateway | Declared per endpoint |
| `anthropic` | Claude models via the Anthropic API or a customer's Bedrock/Vertex deployment | `EXTERNAL` or `REGION(x)` |
| `azure_openai` | Azure OpenAI deployment in a named region | `REGION(x)` |
| `bedrock` / `vertex` | Cloud-hosted models under the customer's own account | `REGION(x)` |
| `none` | Generative features disabled entirely | — |

The `openai_compatible` adapter is the workhorse: most self-hosted inference servers speak it, so a
tenant can point the platform at their own GPU cluster with two configuration values.

### 12.2 Classification-aware routing

The same principle as embeddings (`§11`), and it is enforced in code, not documentation. Each
classification declares which provider tier may see its content:

```yaml
llm:
  default_profile: "enterprise"
  profiles:
    local:
      provider: "local"
      endpoint_env: "LOCAL_LLM_ENDPOINT"
      model: "configured-by-deployment"
      residency: "LOCAL"
    enterprise:
      provider: "openai_compatible"
      endpoint_env: "ENTERPRISE_LLM_ENDPOINT"
      api_key:
        secret_ref: "vault://workspace/llm#api_key"
      model: "configured-by-deployment"
      residency: "REGION(ap-south-1)"
  routing:
    RESTRICTED: "local"          # or "deny"
    HIGHLY_CONFIDENTIAL: "local"
    CONFIDENTIAL: "enterprise"
    INTERNAL: "enterprise"
    PUBLIC: "enterprise"
  limits:
    max_input_tokens: 32000
    max_output_tokens: 2000
    request_timeout: "60s"
    max_concurrent: 8
  controls:
    log_prompts: false
    log_completions: false
    zero_retention_required: true
    tool_use_enabled: false
```

Rules:

- An answer's routing tier is chosen by the **maximum classification across all retrieved sources**,
  not by the question. Mixing a `PUBLIC` and a `RESTRICTED` chunk routes to the `RESTRICTED` tier.
- `routing: "deny"` means the platform refuses to generate over that classification at all and says
  so in the UI, rather than silently downgrading the answer by dropping sources.
- `zero_retention_required: true` refuses to start against a provider profile not marked as
  zero-retention, so a tenant cannot accidentally send regulated content to a training-enabled
  endpoint.
- Residency validation applies exactly as it does to storage: a tenant pinned to a region cannot be
  routed to an endpoint outside it (`§17`).

### 12.3 Safety and cost controls

- **Prompt/response logging is off by default.** When enabled for debugging, it is a tenant-scoped,
  time-boxed, audited setting, and prompts are redacted of detector-matched values.
- **Auditing is by reference**: chunk IDs, model ID, token counts, latency and decision — never the
  prompt or completion text (`07-SEARCH-INDEXING.md §8`).
- **Budgets**: per-tenant daily token caps and per-user rate limits, surfaced through the
  `MCP_CALLS_PER_DAY` and dedicated LLM quota kinds (`04-DATA-MODEL.md §16`). Exceeding a budget
  degrades generative features while leaving search fully functional.
- **Circuit breaking**: a failing or slow provider trips a breaker and generative features degrade to
  plain retrieval results, with the UI stating that answers are unavailable.
- **No tool use by default.** Enabling `tool_use_enabled` lets the model call MCP tools on the user's
  behalf; those calls run through the identical policy chain as any MCP client, with the acting
  user's permissions and an explicit audit trail.

### 12.4 Model changes

Changing the model for a profile is a versioned, audited configuration change. Unlike an embedding
model change it does **not** require a reindex, because generation is stateless — which is precisely
why generation and embedding are separate provider traits.

## 13. BYO PostgreSQL

Self-hosted enterprise deployments may operate their own PostgreSQL, subject to: version 15+,
required extensions (`pgcrypto`, `pg_trgm`), the ability to create a non-owner application role for
RLS (`04-DATA-MODEL.md §3`), and a connection count sufficient for the configured pool.

SaaS mode does not expose arbitrary per-tenant database endpoints unless dedicated isolation is
explicitly purchased.

## 14. Infrastructure profiles

A reusable bundle, so a regulated tenant is configured once rather than seven times:

```text
Infrastructure Profile
 ├── Object Storage
 ├── Secret Provider
 ├── SMTP
 ├── Vector Store
 ├── Embedding Provider
 ├── LLM Provider
 ├── Antivirus
 └── KMS
```

Example — `India Production`: S3 Mumbai, Vault Mumbai, SES Mumbai, internal Milvus, internal
embedding GPU, self-hosted LLM on tenant GPUs, ICAP scanner in the Mumbai DC, KMS key in
`ap-south-1`.

## 15. Main configuration example

```yaml
server:
  bind: "0.0.0.0"
  port: 8080
  public_url: "https://workspace.example.com"
  trusted_proxies:
    - cidr: "10.20.0.0/16"
      hops: 1

# The Prometheus exposition. One section, one bind, and a port per process — `enclave-api` binds
# `api_port`, `enclave-worker` binds `worker_port`. Both null by default. §10.1 of `11-OPERATIONS.md`
# is authoritative for where to place them and why the exposition is not a route on the API port.
metrics:
  bind: "127.0.0.1"
  api_port: 9464
  worker_port: 9465

database:
  url_env: "DATABASE_URL"
  platform_url_env: "DATABASE_PLATFORM_URL"   # BYPASSRLS role; required by the worker only
  max_connections: 50
  statement_timeout: "30s"
  application_role: "enclave_app"        # non-owner, RLS applies

redis:
  url_env: "REDIS_URL"

events:
  nats_url_env: "NATS_URL"
  stream: "vault"

# `provider` and the block that configures it are written together or not at all; one without the
# other refuses to start, naming the missing key. `provider: none` is the default and it is a
# refusal, not a fallback — the indexing pass is then not scheduled at all, which is a legible
# absence rather than a pass that burns its retry budget against a store that cannot answer.
# Credentials are references and there is no field here that can hold a literal.
storage:
  provider: "s3"                          # s3 | none
  s3:
    bucket: "enclave-content"
    region: "eu-west-1"
    endpoint: "https://s3.eu-west-1.amazonaws.com"   # omit for AWS; set for MinIO, Ceph, R2
    flavor: "aws"                         # aws | minio | generic — selects the self-check probes
    path_style: false                     # true for anything without per-bucket DNS
    access_key_id: "vault://workspace/s3#access_key_id"
    secret_access_key: "vault://workspace/s3#secret_access_key"
    signed_url_ttl: "5m"
    max_signed_url_ttl: "1h"

# The embedding width is deliberately not a key here: it is read from
# `enclave_embeddings::model::ACTIVE.dimension`. It is fixed when the collection is created and a
# mismatch errors at neither end, so a configurable width is a way to write that mistake down
# (`07-SEARCH-INDEXING.md §9`).
#
# The query-side keys below (`default_mode` through `denylist_degrade_threshold`) are not read yet;
# they are ignored rather than rejected, like every unmodelled section.
search:
  provider: "milvus"                      # milvus | none
  milvus:
    uri: "http://milvus:19530"
    token: "vault://workspace/milvus#token"   # omit for an unauthenticated cluster
  default_mode: "hybrid"
  dense: true
  sparse: true
  bm25: true
  overfetch_factor: 3
  denylist_degrade_threshold: 10000

# The embedding model is a **mounted directory**, not a name: `bge-m3` is compiled in as the
# model this build indexes against (`plans/M3-DISCOVERY.md` Q14), and what a deployment supplies
# is the weights. `§18.1` is the conversion and what a deployment without it gets.
#
# A top-level key rather than `embedding.model`, so that this and `ENCLAVE_EMBEDDING_MODEL` are one
# spelling — the same reason `ocr_models` and `pdfium` are top level. A path, not a credential.
#
# Setting this with `search.provider: none` is refused at startup: there would be nowhere for the
# vectors to go, and nothing would report it.
embedding_model: "/var/lib/enclave/bge-m3"

antivirus:
  provider: "clamav"
  endpoint_env: "CLAMD_ADDR"
  max_scan_bytes: 2147483648
  archive_depth: 5
  unavailable_policy: "HOLD"

auth:
  access_token:
    algorithm: "EdDSA"
    ttl: "10m"
    privileged_ttl: "5m"
    issuer: "https://workspace.example.com"
    audience: "enclave-api"
  refresh_token:
    idle_ttl: "14d"
    absolute_ttl: "90d"
    rotation: true
    reuse_detection: "REVOKE_FAMILY"
    cookie:
      name: "enclave_rt"
      same_site: "strict"
      path: "/api/v1/auth"
  signing_keys:
    provider: "vault"
    key_ref: "vault://workspace/jwt#ed25519"
    rotation_interval: "90d"
    overlap: "24h"

security:
  password:
    min_length: 12
    max_length: 128
    breach_check: true
    argon2:
      memory_kib: 65536
      iterations: 3
      parallelism: 4
  mfa:
    admins_required: true
    step_up_max_age: "15m"
  privileged_denylist_failure: "FAIL_CLOSED"

dlp:
  enabled: true
  default_mode: "monitor"
  facts_unavailable: "FAIL_CLOSED"

preview:
  sandbox: true
  max_pages: 500
  rendition_cache_bytes: 107374182400

# Mounted volumes for OCR. Absent by default, and a working configuration that way: a scanned
# document then records FAILED / no_text_extracted rather than indexing as empty. Set both or
# neither — one without the other refuses to start. Paths, not credentials. `11-OPERATIONS.md §3.2`
# is authoritative for staging them, for the licensing argument, and for RTEN_NUM_THREADS.
ocr_models: "/var/lib/enclave/ocr-models"
pdfium: "/var/lib/enclave/pdfium/lib"

```

**`storage:` here is the deployment's store, not a tenant's.** An earlier revision of this section
read `storage: { profile: "tenant-default" }`, naming a row in the per-tenant `storage_profiles`
table of `§4`. That table does not exist — no migration creates it — so the key named a row nothing
could resolve, and the two crates that need a bucket (`enclave-worker` for indexing, `enclave-api`
for delivery) had nothing to build a client from. The block above is what a deployment-wide store
looks like; `§4`'s per-tenant override lands with the milestone that creates the table, and will be
read *in addition to* this, not instead of it.

**`server.metrics_port` and `server.metrics_bind` have moved to the `metrics:` section.** They were
one key read by both binaries, so a single file asked the API and the worker to bind the same socket
and whichever started second failed at start-up. An unmigrated file is **refused**, naming the new
keys, rather than loading with the exposition silently off — metrics nobody serves read as zero
forever, which is indistinguishable from a healthy system. `server.*` was also the wrong home: a
worker serves no HTTP API and has no `bind`, `public_url` or `trusted_proxies`.

**`preview.watermark_cache` is deliberately not a setting.** An earlier revision listed it, defaulted
to `false`. A control expressed as a default is a control somebody can turn off, and there is no
deployment for which caching a watermarked artifact is correct: the watermark names the viewer, so a
cached one either serves one person's identity to another or serves a stale identity to its owner
(`§5.1` of `06-SECURITY-DLP-ACCESS.md`). It is now structural instead — a watermarked artifact has
no cache key it could be stored under, because `RenditionKey` has nowhere to put a principal
(`ENC-147`). Nothing in `crates/config` ever parsed the key.

```yaml
sync:
  enabled: true
  max_devices_per_user: 5

mcp:
  enabled: true
  write_tools:
    enabled: false

quotas:
  default_storage_bytes: 5497558138880
  soft_limit_pct: 80

audit:
  enabled: true
  hash_chain: true
  external_anchor: "s3://enclave-audit-anchor/"
  retention_days: 400
```

## 16. LDAP example

```yaml
identity:
  ldap:
    enabled: true
    url: "ldaps://directory.internal:636"
    bind_dn_env: "LDAP_BIND_DN"
    bind_password:
      secret_ref: "vault://workspace/ldap#bind_password"
    base_dn: "DC=company,DC=local"
    users:
      base_dn: "OU=Users,DC=company,DC=local"
      id_attribute: "objectGUID"
      username_attribute: "sAMAccountName"
      email_attribute: "mail"
      filter: "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    groups:
      base_dn: "OU=Groups,DC=company,DC=local"
      id_attribute: "objectGUID"
      membership_attribute: "member"
      nested: true
      max_depth: 8
    sync:
      enabled: true
      interval: "15m"
      deprovision_action: "SUSPEND"     # never hard-delete on a sync glitch
    tls:
      verify_certificate: true
      ca_bundle_ref: "file:///etc/vault/ldap-ca.pem"
```

`deprovision_action: SUSPEND` is the default deliberately: a directory outage that returns an empty
result set must not delete every user in the tenant.

## 17. SMTP example

```yaml
mail:
  provider: smtp
  smtp:
    host: smtp.company.com
    port: 587
    security: starttls
    username:
      secret_ref: "vault://workspace/smtp#username"
    password:
      secret_ref: "vault://workspace/smtp#password"
    from:
      address: workspace@company.com
      name: Company Workspace
    reply_to: no-reply@company.com
    rate_limit_per_minute: 300
```

## 18. Data residency

A tenant may declare preferred, required and allowed regions, and may prohibit cross-region
replication.

Residency applies to authoritative **and** derived content: object storage, database, Milvus,
backups, previews and renditions, embedding endpoints, LLM endpoints, and logs. A startup validation refuses a
configuration whose providers contradict a tenant's declared residency, rather than discovering the
violation during an audit.

### 18.1 Staging the embedding model

`plans/M3-DISCOVERY.md` Q14 chose **`bge-m3`, 1024 dimensions, mounted rather than baked into the
image**. `crates/embeddings/src/model.rs` argues the model choice and `crates/embeddings/src/mounted.rs`
argues the delivery; what follows is the operator half — how the mount is produced, and what a
deployment gets if it is absent.

**Why it is mounted.** The weights are 2.2 GB. An air-gapped install pays that on every image pull,
for content that changes on a different schedule from the code, and changing models would otherwise
mean rebuilding and re-certifying an image. (The OCR weights are mounted for a *stronger* reason —
they are CC-BY-SA-4.0 and `deny.toml`'s allowlist is permissive-only. `bge-m3` is MIT, so this is a
size decision rather than a licensing one.)

**The mount is one directory holding two files:**

| File | What it is |
|---|---|
| `model.rten` | the converted weights |
| `tokenizer.json` | the model's own vocabulary, copied unchanged from the model repository |

Point `embedding_model` at that directory, or set `ENCLAVE_EMBEDDING_MODEL`. It is a path and not a
credential, so it is not a `vault://` reference and does not appear in `secret_refs()`.

**Why a conversion step exists at all.** This build takes `rten` with `default-features = false`
plus `rten_format`, so the ONNX parser is not compiled in — an enabled parser nobody uses is still a
parser inside a customer's trust boundary, which is the same argument the `image` and `pdfium-render`
pins make. `rten` therefore loads `.rten` and BAAI publishes ONNX, and the gap is closed once, by
the operator, with a published tool.

**The conversion.** `rten-convert` is the converter shipped by the `rten` project; its version tracks
the runtime, and **the version to install is the one the `rten` crate in `Cargo.lock` names** — for
`rten 0.24.0` that is `rten-convert 0.22.0`, which is the version in `rten`'s own `v0.24.0` tag.
Python 3.10 or newer.

```bash
python3 -m venv /tmp/rten && /tmp/rten/bin/pip install 'rten-convert==0.22.0'

# The published export. `model.onnx` is the graph; `model.onnx_data` is its external
# tensor data and must sit beside it, or the conversion silently produces a model with
# no weights.
base=https://huggingface.co/BAAI/bge-m3/resolve/main/onnx
mkdir -p /tmp/bge-m3 && cd /tmp/bge-m3
for f in model.onnx model.onnx_data tokenizer.json; do curl -fL -O "${base}/${f}"; done

mkdir -p /var/lib/enclave/bge-m3
/tmp/rten/bin/rten-convert model.onnx /var/lib/enclave/bge-m3/model.rten
cp tokenizer.json /var/lib/enclave/bge-m3/tokenizer.json
```

The result is ~2.27 GB, roughly the size of the ONNX it came from — the conversion re-containers the
weights, it does not quantize them.

**What can go wrong, and why it is a decision rather than a workaround.** `rten` is a smaller project
than ONNX Runtime, and a model whose graph uses an operator it does not implement will fail to
convert or fail to run. `bge-m3` does not: its published export is opset 11 and twenty-eight operator
types, all supported, and the workspace's own tests run a forward pass against the result. **If a
future model fails here, that reopens the runtime choice** — it is not something to route around by
adding a second inference runtime, because the absence of a `links` key is the property that let
`rten` into this image at all (`Cargo.toml`).

**Verifying the mount.** The worker refuses to start if the directory is missing either file, if
`model.rten` is not a graph with `input_ids`, `attention_mask` and `token_embeddings` nodes, or if
the graph's declared width is not the 1024 this build indexes against. There is no silent
degradation: a volume that failed to attach is an outage, not a corpus of documents with no vectors.

**A mounted model needs a vector store.** `embedding_model` set with `search.provider: none` makes
**the worker** refuse to start, naming both keys. Nothing would fail otherwise — the weights would
load, no stage would be built, documents would index exactly as before — and dense search would
return nothing, for months.

The refusal is the worker's and not the configuration loader's, and the distinction is worth knowing
because it decides what a shell variable does to unrelated processes. `enclave-api` builds no vector
stage, so it loads such a configuration without complaint; only the process that would have embedded
refuses. A loader-level check was tried first and made every binary in the workspace refuse to start
in any shell that had exported `ENCLAVE_EMBEDDING_MODEL` — which is what CI and this section tell
you to do.

**What a deployment without the mount gets.** Documents are extracted, chunked and committed to
`chunk_text`, so lexical search works; `index_manifests.embedding_model` records an empty string,
which is the honest value for a deployment where nothing embedded; and dense retrieval returns
nothing. The worker says so once at start-up rather than leaving it to be inferred from an empty
collection.

**Which processes need the mount, and what happens to the one that does not have it.** The worker
mounts it to embed *documents*. `enclave-api` mounts it to embed a *query*, because a vector index
you cannot form a query for is not a vector index — `VectorIndex::candidates` takes an embedding, so
an API replica with a Milvus endpoint and no weights can probe the store and never read it
(`ENC-698`). It is the same directory and the same two files; whether both processes see it is a
scheduling decision, not a configuration one.

The API therefore builds dense retrieval only when **both** `search.milvus` and `embedding_model`
are set, and it does **not** refuse to start when they are not. What it does instead is answer:
`POST /api/v1/search` falls back to lexical search over PostgreSQL and reports
`diagnostics.degraded: true`, which is the state `09-UX-WHITE-LABELING.md §10`'s results header
renders. A deployment that mounted the model on the worker alone gets exactly that, and gets a
warning at boot naming the key that is missing — without it, "search is degraded" has no visible
cause anywhere. A mount that is *configured and broken* is still a start-up failure, as it is in the
worker, and it cannot fire for a deployment that has not asked for dense search because it is only
reached when `search.milvus` is set as well.

**Changing the model later is a reindex, not a configuration edit** (`07-SEARCH-INDEXING.md §9`). The
collection's dense width is fixed when it is created, so a different width needs a new collection and
every chunk of every tenant re-embedded. The worker reads the collection's width back from the server
at start-up and refuses a disagreement, so the mistake is caught at deploy time rather than as
retrieval quietly degrading.

## 19. Deployment profiles

**Community** — single node, local filesystem or MinIO, Milvus standalone, ClamAV embedded.

**Production** — horizontally scaled API/workers, HA data services, S3, Milvus cluster.

**Enterprise** — multi-AZ, BYO Vault/KMS/storage/SMTP/AV/Milvus, SSO, DLP, SIEM, data residency, DR.
The `enterprise` profile refuses to start with `antivirus.provider: none`, `audit.enabled: false`, or
a storage bucket that fails the public-access self-check.

## 20. Configuration precedence

```text
defaults -> YAML/TOML config file -> environment variables -> secret provider
```

Plaintext secrets are never committed to repository configuration. A pre-flight check scans the
resolved configuration for values that look like credentials and refuses to start if any appear
inline rather than as references.

## 21. Configuration versioning

Security-sensitive configuration changes are versioned, diffable, auditable and rollback-capable via
`config_versions` (`04-DATA-MODEL.md §14`). Payloads store secret *references*, so a rolled-back
configuration never resurrects a rotated credential.

Maker/checker approval may be required per scope (`06-SECURITY-DLP-ACCESS.md §22`).

## 22. Change log

| Version | Date | Change |
|---|---|---|
| 2.6 | 2026-08-29 | `§18.1` says which processes need the mount and what a deployment that gives it to only one of them gets. `enclave-api` now loads the same weights to embed a search query, because a vector index a process cannot form a query for is not one it can read; it builds dense retrieval only when `search.milvus` and `embedding_model` are both set, and answers lexically with `diagnostics.degraded: true` — never a refusal to start — when they are not (`ENC-698`). |
| 2.5 | 2026-08-25 | `§18.1` is new: how an operator produces the mounted `bge-m3` model, reproducibly. The conversion step exists because this build compiles `rten` without its ONNX parser — an enabled parser nobody uses is still a parser inside a customer's trust boundary — so `rten-convert` closes the gap once, at the version the `rten` crate in `Cargo.lock` names. `§15`'s `embedding:` block is replaced by a top-level `embedding_model` path: Q14 settled *which* model, so what a deployment supplies is the weights and not a name, and a top-level key makes the field and `ENCLAVE_EMBEDDING_MODEL` one spelling. `provider` and `batch_size` are gone rather than left unread — an inert key is a claim an operator acts on. A mounted model with `search.provider: none` is now refused at startup, because nothing else would report it (`ENC-661`). |
| 2.4 | 2026-08-22 | `§15` gains a modelled `storage:` and `search:` section and a `metrics:` section. `storage.profile: "tenant-default"` is replaced by a deployment-wide `storage.s3` block, because `§4`'s `storage_profiles` table does not exist and the key named a row nothing could resolve (`ENC-562`); `search.milvus` carries the URI and token, and never the embedding width (`ENC-563`). `server.metrics_port` / `server.metrics_bind` move to `metrics.api_port` / `metrics.worker_port` / `metrics.bind` and the old keys are refused at startup — both binaries read the single old key, so one file on one host made the second process to start die with `Address already in use` (`ENC-566`). |
| 2.3 | 2026-08-22 | Earlier revisions predate this table. |
