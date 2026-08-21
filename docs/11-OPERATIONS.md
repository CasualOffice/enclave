# 11 — Operations

> **Status:** Draft · **Version:** 1.4 · **Owner:** SRE · **Last updated:** 2026-08-22
> **Authoritative for:** SLOs, runbooks, backup/DR, key rotation, migrations, capacity, on-call.

## 1. Service level objectives

| SLI | Objective | Measurement |
|---|---|---|
| API availability | 99.9% monthly (99.95% enterprise) | Non-5xx on `/api/v1/*`, excluding client errors |
| Metadata API latency | P95 < 300 ms, P99 < 800 ms | Server-side, excluding client network |
| Search latency | P95 < 500 ms | Includes post-filter |
| Upload success rate | > 99.5% | Completed / initiated, excluding user aborts |
| Index freshness | P95 < 10 min from version creation to `READY` | `index_manifests` timestamps |
| Policy decision latency | P95 < 100 ms cached, < 300 ms cold | Policy engine spans |
| Durability | No authoritative data loss | Backup verification |

Error budget: 0.1% monthly ≈ 43 minutes. Exhausting it freezes feature deploys until a reliability
review has been completed and its actions merged.

## 2. Environments

| Environment | Purpose | Data |
|---|---|---|
| `dev` | Local Compose stack | Synthetic |
| `ci` | Ephemeral per-PR | Synthetic, seeded |
| `staging` | Pre-production, production-shaped | Synthetic + anonymized |
| `production` | Live | Real |

Production data is never copied to a lower environment. Reproducing a customer issue uses synthetic
data plus the customer's *configuration*, which is exportable without content.

## 3. Deployment

Rolling deployment with readiness gating. Order matters:

```text
1. Run forward-compatible migrations (expand phase)
2. Deploy workers    (tolerate both schema shapes)
3. Deploy API        (rolling, readiness-gated)
4. Deploy web assets (cache-busted, served from the API or CDN)
5. Soak, then run the contract phase of migrations in the next release
```

Rollback: redeploy the previous image. Because migrations are expand-then-contract, the previous
release always runs against the current schema — this is what makes rollback safe, and it is why the
contract phase never ships in the same release as its expand phase.

Deploys are blocked while a `STALE`-manifest backlog exceeds threshold or a rebuild is mid-alias-flip.

### 3.1 What the worker process runs, and what it needs to run it

`enclave-worker` is one process running four independent loops, each with its own interval and its
own tenant sweep. What it *will* run is decided at start-up and logged in one line —
`enclave-worker starting passes=["invalidation", "epoch"]`. **Read that line.** A pass whose
dependency is absent is not scheduled at all, and the difference between "not scheduled" and
"scheduled over an empty queue" is invisible on every graph.

| Pass | Interval | Needs | Absent ⇒ |
|---|---|---|---|
| Indexing | 5 s when idle, no wait while there is work | PostgreSQL, object storage | not scheduled; `chunk_text` stays empty and search stays lexical-only |
| Invalidation sweep | 5 min | PostgreSQL | — always scheduled |
| Epoch reconcile | 1 min | PostgreSQL | — always scheduled |
| Coverage probe | 1 min | PostgreSQL, the vector store | not scheduled; `enclave_search_index_observed_chunks` has no series (§5.7 step 5) |

Every pass works on the tenant list the process reads once per tick: `ACTIVE` and `READ_ONLY`, never
`SUSPENDED` or `DELETING`. That follows §12 — suspension pauses background processing — and it has
one consequence worth knowing before it is diagnosed as a fault: **a suspended tenant's coverage
gauges stop being refreshed and therefore freeze at their last value rather than disappearing.**
Suspending a tenant whose index was healthy leaves a healthy-looking series behind it. Read the
tenant's status before reading its gauges.

The intervals differ because the costs do: the sweep is one `DELETE` per tenant over rows that have
already stopped suppressing anything, and the coverage probe is a network round trip to the vector
store per tenant. Indexing is the only pass with a backlog, so it is the only one that goes straight
round again rather than waiting — but a tick that only *deferred* files counts as idle, because a
deferral means antivirus has not finished and re-claiming the same rows immediately would spin.

**Two configuration keys the API does not need:**

* **`database.platform_url`** — the DSN of the `BYPASSRLS` role. **The worker refuses to start
  without it**, and the refusal names it. The query that produces a tenant list cannot itself be
  scoped to a tenant, and every pass takes that list as a parameter; with no credential the process
  would run four loops over nothing while every probe stayed green. Grant it nothing beyond what
  `migrations/0002_rls_policies.sql` already grants `enclave_platform`.
* **`metrics.worker_port`** — the worker binds its **own** metrics socket, and it has its own key.
  It used to read `server.metrics_port`, the key the API also reads: correct for one listener per
  pod, and fatal on a host running both, where whichever started second died with `Address already
  in use` (`ENC-566`). Two keys make both deployments expressible, and equal port numbers are still
  allowed because two pods do not share a port namespace. The coverage probe's gauges are
  process-wide statics published by whichever process runs the pass, so a worker with no port
  publishes them into a registry nothing scrapes — which reads as zero forever, indistinguishable
  from healthy. §10.1 covers where to place the port; it applies unchanged to this one.

**Shutdown.** SIGTERM raises a shared flag; each loop returns at its next boundary — between
transactions, never inside one — and the process exits when the last of them has. An idle loop is
woken rather than left to wait out its interval, so a worker asleep on the five-minute sweep does
not consume the grace period and get `SIGKILL`ed part-way through the batch it started next. Give it
a `terminationGracePeriodSeconds` comfortably above the longest single unit of work, which is one
tenant's indexing batch — the OCR page budget, not the interval, is what bounds that.

### 3.2 The three mounted volumes, and the worker environment variable beside them

Three artefacts are **staged on volumes and mounted at run time, never baked into the container
image**. Two of the three affect what the worker can index; the third decides whether it can index
at all. None of them is a secret — they are paths, and they are configured as plain strings.

| What | Configuration key | Environment | Absent ⇒ |
|---|---|---|---|
| Embedding model weights (`BAAI/bge-m3`) | *not yet modelled* | — | the worker **refuses to index** |
| OCR model weights (`ocrs`) | `ocr_models` | `ENCLAVE_OCR_MODELS` | no OCR; scanned files are `FAILED` |
| PDFium shared library | `pdfium` | `ENCLAVE_PDFIUM` | no page is rasterised; scanned PDFs are `FAILED` |

The two spellings in each row are the same field: the configuration loader derives the environment
name from the key, so `ENCLAVE_OCR_MODELS` and `ocr_models:` are one setting and there is no second
place for them to disagree.

**Why mounted rather than shipped**, because it is asked every time and the answers differ:

* **Embedding weights** — image size. `08-BYO-INFRA.md §18` covers air-gapped installs, where a
  multi-gigabyte layer on every image pull is a real cost, and a mount lets the model be staged once
  beside the deployment. Changing models then does not mean rebuilding and re-certifying an image.
* **OCR weights** — **licensing**, which is the stronger of the two. The published `ocrs` models are
  CC-BY-SA-4.0, a copyleft data licence. `deny.toml`'s allowlist is permissive-only because Enclave
  ships as software an enterprise self-hosts, so a copyleft obligation anywhere in the graph becomes
  a distribution obligation on every one of those customers — and `cargo deny` would never catch
  this one, because the crate is permissive and the weights are a separate download. Mounting means
  the operator obtains them and we redistribute nothing.
* **PDFium** — a binary-artefact problem. 7 MB of shared object per platform (BSD-3-Clause, with
  permissive third-party libraries), content nobody reviews in a diff, invisible to `cargo deny`
  because it is not a crate. The release tag is an **ABI pair** with the `pdfium_7881` feature in
  the workspace manifest; `pdfium-render` resolves every export eagerly at `dlopen`, so a mismatched
  library fails at the mount rather than subtly at render. Use the `pdfium-*` archives and **not**
  `pdfium-v8-*`: the V8 builds embed a JavaScript engine and enable PDF scripting, and a page tree
  is already the widest attack surface in the product without a JIT behind it.

#### What each absence costs

**The embedding model is not optional.** A worker that starts without it refuses to index rather
than indexing empty vectors — `crates/embeddings` documents three separate guards holding that
property. A deployment whose model volume failed to attach has an outage, and it looks like one.

**The two OCR volumes are optional and paired.** With neither, a scanned or image-only document
yields no text, `index_manifests` records `FAILED` with `no_text_extracted`, and the file is
*visibly* unsearchable. That is a documented absence and it is fine. What is not fine, and what the
pairing rule exists to prevent, is a deployment that mounted one of the two: its configuration says
OCR is on, its scanned PDFs index as empty, and nothing anywhere reports the discrepancy. **Setting
one without the other refuses startup**, naming the key that is missing.

Startup failures to expect, and what each means:

| Message names | Cause |
|---|---|
| `pdfium` is set but `ocr_models` is not (or the reverse) | half the pair configured — set both, or neither |
| the OCR model at `…` could not be loaded | the volume is not attached, or holds the wrong files |
| PDFium could not be loaded from `…` | the volume is not attached, or the ABI does not match this build |
| PDFium is already mounted from `…` | the mount path was changed without restarting the process |

The OCR directory must hold `text-detection.rten` and `text-recognition.rten` — the **released**
weights from `ocrs`'s own `download-models.sh`, not the similarly-named training checkpoints on the
model card. The checkpoints load and run and produce plausible nonsense, which is a worse failure
than not loading at all. The PDFium key names the *directory*, not the file; the platform's library
name is derived from it.

#### `RTEN_NUM_THREADS`, beside the worker's CPU limit

**Set `RTEN_NUM_THREADS` on every worker that has OCR mounted, to the same number as its CPU
limit.** It is not set by anything in the application, and that is deliberate: a library that
mutates the process environment does so to every other thread in the process without being asked.

`rten`, the inference runtime under `ocrs`, pulls in `rayon` unconditionally — there is no feature
that removes it (`ENC-535`). Rayon sizes its pool from the *host's* visible core count, which on a
container with a fractional CPU limit is a pool several times larger than the cores it may use. The
symptom is not a crash: it is a worker that spends its quota being throttled and descheduled, so OCR
latency rises, `RenderBudget`'s wall clock starts expiring, and pages come back `Refused(Timeout)` —
which reads on every surface as "OCR is broken" rather than "the pool is four times the limit".

```yaml
# Kubernetes, worker deployment
resources:
  limits:
    cpu: "4"
    memory: "8Gi"          # RenderBudget.max_memory_bytes is 1 GiB per attempt
env:
  - name: RTEN_NUM_THREADS
    value: "4"             # the cpu limit above, as an integer
  - name: ENCLAVE_OCR_MODELS
    value: /var/lib/enclave/ocr-models
  - name: ENCLAVE_PDFIUM
    value: /var/lib/enclave/pdfium/lib
volumeMounts:
  - { name: ocr-models, mountPath: /var/lib/enclave/ocr-models, readOnly: true }
  - { name: pdfium,     mountPath: /var/lib/enclave/pdfium,     readOnly: true }
```

Round a fractional limit **down**, never up: one thread on a `500m` container is correct, and two is
the problem above in miniature. Mount all three volumes read-only — nothing writes to them, and a
writable model volume is a way to change what every future extraction produces without changing an
image.

#### Replacing the weights is a reindex, not a restart

The extractor version string that `docs/07-SEARCH-INDEXING.md §3` compares to decide what needs
reindexing names the *code*, not the files on the volume. Swapping the mounted models therefore
changes every future extraction's output while that marker stays still, and nothing detects it.
**Replacing the weights must be accompanied by a release that bumps the `ocr/N` component of the
extractor version**, followed by the index rebuild in `§5.1`. Nothing in the type system enforces
this today; it is recorded here because the operator action and the code change have to travel
together.

## 4. Backup and restore

| Store | Method | Frequency | Retention | RPO |
|---|---|---|---|---|
| PostgreSQL | Base backup + continuous WAL archiving | Continuous | 35 days PITR | ≤ 5 min |
| Object storage | Provider versioning + cross-region replication | Continuous | Per retention policy | ≤ 15 min |
| Audit archive | Export to object storage with object lock | Daily | Per audit retention | 24 h |
| Configuration | `config_versions` + IaC in git | On change | Indefinite | 0 |
| Milvus | **Not backed up** — rebuilt | — | — | n/a |
| Redis | Not backed up | — | — | n/a |

Targets: **RPO ≤ 5 minutes, RTO ≤ 4 hours** for the enterprise profile.

Restore is exercised monthly in staging and the result is recorded. An unverified backup is not a
backup: the drill restores to a fresh instance, runs migrations, boots the API, and passes a smoke
suite before it counts.

### 4.1 Restore runbook (PostgreSQL)

```text
1. Declare the incident; put the tenant or platform in READ_ONLY if it is still serving.
2. Provision a fresh cluster from the base backup nearest before the target time.
3. Replay WAL to the target timestamp; verify with a known recent audit sequence.
4. Point the API at the restored cluster (config change, not code).
5. Reconcile object storage: purge blobs whose version rows no longer exist (they are orphans);
   flag version rows whose blobs are missing (restore those from object versioning).
6. Reconcile quotas (§5.4) and rebuild the index (§5).
7. Verify: login, upload, download, search, audit chain (§6). Then lift READ_ONLY.
```

Step 5 is not optional — a point-in-time database restore against a live object store always
produces both orphans and dangling references, and both are detectable.

## 5. Runbooks

### 5.1 Index rebuild

Trigger: Milvus data loss, collection schema change, embedding-model change, or drift the metadata
repair path cannot close.

```text
1. POST /admin/search/reindex { scope, tier, budget }
     tier = metadata_repair | vector_cache | full
2. A new collection is created; an alias still points at the old one.
3. Workers process index_manifests, recent content first, honoring the rate limit and token budget.
4. Monitor /admin/search/status: coverage %, failures, spend, ETA.
5. At >= 99% coverage of READY manifests, flip the alias.
6. Soak 24h, then drop the old collection.
```

During a rebuild, search stays available on the old collection; if there is no old collection,
search degrades to lexical over PostgreSQL and reports `degraded: true`. Tell customers that, rather
than letting them infer it from missing results. Full design: `07-SEARCH-INDEXING.md §9`.

### 5.2 Permission-drift repair

Symptom: post-filter drop ratio > 20%, or epoch-drift count non-zero for more than 15 minutes.

```text
1. Check the denylist size per tenant. If growing, the invalidation worker is behind or failing.
2. Inspect the index worker DLQ for permission.changed events.
3. Re-enqueue failed events; the operation is idempotent.
4. If Milvus metadata updates are failing outright, degrade the tenant to lexical search
   (feature flag) rather than serving a knowingly stale index.
5. Confirm recovery: drop ratio normal, denylist drains, epoch drift returns to zero.
```

Correctness is never at risk during this — the post-filter still guarantees it. What is at risk is
result quality and latency.

### 5.3 Quarantine handling

```text
1. Incident fires with severity CRITICAL and the file version in QUARANTINED.
2. Confirm the detection: engine, signature, scan time.
3. Determine exposure: has this version been downloaded, synced or shared? Query audit by version.
4. If exposed, notify affected users and the security contact.
5. Release (privileged, MFA, audited, reason recorded) or purge.
6. Rescan sibling content from the same uploader in the same window.
```

### 5.4 Quota reconciliation

Nightly, the scheduler recomputes cumulative usage from authoritative rows and compares to
`quota_usage`. Drift beyond 0.1% is an alert, not a silent correction — drift means the write path
has a bug. The reconciler records both values and corrects the counter after logging the delta.

### 5.5 Outbox backlog

```text
1. Alert: unpublished outbox rows > 10 000 or oldest > 5 minutes.
2. Check NATS health and the publisher's leader lock.
3. If NATS is down: nothing is lost — the outbox is the buffer. Confirm disk headroom on PostgreSQL.
4. If the publisher is stuck: restart it; it resumes from the oldest unpublished row.
5. After recovery, watch consumer lag; workers will burst.
```

### 5.6 Break-glass admin access

If a conditional-access misconfiguration locks every administrator out, a break-glass account:

- is created at deployment, stored offline, and used only in an incident;
- is exempt from IP/zone policy but **not** from MFA or audit;
- triggers an immediate high-severity alert to the security contact on use;
- has its use reviewed within 24 hours, with a written record.

### 5.7 Search metrics quiet, or the drop ratio at zero

Trigger: `SearchPostFilterDropRatioZero`, `SearchPostFilterSilent`, `SearchDenylistSizeUnreported`,
`SearchIndexCoverageUnreported` or `MetricsSeriesDropped`.

These five share a runbook because they share a shape: the signal stopped, and a stopped signal is
worse news than a moving one. §5.2 handles the drop ratio *climbing*, which is the post-filter doing
its job loudly. This section handles it going quiet, which is what a post-filter that is no longer
running looks like from the outside — no errors, no latency change, no log line, and results that
may contain documents the caller cannot see.

```text
1. Is the post-filter running at all?
     enclave_search_postfilter_passes_total must be increasing. Compare against search request
     volume. Flat counter + live traffic is a SEV1: results are reaching callers without
     PostFilter::confirm. Take search offline for the affected tenants before diagnosing.
     Flat counter + no traffic is a quiet Sunday. Confirm and close.
2. Passes increasing, ratio exactly zero?
     Check that both drop counters are still being published:
       enclave_search_postfilter_candidates_dropped_total{reason="denylisted"}
       enclave_search_postfilter_candidates_dropped_total{reason="unauthorized"}
     A counter that is present and pinned is different from one that is absent. Present-and-pinned
     means the code path runs and never drops — inspect a recent deploy of crates/search.
3. Reproduce with the leakage suite. `12-TESTING.md §4.3` S5 offers deliberately over-permissive
   candidates and asserts they are dropped. If S5 passes against the running build, the post-filter
   is intact and the zero is real: confirm invalidation is healthy (§5.2 step 1) and raise the
   alert's traffic floor rather than silencing it.
4. Denylist gauge absent?
     Nothing is calling the recorder that publishes enclave_search_denylist_entries. Both denylist
     alerts are then incapable of firing, and a tenant can sit in degraded search unannounced.
     Restore the call; until then, query retrieval_denylist directly per tenant.
5. Index coverage gauges absent?
     enclave_search_index_observed_chunks has no series, so nothing is running the coverage probe
     pass (crates/worker/src/coverage.rs) — or the process that runs it is not the one serving
     /metrics. Both index-coverage alerts are then incapable of firing, not merely quiet, and a
     tenant whose collection was wiped answers searches confidently. Until it is scheduled again,
     compare a tenant's chunk count in the store against sum(chunk_count) over its READY
     index_manifests by hand; a store far below that is the rebuild case (§5.1).
6. Series dropped at the cardinality cap?
     Some tenants are unmonitored. Confirm which by comparing exported tenant_id labels against the
     tenant list, then either raise the cap or aggregate upstream.
```

The judgement call in step 1 is the whole runbook. Everything else is confirmation.

## 6. Audit chain verification

```text
POST /admin/audit/verify { from, to }
```

Recomputes `event_hash = SHA256(previous_hash || canonical_event)` across the range and compares to
the stored chain and to the externally anchored head. A mismatch reports the first divergent
`sequence` — the point at which the record stopped being trustworthy.

Anchors are written to object storage with object lock (or to the SIEM) on a schedule, so a
compromise that can rewrite the database cannot silently rewrite history.

## 7. Key and secret rotation

| Secret | Interval | Procedure |
|---|---|---|
| JWT signing key | 90 days | Publish new key as `PENDING` → wait for JWKS propagation → `ACTIVE` for signing → old key `RETIRING` for one full access+refresh lifetime → `RETIRED` |
| Storage credentials | 90 days | Add new credential to the profile, verify with a test operation, remove old |
| Database credentials | 90 days | Vault dynamic credentials preferred; otherwise dual-user rotation |
| SMTP / LDAP bind | 180 days | Update secret reference; verify with "test connection" |
| Webhook signing secrets | 180 days | Dual-secret window: sign with new, accept both, then drop old |
| KMS keys | Per customer policy | Re-wrap DEKs in the background; content is never re-encrypted |
| Password pepper | Rarely; requires rehash-on-login | Versioned pepper; both accepted during transition |

Rotation is never a hard cutover. Every mechanism above has an overlap window, because a cutover
that fails at 03:00 with no accepted old credential is an outage.

## 8. Migrations

- Forward-only, numbered, checksummed; applied by a dedicated migration role.
- **Expand → migrate → contract**, split across releases.
- Every migration must be safe against a table being read concurrently: `CREATE INDEX CONCURRENTLY`,
  no long `ACCESS EXCLUSIVE` locks, `NOT NULL` added via a validated `CHECK` first.
- A migration that rewrites a large table is a background job, not a deploy step.
- New tenant-scoped tables must ship RLS policies in the same migration; CI enforces this
  (`12-TESTING.md §5`).
- `/health/ready` fails when the applied migration version is behind the binary's expected version,
  so a half-migrated cluster does not serve traffic.

## 9. Capacity planning

Baseline per 1 000 active users with 5 TB of content:

| Component | Baseline |
|---|---|
| API | 3 replicas × 2 vCPU / 4 GB |
| Worker | 2 replicas × 4 vCPU / 8 GB (more during reindex) |
| PostgreSQL | 8 vCPU / 32 GB, 500 GB SSD, `max_connections` ≥ 200 |
| Redis | 2 GB, HA pair |
| NATS | 3 nodes, 10 GB JetStream storage |
| Milvus | 3 nodes; ~1.5 KB per chunk vector at 768 dims plus index overhead |
| Object storage | Content + ~10–15% for renditions |

Rules of thumb: ~20–60 chunks per document; embedding throughput is the reindex bottleneck, not
Milvus ingest; preview generation is CPU-bound and spiky — size it for the burst after a bulk
upload, or accept a queue and show it honestly in the UI.

## 10. Monitoring and alerting

### 10.1 Where the metrics are, and why they are not on the API port

The Prometheus exposition is served on a **listener of its own**, configured by the `metrics:`
section: `metrics.bind` for the interface both processes face, `metrics.api_port` for `enclave-api`
and `metrics.worker_port` for `enclave-worker`. Each is **off by default** (`null`) and binds to
loopback when a port is given. `GET /metrics` is the only path it answers; the API port does not
serve it at all, and a gate refuses any change that puts it there.

Two ports rather than one because a single `enclave.yaml` is read by both processes, and one shared
key meant that on a host running both, the second to start died with `Address already in use`.
A file still carrying `server.metrics_port` or `server.metrics_bind` is **refused at startup**,
naming the new keys — ignoring them would leave the exposition silently off, and a metric nobody
serves reads as zero forever.

That is not an inconvenience to route around. The exposition carries `tenant_id` labels — which
tenants exist, how much each one searches, how far behind each one's invalidation has fallen — so it
fails the bar this system sets for an unauthenticated endpoint: never a detail that identifies a
tenant. Putting it behind the policy chain instead would require Prometheus to present a tenant it
cannot honestly claim.

So the port is yours to place. Bind it to a management interface, or to loopback with a sidecar
scraping it. **Do not expose it to the internet**, and do not put it behind the same load balancer as
the API on the assumption that authentication covers it — there is none, deliberately, because the
separation is the control.

If a scrape returns connection-refused, the likeliest cause is that the process's port was never set:
it logs `metrics.api_port is unset; no metrics endpoint is served` (or the worker's louder
`metrics.worker_port is unset…`) on start-up, and logs `metrics listening` with the address when it
is set.

### 10.2 Golden signals

**Golden signals** per service: rate, errors, duration, saturation.

Alerts that page:

| Alert | Threshold |
|---|---|
| API 5xx rate | > 1% for 5 min |
| API P95 latency | > 1 s for 10 min |
| PostgreSQL replication lag | > 30 s |
| PostgreSQL connection saturation | > 85% for 5 min |
| Outbox backlog | > 10 000 or oldest > 5 min |
| Worker DLQ | Any message in the security-relevant DLQs |
| AV unavailable | > 15 min with `unavailable_policy: HOLD` |
| Post-filter drop ratio | > 20% for 15 min |
| Post-filter drop ratio at zero | Exactly 0 for 30 min while candidates are still being proposed |
| Retrieval denylist size | > 1 000 for a tenant |
| Retrieval denylist over its limit | Above the tenant's configured limit — the tenant **is already** in degraded search |
| Backup age | > 24 h since last verified backup |
| Certificate expiry | < 14 days |
| Quota reconciliation drift | > 0.1% |

Alerts that ticket rather than page: index lag, rendition queue depth, SMTP retries, LDAP sync
failures, embedding spend above forecast, no post-filter passes recorded for 30 min, denylist size
unreported for 1 h, index coverage unreported for 1 h or unestablished for 2 h, metric series
refused at the cardinality cap.

**A threshold that can only be crossed upwards is half an alert.** The post-filter drop ratio has two
of them, and the low one is the one that gets forgotten. A ratio that climbs means the index drifted
and the post-filter caught it — bad, visible, recoverable. A ratio that is *exactly zero* while
candidates flow most likely means the post-filter stopped dropping, which produces no error, no
latency change and no log line, and answers with documents the caller may not see. §5.7 is its
runbook, and the same reasoning is why the denylist gauge going absent is itself an alert: an alert
that cannot fire looks exactly like one that has nothing to say.

Every alert links to the runbook section that resolves it. An alert without a runbook is not shipped.

The executable rules live in `deploy/monitoring/alerts/`; the thresholds above are what they are
tuned to, and the denylist limit is read from the process's own configuration rather than restated
in the rule file.

## 11. Incident response

Severity: **SEV1** data loss, security breach or full outage · **SEV2** major degradation ·
**SEV3** minor degradation · **SEV4** cosmetic.

SEV1/SEV2 flow: declare → assign an incident commander → open a channel → mitigate before diagnosing
→ communicate on a fixed cadence → resolve → blameless postmortem within five business days with
owned, dated actions.

Security incidents additionally engage the security contact, preserve evidence (audit range export,
relevant object versions) before remediation changes state, and follow the tenant's contractual
notification timelines.

## 12. Tenant lifecycle

**Provisioning** — create tenant, apply the infrastructure profile, seed roles and classifications,
verify storage/mail/AV connectivity, then enable login.

**Cluster provisioning, before any migration runs.** The three database roles — `enclave_app`,
`enclave_migrator`, `enclave_platform` — are created by the deployment, not by the application.
Migration 0001 also creates them, but its guard is check-then-act and roles are cluster-wide: two
replicas migrating different databases in one cluster can race and one fails
(`unique_violation` on `pg_authid_rolname_index`). Provisioning the roles first makes that guard a
no-op. The dev stack does this in `deploy/compose/init/01-roles.sql`; production does it in the
same step that provisions their credentials. Tracked as `ENC-116`.

**Suspension** — `status = SUSPENDED`: authentication refused, data retained, background processing
paused, admin export still possible. "Paused" is enforced at the tenant enumerator
(`enclave_db::active_tenants`), so it covers every worker pass at once rather than each pass
remembering to check — see §3.1 for the one thing that costs, which is a frozen coverage gauge.

**Export** — a full tenant export produces content plus metadata, ACLs, audit and configuration in a
documented format, generated asynchronously and delivered as an encrypted archive with a
time-limited link.

**Deletion** — `status = DELETING` → grace period (default 30 days, blocked by any active legal
hold) → hard delete of database rows, objects, renditions, index chunks and cached secrets → a
signed deletion certificate recording scope and time.

## 13. On-call

One primary and one secondary, weekly rotation. The primary owns acknowledgement within 5 minutes for
pages; the secondary escalates at 15. Handover is written, including in-flight incidents, ongoing
rebuilds, deploy freezes and any break-glass use.

The on-call kit: this document, the alert-to-runbook index, credentials path for the break-glass
account, the customer communication template, and the escalation tree.
