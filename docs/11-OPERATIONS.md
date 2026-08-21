# 11 — Operations

> **Status:** Draft · **Version:** 1.2 · **Owner:** SRE · **Last updated:** 2026-08-21
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

The Prometheus exposition is served on a **listener of its own**, configured by `server.metrics_port`
and `server.metrics_bind`. It is **off by default** (`metrics_port: null`) and binds to loopback when
a port is given. `GET /metrics` is the only path it answers; the API port does not serve it at all,
and a gate refuses any change that puts it there.

That is not an inconvenience to route around. The exposition carries `tenant_id` labels — which
tenants exist, how much each one searches, how far behind each one's invalidation has fallen — so it
fails the bar this system sets for an unauthenticated endpoint: never a detail that identifies a
tenant. Putting it behind the policy chain instead would require Prometheus to present a tenant it
cannot honestly claim.

So the port is yours to place. Bind it to a management interface, or to loopback with a sidecar
scraping it. **Do not expose it to the internet**, and do not put it behind the same load balancer as
the API on the assumption that authentication covers it — there is none, deliberately, because the
separation is the control.

If a scrape returns connection-refused, the likeliest cause is that `metrics_port` was never set: the
process logs `metrics_port is unset; no metrics endpoint is served` at debug on start-up, and logs
`metrics listening` with the address when it is set.

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
paused, admin export still possible.

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
