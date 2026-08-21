# `deploy/` — the development stack

Everything a contributor needs running locally, and the configuration template a deployment starts
from. Production manifests are not here; this directory is the developer-facing half of
[`docs/08-BYO-INFRA.md`](../docs/08-BYO-INFRA.md).

| Path | What it is |
|---|---|
| [`compose/dev.yml`](compose/dev.yml) | The local infrastructure stack |
| [`config/enclave.example.yaml`](config/enclave.example.yaml) | Template for `enclave.yaml`, which is git-ignored |
| `config/dev-keys/` | Development JWT signing keys, generated on first run, git-ignored, never committed |
| [`monitoring/alerts/`](monitoring/alerts) | Prometheus alerting and recording rules |
| [`monitoring/prometheus.yml`](monitoring/prometheus.yml) | Minimal scrape config, so the rules above are loadable rather than decorative |

## Start it

```bash
docker compose -f deploy/compose/dev.yml up -d --wait
```

`--wait` returns when every service reports **healthy**, not when the containers exist. That is the
whole reason each service declares a healthcheck: without one, `up --wait` comes back while
PostgreSQL is still running `initdb` and the first command you type fails for a reason that has
nothing to do with your code.

Then, from the repository root:

```bash
export DATABASE_URL=postgres://enclave:enclave@localhost:5432/enclave
export REDIS_URL=redis://localhost:6379
export NATS_URL=nats://localhost:4222

cargo run -p enclave-cli -- migrate            # apply 0001 and 0002
cargo run -p enclave-cli -- seed --profile dev # tenant-alpha and tenant-beta
cargo run -p enclave-cli -- doctor             # says what is wrong, read-only
```

`doctor` is the first thing to run when the stack "doesn't work" — it checks connectivity,
migration state, that every tenant-scoped table has row-level security enabled **and** forced, and
that `enclave_app` holds its grants and cannot `UPDATE` or `DELETE` `audit_events`.

## Services

Default profile — this is what M0 needs, and it starts in well under a minute:

| Service | Ports | What it is for |
|---|---|---|
| `postgres` | 5432 | The authoritative store. Everything else is derived from it and must survive its loss. |
| `redis` | 6379 | Cache and rate-limit counters. Persistence is deliberately off (see below). |
| `nats` | 4222, 8222 | JetStream — where the transactional outbox publishes. 8222 is the monitoring endpoint the healthcheck uses. |
| `minio` | 9000, 9001 | S3-compatible object storage. 9001 is the web console; sign in with the values in `dev.yml`. |
| `minio-init` | — | Creates the buckets on first run, then idles so `--wait` has something to wait on. |

Opt-in profiles:

| Profile | Service | Ports | Why it is opt-in |
|---|---|---|---|
| `search` | `milvus`, `etcd` | 19530, 9091, 2379 | Milvus wants gigabytes of RAM and pulls about a gigabyte. Nothing before M2 uses it. |
| `av` | `clamav` | 3310 | Downloads its signature database on first start (minutes). M0 has no upload path, so nothing scans anything yet. |

```bash
docker compose -f deploy/compose/dev.yml --profile search up -d --wait
docker compose -f deploy/compose/dev.yml --profile av     up -d --wait
```

Both images are published to Docker Hub only — ClamAV re-probed 2026-08-20 (`ENC-140`, below), and
Milvus is unchanged since. That is the second
reason they are opt-in: a Docker Hub rate limit on an image the default stack does not need must not
be able to stop every contributor from starting PostgreSQL.

### Why Redis forgets on restart

Everything Enclave puts in Redis is derived from PostgreSQL and must be reconstructible from it. A
development instance that forgets on every restart makes an accidental dependency on cached state
fail here, on a laptop, rather than in production during a failover.

## Running the tests against this stack

Tests that need live infrastructure are `#[ignore]`d, and `--include-ignored` runs them. They read
their endpoints from the environment, and a variable that is unset is a **failure**, not a skip —
deliberately, so that a suite believed to be running cannot quietly not be. The consequence is that
the first local run after `compose up` fails with a message naming the variable:

```sh
export DATABASE_URL=postgres://enclave:enclave@localhost:5432/enclave
export TEST_S3_ENDPOINT=http://localhost:9000
export TEST_S3_ACCESS_KEY_ID=enclave
export TEST_S3_SECRET_ACCESS_KEY=enclave-dev-secret

cargo test --workspace -- --include-ignored --skip a_lost_role_creation_race
```

`--skip a_lost_role_creation_race` because that test drops cluster-wide roles to recreate the race
it exists to prove, which breaks every other binary holding a database. CI runs it in a job with a
server of its own.

The values above match `.github/workflows/ci.yml`, which is the file to check if a test passes in CI
and fails here. Adjust the ports if you set any `ENCLAVE_DEV_*_PORT` override.

### `ENCLAVE_` is reserved — test variables must not use it

**Anything exported as `ENCLAVE_*` is configuration.** `ConfigLoader` reads the whole process
environment, strips that prefix and merges what is left into the configuration tree
(`crates/config/src/loader.rs`, `docs/08-BYO-INFRA.md §20`). A variable in that namespace that is not
a configuration field does not get ignored; it becomes a *field*, and then a startup validator has an
opinion about it.

These variables were `ENCLAVE_TEST_S3_*` until `ENC-544` (as was `ENCLAVE_TEST_CLAMD_ADDR`, now
`TEST_CLAMD_ADDR`), and the consequence was concrete:
`ENCLAVE_TEST_S3_SECRET_ACCESS_KEY` arrived as a field named `test_s3_secret_access_key`, the
inline-credential scanner classed it as a credential and measured 57 bits of entropy against a 48-bit
threshold, and **every process started from a shell with the dev variables exported refused to
start**, naming a field nobody had written. The scanner was correct at every step. The name was the
mistake, so the name is what changed.

The rule, then: **a variable a *test* or a *tool* reads is named without the `ENCLAVE_` prefix.** If
you add one, name it `TEST_*` (or anything outside the prefix) — do not teach the loader to skip a
prefix, because a loader that drops variables silently ignores an override an operator set, which is
a worse failure than refusing to start. `crates/config/tests/ambient_environment.rs` enforces this by
loading configuration from the real process environment, so a variable put back into the reserved
prefix fails CI rather than somebody's next `cargo run`.

`ENCLAVE_DEV_*` — the compose overrides in the table above — sit inside the prefix and are the
remaining exception. They are read by `docker compose` from a `.env` file or an inline assignment and
are not normally exported into a shell, so they do not reach a loading process. If you do export one,
`ENCLAVE_DEV_DB_PASSWORD` and `ENCLAVE_DEV_MINIO_PASSWORD` reach the same scanner by the same route
and refuse the same way once their value clears the entropy threshold. Prefer
`ENCLAVE_DEV_MINIO_PORT=9010 docker compose …` over `export`, and treat renaming this family out of
the prefix as the follow-up it is rather than something to discover during an incident.

**On Apple Silicon**, the antivirus tests cannot run: `clamav/clamav` publishes an amd64 image and
no arm64 one, so `g1_an_eicar_upload_is_quarantined_and_never_becomes_available` fails for reasons
unrelated to the code unless you run it under emulation (`ENC-525`). CI is amd64 and runs it.

## Monitoring

`monitoring/alerts/search.yml` holds the search alerting rules that
[`docs/11-OPERATIONS.md §10`](../docs/11-OPERATIONS.md) describes: post-filter drop ratio in both
directions, retrieval denylist size against the limit the process is running with, and the
"this signal went quiet" alerts that make an unfireable alert visible instead of reassuring. Each
rule carries a `runbook` annotation naming the section that resolves it — `docs/11 §10` refuses to
ship an alert without one.

`/metrics` is served on a **listener of its own**, not on the API port — set `server.metrics_port`
(the example config uses `9464`, which is what `prometheus.yml` scrapes). It is off by default and
binds to loopback. The exposition carries `tenant_id` labels, so it must never be reachable from
where the API is; [`docs/11-OPERATIONS.md §10.1`](../docs/11-OPERATIONS.md) has the reasoning and the
deployment rule. If a scrape is refused, the usual cause is that `metrics_port` was left unset.

Two honest gaps remain, written here rather than discovered during an incident:

- **`promtool` is not in the toolchain**, so `check rules` has never been run over this file and no
  CI job loads it. The rules parse as YAML; that is all that has been verified.
- **`enclave-worker` has no metrics listener**, because the worker binary does not exist yet. Its
  scrape job is kept in `prometheus.yml` so the rules load with both series present, and it will
  show as a down target until the binary lands. That is deliberate: a missing job reads as
  "monitored", and a down one reads as what it is.

## Registries and pinning

Images come from registries that serve anonymous pulls: `public.ecr.aws/docker/library/*` (AWS's
mirror of the Docker official images) and the upstream projects' own registries on `quay.io`.
Anonymous Docker Hub pulls are rate-limited per source IP and, while this file was being written,
were returning `401 unauthorized` outright — a first-day contributor should not have to create a
Docker Hub account to run `cargo test`.

**Re-checked 2026-08-20 (`ENC-140`).** Anonymous Docker Hub pulls work again: an unauthenticated
token for `clamav/clamav` is issued and `1.4_base` resolves, with the registry stating the budget it
grants in the token itself — 100 pulls per six hours per source IP. So `docker login` is no longer
needed for the `av` or `search` profiles. That is a fact about Docker Hub's posture this week, not a
guarantee, which is why nothing here depends on it: both images stay behind profiles and neither is
on the path a fresh clone must pull.

ClamAV still has no second home. Probed and absent: `quay.io/clamav/clamav`, `ghcr.io/clamav/clamav`
and `ghcr.io/cisco-talos/clamav` (401 — no public repository), `public.ecr.aws/clamav/clamav` and
`public.ecr.aws/docker/library/clamav` (404 — it is not a Docker official image, so AWS does not
mirror it). Controls on the same code path — `quay.io/coreos/etcd`, `ghcr.io/astral-sh/uv`,
`public.ecr.aws/docker/library/postgres` — all resolved, so the absences are absences rather than a
broken probe. Mirroring it into a registry we own is the only remaining option, and it is worth
knowing who actually pays if Hub closes again: not this stack, where `--profile av` simply stays
down and the `eicar` tests stay `#[ignore]`d, but **CI**, which pulls `clamav/clamav:1.4`
anonymously in the `test` job and runs those tests with `--include-ignored`. A Hub refusal there
fails leakage row G1 and reads as a security-test failure rather than as a registry one.

Every tag is pinned to an exact version. `:latest` makes "works on my machine" a function of when
you last pulled, and a database that silently major-upgrades underneath its data volume is not
recoverable.

## Credentials

The usernames and passwords in `dev.yml` are local development values, not secrets: the images
require *a* username and password to start, and these are bound to loopback. Override any of them
from the environment (`ENCLAVE_DEV_DB_PASSWORD`, `ENCLAVE_DEV_MINIO_PASSWORD`, …) or with a
`.env` file beside the Compose file.

They are also the only place such a value appears. `enclave.example.yaml` contains no credential —
every field that names one holds a reference (`env://…`, `vault://…`), and startup refuses to
proceed if one is written inline, naming the offending field (CLAUDE.md rule 11,
[`docs/08-BYO-INFRA.md §6`](../docs/08-BYO-INFRA.md)). Never reuse these values anywhere reachable
from another host.

## Ports already in use

Every published port is overridable, so a stack from another project does not force you to stop it:

```bash
ENCLAVE_DEV_DB_PORT=5433 docker compose -f deploy/compose/dev.yml up -d --wait
export DATABASE_URL=postgres://enclave:enclave@localhost:5433/enclave
```

The full set: `ENCLAVE_DEV_DB_PORT`, `ENCLAVE_DEV_REDIS_PORT`, `ENCLAVE_DEV_NATS_PORT`,
`ENCLAVE_DEV_NATS_MONITOR_PORT`, `ENCLAVE_DEV_MINIO_PORT`, `ENCLAVE_DEV_MINIO_CONSOLE_PORT`,
`ENCLAVE_DEV_ETCD_PORT`, `ENCLAVE_DEV_MILVUS_PORT`, `ENCLAVE_DEV_MILVUS_METRICS_PORT`,
`ENCLAVE_DEV_CLAMAV_PORT`.

## Inspect it

```bash
docker compose -f deploy/compose/dev.yml ps                  # health of each service
docker compose -f deploy/compose/dev.yml logs -f postgres    # follow one service
docker compose -f deploy/compose/dev.yml exec postgres psql -U enclave enclave
docker compose -f deploy/compose/dev.yml exec redis redis-cli
docker compose -f deploy/compose/dev.yml exec nats wget -qO- http://127.0.0.1:8222/varz
```

## Stop and reset

```bash
# stop, keep the data
docker compose -f deploy/compose/dev.yml down

# stop and delete every volume — the reset that actually resets
docker compose -f deploy/compose/dev.yml --profile search --profile av down -v
```

Naming the profiles on `down -v` matters: `down` only removes containers for the profiles that are
selected, so a stopped Milvus or ClamAV container — and the volume still attached to it — survives
a "full" reset and comes back with stale state.

Migrations are forward-only by design ([`docs/11-OPERATIONS.md §8`](../docs/11-OPERATIONS.md)) —
there is no down-migration. `down -v` followed by `up -d --wait` and `enclave-cli migrate` is the
supported way to get back to an empty schema, and it takes about a minute.

Integration tests do not need this: `TestDb::start` creates a uniquely-named database per test
binary from `DATABASE_URL` and drops it afterwards, so a test run never touches the database you
have been poking at by hand.

What "never touches" means precisely, since it used not to be true (`ENC-504`): **no migration is
ever applied to the database `DATABASE_URL` names, and no table is created in it.** That matters
because a migration applied there records its *checksum* there — so editing an unmerged migration,
running the tests and then switching branches used to leave your dev database failing the
forward-only checksum gate on a migration you were no longer touching. What still happens against
it, and is unavoidable, is `CREATE DATABASE` / `DROP DATABASE` (cluster-level statements have to be
issued from inside some database), a session advisory lock that serialises setup, and
`pg_terminate_backend` against connections to the throwaway. Migration `0001` also creates the
three `enclave_*` roles, which are cluster objects and outlive the throwaway database that created
them. None of that survives in your schema.

## Signing keys

`deploy/config/dev-keys/` holds the Ed25519 key the development `KeyProvider` generates on first
run. It is git-ignored, and no key material is ever committed — not even a throwaway one, because
throwaway keys get copied into production more often than anyone admits
([`plans/M0-FOUNDATIONS.md`](../plans/M0-FOUNDATIONS.md) D5). To rotate locally, delete the
directory and restart the API.

## Database roles

`compose/init/01-roles.sql` runs once, before PostgreSQL accepts connections, and creates
`enclave_app`, `enclave_migrator` and `enclave_platform`.

Migration 0001 creates them too, but its `IF NOT EXISTS` guard is check-then-act and roles are
cluster-wide, so two databases migrating concurrently can race — it reproduced 10 times out of 10
before this file existed. Creating them up front closes the window.

Production should do the same, in the step that provisions their credentials. Roles are a
deployment concern; see `docs/11-OPERATIONS.md §12` and tracker item `ENC-116`.
