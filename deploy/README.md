# `deploy/` — the development stack

Everything a contributor needs running locally, and the configuration template a deployment starts
from. Production manifests are not here; this directory is the developer-facing half of
[`docs/08-BYO-INFRA.md`](../docs/08-BYO-INFRA.md).

| Path | What it is |
|---|---|
| [`compose/dev.yml`](compose/dev.yml) | The local infrastructure stack |
| [`config/enclave.example.yaml`](config/enclave.example.yaml) | Template for `enclave.yaml`, which is git-ignored |
| `config/dev-keys/` | Development JWT signing keys, generated on first run, git-ignored, never committed |

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

Both images are published to Docker Hub only. That is the second reason they are opt-in: a Docker
Hub rate limit on an image the default stack does not need must not be able to stop every
contributor from starting PostgreSQL.

### Why Redis forgets on restart

Everything Enclave puts in Redis is derived from PostgreSQL and must be reconstructible from it. A
development instance that forgets on every restart makes an accidental dependency on cached state
fail here, on a laptop, rather than in production during a failover.

## Registries and pinning

Images come from registries that serve anonymous pulls: `public.ecr.aws/docker/library/*` (AWS's
mirror of the Docker official images) and the upstream projects' own registries on `quay.io`.
Anonymous Docker Hub pulls are rate-limited per source IP and, while this file was being written,
were returning `401 unauthorized` outright — a first-day contributor should not have to create a
Docker Hub account to run `cargo test`.

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

## Signing keys

`deploy/config/dev-keys/` holds the Ed25519 key the development `KeyProvider` generates on first
run. It is git-ignored, and no key material is ever committed — not even a throwaway one, because
throwaway keys get copied into production more often than anyone admits
([`plans/M0-FOUNDATIONS.md`](../plans/M0-FOUNDATIONS.md) D5). To rotate locally, delete the
directory and restart the API.
