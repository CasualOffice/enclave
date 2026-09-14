# Enclave — the container image the deployment procedure in `docs/11-OPERATIONS.md §3` assumes.
#
# `ENC-993`. That section describes a rolling deploy — *deploy workers, deploy API, rollback by
# redeploying the previous image* — and until this file nothing in the repository built an image.
# `docs/11 §2` names four environments and two of them, `staging` and `production`, had no
# implementation at all. The visible cost was three of M5's exit criteria: the restore drill, the
# performance budgets and the chaos pass each need something to deploy *to*, and none of them could
# be attempted.
#
# # What is deliberately not in this image
#
# **The three mounted artefacts** — embedding weights, OCR models, PDFium — are staged on volumes
# and mounted at run time, and `docs/11 §3.2` gives a different reason for each. The one that is
# not negotiable is OCR: the published `ocrs` weights are CC-BY-SA-4.0, and Enclave ships as
# software an enterprise self-hosts, so baking a copyleft data set into the image would put a
# distribution obligation on every customer. `cargo deny` cannot see it, because the crate is
# permissive and the weights are a separate download. They are mounted, and we redistribute nothing.
#
# The other two follow from size and from ABI: 2.2 GB of embedding weights on every image pull is a
# real cost in the air-gapped installs `docs/08 §18` is written for, and the PDFium release tag is
# an ABI pair with the `pdfium_7881` feature in the workspace manifest — a mismatch has to fail at
# the mount, loudly, rather than subtly at render.
#
# # Why a builder stage and not a `scratch` runtime
#
# The binaries are dynamically linked against glibc, and `aws-lc-rs` brings its own compiled
# objects. A static musl build is possible and is not free — it changes the allocator, the DNS
# resolver and the TLS stack all at once, none of which is exercised by any test in this workspace.
# `bookworm-slim` with the build tooling dropped is 74 MB and honest; a musl port is its own row
# with its own evidence, not a line in a Dockerfile.

# ---------------------------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------------------------
# Pinned to the same channel as `rust-toolchain.toml`. CI asserts that the compiler it runs matches
# that file and fails on drift; this image would otherwise be the one place the pin does not apply,
# and a release binary built by a different compiler than the one the tests ran under is exactly
# the seam this repository keeps finding.
FROM rust:1.98.0-bookworm AS builder

# CI's `ubuntu-latest` image happens to carry these, which is why no workflow installs them and why
# a slim build is where their absence surfaces. Named individually rather than as `build-essential`
# so a future removal says which crate wanted it:
#
#   * `cmake`, `clang`, `perl` — `aws-lc-rs` compiles its own C and drives it from cmake.
#   * `protobuf-compiler` — `tonic-build`, via `milvus-sdk-rust`, shells out to `protoc`.
#   * `pkg-config` — resolution for the above; cheap and load-bearing when anything links natively.
RUN apt-get update \
 && apt-get install --no-install-recommends -y \
      cmake \
      clang \
      perl \
      pkg-config \
      protobuf-compiler \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY . .

# `--locked` for the reason the `build` CI job gives: a build that silently resolves versions other
# than the lockfile is not the build that was audited. `--release` because this is the artefact a
# deployment runs, and because `crates/embeddings` is unusable at `opt-level = 0` — `ENC-979` is
# the row where a debug build of the inference kernels read as a hang.
RUN cargo build --workspace --locked --release \
      --bin enclave-api \
      --bin enclave-worker \
      --bin enclave-cli \
      --bin enclave-scheduler

# ---------------------------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# `ca-certificates` because every outbound leg is TLS — object storage, the identity provider, SMTP,
# Vault. `curl` is here for the container healthcheck and for nothing else; the compose stack's
# `--wait` depends on a real readiness signal rather than on the process existing, which is the
# argument `deploy/README.md` already makes about `postgres` still running `initdb`.
RUN apt-get update \
 && apt-get install --no-install-recommends -y ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# Unprivileged, and with no shell to log into. The processes read a configuration file, listen on a
# port above 1024 and write nothing to the image; nothing they do needs root, and `docs/06` would
# have to argue why if it did.
RUN groupadd --system --gid 10001 enclave \
 && useradd --system --uid 10001 --gid enclave --home-dir /var/lib/enclave \
      --shell /usr/sbin/nologin enclave \
 && mkdir -p /var/lib/enclave /etc/enclave \
 && chown -R enclave:enclave /var/lib/enclave /etc/enclave

COPY --from=builder /build/target/release/enclave-api       /usr/local/bin/
COPY --from=builder /build/target/release/enclave-worker    /usr/local/bin/
COPY --from=builder /build/target/release/enclave-cli       /usr/local/bin/
COPY --from=builder /build/target/release/enclave-scheduler /usr/local/bin/

# The mount points the three staged artefacts land on (`docs/11 §3.2`). Created empty and owned, so
# a deployment that forgets one gets the refusal each absence is documented to produce — the worker
# refusing to index without embedding weights, `FAILED` renditions without PDFium — rather than a
# permission error that names the wrong problem.
RUN mkdir -p /opt/enclave/embedding-model /opt/enclave/ocr-models /opt/enclave/pdfium \
 && chown -R enclave:enclave /opt/enclave

USER enclave
WORKDIR /var/lib/enclave

# No `CMD`. The image carries four binaries and the compose file or the orchestrator names which one
# a container runs; a default would make `enclave-api` the implicit answer and hide a worker that
# was never started — which is the failure `docs/11 §3.1` opens by telling operators to read the
# start-up line for.
ENTRYPOINT []
