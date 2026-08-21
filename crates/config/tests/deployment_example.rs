//! `deploy/config/enclave.example.yaml` is a file this crate must be able to load, and the file the
//! monitoring stack must agree with.
//!
//! Both properties were untested until `ENC-566`, and both were broken. The example set one
//! `server.metrics_port`, `deploy/monitoring/prometheus.yml` scraped two ports, and the
//! configuration model could express neither pair — so a host running the API and the worker from
//! one file had the second process die at start-up with `Address already in use`, while the
//! monitoring configuration encoded a shape the configuration could not.
//!
//! # Why these assertions are here rather than in a unit test
//!
//! Because the subject is the pair of committed files, not a struct. A unit test over
//! [`MetricsConfig`] can only prove that two fields exist, which is the assertion-about-an-absence
//! that passes for free. What has to be proved is that the two numbers a real deployment uses can
//! be bound **at the same time, in one process**, which is exactly what the two binaries do.

// Assertions are the point of a test; the workspace warns on these constructs elsewhere.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::net::TcpListener;
use std::path::PathBuf;

use enclave_config::{ConfigLoader, Loaded, SearchProvider, StorageProvider};

/// A path inside the repository, from this crate's manifest directory.
fn repo_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").join(relative)
}

/// The example, loaded exactly as a binary loads it, minus the ambient environment.
///
/// `without_env()` for the reason `ambient_environment.rs` gives: the loader reads the whole process
/// environment, so a developer's shell would otherwise decide whether this test passes.
fn example() -> Loaded {
    ConfigLoader::new()
        .without_env()
        .with_file(repo_path("deploy/config/enclave.example.yaml"))
        .load()
        .expect("deploy/config/enclave.example.yaml must load and validate")
}

/// The committed example is a file this crate accepts — including every section it now models.
///
/// It stopped being one twice while `ENC-562` was being written: the example's `storage:` block used
/// `access_key_env` and `force_path_style`, spellings nothing ever parsed, and a `search:` block
/// whose keys belonged to a query-side section that is still unmodelled. Both loaded silently while
/// the section was ignored wholesale, which is precisely why the section being modelled has to come
/// with this test.
#[test]
fn the_committed_example_loads_and_validates() {
    let loaded = example();
    let config = loaded.config();

    assert_eq!(config.storage.provider, StorageProvider::S3);
    assert_eq!(config.search.provider, SearchProvider::Milvus);

    let s3 = config.storage.s3.as_ref().expect("the example configures a bucket");
    assert_eq!(s3.bucket, "enclave-content");
    assert!(s3.path_style, "MinIO has no per-bucket DNS");

    // Every credential in the example is a reference, and each is enrolled by field path so an
    // unresolvable one is reported at startup rather than at the first upload.
    let paths: Vec<String> =
        config.secret_refs().into_iter().map(|(path, _)| path).collect::<Vec<_>>();
    assert!(paths.contains(&"storage.s3.access_key_id".to_owned()), "{paths:?}");
    assert!(paths.contains(&"storage.s3.secret_access_key".to_owned()), "{paths:?}");
}

/// **The positive control for `ENC-566`.** Two ports, bound at once, from the real file.
///
/// A test that only asserted `api_port != worker_port` would pass on a model that still had one
/// shared key and two defaults, and would prove nothing about a socket. This binds both, in one
/// process, exactly as a host running `enclave-api` and `enclave-worker` from one `enclave.yaml`
/// does — and the second bind is the one that used to fail.
///
/// Deliberate violation: setting `worker_port` to `9464` in the example, so both processes name the
/// same socket, fails this test by name on the second `TcpListener::bind` with `Address already in
/// use` — the same error, in the same order, that the two binaries produced.
#[test]
fn the_two_metrics_listeners_can_bind_at_the_same_time() {
    let loaded = example();
    let metrics = &loaded.config().metrics;

    let api = metrics.api_addr().expect("the example serves API metrics");
    let worker = metrics.worker_addr().expect("the example serves worker metrics");
    assert_eq!(api.ip(), worker.ip(), "both listeners share `metrics.bind`, deliberately");

    // The real addresses, not ephemeral ones. A test that bound port 0 twice would pass against a
    // model with one shared key, because two ephemeral ports never collide — it would prove
    // something true about the kernel and nothing about this configuration.
    let first = TcpListener::bind(api)
        .unwrap_or_else(|err| panic!("bind the API's metrics listener on {api}: {err}"));
    let second = TcpListener::bind(worker)
        .unwrap_or_else(|err| panic!("bind the worker's metrics listener on {worker}: {err}"));

    // Held at the same time, which is the whole claim. Both are still in scope here; dropping the
    // first before binding the second would let a single shared port pass.
    assert_ne!(
        first.local_addr().expect("the bound address"),
        second.local_addr().expect("the bound address"),
    );
    drop((first, second));
}

/// The example config and the monitoring config name the same two ports.
///
/// They did not. `prometheus.yml` scraped 9464 and 9465 from the day the worker got a listener; the
/// configuration could express one port, and nothing compared the two files. A scrape job pointed at
/// a port nothing binds reports a target that is permanently down, which an operator learns to
/// ignore — the same failure mode as a metric nobody serves.
#[test]
fn prometheus_scrapes_the_ports_the_example_configures() {
    let loaded = example();
    let metrics = &loaded.config().metrics;

    let text = std::fs::read_to_string(repo_path("deploy/monitoring/prometheus.yml"))
        .expect("deploy/monitoring/prometheus.yml");
    let prometheus: serde_yaml::Value = serde_yaml::from_str(&text).expect("valid YAML");

    let port_of = |job_name: &str| -> u16 {
        let jobs = prometheus["scrape_configs"].as_sequence().expect("scrape_configs");
        let job = jobs
            .iter()
            .find(|job| job["job_name"].as_str() == Some(job_name))
            .unwrap_or_else(|| panic!("no scrape job named {job_name}"));
        let target = job["static_configs"][0]["targets"][0].as_str().expect("a target");
        target
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse().ok())
            .unwrap_or_else(|| panic!("{job_name} target `{target}` has no port"))
    };

    assert_eq!(
        Some(port_of("enclave-api")),
        metrics.api_port,
        "prometheus.yml scrapes a port `metrics.api_port` does not open"
    );
    assert_eq!(
        Some(port_of("enclave-worker")),
        metrics.worker_port,
        "prometheus.yml scrapes a port `metrics.worker_port` does not open"
    );
}
