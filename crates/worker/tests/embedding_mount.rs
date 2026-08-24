//! The embedding stage a deployment's configuration builds — `ENC-661`.
//!
//! # What this file is for, and what it is not
//!
//! `crates/embeddings/tests/mounted.rs` already proves the piece: that the converted `bge-m3`
//! weights load, that a forward pass produces vectors of the collection's width, that they come
//! back one per chunk in order, and that half a mount is an outage. None of that is repeated here.
//!
//! What was untested until now is the *composition*: that the environment variable CI sets reaches
//! a [`Config`], that a `Config` naming the mount produces a working embedder, and that the three
//! states of `Config::embedding_mounts` produce three different things rather than two. Every
//! assertion below is about our wiring — `docs/12 §1.1`.
//!
//! # The positive control is the whole file
//!
//! `docs/12 §1.2`: *"an assertion about an absence passes for free."* Every negative here — no
//! model builds no embedder, a stranded model refuses, a missing volume errors — held trivially
//! against the workspace as it stood before this row, because **nothing embedded at all**. So each
//! one is paired with [`both_halves_build_an_embedder`], which needs the real 2.2 GB volume and
//! fails by name if `from_config` has quietly become a function that returns `None` for everything.
//!
//! `#[ignore]`d because they need the mounted model; **CI runs them with `--include-ignored`** and
//! provisions the volume in the "Fetch the embedding model" step of the `test` job.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;

use enclave_config::{Config, ConfigLoader, EmbeddingMounts};
use enclave_worker::embedding::MountedEmbedder;
use enclave_worker::WorkerError;

/// The configuration a deployment that embeds actually has.
///
/// Built through [`ConfigLoader`]'s environment layer rather than by setting the field directly,
/// because the thing worth proving is that the **variable name CI sets** is the name the loader
/// turns into this field. A test that assigned `config.embedding_model` would pass against a field
/// nothing in any environment can reach — which is `crates/worker/tests/ocr_mounts.rs`'s argument,
/// and it is worth more here because this spelling is new and has no runbook history to correct it.
///
/// The values are passed explicitly rather than letting the loader read the whole process
/// environment, for `ocr_mounts.rs`'s reason: `ENCLAVE_*` is a reserved prefix, a shell is not a
/// controlled input, and this test should fail only for reasons about the embedding mount.
fn mounted_config() -> Config {
    let model = std::env::var("ENCLAVE_EMBEDDING_MODEL")
        .expect("ENCLAVE_EMBEDDING_MODEL must name the mounted model directory");

    ConfigLoader::new()
        .with_env([
            ("ENCLAVE_EMBEDDING_MODEL", model),
            // The other half of the pair. Without it `embedding_mounts` is `Incomplete` and the
            // loader refuses, which is `a_model_with_nowhere_to_write_refuses_the_startup` below.
            ("ENCLAVE_SEARCH__PROVIDER", "milvus".to_owned()),
            (
                "ENCLAVE_SEARCH__MILVUS__URI",
                std::env::var("MILVUS_URI").unwrap_or_else(|_| "http://127.0.0.1:19530".to_owned()),
            ),
        ])
        .load()
        .expect("a configuration naming the mount and a vector store is valid")
        .into_config()
}

// -------------------------------------------------------------------------------------------
// Construction — the three states, and the one that needs the volume.
// -------------------------------------------------------------------------------------------

#[test]
#[ignore = "requires the converted bge-m3 weights on a volume named by ENCLAVE_EMBEDDING_MODEL; CI runs it with --include-ignored"]
fn both_halves_build_an_embedder() {
    // **The positive control for this whole file, and for `crates/worker/src/embedding.rs`'s unit
    // tests.** Every other assertion here is about something *not* being built, and every one of
    // them was satisfied by the workspace before this row, when no `EmbeddingProvider` existed at
    // all. This is the one that fails if `from_config` returns `None` for everything.
    let config = mounted_config();

    assert!(
        matches!(config.embedding_mounts(), EmbeddingMounts::Mounted { .. }),
        "the environment did not reach the configuration field"
    );

    let embedder = MountedEmbedder::from_config(&config)
        .expect("the mounted weights load")
        .expect("a configuration naming the mount must build an embedder");

    // Consumed into the trait object `VectorStage::for_collection` takes, which is the only thing
    // the composition root does with it. Proving it converts is proving the wiring compiles *and*
    // that the router is the erased `Embedder` the stage wants.
    let _erased = embedder.into_embedder();
}

#[test]
fn a_deployment_with_no_mount_builds_no_embedder_and_does_not_fail() {
    // Today's behaviour for every deployment, kept: no model is `Ok(None)`, not an error. Not
    // `#[ignore]`d because it needs nothing — and on its own it proves nothing, which is why
    // `both_halves_build_an_embedder` above exists.
    assert!(MountedEmbedder::from_config(&Config::default())
        .expect("no embedding model is not an error")
        .is_none());
}

#[test]
fn a_model_with_nowhere_to_write_refuses_the_startup() {
    // The tri-state's middle arm, at the layer that acts on it. The failure it prevents is silent
    // in every direction an operator can look: the weights load, no stage is built, documents index
    // exactly as before, and dense search has always returned nothing.
    let stranded =
        Config { embedding_model: Some(PathBuf::from("/mnt/enclave/bge-m3")), ..Config::default() };

    match MountedEmbedder::from_config(&stranded) {
        Err(WorkerError::IncompleteMount { present, missing }) => {
            assert_eq!(present, "embedding_model");
            assert_eq!(missing, "search.milvus");
        }
        other => panic!("expected a refusal naming both keys, got {other:?}"),
    }
}

#[test]
#[ignore = "requires the converted bge-m3 weights on a volume named by ENCLAVE_EMBEDDING_MODEL; CI runs it with --include-ignored"]
fn a_configured_volume_that_is_not_there_is_an_outage_and_never_no_embedding() {
    // The distinction this module turns on, and the one with no `FAILED` manifest to fall back on:
    // an OCR volume that fails to attach at least leaves `no_text_extracted` on a surface somebody
    // reads, while a model volume that fails to attach leaves a corpus that indexes *perfectly* and
    // is absent from dense search with nothing anywhere saying so.
    //
    // `#[ignore]`d despite needing no weights, because it is meaningless without its control: the
    // same `mounted_config` shape with a real path must build. Run together, they are a pair.
    let mut config = mounted_config();
    config.embedding_model = Some(PathBuf::from("/nonexistent/enclave/embedding-model"));

    let error = MountedEmbedder::from_config(&config)
        .expect_err("a missing volume must not read as `no embedding`");
    assert!(matches!(error, WorkerError::Embedding(_)), "{error:?}");
}
