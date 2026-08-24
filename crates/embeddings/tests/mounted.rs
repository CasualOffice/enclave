//! The mounted `bge-m3` provider, against the real converted weights — `ENC-661`.
//!
//! # Why every test here is `#[ignore]`d
//!
//! The weights are 2.2 GB and are **mounted, never committed** — `crates/embeddings/src/mounted.rs`
//! and `docs/08-BYO-INFRA.md §18` argue that at length, and `plans/M3-DISCOVERY.md` Q14 settled it
//! before this code existed. So a test that needs the model needs the mount, which is the shape the
//! PostgreSQL, Milvus, ClamAV and OCR suites already have: `#[ignore]`d with a reason naming what is
//! required, run in CI with `--include-ignored` against an environment that has it.
//!
//! Point `ENCLAVE_EMBEDDING_MODEL` at a directory holding `model.rten` and `tokenizer.json` —
//! produced by the conversion in `docs/08-BYO-INFRA.md §18.1` — and run:
//!
//! ```text
//! ENCLAVE_EMBEDDING_MODEL=/path/to/model cargo test --release -p enclave-embeddings \
//!     --test mounted -- --include-ignored
//! ```
//!
//! **Run it in release.** `rten` says so in its own documentation, and a debug build of the
//! inference kernels turns a two-second forward pass into something that reads as a hang.
//!
//! # What is asserted, and what deliberately is not
//!
//! `docs/12-TESTING.md §1.1`. Nothing here measures whether `bge-m3` embeds *well* — whether two
//! paraphrases land near each other, whether retrieval improves, whether the multilingual claim
//! holds. That is BAAI's problem, settled by their own evaluation, and a test of it here would fail
//! when they improve the model, on a line nobody in this repository can act on.
//!
//! What is ours is the wiring, and all of it is asserted below: that the mount loads, that a
//! missing half of it is an outage rather than a provider that embeds nothing, that the vectors
//! come back **one per chunk in the order the chunks were given**, that they are the width the
//! collection was created with, that they are unit length because the index is `COSINE`, and that
//! the model id that reaches `index_manifests.embedding_model` is the one this build indexes
//! against.
//!
//! The two properties worth naming as *ours* rather than obvious: **order** and **completeness**.
//! `TextBatch::texts` documents the positional contract — a provider that reordered or coalesced
//! would attach vectors to the wrong chunk coordinates, which surfaces as a search result
//! deep-linking to the wrong page and never as an error.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};

use enclave_core::ClassificationRank;
use enclave_embeddings::{
    ClassifiedText, EmbeddingError, EmbeddingProvider, EmbeddingRouter, Local, MountedModel,
    TextBatch, ACTIVE,
};

/// Attached to every `#[ignore]` so the requirement is named at the test rather than in a comment
/// somebody has to go and find.
const NEEDS_MODEL: &str = "requires the converted bge-m3 weights on a volume named by \
                           ENCLAVE_EMBEDDING_MODEL; CI runs it with --include-ignored";

/// A rank, so a [`ClassifiedText`] can be built. Nothing here is about routing.
const RESTRICTED: ClassificationRank = ClassificationRank::new(40);

/// The largest chunk `enclave_indexing::ChunkBudget::DEFAULT` can produce.
///
/// A literal rather than the constant itself, because `enclave-embeddings` does not depend on
/// `enclave-indexing` and inventing that edge to read one number would be worse than restating it.
/// It is checked where the two meet, in `crates/worker/tests/embedding.rs`, which holds both.
const LARGEST_CHUNK_BYTES: usize = 3_200;

fn mount() -> PathBuf {
    PathBuf::from(
        std::env::var("ENCLAVE_EMBEDDING_MODEL")
            .expect("ENCLAVE_EMBEDDING_MODEL must name the mounted model directory"),
    )
}

fn model() -> MountedModel {
    MountedModel::mounted(&mount()).expect("the mounted directory holds the converted model")
}

fn batch(chunks: &[&str]) -> TextBatch<Local> {
    TextBatch::<Local>::admit(ClassifiedText::new(
        RESTRICTED,
        chunks.iter().map(|chunk| (*chunk).to_owned()).collect(),
    ))
}

/// What the mount failure's *cause* says.
///
/// `EmbeddingError::LocalUnavailable`'s own `Display` is the fixed sentence the API edge shows; the
/// path an operator needs is on the `#[source]` beneath it, which is the arrangement
/// `crates/embeddings/src/error.rs` chose so a user-facing message cannot grow a filesystem layout.
/// Reading it here is what makes "the refusal names what is missing" checkable.
fn cause(error: &EmbeddingError) -> String {
    use std::error::Error as _;
    error.source().map_or_else(String::new, ToString::to_string)
}

/// How far apart two vectors are, for the tests that need "different" or "the same".
fn distance(left: &[f32], right: &[f32]) -> f32 {
    assert_eq!(left.len(), right.len());
    left.iter().zip(right).map(|(a, b)| (a - b) * (a - b)).sum::<f32>().sqrt()
}

// -----------------------------------------------------------------------------------------------
// The forward pass: the thing `ENC-661` had to prove before anything could be built on it.
// -----------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires the converted bge-m3 weights on a volume named by ENCLAVE_EMBEDDING_MODEL; CI runs it with --include-ignored"]
async fn the_mounted_model_emits_the_width_the_collection_is_created_with() {
    // The whole of `ENC-534`'s decision, made real: `ACTIVE.dimension` is what
    // `enclave_search::collection_schema` creates the dense field with, and until this ran nothing
    // in the workspace had ever produced a vector of that width. A mismatch errors at neither end.
    let model = model();
    assert_eq!(model.dimensions(), ACTIVE.dimension as usize, "{NEEDS_MODEL}");

    let vectors = model.embed(batch(&["the quarterly review is annual"])).await.expect("embed");

    assert_eq!(vectors.len(), 1);
    assert_eq!(vectors[0].dimensions(), ACTIVE.dimension as usize);
}

#[tokio::test]
#[ignore = "requires the converted bge-m3 weights on a volume named by ENCLAVE_EMBEDDING_MODEL; CI runs it with --include-ignored"]
async fn every_chunk_gets_a_vector_and_it_is_the_chunks_own() {
    // Two properties in one arrangement, because they are the two a provider can silently break:
    //
    //  * **completeness** — one vector per chunk. The router refuses a short batch
    //    (`EmbeddingError::IncompleteBatch`), which is exactly why that check exists; this asserts
    //    the provider does not need it.
    //  * **order** — the positional contract `TextBatch::texts` states. A provider that reordered
    //    would attach vectors to the wrong chunk coordinates, and the symptom is a search result
    //    deep-linking to the wrong page rather than an error.
    //
    // Order is checked by embedding the same two texts in both orders and asserting the vectors
    // swap with them. Asserting "the three vectors differ" would pass against a provider that
    // reversed the batch.
    let model = model();

    let forward = model
        .embed(batch(&["a memorandum about drainage", "a recipe for bread"]))
        .await
        .expect("embed");
    let backward = model
        .embed(batch(&["a recipe for bread", "a memorandum about drainage"]))
        .await
        .expect("embed");

    assert_eq!(forward.len(), 2, "a chunk was dropped");
    assert_eq!(backward.len(), 2, "a chunk was dropped");

    assert!(
        distance(forward[0].as_slice(), backward[1].as_slice()) < 1e-4,
        "the first chunk's vector did not follow it to the second position"
    );
    assert!(
        distance(forward[1].as_slice(), backward[0].as_slice()) < 1e-4,
        "the second chunk's vector did not follow it to the first position"
    );
    assert!(
        distance(forward[0].as_slice(), forward[1].as_slice()) > 1e-2,
        "two unrelated chunks produced the same vector, so the text is not reaching the model"
    );
}

#[tokio::test]
#[ignore = "requires the converted bge-m3 weights on a volume named by ENCLAVE_EMBEDDING_MODEL; CI runs it with --include-ignored"]
async fn a_vector_is_unit_length_because_the_dense_index_is_cosine() {
    // `docs/07-SEARCH-INDEXING.md §4`. Cosine over unnormalised vectors makes similarity a function
    // of chunk length, so a long chunk and a short one about the same subject rank apart for a
    // reason that has nothing to do with either. The normalisation is ours (`cls_pool`), not the
    // model's, which is why it is asserted here.
    let vectors =
        model().embed(batch(&["a short one", &"lorem ipsum ".repeat(80)])).await.expect("embed");

    for vector in &vectors {
        let norm = vector.as_slice().iter().map(|value| value * value).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-3, "a vector came back at length {norm}");
    }
}

#[tokio::test]
#[ignore = "requires the converted bge-m3 weights on a volume named by ENCLAVE_EMBEDDING_MODEL; CI runs it with --include-ignored"]
async fn the_largest_chunk_the_chunker_produces_reaches_the_model_whole() {
    // `MAX_TOKENS` is 8192 and the shipped chunker caps a chunk at 3200 **bytes**, so truncation is
    // unreachable — but "unreachable" is a claim, and this is the assertion behind it. If it were
    // reachable the failure would be silent: a truncated chunk embeds perfectly well, and the
    // vector describes the part that fitted.
    //
    // Proved by difference rather than by counting tokens, because the token count is not something
    // this crate exposes and should not be: a full-size chunk and its first half must not produce
    // the same vector, which they would if everything past the cut were being dropped.
    let model = model();

    let whole = "the drainage board met and resolved the following matters. ".repeat(56);
    assert!(whole.len() >= LARGEST_CHUNK_BYTES, "the fixture is smaller than a real chunk");
    let half = &whole[..whole.len() / 2];

    let vectors = model.embed(batch(&[&whole, half])).await.expect("embed");

    assert!(
        distance(vectors[0].as_slice(), vectors[1].as_slice()) > 1e-3,
        "a full-size chunk and its first half embedded identically, so the tail was truncated"
    );
}

#[tokio::test]
#[ignore = "requires the converted bge-m3 weights on a volume named by ENCLAVE_EMBEDDING_MODEL; CI runs it with --include-ignored"]
async fn an_empty_batch_produces_no_vectors_and_that_is_the_only_empty_answer() {
    // The one place an empty answer is correct, and it is correct because it is *equal* to what was
    // asked for. Paired with `a_missing_tokenizer_is_an_outage_and_never_an_empty_batch` below,
    // which is the case where an empty answer would be the silently-unfindable document.
    let vectors = model().embed(batch(&[])).await.expect("an empty batch is not a failure");
    assert!(vectors.is_empty());
}

#[tokio::test]
#[ignore = "requires the converted bge-m3 weights on a volume named by ENCLAVE_EMBEDDING_MODEL; CI runs it with --include-ignored"]
async fn the_router_reports_the_model_a_manifest_has_to_record() {
    // `index_manifests.embedding_model` is compared by `docs/07 §3`'s reindex trigger, and
    // `Embedded` carries the id back from the arm that ran rather than letting a caller supply one.
    // This is the assertion that the value which reaches that column is the model this build
    // indexes against and not `""` or `unconfigured`.
    //
    // `air_gapped` because there is no remote provider in this workspace: it sets the ceiling to
    // `EVERYTHING`, so every rank takes the local arm and `NoRemoteProvider` is never called.
    let router = EmbeddingRouter::air_gapped(model());

    let embedded = router
        .embed(ClassifiedText::new(RESTRICTED, vec!["a restricted paragraph".to_owned()]))
        .await
        .expect("an air-gapped router embeds every rank locally");

    assert_eq!(embedded.model().as_str(), ACTIVE.id);
    assert_eq!(embedded.len(), 1);
    assert_eq!(embedded.embeddings()[0].dimensions(), ACTIVE.dimension as usize);
}

// -----------------------------------------------------------------------------------------------
// Half a mount, and the rule that a failed one is an outage.
// -----------------------------------------------------------------------------------------------

/// A directory holding symlinks to whichever of the two mounted files `keep` names.
///
/// Symlinks and not copies: `model.rten` is 2.2 GB, and a test that copied it would spend a minute
/// and 2.2 GB of disk to prove something about a missing file.
fn partial_mount(name: &str, keep: &[&str]) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("enclave-embedding-{name}"));
    let _ignored = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("create the partial mount");

    let source = mount();
    for file in keep {
        std::os::unix::fs::symlink(source.join(file), directory.join(file))
            .expect("link one half of the mount");
    }
    directory
}

#[test]
#[ignore = "requires the converted bge-m3 weights on a volume named by ENCLAVE_EMBEDDING_MODEL; CI runs it with --include-ignored"]
fn a_missing_tokenizer_is_an_outage_and_never_an_empty_batch() {
    // The distinction the whole module turns on, in the direction that is easy to get wrong. A
    // deployment that staged the weights and not the vocabulary has an outage; a provider that
    // treated it as "no model, embed nothing" would give that deployment a corpus of documents
    // that are filed, visible in the tree and absent from every search.
    //
    // The positive control is `the_mounted_model_emits_the_width_the_collection_is_created_with`:
    // without it, a `mounted` that refused everything would satisfy this assertion.
    let directory = partial_mount("weights-only", &["model.rten"]);

    let error = MountedModel::mounted(&directory)
        .expect_err("a mount with no tokenizer must not read as a working model");
    assert!(matches!(error, EmbeddingError::LocalUnavailable(_)), "{error:?}");

    let shown = cause(&error);
    assert!(shown.contains("tokenizer.json"), "the refusal must name what is missing: {shown}");

    let _ignored = std::fs::remove_dir_all(&directory);
}

#[test]
#[ignore = "requires the converted bge-m3 weights on a volume named by ENCLAVE_EMBEDDING_MODEL; CI runs it with --include-ignored"]
fn a_missing_weights_file_is_an_outage_too() {
    // Both directions, because the tempting implementation checks one.
    let directory = partial_mount("tokenizer-only", &["tokenizer.json"]);

    let error = MountedModel::mounted(&directory)
        .expect_err("a mount with no weights must not read as a working model");
    assert!(matches!(error, EmbeddingError::LocalUnavailable(_)), "{error:?}");

    let shown = cause(&error);
    assert!(shown.contains("model.rten"), "the refusal must name what is missing: {shown}");

    let _ignored = std::fs::remove_dir_all(&directory);
}

#[test]
fn a_directory_that_is_not_a_mount_at_all_is_an_outage() {
    // Not `#[ignore]`d: it needs no weights, and it is the assertion that a deployment which has
    // configured a path and mounted nothing at it gets an error rather than a working-looking
    // provider. On its own it passes for free against a `mounted` that refuses everything — the
    // tests above are the control, and they need the volume, which is why this one is worth having
    // here as well as there.
    let error = MountedModel::mounted(Path::new("/nonexistent/enclave/embedding-model"))
        .expect_err("a missing mount is not a model");
    assert!(matches!(error, EmbeddingError::LocalUnavailable(_)), "{error:?}");
}
