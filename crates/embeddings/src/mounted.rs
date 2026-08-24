//! The local provider that actually produces vectors, from weights a deployment mounted.
//!
//! `ENC-661`. [`crate::provider`] said *"No real model"* and shipped [`NoLocalModel`], which
//! refuses. This is the implementation that makes a deployment able to stop refusing — and
//! [`NoLocalModel`] stays, because a deployment that has mounted nothing must still refuse rather
//! than embed nothing (`crate`'s three ways a document ends up indexed-with-nothing).
//!
//! # Locality is not weakened here
//!
//! `impl EmbeddingProvider<Local> for MountedModel` is a true statement: the weights are a file on
//! the deployment's own filesystem and the forward pass runs in this process. There is no field
//! naming a destination, no client, no URL — [`crate::provider`]'s "what is deliberately absent
//! from this port" applies to this implementation of it, and it holds by construction because this
//! type has nowhere to put one.
//!
//! A `TextBatch<Local>` is what [`EmbeddingProvider::embed`] takes here, so holding one is still
//! the proof that S8's ceiling was applied — this module reads its texts and does nothing else with
//! them.
//!
//! # Mounted, never baked in
//!
//! [`model::DELIVERY`](crate::model::DELIVERY) is [`Delivery::Mounted`](crate::model::Delivery) and
//! `docs/08-BYO-INFRA.md §18` is why: an air-gapped install pays a multi-gigabyte layer on every
//! image pull for weights that change on a different schedule from the code. `bge-m3` is 2.2 GB.
//!
//! So this type has exactly one constructor, [`MountedModel::mounted`], which takes a directory —
//! the shape [`OcrModels::mounted`](../../enclave_indexing/struct.OcrModels.html) already
//! established, and deliberately not a constructor taking bytes. `include_bytes!` is not something
//! a caller can express, so "bake the model in" is not a shortcut somebody reaches for under
//! deadline.
//!
//! # A failed mount is an outage, never an empty vector
//!
//! Every failure below is [`EmbeddingError::LocalUnavailable`] or [`EmbeddingError::Provider`], and
//! both are retryable: [`crate::error`] has no variant meaning *"this text will not embed"* because
//! there is no such text. There is no path in this module that returns `Ok(Vec::new())` for a
//! non-empty batch, which is the failure `NoLocalModel`'s own comment calls the dangerous one.
//!
//! That is [`MountedOcr`](../../enclave_worker/ocr/struct.MountedOcr.html)'s rule, one artefact
//! along: a volume that failed to attach is an outage, and reporting it as a corpus of documents
//! with no vectors would leave every one of them absent from search long after the outage ended.
//!
//! # What the engine is allowed to say
//!
//! Nothing. `rten` and `tokenizers` errors are derived from a model file an operator staged and
//! from **document text**, and `CLAUDE.md` rule 10 keeps both out of a log line. Every error
//! constructed here carries a fixed string, plus — on the load path only — the mount path, which is
//! operator configuration and is the same distinction `OcrModels::mounted` draws.
//!
//! # Why the forward pass is one chunk at a time
//!
//! The graph takes `[batch, sequence]`, so a batch of chunks has to be padded to its longest
//! member: every chunk in a batch then pays the longest chunk's sequence length, and attention is
//! quadratic in that length. `rten` already parallelises *within* a matmul through `rayon`
//! (`Cargo.toml`'s note on the OCR pin), so the batch dimension buys throughput that the thread
//! pool is largely providing anyway, in exchange for padding waste and a second shape to get
//! wrong. One sequence per pass, in order, inside one [`spawn_blocking`](tokio::task::spawn_blocking).
//!
//! The batch is still the unit of the *port* — [`crate::provider`] explains why there is no
//! `embed_one` — so a caller cannot loop and retry a chunk at a time, which is where a second
//! provider gets introduced. This is an implementation detail behind that boundary.

use core::fmt;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use rten::{Dimension, Model, NodeId};
use rten_tensor::prelude::*;
use rten_tensor::NdTensor;
use tokenizers::tokenizer::Tokenizer;
use tokenizers::TruncationParams;

use crate::error::{EmbeddingError, Result};
use crate::locality::Local;
use crate::model::ACTIVE;
use crate::provider::{Availability, Embedding, EmbeddingProvider, ModelId};
use crate::text::TextBatch;

/// The converted weights, inside the mounted directory.
///
/// `.rten` and not `.onnx`: this build takes `rten` with `default-features = false` plus
/// `rten_format`, so the ONNX parser is not compiled in at all (the workspace manifest argues why an
/// enabled parser nobody uses is still a parser in the image). Conversion is therefore an operator
/// step, and `docs/08-BYO-INFRA.md §18.1` is where it is written down.
const WEIGHTS: &str = "model.rten";

/// The model's own tokenizer, inside the mounted directory.
///
/// Staged beside the weights rather than derived from them. A `.rten` graph carries no vocabulary,
/// and `bge-m3`'s is a 250k-piece SentencePiece unigram — see the workspace manifest for why an
/// approximation here would produce well-formed vectors of the wrong text rather than an error.
const TOKENIZER: &str = "tokenizer.json";

/// The graph's token-id input.
///
/// A property of the published export, asserted rather than assumed: [`MountedModel::mounted`]
/// looks all three of these up and refuses a graph that does not have them, so a directory holding
/// *some other* `.rten` file fails at the mount instead of at the first document.
const INPUT_IDS: &str = "input_ids";

/// The graph's attention-mask input.
const ATTENTION_MASK: &str = "attention_mask";

/// The graph's per-token hidden states, `[batch, sequence, dimension]`.
///
/// Read rather than the export's `sentence_embedding` output, which is `sentence-transformers`'
/// pooling head. Two reasons, and the second is the one that matters:
///
/// 1. Its width is symbolic in the graph, so there is nothing to check a mount against; this
///    output's last dimension is the fixed `1024` that [`MountedModel::mounted`] compares to
///    [`ACTIVE`].
/// 2. Checking the width of one output and reading the values of another is the shape
///    `crates/indexing/src/ocr.rs` refuses on its decode path — inspect with one parse, use another
///    — and the pooling is four lines we can read (see [`cls_pool`]).
const TOKEN_EMBEDDINGS: &str = "token_embeddings";

/// The longest sequence the mounted weights were trained to position.
///
/// `bge-m3` is trained to 8192 tokens. The shipped chunker never approaches it —
/// `ChunkBudget::DEFAULT.max_chars` is 3200 **bytes**, and no encoding produces more than one token
/// per byte — so truncation here is unreachable under the pipeline that feeds this provider, and
/// `tests/mounted.rs` asserts that rather than leaving it as a comment.
///
/// It is configured anyway, because the alternative for an over-long chunk is worse in both
/// directions: without truncation the graph is asked to position tokens beyond its embedding table
/// and fails, and [`crate::error`] has no way to say *"this text will not embed"*, so the document
/// would be retried forever. A bound that is provably not reached costs nothing and closes that.
const MAX_TOKENS: usize = 8192;

/// `bge-m3` at 1024 dimensions, from weights on a volume.
///
/// One forward pass per chunk, on a blocking thread, holding the weights and the vocabulary and
/// nothing else — see the module documentation for why there is no field here that could name a
/// destination.
///
/// [`Arc`] on both because a worker runs many extractions concurrently, the weights are 2.2 GB, and
/// `spawn_blocking` needs an owned `'static` handle.
pub struct MountedModel {
    model: Arc<Model>,
    tokenizer: Arc<Tokenizer>,
    /// Resolved once at the mount, so a forward pass is not three string lookups deep in a loop.
    nodes: Nodes,
    id: ModelId,
    /// The width the mounted graph declares, checked against [`ACTIVE`] at the mount.
    dimension: usize,
}

/// The three graph nodes a forward pass names.
#[derive(Debug, Clone, Copy)]
struct Nodes {
    input_ids: NodeId,
    attention_mask: NodeId,
    token_embeddings: NodeId,
}

impl fmt::Debug for MountedModel {
    /// Names the model and its width, never the graph.
    ///
    /// `Model` is not [`Debug`] and would be the wrong thing to print if it were: a debug line
    /// carrying model internals is gigabytes of weights in a log — `OcrModels`' reason, at four
    /// times the size.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MountedModel")
            .field("model", &self.id.as_str())
            .field("dimension", &self.dimension)
            .finish_non_exhaustive()
    }
}

impl MountedModel {
    /// Loads the weights and the tokenizer from a mounted directory.
    ///
    /// The directory holds [`WEIGHTS`] and [`TOKENIZER`], staged by the deployment;
    /// `docs/08-BYO-INFRA.md §18.1` gives the conversion that produces the first from the published
    /// ONNX export, reproducibly.
    ///
    /// # Errors
    ///
    /// [`EmbeddingError::LocalUnavailable`] for every failure — a missing file, a file that is not a
    /// `.rten` model, a graph without the three nodes a `bge-m3` export has, and a graph whose
    /// declared width is not [`ACTIVE`]'s. All of them are "there is no local model right now",
    /// which is the fact indexing acts on, and [`crate::error`] explains why that is deliberately
    /// not a separate permanent variant.
    ///
    /// The message names the **path** and never the runtime's own error. The path is operator
    /// configuration, which is safe to surface and miserable to diagnose without; a runtime message
    /// is derived from file contents, which is the class `CLAUDE.md` rule 10 keeps out of logs.
    pub fn mounted(directory: &Path) -> Result<Self> {
        let weights = directory.join(WEIGHTS);
        let model = Model::load_file(&weights).map_err(|_| unavailable(&weights, "load"))?;

        let vocabulary = directory.join(TOKENIZER);
        let mut tokenizer =
            Tokenizer::from_file(&vocabulary).map_err(|_| unavailable(&vocabulary, "load"))?;

        // See `MAX_TOKENS`: unreachable under the shipped chunker, and configured so that an
        // over-long chunk cannot become a document that is retried forever.
        tokenizer
            .with_truncation(Some(TruncationParams {
                max_length: MAX_TOKENS,
                ..TruncationParams::default()
            }))
            .map_err(|_| unavailable(&vocabulary, "configure"))?;

        let node = |name: &str| {
            model.find_node(name).ok_or_else(|| {
                EmbeddingError::LocalUnavailable(anyhow::anyhow!(
                    "the model at {} has no `{name}` node, so it is not the graph this build \
                     embeds with",
                    weights.display()
                ))
            })
        };
        let nodes = Nodes {
            input_ids: node(INPUT_IDS)?,
            attention_mask: node(ATTENTION_MASK)?,
            token_embeddings: node(TOKEN_EMBEDDINGS)?,
        };

        // `ENC-533` at the mount rather than at the first write. The collection's width is fixed
        // when it is created, so a mounted model of the wrong width is a reindex discovered late —
        // and it errors at neither end, because Milvus accepts the width it was made with and a
        // model emits the width it was trained at.
        //
        // **This check has no test, and that is stated rather than left to be assumed.** Deleting
        // it fails nothing in the suite, because the only model any test mounts is `bge-m3` and
        // `bge-m3` is 1024 wide — falsifying it needs a deliberately wrong model, which would be a
        // binary fixture nobody can review in a diff (`crates/indexing/tests/pdf.rs`'s argument
        // against exactly that). Recorded because `docs/12 §1.2` says a break that fails nothing is
        // a result, and because a reader must not mistake this for a covered control.
        //
        // What *is* covered is the same disagreement at two later layers, both with real tests:
        // `VectorStage::for_collection` refuses a collection whose server-reported width is not
        // `ACTIVE.dimension`, and `VectorStage::write` refuses a batch whose vectors are not the
        // width the deployment claimed. This is the earliest and least tested of the three.
        let dimension = declared_width(&model, nodes.token_embeddings)
            .ok_or_else(|| unavailable(&weights, "read the output width of"))?;
        if dimension != ACTIVE.dimension as usize {
            return Err(EmbeddingError::LocalUnavailable(anyhow::anyhow!(
                "the model at {} emits {dimension}-dimensional vectors and this build indexes \
                 against {} ({}); a collection's width is fixed at creation, so mounting this \
                 would be a reindex rather than a configuration change",
                weights.display(),
                ACTIVE.dimension,
                ACTIVE.id
            )));
        }

        Ok(Self {
            model: Arc::new(model),
            tokenizer: Arc::new(tokenizer),
            nodes,
            // `ModelId::known` and not a name read from the mount. `index_manifests.embedding_model`
            // is compared to decide what needs reindexing, and the mount cannot be asked what it is
            // — see the honesty note in `docs/07-SEARCH-INDEXING.md §9` about swapping weights under
            // a marker that does not move.
            id: ModelId::known(ACTIVE.id),
            dimension,
        })
    }
}

/// The last dimension of a node's declared shape, when the graph states one.
///
/// `None` for a symbolic width, which is what makes the check above a real one: a graph that does
/// not say how wide its hidden states are is refused rather than assumed to be right.
fn declared_width(model: &Model, node: NodeId) -> Option<usize> {
    match model.node_info(node)?.shape()?.last()? {
        Dimension::Fixed(width) => Some(*width),
        Dimension::Symbolic(_) => None,
    }
}

/// A mount failure that names the path and nothing the runtime said.
fn unavailable(path: &Path, verb: &str) -> EmbeddingError {
    EmbeddingError::LocalUnavailable(anyhow::anyhow!(
        "could not {verb} the mounted embedding model at {}",
        path.display()
    ))
}

#[async_trait]
impl EmbeddingProvider<Local> for MountedModel {
    fn model(&self) -> &ModelId {
        &self.id
    }

    fn dimensions(&self) -> usize {
        self.dimension
    }

    async fn embed(&self, batch: TextBatch<Local>) -> Result<Vec<Embedding>> {
        if batch.is_empty() {
            // The only case in this module where an empty answer is correct, and it is correct
            // because it is *equal* to what was asked for. The router's count check is what makes
            // that statable rather than a special case: zero chunks in, zero vectors out.
            return Ok(Vec::new());
        }

        // Cloned onto the blocking thread rather than borrowed. `spawn_blocking` needs `'static`,
        // and the alternative — running inference on a poll thread — is what
        // `crates/indexing/src/ocr.rs` argues at length is not bounded by anything: a wall clock
        // built from `tokio::time::timeout` cannot interrupt a thread already inside a matmul.
        let texts: Vec<String> = batch.texts().to_vec();
        let model = Arc::clone(&self.model);
        let tokenizer = Arc::clone(&self.tokenizer);
        let nodes = self.nodes;
        let width = self.dimension;

        match tokio::task::spawn_blocking(move || {
            embed_all(&model, &tokenizer, nodes, width, &texts)
        })
        .await
        {
            Ok(vectors) => vectors,
            // A panicked or cancelled worker, reported as *ours* and with nothing of the payload.
            // `JoinError`'s own `Display` can carry a panic message, and a panic inside a
            // tokenizer is a message derived from document text (`CLAUDE.md` rule 10).
            //
            // Retryable, like everything else here, and the tension is worth stating rather than
            // hiding: a panic on the same bytes panics again, so this retries. It is still the
            // right answer, because `crate::error` has no permanent variant *by design* — the one
            // that existed would be mapped to "give up on this document", which is the silently
            // unfindable file this whole crate is arranged against.
            Err(_) => Err(EmbeddingError::Provider(anyhow::anyhow!(
                "the embedding worker thread did not complete"
            ))),
        }
    }

    async fn availability(&self) -> Availability {
        // The weights are loaded and resident: there is no session to lose and no endpoint to
        // probe. Reported for the operator surfaces of `docs/08 §2`; the router never asks
        // (`Availability` says why that is deliberate).
        Availability::Ready
    }
}

/// One vector per text, in order, on the calling (blocking) thread.
///
/// Sequential and not `rayon`: `rten` already runs a thread pool inside each forward pass, so
/// parallelising the loop as well would multiply two pools together on a thread the runtime sized
/// for one — the parallelism-nobody-is-accounting-for the workspace manifest names.
fn embed_all(
    model: &Model,
    tokenizer: &Tokenizer,
    nodes: Nodes,
    width: usize,
    texts: &[String],
) -> Result<Vec<Embedding>> {
    let mut vectors = Vec::with_capacity(texts.len());
    for text in texts {
        vectors.push(embed_one(model, tokenizer, nodes, width, text)?);
    }
    Ok(vectors)
}

/// Tokenize, run the graph, take the `CLS` state, normalise.
fn embed_one(
    model: &Model,
    tokenizer: &Tokenizer,
    nodes: Nodes,
    width: usize,
    text: &str,
) -> Result<Embedding> {
    // `true`: the special tokens are what the model was trained with, and position 0 being `<s>` is
    // what makes `cls_pool` below read the right row. Dropping them would produce a vector that is
    // well-formed, plausible and not what the weights compute.
    let encoded = tokenizer
        .encode(text, true)
        .map_err(|_| provider("a chunk could not be tokenized for the mounted model"))?;

    // `i32` and not `i64`: the conversion to `.rten` narrows ONNX's integer tensors, and `rten`
    // has no 64-bit integer tensor to hand one to.
    let ids: Vec<i32> = encoded.get_ids().iter().map(|&id| id as i32).collect();
    if ids.is_empty() {
        // A tokenizer that produced nothing for a non-empty chunk. Refused rather than embedded as
        // a zero vector: a zero vector is a valid-looking row in the collection that matches
        // nothing, which is the indexed-with-nothing outcome by another route.
        return Err(provider("the mounted tokenizer produced no tokens for a chunk"));
    }

    let tokens = ids.len();
    let ids = NdTensor::from_data([1, tokens], ids);
    // Every token is real: one sequence per pass means there is no padding to mask (see the module
    // documentation). Built explicitly anyway because the graph requires the input, and a mask that
    // is implicitly right is one that becomes implicitly wrong the day batching is added.
    let mask = NdTensor::from_data([1, tokens], vec![1_i32; tokens]);

    let [output] = model
        .run_n(
            vec![(nodes.input_ids, ids.view().into()), (nodes.attention_mask, mask.view().into())],
            [nodes.token_embeddings],
            None,
        )
        .map_err(|_| provider("the mounted embedding model failed to run"))?;

    let states: NdTensor<f32, 3> = output
        .try_into()
        .map_err(|_| provider("the mounted embedding model returned an unexpected output shape"))?;

    cls_pool(&states, width).ok_or_else(|| {
        provider("the mounted embedding model returned no hidden state for the CLS token")
    })
}

/// `bge-m3`'s dense vector: the first token's hidden state, L2-normalised.
///
/// This is the pooling `BAAI`'s own reference implementation performs for the dense head — take
/// `last_hidden_state[:, 0]`, normalise — and it is done here rather than read out of the export's
/// `sentence_embedding` output for the reason [`TOKEN_EMBEDDINGS`] gives.
///
/// Normalised because the collection's dense index is `COSINE` (`docs/07-SEARCH-INDEXING.md §4`) and
/// an unnormalised vector makes cosine distance a function of chunk length. `None` rather than a
/// panic for a shape that cannot be pooled, so a surprising output is an error the caller reports
/// rather than a dead worker thread.
fn cls_pool(states: &NdTensor<f32, 3>, width: usize) -> Option<Embedding> {
    let [_batch, _sequence, emitted] = states.shape();
    if emitted != width {
        // Belt and braces against the width checked at the mount: `VectorStage` refuses a
        // mis-sized vector per batch as well (`ENC-533`), and a provider that is only correct
        // inside its caller is one somebody will use outside it.
        return None;
    }

    let cls = states.slice((0, 0));
    let mut values: Vec<f32> = cls.iter().copied().collect();
    if values.len() != width {
        return None;
    }

    let norm = values.iter().map(|value| value * value).sum::<f32>().sqrt();
    if norm > 0.0 {
        for value in &mut values {
            *value /= norm;
        }
    }

    Some(Embedding::new(values))
}

/// A run-time failure that says what stage it was, and nothing derived from the text.
fn provider(reason: &'static str) -> EmbeddingError {
    EmbeddingError::Provider(anyhow::anyhow!(reason))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// A mount that is not there is an error, and never a provider that embeds nothing.
    ///
    /// The distinction the module exists to hold: `Ok(None)`-shaped thinking here would give a
    /// deployment whose model volume failed to attach a corpus of documents with no vectors and no
    /// error anywhere. This assertion is cheap and needs no weights; the positive control — that a
    /// real mount *does* build — is `tests/mounted.rs`, which needs 2.2 GB and so cannot live here.
    #[test]
    fn a_mount_that_does_not_exist_is_an_outage_and_never_an_empty_provider() {
        let error = MountedModel::mounted(Path::new("/nonexistent/enclave/embedding-model"))
            .expect_err("a missing mount must not read as `no model`");
        assert!(matches!(error, EmbeddingError::LocalUnavailable(_)), "{error:?}");
    }

    /// The mount refusal names the path and nothing the runtime said.
    ///
    /// `CLAUDE.md` rule 10, and the same distinction `OcrModels::mounted` draws: a path is operator
    /// configuration and is safe to surface, while a runtime's message is derived from the contents
    /// of a file.
    #[test]
    fn a_mount_failure_names_the_operators_path_and_not_the_runtimes_message() {
        let error = MountedModel::mounted(Path::new("/nonexistent/enclave/embedding-model"))
            .expect_err("a missing mount is an error");

        // The variant's own `Display` is the fixed sentence the API edge shows — that is the point
        // of the split in `crate::error` — so the operator's path is read off the `#[source]`
        // beneath it. A message that carried both would put a filesystem layout on a user-facing
        // surface, and one that carried neither would be undiagnosable.
        let cause = std::error::Error::source(&error).map(ToString::to_string).unwrap_or_default();
        assert!(cause.contains("/nonexistent/enclave/embedding-model"), "{cause}");
        assert!(cause.contains(WEIGHTS), "the refusal must name the file it looked for: {cause}");
    }

    /// An unpoolable output is `None` rather than a panic or a plausible vector.
    ///
    /// The width check inside [`cls_pool`] is belt-and-braces against the one at the mount, and it
    /// is the layer that would answer if a graph's declared width and its actual output ever
    /// disagreed — which is exactly the mismatch that errors at neither end. Testable without
    /// weights because it is arithmetic over a tensor.
    #[test]
    fn a_hidden_state_of_the_wrong_width_is_refused_rather_than_pooled() {
        let states = NdTensor::from_data([1, 2, 4], vec![1.0_f32; 8]);
        assert!(cls_pool(&states, 1024).is_none(), "a 4-wide state was pooled into a 1024 slot");
    }

    /// The positive control for the assertion above, and the property the collection needs.
    ///
    /// Without it, `cls_pool` returning `None` for everything would satisfy the refusal test and
    /// this module would produce no vectors at all (`docs/12 §1.2`). It also pins the two things
    /// the pooling is *for*: the **first** token's row, and unit length, because the collection's
    /// dense index is `COSINE`.
    #[test]
    fn pooling_takes_the_first_tokens_state_and_returns_it_at_unit_length() {
        // Token 0 is `[3, 4]`; token 1 is `[100, 100]` and must not appear in the answer.
        let states = NdTensor::from_data([1, 2, 2], vec![3.0_f32, 4.0, 100.0, 100.0]);
        let pooled = cls_pool(&states, 2).expect("a 2-wide state pools into a 2 slot");

        let values = pooled.as_slice();
        assert_eq!(values.len(), 2);
        assert!((values[0] - 0.6).abs() < 1e-6, "{values:?}");
        assert!((values[1] - 0.8).abs() < 1e-6, "{values:?}");

        let norm = values.iter().map(|value| value * value).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-6, "an unnormalised vector makes cosine length-dependent");
    }
}
