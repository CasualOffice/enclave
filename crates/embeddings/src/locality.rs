//! Where a provider runs, expressed so the compiler can reason about it.
//!
//! `docs/08-BYO-INFRA.md §2` gives `EmbeddingProvider` a `residency()` method and calls it "what
//! makes classification routing enforceable rather than advisory". It is not, on its own. A method
//! that reports a fact is a fact somebody has to remember to ask for, and the failure mode
//! `plans/M3-DISCOVERY.md` D23 names — a retry against a second provider, added under load by
//! someone fixing a different problem — is precisely the case where nobody asks.
//!
//! So locality is a *type parameter* here rather than a value. [`Local`] and [`Remote`] are
//! uninhabited-in-practice marker types that appear in [`EmbeddingProvider`](crate::EmbeddingProvider)'s
//! signature and in [`TextBatch`](crate::TextBatch)'s. A provider does not *report* that it is
//! local; it is local because `EmbeddingProvider<Local>` is the trait it implements, and the router
//! holds it in a slot typed for that trait. Wiring a network client into the local slot is then an
//! `impl EmbeddingProvider<Local> for HostedApiClient` — a false statement written in a diff, which
//! is the shape of mistake review catches. A `residency()` that returns the wrong constant is not.
//!
//! `residency()` still belongs on the port for the things it is good at: the admin "test
//! connection" surface, the startup residency validation of `docs/08 §18`, and telling an operator
//! which endpoint their `CONFIDENTIAL` content went to. It is a description. It is not the control.
//!
//! # Why the trait is sealed
//!
//! `docs/07-SEARCH-INDEXING.md §2.3` has three tiers, not two: `LOCAL_ONLY`, `APPROVED_ONLY` and
//! `ANY`. M3 implements the boundary that S8 is about — local against everything else — and an
//! `Approved` tier will want to sit between them.
//!
//! Sealing means that tier has to be added *here*, beside the ceiling comparison in
//! [`crate::text`], rather than declared by a downstream crate that then obtains an
//! `EmbeddingProvider<TheirTier>` and a `TextBatch<TheirTier>` with admission rules of its own
//! devising. A third locality is a change to this crate's routing rules, and it should read like
//! one.

/// A place an embedding provider can run, as a type.
///
/// Implemented only by [`Local`] and [`Remote`], and sealed so it stays that way — see the module
/// documentation.
pub trait Locality: sealed::Sealed + Send + Sync + 'static {
    /// What to call this locality in an error message or a metric label.
    ///
    /// An associated constant rather than a `Display` impl on the marker types, because the marker
    /// types are never instantiated: the only thing that ever exists is `Local` as a type argument.
    const LABEL: &'static str;
}

/// In-cluster or in-process: the tenant's own compute, on the tenant's own network.
///
/// The only locality `RESTRICTED` content may reach (`docs/07 §2.3`), and — with the ceiling set to
/// [`LocalCeiling::EVERYTHING`](crate::LocalCeiling::EVERYTHING) — the only locality an air-gapped
/// install has at all (`docs/08 §18`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Local;

/// Anything reached across a network boundary the tenant does not control.
///
/// Deliberately one bucket, not a gradient. A customer-hosted inference endpoint in the tenant's
/// own VPC and a public API are different *risks*, and the residency validation of `docs/08 §18`
/// treats them differently — but for S8 they are the same *answer*: not somewhere `RESTRICTED` text
/// goes. Splitting the bucket here would put the S8 boundary in the middle of an enum, where an
/// added variant lands on the permissive side by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Remote;

impl Locality for Local {
    const LABEL: &'static str = "local";
}

impl Locality for Remote {
    const LABEL: &'static str = "remote";
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Local {}
    impl Sealed for super::Remote {}
}
