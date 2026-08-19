//! The bounds a rendering attempt runs inside, and what happens when it exceeds one.
//!
//! `docs/06-SECURITY-DLP-ACCESS.md §5`: renditions are produced *"in a sandboxed worker with no
//! network egress, a CPU/memory/time budget, and a hard page limit, because document parsers are a
//! large attack surface."* The roadmap's risk register rates that surface likelihood **High**,
//! impact **High** — the highest-rated pair in the product.
//!
//! # A budget the renderer cannot exceed, rather than one it is asked to respect
//!
//! The obvious design hands [`RenderBudget`] to the renderer and trusts it to stop. That is
//! backwards: the renderer is the component parsing hostile input, so it is the component most
//! likely to be stuck, wrong, or under someone else's control. A budget it enforces on itself
//! protects nothing in the case that matters.
//!
//! So [`crate::Bounded`] enforces the wall clock and the output cap **around** the renderer, from
//! outside. A renderer that ignores its budget entirely still cannot exceed it. The budget is
//! passed in as well, so a well-behaved renderer can fail early and cheaply rather than being
//! killed — but nothing depends on it doing so.
//!
//! Memory and CPU are not enforced here, and this module does not pretend otherwise: an in-process
//! wrapper cannot bound another component's allocations. Those are the worker's process limits
//! (`plans/M2-ACCESS-DELIVERY.md` D17), and [`RenderBudget`] carries them so that the process that
//! spawns the worker has one place to read them from. See [`RenderBudget::max_memory_bytes`].
//!
//! # A refusal is an answer
//!
//! D17: *a timeout is a verdict, not an error.* A document that will not render inside its budget
//! renders to "no preview available" — permanently, cached as such, for that generator. Treated as
//! an error it becomes a retry, and a retry against a document engineered to take forever is a
//! denial-of-service primitive with a scheduler helping it along.
//!
//! This is why [`Refusal`] is a value returned in the success channel and not a variant of
//! [`crate::PreviewError`]. The distinction is the same one `enclave-authorization` draws between a
//! denial and a failure, for the same reason: collapsing them makes an outage indistinguishable
//! from a verdict.

use core::fmt;
use core::time::Duration;

/// What a single rendering attempt is allowed to consume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenderBudget {
    /// How long the attempt may run before it is abandoned.
    pub wall_clock: Duration,
    /// The largest source the renderer will be handed.
    ///
    /// Checked before the bytes are read, not after: the point is to never hold a hostile input in
    /// memory, and a check that runs afterwards has already done the thing it was meant to prevent.
    pub max_input_bytes: u64,
    /// The largest artefact the renderer may produce.
    ///
    /// A decompression bomb's defining property is that it is small going in and enormous coming
    /// out, so an input cap alone does not bound it.
    pub max_output_bytes: u64,
    /// How many pages a paginated profile may render.
    pub max_pages: u32,
    /// The memory ceiling for the worker process.
    ///
    /// Carried, not enforced here — see the module documentation. It exists on this struct so that
    /// the deployment's limit and the renderer's expectations come from one value rather than from
    /// a container manifest and a constant that drift apart.
    pub max_memory_bytes: u64,
}

impl RenderBudget {
    /// The budget in force unless a deployment says otherwise.
    ///
    /// 30 seconds is generous for a document a person is waiting on and short enough that a stuck
    /// render frees its slot inside one page load. 512 MiB in and 256 MiB out bound the two
    /// directions separately, because the bombs go in the second one. 500 pages is well past what
    /// anyone previews and well short of what exhausts a disk.
    pub const DEFAULT: Self = Self {
        wall_clock: Duration::from_secs(30),
        max_input_bytes: 512 * 1024 * 1024,
        max_output_bytes: 256 * 1024 * 1024,
        max_pages: 500,
        max_memory_bytes: 1024 * 1024 * 1024,
    };
}

impl Default for RenderBudget {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Why no rendition was produced, when nothing went wrong.
///
/// Every variant is a *verdict* about this source under this profile: re-running it changes
/// nothing, so the answer is cached and the caller is told "no preview available" rather than
/// invited to retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// The attempt exceeded [`RenderBudget::wall_clock`].
    ///
    /// The single most important variant: it is what a document engineered to hang produces, and
    /// it is the one a careless implementation turns into a retry loop.
    Timeout,
    /// The source is larger than [`RenderBudget::max_input_bytes`].
    InputTooLarge,
    /// The artefact exceeded [`RenderBudget::max_output_bytes`].
    OutputTooLarge,
    /// A paginated profile exceeded [`RenderBudget::max_pages`].
    TooManyPages,
    /// Nothing in the pipeline renders this media type.
    ///
    /// Not a failure. An installer or a video has no preview and never will, and reporting that as
    /// an error would fill the logs with the ordinary case.
    UnsupportedFormat,
    /// The source parsed as its declared format and the content was not renderable — truncated,
    /// corrupt, or password-protected.
    SourceUnreadable,
}

impl Refusal {
    /// A stable identifier for logs and metrics.
    ///
    /// Never rendered to an end user as-is: `docs/09-UX-WHITE-LABELING.md` and `docs/14-I18N-L10N.md`
    /// require user-facing strings to come from the catalog, and this is a code the catalog keys on.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "TIMEOUT",
            Self::InputTooLarge => "INPUT_TOO_LARGE",
            Self::OutputTooLarge => "OUTPUT_TOO_LARGE",
            Self::TooManyPages => "TOO_MANY_PAGES",
            Self::UnsupportedFormat => "UNSUPPORTED_FORMAT",
            Self::SourceUnreadable => "SOURCE_UNREADABLE",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_default_budget_bounds_both_directions_independently() {
        let budget = RenderBudget::DEFAULT;
        assert!(budget.max_output_bytes > 0);
        assert!(budget.max_input_bytes > 0);
        // Not a style check. If the output cap were derived from the input cap — or, worse, absent
        // — a decompression bomb would pass every check by being small, which is its whole design.
        assert!(
            budget.max_output_bytes < budget.max_input_bytes * 1024,
            "the output cap must bound the bomb, not follow the input"
        );
        assert!(budget.wall_clock > Duration::ZERO, "a zero budget refuses everything");
    }

    #[test]
    fn refusal_codes_are_distinct() {
        // They key metrics and catalog entries; two variants sharing a code would merge a
        // "we cannot render video" count into a "someone is feeding us hostile input" count.
        let all = [
            Refusal::Timeout,
            Refusal::InputTooLarge,
            Refusal::OutputTooLarge,
            Refusal::TooManyPages,
            Refusal::UnsupportedFormat,
            Refusal::SourceUnreadable,
        ];
        let mut codes: Vec<&str> = all.iter().map(|r| r.as_str()).collect();
        codes.sort_unstable();
        let count = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), count);
    }
}
