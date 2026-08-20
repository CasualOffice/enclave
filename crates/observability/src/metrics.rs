//! Process-wide metrics: the instruments an operator alerts on, and the text exposition that
//! carries them to Prometheus.
//!
//! # Why this is hand-rolled rather than `prometheus` or `metrics`
//!
//! The workspace pins every shared dependency once, in the root manifest, and neither of those
//! crates is pinned. Adding one is a workspace-level decision with a `cargo-deny` licence and
//! advisory review attached to it, and it is not a decision an exit criterion about two numbers
//! should make on everyone else's behalf.
//!
//! What alerting on those two numbers actually needs from a metrics library is a monotonic counter,
//! a settable gauge and the 0.0.4 text exposition format. That is this file, it has no supply chain,
//! and nothing outside it knows how a counter stores its value — so replacing it wholesale when a
//! real registry is pinned is a change to one module.
//!
//! **What this deliberately is not.** No histograms, no summaries, no exemplars, no push gateway, no
//! OTLP. `docs/11-OPERATIONS.md §1` states latency SLOs as P95s, and a P95 needs a histogram: this
//! module cannot serve those objectives and does not pretend to. When a latency SLO needs alerting,
//! the registry decision gets made properly rather than extended sideways from here.
//!
//! # Why every instrument is a `static` in this file
//!
//! An instrument that registers itself the first time its code path runs is *absent* until then, and
//! an absent metric is indistinguishable from a metric sitting at zero. The whole point of the
//! alerts wired to this module is that the difference matters: a post-filter drop ratio of zero is
//! the alarming reading, and it is only legible if the counters were there, at zero, from process
//! start.
//!
//! So the instruments are declared here, [`ALL`] enumerates them, and every one is rendered from the
//! first scrape whether or not anything has touched it. A test reads this file's own source and
//! fails if something was declared and left out of [`ALL`] — the same trick the span attribute
//! conventions use, for the same reason: a metric missing from the exposition is not an error
//! anywhere, it is a dashboard that is quietly empty six months later.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// A label attached to every sample of one instrument, fixed at declaration.
///
/// Constant rather than per-observation because the label sets in this module are enumerable:
/// `reason="denylisted"` and `reason="unauthorized"` are two instruments, not one instrument with a
/// runtime key. Where a label genuinely varies at runtime — the tenant on a gauge — that is
/// [`GaugeVec`], which is bounded on purpose.
#[derive(Debug, Clone, Copy)]
pub struct Label {
    /// The label name.
    pub name: &'static str,
    /// The label value.
    pub value: &'static str,
}

impl Label {
    /// A label with a fixed name and value.
    #[must_use]
    pub const fn new(name: &'static str, value: &'static str) -> Self {
        Self { name, value }
    }
}

/// A count that only ever goes up.
///
/// `Relaxed` ordering throughout. The only reader is the scrape, which asks "how many by now" and
/// has no ordering relationship to any other memory in the process; paying for `SeqCst` on the
/// hottest path in search would buy an operator nothing they can observe.
#[derive(Debug)]
pub struct Counter {
    name: &'static str,
    help: &'static str,
    labels: &'static [Label],
    value: AtomicU64,
}

impl Counter {
    /// Declares an unlabelled counter.
    #[must_use]
    pub const fn new(name: &'static str, help: &'static str) -> Self {
        Self { name, help, labels: &[], value: AtomicU64::new(0) }
    }

    /// Declares a counter carrying fixed labels, for the case where one metric name has a small,
    /// known set of series.
    #[must_use]
    pub const fn labelled(
        name: &'static str,
        help: &'static str,
        labels: &'static [Label],
    ) -> Self {
        Self { name, help, labels, value: AtomicU64::new(0) }
    }

    /// Adds one.
    pub fn increment(&self) {
        self.add(1);
    }

    /// Adds `count`.
    pub fn add(&self, count: u64) {
        self.value.fetch_add(count, Ordering::Relaxed);
    }

    /// The count so far.
    ///
    /// Public so a test can assert that a metric moved when the thing it measures moved — and did
    /// not when it did not, which is the half that catches a miswired counter.
    #[must_use]
    pub fn value(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    /// The metric name, as it appears in the exposition.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }
}

/// A set of gauges sharing one metric name, keyed by a single label whose values appear at runtime.
///
/// # Why the capacity is not optional
///
/// The label this exists for is `tenant_id`, and a map keyed by tenant that nothing ever evicts is a
/// leak in a deployment with tenant churn — one that grows inside the metrics subsystem, which is
/// the last place anybody looks. Worse, an unbounded label makes the scrape response grow without
/// limit, so the failure mode is "the exposition endpoint times out" and every alert goes dark at
/// once.
///
/// Past the cap, new series are refused and [`meta::SERIES_DROPPED`] counts the refusals, so the
/// truncation is a number an operator can see rather than a gap they have to notice.
#[derive(Debug)]
pub struct GaugeVec {
    name: &'static str,
    help: &'static str,
    label: &'static str,
    capacity: usize,
    series: Mutex<BTreeMap<String, u64>>,
}

impl GaugeVec {
    /// Declares a gauge family keyed by `label`, holding at most `capacity` series.
    #[must_use]
    pub const fn new(
        name: &'static str,
        help: &'static str,
        label: &'static str,
        capacity: usize,
    ) -> Self {
        Self { name, help, label, capacity, series: Mutex::new(BTreeMap::new()) }
    }

    /// Sets the current level for one label value.
    ///
    /// A level, not an increment: the denylist drains as well as fills, and a counter here would
    /// show a "size" that rises forever and never comes back down — precisely the wrong shape for
    /// the thing degraded mode switches on.
    pub fn set(&self, label_value: &str, value: u64) {
        let mut series = self.lock();
        if let Some(existing) = series.get_mut(label_value) {
            *existing = value;
            return;
        }
        if series.len() >= self.capacity {
            drop(series);
            meta::SERIES_DROPPED.increment();
            return;
        }
        series.insert(label_value.to_owned(), value);
    }

    /// The current level for one label value, if it has ever been set.
    #[must_use]
    pub fn get(&self, label_value: &str) -> Option<u64> {
        self.lock().get(label_value).copied()
    }

    /// Drops one series.
    ///
    /// Called when the thing the label names stops existing — a deleted tenant. A gauge left behind
    /// reports a denylist size for a tenant that has none, and holds a slot against the cap forever.
    pub fn forget(&self, label_value: &str) {
        self.lock().remove(label_value);
    }

    /// How many series are currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether nothing has been reported yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The metric name, as it appears in the exposition.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Takes the lock, recovering from poisoning rather than propagating it.
    ///
    /// A panic while another thread held this lock says nothing about whether the map is usable, and
    /// a metrics subsystem that starts panicking because it once observed a panic turns a
    /// recoverable incident into an outage of the thing you diagnose incidents with.
    fn lock(&self) -> MutexGuard<'_, BTreeMap<String, u64>> {
        self.series.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

// ---------------------------------------------------------------------------------------------
// Instruments
// ---------------------------------------------------------------------------------------------

/// Metrics about the metrics subsystem itself.
pub mod meta {
    use super::Counter;

    /// Series refused because a [`super::GaugeVec`] was at its cardinality cap.
    ///
    /// Non-zero means some tenant's denylist size is **not** being reported and its alerts cannot
    /// fire. That is a silent hole in the alerting story, so it gets a number of its own rather than
    /// a log line nobody greps for.
    pub static SERIES_DROPPED: Counter = Counter::new(
        "enclave_metrics_series_dropped_total",
        "Label series refused because a gauge family was at its cardinality cap. Non-zero means \
         some series are unreported and their alerts cannot fire.",
    );
}

/// Search metrics: the post-filter's drop counts, and denylist pressure.
///
/// # What each of these means when it moves
///
/// **The drop ratio climbs.** The index is drifting more permissive than the ACLs, and the
/// post-filter is catching it. That is the post-filter working as designed
/// (`crates/search/src/postfilter.rs`), and simultaneously a signal that invalidation is falling
/// behind: candidates are being spent on documents the caller cannot see, so pages come back short
/// and latency is paid for results that are discarded. Correctness is not at risk; result quality
/// is. `docs/11-OPERATIONS.md §5.2` is the runbook.
///
/// **The drop ratio falls to zero.** Worse news than it climbing, and the alert people forget to
/// write. The benign reading — index and ACLs agreeing perfectly, for every tenant, for half an
/// hour — is the least likely explanation. The likely ones are that the post-filter stopped
/// dropping, or that something reached results without going through it at all. A search that
/// silently stopped filtering does not fail, does not log and does not slow down; the only thing it
/// does differently is answer with documents the caller may not see. Zero-with-traffic is an alert,
/// not a green light.
///
/// **The passes counter stops moving.** Either nobody is searching, or search is being served
/// without a pass ever being recorded. Those two are not distinguishable from here — this module
/// cannot see request volume — so the alert on it tickets rather than pages, and its runbook opens
/// by separating them.
///
/// **The denylist size climbs.** Invalidation is behind by exactly this many files. A backlog
/// gauge; it drains on its own once the worker catches up.
///
/// **The denylist size crosses its limit.** Not a warning — a *state change*.
/// `docs/07-SEARCH-INDEXING.md §6.4` puts the default at 10 000, past which
/// `crates/search/src/degraded.rs` engages degraded mode for that tenant: lexical search over
/// PostgreSQL, reduced recall, `degraded: true` in the response. Users see fewer results. The alert
/// should say the tenant is *already degraded*, because by the time it fires, it is.
pub mod search {
    use enclave_core::TenantId;

    use super::{Counter, GaugeVec, Label};

    /// Post-filter passes that completed without error.
    ///
    /// The evidence that the post-filter is running at all. Counted per *pass* rather than per
    /// candidate, because a pass over zero candidates is still proof the code path executed.
    pub static POST_FILTER_PASSES: Counter = Counter::new(
        "enclave_search_postfilter_passes_total",
        "Post-filter passes that completed. Flat while search is being served means results are \
         reaching callers without the post-filter.",
    );

    /// Candidates the index proposed, summed over passes. The drop ratio's denominator.
    pub static CANDIDATES_PROPOSED: Counter = Counter::new(
        "enclave_search_postfilter_candidates_proposed_total",
        "Candidates offered to the post-filter by a candidate generator.",
    );

    /// Candidates dropped because the file is on the retrieval denylist.
    ///
    /// Split from the authorization drops by a label because they mean different things: this one is
    /// *index freshness* — a revocation the index has not heard about (`docs/07 §6.4`) — the other
    /// is the ACL resolution itself refusing. An operator watching the ratio climb needs to know
    /// which, because only one of them points at the invalidation worker.
    pub static CANDIDATES_DROPPED_DENYLISTED: Counter = Counter::labelled(
        "enclave_search_postfilter_candidates_dropped_total",
        "Candidates the post-filter discarded, by reason.",
        &[Label::new("reason", "denylisted")],
    );

    /// Candidates dropped because the caller may not see the file at all.
    pub static CANDIDATES_DROPPED_UNAUTHORIZED: Counter = Counter::labelled(
        "enclave_search_postfilter_candidates_dropped_total",
        "Candidates the post-filter discarded, by reason.",
        &[Label::new("reason", "unauthorized")],
    );

    /// Hits kept with the excerpt withheld: the caller may know the document exists, not read it.
    ///
    /// Not a drop, and deliberately not counted as one. Folding it into the ratio would make the
    /// ratio move when *disclosure* narrowed rather than when the index drifted, and those two call
    /// for opposite responses.
    pub static EXCERPTS_WITHHELD: Counter = Counter::new(
        "enclave_search_postfilter_excerpts_withheld_total",
        "Hits returned with the excerpt withheld because the caller may see the file but not read \
         its content.",
    );

    /// Files currently suppressed from retrieval, per tenant.
    pub static DENYLIST_ENTRIES: GaugeVec = GaugeVec::new(
        "enclave_search_denylist_entries",
        "Files currently suppressed from retrieval for a tenant. A proxy for how far behind \
         invalidation is.",
        "tenant_id",
        DENYLIST_SERIES_CAPACITY,
    );

    /// The limit above which degraded mode engages, per tenant.
    ///
    /// Exported alongside the size so the alert compares against the limit the process is actually
    /// running with. A threshold written into the rule file instead would be a second copy of
    /// `enclave_search::DEFAULT_DENYLIST_LIMIT`, and the copy that drifts is always the one in the
    /// YAML.
    pub static DENYLIST_LIMIT: GaugeVec = GaugeVec::new(
        "enclave_search_denylist_limit",
        "The denylist size above which degraded mode engages for a tenant \
         (docs/07-SEARCH-INDEXING.md 6.4).",
        "tenant_id",
        DENYLIST_SERIES_CAPACITY,
    );

    /// How many tenants may have their denylist size reported before series are refused.
    ///
    /// Two series per tenant, so ten thousand tenants is twenty thousand samples per scrape — large,
    /// and about the point where the exposition stops being cheap. A deployment past it needs
    /// aggregation upstream, not a bigger number here.
    pub const DENYLIST_SERIES_CAPACITY: usize = 10_000;

    /// One completed post-filter pass, as tallies.
    ///
    /// # Why this is not `enclave_search::DropCounts`
    ///
    /// `observability` sits at the bottom of the dependency graph so everything above may depend on
    /// it (`plans/M0-FOUNDATIONS.md` D1). Naming a type from `search` here would invert that and
    /// cycle.
    ///
    /// It is still not a second implementation of the same number, and the distinction is worth
    /// being precise about: this struct *transports* four tallies and derives nothing from them.
    /// There is no `drop_ratio` field, on purpose. The ratio has exactly two implementations —
    /// `DropCounts::drop_ratio` in process, and one recording rule in
    /// `deploy/monitoring/alerts/search.yml` at query time — and both divide the same two numbers
    /// carried here. A ratio recorded as a gauge would be a third, it would be the one the dashboard
    /// reads, and averaging a ratio across scrapes weights a pass with one candidate the same as a
    /// pass with two hundred.
    #[derive(Debug, Clone, Copy)]
    pub struct PostFilterPass {
        /// Candidates the generator offered.
        pub proposed: u64,
        /// Dropped as denylisted.
        pub denylisted: u64,
        /// Dropped as unauthorized.
        pub unauthorized: u64,
        /// Kept, with the excerpt withheld.
        pub excerpt_withheld: u64,
    }

    impl PostFilterPass {
        /// Publishes the pass.
        ///
        /// Every field lands, including the zeros — a pass that dropped nothing has to move
        /// `proposed` while leaving the drop counters alone, because that is the arithmetic the
        /// "ratio is zero" alert reads.
        pub fn record(self) {
            POST_FILTER_PASSES.increment();
            CANDIDATES_PROPOSED.add(self.proposed);
            CANDIDATES_DROPPED_DENYLISTED.add(self.denylisted);
            CANDIDATES_DROPPED_UNAUTHORIZED.add(self.unauthorized);
            EXCERPTS_WITHHELD.add(self.excerpt_withheld);
        }
    }

    /// Reports a tenant's denylist pressure: how many files are suppressed, and the limit that
    /// degrades the tenant.
    ///
    /// Both in one call so no caller can report a size without the limit it is judged against. An
    /// alert comparing a fresh size against a limit published by a since-restarted process with
    /// different configuration is an alert that fires, or fails to, for a reason nobody can
    /// reconstruct afterwards.
    ///
    /// **The producer is the code that already counts.** `crates/search/src/degraded.rs`'s
    /// `Retrieval::decide` is handed both numbers because it needs them to choose a retrieval path;
    /// its caller is where this call belongs. Counting the denylist a second time to feed a metric
    /// would put a second `count(*)` on the search path and a second answer in the tree.
    pub fn record_denylist_size(tenant: TenantId, entries: u64, limit: u64) {
        let tenant = tenant.to_string();
        DENYLIST_ENTRIES.set(&tenant, entries);
        DENYLIST_LIMIT.set(&tenant, limit);
    }

    /// Stops reporting a tenant's denylist pressure.
    ///
    /// For tenant deletion (`docs/11-OPERATIONS.md §12`): a gauge left behind reports a backlog for
    /// a tenant that no longer has one, and holds a slot against the cardinality cap forever.
    pub fn forget_tenant(tenant: TenantId) {
        let tenant = tenant.to_string();
        DENYLIST_ENTRIES.forget(&tenant);
        DENYLIST_LIMIT.forget(&tenant);
    }
}

// ---------------------------------------------------------------------------------------------
// Registry and exposition
// ---------------------------------------------------------------------------------------------

/// One declared instrument, for enumeration by [`ALL`].
#[derive(Debug, Clone, Copy)]
pub enum Instrument {
    /// A monotonic count.
    Counter(&'static Counter),
    /// A family of levels keyed by one label.
    Gauge(&'static GaugeVec),
}

impl Instrument {
    /// The metric name this instrument contributes samples to.
    ///
    /// Several instruments may share one — `..._dropped_total` is two instruments and one metric.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Counter(counter) => counter.name,
            Self::Gauge(gauge) => gauge.name,
        }
    }
}

/// Every instrument this process exports.
///
/// The list *is* the registry. A test reads this file's source and fails if an instrument was
/// declared above and does not appear here, because the failure mode of forgetting is not a compile
/// error, a panic or a wrong number — it is a metric that is never emitted, and alerts wired to it
/// that never fire.
pub const ALL: &[Instrument] = &[
    Instrument::Counter(&search::POST_FILTER_PASSES),
    Instrument::Counter(&search::CANDIDATES_PROPOSED),
    Instrument::Counter(&search::CANDIDATES_DROPPED_DENYLISTED),
    Instrument::Counter(&search::CANDIDATES_DROPPED_UNAUTHORIZED),
    Instrument::Counter(&search::EXCERPTS_WITHHELD),
    Instrument::Gauge(&search::DENYLIST_ENTRIES),
    Instrument::Gauge(&search::DENYLIST_LIMIT),
    Instrument::Counter(&meta::SERIES_DROPPED),
];

/// The `Content-Type` a scrape of [`render_prometheus`] must be served with.
pub const EXPOSITION_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Renders every instrument in the Prometheus text exposition format (version 0.0.4).
///
/// The body of a `/metrics` endpoint. This crate owns the rendering and not the endpoint, because a
/// subscriber crate that opened a socket would be a subscriber crate every test binary had to think
/// about; the HTTP surface belongs to whichever binary is being scraped.
///
/// Series sharing a metric name are emitted as one contiguous group under a single `# HELP` and
/// `# TYPE`, which the format requires — a parser handed two `# TYPE` lines for one name rejects the
/// whole scrape, which would take every alert down at once rather than one.
#[must_use]
pub fn render_prometheus() -> String {
    struct Group {
        name: &'static str,
        help: &'static str,
        kind: &'static str,
        samples: Vec<String>,
    }

    let mut groups: Vec<Group> = Vec::new();
    for instrument in ALL {
        let (name, help, kind) = match instrument {
            Instrument::Counter(counter) => (counter.name, counter.help, "counter"),
            Instrument::Gauge(gauge) => (gauge.name, gauge.help, "gauge"),
        };
        let index = match groups.iter().position(|group| group.name == name) {
            Some(index) => index,
            None => {
                groups.push(Group { name, help, kind, samples: Vec::new() });
                groups.len() - 1
            }
        };

        match instrument {
            Instrument::Counter(counter) => {
                let labels = fixed_labels(counter.labels);
                groups[index].samples.push(format!("{name}{labels} {}", counter.value()));
            }
            Instrument::Gauge(gauge) => {
                for (label_value, value) in gauge.lock().iter() {
                    let label = gauge.label;
                    let escaped = escape_label_value(label_value);
                    groups[index].samples.push(format!("{name}{{{label}=\"{escaped}\"}} {value}"));
                }
            }
        }
    }

    // Built by `push_str` rather than `write!`, because writing to a `String` cannot fail and the
    // workspace denies discarding a `#[must_use]` result — a rule worth keeping absolute rather
    // than carving an exception into for a `Result` that is structurally always `Ok`.
    let mut out = String::new();
    for group in &groups {
        out.push_str(&format!("# HELP {} {}\n", group.name, escape_help(group.help)));
        out.push_str(&format!("# TYPE {} {}\n", group.name, group.kind));
        for sample in &group.samples {
            out.push_str(sample);
            out.push('\n');
        }
    }
    out
}

/// Renders a fixed label set as `{a="b",c="d"}`, or the empty string when there are none.
fn fixed_labels(labels: &[Label]) -> String {
    if labels.is_empty() {
        return String::new();
    }
    let rendered: Vec<String> = labels
        .iter()
        .map(|label| format!("{}=\"{}\"", label.name, escape_label_value(label.value)))
        .collect();
    format!("{{{}}}", rendered.join(","))
}

/// Escapes a label value per the exposition format: backslash, double quote and newline.
///
/// Label values here are UUIDs today, so this escapes nothing in practice. It exists because the
/// next label value comes from configuration or a tenant slug, and an unescaped quote does not
/// corrupt one sample — it corrupts the parse of everything after it in the scrape.
fn escape_label_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

/// Escapes help text: backslash and newline only. A quote is literal in a `# HELP` line.
fn escape_help(help: &str) -> String {
    let mut out = String::with_capacity(help.len());
    for character in help.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal, not a
    // production hazard. The workspace warns on these constructs for non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::TenantId;

    use super::search::{
        PostFilterPass, CANDIDATES_DROPPED_DENYLISTED, CANDIDATES_DROPPED_UNAUTHORIZED,
        CANDIDATES_PROPOSED, DENYLIST_ENTRIES, DENYLIST_LIMIT, EXCERPTS_WITHHELD,
        POST_FILTER_PASSES,
    };
    use super::*;

    /// Instruments are process-global and the harness is threaded, so a test that reads a counter
    /// has to be the only test moving one. Held by every test that asserts on movement; tests that
    /// only inspect declarations or use their own instrument do not need it.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn serial() -> MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
    }

    // --- a metric moves when the thing it measures moves, and not otherwise -------------------

    #[test]
    fn a_pass_that_dropped_nothing_moves_the_proposed_count_and_leaves_the_drops_alone() {
        let _guard = serial();
        let passes = POST_FILTER_PASSES.value();
        let proposed = CANDIDATES_PROPOSED.value();
        let denylisted = CANDIDATES_DROPPED_DENYLISTED.value();
        let unauthorized = CANDIDATES_DROPPED_UNAUTHORIZED.value();

        PostFilterPass { proposed: 20, denylisted: 0, unauthorized: 0, excerpt_withheld: 0 }
            .record();

        assert_eq!(POST_FILTER_PASSES.value(), passes + 1, "the pass itself must be counted");
        assert_eq!(CANDIDATES_PROPOSED.value(), proposed + 20);
        assert_eq!(
            CANDIDATES_DROPPED_DENYLISTED.value(),
            denylisted,
            "nothing was denylisted, so the counter must not move"
        );
        assert_eq!(
            CANDIDATES_DROPPED_UNAUTHORIZED.value(),
            unauthorized,
            "nothing was unauthorized, so the counter must not move"
        );
    }

    #[test]
    fn each_drop_reason_moves_only_its_own_counter() {
        let _guard = serial();
        let denylisted = CANDIDATES_DROPPED_DENYLISTED.value();
        let unauthorized = CANDIDATES_DROPPED_UNAUTHORIZED.value();

        PostFilterPass { proposed: 10, denylisted: 3, unauthorized: 0, excerpt_withheld: 0 }
            .record();
        assert_eq!(CANDIDATES_DROPPED_DENYLISTED.value(), denylisted + 3);
        assert_eq!(
            CANDIDATES_DROPPED_UNAUTHORIZED.value(),
            unauthorized,
            "a denylist drop must not be attributed to authorization: the two point at different \
             steps of the runbook"
        );

        PostFilterPass { proposed: 10, denylisted: 0, unauthorized: 4, excerpt_withheld: 0 }
            .record();
        assert_eq!(CANDIDATES_DROPPED_DENYLISTED.value(), denylisted + 3);
        assert_eq!(CANDIDATES_DROPPED_UNAUTHORIZED.value(), unauthorized + 4);
    }

    #[test]
    fn a_withheld_excerpt_is_not_counted_as_a_drop() {
        let _guard = serial();
        let denylisted = CANDIDATES_DROPPED_DENYLISTED.value();
        let unauthorized = CANDIDATES_DROPPED_UNAUTHORIZED.value();
        let withheld = EXCERPTS_WITHHELD.value();

        PostFilterPass { proposed: 5, denylisted: 0, unauthorized: 0, excerpt_withheld: 5 }
            .record();

        assert_eq!(EXCERPTS_WITHHELD.value(), withheld + 5);
        assert_eq!(CANDIDATES_DROPPED_DENYLISTED.value(), denylisted);
        assert_eq!(
            CANDIDATES_DROPPED_UNAUTHORIZED.value(),
            unauthorized,
            "a hit kept without its excerpt was not dropped, and must not move the ratio"
        );
    }

    #[test]
    fn the_ratio_an_alert_divides_is_the_ratio_the_pass_reported() {
        // The ratio is never recorded, so the property to hold is that the two numbers the alert
        // divides are the two the pass reported. 5 of 20 is 25%, over the paging threshold in
        // deploy/monitoring/alerts/search.yml.
        let _guard = serial();
        let proposed_before = CANDIDATES_PROPOSED.value();
        let dropped_before =
            CANDIDATES_DROPPED_DENYLISTED.value() + CANDIDATES_DROPPED_UNAUTHORIZED.value();

        PostFilterPass { proposed: 20, denylisted: 2, unauthorized: 3, excerpt_withheld: 1 }
            .record();

        let proposed = CANDIDATES_PROPOSED.value() - proposed_before;
        let dropped = CANDIDATES_DROPPED_DENYLISTED.value()
            + CANDIDATES_DROPPED_UNAUTHORIZED.value()
            - dropped_before;
        assert_eq!((proposed, dropped), (20, 5));
        let ratio = dropped as f64 / proposed as f64;
        assert!((ratio - 0.25).abs() < 1e-9, "ratio was {ratio}");
    }

    // --- gauges --------------------------------------------------------------------------------

    #[test]
    fn a_denylist_report_sets_a_level_rather_than_accumulating() {
        let tenant = TenantId::new_v7();
        search::record_denylist_size(tenant, 12_000, 10_000);
        assert_eq!(DENYLIST_ENTRIES.get(&tenant.to_string()), Some(12_000));
        assert_eq!(DENYLIST_LIMIT.get(&tenant.to_string()), Some(10_000));

        // The backlog drained. A counter here would still read 12 000 plus whatever came next, and
        // the tenant would look permanently degraded.
        search::record_denylist_size(tenant, 7, 10_000);
        assert_eq!(DENYLIST_ENTRIES.get(&tenant.to_string()), Some(7));

        search::forget_tenant(tenant);
        assert_eq!(DENYLIST_ENTRIES.get(&tenant.to_string()), None);
        assert_eq!(DENYLIST_LIMIT.get(&tenant.to_string()), None);
    }

    #[test]
    fn one_tenants_denylist_report_does_not_move_anothers() {
        let alpha = TenantId::new_v7();
        let beta = TenantId::new_v7();
        search::record_denylist_size(alpha, 4, 10_000);
        search::record_denylist_size(beta, 11_000, 10_000);

        assert_eq!(DENYLIST_ENTRIES.get(&alpha.to_string()), Some(4));
        assert_eq!(
            DENYLIST_ENTRIES.get(&beta.to_string()),
            Some(11_000),
            "the limit is per tenant: one tenant's reorganisation degrades that tenant and no other"
        );

        search::forget_tenant(alpha);
        search::forget_tenant(beta);
    }

    #[test]
    fn a_gauge_at_its_cardinality_cap_refuses_new_series_and_counts_the_refusal() {
        let _guard = serial();
        static TINY: GaugeVec = GaugeVec::new("enclave_test_tiny", "help", "tenant_id", 2);
        let refused = meta::SERIES_DROPPED.value();

        TINY.set("a", 1);
        TINY.set("b", 2);
        TINY.set("c", 3);

        assert_eq!(TINY.len(), 2);
        assert_eq!(TINY.get("c"), None, "past the cap, a new series is refused");
        assert_eq!(
            meta::SERIES_DROPPED.value(),
            refused + 1,
            "a refused series must be visible as a number, not inferred from a gap"
        );

        // An existing series still updates: the cap bounds distinct labels, not reporting.
        TINY.set("a", 99);
        assert_eq!(TINY.get("a"), Some(99));
        assert_eq!(meta::SERIES_DROPPED.value(), refused + 1);
    }

    // --- exposition ----------------------------------------------------------------------------

    #[test]
    fn every_declared_instrument_is_exported_from_process_start() {
        // Absent and zero look identical to an alert, and the "drop ratio is zero" alert turns on
        // exactly that distinction. So every instrument renders before anything has touched it.
        let rendered = render_prometheus();
        for instrument in ALL {
            let name = instrument.name();
            assert!(
                rendered.contains(&format!("# TYPE {name} ")),
                "`{name}` is declared but never exported:\n{rendered}"
            );
        }
    }

    #[test]
    fn nothing_declared_in_this_file_is_missing_from_all() {
        // Forgetting to add an instrument to `ALL` is not a compile error, a panic or a wrong
        // number — it is a metric that is never emitted and an alert that never fires. So the
        // source itself is the check.
        let source = include_str!("metrics.rs");
        let exported: Vec<&str> = ALL.iter().map(|instrument| instrument.name()).collect();

        for line in source.lines().map(str::trim) {
            let Some(declaration) = line.strip_prefix("pub static ") else { continue };
            let Some((binding, rest)) = declaration.split_once(':') else { continue };
            let rest = rest.trim_start();
            if !rest.starts_with("Counter") && !rest.starts_with("GaugeVec") {
                continue;
            }
            let name = declared_metric_name(source, binding);
            assert!(
                exported.contains(&name.as_str()),
                "`{binding}` declares metric `{name}`, which is missing from `ALL`"
            );
        }
    }

    #[test]
    fn counter_names_end_in_total_and_every_name_is_a_legal_metric_name() {
        for instrument in ALL {
            let name = instrument.name();
            let is_counter = matches!(instrument, Instrument::Counter(_));
            assert!(
                name.starts_with("enclave_"),
                "`{name}` must be namespaced so it cannot collide with a sidecar's metrics"
            );
            assert!(
                name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
                "`{name}` is not a legal Prometheus metric name"
            );
            assert_eq!(
                is_counter,
                name.ends_with("_total"),
                "`{name}`: the `_total` suffix is how a reader knows to wrap it in `rate()`"
            );
        }
    }

    #[test]
    fn a_metric_name_with_two_series_is_one_group_under_one_type_line() {
        // `..._dropped_total` is two instruments and one metric. A parser handed two `# TYPE` lines
        // for one name rejects the whole scrape, taking every alert down rather than one.
        let rendered = render_prometheus();
        let name = "enclave_search_postfilter_candidates_dropped_total";
        let type_lines =
            rendered.lines().filter(|line| *line == format!("# TYPE {name} counter")).count();
        assert_eq!(type_lines, 1, "expected exactly one TYPE line:\n{rendered}");
        assert!(rendered.contains(&format!("{name}{{reason=\"denylisted\"}} ")), "{rendered}");
        assert!(rendered.contains(&format!("{name}{{reason=\"unauthorized\"}} ")), "{rendered}");
    }

    #[test]
    fn a_recorded_gauge_appears_in_the_exposition_under_its_tenant() {
        let tenant = TenantId::new_v7();
        search::record_denylist_size(tenant, 10_001, 10_000);

        let rendered = render_prometheus();
        assert!(
            rendered.contains(&format!(
                "enclave_search_denylist_entries{{tenant_id=\"{tenant}\"}} 10001"
            )),
            "{rendered}"
        );
        assert!(
            rendered.contains(&format!(
                "enclave_search_denylist_limit{{tenant_id=\"{tenant}\"}} 10000"
            )),
            "{rendered}"
        );

        search::forget_tenant(tenant);
    }

    #[test]
    fn a_label_value_cannot_break_out_of_its_quotes() {
        // One unescaped quote does not corrupt one sample, it corrupts the parse of every sample
        // after it — so the whole scrape, and every alert reading it, goes with it.
        assert_eq!(escape_label_value("a\"b\\c"), "a\\\"b\\\\c");

        static HOSTILE: GaugeVec = GaugeVec::new("enclave_test_hostile", "help", "name", 8);
        HOSTILE.set("a\"b", 1);
        assert_eq!(HOSTILE.get("a\"b"), Some(1));
    }

    /// Reads the metric name out of a declaration: the first string literal after the binding.
    fn declared_metric_name(source: &str, binding: &str) -> String {
        let declaration = source
            .find(&format!("pub static {binding}:"))
            .expect("the binding was found by scanning this same source");
        let open = declaration
            + source[declaration..].find('"').expect("every instrument names its metric");
        let start = open + 1;
        let end =
            start + source[start..].find('"').expect("the metric name literal must be closed");
        source[start..end].to_owned()
    }
}
