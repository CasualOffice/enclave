//! **Every endpoint `docs/05-API.md` documents is either registered or marked as absent.**
//!
//! `ENC-997`. `crates/api/tests/reachability.rs` proves one direction — *registered ⇒ answers* — and
//! nothing proved the other. `docs/05` described roughly a third more surface than the binary
//! serves, and a client author reads an API document as a list of things they can call, so an
//! unmarked absence is not a gap in the document: it is a wrong answer given confidently.
//!
//! # Why this is a gate and not a sweep
//!
//! `ENC-985` marked the document by hand, which makes it true exactly once. The three errors that
//! preceded this file were all the same shape and all mine:
//!
//!   * `ENC-988` — a regex matching `\.(rs|ts)` truncated `.test.tsx` and invented six missing
//!     files that were never missing;
//!   * `ENC-985` — normalising `{token}` to `{id}` collapsed the **unregistered**
//!     `GET /shares/{token}` onto the **registered** `PATCH|DELETE /shares/{id}`, and reported
//!     external sharing as working when no recipient can open a link;
//!   * `ENC-998` — searching for tests by an id prefix two of them do not use reported two proved
//!     security properties as untested.
//!
//! Each was found by opening a file, never by improving the grep. So this compares **(method,
//! path)** rather than path alone — the pair is what `ENC-985` got wrong — and it reads the router
//! through `syn` rather than by matching text, reusing [`crate::policy_routing::analyze`], which
//! has its own tests and its own proof that it is reading the router at all.
//!
//! # What counts as "marked"
//!
//! A documented endpoint that is not registered must sit in a `##` section whose prose says so.
//! The accepted phrasings are [`ABSENCE_NOTES`], and they are matched over the **whole section**
//! rather than the line, because the note belongs in a sentence that explains *why* — which is the
//! form `§14` used for years before anything enforced it.
//!
//! This is deliberately coarse. A finer rule — a marker per path — would be more precise and would
//! be ignored: the value here is that adding an undocumented-as-absent endpoint fails review, not
//! that the document carries a machine-readable schema it has no other use for.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};

use crate::policy_routing::{analyze, load_sources, workspace_root, API_SRC};

/// The document this gate reads.
const DOC: &str = "docs/05-API.md";

/// Phrases that mark a section as containing endpoints the binary does not serve.
///
/// Lower-cased before matching. Kept short and few: a long list becomes a list of ways to satisfy
/// the gate without saying anything, and the point is the sentence a reader gets, not the token.
const ABSENCE_NOTES: &[&str] =
    &["not implemented", "not registered", "not built", "is built", "are built", "not testable"];

/// HTTP methods this gate recognises in the document.
const METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE"];

/// One endpoint as the document states it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Documented {
    method: String,
    path: String,
    /// The `##` heading it sits under, so a failure names where to write the note.
    section: String,
    /// 1-based line, so the annotation lands on it.
    line: usize,
}

/// Runs the gate.
///
/// # Errors
///
/// Returns an error when a documented endpoint is neither registered nor marked, and when either
/// input cannot be read or parsed.
pub(crate) fn run() -> Result<()> {
    let root = workspace_root()?;

    let sources = load_sources(&root.join(API_SRC), &root)
        .with_context(|| format!("reading Rust sources under {API_SRC}"))?;
    let registered: BTreeSet<(String, String)> = analyze(&sources)?
        .routes
        .iter()
        .filter_map(|route| {
            route.path.as_ref().map(|path| (route.method.to_uppercase(), normalize(path)))
        })
        .collect();

    // The parse has to be checked before its result is trusted, for `reachability.rs`'s reason: a
    // parser that silently found nothing would report a perfectly clean document.
    anyhow::ensure!(
        !registered.is_empty(),
        "api-surface: no routes were parsed out of {API_SRC}. The gate cannot pass on an empty \
         reading — that is a broken parse, not a clean router."
    );

    let text = std::fs::read_to_string(root.join(DOC)).with_context(|| format!("reading {DOC}"))?;
    let documented = parse(&text);
    anyhow::ensure!(
        !documented.is_empty(),
        "api-surface: no endpoints were parsed out of {DOC}. Same rule as above — an empty reading \
         is a broken parse."
    );

    let marked = marked_sections(&text);

    let unmarked: Vec<&Documented> = documented
        .iter()
        .filter(|entry| !registered.contains(&(entry.method.clone(), entry.path.clone())))
        .filter(|entry| !marked.contains(&entry.section))
        .collect();

    println!(
        "api-surface: {} documented endpoint(s), {} registered route(s), {} section(s) marked.",
        documented.len(),
        registered.len(),
        marked.len()
    );

    if unmarked.is_empty() {
        println!(
            "Every documented endpoint is registered or sits in a section that says it is not."
        );
        return Ok(());
    }

    let mut by_section: BTreeMap<&str, Vec<&Documented>> = BTreeMap::new();
    for entry in &unmarked {
        by_section.entry(entry.section.as_str()).or_default().push(entry);
    }
    for (section, entries) in &by_section {
        for entry in entries {
            println!(
                "::error file={DOC},line={}::{} {} is documented and not registered, and `{}` \
                 does not say so",
                entry.line, entry.method, entry.path, section
            );
        }
    }

    anyhow::bail!(
        "api-surface: {} documented endpoint(s) are neither registered nor marked as absent.\n\
         \n\
         Either register them, or add a sentence to the section saying they are not built and why \
         — one of: {}.\n\
         \n\
         A contract document that does not distinguish the built half from the intended half is \
         read as an inventory, and `ENC-985` is the row for what that cost: `§10` listed six \
         sharing paths of which the two an external recipient actually calls were absent, so the \
         section read as a working feature while no link could be opened.",
        unmarked.len(),
        ABSENCE_NOTES.join(", ")
    );
}

/// Strips the version prefix and the parameter names, so two spellings of one route compare equal.
///
/// The parameter *names* are dropped and the parameter *positions* are not: `docs/05` writes
/// `{token}` where the router writes `{id}`, and treating those as different endpoints would fail
/// the gate on every parameterised path. Collapsing the whole segment instead — to `{}` — keeps
/// `/shares/{token}` and `/shares/{id}` equal, which is correct, because what distinguishes them is
/// the **method**, and that is compared separately. Getting exactly this wrong is `ENC-985`.
fn normalize(path: &str) -> String {
    let path = path.strip_prefix("/api/v1").unwrap_or(path);
    let joined = path
        .split('/')
        .map(|segment| if segment.starts_with('{') { "{}" } else { segment })
        .collect::<Vec<_>>()
        .join("/");
    let trimmed = joined.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// Every `##` section whose prose contains one of [`ABSENCE_NOTES`].
fn marked_sections(text: &str) -> BTreeSet<String> {
    let mut marked = BTreeSet::new();
    let mut section = String::new();
    let mut body = String::new();
    for line in text.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            if ABSENCE_NOTES.iter().any(|note| body.contains(note)) {
                marked.insert(section.clone());
            }
            section = heading.trim().to_owned();
            body.clear();
        } else {
            body.push_str(&line.to_lowercase());
            body.push('\n');
        }
    }
    if ABSENCE_NOTES.iter().any(|note| body.contains(note)) {
        marked.insert(section);
    }
    marked
}

/// Pulls every `METHOD /path` the document states, from fenced blocks and from tables alike.
fn parse(text: &str) -> Vec<Documented> {
    let mut found = Vec::new();
    let mut section = String::new();
    for (index, line) in text.lines().enumerate() {
        if let Some(heading) = line.strip_prefix("## ") {
            section = heading.trim().to_owned();
            continue;
        }
        let trimmed = line.trim();
        let (methods, rest) = if trimmed.starts_with('|') {
            // `| `GET` | `/files/{id}/shares` | notes |`
            let mut cells = trimmed.trim_matches('|').split('|');
            let (Some(first), Some(second)) = (cells.next(), cells.next()) else { continue };
            (first.trim().trim_matches('`').to_owned(), second.trim().trim_matches('`').to_owned())
        } else {
            // `GET|POST   /workspaces/{id}/lists   trailing prose`
            let mut parts = trimmed.split_whitespace();
            let (Some(first), Some(second)) = (parts.next(), parts.next()) else { continue };
            (first.to_owned(), second.to_owned())
        };

        if !rest.starts_with('/') {
            continue;
        }
        // A path cell may carry a trailing backtick-quoted comment or punctuation; the path is the
        // leading run of URL characters.
        let path: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || "/{}_.-*".contains(*c))
            .collect();
        if path.len() < 2 {
            continue;
        }
        // `*` appears in prose forms like `/files/*/download`. Those are illustrations, not
        // contracts, and pairing one with a method would invent an endpoint nobody wrote.
        if path.contains('*') {
            continue;
        }

        for method in methods.split('|') {
            let method = method.trim().to_uppercase();
            if METHODS.contains(&method.as_str()) {
                found.push(Documented {
                    method,
                    path: normalize(&path),
                    section: section.clone(),
                    line: index + 1,
                });
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_version_prefix_and_a_parameter_name_do_not_make_two_endpoints() {
        // The `ENC-985` case, stated as an assertion: these are one path, and only the method tells
        // them apart.
        assert_eq!(normalize("/api/v1/shares/{token}"), normalize("/shares/{id}"));
        assert_eq!(normalize("/api/v1/files/{id}/metadata"), "/files/{}/metadata");
    }

    #[test]
    fn both_spellings_the_document_uses_are_parsed() {
        let doc =
            "## 10. Sharing\n\n| `POST` | `/files/{id}/shares` | Create |\n\n## 12. Lists\n\n\
                   ```text\nGET|POST         /workspaces/{id}/lists\n```\n";
        let found = parse(doc);
        assert!(found.contains(&Documented {
            method: "POST".to_owned(),
            path: "/files/{}/shares".to_owned(),
            section: "10. Sharing".to_owned(),
            line: 3,
        }));
        // `GET|POST` is two endpoints, not one — the pair is the unit this gate compares.
        assert_eq!(found.iter().filter(|e| e.path == "/workspaces/{}/lists").count(), 2);
    }

    #[test]
    fn a_prose_wildcard_is_not_an_endpoint() {
        // `/files/*/download` appears in prose. Pairing it with a method would invent a contract.
        assert!(parse("## 9. Delivery\n\nPOST /files/*/download\n").is_empty());
    }

    #[test]
    fn a_section_is_marked_only_by_its_own_prose() {
        let doc = "## 16. Signing\n\nEvery signing route below is **not implemented**.\n\n\
                   ## 17. Webhooks\n\nDeliveries are signed.\n";
        let marked = marked_sections(doc);
        assert!(marked.contains("16. Signing"));
        // The positive control: a section that says nothing must not inherit its neighbour's note,
        // which is the bug a single `text.contains(..)` would have.
        assert!(!marked.contains("17. Webhooks"));
    }
}
