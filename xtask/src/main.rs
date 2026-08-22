//! Build tooling — the structural lints CI enforces, runnable with the same command locally.
//!
//! Structural gates are assertions about the codebase rather than its behaviour
//! (`docs/12-TESTING.md §5`). The ones that are pure shell live in `.github/`; the ones that need
//! to understand Rust live here, so that a developer can run the identical check before pushing
//! instead of discovering it in a red pull request.

mod audit_coverage;
mod policy_routing;

use anyhow::{bail, Result};

/// Dispatch a subcommand.
///
/// # Errors
///
/// Returns an error when the subcommand is unknown or the lint it names fails. The non-zero exit
/// is what CI keys on; the diagnostics are printed by the lint itself first.
fn main() -> Result<()> {
    let subcommand = std::env::args().nth(1);
    match subcommand.as_deref() {
        Some("policy-routing") => policy_routing::run(),
        Some("audit-coverage") => audit_coverage::run(),
        Some(other) => bail!("unknown subcommand `{other}`\n{USAGE}"),
        None => {
            println!("{USAGE}");
            Ok(())
        }
    }
}

const USAGE: &str = "\
usage: cargo run -p xtask -- <subcommand>

subcommands:
  policy-routing   assert every Axum route handler reaches PolicyEngine::enforce
                   (CLAUDE.md rule 1, docs/12-TESTING.md §5)
  audit-coverage   assert every refusal is constructed where the policy engine records it
                   (CLAUDE.md rule 10, plans/M4-GOVERNANCE.md D32)";
