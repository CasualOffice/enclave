//! Makes an edited migration reach the binary that embeds it.
//!
//! # The defect this closes (`ENC-155`)
//!
//! `sqlx::migrate!` reads `migrations/` at **compile** time and bakes the statements into this
//! crate. Cargo, left to itself, does not know that: the macro's input is a directory no `.rs` file
//! mentions, so editing a `.sql` changes nothing Cargo tracks and `enclave-db` is not rebuilt.
//!
//! The consequence is worse than a stale build. Every schema gate in the workspace — RLS coverage,
//! grant coverage, composite foreign keys — applies migrations through this crate and then inspects
//! the result. Run one after editing a migration and it reports **green against a schema nobody is
//! running**. That is the failure mode this repository has spent four milestones building gates to
//! prevent, arriving through the gates themselves.
//!
//! It was found by a deliberate violation *failing to fail*: removing `FORCE ROW LEVEL SECURITY`
//! from a migration left the RLS gate passing, and reporting one table fewer than the schema
//! actually had. It then caught the person who logged it, two tasks later, as "relation does not
//! exist" against a table the migration plainly creates.
//!
//! # Why a build script rather than a lint or a note in CONTRIBUTING
//!
//! CI is unaffected — it builds from scratch every time — so this is invisible to every check that
//! could otherwise catch it. It only bites a person iterating locally, at the moment they are
//! trusting a gate. A note asking people to remember `touch crates/db/src/migrate.rs` is a control
//! that works until somebody is concentrating on something else, which is precisely when a
//! green-but-stale gate does its damage.
//!
//! `rerun-if-changed` on a directory covers files added and removed as well as edited, which
//! matters here: a new migration is the common case.

fn main() {
    // Relative to this crate's manifest directory, which is where Cargo runs a build script.
    println!("cargo:rerun-if-changed=../../migrations");

    // And the script itself, so that changing the line above takes effect. Without it, editing a
    // build script's directives can leave the previous ones in force for one build — a small trap,
    // but one that would waste exactly the debugging session this file exists to prevent.
    println!("cargo:rerun-if-changed=build.rs");
}
