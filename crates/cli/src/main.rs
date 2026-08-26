//! `enclave-cli` — the operator and developer command line (`docs/02-HLD.md §4`, ENC-115).
//!
//! Three commands, each of which exists because of a moment someone actually has:
//!
//! * `seed` — a contributor who has just started the stack and wants something to look at. It
//!   writes the same `tenant-alpha` / `tenant-beta` fixtures every test asserts against, and it
//!   refuses to write to a database holding tenants it did not create.
//! * `migrate` — applying the schema and being told which migrations ran, rather than "done".
//! * `doctor` — the read-only command someone runs when the stack "doesn't work", which checks the
//!   things that are wrong nine times out of ten, including the two security properties that fail
//!   silently: forced row-level security and an append-only audit log.
//! * `set-password` — the moment after the first two: a seeded deployment has a directory full of
//!   accounts and no credentials, so every one of them correctly answers `401`. This is how the
//!   first sign-in becomes possible (`ENC-687`).
//!
//! # What this binary will not do
//!
//! Take a database URL on the command line. It would end up in shell history and in `ps` output,
//! and it carries a password (`CLAUDE.md` rule 11). The connection comes from `DATABASE_URL` or
//! from a configuration file whose DSN is a secret reference.
//!
//! Nor take a *password* on the command line, for the same reason applied to the stronger case.
//! `set-password` reads from stdin and has no flag that could carry one.

mod cli;
mod connect;
mod doctor;
mod migrate;
mod password;
mod schema;
mod seed;

use std::process::ExitCode;

use clap::Parser as _;

use crate::cli::{Cli, Command};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match dispatch(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // The full chain, on stderr, so that piping the report somewhere does not lose the
            // reason. `{error}` rather than `{error:?}`: anyhow's debug form prints a backtrace,
            // which is noise for an operator and hides the message that matters.
            eprintln!();
            eprintln!("error: {error}");
            for cause in error.chain().skip(1) {
                eprintln!("  caused by: {cause}");
            }
            ExitCode::FAILURE
        }
    }
}

/// Resolves the database once, then runs the requested command.
async fn dispatch(cli: Cli) -> anyhow::Result<()> {
    let target = connect::Target::resolve(cli.config.as_deref()).await?;

    match &cli.command {
        Command::Seed(args) => seed::run(&target, args).await,
        Command::Migrate => migrate::run(&target).await,
        Command::Doctor => doctor::run(&target).await,
        Command::SetPassword(args) => password::run(&target, args).await,
    }
}
