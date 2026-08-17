//! The command line surface.
//!
//! Kept in its own module, free of any I/O, so that the shape of the interface can be asserted in
//! unit tests. Argument parsing is where a destructive command acquires its safety flags, and a
//! test that has to reach a database to find out whether `--force` defaults to `false` is a test
//! nobody runs.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Operator and developer commands for an Enclave deployment.
///
/// Every subcommand needs a database. There is deliberately **no `--database-url` flag**: a URL
/// passed on the command line lands in the shell history and in `ps` output for every user on the
/// machine, and it carries a password. The URL comes from `DATABASE_URL` or from a configuration
/// file that references a secret (`CLAUDE.md` rule 11).
#[derive(Debug, Parser)]
#[command(
    name = "enclave-cli",
    version,
    about = "Operator and developer commands for Enclave",
    long_about = None,
)]
pub(crate) struct Cli {
    /// Configuration file to read the database connection from.
    ///
    /// Without it the connection is read from the `DATABASE_URL` environment variable.
    #[arg(long, short = 'c', value_name = "PATH", global = true)]
    pub(crate) config: Option<PathBuf>,

    /// What to do.
    #[command(subcommand)]
    pub(crate) command: Command,
}

/// The subcommands.
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Write the development fixture tenants into the database.
    Seed(SeedArgs),

    /// Apply every outstanding migration and report which ones ran.
    Migrate,

    /// Check the database the way someone does when the stack "doesn't work". Read-only.
    Doctor,
}

/// Arguments for `seed`.
#[derive(Debug, Args)]
pub(crate) struct SeedArgs {
    /// Which fixture set to write.
    #[arg(long, value_enum, default_value = "dev", value_name = "PROFILE")]
    pub(crate) profile: SeedProfile,

    /// Seed even though the database holds tenants that are not fixtures.
    ///
    /// The refusal exists because `DATABASE_URL` is one exported variable away from pointing at
    /// something that matters.
    #[arg(long)]
    pub(crate) force: bool,
}

/// The fixture sets `seed` knows how to write.
///
/// One variant today, and it is still an enum rather than a `bool`: the profile is printed in the
/// plan and recorded in the report, and a later profile (a large-content set for performance work,
/// say) has to arrive as a new value here rather than as a second seeding command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum SeedProfile {
    /// `tenant-alpha` and `tenant-beta` exactly as `docs/12-TESTING.md §3` defines them.
    Dev,
}

impl SeedProfile {
    /// The spelling used in output, so the plan echoes what was typed.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Dev => "dev",
        }
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use clap::CommandFactory as _;

    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    #[test]
    fn the_command_definition_is_internally_consistent() {
        // clap's own audit: duplicate short flags, an argument referring to a missing group, a
        // `default_value` that its own value parser rejects. All of these are runtime panics
        // otherwise, and this turns them into a test failure at build time.
        Cli::command().debug_assert();
    }

    #[test]
    fn seed_defaults_to_the_dev_profile() {
        // CONTRIBUTING.md documents `seed --profile dev`; a bare `seed` must mean the same thing.
        let cli = parse(&["enclave-cli", "seed"]).expect("seed parses with no arguments");
        let Command::Seed(args) = cli.command else { panic!("expected seed") };
        assert_eq!(args.profile, SeedProfile::Dev);
    }

    #[test]
    fn seed_is_not_forced_unless_force_is_typed() {
        // The default matters more than the flag: if this ever defaulted to true, the refusal that
        // protects a real database would be decoration.
        let cli = parse(&["enclave-cli", "seed", "--profile", "dev"]).expect("parses");
        let Command::Seed(args) = cli.command else { panic!("expected seed") };
        assert!(!args.force);

        let cli = parse(&["enclave-cli", "seed", "--force"]).expect("parses");
        let Command::Seed(args) = cli.command else { panic!("expected seed") };
        assert!(args.force);
    }

    #[test]
    fn an_unknown_profile_is_refused_rather_than_ignored() {
        let err = parse(&["enclave-cli", "seed", "--profile", "production"])
            .expect_err("an unrecognised profile must not silently become the default");
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidValue);
    }

    #[test]
    fn the_config_flag_works_before_and_after_the_subcommand() {
        // `global = true`. Someone who types `enclave-cli seed --config enclave.yaml` should not
        // get a usage error for putting the flag where it reads naturally.
        for args in [
            ["enclave-cli", "--config", "enclave.yaml", "seed"],
            ["enclave-cli", "seed", "--config", "enclave.yaml"],
        ] {
            let cli = parse(&args).expect("both orders parse");
            assert_eq!(cli.config.as_deref(), Some(std::path::Path::new("enclave.yaml")));
        }
    }

    #[test]
    fn a_missing_subcommand_is_an_error_not_a_default() {
        // Which of the two kinds clap picks is its business — showing the help is one of them. What
        // matters is that a bare `enclave-cli` never *runs* anything: the most destructive command
        // here must not be reachable by pressing return.
        let err = parse(&["enclave-cli"]).expect_err("there is no default command");
        assert!(
            matches!(
                err.kind(),
                clap::error::ErrorKind::MissingSubcommand
                    | clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
            ),
            "{:?}",
            err.kind()
        );
    }

    #[test]
    fn force_is_not_accepted_by_the_read_only_commands() {
        // `doctor` is read-only and `migrate` has nothing to override. Accepting `--force` there
        // would teach the flag as a general-purpose incantation, which is how it ends up typed
        // reflexively on `seed`.
        for args in [["enclave-cli", "doctor", "--force"], ["enclave-cli", "migrate", "--force"]] {
            let err = parse(&args).expect_err("--force belongs to seed alone");
            assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
        }
    }
}
