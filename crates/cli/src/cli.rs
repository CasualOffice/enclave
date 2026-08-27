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

    /// Reclaim upload sessions stranded in `SCANNING` with no version behind them.
    ///
    /// The repair pass for `ENC-787`. A session left `SCANNING` by the pre-`ENC-691` completion
    /// path is collected by nothing — no antivirus pass (it queues on `file_versions.av_status`,
    /// and there is no version), no reaper (`Scanning.holds_staged_bytes()` is `false`) — so its
    /// staged object sits in the bucket, unmetered and unreadable, indefinitely.
    ReclaimUploads(ReclaimUploadsArgs),

    /// Set an account's password, reading it from standard input.
    ///
    /// The command a deployment needs to get its first sign-in: `seed` writes users and nothing has
    /// ever written a `user_credentials` row, so every seeded account correctly answers `401`
    /// (`ENC-687`).
    SetPassword(SetPasswordArgs),
}

/// Arguments for `set-password`.
///
/// **There is deliberately no `--password` flag.** This binary already refuses `--database-url`
/// because a command line lands in shell history and in `ps` output for every user on the machine,
/// and a password is a stronger case for the same rule, not a weaker one. The value comes from
/// stdin and there is nothing here to reach for instead.
#[derive(Debug, Args)]
pub(crate) struct SetPasswordArgs {
    /// The tenant's slug, as `seed` writes it and as the routing host uses it.
    ///
    /// A slug and not a UUID: the operator has the hostname in front of them, and a UUID typed from
    /// a different terminal is how a password gets set on the wrong tenant's account.
    #[arg(long, value_name = "SLUG")]
    pub(crate) tenant: String,

    /// The account's email address. Normalised the way the login path normalises it.
    #[arg(long, value_name = "EMAIL")]
    pub(crate) email: String,
}

/// Arguments for `reclaim-uploads`.
#[derive(Debug, Args)]
pub(crate) struct ReclaimUploadsArgs {
    /// The tenant's slug, as `seed` writes it and as the routing host uses it.
    ///
    /// A slug and not a UUID, for `set-password`'s reason: the operator has the hostname in front
    /// of them. There is no `--all-tenants`, deliberately — the sweep runs inside a `TenantScoped`
    /// transaction, and a cross-tenant one would need a connection with row-level security
    /// disabled (`docs/04-DATA-MODEL.md §3`).
    #[arg(long, value_name = "SLUG")]
    pub(crate) tenant: String,

    /// How long a session must have been claiming to scan before it is a candidate.
    ///
    /// The grace period. It exists so that a completion genuinely in flight is never collected, and
    /// it is the operator's to choose because a one-off repair of a two-year backlog and a routine
    /// sweep want different answers. The default is a day: long past any real hand-off, and short
    /// enough that a backlog is not left sitting.
    #[arg(long, value_name = "HOURS", default_value_t = 24)]
    pub(crate) idle_hours: u32,

    /// The most sessions to claim in one run.
    ///
    /// Small on purpose. The claim takes `FOR UPDATE`, so the rows stay locked for the whole batch,
    /// and each release is a round trip to the object store — a huge batch holds locks across
    /// minutes of I/O. The report says when it filled, so run it again.
    #[arg(long, value_name = "N", default_value_t = 100)]
    pub(crate) limit: usize,

    /// List what would be reclaimed and delete nothing.
    ///
    /// `ENC-787` asks for a pass that reports what it found rather than deleting quietly. This is
    /// the strong form of that: an operator can read the whole list before anything is destroyed.
    #[arg(long)]
    pub(crate) dry_run: bool,
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

    /// The whole point of the command's shape: there is no way to put a password on the command
    /// line, so nobody can.
    ///
    /// A doc comment saying "pipe it in" is advice. This is the mechanism, and it is asserted
    /// against the three spellings somebody would actually try.
    #[test]
    fn a_password_cannot_be_passed_as_an_argument() {
        for flag in ["--password", "--pass", "-p"] {
            let err = parse(&[
                "enclave-cli",
                "set-password",
                "--tenant",
                "tenant-alpha",
                "--email",
                "owner@tenant-alpha.example",
                flag,
                "whatever-was-typed",
            ])
            .expect_err("a password on the command line is visible in `ps` to every local user");
            assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument, "{flag}");
        }

        // The positive control: without that flag the same command parses, so the four refusals
        // above are about the flag and not about the command being unreachable.
        let cli = parse(&[
            "enclave-cli",
            "set-password",
            "--tenant",
            "tenant-alpha",
            "--email",
            "owner@tenant-alpha.example",
        ])
        .expect("the command itself parses");
        let Command::SetPassword(args) = cli.command else { panic!("expected set-password") };
        assert_eq!(args.tenant, "tenant-alpha");
        assert_eq!(args.email, "owner@tenant-alpha.example");
    }

    /// Both arguments are required, because a default for either is a password set on an account
    /// nobody named.
    #[test]
    fn set_password_names_its_account_explicitly_or_refuses() {
        for args in [
            vec!["enclave-cli", "set-password"],
            vec!["enclave-cli", "set-password", "--tenant", "tenant-alpha"],
            vec!["enclave-cli", "set-password", "--email", "owner@tenant-alpha.example"],
        ] {
            let err = parse(&args).expect_err("both the tenant and the account must be named");
            assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument, "{args:?}");
        }
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
