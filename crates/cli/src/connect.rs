//! Working out which database to talk to, and saying so without printing a password.
//!
//! Every command in this binary prints the database it is about to touch, because "it seeded the
//! wrong database" is only preventable if the operator can see which one it is. That makes the
//! rendering of a connection URL a security-relevant function rather than a cosmetic one: it is on
//! the path of every command, including the ones that fail, and `CLAUDE.md` rule 11 has no
//! exception for diagnostics.
//!
//! The rule here is that the URL is never rendered — only [`Target::summary`] is, and it is built
//! by an allowlist (scheme, host, database) rather than by removing the parts known to be
//! sensitive. A denylist would need updating every time libpq grows another connection parameter.

use std::path::Path;

use anyhow::{anyhow, Context as _};
use enclave_config::{ConfigLoader, SecretRegistry};
use enclave_db::{ConnectionUrl, DbConfig, DbError, DbPool};
use sqlx::{Connection as _, PgConnection};

/// The environment variable every command falls back to. Named in `CONTRIBUTING.md`.
const DATABASE_URL_ENV: &str = "DATABASE_URL";

/// The configuration path a file-based deployment holds its DSN at.
const DATABASE_URL_FIELD: &str = "database.url";

/// A resolved connection string and where it came from.
///
/// `Debug` is hand-written and `Display` is deliberately absent, for the reason in the module
/// documentation: the compiler should refuse to print this type, so that printing it requires
/// typing [`summary`](Self::summary) and noticing what that means.
pub(crate) struct Target {
    url: String,
    origin: String,
}

impl core::fmt::Debug for Target {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Target").field("origin", &self.origin).field("url", &"<redacted>").finish()
    }
}

impl Target {
    /// Resolves the database from a configuration file when one is given, and from the environment
    /// otherwise.
    ///
    /// The file wins when it is passed explicitly, because passing it is a statement of intent.
    /// Nothing searches for a configuration file automatically: a command that picks up
    /// `./enclave.yaml` because of the directory it was run from is a command that writes to a
    /// different database depending on where the terminal happened to be.
    ///
    /// # Errors
    ///
    /// When neither source yields a URL, or the file cannot be read, parsed, validated, or its
    /// secret references resolved.
    pub(crate) async fn resolve(config: Option<&Path>) -> anyhow::Result<Self> {
        match config {
            Some(path) => Self::from_config_file(path).await,
            None => Self::from_environment(),
        }
    }

    async fn from_config_file(path: &Path) -> anyhow::Result<Self> {
        let display = path.display();

        let loaded = ConfigLoader::new()
            .with_file(path)
            .load()
            .with_context(|| format!("could not load configuration from {display}"))?;

        let reference = loaded.config().database.url_ref().ok_or_else(|| {
            anyhow!(
                "{display} does not configure a database connection.\n  \
                 add `database:` with either `url: env://{DATABASE_URL_ENV}` or \
                 `url_env: {DATABASE_URL_ENV}`"
            )
        })?;

        // One reference, resolved on its own, rather than `Loaded::resolve_secrets`, which resolves
        // every reference in the file. A server is right to refuse to start when its Redis
        // credential is missing; this command is not, because `doctor` is what someone runs on a
        // half-configured machine and refusing to look at the database until NATS is configured
        // would make it useless exactly when it is needed.
        //
        // `SecretRegistry::local()` covers `env://` and `file://`, which is what a development or
        // single-node deployment uses. A DSN behind a `vault://` reference needs that provider
        // registered here; it lands with the secrets crate, not with this command.
        let value = SecretRegistry::local().read(&reference).await.with_context(|| {
            format!("could not resolve `{reference}`, the {DATABASE_URL_FIELD} in {display}")
        })?;

        let url = value
            .expose_str()
            .with_context(|| format!("`{DATABASE_URL_FIELD}` in {display} is not valid UTF-8"))?
            .to_owned();

        if url.trim().is_empty() {
            anyhow::bail!("`{reference}`, the {DATABASE_URL_FIELD} in {display}, is empty");
        }

        Ok(Self { url, origin: format!("`{DATABASE_URL_FIELD}` in {display}") })
    }

    fn from_environment() -> anyhow::Result<Self> {
        let url = std::env::var(DATABASE_URL_ENV)
            .ok()
            .filter(|url| !url.trim().is_empty())
            .ok_or_else(|| {
                anyhow!(
                    "no database connection is configured.\n  \
                     set {DATABASE_URL_ENV}, for example \
                     `export {DATABASE_URL_ENV}=postgres://enclave@localhost:5432/enclave`,\n  \
                     or pass `--config <PATH>` to read it from a configuration file"
                )
            })?;

        Ok(Self { url, origin: format!("${DATABASE_URL_ENV}") })
    }

    /// Builds a target straight from a URL, for the tests that talk to a throwaway database.
    ///
    /// Test-only on purpose: every real invocation goes through [`resolve`](Self::resolve), so that
    /// "where did this connection come from" always has an answer to print.
    #[cfg(test)]
    pub(crate) fn from_url(url: impl Into<String>) -> Self {
        Self { url: url.into(), origin: "a test harness".to_owned() }
    }

    /// Where the URL came from, for an error message that says what to go and edit.
    pub(crate) fn origin(&self) -> &str {
        &self.origin
    }

    /// The host and database, with credentials and every connection parameter removed.
    pub(crate) fn summary(&self) -> String {
        summarize(&self.url)
    }

    /// Opens a single connection.
    ///
    /// A connection rather than a pool for the read-only and migration paths: both do their work
    /// on one session, and migrations in particular must not be spread across pooled connections,
    /// since the advisory lock they take is session-scoped.
    ///
    /// # Errors
    ///
    /// Connection failures, rendered without the URL.
    pub(crate) async fn connect(&self) -> anyhow::Result<PgConnection> {
        PgConnection::connect(&self.url).await.map_err(|error| self.connect_failed(&error))
    }

    /// Builds an application pool, used by the seeding path so that writes go through
    /// [`enclave_db::TenantScoped`] rather than around it.
    ///
    /// # Errors
    ///
    /// Connection or configuration failures, rendered without the URL.
    pub(crate) async fn pool(&self) -> anyhow::Result<DbPool> {
        // Two connections: seeding is sequential, and a development database is often the one with
        // the smallest `max_connections` anyone will meet.
        let config = DbConfig::new(ConnectionUrl::new(self.url.clone()))
            .with_application_name("enclave-cli")
            .with_max_connections(2);

        DbPool::connect(&config).await.map_err(|error| match error {
            DbError::Connect(source) | DbError::Acquire(source) => self.connect_failed(&source),
            other => anyhow!(other),
        })
    }

    /// Renders a connection failure with the summary and the origin, never the URL.
    fn connect_failed(&self, error: &sqlx::Error) -> anyhow::Error {
        anyhow!("could not connect to {} (from {}): {}", self.summary(), self.origin, detail(error))
    }
}

/// A connection error, with the malformed-URL case flattened.
///
/// `sqlx::Error::Configuration` wraps the URL parser, whose message quotes the string it failed on
/// — which is the one string that must not reach a terminal or a CI log. Every other variant is a
/// message from the server or the socket layer and is safe to show.
fn detail(error: &sqlx::Error) -> String {
    match error {
        sqlx::Error::Configuration(_) => {
            "the connection url is not valid (expected postgres://user@host:port/database)"
                .to_owned()
        }
        other => other.to_string(),
    }
}

/// Renders `scheme://host[:port]/database` from a PostgreSQL URL.
///
/// Built by keeping three things rather than by stripping the dangerous ones. Userinfo, query
/// parameters and fragments are dropped wholesale: `?password=` and `?sslpassword=` are both
/// legal, and a denylist would have to be revised for each new one.
///
/// Anything that is not recognisably a PostgreSQL URL renders as a fixed placeholder. libpq also
/// accepts the `host=… password=…` keyword form, and printing an unparsed string on the theory
/// that it is probably a URL is exactly how a password reaches a log.
fn summarize(url: &str) -> String {
    let Some(rest) = url.strip_prefix("postgres://").or_else(|| url.strip_prefix("postgresql://"))
    else {
        return "<database url>".to_owned();
    };

    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    // Last `@`, not first: a password may legitimately contain one.
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let database = path.split(['?', '#']).next().unwrap_or("");

    if host.is_empty() {
        return "<database url>".to_owned();
    }
    if database.is_empty() {
        return format!("postgres://{host}");
    }
    format!("postgres://{host}/{database}")
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_password_never_survives_summarisation() {
        let summary = summarize("postgres://enclave:hunter2@db.internal:5432/enclave");
        assert!(!summary.contains("hunter2"), "{summary}");
        assert!(!summary.contains("enclave:"), "{summary}");
        // The parts an operator needs in order to recognise the wrong database must survive.
        assert_eq!(summary, "postgres://db.internal:5432/enclave");
    }

    #[test]
    fn connection_parameters_are_dropped_entirely() {
        // `password` is a legal query parameter, so keeping "harmless" ones is not an option.
        assert_eq!(
            summarize("postgres://u:p@localhost/enclave?sslmode=require&password=hunter2"),
            "postgres://localhost/enclave"
        );
        assert_eq!(
            summarize("postgresql://localhost/enclave#frag"),
            "postgres://localhost/enclave"
        );
    }

    #[test]
    fn an_at_sign_inside_the_password_does_not_expose_the_rest_of_it() {
        let summary = summarize("postgres://user:hunt@er2@localhost:5432/enclave");
        assert_eq!(summary, "postgres://localhost:5432/enclave");
    }

    #[test]
    fn a_url_without_credentials_still_renders() {
        assert_eq!(
            summarize("postgres://localhost:5432/enclave"),
            "postgres://localhost:5432/enclave"
        );
        assert_eq!(summarize("postgres://localhost"), "postgres://localhost");
    }

    #[test]
    fn anything_that_is_not_a_postgres_url_renders_as_a_placeholder() {
        // The libpq keyword form is the case that matters: it carries the password in the clear
        // and looks nothing like a URL, so the safe reading of "unrecognised" is "print nothing".
        for hostile in [
            "host=db.internal password=hunter2 dbname=enclave",
            "hunter2",
            "",
            "mysql://user:hunter2@localhost/enclave",
        ] {
            let summary = summarize(hostile);
            assert_eq!(summary, "<database url>", "{hostile} leaked as {summary}");
        }
    }

    #[test]
    fn a_target_never_prints_its_url_in_debug_output() {
        let target = Target {
            url: "postgres://u:hunter2@localhost/enclave".to_owned(),
            origin: "$DATABASE_URL".to_owned(),
        };
        let rendered = format!("{target:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("$DATABASE_URL"), "{rendered}");
    }

    #[test]
    fn an_absent_database_url_names_both_ways_to_supply_one() {
        // The message is the whole value of this path: someone hitting it has just cloned the repo.
        temp_env_absent(DATABASE_URL_ENV, || {
            let err = Target::from_environment().expect_err("must refuse");
            let message = format!("{err}");
            assert!(message.contains(DATABASE_URL_ENV), "{message}");
            assert!(message.contains("--config"), "{message}");
        });
    }

    #[test]
    fn a_blank_database_url_is_treated_as_absent() {
        // An exported-but-empty variable is a common shell accident, and "" fails later with a
        // parser error that says nothing useful.
        temp_env_set(DATABASE_URL_ENV, "   ", || {
            assert!(Target::from_environment().is_err());
        });
    }

    /// Runs `body` with `key` unset, restoring whatever was there.
    ///
    /// Written by hand rather than pulled in as a dependency: this is the only place in the crate
    /// that needs it. Tests touching the same variable must not run concurrently, which is what
    /// the mutex below is for.
    fn temp_env_absent<T>(key: &str, body: impl FnOnce() -> T) -> T {
        with_env(key, None, body)
    }

    fn temp_env_set<T>(key: &str, value: &str, body: impl FnOnce() -> T) -> T {
        with_env(key, Some(value), body)
    }

    fn with_env<T>(key: &str, value: Option<&str>, body: impl FnOnce() -> T) -> T {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let previous = std::env::var(key).ok();
        match value {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
        let outcome = body();
        match previous {
            Some(previous) => std::env::set_var(key, previous),
            None => std::env::remove_var(key),
        }
        outcome
    }
}
