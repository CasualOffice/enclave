//! Connection configuration for the pools this crate builds.
//!
//! This type is deliberately *not* the shape a YAML file has. `enclave-config` (ENC-102) owns
//! layering, precedence and secret resolution; by the time a value reaches here the `vault://…`
//! reference has already been dereferenced, so what this module receives is a resolved connection
//! string and a set of already-validated knobs. Keeping the driver-facing struct separate means the
//! `db` crate can be constructed in a test — or by the migration CLI — without standing up the whole
//! configuration stack.
//!
//! Three of the fields exist because of a control, not because of ergonomics:
//!
//! * `statement_timeout` — an unbounded statement on a request path pins a pooled connection for as
//!   long as it runs. With a small pool that is indistinguishable from an outage, so the timeout is
//!   mandatory rather than optional.
//! * `idle_in_transaction_timeout` — a transaction left open holds its `SET LOCAL app.tenant_id`
//!   *and* its connection. Bounding it bounds the blast radius of a caller that forgot to commit.
//! * `application_role` — the application must connect as a role that is neither an owner nor
//!   `BYPASSRLS`, or `FORCE ROW LEVEL SECURITY` does not apply to it and layer 2 of tenant isolation
//!   silently disappears (`docs/04-DATA-MODEL.md §3.2`).

use core::fmt;
use core::time::Duration;

use sqlx::postgres::PgConnectOptions;

use crate::DbError;

/// A PostgreSQL connection string, kept in a type whose `Debug` cannot print it.
///
/// A `postgres://` URL contains a password. `Debug` is reached by accident constantly — a
/// `#[derive(Debug)]` on an enclosing struct, a `tracing` field, `unwrap()`'s panic message — and
/// each of those is a path from a credential to a log aggregator (`CLAUDE.md` rule 11). There is no
/// `Display`, so the only way to obtain the string is [`ConnectionUrl::expose`], which is
/// `pub(crate)` and used at exactly one place: building [`PgConnectOptions`].
#[derive(Clone, PartialEq, Eq)]
pub struct ConnectionUrl(String);

impl ConnectionUrl {
    /// Wraps an already-resolved connection string.
    ///
    /// "Resolved" is the contract: this constructor takes the literal URL, so a caller holding a
    /// `SecretRef` must dereference it first. Nothing here reads the environment or a secret store,
    /// because a type that can fetch secrets is a type that gets called from surprising places.
    pub fn new(url: impl Into<String>) -> Self {
        Self(url.into())
    }

    /// The raw string, for the one caller that has to hand it to the driver.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }

    /// Parses into driver options, naming the configuration field rather than quoting the value.
    ///
    /// The parse error from the driver is discarded on purpose: it renders the offending URL, which
    /// is precisely the string that must not reach a log line. `field` is what an operator needs to
    /// fix the problem, and it is enough.
    pub(crate) fn connect_options(&self, field: &'static str) -> Result<PgConnectOptions, DbError> {
        self.0.parse::<PgConnectOptions>().map_err(|_| DbError::InvalidConfig {
            field,
            problem: "is not a valid postgres connection url",
        })
    }
}

impl fmt::Debug for ConnectionUrl {
    /// Prints a fixed placeholder. See the type documentation for why this is not a courtesy.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConnectionUrl(<redacted>)")
    }
}

impl From<String> for ConnectionUrl {
    fn from(url: String) -> Self {
        Self(url)
    }
}

impl From<&str> for ConnectionUrl {
    fn from(url: &str) -> Self {
        Self(url.to_owned())
    }
}

/// How the application and platform pools are built.
///
/// Cloneable and cheap to construct so tests can start from [`DbConfig::new`] and override one
/// field, rather than assembling a configuration file to exercise a pool property.
#[derive(Clone)]
pub struct DbConfig {
    /// Where the application connects. This connection's role is subject to RLS.
    pub url: ConnectionUrl,

    /// Where the three cross-tenant callers connect, as a `BYPASSRLS` role.
    ///
    /// `None` on any deployment that runs no background workers — and then
    /// [`crate::DbPool::platform_connection`] fails loudly rather than falling back to the
    /// application pool, because a "helpful" fallback turns a missing setting into an
    /// RLS-filtered query that silently sees nothing (`docs/04-DATA-MODEL.md §3.2`).
    pub platform_url: Option<ConnectionUrl>,

    /// Where migrations connect, as the schema owner.
    ///
    /// Separate from `platform_url` because owning the schema and bypassing RLS are different
    /// privileges held by different roles (`enclave_migrator` vs `enclave_platform`), and migration
    /// credentials should not be resident in a long-running process at all. Falls back to
    /// `platform_url` when unset, which is the shape a development stack has.
    pub migration_url: Option<ConnectionUrl>,

    /// Upper bound on application connections.
    ///
    /// Sized against PostgreSQL's `max_connections` divided by the number of application replicas,
    /// not against expected concurrency: exceeding the server's limit fails *other* replicas'
    /// connections, not this one's.
    pub max_connections: u32,

    /// Connections kept warm. Zero is a legitimate choice for a worker that is idle most of the day.
    pub min_connections: u32,

    /// Upper bound on platform connections. Small by construction — three code paths use it.
    pub platform_max_connections: u32,

    /// How long a caller waits for a free connection before giving up.
    ///
    /// Bounded and short: a caller queued behind an exhausted pool is a caller holding a request
    /// slot, and failing fast sheds load instead of accumulating it.
    pub acquire_timeout: Duration,

    /// How long an unused connection is kept before being closed.
    pub idle_timeout: Option<Duration>,

    /// Hard age limit on a connection, regardless of use.
    ///
    /// Non-`None` by default so that a rolling failover or a rotated password takes effect within a
    /// bounded window rather than at the next restart.
    pub max_lifetime: Option<Duration>,

    /// `statement_timeout` applied to every application connection. Must be non-zero.
    pub statement_timeout: Duration,

    /// `idle_in_transaction_session_timeout` applied to every application connection.
    ///
    /// This is the safety net under [`crate::TenantScoped`]: a handle that is neither committed nor
    /// dropped cannot hold its connection — and its tenant context — indefinitely.
    pub idle_in_transaction_timeout: Duration,

    /// Optional `SET ROLE` issued once per connection.
    ///
    /// Preferred shape is to connect *as* `enclave_app` and leave this `None`. It exists for
    /// deployments where the connection credential belongs to a bootstrap role (a managed-database
    /// admin user, a cloud IAM principal) that must be reduced to the application role before any
    /// query runs. Validated as a plain identifier, then quoted, so it can never carry SQL.
    pub application_role: Option<String>,

    /// Value of the `application_name` startup parameter.
    ///
    /// Worth setting precisely: it is what `pg_stat_activity` shows when someone is trying to work
    /// out which process is holding the lock.
    pub application_name: String,
}

impl DbConfig {
    /// Defaults chosen for a single API replica in front of a modestly sized PostgreSQL.
    ///
    /// Every default is a control decision rather than a guess, and each is documented on its
    /// field. Callers override individual fields; nothing here reads the environment.
    pub fn new(url: impl Into<ConnectionUrl>) -> Self {
        Self {
            url: url.into(),
            platform_url: None,
            migration_url: None,
            max_connections: 16,
            min_connections: 1,
            platform_max_connections: 4,
            acquire_timeout: Duration::from_secs(5),
            idle_timeout: Some(Duration::from_secs(600)),
            max_lifetime: Some(Duration::from_secs(1800)),
            statement_timeout: Duration::from_secs(30),
            idle_in_transaction_timeout: Duration::from_secs(60),
            application_role: None,
            application_name: "enclave".to_owned(),
        }
    }

    /// Sets the pool ceiling. Present because the D3 proof test runs on a pool of size two.
    #[must_use]
    pub fn with_max_connections(mut self, max: u32) -> Self {
        self.max_connections = max;
        self.min_connections = self.min_connections.min(max);
        self
    }

    /// Sets the cross-tenant connection string.
    #[must_use]
    pub fn with_platform_url(mut self, url: impl Into<ConnectionUrl>) -> Self {
        self.platform_url = Some(url.into());
        self
    }

    /// Sets the schema-owner connection string used by the migration runner.
    #[must_use]
    pub fn with_migration_url(mut self, url: impl Into<ConnectionUrl>) -> Self {
        self.migration_url = Some(url.into());
        self
    }

    /// Sets the role every application connection is reduced to. See the field documentation.
    #[must_use]
    pub fn with_application_role(mut self, role: impl Into<String>) -> Self {
        self.application_role = Some(role.into());
        self
    }

    /// Sets the `application_name` reported to PostgreSQL. Worth distinguishing per binary, since
    /// this is the column an operator reads in `pg_stat_activity` at the worst possible moment.
    #[must_use]
    pub fn with_application_name(mut self, name: impl Into<String>) -> Self {
        self.application_name = name.into();
        self
    }

    /// Sets the per-statement timeout.
    #[must_use]
    pub fn with_statement_timeout(mut self, timeout: Duration) -> Self {
        self.statement_timeout = timeout;
        self
    }

    /// Sets how long a connection may sit inside an open transaction before PostgreSQL ends it.
    ///
    /// Exists so a test can make the control fire in seconds rather than in the sixty a deployment
    /// uses (`ENC-850`). It is a knob for shortening, not for lengthening: the default is a
    /// control, not a tuning parameter — a transaction left open holds its `SET LOCAL
    /// app.tenant_id` — and raising it in a deployment to accommodate slow work inside a
    /// transaction is fixing the wrong thing.
    #[must_use]
    pub fn with_idle_in_transaction_timeout(mut self, timeout: Duration) -> Self {
        self.idle_in_transaction_timeout = timeout;
        self
    }

    /// Rejects a configuration that would weaken a control, before any connection is attempted.
    ///
    /// Validation happens at load rather than at first use because the failure modes here are
    /// asymmetric: a wrong pool size produces a slow morning, but an unvalidated role name produces
    /// a statement built by string concatenation, and a zero statement timeout produces a pool that
    /// can be exhausted by a single query. Startup is the cheapest moment to say no.
    pub fn validate(&self) -> Result<(), DbError> {
        if self.url.expose().is_empty() {
            return Err(DbError::InvalidConfig { field: "url", problem: "is empty" });
        }
        if self.max_connections == 0 {
            return Err(DbError::InvalidConfig {
                field: "max_connections",
                problem: "must be at least 1",
            });
        }
        if self.min_connections > self.max_connections {
            return Err(DbError::InvalidConfig {
                field: "min_connections",
                problem: "exceeds max_connections",
            });
        }
        if self.platform_url.is_some() && self.platform_max_connections == 0 {
            return Err(DbError::InvalidConfig {
                field: "platform_max_connections",
                problem: "must be at least 1",
            });
        }
        if self.acquire_timeout.is_zero() {
            return Err(DbError::InvalidConfig {
                field: "acquire_timeout",
                problem: "must be greater than zero",
            });
        }
        if self.statement_timeout.is_zero() {
            // PostgreSQL reads zero as "no limit". On the request path that is a way for one query
            // to hold a pooled connection until the server restarts, so it is refused rather than
            // silently translated into something else.
            return Err(DbError::InvalidConfig {
                field: "statement_timeout",
                problem: "must be greater than zero",
            });
        }
        if self.idle_in_transaction_timeout.is_zero() {
            return Err(DbError::InvalidConfig {
                field: "idle_in_transaction_timeout",
                problem: "must be greater than zero",
            });
        }
        if let Some(role) = &self.application_role {
            if !is_plain_identifier(role) {
                return Err(DbError::InvalidConfig {
                    field: "application_role",
                    problem: "is not a plain identifier",
                });
            }
        }
        if self.application_name.is_empty() || self.application_name.len() > 63 {
            return Err(DbError::InvalidConfig {
                field: "application_name",
                problem: "must be 1 to 63 characters",
            });
        }
        Ok(())
    }

    /// The connection string the migration runner should use, with its fallback applied.
    pub(crate) fn migration_target(&self) -> Option<(&ConnectionUrl, &'static str)> {
        self.migration_url
            .as_ref()
            .map(|url| (url, "migration_url"))
            .or_else(|| self.platform_url.as_ref().map(|url| (url, "platform_url")))
    }

    /// The `SET` statements issued once on every freshly opened application connection.
    ///
    /// Built as a single batch so a new connection costs one extra round trip rather than three.
    /// Every interpolated value is either an integer this code formatted or an identifier
    /// [`validate`](Self::validate) has already constrained to `[A-Za-z_][A-Za-z0-9_]*` — there is
    /// no path by which caller data reaches this string.
    pub(crate) fn session_setup_sql(&self) -> String {
        let mut sql = format!(
            "SET statement_timeout = {}; SET idle_in_transaction_session_timeout = {};",
            millis(self.statement_timeout),
            millis(self.idle_in_transaction_timeout),
        );
        if let Some(role) = &self.application_role {
            // Last, so the connection ends its setup in the least-privileged state it will ever be
            // in. Quoted to preserve case exactly; validation has already excluded a closing quote.
            sql.push_str(&format!(" SET ROLE \"{role}\";"));
        }
        sql
    }
}

impl fmt::Debug for DbConfig {
    /// Hand-written so that adding a field can never re-introduce a URL into the output: the two
    /// URL fields are rendered as presence, not value, and the derive that would print them is
    /// deliberately absent.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DbConfig")
            .field("url", &"<redacted>")
            .field("platform_url", &self.platform_url.is_some())
            .field("migration_url", &self.migration_url.is_some())
            .field("max_connections", &self.max_connections)
            .field("min_connections", &self.min_connections)
            .field("platform_max_connections", &self.platform_max_connections)
            .field("acquire_timeout", &self.acquire_timeout)
            .field("idle_timeout", &self.idle_timeout)
            .field("max_lifetime", &self.max_lifetime)
            .field("statement_timeout", &self.statement_timeout)
            .field("idle_in_transaction_timeout", &self.idle_in_transaction_timeout)
            .field("application_role", &self.application_role)
            .field("application_name", &self.application_name)
            .finish()
    }
}

/// Milliseconds, saturated into the range PostgreSQL accepts for a timeout GUC.
///
/// Saturating rather than wrapping: a duration long enough to overflow is a configuration mistake,
/// and the safe reading of a mistake in a *timeout* is the largest finite bound, never zero — zero
/// means "no limit" and would turn a typo into a disabled control.
fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::from(u32::MAX))
}

/// Whether a string is an unquoted-safe SQL identifier.
///
/// Used for the one place an identifier is interpolated into SQL. An allowlist rather than an
/// escape function, because the set of characters that are safe in an identifier is small and
/// knowable, whereas the set that must be escaped grows with every server version.
fn is_plain_identifier(value: &str) -> bool {
    if value.is_empty() || value.len() > 63 {
        return false;
    }
    let mut chars = value.chars();
    let leads = chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    leads && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn config() -> DbConfig {
        DbConfig::new("postgres://enclave_app@localhost/enclave")
    }

    #[test]
    fn the_default_configuration_is_valid() {
        config().validate().expect("defaults must be usable without editing");
    }

    #[test]
    fn a_connection_url_never_appears_in_debug_output() {
        let cfg = config()
            .with_platform_url("postgres://enclave_platform:hunter2@localhost/enclave")
            .with_migration_url("postgres://enclave_migrator:hunter2@localhost/enclave");
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains("hunter2"), "password leaked into Debug: {rendered}");
        assert!(!rendered.contains("postgres://"), "url leaked into Debug: {rendered}");
        // Presence still has to be visible, or the output is useless for diagnosis.
        assert!(rendered.contains("platform_url: true"));
    }

    #[test]
    fn a_bare_connection_url_never_appears_in_debug_output() {
        let url = ConnectionUrl::new("postgres://user:hunter2@localhost/enclave");
        assert_eq!(format!("{url:?}"), "ConnectionUrl(<redacted>)");
    }

    #[test]
    fn a_zero_statement_timeout_is_refused_because_zero_means_unlimited() {
        let err = config()
            .with_statement_timeout(Duration::ZERO)
            .validate()
            .expect_err("zero must be refused");
        assert!(matches!(err, DbError::InvalidConfig { field: "statement_timeout", .. }));
    }

    #[test]
    fn an_empty_pool_is_refused() {
        let err = config().with_max_connections(0).validate().expect_err("must be refused");
        assert!(matches!(err, DbError::InvalidConfig { field: "max_connections", .. }));
    }

    #[test]
    fn a_role_name_carrying_sql_is_refused() {
        // The single reason `application_role` is validated at all: it is interpolated into a
        // statement. Each of these would otherwise close the quote or end the statement.
        for hostile in [
            "app\"; DROP TABLE files; --",
            "app\"",
            "app; SELECT 1",
            "app role",
            "1app",
            "",
            "app-role",
            "app'",
        ] {
            let err = config()
                .with_application_role(hostile)
                .validate()
                .expect_err(&format!("{hostile:?} must be refused"));
            assert!(
                matches!(err, DbError::InvalidConfig { field: "application_role", .. }),
                "{hostile:?} was refused for the wrong reason: {err:?}"
            );
        }
    }

    #[test]
    fn a_plain_role_name_is_accepted_and_quoted() {
        let cfg = config().with_application_role("enclave_app");
        cfg.validate().expect("a plain identifier is fine");
        let sql = cfg.session_setup_sql();
        assert!(sql.contains("SET ROLE \"enclave_app\";"), "{sql}");
        // Ordering is load-bearing: privilege reduction happens after the timeouts are in place.
        let role_at = sql.find("SET ROLE").expect("role statement present");
        let timeout_at = sql.find("statement_timeout").expect("timeout statement present");
        assert!(timeout_at < role_at);
    }

    #[test]
    fn session_setup_expresses_timeouts_in_milliseconds() {
        let sql = config().with_statement_timeout(Duration::from_secs(7)).session_setup_sql();
        assert!(sql.contains("SET statement_timeout = 7000;"), "{sql}");
        assert!(sql.contains("SET idle_in_transaction_session_timeout = 60000;"), "{sql}");
    }

    #[test]
    fn an_absurd_timeout_saturates_rather_than_becoming_unlimited() {
        // Zero would mean "no limit", which is the one answer a timeout must never degrade into.
        assert_eq!(millis(Duration::MAX), u64::from(u32::MAX));
        assert_ne!(millis(Duration::MAX), 0);
    }

    #[test]
    fn migration_target_falls_back_to_the_platform_url() {
        let cfg = config().with_platform_url("postgres://enclave_platform@localhost/enclave");
        let (_, field) = cfg.migration_target().expect("platform url is a valid fallback");
        assert_eq!(field, "platform_url");

        let cfg = cfg.with_migration_url("postgres://enclave_migrator@localhost/enclave");
        let (_, field) = cfg.migration_target().expect("explicit migration url wins");
        assert_eq!(field, "migration_url");

        assert!(config().migration_target().is_none(), "no owner credential, no migrations");
    }

    #[test]
    fn identifier_rules_match_postgres_unquoted_identifiers() {
        assert!(is_plain_identifier("enclave_app"));
        assert!(is_plain_identifier("_app1"));
        assert!(!is_plain_identifier("app.role"));
        assert!(!is_plain_identifier(&"a".repeat(64)));
        assert!(!is_plain_identifier("ρόλος"));
    }
}
