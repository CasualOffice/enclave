//! `enclave-cli set-password` — how a deployment gets its first sign-in (`ENC-687`).
//!
//! # Why an operator needs this at all
//!
//! `seed` writes users into `users`; nothing has ever written a row into `user_credentials`. So a
//! freshly migrated and seeded deployment has a directory full of accounts, none of which can sign
//! in, and `POST /api/v1/auth/login` correctly answers `401` for every one of them. An operator who
//! cannot create the first credential cannot use the product — and until SSO lands
//! (`docs/13-IDENTITY-SSO-SCIM.md`) there is no other way in.
//!
//! # The password is read from **stdin**, never from an argument
//!
//! This binary already refuses `--database-url` for the reason the module documentation gives:
//! anything on a command line lands in shell history and in `ps` output, visible to every user on
//! the machine. A password is worse than a DSN, not better, so it gets the same treatment and there
//! is deliberately **no** `--password` flag to reach for:
//!
//! ```text
//! printf '%s' "$NEW_PASSWORD" | enclave-cli set-password --tenant tenant-alpha --email owner@…
//! ```
//!
//! A trailing newline is stripped — a here-string and an `echo` both add one, and a password that
//! differs from what the operator typed by an invisible byte is a support call rather than a
//! control. Nothing else is trimmed: leading and interior whitespace are part of a password.
//!
//! # What is never printed
//!
//! The password, the hash, and any prefix of either. What the command prints is the tenant, the
//! email it resolved, and whether a credential was created or replaced — which is exactly enough to
//! know it did the right thing to the right account, and nothing an onlooker can use.
//!
//! # Why the hashing is `crates/auth`'s and not this command's
//!
//! [`enclave_auth::PasswordHasher`] applies the configured policy *and* produces the PHC string
//! that `crates/api/src/routes/auth.rs` verifies against. A second hasher here would be a second
//! place the Argon2 parameters are chosen, and the failure mode of that divergence is an account
//! that cannot sign in with the password it was just given.

use anyhow::Context as _;
use enclave_auth::{PasswordHasher, PasswordPolicy};
use enclave_core::TenantId;
use sqlx::Row as _;

use crate::cli::SetPasswordArgs;
use crate::connect::Target;

/// Resolves the tenant by slug. Cross-tenant by necessity — an operator names a slug, not a UUID —
/// and this command holds the schema owner's connection, which is what an operator command is.
const SELECT_TENANT: &str =
    "SELECT id FROM tenants WHERE slug = $1 AND deleted_at IS NULL AND status <> 'DELETING'";

/// Resolves the account inside that tenant.
///
/// No status filter, unlike the login path's statement. The two are asking different questions: a
/// login must not reveal whether a suspended account exists, and an operator setting a password on
/// a suspended account should be told it is suspended rather than told it does not exist.
const SELECT_USER: &str =
    "SELECT id, status, deleted_at IS NOT NULL AS deleted FROM users \
     WHERE tenant_id = $1 AND normalized_email = $2";

/// Writes the credential.
///
/// `ON CONFLICT … DO UPDATE` because `user_credentials` is keyed on `user_id`: setting a password
/// for an account that already has one is a reset, which is the second-commonest reason to run
/// this. The counters are cleared in the same statement — an operator who has just set a password
/// to unlock somebody would otherwise leave them locked by the failed attempts that got them here.
const UPSERT_CREDENTIAL: &str = "INSERT INTO user_credentials \
     (user_id, tenant_id, password_hash, algorithm, changed_at, must_change, failed_attempts, \
      locked_until) \
     VALUES ($1, $2, $3, 'argon2id', now(), FALSE, 0, NULL) \
     ON CONFLICT (user_id) DO UPDATE SET \
       password_hash = EXCLUDED.password_hash, algorithm = EXCLUDED.algorithm, \
       changed_at = EXCLUDED.changed_at, must_change = EXCLUDED.must_change, \
       failed_attempts = 0, locked_until = NULL \
     RETURNING (xmax = 0) AS created";

/// Runs the command.
///
/// # Errors
///
/// A password that stdin did not carry or that the policy refuses, a tenant or account that does
/// not resolve, and connection or statement failures.
pub(crate) async fn run(target: &Target, args: &SetPasswordArgs) -> anyhow::Result<()> {
    let password = read_password_from_stdin()?;

    // The policy is checked before anything is read from the database, so a refused password
    // cannot double as a probe for which accounts exist.
    let hasher = PasswordHasher::new(PasswordPolicy::default())
        .context("the default password policy is not usable")?;
    hasher.check_policy(&password).map_err(|error| {
        // `error` carries a `ValidationCode` and no part of the password. Rendering it is safe;
        // rendering the password to explain what it broke would not be.
        anyhow::anyhow!("the password was refused before it was hashed: {error}")
    })?;

    println!("target:   {}", target.summary());
    println!("tenant:   {}", args.tenant);
    println!("account:  {}", args.email);
    println!();

    let mut conn = target.connect().await?;
    let tenant_row = sqlx::query(SELECT_TENANT)
        .bind(&args.tenant)
        .fetch_optional(&mut conn)
        .await
        .context("look up the tenant")?
        .with_context(|| {
            format!(
                "no live tenant with the slug `{}`. Run `enclave-cli seed` first, or check the \
                 slug against `SELECT slug FROM tenants`",
                args.tenant
            )
        })?;
    let tenant_id = TenantId::from_uuid(tenant_row.get("id"));

    let normalized = enclave_identity::normalize_email(&args.email);
    let user_row = sqlx::query(SELECT_USER)
        .bind(tenant_id.as_uuid())
        .bind(&normalized)
        .fetch_optional(&mut conn)
        .await
        .context("look up the account")?
        .with_context(|| {
            format!("`{}` is not an account in `{}`", args.email, args.tenant)
        })?;

    // Reported rather than refused. Setting a password on a suspended account is a legitimate
    // preparation for reinstating it, and an operator who is told the account exists but cannot
    // sign in has learned something a silent success would have hidden.
    let status: String = user_row.get("status");
    let deleted: bool = user_row.get("deleted");
    if deleted || status != "ACTIVE" {
        println!(
            "note:     this account is {}, so it still cannot sign in — the login path requires \
             status = ACTIVE and no deleted_at",
            if deleted { "soft-deleted".to_owned() } else { format!("status {status}") }
        );
    }

    // Argon2 at the configured cost is deliberately slow and this is a blocking hash on the async
    // runtime. That is correct here and would not be in a server: this process does one of these
    // and then exits, and moving it to `spawn_blocking` would buy nothing but a `Send` bound.
    let hash = hasher.hash(&password).context("hash the password")?;
    drop(password);

    let user_id: uuid::Uuid = user_row.get("id");
    let written = sqlx::query(UPSERT_CREDENTIAL)
        .bind(user_id)
        .bind(tenant_id.as_uuid())
        .bind(&hash)
        .fetch_one(&mut conn)
        .await
        .context("write the credential")?;

    let created: bool = written.get("created");
    println!(
        "{}",
        if created {
            "written:  a password credential was created for this account"
        } else {
            "written:  the existing password credential was replaced, and the failed-attempt \
             counter and lockout cleared"
        }
    );
    println!();
    println!(
        "The account can now sign in at POST /api/v1/auth/login, on a host that routes to this \
         tenant — `{}.<your-domain>`. Existing sessions are unaffected: revoking them is \
         POST /api/v1/auth/logout-all, which is a separate decision.",
        args.tenant
    );
    Ok(())
}

/// Reads the password from standard input.
///
/// # Errors
///
/// When stdin is a terminal with nothing piped into it, or carries nothing.
fn read_password_from_stdin() -> anyhow::Result<String> {
    use std::io::Read as _;

    let mut buffer = String::new();
    std::io::stdin().read_to_string(&mut buffer).context("read the password from stdin")?;

    let password = strip_one_trailing_newline(&buffer);
    if password.is_empty() {
        anyhow::bail!(
            "no password arrived on stdin.\n  \
             pipe it in, so that it never reaches shell history or `ps` output:\n    \
             printf '%s' \"$NEW_PASSWORD\" | enclave-cli set-password --tenant … --email …"
        );
    }
    Ok(password.to_owned())
}

/// Removes exactly one trailing line ending, and nothing else.
///
/// `echo` and a here-string both append one, and a password that differs from what the operator
/// typed by an invisible byte is unfixable from the outside — they will type the password they
/// meant and be told it is wrong. One newline is removed because that is what the shell adds;
/// `trim` would silently change a password that legitimately ends in a space.
fn strip_one_trailing_newline(raw: &str) -> &str {
    raw.strip_suffix('\n').map_or(raw, |line| line.strip_suffix('\r').unwrap_or(line))
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// The shells' trailing newline goes, and nothing a password could legitimately contain does.
    #[test]
    fn exactly_one_trailing_line_ending_is_removed() {
        assert_eq!(strip_one_trailing_newline("hunter2hunter2\n"), "hunter2hunter2");
        assert_eq!(strip_one_trailing_newline("hunter2hunter2\r\n"), "hunter2hunter2");
        assert_eq!(strip_one_trailing_newline("hunter2hunter2"), "hunter2hunter2");

        // The properties that make this a hand-written function rather than `trim`.
        assert_eq!(
            strip_one_trailing_newline("trailing space \n"),
            "trailing space ",
            "a space before the newline is part of the password"
        );
        assert_eq!(
            strip_one_trailing_newline("  leading space\n"),
            "  leading space",
            "leading whitespace is part of the password"
        );
        assert_eq!(
            strip_one_trailing_newline("two newlines\n\n"),
            "two newlines\n",
            "only the shell's own newline is removed"
        );
    }

    /// The statement has to *replace* rather than fail, and has to clear the lockout.
    ///
    /// Asserted over the SQL text because the alternative — a database test — would prove the same
    /// thing at a hundred times the cost, and the property that matters is a property of the
    /// statement. The behavioural half is `crates/cli/tests/set_password.rs`.
    #[test]
    fn the_upsert_replaces_an_existing_credential_and_clears_the_lockout() {
        assert!(UPSERT_CREDENTIAL.contains("ON CONFLICT (user_id) DO UPDATE"), "{UPSERT_CREDENTIAL}");
        assert!(UPSERT_CREDENTIAL.contains("failed_attempts = 0"), "{UPSERT_CREDENTIAL}");
        assert!(UPSERT_CREDENTIAL.contains("locked_until = NULL"), "{UPSERT_CREDENTIAL}");
        // Whether the row was created is reported to the operator, so the statement has to say.
        assert!(UPSERT_CREDENTIAL.contains("xmax = 0"), "{UPSERT_CREDENTIAL}");
    }

    /// The login path will not accept a credential this command wrote unless both agree on the
    /// email normalisation, and they agree by calling the same function rather than by convention.
    #[test]
    fn the_email_is_normalised_the_way_the_login_path_normalises_it() {
        assert_eq!(
            enclave_identity::normalize_email("  Owner@Tenant-Alpha.Example  "),
            enclave_identity::normalize_email("owner@tenant-alpha.example"),
            "a login typed in a different case must find the row this command wrote"
        );
    }
}
