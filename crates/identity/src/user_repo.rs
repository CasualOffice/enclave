//! Reading users, and the two writes that belong to identity rather than to a domain service.
//!
//! Both writes here — recording a sign-in and bumping the mass-revocation counter — are *named
//! operations* rather than SQL a caller assembles. That is the point of
//! [`UserRepository::bump_token_epoch`] in particular: `docs/03-LLD.md §5.4` makes `token_epoch`
//! the immediate revocation mechanism for password change, MFA reset, offboarding, role removal and
//! "log me out everywhere", so it is reached from at least five call sites. Five hand-written
//! `UPDATE`s are five chances to forget the tenant predicate, to add `deleted_at IS NULL` where it
//! must not be, or to set the column rather than increment it.

use chrono::{DateTime, Utc};
use enclave_core::{TenantId, UserId};
use enclave_db::{sql, Cursor, FilterFingerprint, PageSize};
use sqlx::{PgConnection, Row as _};

use crate::error::Result;
use crate::model::{User, UserStatus};
use crate::normalize::normalize_email;
use crate::row::user_from_row;

/// Which users a listing should return.
///
/// The fingerprint of this value is bound into the cursor, so a caller cannot page through with one
/// filter and resume with another — see [`enclave_db::cursor`] for why that is a correctness problem and
/// not a nicety.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UserFilter {
    /// Restrict to one lifecycle state, or `None` for every state.
    pub status: Option<UserStatus>,
    /// Include soft-deleted users.
    ///
    /// `false` by default and it should stay that way outside administrative and compliance
    /// surfaces: a deleted user appearing in an ordinary picker is how a deprovisioned account gets
    /// re-shared with.
    pub include_deleted: bool,
}

impl UserFilter {
    /// The digest bound into this listing's cursors.
    ///
    /// Every field participates. A field added here and forgotten in this function produces cursors
    /// that are accepted across two different filters, which silently skips rows.
    #[must_use]
    pub fn fingerprint(&self) -> FilterFingerprint {
        FilterFingerprint::of(&[
            "status",
            self.status.map_or("*", |status| status.as_str()),
            "deleted",
            if self.include_deleted { "include" } else { "exclude" },
        ])
    }
}

/// One page of a user listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserPage {
    /// The users, in ascending id order — which, since every id is UUIDv7, is creation order.
    pub users: Vec<User>,
    /// The opaque cursor for the next page, or `None` at the end of the listing.
    pub next_cursor: Option<String>,
    /// Whether another page exists. Redundant with `next_cursor.is_some()` and carried anyway,
    /// because `docs/05-API.md §6` puts `hasMore` on the wire and a caller should not have to infer
    /// a documented field from the absence of another one.
    pub has_more: bool,
    /// The size actually used, after clamping.
    pub limit: PageSize,
}

/// Reads and updates users.
///
/// Every function takes the `&mut PgConnection` a `TenantScoped` transaction derefs to, never a
/// pool (`plans/M1-CONTENT-CORE.md` D10). The `tenant` argument is the application-layer half of the
/// two-layer isolation in `docs/04-DATA-MODEL.md §3`.
#[derive(Debug, Clone, Copy, Default)]
pub struct UserRepository;

impl UserRepository {
    /// Finds a user by id.
    ///
    /// Soft-deleted users are not returned; see [`UserFilter::include_deleted`] for the listing
    /// that can see them.
    ///
    /// # Errors
    ///
    /// Storage failures, and [`crate::IdentityError::MalformedRow`] if a stored row holds a value
    /// outside the vocabulary in [`crate::model`].
    pub async fn find_by_id(
        conn: &mut PgConnection,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Option<User>> {
        let row = sqlx::query(SELECT_USER_BY_ID)
            .bind(sql(tenant))
            .bind(sql(user))
            .fetch_optional(&mut *conn)
            .await?;
        row.as_ref().map(user_from_row).transpose()
    }

    /// Finds a user by email within one tenant.
    ///
    /// The address is folded through [`normalize_email`] and matched against `normalized_email`,
    /// which is the column `uq_users_email` is built on — so this lookup uses the index and, more
    /// importantly, agrees with the constraint about which addresses are the same address.
    ///
    /// Scoped to a tenant, always: the same person may exist in several tenants, and the unique
    /// index is `(tenant_id, normalized_email)` rather than `(normalized_email)` for exactly that
    /// reason.
    ///
    /// # Errors
    ///
    /// As [`UserRepository::find_by_id`].
    pub async fn find_by_email(
        conn: &mut PgConnection,
        tenant: TenantId,
        email: &str,
    ) -> Result<Option<User>> {
        let row = sqlx::query(SELECT_USER_BY_EMAIL)
            .bind(sql(tenant))
            .bind(normalize_email(email))
            .fetch_optional(&mut *conn)
            .await?;
        row.as_ref().map(user_from_row).transpose()
    }

    /// Lists a tenant's users, one page at a time.
    ///
    /// Ordered by `id`, which is a UUIDv7 and therefore both creation-ordered and unique — so the
    /// sort key and the tie-break are one column and there is no equal-key window to step over.
    /// `OFFSET` is not used anywhere: `docs/03-LLD.md §17` prohibits it, because a deep offset
    /// re-reads and discards every preceding row and shifts under concurrent inserts.
    ///
    /// # Errors
    ///
    /// Storage failures, decode failures, and [`crate::IdentityError::InvalidCursor`] if the cursor
    /// was issued for a different tenant or a different filter set.
    pub async fn list_by_tenant(
        conn: &mut PgConnection,
        tenant: TenantId,
        filter: &UserFilter,
        limit: PageSize,
        cursor: Option<&str>,
    ) -> Result<UserPage> {
        let fingerprint = filter.fingerprint();
        let after = match cursor {
            Some(text) => Some(Cursor::<UserId>::decode(text, tenant, fingerprint)?),
            None => None,
        };

        // One more row than asked for, so "is there a next page" is answered by the same query
        // rather than by a second `COUNT` — which would be both a round trip and a different
        // snapshot from the page it describes.
        let probe = limit.get().saturating_add(1);

        let rows = sqlx::query(SELECT_USER_PAGE)
            .bind(sql(tenant))
            .bind(after.map(sql))
            .bind(filter.status.map(|status| status.as_str()))
            .bind(filter.include_deleted)
            .bind(probe)
            .fetch_all(&mut *conn)
            .await?;

        let has_more = rows.len() as i64 > limit.get();
        let kept = rows.iter().take(usize::try_from(limit.get()).unwrap_or(usize::MAX));
        let users: Vec<User> = kept.map(user_from_row).collect::<Result<_>>()?;

        let next_cursor = match users.last() {
            Some(last) if has_more => Some(Cursor::new(tenant, last.id, fingerprint).encode()),
            _ => None,
        };

        Ok(UserPage { users, next_cursor, has_more, limit })
    }

    /// Records a successful sign-in.
    ///
    /// Returns whether a row was updated: `false` means the user does not exist, or is soft-deleted,
    /// in this tenant. A caller that has just authenticated someone and gets `false` has a genuine
    /// inconsistency to report rather than a no-op to ignore.
    ///
    /// **`updated_at` is deliberately not touched.** It is the optimistic-concurrency and
    /// cache-invalidation key for the user record, and a sign-in does not change the record's
    /// content. Bumping it on every login would invalidate caches and break `If-Match` for callers
    /// holding a perfectly current copy — for information that is not part of what they hold.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub async fn update_last_login_at(
        conn: &mut PgConnection,
        tenant: TenantId,
        user: UserId,
        at: DateTime<Utc>,
    ) -> Result<bool> {
        let result = sqlx::query(UPDATE_LAST_LOGIN)
            .bind(sql(tenant))
            .bind(sql(user))
            .bind(at)
            .execute(&mut *conn)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Increments the user's `token_epoch`, revoking every outstanding access token for them.
    ///
    /// The mass-revocation path of `docs/03-LLD.md §5.4`. Returns the new epoch, or `None` if no
    /// such user exists in this tenant.
    ///
    /// Three deliberate details:
    ///
    /// * **`token_epoch + 1`, computed by the database.** Read-modify-write in the application
    ///   loses a revocation whenever two happen at once — and "two at once" is precisely the
    ///   incident-response case this exists for.
    /// * **No `deleted_at IS NULL` predicate.** A soft-deleted user is exactly who a mass
    ///   revocation is most likely aimed at. Refusing to revoke because the account is already
    ///   being removed would be the wrong way round.
    /// * **`updated_at` *is* bumped**, unlike [`UserRepository::update_last_login_at`]: this is a
    ///   change to the user's security state, and anything caching the record must see it.
    ///
    /// This is not, by itself, "log out everywhere": refresh-token families are revoked separately
    /// by the `auth` crate (`docs/03-LLD.md §5.3`). This kills the access tokens.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub async fn bump_token_epoch(
        conn: &mut PgConnection,
        tenant: TenantId,
        user: UserId,
        now: DateTime<Utc>,
    ) -> Result<Option<i32>> {
        let row = sqlx::query(BUMP_TOKEN_EPOCH)
            .bind(sql(tenant))
            .bind(sql(user))
            .bind(now)
            .fetch_optional(&mut *conn)
            .await?;

        let epoch = match row {
            Some(row) => Some(row.try_get::<i32, _>("token_epoch")?),
            None => None,
        };

        if let Some(epoch) = epoch {
            // No user id in the message body — the structured fields carry it, and they are what a
            // log pipeline redacts on. Never the email address (`CLAUDE.md` rule 10).
            tracing::info!(
                tenant_id = %tenant,
                user_id = %user,
                token_epoch = epoch,
                "token epoch bumped; every outstanding access token for this user is revoked"
            );
        }

        Ok(epoch)
    }
}

/// One user by id.
const SELECT_USER_BY_ID: &str = "SELECT id, tenant_id, email, normalized_email, display_name, \
     status, is_admin, token_epoch, source, external_id, department, locale, last_login_at, \
     created_at, updated_at \
     FROM users WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL";

/// One user by normalized email, within a tenant. Matches `uq_users_email`.
const SELECT_USER_BY_EMAIL: &str = "SELECT id, tenant_id, email, normalized_email, display_name, \
     status, is_admin, token_epoch, source, external_id, department, locale, last_login_at, \
     created_at, updated_at \
     FROM users WHERE tenant_id = $1 AND normalized_email = $2 AND deleted_at IS NULL";

/// One page of users.
///
/// The `$2::uuid IS NULL OR` form is what lets one statement serve the first page and every page
/// after it. The alternative — two SQL strings chosen by a branch — is two query plans, two places
/// for the filter predicates to drift, and a first page that can be filtered differently from the
/// rest without anything failing.
const SELECT_USER_PAGE: &str = "SELECT id, tenant_id, email, normalized_email, display_name, \
     status, is_admin, token_epoch, source, external_id, department, locale, last_login_at, \
     created_at, updated_at \
     FROM users \
     WHERE tenant_id = $1 \
       AND ($2::uuid IS NULL OR id > $2::uuid) \
       AND ($3::text IS NULL OR status = $3::text) \
       AND ($4::boolean OR deleted_at IS NULL) \
     ORDER BY id ASC \
     LIMIT $5";

/// Records a sign-in. `updated_at` is untouched on purpose — see `update_last_login_at`.
const UPDATE_LAST_LOGIN: &str = "UPDATE users SET last_login_at = $3 \
     WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL";

/// The mass-revocation increment. No `deleted_at` predicate, on purpose.
const BUMP_TOKEN_EPOCH: &str = "UPDATE users SET token_epoch = token_epoch + 1, updated_at = $3 \
     WHERE tenant_id = $1 AND id = $2 \
     RETURNING token_epoch";

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::row::USER_COLUMNS;

    #[test]
    fn the_select_lists_match_the_decoders_column_constant() {
        for query in [SELECT_USER_BY_ID, SELECT_USER_BY_EMAIL, SELECT_USER_PAGE] {
            assert!(query.contains(USER_COLUMNS), "{query}");
        }
    }

    #[test]
    fn every_user_query_carries_the_application_tenant_predicate() {
        // RLS is the other layer and neither is redundant (`docs/04-DATA-MODEL.md §3`). A query
        // that lost this would still be correct today and would stop being correct the moment
        // something ran it on a connection without a tenant context.
        for query in [
            SELECT_USER_BY_ID,
            SELECT_USER_BY_EMAIL,
            SELECT_USER_PAGE,
            UPDATE_LAST_LOGIN,
            BUMP_TOKEN_EPOCH,
        ] {
            assert!(query.contains("tenant_id = $1"), "{query}");
        }
    }

    #[test]
    fn the_listing_never_uses_offset() {
        // `docs/03-LLD.md §17` prohibits deep OFFSET in the query layer.
        assert!(!SELECT_USER_PAGE.to_uppercase().contains("OFFSET"));
        assert!(SELECT_USER_PAGE.contains("ORDER BY id ASC"), "the cursor assumes this order");
    }

    #[test]
    fn revocation_is_an_increment_and_reaches_deleted_users() {
        // Set-to-a-value loses a concurrent revocation; a `deleted_at` predicate would refuse to
        // revoke exactly the accounts most likely to need it.
        assert!(BUMP_TOKEN_EPOCH.contains("token_epoch = token_epoch + 1"));
        assert!(!BUMP_TOKEN_EPOCH.contains("deleted_at"));
        assert!(BUMP_TOKEN_EPOCH.contains("RETURNING token_epoch"));
    }

    #[test]
    fn a_sign_in_does_not_bump_updated_at() {
        assert!(!UPDATE_LAST_LOGIN.contains("updated_at"));
        assert!(BUMP_TOKEN_EPOCH.contains("updated_at = $3"), "a security change must be visible");
    }

    #[test]
    fn every_filter_field_changes_the_fingerprint() {
        // The property: a cursor issued under one filter must not be accepted under another. It
        // holds only if every field is hashed, so enumerate them here — a new field added to
        // `UserFilter` and forgotten in `fingerprint` fails this test.
        let base = UserFilter::default();
        let by_status = UserFilter { status: Some(UserStatus::Active), ..base };
        let by_deleted = UserFilter { include_deleted: true, ..base };

        assert_ne!(base.fingerprint(), by_status.fingerprint());
        assert_ne!(base.fingerprint(), by_deleted.fingerprint());
        assert_ne!(by_status.fingerprint(), by_deleted.fingerprint());
        assert_eq!(base.fingerprint(), UserFilter::default().fingerprint());
    }

    #[test]
    fn two_different_statuses_produce_two_different_fingerprints() {
        let active = UserFilter { status: Some(UserStatus::Active), include_deleted: false };
        let suspended = UserFilter { status: Some(UserStatus::Suspended), include_deleted: false };
        assert_ne!(active.fingerprint(), suspended.fingerprint());
    }

    #[test]
    fn a_cursor_from_one_filter_is_rejected_by_another() {
        // The end-to-end statement of the property, without a database: `list_by_tenant` decodes
        // through exactly this call.
        let tenant = TenantId::new_v7();
        let listing = UserFilter { status: Some(UserStatus::Active), include_deleted: false };
        let cursor = Cursor::new(tenant, UserId::new_v7(), listing.fingerprint()).encode();

        assert!(Cursor::<UserId>::decode(&cursor, tenant, listing.fingerprint()).is_ok());
        assert!(
            Cursor::<UserId>::decode(&cursor, tenant, UserFilter::default().fingerprint()).is_err()
        );
    }
}
