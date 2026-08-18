//! Workspace membership: who is in a workspace, and which workspaces a principal is in.
//!
//! # A membership is an input, not a verdict
//!
//! Nothing here answers "may this principal read that file". Effective permission is resolved by
//! the authorization stage from ACL entries, inheritance and group closure
//! (`docs/04-DATA-MODEL.md §9`, `enclave-authorization`); a membership row is one of the facts that
//! resolution reads. In particular [`WorkspaceMemberRepository::list_for_principal`] returns the
//! workspaces a principal is a **direct** member of — not the workspaces it can see. A principal
//! also reaches workspaces through a group it belongs to, through tenant-wide visibility, and
//! through an ACL entry granted on a library beneath one. A caller that used this listing as an
//! access answer would be under-reporting in the ordinary case and, the moment someone "fixed" that
//! by adding a union, would be enforcing policy outside `PolicyEngine::enforce`
//! (`plans/M1-CONTENT-CORE.md` D11).
//!
//! # Expiry is filtered, never enforced
//!
//! `expires_at` is compared against a clock the caller passes in, and only to keep lapsed rows out
//! of a listing that asks for current members. Whether an expired membership grants anything is the
//! policy chain's decision against its own clock; a repository that made it here would be a second
//! place for the two clocks to disagree.
//!
//! # Adding is not upserting
//!
//! [`WorkspaceMemberRepository::add`] fails with [`WorkspaceError::AlreadyMember`] rather than
//! quietly rewriting an existing row. `ON CONFLICT DO UPDATE` would turn "add Dana as a viewer"
//! into a silent demotion of an owner, which is a privilege change with no record that it was
//! intended. Changing a role is a separate act with its own audit event.

use chrono::{DateTime, Utc};
use enclave_core::{TenantId, WorkspaceId};
use enclave_db::sql;
use enclave_identity::{Cursor, FilterFingerprint, PageSize};
use sqlx::PgConnection;

use crate::error::{Result, WorkspaceError};
use crate::model::{NewMember, PrincipalId, WorkspaceMember};
use crate::row::member_from_row;
use crate::violation::{is_foreign_key_violation, is_unique_violation};
use crate::workspace_repo::{page_from_rows, WorkspacePage};

/// Which membership rows a listing should return.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MemberFilter {
    /// Include memberships whose `expires_at` has passed.
    ///
    /// `false` by default: an administrative view that shows a lapsed grant as a current one
    /// invites someone to "remove" access that was already gone and to believe access was removed
    /// when it was not.
    pub include_expired: bool,
}

impl MemberFilter {
    /// The digest bound into this listing's cursors, for a listing scoped to `scope`.
    ///
    /// The scope — a workspace id or a principal id — participates in the fingerprint alongside the
    /// filter fields. Two listings of the same shape over different subjects are different
    /// listings, and a cursor that crossed between them would resume at a position that means
    /// nothing in the second one.
    fn fingerprint(&self, listing: &str, scope: &str) -> FilterFingerprint {
        FilterFingerprint::of(&[
            listing,
            "scope",
            scope,
            "expired",
            if self.include_expired { "include" } else { "exclude" },
        ])
    }
}

/// One page of a membership listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberPage {
    /// The memberships, in ascending principal-id order.
    pub members: Vec<WorkspaceMember>,
    /// The opaque cursor for the next page, or `None` at the end of the listing.
    pub next_cursor: Option<String>,
    /// Whether another page exists (`docs/05-API.md §6` puts `hasMore` on the wire).
    pub has_more: bool,
    /// The size actually used, after clamping.
    pub limit: PageSize,
}

/// Reads and writes workspace membership.
///
/// `&mut PgConnection`, never a pool (`plans/M1-CONTENT-CORE.md` D10), and every statement carries
/// its own `tenant_id = $1` predicate beside row-level security.
#[derive(Debug, Clone, Copy, Default)]
pub struct WorkspaceMemberRepository;

impl WorkspaceMemberRepository {
    /// Adds a principal to a workspace.
    ///
    /// The workspace's existence is established by the composite foreign key rather than by a
    /// prior `SELECT`: the check and the insert would otherwise be two statements with a window
    /// between them, and the constraint covers the cross-tenant case in the same breath — a
    /// workspace id belonging to another tenant fails the key exactly as a fabricated one does.
    ///
    /// # Errors
    ///
    /// * [`WorkspaceError::AlreadyMember`] — the principal already has a membership row here.
    /// * [`WorkspaceError::NoSuchWorkspace`] — no such workspace in this tenant.
    /// * Storage and decode failures.
    pub async fn add(
        conn: &mut PgConnection,
        tenant: TenantId,
        workspace: WorkspaceId,
        member: &NewMember,
        now: DateTime<Utc>,
    ) -> Result<WorkspaceMember> {
        let row = sqlx::query(INSERT_MEMBER)
            .bind(sql(tenant))
            .bind(sql(workspace))
            .bind(sql(member.principal_id))
            .bind(member.principal_type.as_str())
            .bind(sql(member.role_id))
            .bind(sql(member.added_by))
            .bind(now)
            .bind(member.expires_at)
            .fetch_one(&mut *conn)
            .await
            .map_err(membership_aware)?;

        // Ids only: a principal id is not personal data, a display name would be
        // (`CLAUDE.md` rule 10). The audit record proper is written by the policy engine.
        tracing::info!(
            tenant_id = %tenant,
            workspace_id = %workspace,
            principal_id = %member.principal_id,
            principal_type = member.principal_type.as_str(),
            "workspace membership granted"
        );

        member_from_row(&row)
    }

    /// Removes a principal's membership.
    ///
    /// A row removal rather than a soft delete, which is what migration 0004 provides for
    /// (`workspace_members` has no `deleted_at`, and its grant includes `DELETE`). Revoked access
    /// must leave nothing behind that a later query could still read as a grant; the record that it
    /// *was* revoked lives in `audit_events`, which is append-only and cannot be deleted at all.
    ///
    /// Returns `false` if there was no such membership, so a repeated revocation is idempotent
    /// rather than an error.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub async fn remove(
        conn: &mut PgConnection,
        tenant: TenantId,
        workspace: WorkspaceId,
        principal: PrincipalId,
    ) -> Result<bool> {
        let removed = sqlx::query(DELETE_MEMBER)
            .bind(sql(tenant))
            .bind(sql(workspace))
            .bind(sql(principal))
            .execute(&mut *conn)
            .await?
            .rows_affected()
            == 1;

        if removed {
            tracing::info!(
                tenant_id = %tenant,
                workspace_id = %workspace,
                principal_id = %principal,
                "workspace membership revoked"
            );
        }

        Ok(removed)
    }

    /// Lists a workspace's members, one page at a time.
    ///
    /// Ordered by `principal_id`, which is the last column of the primary key
    /// `(tenant_id, workspace_id, principal_id)` — so the page is an index range scan and the sort
    /// key is unique within the workspace, which is what the cursor needs.
    ///
    /// # Errors
    ///
    /// Storage failures, decode failures, and [`WorkspaceError::InvalidCursor`] if the cursor was
    /// issued for a different tenant, workspace or filter set.
    pub async fn list_members(
        conn: &mut PgConnection,
        tenant: TenantId,
        workspace: WorkspaceId,
        filter: &MemberFilter,
        now: DateTime<Utc>,
        limit: PageSize,
        cursor: Option<&str>,
    ) -> Result<MemberPage> {
        let fingerprint =
            filter.fingerprint("workspace_members.by_workspace", &workspace.to_string());
        let after = decode_cursor::<PrincipalId>(cursor, tenant, fingerprint)?;
        let probe = limit.get().saturating_add(1);

        let rows = sqlx::query(SELECT_MEMBER_PAGE)
            .bind(sql(tenant))
            .bind(sql(workspace))
            .bind(after.map(sql))
            .bind(filter.include_expired)
            .bind(now)
            .bind(probe)
            .fetch_all(&mut *conn)
            .await?;

        let has_more = rows.len() as i64 > limit.get();
        let kept = rows.iter().take(usize::try_from(limit.get()).unwrap_or(usize::MAX));
        let members: Vec<WorkspaceMember> = kept.map(member_from_row).collect::<Result<_>>()?;

        let next_cursor = match members.last() {
            Some(last) if has_more => {
                Some(Cursor::new(tenant, last.principal_id, fingerprint).encode())
            }
            _ => None,
        };

        Ok(MemberPage { members, next_cursor, has_more, limit })
    }

    /// Lists the workspaces a principal is a **direct** member of.
    ///
    /// Not "the workspaces this principal can see" — see the [module documentation](self) for the
    /// three other ways a workspace becomes reachable, and for why widening this query would be the
    /// wrong fix.
    ///
    /// Trashed workspaces are excluded: a membership row survives the workspace being trashed
    /// (nothing cascades), and a trash view is a different query from "my workspaces".
    ///
    /// # Errors
    ///
    /// As [`WorkspaceMemberRepository::list_members`].
    pub async fn list_for_principal(
        conn: &mut PgConnection,
        tenant: TenantId,
        principal: PrincipalId,
        filter: &MemberFilter,
        now: DateTime<Utc>,
        limit: PageSize,
        cursor: Option<&str>,
    ) -> Result<WorkspacePage> {
        let fingerprint =
            filter.fingerprint("workspace_members.by_principal", &principal.to_string());
        let after = decode_cursor::<WorkspaceId>(cursor, tenant, fingerprint)?;
        let probe = limit.get().saturating_add(1);

        let rows = sqlx::query(SELECT_PRINCIPAL_WORKSPACE_PAGE)
            .bind(sql(tenant))
            .bind(sql(principal))
            .bind(after.map(sql))
            .bind(filter.include_expired)
            .bind(now)
            .bind(probe)
            .fetch_all(&mut *conn)
            .await?;

        page_from_rows(&rows, tenant, limit, fingerprint)
    }
}

/// Decodes an optional cursor, collapsing every rejection into one answer.
fn decode_cursor<T: enclave_db::SqlId>(
    cursor: Option<&str>,
    tenant: TenantId,
    fingerprint: FilterFingerprint,
) -> Result<Option<T>> {
    match cursor {
        Some(text) => Cursor::<T>::decode(text, tenant, fingerprint)
            .map(Some)
            .map_err(|_| WorkspaceError::InvalidCursor),
        None => Ok(None),
    }
}

/// Turns the two constraint violations an insert can raise into domain answers.
fn membership_aware(error: sqlx::Error) -> WorkspaceError {
    if is_unique_violation(&error, "workspace_members_pkey", "workspace_members") {
        return WorkspaceError::AlreadyMember;
    }
    if is_foreign_key_violation(
        &error,
        "workspace_members_tenant_id_workspace_id_fkey",
        "workspace_members",
    ) {
        return WorkspaceError::NoSuchWorkspace;
    }
    WorkspaceError::from(error)
}

/// Grants a membership. `RETURNING` so the caller gets the row as stored rather than as sent.
const INSERT_MEMBER: &str = "INSERT INTO workspace_members \
     (tenant_id, workspace_id, principal_id, principal_type, role_id, added_by, added_at, \
      expires_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
     RETURNING tenant_id, workspace_id, principal_id, principal_type, role_id, added_by, \
     added_at, expires_at";

/// Revokes a membership.
const DELETE_MEMBER: &str = "DELETE FROM workspace_members \
     WHERE tenant_id = $1 AND workspace_id = $2 AND principal_id = $3";

/// One page of a workspace's members.
///
/// `$4` is `include_expired` and `$5` is the caller's clock: an expired row is one whose
/// `expires_at` is in the past, and a row with no `expires_at` never expires.
const SELECT_MEMBER_PAGE: &str = "SELECT tenant_id, workspace_id, principal_id, principal_type, \
     role_id, added_by, added_at, expires_at \
     FROM workspace_members \
     WHERE tenant_id = $1 AND workspace_id = $2 \
       AND ($3::uuid IS NULL OR principal_id > $3::uuid) \
       AND ($4::boolean OR expires_at IS NULL OR expires_at > $5) \
     ORDER BY principal_id ASC \
     LIMIT $6";

/// One page of the workspaces a principal belongs to.
///
/// The join is on `(tenant_id, id)` — the composite key `workspaces_tenant_id_id_key` exists for
/// exactly this, and joining on `id` alone would be a join that spans tenants if the isolation
/// predicate above it were ever lost.
const SELECT_PRINCIPAL_WORKSPACE_PAGE: &str = "SELECT w.id, w.tenant_id, w.name, w.slug, \
     w.description, w.visibility, w.default_classification_id, w.storage_profile_id, w.revision, \
     w.created_by, w.created_at, w.updated_at, w.deleted_at \
     FROM workspace_members m \
     JOIN workspaces w ON w.tenant_id = m.tenant_id AND w.id = m.workspace_id \
     WHERE m.tenant_id = $1 AND m.principal_id = $2 \
       AND ($3::uuid IS NULL OR w.id > $3::uuid) \
       AND ($4::boolean OR m.expires_at IS NULL OR m.expires_at > $5) \
       AND w.deleted_at IS NULL \
     ORDER BY w.id ASC \
     LIMIT $6";

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::row::{MEMBER_COLUMNS, WORKSPACE_COLUMNS_ALIASED};

    const EVERY_QUERY: [&str; 4] =
        [INSERT_MEMBER, DELETE_MEMBER, SELECT_MEMBER_PAGE, SELECT_PRINCIPAL_WORKSPACE_PAGE];

    #[test]
    fn the_select_lists_match_the_decoders_column_constants() {
        assert!(INSERT_MEMBER.contains(MEMBER_COLUMNS));
        assert!(SELECT_MEMBER_PAGE.contains(MEMBER_COLUMNS));
        assert!(SELECT_PRINCIPAL_WORKSPACE_PAGE.contains(WORKSPACE_COLUMNS_ALIASED));
    }

    #[test]
    fn every_query_carries_the_application_tenant_predicate() {
        for query in [DELETE_MEMBER, SELECT_MEMBER_PAGE] {
            assert!(query.contains("tenant_id = $1"), "{query}");
        }
        assert!(SELECT_PRINCIPAL_WORKSPACE_PAGE.contains("m.tenant_id = $1"));
        assert!(INSERT_MEMBER.contains("VALUES ($1,"), "the insert stamps tenant_id itself");
    }

    #[test]
    fn the_join_is_on_the_composite_key_and_not_on_the_id_alone() {
        // `workspaces_tenant_id_id_key` exists for this. A join on `id` alone is a join that
        // crosses tenants the moment the predicate above it is lost or the query is reused.
        assert!(SELECT_PRINCIPAL_WORKSPACE_PAGE
            .contains("ON w.tenant_id = m.tenant_id AND w.id = m.workspace_id"));
    }

    #[test]
    fn no_listing_uses_offset_and_both_order_by_their_cursor_key() {
        for query in [SELECT_MEMBER_PAGE, SELECT_PRINCIPAL_WORKSPACE_PAGE] {
            assert!(!query.to_uppercase().contains("OFFSET"), "{query}");
        }
        assert!(SELECT_MEMBER_PAGE.contains("ORDER BY principal_id ASC"));
        assert!(SELECT_PRINCIPAL_WORKSPACE_PAGE.contains("ORDER BY w.id ASC"));
    }

    #[test]
    fn an_open_ended_membership_is_never_treated_as_expired() {
        // `expires_at IS NULL` means "does not expire". Without that arm, every open-ended
        // membership would vanish from the default listing — the loudest possible wrong answer,
        // and the one a NULL comparison produces silently.
        for query in [SELECT_MEMBER_PAGE, SELECT_PRINCIPAL_WORKSPACE_PAGE] {
            assert!(query.contains("expires_at IS NULL OR"), "{query}");
        }
    }

    #[test]
    fn a_revocation_removes_the_row_rather_than_marking_it() {
        assert!(DELETE_MEMBER.starts_with("DELETE FROM workspace_members"));
        assert!(!DELETE_MEMBER.contains("deleted_at"));
    }

    #[test]
    fn an_add_never_becomes_an_upsert() {
        // `ON CONFLICT DO UPDATE` here would silently rewrite an existing role.
        assert!(!INSERT_MEMBER.to_uppercase().contains("ON CONFLICT"));
    }

    #[test]
    fn the_listing_never_returns_a_trashed_workspace() {
        assert!(SELECT_PRINCIPAL_WORKSPACE_PAGE.contains("w.deleted_at IS NULL"));
        for query in EVERY_QUERY {
            assert!(!query.is_empty());
        }
    }

    #[test]
    fn every_filter_field_and_the_scope_change_the_fingerprint() {
        let workspace = WorkspaceId::new_v7();
        let other = WorkspaceId::new_v7();
        let base = MemberFilter::default();
        let expired = MemberFilter { include_expired: true };

        let listing = "workspace_members.by_workspace";
        assert_ne!(
            base.fingerprint(listing, &workspace.to_string()),
            expired.fingerprint(listing, &workspace.to_string())
        );
        // Two workspaces are two listings, even under the same filter.
        assert_ne!(
            base.fingerprint(listing, &workspace.to_string()),
            base.fingerprint(listing, &other.to_string())
        );
        // As are the two listings themselves, even scoped to the same string.
        assert_ne!(
            base.fingerprint("workspace_members.by_workspace", "x"),
            base.fingerprint("workspace_members.by_principal", "x")
        );
        assert_eq!(
            base.fingerprint(listing, &workspace.to_string()),
            MemberFilter::default().fingerprint(listing, &workspace.to_string())
        );
    }

    #[test]
    fn a_cursor_issued_for_one_workspace_is_rejected_for_another() {
        let tenant = TenantId::new_v7();
        let filter = MemberFilter::default();
        let listing = "workspace_members.by_workspace";
        let mine = filter.fingerprint(listing, &WorkspaceId::new_v7().to_string());
        let yours = filter.fingerprint(listing, &WorkspaceId::new_v7().to_string());

        let cursor =
            Cursor::new(tenant, PrincipalId::from_uuid(enclave_core::Uuid::now_v7()), mine)
                .encode();
        assert!(Cursor::<PrincipalId>::decode(&cursor, tenant, mine).is_ok());
        assert!(Cursor::<PrincipalId>::decode(&cursor, tenant, yours).is_err());
    }
}
