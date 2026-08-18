//! Content fixtures: the workspace → library → folder → file spine, and the ACL entries over it.
//!
//! # Why this is here rather than in each suite
//!
//! Three suites already write this spine by hand — `crates/authorization/tests/acl_resolution.rs`,
//! `crates/versions/tests/versions.rs`, `crates/uploads/tests/sessions.rs` — and the leakage matrix
//! (`docs/12-TESTING.md §4`) needs it again. Four hand-written copies of the same `INSERT` are four
//! chances to spell a column differently from the migration, and the copy that gets it wrong is the
//! one whose test then passes for the wrong reason.
//!
//! # Plain SQL, not the domain crates
//!
//! Nothing here calls `enclave-files`, `enclave-libraries` or `enclave-workspaces`. `enclave-testing`
//! sits *below* every domain crate: those crates take this one as a dev-dependency, and a normal
//! dependency back would invert the layering and make an unrelated compile error in a domain crate
//! break every suite in the workspace. Every column below is spelled as `docs/04-DATA-MODEL.md §7`
//! and `§8` define it, so a migration that drifts from the document fails here rather than in
//! production.
//!
//! # Written over an administrative connection
//!
//! [`Spine::insert`] and [`grant`] take a `&mut PgConnection`, and every caller should hand them
//! [`crate::TestDb::connect`] — the harness's own superuser connection — because they are *setup*,
//! not subject. Assertions must run over [`crate::TestDb::pool`], which `SET ROLE enclave_app`s, or
//! they run with row-level security switched off and prove nothing (PR #22).

use chrono::{DateTime, Utc};
use enclave_core::{
    Action, FileId, GroupId, LibraryId, ResourceRef, TenantId, UserId, WorkspaceId,
};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::HarnessError;

/// A workspace → library → folder → file spine: the shape every content permission question has.
///
/// Identifiers are fresh UUIDv7s per instance rather than derived from the tenant, so a test may
/// build several spines in one tenant and keep them independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spine {
    /// The tenant every row belongs to.
    pub tenant: TenantId,
    /// The workspace at the top of the chain.
    pub workspace: WorkspaceId,
    /// The library inside it.
    pub library: LibraryId,
    /// A folder at the library root.
    pub folder: FileId,
    /// A file inside that folder — two levels below the library, so an inheritance walk has
    /// something to walk.
    pub file: FileId,
}

impl Spine {
    /// A spine of fresh identifiers in `tenant`. Nothing is written until [`Spine::insert`].
    #[must_use]
    pub fn new(tenant: TenantId) -> Self {
        Self {
            tenant,
            workspace: WorkspaceId::new_v7(),
            library: LibraryId::new_v7(),
            folder: FileId::new_v7(),
            file: FileId::new_v7(),
        }
    }

    /// A reference to the file, for `PolicyEngine::enforce` and the authorization services.
    #[must_use]
    pub fn file_ref(&self) -> ResourceRef {
        ResourceRef::file(self.tenant, self.file)
    }

    /// A reference to the folder.
    #[must_use]
    pub fn folder_ref(&self) -> ResourceRef {
        ResourceRef::folder(self.tenant, self.folder)
    }

    /// Writes the whole spine.
    ///
    /// The file lands `AVAILABLE` (the column default): these fixtures exist to ask permission
    /// questions, and a `PROCESSING` file would make every read path refuse for reasons that have
    /// nothing to do with the ACL under test. A suite testing rule 9 should write its own row.
    ///
    /// # Errors
    ///
    /// Any statement failure — a missing migration, or a column the document and the migration
    /// disagree about.
    pub async fn insert(
        &self,
        conn: &mut PgConnection,
        owner: UserId,
        at: DateTime<Utc>,
    ) -> Result<(), HarnessError> {
        sqlx::query(
            "INSERT INTO workspaces
               (id, tenant_id, name, slug, visibility, created_by, created_at, updated_at)
             VALUES ($1, $2, 'ws', $3, 'PRIVATE', $4, $5, $5)",
        )
        .bind(self.workspace.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(format!("ws-{}", self.workspace.as_uuid()))
        .bind(owner.as_uuid())
        .bind(at)
        .execute(&mut *conn)
        .await?;

        sqlx::query(
            "INSERT INTO libraries
               (id, tenant_id, workspace_id, name, slug, inherit_permissions, versioning_mode,
                external_sharing, created_at, updated_at)
             VALUES ($1, $2, $3, 'lib', $4, TRUE, 'MAJOR', 'DISABLED', $5, $5)",
        )
        .bind(self.library.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(self.workspace.as_uuid())
        .bind(format!("lib-{}", self.library.as_uuid()))
        .bind(at)
        .execute(&mut *conn)
        .await?;

        self.insert_node(conn, self.folder, None, "FOLDER", owner, at).await?;
        self.insert_node(conn, self.file, Some(self.folder), "FILE", owner, at).await
    }

    async fn insert_node(
        &self,
        conn: &mut PgConnection,
        id: FileId,
        parent: Option<FileId>,
        node_type: &str,
        owner: UserId,
        at: DateTime<Utc>,
    ) -> Result<(), HarnessError> {
        sqlx::query(
            "INSERT INTO files
               (id, tenant_id, workspace_id, library_id, parent_id, node_type, name,
                normalized_name, mime_type, inherit_permissions, created_by, modified_by,
                created_at, modified_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $7, 'application/octet-stream', TRUE, $8, $8,
                     $9, $9)",
        )
        .bind(id.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(self.workspace.as_uuid())
        .bind(self.library.as_uuid())
        .bind(parent.map(|id| id.as_uuid()))
        .bind(node_type)
        // The id as the name: unique within the folder without a counter, and it makes a failing
        // assertion name the row it is about.
        .bind(id.as_uuid().to_string())
        .bind(owner.as_uuid())
        .bind(at)
        .execute(&mut *conn)
        .await?;
        Ok(())
    }
}

/// Where an ACL entry hangs.
///
/// An enum rather than a `(&str, Uuid)` pair because `resource_type` and `resource_id` have to
/// agree — `("FILE", folder_id)` is accepted by the `CHECK` constraint, resolves against nothing,
/// and turns a permission test into a test of the empty set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclScope {
    /// On the workspace, at the top of the chain.
    Workspace(WorkspaceId),
    /// On the library.
    Library(LibraryId),
    /// On a folder.
    Folder(FileId),
    /// On a file.
    File(FileId),
}

impl AclScope {
    /// The `(resource_type, resource_id)` pair, exactly as `acl_entries`' `CHECK` spells it.
    #[must_use]
    pub fn columns(self) -> (&'static str, Uuid) {
        match self {
            Self::Workspace(id) => ("WORKSPACE", id.as_uuid()),
            Self::Library(id) => ("LIBRARY", id.as_uuid()),
            Self::Folder(id) => ("FOLDER", id.as_uuid()),
            Self::File(id) => ("FILE", id.as_uuid()),
        }
    }
}

/// Who an ACL entry names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclPrincipal {
    /// One user.
    User(UserId),
    /// One group, resolved through the transitive closure.
    Group(GroupId),
    /// Everyone in the tenant — the most permissive entry that can exist, and therefore the one a
    /// cross-tenant test should use.
    Everyone,
}

impl AclPrincipal {
    /// The `(principal_type, principal_id)` pair; `EVERYONE` carries a `NULL` id.
    #[must_use]
    pub fn columns(self) -> (&'static str, Option<Uuid>) {
        match self {
            Self::User(id) => ("USER", Some(id.as_uuid())),
            Self::Group(id) => ("GROUP", Some(id.as_uuid())),
            Self::Everyone => ("EVERYONE", None),
        }
    }
}

/// Allow or deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclEffect {
    /// Grants the action, unless a `DENY` anywhere in the chain overrides it.
    Allow,
    /// Refuses it, wherever in the chain it sits (`docs/04-DATA-MODEL.md §9` rule 3).
    Deny,
}

impl AclEffect {
    /// The stored value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Deny => "DENY",
        }
    }
}

/// Writes one ACL entry.
///
/// The action is an [`Action`] rather than a string so that the entry, the resolver and the audit
/// row all name it identically — `Action`'s `Display` is what `acl_entries.action` holds, and a
/// grant that spells it differently is a grant that never matches.
///
/// # Errors
///
/// Any statement failure, including the unique violation from writing the same
/// `(resource, principal, action)` twice — which is a test bug worth surfacing rather than folding
/// into `ON CONFLICT DO NOTHING`.
pub async fn grant(
    conn: &mut PgConnection,
    tenant: TenantId,
    scope: AclScope,
    principal: AclPrincipal,
    action: Action,
    effect: AclEffect,
    expires_at: Option<DateTime<Utc>>,
) -> Result<Uuid, HarnessError> {
    let (resource_type, resource_id) = scope.columns();
    let (principal_type, principal_id) = principal.columns();
    let id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO acl_entries
           (id, tenant_id, resource_type, resource_id, principal_type, principal_id, action,
            effect, granted_by, granted_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(id)
    .bind(tenant.as_uuid())
    .bind(resource_type)
    .bind(resource_id)
    .bind(principal_type)
    .bind(principal_id)
    .bind(action.to_string())
    .bind(effect.as_str())
    .bind(Uuid::nil())
    .bind(Utc::now())
    .bind(expires_at)
    .execute(&mut *conn)
    .await?;

    Ok(id)
}

/// Removes every ACL entry on one resource — a revocation, in the bluntest form.
///
/// Returns how many rows went, so a test can assert the revocation actually removed something
/// rather than silently matching nothing.
///
/// # Errors
///
/// Any statement failure.
pub async fn revoke_all(
    conn: &mut PgConnection,
    tenant: TenantId,
    scope: AclScope,
) -> Result<u64, HarnessError> {
    let (resource_type, resource_id) = scope.columns();
    let result = sqlx::query(
        "DELETE FROM acl_entries
         WHERE tenant_id = $1 AND resource_type = $2 AND resource_id = $3",
    )
    .bind(tenant.as_uuid())
    .bind(resource_type)
    .bind(resource_id)
    .execute(&mut *conn)
    .await?;
    Ok(result.rows_affected())
}
