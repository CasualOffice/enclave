//! What is being attempted, and to what.
//!
//! The pair `(Action, ResourceRef)` is the question the policy chain answers. Both halves are
//! typed rather than stringly, because the entire access model rests on distinctions that a string
//! comparison silently erases.

use core::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::id::{
    ChunkId, DeviceId, FileId, GroupId, LibraryId, ShareLinkId, TenantId, UserId, VersionId,
    WorkspaceId,
};

wire_enum! {
    /// Everything that can be attempted against a file or folder (`docs/03-LLD.md §6`).
    ///
    /// **There is deliberately no generic `Read`.** Preview, content read, download, print, export
    /// and sync are six different exposures of the same bytes with six different risk profiles,
    /// and a product that collapses them cannot express "view it in the browser, but it never
    /// leaves the browser" — which is the single most requested enterprise control
    /// (`CLAUDE.md` non-negotiable rule 6). Every one of these variants exists because some policy
    /// needs to permit it while denying its neighbour.
    ///
    /// Not `#[non_exhaustive]`: adding an action *should* break every exhaustive `match` in every
    /// policy service, because each of them genuinely has to decide what the new action means. A
    /// wildcard arm defaulting to "treat it like the others" is how an unconsidered action becomes
    /// an unguarded one.
    pub enum FileAction {
        /// Read name, size, timestamps and other metadata without touching content.
        MetadataRead => "metadata_read",
        /// View a server-rendered rendition. Never yields the original bytes, and never an
        /// object-storage URL for them.
        Preview => "preview",
        /// Read the content itself, e.g. for extraction or in-place editing.
        ContentRead => "content_read",
        /// Obtain the original bytes as a file.
        Download => "download",
        /// Render to a printer. Separate from download because a watermark obligation applies
        /// differently, and because "may print but may not keep a copy" is a real policy.
        Print => "print",
        /// Convert and take away in another format — the download path that a naive
        /// download-blocking policy misses.
        Export => "export",
        /// Modify content.
        Edit => "edit",
        /// Duplicate into another location, which creates a copy outside the original's inherited
        /// permissions and therefore is not merely a read.
        Copy => "copy",
        /// Relocate, which changes inherited permissions.
        Move => "move",
        /// Grant access to another principal inside the tenant.
        Share => "share",
        /// Grant access to someone outside the tenant. Always distinct from `Share`: external
        /// sharing is the highest-consequence grant in the system.
        ShareExternal => "share_external",
        /// Move to the recycle bin or purge.
        Delete => "delete",
        /// Bring back from the recycle bin.
        Restore => "restore",
        /// Read a specific historical version. Distinct because version history can contain
        /// content that was later redacted from the current version.
        VersionRead => "version_read",
        /// Promote a historical version to current.
        VersionRestore => "version_restore",
        /// Change the resource's own permissions — the action that can grant every other action,
        /// and therefore never implied by any of them.
        ManagePermissions => "manage_permissions",
        /// Replicate to a device for offline availability. Distinct from `Download` so a policy
        /// can allow browsing and downloading while refusing to place a copy on a device that
        /// leaves the building.
        Sync => "sync",
    }
}

wire_enum! {
    /// What can be attempted against a container — a workspace, a library or a folder.
    ///
    /// Containers share one vocabulary because they share one permission model; which container is
    /// meant is carried by [`ResourceRef::kind`], so splitting this into three identical
    /// enumerations would add ceremony without adding a distinction.
    ///
    /// Provisional in the sense that it will grow as M1 and M2 land real container features. That
    /// growth is safe precisely because it breaks exhaustive matches.
    pub enum ContainerAction {
        /// List or open the container.
        Read => "read",
        /// Create a child item inside it.
        Create => "create",
        /// Rename or change settings.
        Update => "update",
        /// Remove the container and, transitively, what it holds.
        Delete => "delete",
        /// Add or remove members.
        ManageMembers => "manage_members",
        /// Change permissions on the container itself.
        ManagePermissions => "manage_permissions",
    }
}

wire_enum! {
    /// What can be attempted against a sharing link or grant.
    ///
    /// Kept apart from [`FileAction::Share`] because that action is "may this caller share this
    /// file?", whereas these are operations on the resulting share object — a distinction that
    /// matters when revoking someone else's link.
    pub enum ShareAction {
        /// Create a link or grant scoped to the tenant.
        Create => "create",
        /// Create one usable outside the tenant.
        CreateExternal => "create_external",
        /// Inspect an existing share and its recipients.
        Read => "read",
        /// Change expiry, permission or password on an existing share.
        Update => "update",
        /// Revoke it.
        Revoke => "revoke",
    }
}

wire_enum! {
    /// Tenant-administration operations.
    ///
    /// Coarse on purpose at this stage: these gate whole administrative surfaces, and inventing a
    /// fine-grained vocabulary before the admin surfaces exist would be guessing. It grows with
    /// the admin API.
    pub enum AdminAction {
        /// View tenant configuration.
        ReadConfig => "read_config",
        /// Change tenant configuration: domains, branding, quotas, integrations.
        WriteConfig => "write_config",
        /// Read the audit log.
        ReadAudit => "read_audit",
        /// Manage users, groups and guests.
        ManageIdentity => "manage_identity",
        /// Create or change policy: DLP rules, conditional access, barriers, retention.
        ManagePolicy => "manage_policy",
    }
}

/// Any action the policy chain can be asked to authorize.
///
/// A single enum so that `PolicyEngine::enforce` has one signature rather than one per resource
/// family; the inner enums keep each family's vocabulary honest.
///
/// Not `#[non_exhaustive]`, for the reason given on [`FileAction`]: adding a resource family must
/// force every policy service to consider it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "resource", content = "action", rename_all = "snake_case")]
pub enum Action {
    /// Against a file or folder.
    File(FileAction),
    /// Against a workspace, library or folder as a container.
    Container(ContainerAction),
    /// Against a share link or grant.
    Share(ShareAction),
    /// Against tenant administration.
    Admin(AdminAction),
}

impl Action {
    /// The resource family this action belongs to, as a stable string.
    #[must_use]
    pub const fn family(&self) -> &'static str {
        match self {
            Self::File(_) => "file",
            Self::Container(_) => "container",
            Self::Share(_) => "share",
            Self::Admin(_) => "admin",
        }
    }

    /// The action itself, as a stable string, without its family.
    #[must_use]
    pub const fn verb(&self) -> &'static str {
        match self {
            Self::File(a) => a.as_str(),
            Self::Container(a) => a.as_str(),
            Self::Share(a) => a.as_str(),
            Self::Admin(a) => a.as_str(),
        }
    }

    /// Whether this action can put content, or a rendition of it, in front of the caller.
    ///
    /// Used by the stages that only care about exposure — watermarking, DLP inspection, egress
    /// accounting. Defined once here rather than as a `matches!` at each stage, because a stage
    /// that forgets a variant is a stage that silently stops inspecting one path.
    #[must_use]
    pub const fn exposes_content(&self) -> bool {
        matches!(
            self,
            Self::File(
                FileAction::Preview
                    | FileAction::ContentRead
                    | FileAction::Download
                    | FileAction::Print
                    | FileAction::Export
                    | FileAction::Sync
                    | FileAction::VersionRead
            )
        )
    }

    /// Whether this action puts content, or the means to reach it, outside the tenant.
    ///
    /// Defined once here for the same reason [`Self::exposes_content`] is: an external boundary
    /// that each stage recognises with its own `matches!` is an external boundary one stage
    /// eventually stops recognising. `plans/M4-GOVERNANCE.md` D27 makes this the condition under
    /// which missing security facts must fail closed *whatever* the tenant configured, so a
    /// forgotten variant here is a control that silently stops applying to one sharing path.
    ///
    /// External *sharing*, not external *access*: `file.download` by an already-admitted guest is
    /// content leaving the building too, but it is governed by the download and classification
    /// controls rather than by the ones that decide whether a link may exist at all.
    #[must_use]
    pub const fn is_external_share(&self) -> bool {
        matches!(
            self,
            Self::File(FileAction::ShareExternal) | Self::Share(ShareAction::CreateExternal)
        )
    }

    /// Whether this action changes the terms of an *existing* share — its expiry, its permission
    /// or its password.
    ///
    /// The companion to [`Self::is_external_share`], and `ENC-588` is why there are two. That one
    /// recognises the actions that *create* external exposure, which is a property of the action
    /// alone. This one recognises the action that can *broaden* exposure that already exists,
    /// which is only half the question — the other half is whether the share in hand is external,
    /// a property of the resource. `FactsPolicy::is_forced_closed` pairs them; neither is a
    /// control on its own.
    ///
    /// `Revoke` is deliberately absent. Revoking *reduces* exposure, and a tenant that cannot
    /// revoke an external link over unscanned content is left holding the link — the shape D31
    /// names for a delete refused on a quota, reached by a different road. `Read` is absent
    /// because inspecting a share changes nothing about who can reach it.
    #[must_use]
    pub const fn alters_existing_share(&self) -> bool {
        matches!(self, Self::Share(ShareAction::Update))
    }

    /// Whether this action changes state, and therefore must not be served from a cached decision
    /// or run against a read replica.
    #[must_use]
    pub const fn is_mutating(&self) -> bool {
        match self {
            Self::File(a) => matches!(
                a,
                FileAction::Edit
                    | FileAction::Copy
                    | FileAction::Move
                    | FileAction::Share
                    | FileAction::ShareExternal
                    | FileAction::Delete
                    | FileAction::Restore
                    | FileAction::VersionRestore
                    | FileAction::ManagePermissions
            ),
            Self::Container(a) => !matches!(a, ContainerAction::Read),
            Self::Share(a) => !matches!(a, ShareAction::Read),
            Self::Admin(a) => !matches!(a, AdminAction::ReadConfig | AdminAction::ReadAudit),
        }
    }
}

impl fmt::Display for Action {
    /// Renders as `family.verb`, e.g. `file.download`. This is the form written to audit rows, so
    /// treat it as a stable wire representation.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.family(), self.verb())
    }
}

impl From<FileAction> for Action {
    fn from(value: FileAction) -> Self {
        Self::File(value)
    }
}

impl From<ContainerAction> for Action {
    fn from(value: ContainerAction) -> Self {
        Self::Container(value)
    }
}

impl From<ShareAction> for Action {
    fn from(value: ShareAction) -> Self {
        Self::Share(value)
    }
}

impl From<AdminAction> for Action {
    fn from(value: AdminAction) -> Self {
        Self::Admin(value)
    }
}

wire_enum! {
    /// The kind of thing a [`ResourceRef`] points at.
    ///
    /// Needed because a reference carries an untyped id: the kind is what makes
    /// `(kind, id)` as specific as a typed identifier would have been.
    pub enum ResourceKind {
        /// The tenant itself, for tenant-wide administrative operations.
        Tenant => "tenant",
        /// A workspace.
        Workspace => "workspace",
        /// A document library.
        Library => "library",
        /// A folder.
        Folder => "folder",
        /// A file.
        File => "file",
        /// A specific version of a file.
        Version => "version",
        /// A unit of extracted text held in the index.
        Chunk => "chunk",
        /// A structured list.
        List => "list",
        /// One row of a list.
        ListItem => "list_item",
        /// A published page.
        Page => "page",
        /// A share link or grant.
        Share => "share",
        /// A directory user.
        User => "user",
        /// A group.
        Group => "group",
        /// A registered device.
        Device => "device",
    }
}

/// A tenant-qualified pointer to the thing an action is being attempted against.
///
/// The `tenant_id` is part of the reference rather than being taken from the context, and that is
/// the whole point: `PolicyEngine::enforce` compares the two and returns [`NotFound`] on a
/// mismatch. If the resource carried no tenant of its own there would be nothing to compare, and
/// the first line of defence against cross-tenant access would be an assumption instead of a
/// check.
///
/// [`NotFound`]: crate::error::Error::NotFound
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourceRef {
    /// The tenant the resource belongs to.
    pub tenant_id: TenantId,
    /// What kind of resource it is.
    pub kind: ResourceKind,
    /// Its identifier.
    ///
    /// Untyped here because a single reference type has to be able to point at any kind. The
    /// typed constructors below are the intended way in, so the untyped field is a storage detail
    /// rather than an invitation to pass a `Uuid` around.
    pub id: Uuid,
}

impl ResourceRef {
    /// Builds a reference from a kind and a raw id.
    ///
    /// For the deserialization and database boundaries where the kind genuinely arrives as data.
    /// Prefer the typed constructors everywhere else.
    #[must_use]
    pub const fn new(tenant_id: TenantId, kind: ResourceKind, id: Uuid) -> Self {
        Self { tenant_id, kind, id }
    }

    /// A reference to the tenant itself.
    #[must_use]
    pub const fn tenant(tenant_id: TenantId) -> Self {
        Self::new(tenant_id, ResourceKind::Tenant, tenant_id.as_uuid())
    }

    /// A reference to a workspace.
    #[must_use]
    pub const fn workspace(tenant_id: TenantId, id: WorkspaceId) -> Self {
        Self::new(tenant_id, ResourceKind::Workspace, id.as_uuid())
    }

    /// A reference to a library.
    #[must_use]
    pub const fn library(tenant_id: TenantId, id: LibraryId) -> Self {
        Self::new(tenant_id, ResourceKind::Library, id.as_uuid())
    }

    /// A reference to a file.
    #[must_use]
    pub const fn file(tenant_id: TenantId, id: FileId) -> Self {
        Self::new(tenant_id, ResourceKind::File, id.as_uuid())
    }

    /// A reference to a folder.
    ///
    /// Folders share the [`FileId`] space with files because they share the permission and
    /// hierarchy model; the kind is what distinguishes them.
    #[must_use]
    pub const fn folder(tenant_id: TenantId, id: FileId) -> Self {
        Self::new(tenant_id, ResourceKind::Folder, id.as_uuid())
    }

    /// A reference to a specific file version.
    #[must_use]
    pub const fn version(tenant_id: TenantId, id: VersionId) -> Self {
        Self::new(tenant_id, ResourceKind::Version, id.as_uuid())
    }

    /// A reference to an indexed chunk.
    #[must_use]
    pub const fn chunk(tenant_id: TenantId, id: ChunkId) -> Self {
        Self::new(tenant_id, ResourceKind::Chunk, id.as_uuid())
    }

    /// A reference to a share link.
    ///
    /// The link is a resource in its own right — `docs/05-API.md §10`'s `PATCH` and `DELETE` are
    /// about the link, not about the file behind it — even though it carries no `acl_entries` rows.
    /// `enclave_authorization` resolves it by walking whatever the link points at (`ENC-879`).
    #[must_use]
    pub const fn share(tenant_id: TenantId, id: ShareLinkId) -> Self {
        Self::new(tenant_id, ResourceKind::Share, id.as_uuid())
    }

    /// A reference to a user.
    #[must_use]
    pub const fn user(tenant_id: TenantId, id: UserId) -> Self {
        Self::new(tenant_id, ResourceKind::User, id.as_uuid())
    }

    /// A reference to a group.
    #[must_use]
    pub const fn group(tenant_id: TenantId, id: GroupId) -> Self {
        Self::new(tenant_id, ResourceKind::Group, id.as_uuid())
    }

    /// A reference to a device.
    #[must_use]
    pub const fn device(tenant_id: TenantId, id: DeviceId) -> Self {
        Self::new(tenant_id, ResourceKind::Device, id.as_uuid())
    }

    /// Recovers the typed file identifier, if this reference points at a file or folder.
    ///
    /// The typed way back out, so callers are not tempted to construct a `FileId` from `self.id`
    /// without checking the kind first.
    #[must_use]
    pub const fn as_file_id(&self) -> Option<FileId> {
        match self.kind {
            ResourceKind::File | ResourceKind::Folder => Some(FileId::from_uuid(self.id)),
            _ => None,
        }
    }
}

impl fmt::Display for ResourceRef {
    /// Renders as `kind:id`, with the tenant deliberately omitted: this string ends up in log
    /// lines and error contexts, and a resource reference is only ever interpreted inside a tenant
    /// that has already been established.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind, self.id)
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal, not a
    // production hazard. The workspace warns on these constructs for non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn file_action_has_every_documented_variant() {
        // `docs/03-LLD.md §6` lists exactly seventeen. A count assertion catches an accidental
        // deletion during a refactor, which a spelling test would not.
        assert_eq!(FileAction::all().len(), 17);
    }

    #[test]
    fn file_actions_round_trip() {
        for action in FileAction::all() {
            assert_eq!(action.as_str().parse::<FileAction>(), Ok(*action));
        }
    }

    #[test]
    fn actions_render_as_family_dot_verb() {
        assert_eq!(Action::File(FileAction::Download).to_string(), "file.download");
        assert_eq!(Action::Admin(AdminAction::ReadAudit).to_string(), "admin.read_audit");
        assert_eq!(Action::from(ShareAction::CreateExternal).to_string(), "share.create_external");
    }

    #[test]
    fn actions_round_trip_through_serde() {
        let action = Action::File(FileAction::ShareExternal);
        let json = serde_json::to_string(&action).expect("serialize");
        assert_eq!(json, r#"{"resource":"file","action":"share_external"}"#);
        assert_eq!(serde_json::from_str::<Action>(&json).expect("deserialize"), action);
    }

    #[test]
    fn content_exposing_actions_are_recognised() {
        // Every path by which bytes or a rendition can reach a caller must be inspectable.
        for action in [
            FileAction::Preview,
            FileAction::ContentRead,
            FileAction::Download,
            FileAction::Print,
            FileAction::Export,
            FileAction::Sync,
            FileAction::VersionRead,
        ] {
            assert!(Action::File(action).exposes_content(), "{action} must count as exposure");
        }
        assert!(!Action::File(FileAction::MetadataRead).exposes_content());
        assert!(!Action::File(FileAction::Delete).exposes_content());
    }

    #[test]
    fn reads_are_not_mutations_and_mutations_are() {
        assert!(!Action::File(FileAction::Preview).is_mutating());
        assert!(Action::File(FileAction::Delete).is_mutating());
        assert!(!Action::Container(ContainerAction::Read).is_mutating());
        assert!(Action::Container(ContainerAction::Create).is_mutating());
        assert!(!Action::Admin(AdminAction::ReadAudit).is_mutating());
        assert!(Action::Admin(AdminAction::ManagePolicy).is_mutating());
    }

    #[test]
    fn resource_refs_are_tenant_qualified_and_typed_on_the_way_in() {
        let tenant = TenantId::new_v7();
        let file = FileId::new_v7();
        let resource = ResourceRef::file(tenant, file);
        assert_eq!(resource.tenant_id, tenant);
        assert_eq!(resource.kind, ResourceKind::File);
        assert_eq!(resource.as_file_id(), Some(file));
        assert_eq!(resource.to_string(), format!("file:{}", file.as_uuid()));
    }

    #[test]
    fn as_file_id_refuses_to_retype_an_unrelated_resource() {
        let tenant = TenantId::new_v7();
        let resource = ResourceRef::workspace(tenant, WorkspaceId::new_v7());
        assert_eq!(resource.as_file_id(), None);
    }

    #[test]
    fn a_tenant_reference_points_at_itself() {
        let tenant = TenantId::new_v7();
        let resource = ResourceRef::tenant(tenant);
        assert_eq!(resource.id, tenant.as_uuid());
        assert_eq!(resource.kind, ResourceKind::Tenant);
    }
}
