//! The resolution rules of `docs/04-DATA-MODEL.md §9`, as pure functions over already-fetched rows.
//!
//! # Why the rules live apart from the SQL
//!
//! The four rules — inheritance chain, group closure, deny-wins, expiry — are the security-relevant
//! part of authorization, and the part most likely to be subtly wrong. Expressed only as `WHERE`
//! clauses they can be tested exclusively against a live PostgreSQL, which means in practice they
//! are tested rarely, in one configuration, by tests that are `#[ignore]`d when the database is not
//! there. Expressed here they are tested on every `cargo test`, in every combination that matters,
//! in milliseconds.
//!
//! The SQL in [`crate::repo`] applies the same filters (`expires_at`, principal match) so that the
//! database returns a few dozen rows rather than a tenant's whole ACL. That is a **prefilter, not
//! the rule**: this module re-applies every one of them, so a query that fetches too much is a
//! performance defect rather than a security one. The
//! `an_unfiltered_row_set_reaches_the_same_verdict` test below is what keeps that true.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use enclave_core::{Actor, GroupId, ReasonCode, StageDecision};
use uuid::Uuid;

/// A table an ACL entry can be attached to.
///
/// The spellings are the `resource_type` values of the `CHECK` constraint in
/// `docs/04-DATA-MODEL.md §9`, and they are the whole reason this is not
/// [`enclave_core::ResourceKind`]: that enumeration covers versions, chunks, devices and users,
/// none of which carry ACL rows, and a conversion that silently mapped one of those onto a
/// plausible-looking type would resolve against an empty node instead of refusing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AclResourceType {
    /// A workspace — the root of every inheritance chain.
    Workspace,
    /// A document library.
    Library,
    /// A folder.
    Folder,
    /// A file.
    File,
    /// A published page.
    Page,
    /// A structured list.
    List,
    /// One row of a list.
    ListItem,
}

impl AclResourceType {
    /// The database spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Workspace => "WORKSPACE",
            Self::Library => "LIBRARY",
            Self::Folder => "FOLDER",
            Self::File => "FILE",
            Self::Page => "PAGE",
            Self::List => "LIST",
            Self::ListItem => "LIST_ITEM",
        }
    }

    /// Parses the database spelling.
    ///
    /// `None` rather than a default: an unrecognised `resource_type` means the schema has grown a
    /// value this code has never considered, and guessing which existing type it resembles is how
    /// an unconsidered resource becomes an unguarded one.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "WORKSPACE" => Some(Self::Workspace),
            "LIBRARY" => Some(Self::Library),
            "FOLDER" => Some(Self::Folder),
            "FILE" => Some(Self::File),
            "PAGE" => Some(Self::Page),
            "LIST" => Some(Self::List),
            "LIST_ITEM" => Some(Self::ListItem),
            _ => None,
        }
    }
}

impl core::fmt::Display for AclResourceType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One rung of an inheritance chain: a resource an ACL entry may be attached to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainNode {
    /// Which table the node lives in.
    pub kind: AclResourceType,
    /// The row's identifier.
    ///
    /// Untyped for the same reason [`enclave_core::ResourceRef::id`] is: one type has to be able to
    /// point at a workspace, a library, a folder and a file, and the `kind` beside it is what makes
    /// the pair as specific as a newtype would have been.
    pub id: Uuid,
}

impl ChainNode {
    /// Builds a node.
    #[must_use]
    pub const fn new(kind: AclResourceType, id: Uuid) -> Self {
        Self { kind, id }
    }
}

/// A resource's inheritance chain, in the order it was walked.
///
/// Order carries no weight in the verdict — deny-wins is unordered by construction — but it is kept
/// because it is what a "why was I denied?" explanation and any future cache entry are built from,
/// and reconstructing it later would mean walking the tree twice.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InheritanceChain {
    nodes: Vec<ChainNode>,
}

impl InheritanceChain {
    /// Builds a chain from the resource outward.
    #[must_use]
    pub fn new(nodes: Vec<ChainNode>) -> Self {
        Self { nodes }
    }

    /// The nodes, resource first.
    #[must_use]
    pub fn nodes(&self) -> &[ChainNode] {
        &self.nodes
    }

    /// Whether the walk found nothing at all — a resource that does not exist, was soft-deleted, or
    /// belongs to a tenant this transaction cannot see.
    ///
    /// All three are the same answer on purpose: distinguishing them is how a caller learns that a
    /// resource exists in another tenant (`CLAUDE.md` rule 7).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Appends a node further up the tree.
    pub fn push(&mut self, node: ChainNode) {
        self.nodes.push(node);
    }
}

/// The kind of principal an ACL entry names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PrincipalKind {
    /// A directory member.
    User,
    /// A group, matched through the transitive closure rather than directly.
    Group,
    /// An external participant.
    Guest,
    /// A machine caller.
    ServiceAccount,
    /// Everyone in the tenant. Carries no identifier.
    Everyone,
}

impl PrincipalKind {
    /// The database spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "USER",
            Self::Group => "GROUP",
            Self::Guest => "GUEST",
            Self::ServiceAccount => "SERVICE_ACCOUNT",
            Self::Everyone => "EVERYONE",
        }
    }

    /// Parses the database spelling. `None` for anything unrecognised — see
    /// [`AclResourceType::parse`] for why that is not a default.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "USER" => Some(Self::User),
            "GROUP" => Some(Self::Group),
            "GUEST" => Some(Self::Guest),
            "SERVICE_ACCOUNT" => Some(Self::ServiceAccount),
            "EVERYONE" => Some(Self::Everyone),
            _ => None,
        }
    }
}

/// The principal named by one ACL entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Principal {
    /// Which kind of principal.
    pub kind: PrincipalKind,
    /// Its identifier — `None` only for [`PrincipalKind::Everyone`], which is the one kind with
    /// nothing to identify (`principal_id UUID, -- NULL for EVERYONE`).
    pub id: Option<Uuid>,
}

impl Principal {
    /// A specific principal.
    #[must_use]
    pub const fn new(kind: PrincipalKind, id: Uuid) -> Self {
        Self { kind, id: Some(id) }
    }

    /// The tenant-wide principal.
    #[must_use]
    pub const fn everyone() -> Self {
        Self { kind: PrincipalKind::Everyone, id: None }
    }
}

/// The caller expanded per rule 2: itself, its transitive group closure, and `EVERYONE`.
///
/// # What `EVERYONE` includes
///
/// Every supported principal, guests included. `docs/04-DATA-MODEL.md §9` states rule 2 without
/// qualification, and an ACL row is already tenant-scoped, so `EVERYONE` reads as "every principal
/// of this tenant". Narrowing it to non-guests here would be inventing a rule no document states —
/// but it is a rule worth stating, because "everyone" meaning "including the contractor you shared
/// one folder with" surprises people. Raised as a documentation question rather than decided here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalSet {
    direct: Principal,
    groups: HashSet<GroupId>,
}

impl PrincipalSet {
    /// Expands an actor into the principal it is matched as, or `None` when it has none.
    ///
    /// `None` for [`Actor::McpClient`] and [`Actor::System`], and that is a refusal rather than an
    /// omission. Neither appears in the `principal_type` enumeration of `acl_entries`, so no ACL
    /// row can name them; the alternative — letting them fall through to `EVERYONE` — would give
    /// every MCP client and every background job whatever the tenant grants tenant-wide, which is
    /// precisely the "one quiet path around the policy chain" this codebase exists to not have.
    /// MCP access is gated by scopes and a workspace allowlist (`docs/04 §5`), and system paths get
    /// an explicit grant when one is designed.
    #[must_use]
    pub fn for_actor(actor: &Actor) -> Option<Self> {
        let direct = match actor {
            Actor::User(id) => Principal::new(PrincipalKind::User, id.as_uuid()),
            Actor::Guest(id) => Principal::new(PrincipalKind::Guest, id.as_uuid()),
            Actor::ServiceAccount(id) => {
                Principal::new(PrincipalKind::ServiceAccount, id.as_uuid())
            }
            Actor::McpClient(_) | Actor::System => return None,
        };
        Some(Self { direct, groups: HashSet::new() })
    }

    /// Adds the resolved transitive group closure.
    #[must_use]
    pub fn with_groups(mut self, groups: impl IntoIterator<Item = GroupId>) -> Self {
        self.groups.extend(groups);
        self
    }

    /// The principal as which the caller is matched directly.
    #[must_use]
    pub const fn direct(&self) -> Principal {
        self.direct
    }

    /// The groups the caller belongs to, transitively.
    #[must_use]
    pub const fn groups(&self) -> &HashSet<GroupId> {
        &self.groups
    }

    /// Whether an entry's principal names this caller (rule 2).
    #[must_use]
    pub fn matches(&self, principal: &Principal) -> bool {
        match principal.kind {
            PrincipalKind::Everyone => true,
            PrincipalKind::Group => {
                principal.id.is_some_and(|id| self.groups.contains(&GroupId::from_uuid(id)))
            }
            // The kind is compared as well as the identifier. A guest and a user could in principle
            // be issued the same UUID; more to the point, comparing identifiers alone would make a
            // `GUEST` entry grant a user, which is the kind of collapse `Actor` is an enum to avoid.
            kind => kind == self.direct.kind && principal.id == self.direct.id,
        }
    }
}

/// Whether an entry grants or refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Effect {
    /// Grants the action.
    Allow,
    /// Refuses it, at any level, overriding every `Allow` (rule 3).
    Deny,
}

impl Effect {
    /// The database spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Deny => "DENY",
        }
    }

    /// Parses the database spelling. `None` for anything else — an effect this code does not
    /// understand must never be guessed at, in either direction.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "ALLOW" => Some(Self::Allow),
            "DENY" => Some(Self::Deny),
            _ => None,
        }
    }
}

/// One `acl_entries` row, reduced to what resolution needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AclEntry {
    /// The node it is attached to.
    pub resource: ChainNode,
    /// The principal it names.
    pub principal: Principal,
    /// Grant or refusal.
    pub effect: Effect,
    /// When it stops applying, if ever.
    pub expires_at: Option<DateTime<Utc>>,
}

impl AclEntry {
    /// Whether the entry is still in force at `now` (rule 4).
    ///
    /// `expires_at` exactly equal to `now` counts as expired, matching the `expires_at > now()`
    /// predicate in the query: the two must agree, or a row would be fetched and then not applied
    /// (or worse, the reverse).
    #[must_use]
    pub fn is_live_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_none_or(|expiry| expiry > now)
    }
}

/// The effect of an action on a resource, once every rule has been applied.
///
/// Three variants rather than a boolean because `Denied` and `NotGranted` are the same answer to
/// the caller and completely different answers to an operator: one is a policy someone wrote, the
/// other is a permission nobody has granted yet. Audit and support both need the distinction, and
/// the tests below need it to tell "deny-wins worked" apart from "nothing matched at all", which
/// are the two ways the same assertion can pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effective {
    /// At least one `ALLOW` matched and no `DENY` did.
    Allowed,
    /// A `DENY` matched somewhere in the chain.
    Denied,
    /// Nothing matched. The default, and the reason authorization is deny-by-default.
    NotGranted,
}

impl Effective {
    /// Whether the action is permitted.
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }

    /// Converts to the chain's uniform stage decision.
    ///
    /// Both refusals become the same [`ReasonCode::AccessDenied`]: telling a caller that they were
    /// *explicitly* denied, rather than merely not granted, confirms that someone wrote a rule
    /// about the resource — which confirms the resource exists.
    pub fn into_stage_decision(self) -> StageDecision {
        if self.is_allowed() {
            StageDecision::allow()
        } else {
            StageDecision::deny(ReasonCode::AccessDenied)
        }
    }
}

/// What the fetched entries say about each node, once principal and expiry filtering is done.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct NodeEffects {
    allow: bool,
    deny: bool,
}

/// The matching entries of one batch, indexed by node.
///
/// Built once per batch and consulted once per resource. That is what makes `authorize_many`
/// linear: the alternative — rescanning every fetched entry for every candidate — is quadratic, and
/// the search post-filter (`docs/07-SEARCH-INDEXING.md §6.2`) runs it on 200 candidates per query.
#[derive(Debug, Clone, Default)]
pub struct EffectiveIndex {
    nodes: HashMap<ChainNode, NodeEffects>,
}

impl EffectiveIndex {
    /// Applies rules 2 and 4 to a batch of entries, keeping only what this caller is matched by and
    /// what has not expired.
    #[must_use]
    pub fn build(entries: &[AclEntry], principals: &PrincipalSet, now: DateTime<Utc>) -> Self {
        let mut nodes: HashMap<ChainNode, NodeEffects> = HashMap::new();
        for entry in entries {
            if !entry.is_live_at(now) || !principals.matches(&entry.principal) {
                continue;
            }
            let effects = nodes.entry(entry.resource).or_default();
            match entry.effect {
                Effect::Allow => effects.allow = true,
                Effect::Deny => effects.deny = true,
            }
        }
        Self { nodes }
    }

    /// Applies rules 1 and 3 to one resource's chain.
    ///
    /// Deny-wins is implemented as a full pass over the chain rather than an early return on the
    /// first match, because an early return would make the verdict depend on the order the nodes
    /// were walked in: an `ALLOW` on the file would win over a `DENY` on the library purely because
    /// the file was visited first. That is the single most likely way this function goes wrong, and
    /// the shape of the loop is what prevents it.
    #[must_use]
    pub fn decide(&self, chain: &InheritanceChain) -> Effective {
        let mut allowed = false;
        for node in chain.nodes() {
            if let Some(effects) = self.nodes.get(node) {
                if effects.deny {
                    return Effective::Denied;
                }
                allowed |= effects.allow;
            }
        }
        if allowed {
            Effective::Allowed
        } else {
            Effective::NotGranted
        }
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use chrono::TimeZone as _;
    use enclave_core::{GuestId, McpClientId, ServiceAccountId, UserId};

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).single().expect("a valid fixed instant")
    }

    fn node(kind: AclResourceType) -> ChainNode {
        ChainNode::new(kind, Uuid::new_v4())
    }

    /// file → folder → library → workspace, the shape every content ACL question has.
    fn chain() -> (InheritanceChain, ChainNode, ChainNode, ChainNode, ChainNode) {
        let file = node(AclResourceType::File);
        let folder = node(AclResourceType::Folder);
        let library = node(AclResourceType::Library);
        let workspace = node(AclResourceType::Workspace);
        (
            InheritanceChain::new(vec![file, folder, library, workspace]),
            file,
            folder,
            library,
            workspace,
        )
    }

    fn entry(resource: ChainNode, principal: Principal, effect: Effect) -> AclEntry {
        AclEntry { resource, principal, effect, expires_at: None }
    }

    fn user_set(user: UserId) -> PrincipalSet {
        PrincipalSet::for_actor(&Actor::User(user)).expect("a user is an acl principal")
    }

    fn decide(
        entries: &[AclEntry],
        principals: &PrincipalSet,
        chain: &InheritanceChain,
    ) -> Effective {
        EffectiveIndex::build(entries, principals, now()).decide(chain)
    }

    #[test]
    fn an_allow_on_the_resource_grants() {
        let (chain, file, ..) = chain();
        let user = UserId::new_v7();
        let entries =
            [entry(file, Principal::new(PrincipalKind::User, user.as_uuid()), Effect::Allow)];
        assert_eq!(decide(&entries, &user_set(user), &chain), Effective::Allowed);
    }

    #[test]
    fn an_allow_on_an_ancestor_is_inherited() {
        let (chain, _, _, library, _) = chain();
        let user = UserId::new_v7();
        let entries =
            [entry(library, Principal::new(PrincipalKind::User, user.as_uuid()), Effect::Allow)];
        assert_eq!(decide(&entries, &user_set(user), &chain), Effective::Allowed);
    }

    #[test]
    fn nothing_matching_is_not_granted() {
        let (chain, file, ..) = chain();
        let user = UserId::new_v7();
        // An entry for somebody else, on the right resource.
        let entries = [entry(
            file,
            Principal::new(PrincipalKind::User, UserId::new_v7().as_uuid()),
            Effect::Allow,
        )];
        assert_eq!(decide(&entries, &user_set(user), &chain), Effective::NotGranted);
    }

    #[test]
    fn a_deny_on_a_parent_beats_an_allow_on_the_child() {
        // Rule 3, in the arrangement that a naive "walk up until you find something" resolver gets
        // wrong: the nearest entry is a grant, and the correct answer is still deny.
        let (chain, file, folder, library, workspace) = chain();
        let user = UserId::new_v7();
        let me = Principal::new(PrincipalKind::User, user.as_uuid());

        for ancestor in [folder, library, workspace] {
            let entries = [entry(file, me, Effect::Allow), entry(ancestor, me, Effect::Deny)];
            assert_eq!(
                decide(&entries, &user_set(user), &chain),
                Effective::Denied,
                "an ALLOW on the file beat a DENY on {}",
                ancestor.kind
            );
        }
    }

    #[test]
    fn a_deny_on_the_child_beats_an_allow_on_a_parent() {
        // The mirror image, so the rule is not accidentally "whichever is higher wins".
        let (chain, file, _, library, _) = chain();
        let user = UserId::new_v7();
        let me = Principal::new(PrincipalKind::User, user.as_uuid());
        let entries = [entry(library, me, Effect::Allow), entry(file, me, Effect::Deny)];
        assert_eq!(decide(&entries, &user_set(user), &chain), Effective::Denied);
    }

    #[test]
    fn a_deny_via_one_group_beats_an_allow_via_another() {
        // The arrangement that real tenants produce: "all-staff" grants, "contractors" denies, and
        // one person is in both.
        let (chain, file, ..) = chain();
        let user = UserId::new_v7();
        let allowing = GroupId::new_v7();
        let denying = GroupId::new_v7();
        let principals = user_set(user).with_groups([allowing, denying]);

        let entries = [
            entry(file, Principal::new(PrincipalKind::Group, allowing.as_uuid()), Effect::Allow),
            entry(file, Principal::new(PrincipalKind::Group, denying.as_uuid()), Effect::Deny),
        ];
        assert_eq!(decide(&entries, &principals, &chain), Effective::Denied);

        // And the same two entries in the other order, because a fold that returns early would pass
        // one arrangement and fail the other.
        let reversed = [entries[1], entries[0]];
        assert_eq!(decide(&reversed, &principals, &chain), Effective::Denied);
    }

    #[test]
    fn a_group_deny_beats_a_direct_user_allow() {
        let (chain, file, _, library, _) = chain();
        let user = UserId::new_v7();
        let group = GroupId::new_v7();
        let principals = user_set(user).with_groups([group]);
        let entries = [
            entry(file, Principal::new(PrincipalKind::User, user.as_uuid()), Effect::Allow),
            entry(library, Principal::new(PrincipalKind::Group, group.as_uuid()), Effect::Deny),
        ];
        assert_eq!(decide(&entries, &principals, &chain), Effective::Denied);
    }

    #[test]
    fn an_expired_deny_does_not_deny() {
        // Rule 4. The failure this guards is the opposite of the usual one: an expiry that is not
        // honoured leaves a person locked out of their own content long after the reason ended.
        let (chain, file, _, library, _) = chain();
        let user = UserId::new_v7();
        let me = Principal::new(PrincipalKind::User, user.as_uuid());

        let expired = AclEntry {
            resource: library,
            principal: me,
            effect: Effect::Deny,
            expires_at: Some(now() - chrono::Duration::seconds(1)),
        };
        let entries = [entry(file, me, Effect::Allow), expired];
        assert_eq!(decide(&entries, &user_set(user), &chain), Effective::Allowed);

        // One second the other way, and it denies again — otherwise this test would pass against a
        // resolver that ignored `expires_at` entirely.
        let live = AclEntry { expires_at: Some(now() + chrono::Duration::seconds(1)), ..expired };
        assert_eq!(decide(&[entries[0], live], &user_set(user), &chain), Effective::Denied);
    }

    #[test]
    fn an_expired_allow_does_not_grant() {
        let (chain, file, ..) = chain();
        let user = UserId::new_v7();
        let expired = AclEntry {
            resource: file,
            principal: Principal::new(PrincipalKind::User, user.as_uuid()),
            effect: Effect::Allow,
            expires_at: Some(now() - chrono::Duration::hours(1)),
        };
        assert_eq!(decide(&[expired], &user_set(user), &chain), Effective::NotGranted);
    }

    #[test]
    fn an_entry_expiring_exactly_now_is_expired() {
        // The boundary has to agree with the `expires_at > now()` predicate in the query, or a row
        // is fetched and then ignored — or, if they disagreed the other way, applied after it had
        // been fetched by a query that thought it was live.
        let (chain, file, ..) = chain();
        let user = UserId::new_v7();
        let boundary = AclEntry {
            resource: file,
            principal: Principal::new(PrincipalKind::User, user.as_uuid()),
            effect: Effect::Deny,
            expires_at: Some(now()),
        };
        assert!(!boundary.is_live_at(now()));
        assert_eq!(decide(&[boundary], &user_set(user), &chain), Effective::NotGranted);
    }

    #[test]
    fn everyone_matches_every_supported_principal() {
        let (chain, _, _, library, _) = chain();
        let entries = [entry(library, Principal::everyone(), Effect::Allow)];
        for actor in [
            Actor::User(UserId::new_v7()),
            Actor::Guest(GuestId::new_v7()),
            Actor::ServiceAccount(ServiceAccountId::new_v7()),
        ] {
            let principals = PrincipalSet::for_actor(&actor).expect("an acl principal");
            assert_eq!(
                decide(&entries, &principals, &chain),
                Effective::Allowed,
                "EVERYONE did not match {actor:?}"
            );
        }
    }

    #[test]
    fn a_deny_to_everyone_beats_a_direct_allow() {
        let (chain, file, _, library, _) = chain();
        let user = UserId::new_v7();
        let entries = [
            entry(file, Principal::new(PrincipalKind::User, user.as_uuid()), Effect::Allow),
            entry(library, Principal::everyone(), Effect::Deny),
        ];
        assert_eq!(decide(&entries, &user_set(user), &chain), Effective::Denied);
    }

    #[test]
    fn actors_with_no_acl_principal_are_refused_before_anything_is_queried() {
        // If either of these ever produced a `PrincipalSet`, `EVERYONE` would grant every MCP
        // client and every background job whatever the tenant grants tenant-wide.
        assert!(PrincipalSet::for_actor(&Actor::McpClient(McpClientId::new_v7())).is_none());
        assert!(PrincipalSet::for_actor(&Actor::System).is_none());
    }

    #[test]
    fn a_principal_of_another_kind_with_the_same_id_does_not_match() {
        let (chain, file, ..) = chain();
        let id = Uuid::new_v4();
        let principals =
            PrincipalSet::for_actor(&Actor::User(UserId::from_uuid(id))).expect("acl principal");
        let entries = [entry(file, Principal::new(PrincipalKind::Guest, id), Effect::Allow)];
        assert_eq!(decide(&entries, &principals, &chain), Effective::NotGranted);
    }

    #[test]
    fn a_group_the_caller_is_not_in_does_not_match() {
        let (chain, file, ..) = chain();
        let user = UserId::new_v7();
        let principals = user_set(user).with_groups([GroupId::new_v7()]);
        let entries = [entry(
            file,
            Principal::new(PrincipalKind::Group, GroupId::new_v7().as_uuid()),
            Effect::Allow,
        )];
        assert_eq!(decide(&entries, &principals, &chain), Effective::NotGranted);
    }

    #[test]
    fn an_entry_outside_the_chain_is_ignored() {
        // A resource whose inheritance was broken above it: the entries on the severed ancestors are
        // fetched (they are in some other resource's chain in the same batch) and must not apply.
        let (chain, ..) = chain();
        let user = UserId::new_v7();
        let elsewhere = node(AclResourceType::Folder);
        let entries =
            [entry(elsewhere, Principal::new(PrincipalKind::User, user.as_uuid()), Effect::Deny)];
        assert_eq!(decide(&entries, &user_set(user), &chain), Effective::NotGranted);
    }

    #[test]
    fn an_empty_chain_grants_nothing() {
        // A resource that does not exist, is deleted, or is another tenant's. Same answer to all
        // three (`CLAUDE.md` rule 7).
        let user = UserId::new_v7();
        let entries = [entry(
            node(AclResourceType::File),
            Principal::new(PrincipalKind::User, user.as_uuid()),
            Effect::Allow,
        )];
        let empty = InheritanceChain::default();
        assert!(empty.is_empty());
        assert_eq!(decide(&entries, &user_set(user), &empty), Effective::NotGranted);
    }

    #[test]
    fn an_unfiltered_row_set_reaches_the_same_verdict() {
        // The SQL narrows what is fetched; these rules decide. If the two ever disagreed, a change
        // to a `WHERE` clause would silently become a change to the access model — so this feeds in
        // rows the query would never have returned and asserts they change nothing.
        let (chain, file, _, library, _) = chain();
        let user = UserId::new_v7();
        let me = Principal::new(PrincipalKind::User, user.as_uuid());
        let stranger = Principal::new(PrincipalKind::User, UserId::new_v7().as_uuid());
        let foreign_group = Principal::new(PrincipalKind::Group, GroupId::new_v7().as_uuid());

        let entries = [
            entry(file, me, Effect::Allow),
            entry(file, stranger, Effect::Deny),
            entry(library, foreign_group, Effect::Deny),
            AclEntry {
                resource: library,
                principal: me,
                effect: Effect::Deny,
                expires_at: Some(now() - chrono::Duration::days(30)),
            },
        ];
        assert_eq!(decide(&entries, &user_set(user), &chain), Effective::Allowed);
    }

    #[test]
    fn both_refusals_are_indistinguishable_to_the_caller() {
        for effective in [Effective::Denied, Effective::NotGranted] {
            let decision = effective.into_stage_decision();
            assert!(!decision.is_allowed());
            assert_eq!(
                decision,
                StageDecision::deny(ReasonCode::AccessDenied),
                "{effective:?} is distinguishable from the other refusal"
            );
        }
        assert!(Effective::Allowed.into_stage_decision().is_allowed());
    }

    #[test]
    fn database_spellings_round_trip() {
        // These strings are the `CHECK` constraints of `docs/04-DATA-MODEL.md §9`. A rename on
        // either side silently stops matching rows, which reads as "no permissions" — a failure
        // that looks like a strict policy.
        for kind in [
            AclResourceType::Workspace,
            AclResourceType::Library,
            AclResourceType::Folder,
            AclResourceType::File,
            AclResourceType::Page,
            AclResourceType::List,
            AclResourceType::ListItem,
        ] {
            assert_eq!(AclResourceType::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(AclResourceType::parse("VERSION"), None);

        for kind in [
            PrincipalKind::User,
            PrincipalKind::Group,
            PrincipalKind::Guest,
            PrincipalKind::ServiceAccount,
            PrincipalKind::Everyone,
        ] {
            assert_eq!(PrincipalKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(PrincipalKind::parse("MCP"), None);

        assert_eq!(Effect::parse("ALLOW"), Some(Effect::Allow));
        assert_eq!(Effect::parse("DENY"), Some(Effect::Deny));
        assert_eq!(Effect::parse("allow"), None, "the spelling is exact, not case-insensitive");
    }
}
