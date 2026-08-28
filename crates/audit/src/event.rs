//! The audit record itself: one row of `audit_events` (`docs/04-DATA-MODEL.md §14`).

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use enclave_core::{
    Action, Actor, ActorKind, AdminAction, ClientType, ContainerAction, DeviceId, FileAction,
    McpClientId, Obligations, PolicyDecision, ReasonCode, RequestContext, RequestId, ResourceKind,
    ResourceRef, SessionId, ShareAction, TenantId, UserId, Uuid, WorkspaceId,
};
use serde::{Deserialize, Serialize};

use crate::chain::EventHash;
use crate::error::AuditError;
use crate::redact::Detail;

/// The sequence value of an event that has not been written yet.
///
/// PostgreSQL's sequence starts at 1, so zero is unambiguously "unassigned". It is not
/// `Option<i64>` because the value is part of the canonically hashed bytes and an `Option` there
/// would invite two encodings of the same event.
pub const UNASSIGNED_SEQUENCE: i64 = 0;

/// How much of a `User-Agent` header is kept.
///
/// Bounded because the header is attacker-controlled and lands in a table that is queried by
/// auditors and forwarded to a SIEM; an unbounded string there is an unbounded row and a log-line
/// amplification primitive.
pub const MAX_USER_AGENT_BYTES: usize = 512;

/// What the policy chain decided, as stored in the `outcome` column.
///
/// The three values match the column's `CHECK` constraint verbatim. `Error` exists so that a
/// request that failed *before* a decision was reached still leaves a row — an operation that
/// vanishes from the audit trail because it crashed is indistinguishable from one that was
/// suppressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Outcome {
    /// The chain permitted the action, with or without obligations.
    Allow,
    /// The chain refused it. Denials are audited exactly as allows are (`CLAUDE.md` rule 10).
    Deny,
    /// The attempt failed for a reason that is not a policy decision.
    Error,
}

impl Outcome {
    /// The stable stored form. Changing one of these strings breaks the column's `CHECK`
    /// constraint and every previously computed hash.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Deny => "DENY",
            Self::Error => "ERROR",
        }
    }

    /// Every variant, for exhaustive admin filters and tests.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::Allow, Self::Deny, Self::Error]
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Outcome {
    type Err = AuditError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ALLOW" => Ok(Self::Allow),
            "DENY" => Ok(Self::Deny),
            "ERROR" => Ok(Self::Error),
            _ => Err(AuditError::MalformedRow {
                column: "outcome",
                reason: "not one of ALLOW, DENY, ERROR",
            }),
        }
    }
}

impl Serialize for Outcome {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Outcome {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

/// A pointer to the policy that produced a decision, stored in `policy_refs`.
///
/// Modelled as a struct rather than free JSON for one reason: `policy_refs` is inside the hashed
/// bytes, and free JSON has no canonical ordering. Three named fields have exactly one encoding.
///
/// The point of storing these at all is answering "why was this allowed in March?" after the
/// policy has been edited twice — hence `version`, without which the reference names a document
/// whose content has moved on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRef {
    /// Which policy family, e.g. `dlp`, `conditional_access`, `barrier`, `retention`, `acl`.
    pub kind: String,
    /// The policy's identifier, where it has one. Absent for built-in rules.
    pub id: Option<Uuid>,
    /// The policy version that was evaluated, from `config_versions` (`docs/04 §14`).
    pub version: Option<i32>,
}

impl PolicyRef {
    /// A reference to a specific stored policy.
    #[must_use]
    pub fn new(kind: impl Into<String>, id: Uuid) -> Self {
        Self { kind: kind.into(), id: Some(id), version: None }
    }

    /// A reference pinned to the exact version that was evaluated — the form to prefer.
    #[must_use]
    pub fn versioned(kind: impl Into<String>, id: Uuid, version: i32) -> Self {
        Self { kind: kind.into(), id: Some(id), version: Some(version) }
    }

    /// A reference to a built-in rule that has no stored identity.
    #[must_use]
    pub fn builtin(kind: impl Into<String>) -> Self {
        Self { kind: kind.into(), id: None, version: None }
    }
}

/// One audit row (`docs/04-DATA-MODEL.md §14`).
///
/// # Why the fields are typed rather than `Uuid` everywhere
///
/// The column set is untyped by necessity — `resource_id` holds a file, a share or a group — but
/// the *constructor* is not, so an event is assembled from a [`RequestContext`], an [`Action`] and
/// a [`ResourceRef`] that the compiler has already agreed belong together. That is what makes
/// "audit says a file id but the row holds a version id" unwritable rather than merely unlikely.
///
/// # Hashes are not part of the hashed bytes
///
/// [`Self::previous_hash`] and [`Self::event_hash`] are metadata *about* the record, not content
/// *of* it. The canonical encoding (`crate::canonical`) deliberately excludes them: including
/// `event_hash` would be circular, and including `previous_hash` would double-count it, since the
/// chain already prefixes it before hashing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Application-generated UUIDv7 primary key. Client-visible in the error envelope, so a user
    /// report resolves to one row.
    pub id: Uuid,
    /// The tenant this happened inside. The chain is per tenant, so this is also the chain key.
    pub tenant_id: TenantId,
    /// Position in the tenant's chain, assigned by the database sequence at write time.
    /// [`UNASSIGNED_SEQUENCE`] until then.
    pub sequence: i64,
    /// When the action happened, truncated to microseconds — see
    /// [`AuditEventBuilder::occurred_at`].
    pub occurred_at: DateTime<Utc>,
    /// Who acted. Split into `actor_id` and `actor_type` on the way to the database.
    pub actor: Actor,
    /// The user an administrator or service was acting for, on delegated paths.
    pub on_behalf_of: Option<UserId>,
    /// What was attempted, stored as `family.verb`.
    pub action: Action,
    /// What it was attempted against. `None` only for actions with no single subject.
    pub resource: Option<ResourceRef>,
    /// The containing workspace, denormalized so that "everything that happened in this workspace"
    /// does not require joining to a resource that may since have been deleted.
    pub workspace_id: Option<WorkspaceId>,
    /// The decision.
    pub outcome: Outcome,
    /// Why, for denials. The same closed vocabulary the API returns (`docs/05-API.md §5`), so an
    /// auditor and the user who was refused are reading the same word.
    pub reason_code: Option<ReasonCode>,
    /// Which policies produced the decision.
    pub policy_refs: Vec<PolicyRef>,
    /// Correlation id shared with logs, traces and the error envelope.
    pub request_id: RequestId,
    /// The refresh-token family, for reconstructing a session's activity.
    pub session_id: Option<SessionId>,
    /// Which client the request arrived through — the difference between a sync agent and a
    /// browser is a security-relevant one (`CLAUDE.md` rule 6).
    pub client_type: Option<ClientType>,
    /// The MCP client, when one mediated the request.
    pub mcp_client_id: Option<McpClientId>,
    /// The registered device, where one was bound.
    pub device_id: Option<DeviceId>,
    /// Source address, as resolved by the edge — never as claimed by a header alone.
    pub ip: Option<IpAddr>,
    /// ISO 3166-1 alpha-2 country, where geolocation was available.
    pub country: Option<String>,
    /// Truncated `User-Agent`.
    pub user_agent: Option<String>,
    /// Structured extras. [`Detail`] is the only accepted type, which is what keeps credentials
    /// out of this column structurally rather than by convention.
    pub detail: Detail,
    /// The previous event's hash in this tenant's chain. `None` for the first event, and for every
    /// event when tamper evidence is disabled (`docs/08 §14`).
    pub previous_hash: Option<EventHash>,
    /// This event's hash. `None` until the event is sealed, and permanently `None` when tamper
    /// evidence is disabled.
    pub event_hash: Option<EventHash>,
}

impl AuditEvent {
    /// Starts an event from the request context that produced it.
    ///
    /// Taking the context rather than loose fields is the point: the actor, tenant, session,
    /// client, device, address and country are copied from one verified source, so an audit row
    /// cannot disagree with the request it describes.
    #[must_use]
    pub fn builder(ctx: &RequestContext, action: Action, outcome: Outcome) -> AuditEventBuilder {
        AuditEventBuilder {
            event: Self {
                id: Uuid::now_v7(),
                tenant_id: ctx.tenant_id,
                sequence: UNASSIGNED_SEQUENCE,
                occurred_at: truncate_to_micros(Utc::now()),
                actor: ctx.actor,
                on_behalf_of: None,
                action,
                resource: None,
                workspace_id: None,
                outcome,
                reason_code: None,
                policy_refs: Vec::new(),
                request_id: ctx.request_id,
                session_id: ctx.session_id,
                client_type: Some(ctx.client),
                mcp_client_id: match ctx.actor {
                    Actor::McpClient(id) => Some(id),
                    _ => None,
                },
                device_id: ctx.device.device_id,
                ip: Some(ctx.network.source_ip),
                country: ctx.network.country.clone(),
                user_agent: None,
                detail: Detail::empty(),
                previous_hash: None,
                event_hash: None,
            },
        }
    }

    /// An allow record for a completed policy decision, including its obligations.
    ///
    /// The obligations are recorded because they are the difference between "this download was
    /// allowed" and "this download was allowed only watermarked" — and an auditor who cannot see
    /// that difference cannot tell whether the control was applied.
    #[must_use]
    pub fn allowed(
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
        decision: &PolicyDecision,
    ) -> Self {
        Self::builder(ctx, action, Outcome::Allow)
            .resource(resource)
            .obligations(decision.obligations())
            .build()
    }

    /// A deny record. Denials are audited on exactly the same path as allows.
    #[must_use]
    pub fn denied(
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
        code: ReasonCode,
    ) -> Self {
        Self::builder(ctx, action, Outcome::Deny).resource(resource).reason(code).build()
    }

    /// The actor as it is stored: kind string plus optional subject id.
    #[must_use]
    pub const fn actor_parts(&self) -> (ActorKind, Option<Uuid>) {
        (self.actor.kind(), self.actor.subject_id())
    }

    /// The `resource_type` column value.
    #[must_use]
    pub fn resource_kind(&self) -> Option<ResourceKind> {
        self.resource.as_ref().map(|r| r.kind)
    }

    /// The `resource_id` column value.
    #[must_use]
    pub fn resource_id(&self) -> Option<Uuid> {
        self.resource.as_ref().map(|r| r.id)
    }

    /// Whether this event carries chain hashes at all.
    ///
    /// `false` means tamper evidence was off when it was written — which verification must report
    /// as "not chained" rather than as "valid" (`plans/M0-FOUNDATIONS.md` ENC-107).
    #[must_use]
    pub const fn is_chained(&self) -> bool {
        self.event_hash.is_some()
    }
}

/// Truncates a timestamp to microsecond precision.
///
/// `TIMESTAMPTZ` stores microseconds. If an event were hashed at nanosecond precision, the value
/// read back from the database would differ from the value that was hashed and every chain would
/// verify as tampered — a bug that only appears once real rows exist. Truncating at construction
/// makes the in-memory value the same one the column will hold.
#[must_use]
pub fn truncate_to_micros(value: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp_micros(value.timestamp_micros()).unwrap_or(value)
}

/// Assembles an [`AuditEvent`].
///
/// A builder rather than a 23-argument constructor, and rather than public field mutation, because
/// the required fields come from the context and the optional ones do not — and an event with an
/// unset `tenant_id` should not be representable at any point.
#[derive(Debug, Clone)]
pub struct AuditEventBuilder {
    event: AuditEvent,
}

impl AuditEventBuilder {
    /// Records what the action targeted, and the workspace it sits in when the reference names one.
    #[must_use]
    pub fn resource(mut self, resource: &ResourceRef) -> Self {
        if resource.kind == ResourceKind::Workspace {
            self.event.workspace_id = Some(WorkspaceId::from_uuid(resource.id));
        }
        self.event.resource = Some(*resource);
        self
    }

    /// Records the containing workspace explicitly, for resources that do not carry it.
    #[must_use]
    pub fn workspace(mut self, id: WorkspaceId) -> Self {
        self.event.workspace_id = Some(id);
        self
    }

    /// Records the denial reason. Only meaningful for [`Outcome::Deny`].
    #[must_use]
    pub fn reason(mut self, code: ReasonCode) -> Self {
        self.event.reason_code = Some(code);
        self
    }

    /// Adds one policy reference.
    #[must_use]
    pub fn policy_ref(mut self, reference: PolicyRef) -> Self {
        self.event.policy_refs.push(reference);
        self
    }

    /// Adds several policy references.
    #[must_use]
    pub fn policy_refs(mut self, refs: impl IntoIterator<Item = PolicyRef>) -> Self {
        self.event.policy_refs.extend(refs);
        self
    }

    /// Records the obligations a decision carried, as a sorted string array in `detail`.
    ///
    /// Sorted so that two decisions with the same obligations produce the same bytes; obligation
    /// accumulation order is an implementation detail of the chain and must not leak into a hash.
    #[must_use]
    pub fn obligations(mut self, obligations: &Obligations) -> Self {
        if obligations.is_empty() {
            return self;
        }
        let mut names: Vec<String> = obligations
            .iter()
            .map(|o| serde_json::to_string(o).unwrap_or_else(|_| "unserializable".to_owned()))
            .collect();
        names.sort_unstable();
        // The key is a fixed literal with no credential marker, so this cannot fail; log rather
        // than panic if that ever stops being true, because losing one detail field is a far
        // better outcome than losing the audit row.
        if let Err(error) = self.event.detail.try_insert("obligations", names) {
            tracing::error!(%error, "obligations could not be attached to an audit event");
        }
        self
    }

    /// Attaches a checked detail payload, replacing any already set.
    #[must_use]
    pub fn detail(mut self, detail: Detail) -> Self {
        self.event.detail = detail;
        self
    }

    /// Records the delegating user on an on-behalf-of path.
    #[must_use]
    pub fn on_behalf_of(mut self, user: UserId) -> Self {
        self.event.on_behalf_of = Some(user);
        self
    }

    /// Records the client's `User-Agent`, truncated to [`MAX_USER_AGENT_BYTES`] on a character
    /// boundary.
    #[must_use]
    pub fn user_agent(mut self, value: &str) -> Self {
        self.event.user_agent = Some(truncate_utf8(value, MAX_USER_AGENT_BYTES).to_owned());
        self
    }

    /// Overrides the timestamp — for backdated imports and for tests that need determinism.
    /// Truncated to microseconds for the reason given on [`truncate_to_micros`].
    #[must_use]
    pub fn occurred_at(mut self, at: DateTime<Utc>) -> Self {
        self.event.occurred_at = truncate_to_micros(at);
        self
    }

    /// Overrides the event id. Only for reconstructing a known row; ordinary callers take the
    /// generated UUIDv7.
    #[must_use]
    pub fn id(mut self, id: Uuid) -> Self {
        self.event.id = id;
        self
    }

    /// Finishes the event. It is not yet sealed and has no sequence — the sink assigns both.
    #[must_use]
    pub fn build(self) -> AuditEvent {
        self.event
    }
}

/// Truncates a string to at most `max` bytes without splitting a character.
fn truncate_utf8(value: &str, max: usize) -> &str {
    if value.len() <= max {
        return value;
    }
    let mut end = max;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

/// Parses the stored `family.verb` form back into an [`Action`].
///
/// Needed on the verification path: recomputing a hash requires reconstructing the exact event,
/// and `Action`'s serde form is the JSON `{"resource":…,"action":…}` shape, not the string the
/// column holds.
///
/// # Errors
///
/// [`AuditError::MalformedRow`] if the string is not a known family and verb.
pub fn parse_action(value: &str) -> Result<Action, AuditError> {
    let malformed =
        || AuditError::MalformedRow { column: "action", reason: "not a known family.verb" };
    let (family, verb) = value.split_once('.').ok_or_else(malformed)?;
    let action = match family {
        "file" => Action::File(FileAction::from_str(verb).map_err(|_| malformed())?),
        "container" => Action::Container(ContainerAction::from_str(verb).map_err(|_| malformed())?),
        "share" => Action::Share(ShareAction::from_str(verb).map_err(|_| malformed())?),
        "admin" => Action::Admin(AdminAction::from_str(verb).map_err(|_| malformed())?),
        _ => return Err(malformed()),
    };
    Ok(action)
}

/// Rebuilds an [`Actor`] from the two columns that store it.
///
/// # Errors
///
/// [`AuditError::MalformedRow`] when the kind is unknown, or when a kind that requires a subject
/// id has none. A `NULL` `actor_id` on a `user` row is corruption, not a system actor, and
/// quietly turning it into [`Actor::System`] would attribute a user's action to the platform.
pub fn actor_from_parts(actor_type: &str, actor_id: Option<Uuid>) -> Result<Actor, AuditError> {
    let kind = ActorKind::from_str(actor_type)
        .map_err(|_| AuditError::MalformedRow { column: "actor_type", reason: "unknown kind" })?;
    let missing = || AuditError::MalformedRow {
        column: "actor_id",
        reason: "null for a kind that needs one",
    };
    let actor = match kind {
        ActorKind::User => Actor::User(actor_id.ok_or_else(missing)?.into()),
        ActorKind::Guest => Actor::Guest(actor_id.ok_or_else(missing)?.into()),
        ActorKind::ServiceAccount => Actor::ServiceAccount(actor_id.ok_or_else(missing)?.into()),
        ActorKind::McpClient => Actor::McpClient(actor_id.ok_or_else(missing)?.into()),
        // `ENC-879`. A share-link row needs its id as much as a user row does, and for the same
        // reason: `actor_id` is `share_links.id`, so *which link* was redeemed is the question an
        // investigation asks first, and a row that lost it names an event nobody can attribute.
        ActorKind::ShareLink => Actor::LinkBearer(actor_id.ok_or_else(missing)?.into()),
        ActorKind::System => Actor::System,
    };
    Ok(actor)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use enclave_core::{FileId, Obligation};

    use crate::test_support::context;

    #[test]
    fn outcome_strings_match_the_check_constraint() {
        assert_eq!(Outcome::Allow.as_str(), "ALLOW");
        assert_eq!(Outcome::Deny.as_str(), "DENY");
        assert_eq!(Outcome::Error.as_str(), "ERROR");
        for outcome in Outcome::all() {
            assert_eq!(outcome.as_str().parse::<Outcome>().unwrap(), *outcome);
        }
        assert!("allow".parse::<Outcome>().is_err(), "the stored form is uppercase only");
    }

    #[test]
    fn builder_copies_identity_from_the_context() {
        let ctx = context();
        let resource = ResourceRef::file(ctx.tenant_id, FileId::new_v7());
        let event = AuditEvent::denied(
            &ctx,
            Action::File(FileAction::Download),
            &resource,
            ReasonCode::DownloadBlockedByPolicy,
        );

        assert_eq!(event.tenant_id, ctx.tenant_id);
        assert_eq!(event.request_id, ctx.request_id);
        assert_eq!(event.actor, ctx.actor);
        assert_eq!(event.client_type, Some(ctx.client));
        assert_eq!(event.ip, Some(ctx.network.source_ip));
        assert_eq!(event.outcome, Outcome::Deny);
        assert_eq!(event.reason_code, Some(ReasonCode::DownloadBlockedByPolicy));
        assert_eq!(event.resource_id(), Some(resource.id));
        assert_eq!(event.sequence, UNASSIGNED_SEQUENCE);
        assert!(!event.is_chained());
    }

    #[test]
    fn obligations_are_recorded_sorted() {
        let ctx = context();
        let resource = ResourceRef::file(ctx.tenant_id, FileId::new_v7());
        let decision = PolicyDecision::allow(
            [Obligation::Watermark, Obligation::NoDownload].into_iter().collect(),
        );
        let a = AuditEvent::allowed(&ctx, Action::File(FileAction::Preview), &resource, &decision);

        let reversed = PolicyDecision::allow(
            [Obligation::NoDownload, Obligation::Watermark].into_iter().collect(),
        );
        let b = AuditEvent::allowed(&ctx, Action::File(FileAction::Preview), &resource, &reversed);

        assert_eq!(a.detail.get("obligations"), b.detail.get("obligations"));
        assert!(a.detail.get("obligations").is_some());
    }

    #[test]
    fn action_round_trips_through_its_stored_form() {
        for action in [
            Action::File(FileAction::Download),
            Action::Container(ContainerAction::ManageMembers),
            Action::Share(ShareAction::CreateExternal),
            Action::Admin(AdminAction::ReadAudit),
        ] {
            assert_eq!(parse_action(&action.to_string()).unwrap(), action);
        }
        assert!(parse_action("file").is_err());
        assert!(parse_action("file.teleport").is_err());
        assert!(parse_action("galaxy.read").is_err());
    }

    #[test]
    fn actor_round_trips_through_its_two_columns() {
        for actor in [
            Actor::User(enclave_core::UserId::new_v7()),
            Actor::Guest(enclave_core::GuestId::new_v7()),
            Actor::McpClient(McpClientId::new_v7()),
            Actor::System,
        ] {
            let (kind, id) = (actor.kind(), actor.subject_id());
            assert_eq!(actor_from_parts(kind.as_str(), id).unwrap(), actor);
        }
        assert!(actor_from_parts("user", None).is_err(), "a user row with no id is corruption");
        assert!(actor_from_parts("wizard", None).is_err());
    }

    #[test]
    fn user_agent_is_truncated_on_a_character_boundary() {
        let ctx = context();
        let long = "é".repeat(MAX_USER_AGENT_BYTES);
        let event = AuditEvent::builder(&ctx, Action::File(FileAction::Preview), Outcome::Allow)
            .user_agent(&long)
            .build();
        let stored = event.user_agent.expect("set");
        assert!(stored.len() <= MAX_USER_AGENT_BYTES);
        assert!(long.starts_with(&stored));
    }

    #[test]
    fn timestamps_are_truncated_to_microseconds() {
        let ctx = context();
        let event = AuditEvent::builder(&ctx, Action::File(FileAction::Preview), Outcome::Allow)
            .occurred_at(DateTime::from_timestamp_nanos(1_700_000_000_123_456_789))
            .build();
        assert_eq!(event.occurred_at.timestamp_subsec_nanos() % 1_000, 0);
    }
}
