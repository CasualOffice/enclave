//! Who is making a request, and through what kind of client.
//!
//! [`Actor`] and [`ClientType`] are separate axes on purpose. *Who* decides what the ACL says;
//! *how* decides what conditional access says. The same user is allowed to preview a file from a
//! browser and forbidden to replicate it to a sync agent, and collapsing the two axes into one
//! "principal" makes that policy inexpressible.

use crate::id::{GuestId, McpClientId, ServiceAccountId, UserId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

wire_enum! {
    /// The kind of principal, without its identifier.
    ///
    /// Exists separately from [`Actor`] because audit rows, policy rules and admin filters
    /// frequently need the *kind* alone — "deny external sharing to guests", "show me every action
    /// by an MCP client" — and forcing those to carry an identifier they do not use would mean
    /// inventing a placeholder one.
    ///
    /// The strings match the `typ` access-token claim (`docs/03-LLD.md §5.2`).
    pub enum ActorKind {
        /// A member of the tenant's directory.
        User => "user",
        /// An external participant with access to specific resources only.
        Guest => "guest",
        /// A machine caller using client credentials.
        ServiceAccount => "service",
        /// An MCP client, which additionally carries a classification ceiling.
        McpClient => "mcp",
        /// Enclave itself, acting with no human principal behind the request.
        System => "system",
    }
}

wire_enum! {
    /// The kind of client software a request arrived through (`docs/03-LLD.md §3`).
    ///
    /// This is an *assertion* from the token's `cli` claim, not proof — it narrows what a caller
    /// may attempt and is an input to conditional access, never a grant on its own.
    ///
    /// The canonical strings are lowercase to match the `cli` claim; the `devices` table spells its
    /// three-value subset uppercase, and parsing accepts either.
    pub enum ClientType {
        /// The browser SPA.
        Web => "web",
        /// The native desktop application.
        Desktop => "desktop",
        /// The native mobile application.
        Mobile => "mobile",
        /// The file synchronization agent. Distinct from `Desktop` because replication is a
        /// distinct permission from reading (`CLAUDE.md` non-negotiable rule 6).
        Sync => "sync",
        /// An external document editor integration acting on the user's behalf.
        Editor => "editor",
        /// A direct API caller: script, integration, service account.
        Api => "api",
        /// An MCP client mediating access for an AI assistant.
        Mcp => "mcp",
        /// Internal traffic from a worker or the scheduler.
        System => "system",
    }
}

/// The principal a request is attributed to (`docs/03-LLD.md §4`).
///
/// Modelled as an enum rather than a `user_id` plus flags so that every consumer is forced by the
/// compiler to decide what a guest, a service account and an MCP client mean for it. The commonest
/// real-world variant of this bug — treating a guest as a user because both had a `UserId` — is
/// not writable here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum Actor {
    /// A directory member.
    User(UserId),
    /// An external participant.
    Guest(GuestId),
    /// A machine caller.
    ServiceAccount(ServiceAccountId),
    /// An MCP client.
    McpClient(McpClientId),
    /// Enclave itself: schedulers, retention sweeps, outbox publishing. It is a first-class actor
    /// rather than an absent one because these actions are audited like any other, and an audit
    /// row with no actor is an audit row nobody can interpret.
    System,
}

impl Actor {
    /// The principal's identifier as a raw UUID, for audit and for the persistence layer.
    ///
    /// `None` for [`Actor::System`], which has no identity to record — represented honestly rather
    /// than as a nil-UUID sentinel, because a sentinel is indistinguishable from a bug that failed
    /// to populate the column, and audit is the one place where that ambiguity is unaffordable.
    /// Pair it with [`Actor::kind`], which is always present.
    #[must_use]
    pub const fn subject_id(&self) -> Option<Uuid> {
        match self {
            Self::User(id) => Some(id.as_uuid()),
            Self::Guest(id) => Some(id.as_uuid()),
            Self::ServiceAccount(id) => Some(id.as_uuid()),
            Self::McpClient(id) => Some(id.as_uuid()),
            Self::System => None,
        }
    }

    /// The principal's kind, discarding its identifier.
    #[must_use]
    pub const fn kind(&self) -> ActorKind {
        match self {
            Self::User(_) => ActorKind::User,
            Self::Guest(_) => ActorKind::Guest,
            Self::ServiceAccount(_) => ActorKind::ServiceAccount,
            Self::McpClient(_) => ActorKind::McpClient,
            Self::System => ActorKind::System,
        }
    }

    /// Whether this principal is external to the tenant.
    ///
    /// Named as a question about the principal rather than a comparison against a variant, so that
    /// adding a future external principal kind updates every caller by updating this one `match`.
    #[must_use]
    pub const fn is_external(&self) -> bool {
        matches!(self, Self::Guest(_))
    }

    /// Whether this principal is a human being.
    ///
    /// Several controls only make sense against a person — step-up MFA, justification prompts,
    /// notification of a revoked session. Asking here keeps those controls from silently becoming
    /// no-ops when a service account arrives.
    #[must_use]
    pub const fn is_human(&self) -> bool {
        matches!(self, Self::User(_) | Self::Guest(_))
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal, not a
    // production hazard. The workspace warns on these constructs for non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn system_has_a_kind_but_no_subject() {
        assert_eq!(Actor::System.kind(), ActorKind::System);
        assert_eq!(Actor::System.subject_id(), None);
    }

    #[test]
    fn subject_id_is_the_wrapped_uuid() {
        let user = UserId::new_v7();
        assert_eq!(Actor::User(user).subject_id(), Some(user.as_uuid()));
        let guest = GuestId::new_v7();
        assert_eq!(Actor::Guest(guest).subject_id(), Some(guest.as_uuid()));
    }

    #[test]
    fn only_guests_are_external_and_only_people_are_human() {
        assert!(Actor::Guest(GuestId::new_v7()).is_external());
        assert!(!Actor::User(UserId::new_v7()).is_external());
        assert!(!Actor::ServiceAccount(ServiceAccountId::new_v7()).is_human());
        assert!(!Actor::System.is_human());
    }

    #[test]
    fn actor_serializes_adjacently_tagged() {
        let id = UserId::new_v7();
        let json = serde_json::to_string(&Actor::User(id)).expect("serialize");
        assert_eq!(json, format!(r#"{{"kind":"user","id":"{id}"}}"#));
        let back: Actor = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, Actor::User(id));

        // The unit variant must survive the same treatment.
        let json = serde_json::to_string(&Actor::System).expect("serialize");
        assert_eq!(json, r#"{"kind":"system"}"#);
        assert_eq!(serde_json::from_str::<Actor>(&json).expect("deserialize"), Actor::System);
    }

    #[test]
    fn client_types_round_trip_and_accept_the_database_spelling() {
        for client in ClientType::all() {
            assert_eq!(client.as_str().parse::<ClientType>(), Ok(*client));
        }
        assert_eq!("WEB".parse::<ClientType>(), Ok(ClientType::Web));
        assert!("browser".parse::<ClientType>().is_err());
    }
}
