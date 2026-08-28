//! Who is making a request, and through what kind of client.
//!
//! [`Actor`] and [`ClientType`] are separate axes on purpose. *Who* decides what the ACL says;
//! *how* decides what conditional access says. The same user is allowed to preview a file from a
//! browser and forbidden to replicate it to a sync agent, and collapsing the two axes into one
//! "principal" makes that policy inexpressible.

use crate::id::{GuestId, McpClientId, ServiceAccountId, ShareLinkId, UserId};
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
    /// The strings match the `typ` access-token claim (`docs/03-LLD.md §5.2`) — with one
    /// deliberate exception. [`ActorKind::ShareLink`] is a kind the audit trail and `acl_entries`
    /// can name and that **no token may ever carry**: `enclave_auth::AccessTokenIssuer::issue`
    /// refuses to mint one and `AccessTokenVerifier::check_claims` refuses to accept one, so a
    /// `typ` of `share_link` is a rejected token rather than a principal. See
    /// [`Actor::LinkBearer`] for the argument.
    pub enum ActorKind {
        /// A member of the tenant's directory.
        User => "user",
        /// An external participant with access to specific resources only.
        Guest => "guest",
        /// A machine caller using client credentials.
        ServiceAccount => "service",
        /// An MCP client, which additionally carries a classification ceiling.
        McpClient => "mcp",
        /// Whoever presented a share link. Named by the link, because the link is all there is.
        ///
        /// Spelled out rather than abbreviated like its neighbours because, unlike them, this
        /// string is **not** a `typ` claim: no token is ever issued with it
        /// ([`crate::Actor::LinkBearer`] explains why), so its only readers are the audit trail and
        /// `acl_entries.principal_type`, where an investigator reading `share_link` should not have
        /// to look up what it means.
        ShareLink => "share_link",
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
    /// Whoever presented a share link, named by the link they presented (`ENC-879`).
    ///
    /// # Why the chain needed a variant rather than a borrowed one
    ///
    /// A redemption is the one entry point in this product that arrives with a **credential and no
    /// principal**. There is nobody to name: the token proves possession of a link and nothing
    /// about who is holding it. Every other option puts a lie somewhere:
    ///
    /// * fabricating a [`GuestId`] writes a principal into `audit_events.actor_id` that names no
    ///   guest anybody provisioned, so the one table an investigation depends on records an actor
    ///   that does not exist;
    /// * reusing the link creator's [`UserId`] attributes the redeemer's downloads to the person
    ///   who shared the file;
    /// * running the redemption as [`Actor::System`] bypasses the ACL entirely, because
    ///   `PrincipalSet::for_actor` refuses `System` and the handler would have to decide by itself.
    ///
    /// So the honest principal is the link. `ShareLinkId` is `share_links.id`, never the token —
    /// the token exists once, in the response that minted it, and putting it here would put a live
    /// credential in every audit row (`CLAUDE.md` rule 10).
    ///
    /// # This is not a token subject
    ///
    /// No access token is ever issued with `typ: "share_link"`, and one that claims to be is
    /// refused twice: `enclave_auth::AccessTokenIssuer::issue` will not mint it, and
    /// `AccessTokenVerifier::check_claims` will not accept it even when correctly signed. The
    /// refusal is at the door and not in the claim projection, so it is testable by name and so
    /// that `AccessTokenClaims::actor` stays an honest reading of what a token says.
    ///
    /// A link bearer is established **only** by redeeming a token on the redemption path, inside
    /// the transaction that spends the link's budget. If a token could mint this actor, then every
    /// conditional-access and MFA requirement the link states would be escapable by asking for a
    /// token instead of redeeming the link.
    LinkBearer(ShareLinkId),
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
            // The link's own id, which is the whole point of the variant: the audit row names the
            // credential that was presented, and `share_links.id` is a real row an investigator can
            // join against. It is not the token — see [`Actor::LinkBearer`].
            Self::LinkBearer(id) => Some(id.as_uuid()),
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
            Self::LinkBearer(_) => ActorKind::ShareLink,
            Self::System => ActorKind::System,
        }
    }

    /// Whether this principal is external to the tenant.
    ///
    /// Named as a question about the principal rather than a comparison against a variant, so that
    /// adding a future external principal kind updates every caller by updating this one `match`.
    ///
    /// [`Actor::LinkBearer`] is external, and that answer is the reason this method was written as
    /// a question rather than as `== Actor::Guest(_)` at each call site. A share link is very often
    /// the *only* credential protecting a document that has left the organisation
    /// (`crates/sharing/src/lib.rs`), and `docs/06 §12.1` fails closed on external sharing at any
    /// classification. A link bearer answering `false` here would have quietly exempted every
    /// redemption from that escalation.
    #[must_use]
    pub const fn is_external(&self) -> bool {
        matches!(self, Self::Guest(_) | Self::LinkBearer(_))
    }

    /// Whether this principal is a human being.
    ///
    /// Several controls only make sense against a person — step-up MFA, justification prompts,
    /// notification of a revoked session. Asking here keeps those controls from silently becoming
    /// no-ops when a service account arrives.
    ///
    /// [`Actor::LinkBearer`] answers `true`, and it is the one variant where the answer is a
    /// judgement rather than a fact: nobody knows who is holding a link. The two answers are not
    /// symmetric. Every control gated on this is a *demand for evidence from a person* — step up,
    /// justify, acknowledge — so `true` makes a redemption that cannot produce it fail, while
    /// `false` makes those controls silently not apply to the one caller in the product whose
    /// identity is unknown. That is precisely the no-op this method exists to prevent, so the
    /// unknown is resolved towards the demand.
    #[must_use]
    pub const fn is_human(&self) -> bool {
        matches!(self, Self::User(_) | Self::Guest(_) | Self::LinkBearer(_))
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

    /// `ENC-879`. The two judgements the link-bearer variant had to make, asserted rather than left
    /// to a doc comment — both are `matches!` rather than exhaustive matches, so the compiler will
    /// not ask again if either is ever narrowed.
    #[test]
    fn a_link_bearer_is_external_and_is_treated_as_a_person() {
        let bearer = Actor::LinkBearer(ShareLinkId::new_v7());

        // External: a share link is very often the only credential protecting a document that has
        // left the organisation, and `docs/06 §12.1` fails closed on external sharing at any
        // classification. `false` here would exempt every redemption from that escalation.
        assert!(bearer.is_external());

        // Human: nobody knows who holds a link, and the two answers are not symmetric. Every
        // control gated on this demands evidence *from a person*, so `true` makes a redemption that
        // cannot produce it fail, and `false` makes those controls silently not apply to the one
        // caller whose identity is unknown.
        assert!(bearer.is_human());

        // And the id is the link's own, so the audit row can name which link was used.
        let id = ShareLinkId::new_v7();
        assert_eq!(Actor::LinkBearer(id).subject_id(), Some(id.as_uuid()));
        assert_eq!(Actor::LinkBearer(id).kind(), ActorKind::ShareLink);
    }

    /// The wire spelling is stable: it is written into `audit_events.actor_type` and read back by
    /// `enclave_audit::actor_from_parts`, so changing it orphans every historical row.
    #[test]
    fn the_share_link_kind_round_trips_on_its_stored_spelling() {
        assert_eq!(ActorKind::ShareLink.as_str(), "share_link");
        assert_eq!("share_link".parse::<ActorKind>(), Ok(ActorKind::ShareLink));
        assert_eq!("SHARE_LINK".parse::<ActorKind>(), Ok(ActorKind::ShareLink));
        // Not the abbreviation its neighbours use, and not silently accepted as one.
        assert!("link".parse::<ActorKind>().is_err());
        assert!("share".parse::<ActorKind>().is_err());
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
