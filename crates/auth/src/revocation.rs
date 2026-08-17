//! The two revocation mechanisms that act faster than expiry (`docs/03-LLD.md §5.4`).
//!
//! A signed JWT is valid until it expires. That is the price of a hot path with no I/O, and it is
//! paid down by three layers: a short TTL, a `jti` denylist, and a per-subject `token_epoch`. The
//! first is arithmetic. The other two are here.
//!
//! # The asymmetry that makes this safe
//!
//! Both stores can be unavailable, and what that means depends entirely on the token:
//!
//! - Ordinary scopes **fail open**, with an audit record. The exposure is bounded by the
//!   ten-minute access-token TTL, and failing closed would mean a Redis blip logs out every user in
//!   the deployment — an availability incident manufactured out of a dependency wobble.
//! - Privileged scopes (`admin:*`, `security:*`, `share:external`) **fail closed**. Here the
//!   asymmetry inverts: the cost of refusing an administrator for the duration of an outage is an
//!   inconvenience, and the cost of honouring a revoked administrator token is the deployment.
//!
//! That split is test K9, and modelling the stores as traits is what makes it testable — an
//! outage is a value returned by a double, not a container someone has to remember to stop.

use core::fmt;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use enclave_core::{Dependency, SessionId, TenantId};
use uuid::Uuid;

use crate::access::is_privileged;
use crate::claims::AccessTokenClaims;
use crate::error::{AuthError, StoreUnavailable};
use crate::refresh::RevokeReason;

/// The `jti` denylist (Redis in production, TTL equal to the remaining token life).
///
/// # Why `deny_session` exists
///
/// Revoking a refresh family has to stop the access tokens issued inside it, and we do not hold a
/// list of their `jti`s — `refresh_tokens` has no column for them. Denying by `sid` covers every
/// token in the family with one entry, and the `sid` claim is present on every access token, so the
/// check costs the same lookup. See the note in `crate` documentation: persisting this needs a
/// session-scoped row that `docs/04-DATA-MODEL.md §6` does not yet define.
#[async_trait]
pub trait DenylistStore: Send + Sync + fmt::Debug {
    /// Denies one token until it would have expired anyway.
    ///
    /// # Errors
    ///
    /// [`StoreUnavailable`] when the store cannot be reached. Note the signature: it reports
    /// unavailability rather than deciding what it means, because only the caller knows the
    /// token's scopes.
    async fn deny_jti(
        &self,
        tenant_id: TenantId,
        jti: Uuid,
        expires_at: DateTime<Utc>,
        reason: RevokeReason,
    ) -> Result<(), StoreUnavailable>;

    /// Denies every access token in a refresh family.
    ///
    /// # Errors
    ///
    /// [`StoreUnavailable`].
    async fn deny_session(
        &self,
        tenant_id: TenantId,
        session_id: SessionId,
        expires_at: DateTime<Utc>,
        reason: RevokeReason,
    ) -> Result<(), StoreUnavailable>;

    /// Whether this token, or its family, has been denied.
    ///
    /// # Errors
    ///
    /// [`StoreUnavailable`].
    async fn is_denied(
        &self,
        tenant_id: TenantId,
        jti: Uuid,
        session_id: SessionId,
    ) -> Result<bool, StoreUnavailable>;
}

/// The per-subject `token_epoch` counter (`users.token_epoch`, cached in process).
///
/// One integer invalidates every outstanding token for a subject at once, which is what makes
/// password change, MFA reset, offboarding and role removal take effect immediately rather than
/// within a token lifetime.
#[async_trait]
pub trait EpochStore: Send + Sync + fmt::Debug {
    /// The subject's current epoch.
    ///
    /// # Errors
    ///
    /// [`StoreUnavailable`].
    async fn current_epoch(
        &self,
        tenant_id: TenantId,
        subject: Uuid,
    ) -> Result<i32, StoreUnavailable>;
}

/// What a revocation check concluded, and how confident it is.
///
/// [`RevocationVerdict::AllowedUnverified`] exists so the fail-open path cannot be mistaken for a
/// clean allow. `docs/03-LLD.md §5.4` requires an audit record when a check is skipped, and a
/// `Result<(), _>` return would have made that record something a caller could forget to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "an unverified allow must be audited"]
pub enum RevocationVerdict {
    /// Both stores answered, and neither revoked the token.
    Allowed,
    /// A store was unavailable, the token holds no privileged scopes, and the request proceeds
    /// under the bounded risk described in `docs/03-LLD.md §5.4`. **Audit this.**
    AllowedUnverified {
        /// Which dependency did not answer, for the audit record.
        dependency: Dependency,
    },
}

/// Applies the denylist and epoch checks with the fail-open/fail-closed split.
#[derive(Debug)]
pub struct RevocationChecker<D, E> {
    denylist: D,
    epochs: E,
}

impl<D: DenylistStore, E: EpochStore> RevocationChecker<D, E> {
    /// Builds a checker over the two stores.
    pub const fn new(denylist: D, epochs: E) -> Self {
        Self { denylist, epochs }
    }

    /// The denylist store, for callers that need to write to it (logout, family revoke).
    pub const fn denylist(&self) -> &D {
        &self.denylist
    }

    /// Runs both checks against a verified token.
    ///
    /// Takes [`AccessTokenClaims`] rather than a raw token so that it cannot be called on something
    /// whose signature has not been checked — revoking an unverified token is meaningless, and
    /// *allowing* one is a catastrophe.
    ///
    /// # Errors
    ///
    /// - [`AuthError::TokenRevoked`] — the `jti` or its family is denied.
    /// - [`AuthError::EpochStale`] — K5: the token predates the subject's current epoch.
    /// - [`AuthError::RevocationUnavailable`] — K9: a store did not answer and the token is
    ///   privileged.
    pub async fn check(&self, claims: &AccessTokenClaims) -> Result<RevocationVerdict, AuthError> {
        let privileged = is_privileged(&claims.scopes());
        let tenant_id = TenantId::from_uuid(claims.tid);

        match self.denylist.is_denied(tenant_id, claims.jti, SessionId::from_uuid(claims.sid)).await
        {
            Ok(true) => return Err(AuthError::TokenRevoked),
            Ok(false) => {}
            Err(unavailable) => {
                if privileged {
                    return Err(AuthError::RevocationUnavailable(unavailable));
                }
                let dependency = unavailable.dependency;
                tracing::warn!(
                    dependency = %dependency,
                    tenant_id = %tenant_id,
                    "denylist unavailable; allowing an unprivileged token unverified, bounded by its TTL"
                );
                return Ok(RevocationVerdict::AllowedUnverified { dependency });
            }
        }

        // K5. The epoch lives in PostgreSQL rather than Redis, so it fails differently — but the
        // privileged/ordinary split is the same, because the question it answers is the same one:
        // "has this token been revoked out of band?"
        match self.epochs.current_epoch(tenant_id, claims.sub).await {
            // Strictly less than: a token issued at the current epoch is fine, and one issued at a
            // *higher* epoch than the store reports means the cache is stale, not that the token is
            // forged — refusing it would turn a replication lag into a logout storm.
            Ok(current) if claims.epoch < current => Err(AuthError::EpochStale),
            Ok(_) => Ok(RevocationVerdict::Allowed),
            Err(unavailable) => {
                if privileged {
                    return Err(AuthError::RevocationUnavailable(unavailable));
                }
                let dependency = unavailable.dependency;
                tracing::warn!(
                    dependency = %dependency,
                    tenant_id = %tenant_id,
                    "epoch store unavailable; allowing an unprivileged token unverified, bounded by its TTL"
                );
                Ok(RevocationVerdict::AllowedUnverified { dependency })
            }
        }
    }
}

/// An in-memory [`DenylistStore`] that can be told to fail.
///
/// The `available` switch is the whole point: K9 is about behaviour during an outage, and an outage
/// you cannot produce on demand is a behaviour you cannot test. Public because the API crate needs
/// the same double for its middleware tests.
#[derive(Debug, Default)]
pub struct InMemoryDenylist {
    denied_jtis: std::sync::Mutex<Vec<(TenantId, Uuid)>>,
    denied_sessions: std::sync::Mutex<Vec<(TenantId, SessionId)>>,
    available: std::sync::atomic::AtomicBool,
}

impl InMemoryDenylist {
    /// An empty, available denylist.
    #[must_use]
    pub fn new() -> Self {
        Self {
            denied_jtis: std::sync::Mutex::default(),
            denied_sessions: std::sync::Mutex::default(),
            available: std::sync::atomic::AtomicBool::new(true),
        }
    }

    /// Simulates the store going down, or coming back.
    pub fn set_available(&self, available: bool) {
        self.available.store(available, std::sync::atomic::Ordering::SeqCst);
    }

    fn guard(&self) -> Result<(), StoreUnavailable> {
        if self.available.load(std::sync::atomic::Ordering::SeqCst) {
            Ok(())
        } else {
            Err(StoreUnavailable::new(Dependency::Redis))
        }
    }
}

#[async_trait]
impl DenylistStore for InMemoryDenylist {
    async fn deny_jti(
        &self,
        tenant_id: TenantId,
        jti: Uuid,
        _expires_at: DateTime<Utc>,
        _reason: RevokeReason,
    ) -> Result<(), StoreUnavailable> {
        self.guard()?;
        let mut denied =
            self.denied_jtis.lock().map_err(|_| StoreUnavailable::new(Dependency::Redis))?;
        denied.push((tenant_id, jti));
        Ok(())
    }

    async fn deny_session(
        &self,
        tenant_id: TenantId,
        session_id: SessionId,
        _expires_at: DateTime<Utc>,
        _reason: RevokeReason,
    ) -> Result<(), StoreUnavailable> {
        self.guard()?;
        let mut denied =
            self.denied_sessions.lock().map_err(|_| StoreUnavailable::new(Dependency::Redis))?;
        denied.push((tenant_id, session_id));
        Ok(())
    }

    async fn is_denied(
        &self,
        tenant_id: TenantId,
        jti: Uuid,
        session_id: SessionId,
    ) -> Result<bool, StoreUnavailable> {
        self.guard()?;
        let jtis = self.denied_jtis.lock().map_err(|_| StoreUnavailable::new(Dependency::Redis))?;
        if jtis.contains(&(tenant_id, jti)) {
            return Ok(true);
        }
        let sessions =
            self.denied_sessions.lock().map_err(|_| StoreUnavailable::new(Dependency::Redis))?;
        Ok(sessions.contains(&(tenant_id, session_id)))
    }
}

/// An in-memory [`EpochStore`] that can be told to fail.
#[derive(Debug, Default)]
pub struct InMemoryEpochs {
    epochs: std::sync::Mutex<Vec<(TenantId, Uuid, i32)>>,
    available: std::sync::atomic::AtomicBool,
}

impl InMemoryEpochs {
    /// An empty, available epoch store. Unknown subjects report epoch 1, matching the
    /// `users.token_epoch` default.
    #[must_use]
    pub fn new() -> Self {
        Self {
            epochs: std::sync::Mutex::default(),
            available: std::sync::atomic::AtomicBool::new(true),
        }
    }

    /// Sets a subject's epoch, as `POST /auth/logout-all` and a password change would.
    ///
    /// # Panics
    ///
    /// If the lock was poisoned by a panic in another test.
    pub fn bump_to(&self, tenant_id: TenantId, subject: Uuid, epoch: i32) {
        #[allow(clippy::expect_used)]
        let mut epochs = self.epochs.lock().expect("in-memory epoch lock poisoned");
        epochs.retain(|(t, s, _)| !(*t == tenant_id && *s == subject));
        epochs.push((tenant_id, subject, epoch));
    }

    /// Simulates the store going down, or coming back.
    pub fn set_available(&self, available: bool) {
        self.available.store(available, std::sync::atomic::Ordering::SeqCst);
    }
}

#[async_trait]
impl EpochStore for InMemoryEpochs {
    async fn current_epoch(
        &self,
        tenant_id: TenantId,
        subject: Uuid,
    ) -> Result<i32, StoreUnavailable> {
        if !self.available.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(StoreUnavailable::new(Dependency::Postgres));
        }
        let epochs = self.epochs.lock().map_err(|_| StoreUnavailable::new(Dependency::Postgres))?;
        Ok(epochs
            .iter()
            .find(|(t, s, _)| *t == tenant_id && *s == subject)
            .map_or(1, |(_, _, e)| *e))
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal, not a
    // production hazard. The workspace warns on these constructs for non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::claims::{Acr, AuthMethod};
    use chrono::Duration;
    use enclave_core::{ActorKind, ClientType};

    fn claims(scopes: &[&str]) -> AccessTokenClaims {
        AccessTokenClaims {
            iss: "https://workspace.example.com".to_owned(),
            aud: "enclave-api".to_owned(),
            sub: Uuid::new_v4(),
            tid: Uuid::new_v4(),
            sid: Uuid::new_v4(),
            typ: ActorKind::User,
            scp: scopes.iter().map(|s| (*s).to_owned()).collect(),
            amr: vec![AuthMethod::Pwd],
            auth_time: Utc::now().timestamp(),
            acr: Acr::SingleFactor,
            dev: None,
            cli: ClientType::Web,
            epoch: 7,
            jti: Uuid::new_v4(),
            iat: Utc::now().timestamp(),
            exp: (Utc::now() + Duration::minutes(10)).timestamp(),
            max_cls: None,
        }
    }

    fn checker() -> RevocationChecker<InMemoryDenylist, InMemoryEpochs> {
        RevocationChecker::new(InMemoryDenylist::new(), InMemoryEpochs::new())
    }

    #[tokio::test]
    async fn a_clean_token_is_allowed_with_both_stores_answering() {
        let c = checker();
        let token = claims(&["files:read"]);
        // The subject's stored epoch must not be below the token's, or K5 would fire.
        c.epochs.bump_to(TenantId::from_uuid(token.tid), token.sub, 7);
        assert_eq!(c.check(&token).await.expect("allowed"), RevocationVerdict::Allowed);
    }

    #[tokio::test]
    async fn a_denied_jti_is_rejected() {
        let c = checker();
        let token = claims(&["files:read"]);
        let tenant = TenantId::from_uuid(token.tid);
        c.epochs.bump_to(tenant, token.sub, 7);
        c.denylist
            .deny_jti(tenant, token.jti, token.expires_at(), RevokeReason::Logout)
            .await
            .expect("deny");
        assert!(matches!(c.check(&token).await, Err(AuthError::TokenRevoked)));
    }

    #[tokio::test]
    async fn k4_denying_a_family_stops_every_access_token_in_it() {
        let c = checker();
        let mut first = claims(&["files:read"]);
        let mut second = claims(&["files:read"]);
        // Two access tokens from the same login session, with different `jti`s.
        second.tid = first.tid;
        second.sub = first.sub;
        second.sid = first.sid;
        first.epoch = 1;
        second.epoch = 1;

        let tenant = TenantId::from_uuid(first.tid);
        c.denylist
            .deny_session(
                tenant,
                SessionId::from_uuid(first.sid),
                first.expires_at(),
                RevokeReason::SessionReplay,
            )
            .await
            .expect("deny family");

        assert!(matches!(c.check(&first).await, Err(AuthError::TokenRevoked)));
        assert!(
            matches!(c.check(&second).await, Err(AuthError::TokenRevoked)),
            "a family denial must cover access tokens whose jti was never recorded"
        );
    }

    #[tokio::test]
    async fn k5_a_token_epoch_bump_invalidates_every_outstanding_token_for_that_subject() {
        let c = checker();
        let mut older = claims(&["files:read"]);
        let mut newer = claims(&["files:read"]);
        newer.tid = older.tid;
        newer.sub = older.sub;
        older.epoch = 7;
        newer.epoch = 7;
        let tenant = TenantId::from_uuid(older.tid);
        c.epochs.bump_to(tenant, older.sub, 7);

        assert_eq!(c.check(&older).await.expect("allowed"), RevocationVerdict::Allowed);

        // Password change, MFA reset, offboarding: one integer, every token gone.
        c.epochs.bump_to(tenant, older.sub, 8);
        assert!(matches!(c.check(&older).await, Err(AuthError::EpochStale)));
        assert!(matches!(c.check(&newer).await, Err(AuthError::EpochStale)));

        // A different subject in the same tenant is untouched.
        let bystander = claims(&["files:read"]);
        let mut bystander = AccessTokenClaims { tid: older.tid, ..bystander };
        bystander.epoch = 1;
        assert_eq!(c.check(&bystander).await.expect("allowed"), RevocationVerdict::Allowed);
    }

    #[tokio::test]
    async fn k9_privileged_scopes_fail_closed_when_the_denylist_is_unavailable() {
        let c = checker();
        c.denylist.set_available(false);

        for privileged in [&["admin:users"][..], &["security:incidents"], &["share:external"]] {
            let token = claims(privileged);
            assert!(
                matches!(c.check(&token).await, Err(AuthError::RevocationUnavailable(_))),
                "K9: {privileged:?} must fail closed"
            );
        }
    }

    #[tokio::test]
    async fn k9_ordinary_scopes_fail_open_and_say_so() {
        let c = checker();
        c.denylist.set_available(false);

        let token = claims(&["files:read", "search"]);
        assert_eq!(
            c.check(&token).await.expect("bounded fail-open"),
            RevocationVerdict::AllowedUnverified { dependency: Dependency::Redis },
            "the verdict must record that the check did not actually happen"
        );
    }

    #[tokio::test]
    async fn k9_the_same_split_applies_to_the_epoch_store() {
        let c = checker();
        c.epochs.set_available(false);

        assert!(matches!(
            c.check(&claims(&["admin:users"])).await,
            Err(AuthError::RevocationUnavailable(_))
        ));
        assert_eq!(
            c.check(&claims(&["files:read"])).await.expect("bounded fail-open"),
            RevocationVerdict::AllowedUnverified { dependency: Dependency::Postgres }
        );
    }

    #[tokio::test]
    async fn k9_an_empty_scope_set_is_not_privileged() {
        let c = checker();
        c.denylist.set_available(false);
        assert!(c.check(&claims(&[])).await.is_ok());
    }

    #[tokio::test]
    async fn a_stale_epoch_cache_does_not_reject_a_newer_token() {
        let c = checker();
        let mut token = claims(&["files:read"]);
        token.epoch = 9;
        c.epochs.bump_to(TenantId::from_uuid(token.tid), token.sub, 8);
        assert_eq!(c.check(&token).await.expect("allowed"), RevocationVerdict::Allowed);
    }
}
