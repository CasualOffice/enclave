//! Where audit events go: the [`AuditSink`] trait, a PostgreSQL implementation and an in-memory
//! one for tests.
//!
//! # Why a trait at all
//!
//! `PolicyEngine` holds an `Arc<dyn AuditSink>` (`docs/03-LLD.md §12`) so that the engine can be
//! unit-tested without a database, and so that the *only* way to reach the audit table from domain
//! code is through this interface. A handler that could write the table directly could also write
//! a row that says something other than what the engine decided.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Mutex;

use async_trait::async_trait;
use enclave_core::{
    Action, ClientType, DeviceId, McpClientId, PolicyDecision, ReasonCode, RequestContext,
    ResourceKind, ResourceRef, SessionId, TenantId, Uuid, WorkspaceId,
};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgRow;
use sqlx::{PgConnection, Row};

use enclave_db::{DbPool, TenantScoped};

use crate::canonical::CANONICAL_VERSION;
use crate::chain::{seal, verify_chain, EventHash, VerifyResult};
use crate::error::{AuditError, Result};
use crate::event::{actor_from_parts, parse_action, AuditEvent, Outcome, PolicyRef};
use crate::redact::Detail;

/// The name of the sequence backing `audit_events.sequence`.
///
/// Read explicitly with `nextval` rather than left to the column default, because the sequence
/// value is inside the canonically hashed bytes and therefore has to be known *before* the row is
/// hashed, not after it is inserted.
const SEQUENCE_NAME: &str = "audit_events_sequence_seq";

/// Domain separator for the per-tenant advisory lock key.
const LOCK_DOMAIN: &[u8] = b"enclave.audit.chain";

/// Whether tamper evidence is on for this tenant (`docs/08-BYO-INFRA.md §14`).
///
/// A configuration switch rather than a build-time one because chaining serializes writes per
/// tenant, which a very high-volume tenant may not want to pay for. When it is off the hash
/// columns stay `NULL` and verification reports [`VerifyResult::NotChained`] — never "valid".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChainMode {
    /// Compute and store the chain. The default, because tamper evidence should be opted out of
    /// deliberately rather than opted into.
    #[default]
    Enabled,
    /// Leave `previous_hash` and `event_hash` `NULL`.
    Disabled,
}

/// What a sink assigned to an event it accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recorded {
    /// The event's id, for correlating with the request that produced it.
    pub id: Uuid,
    /// The sequence the row was written at.
    pub sequence: i64,
    /// The chain hash, or `None` when chaining is disabled.
    pub event_hash: Option<EventHash>,
}

/// The audit write path.
///
/// `Debug` is a supertrait so that structures holding an `Arc<dyn AuditSink>` can still derive
/// `Debug` — the workspace warns on types that cannot.
#[async_trait]
pub trait AuditSink: fmt::Debug + Send + Sync {
    /// Records one event, assigning it a sequence and (when enabled) a chain hash.
    ///
    /// # Errors
    ///
    /// Any failure to persist. Callers must **not** swallow it: an unaudited action is an action
    /// that must not be treated as having happened (`CLAUDE.md` rule 10).
    async fn record(&self, event: AuditEvent) -> Result<Recorded>;

    /// Records an allow, including the obligations the decision carried.
    ///
    /// # Errors
    ///
    /// As [`AuditSink::record`].
    async fn record_allow(
        &self,
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
        decision: &PolicyDecision,
    ) -> Result<Recorded> {
        self.record(AuditEvent::allowed(ctx, action, resource, decision)).await
    }

    /// Records a denial. Denials go through the same path as allows, deliberately: two paths is
    /// one path that can be forgotten.
    ///
    /// # Errors
    ///
    /// As [`AuditSink::record`].
    async fn record_deny(
        &self,
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
        code: ReasonCode,
    ) -> Result<Recorded> {
        self.record(AuditEvent::denied(ctx, action, resource, code)).await
    }
}

/// The advisory-lock key that serializes chain writes for one tenant.
///
/// Derived from the tenant id by hashing rather than by truncating it, so two tenants whose UUIDs
/// share a prefix do not contend, and so the key cannot be guessed into colliding with another
/// subsystem's lock — hence the domain separator.
#[must_use]
pub fn chain_lock_key(tenant: TenantId) -> i64 {
    let mut hasher = Sha256::new();
    hasher.update(LOCK_DOMAIN);
    hasher.update(tenant.as_uuid().as_bytes());
    let digest = hasher.finalize();
    let mut head = [0u8; 8];
    head.copy_from_slice(&digest[..8]);
    i64::from_be_bytes(head)
}

/// Writes audit events to PostgreSQL.
///
/// # Ordering and the advisory lock
///
/// `event_hash` depends on the previous row's hash, so two concurrent writers for one tenant must
/// not both read the same head. `pg_advisory_xact_lock` keyed by tenant makes the read-modify-write
/// atomic and releases at commit, so a rolled-back audit write leaves no lock behind. It is per
/// tenant, so one busy tenant cannot serialize another's writes.
///
/// # Row-level security
///
/// This type does not set the tenant GUC. Connections come from the pool already scoped by the
/// `db` crate's `TenantScoped` wrapper (`CLAUDE.md`), and the intended path for anything that is
/// already inside a transaction is [`record_in_tx`] — which is also the only way to make the audit
/// row and the state change it describes commit or roll back together (`docs/03-LLD.md §15`).
#[derive(Debug, Clone)]
pub struct PgAuditSink {
    pool: DbPool,
    chain: ChainMode,
}

impl PgAuditSink {
    /// Builds a sink over an existing pool.
    #[must_use]
    pub const fn new(pool: DbPool, chain: ChainMode) -> Self {
        Self { pool, chain }
    }

    /// Whether this sink is computing a chain.
    #[must_use]
    pub const fn chain_mode(&self) -> ChainMode {
        self.chain
    }

    /// Reads a page of a tenant's chain in ascending sequence order.
    ///
    /// Paged rather than "load the chain", because a mature tenant's chain does not fit in memory
    /// and a verifier that assumes it does is a verifier that stops being run.
    ///
    /// # Errors
    ///
    /// Storage failures, and [`AuditError::MalformedRow`] if a stored row cannot be reconstructed
    /// — which is itself a tamper signal and must not be skipped over.
    pub async fn load_page(
        &self,
        tenant: TenantId,
        after_sequence: i64,
        limit: i64,
    ) -> Result<Vec<AuditEvent>> {
        let mut tx = TenantScoped::begin(&self.pool, tenant).await?;
        let rows = sqlx::query(SELECT_PAGE_SQL)
            .bind(tenant.as_uuid())
            .bind(after_sequence)
            .bind(limit)
            .fetch_all(&mut *tx)
            .await?;
        let events: Result<Vec<AuditEvent>> = rows.iter().map(event_from_row).collect();
        tx.commit().await?;
        events
    }

    /// Verifies a tenant's chain from the beginning, one page at a time.
    ///
    /// Returns at the first divergence rather than continuing, because every later row will also
    /// fail and only the first is evidence.
    ///
    /// # Errors
    ///
    /// Storage failures and unreadable rows.
    pub async fn verify_tenant(&self, tenant: TenantId, page_size: i64) -> Result<VerifyResult> {
        let mut after = 0i64;
        let mut checked = 0usize;
        let mut carry: Vec<AuditEvent> = Vec::new();
        let mut head = None;
        let mut chained = false;

        loop {
            let page = self.load_page(tenant, after, page_size).await?;
            if page.is_empty() {
                break;
            }
            after = page.last().map_or(after, |e| e.sequence);

            // The last row of the previous page is prepended so the link across the page boundary
            // is verified rather than assumed.
            let mut window = std::mem::take(&mut carry);
            let overlap = window.len();
            window.extend(page);

            match verify_chain(&window) {
                VerifyResult::Diverged { sequence, divergence } => {
                    return Ok(VerifyResult::Diverged { sequence, divergence })
                }
                VerifyResult::Valid { events_checked, head: page_head, .. } => {
                    chained = true;
                    checked += events_checked - overlap;
                    head = page_head;
                }
                VerifyResult::NotChained { events_checked } => {
                    checked += events_checked - overlap;
                }
            }

            if let Some(last) = window.pop() {
                carry.push(last);
            }
        }

        if checked == 0 {
            return Ok(VerifyResult::Valid { events_checked: 0, from_genesis: true, head: None });
        }
        if !chained {
            return Ok(VerifyResult::NotChained { events_checked: checked });
        }
        Ok(VerifyResult::Valid { events_checked: checked, from_genesis: true, head })
    }
}

#[async_trait]
impl AuditSink for PgAuditSink {
    /// Opens its own transaction.
    ///
    /// Correct for standalone audit — a denial, a login, an administrative read — but not for an
    /// action that also changes state: use [`record_in_tx`] there, so the audit row cannot commit
    /// while the change it describes rolls back, or the reverse.
    async fn record(&self, event: AuditEvent) -> Result<Recorded> {
        let mut tx = TenantScoped::begin(&self.pool, event.tenant_id).await?;
        let recorded = record_in_tx(&mut tx, event, self.chain).await?;
        tx.commit().await?;
        Ok(recorded)
    }
}

/// Writes one audit event inside a caller-supplied transaction.
///
/// This is the primitive; [`PgAuditSink::record`] is the convenience wrapper. Taking the
/// transaction by reference is what makes "the audit row and the state change commit together"
/// a property of the type signature rather than of a comment.
///
/// # Errors
///
/// Storage failures. A failure here must fail the surrounding transaction.
pub async fn record_in_tx(
    conn: &mut PgConnection,
    mut event: AuditEvent,
    chain: ChainMode,
) -> Result<Recorded> {
    if chain == ChainMode::Enabled {
        // Held until commit, so a rollback cannot strand it. Per tenant, so tenants do not
        // serialize each other.
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(chain_lock_key(event.tenant_id))
            .execute(&mut *conn)
            .await?;
    }

    event.sequence =
        sqlx::query_scalar::<_, i64>(NEXTVAL_SQL).bind(SEQUENCE_NAME).fetch_one(&mut *conn).await?;

    if chain == ChainMode::Enabled {
        let previous: Option<Option<Vec<u8>>> = sqlx::query_scalar(SELECT_HEAD_SQL)
            .bind(event.tenant_id.as_uuid())
            .fetch_optional(&mut *conn)
            .await?;
        let previous = match previous.flatten() {
            Some(bytes) => Some(EventHash::from_slice(&bytes)?),
            None => None,
        };
        seal(&mut event, previous);
    } else {
        event.previous_hash = None;
        event.event_hash = None;
    }

    let (actor_kind, actor_id) = event.actor_parts();
    let detail = if event.detail.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(event.detail.as_map().clone()))
    };
    let policy_refs = if event.policy_refs.is_empty() {
        None
    } else {
        serde_json::to_value(&event.policy_refs).ok()
    };

    sqlx::query(INSERT_SQL)
        .bind(event.id)
        .bind(event.tenant_id.as_uuid())
        .bind(event.sequence)
        .bind(event.occurred_at)
        .bind(actor_id)
        .bind(actor_kind.as_str())
        .bind(event.on_behalf_of.map(|u| u.as_uuid()))
        .bind(event.action.to_string())
        .bind(event.resource_kind().map(|k| k.as_str()))
        .bind(event.resource_id())
        .bind(event.workspace_id.map(|w| w.as_uuid()))
        .bind(event.outcome.as_str())
        .bind(event.reason_code.map(|c| c.as_str()))
        .bind(policy_refs)
        .bind(event.request_id.as_uuid())
        .bind(event.session_id.map(|s| s.as_uuid()))
        .bind(event.client_type.map(|c| c.as_str()))
        .bind(event.mcp_client_id.map(|c| c.as_uuid()))
        .bind(event.device_id.map(|d| d.as_uuid()))
        .bind(event.ip.map(|ip| ip.to_string()))
        .bind(event.country.clone())
        .bind(event.user_agent.clone())
        .bind(detail)
        .bind(event.previous_hash.map(|h| h.as_bytes().to_vec()))
        .bind(event.event_hash.map(|h| h.as_bytes().to_vec()))
        .execute(&mut *conn)
        .await?;

    tracing::debug!(
        audit_id = %event.id,
        sequence = event.sequence,
        canonical_version = CANONICAL_VERSION,
        "audit event recorded"
    );

    Ok(Recorded { id: event.id, sequence: event.sequence, event_hash: event.event_hash })
}

/// `nextval` is called with the sequence name as a parameter so the name is never concatenated
/// into SQL, even though it is a constant today.
const NEXTVAL_SQL: &str = "SELECT nextval($1::text::regclass)";

/// The chain head for a tenant. `sequence DESC LIMIT 1` under the advisory lock is the whole
/// read-modify-write.
const SELECT_HEAD_SQL: &str = "SELECT event_hash FROM audit_events \
     WHERE tenant_id = $1 ORDER BY sequence DESC LIMIT 1";

/// The insert. `ip` is bound as text and cast, so the crate does not need an INET-typed binding
/// and its dependency.
const INSERT_SQL: &str = "INSERT INTO audit_events (\
     id, tenant_id, sequence, occurred_at, actor_id, actor_type, on_behalf_of, action, \
     resource_type, resource_id, workspace_id, outcome, reason_code, policy_refs, request_id, \
     session_id, client_type, mcp_client_id, device_id, ip, country, user_agent, detail, \
     previous_hash, event_hash) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, \
     $19, $20::text::inet, $21, $22, $23, $24, $25)";

/// The verification read. `host(ip)` renders the address without a netmask so it round-trips
/// through [`IpAddr`] and reproduces the bytes that were hashed.
const SELECT_PAGE_SQL: &str = "SELECT id, tenant_id, sequence, occurred_at, actor_id, actor_type, \
     on_behalf_of, action, resource_type, resource_id, workspace_id, outcome, reason_code, \
     policy_refs, request_id, session_id, client_type, mcp_client_id, device_id, host(ip) AS ip, \
     country, user_agent, detail, previous_hash, event_hash \
     FROM audit_events WHERE tenant_id = $1 AND sequence > $2 ORDER BY sequence ASC LIMIT $3";

/// Rebuilds an event from a stored row.
///
/// Every failure is [`AuditError::MalformedRow`] naming the column and a fixed reason — never the
/// value, because an unreadable audit row is frequently an attacked one and echoing its content
/// into a log is how a payload travels.
fn event_from_row(row: &PgRow) -> Result<AuditEvent> {
    let tenant_id = TenantId::from_uuid(row.try_get("tenant_id")?);

    let actor_type: String = row.try_get("actor_type")?;
    let actor = actor_from_parts(&actor_type, row.try_get("actor_id")?)?;

    let action_text: String = row.try_get("action")?;
    let action = parse_action(&action_text)?;

    let resource_type: Option<String> = row.try_get("resource_type")?;
    let resource_id: Option<Uuid> = row.try_get("resource_id")?;
    let resource = match (resource_type, resource_id) {
        (Some(kind), Some(id)) => {
            let kind = ResourceKind::from_str(&kind).map_err(|_| AuditError::MalformedRow {
                column: "resource_type",
                reason: "unknown resource kind",
            })?;
            Some(ResourceRef::new(tenant_id, kind, id))
        }
        _ => None,
    };

    let outcome_text: String = row.try_get("outcome")?;
    let outcome = Outcome::from_str(&outcome_text)?;

    let reason_code = match row.try_get::<Option<String>, _>("reason_code")? {
        Some(text) => Some(ReasonCode::from_str(&text).map_err(|_| AuditError::MalformedRow {
            column: "reason_code",
            reason: "unknown reason code",
        })?),
        None => None,
    };

    let client_type = match row.try_get::<Option<String>, _>("client_type")? {
        Some(text) => Some(ClientType::from_str(&text).map_err(|_| AuditError::MalformedRow {
            column: "client_type",
            reason: "unknown client type",
        })?),
        None => None,
    };

    let policy_refs = match row.try_get::<Option<serde_json::Value>, _>("policy_refs")? {
        Some(value) => serde_json::from_value::<Vec<PolicyRef>>(value).map_err(|_| {
            AuditError::MalformedRow {
                column: "policy_refs",
                reason: "not a policy reference list",
            }
        })?,
        None => Vec::new(),
    };

    let detail = match row.try_get::<Option<serde_json::Value>, _>("detail")? {
        Some(serde_json::Value::Object(map)) => Detail::redacted(map),
        Some(_) => {
            return Err(AuditError::MalformedRow { column: "detail", reason: "not a JSON object" })
        }
        None => Detail::empty(),
    };

    let ip =
        match row.try_get::<Option<String>, _>("ip")? {
            Some(text) => Some(IpAddr::from_str(&text).map_err(|_| AuditError::MalformedRow {
                column: "ip",
                reason: "not an IP address",
            })?),
            None => None,
        };

    let previous_hash = match row.try_get::<Option<Vec<u8>>, _>("previous_hash")? {
        Some(bytes) => Some(EventHash::from_slice(&bytes)?),
        None => None,
    };
    let event_hash = match row.try_get::<Option<Vec<u8>>, _>("event_hash")? {
        Some(bytes) => Some(EventHash::from_slice(&bytes)?),
        None => None,
    };

    Ok(AuditEvent {
        id: row.try_get("id")?,
        tenant_id,
        sequence: row.try_get("sequence")?,
        occurred_at: row.try_get("occurred_at")?,
        actor,
        on_behalf_of: row.try_get::<Option<Uuid>, _>("on_behalf_of")?.map(Into::into),
        action,
        resource,
        workspace_id: row.try_get::<Option<Uuid>, _>("workspace_id")?.map(WorkspaceId::from_uuid),
        outcome,
        reason_code,
        policy_refs,
        request_id: row.try_get::<Uuid, _>("request_id")?.into(),
        session_id: row.try_get::<Option<Uuid>, _>("session_id")?.map(SessionId::from_uuid),
        client_type,
        mcp_client_id: row.try_get::<Option<Uuid>, _>("mcp_client_id")?.map(McpClientId::from_uuid),
        device_id: row.try_get::<Option<Uuid>, _>("device_id")?.map(DeviceId::from_uuid),
        ip,
        country: row.try_get("country")?,
        user_agent: row.try_get("user_agent")?,
        detail,
        previous_hash,
        event_hash,
    })
}

/// An in-process sink that keeps events in a `Vec`.
///
/// For unit tests of anything that holds an `Arc<dyn AuditSink>` — chiefly `PolicyEngine`, which
/// must be testable without a database if "every path is audited" is going to be asserted at all.
/// It maintains a real chain, so a test can assert on hashes rather than only on counts.
///
/// Not for production: it forgets everything on restart, which is the one thing an audit trail may
/// not do.
#[derive(Debug)]
pub struct MemoryAuditSink {
    state: Mutex<MemoryState>,
    chain: ChainMode,
}

/// The mutable half, kept in one lock so sequence assignment and sealing cannot interleave.
#[derive(Debug, Default)]
struct MemoryState {
    events: Vec<AuditEvent>,
    head: Option<EventHash>,
    next_sequence: i64,
}

impl Default for MemoryAuditSink {
    /// Chains, like the production default — a test double that silently skipped the chain would
    /// let a chain regression pass every test.
    fn default() -> Self {
        Self::new(ChainMode::Enabled)
    }
}

impl MemoryAuditSink {
    /// A sink that chains, matching the production default.
    #[must_use]
    pub fn new(chain: ChainMode) -> Self {
        Self {
            state: Mutex::new(MemoryState { next_sequence: 1, ..MemoryState::default() }),
            chain,
        }
    }

    /// Everything recorded so far, in write order.
    ///
    /// # Errors
    ///
    /// [`AuditError::Internal`] if a previous panic poisoned the lock.
    pub fn events(&self) -> Result<Vec<AuditEvent>> {
        let state = self.state.lock().map_err(|_| AuditError::Internal("audit sink lock"))?;
        Ok(state.events.clone())
    }

    /// How many events were recorded.
    ///
    /// # Errors
    ///
    /// As [`MemoryAuditSink::events`].
    pub fn len(&self) -> Result<usize> {
        let state = self.state.lock().map_err(|_| AuditError::Internal("audit sink lock"))?;
        Ok(state.events.len())
    }

    /// Whether nothing has been recorded.
    ///
    /// # Errors
    ///
    /// As [`MemoryAuditSink::events`].
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }
}

#[async_trait]
impl AuditSink for MemoryAuditSink {
    async fn record(&self, mut event: AuditEvent) -> Result<Recorded> {
        // No `await` inside the critical section, so a std mutex is the right lock here and the
        // guard cannot be held across a yield point.
        let mut state = self.state.lock().map_err(|_| AuditError::Internal("audit sink lock"))?;
        event.sequence = state.next_sequence;
        state.next_sequence += 1;
        if self.chain == ChainMode::Enabled {
            state.head = Some(seal(&mut event, state.head));
        }
        let recorded =
            Recorded { id: event.id, sequence: event.sequence, event_hash: event.event_hash };
        state.events.push(event);
        Ok(recorded)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use enclave_core::{FileAction, FileId};

    use crate::test_support::context;

    #[tokio::test]
    async fn the_memory_sink_assigns_sequences_and_builds_a_verifiable_chain() {
        let sink = MemoryAuditSink::new(ChainMode::Enabled);
        let ctx = context();
        for _ in 0..25 {
            let resource = ResourceRef::file(ctx.tenant_id, FileId::new_v7());
            sink.record_deny(
                &ctx,
                Action::File(FileAction::Download),
                &resource,
                ReasonCode::DownloadBlockedByPolicy,
            )
            .await
            .unwrap();
        }

        let events = sink.events().unwrap();
        assert_eq!(events.len(), 25);
        assert_eq!(events[0].sequence, 1);
        assert_eq!(events[24].sequence, 25);
        assert!(events[0].previous_hash.is_none(), "the first event opens the chain");
        assert!(verify_chain(&events).is_valid());
    }

    #[tokio::test]
    async fn a_disabled_chain_reports_not_chained_rather_than_valid() {
        let sink = MemoryAuditSink::new(ChainMode::Disabled);
        let ctx = context();
        let resource = ResourceRef::file(ctx.tenant_id, FileId::new_v7());
        let decision = PolicyDecision::allow_unconditional();
        for _ in 0..3 {
            sink.record_allow(&ctx, Action::File(FileAction::Preview), &resource, &decision)
                .await
                .unwrap();
        }
        let events = sink.events().unwrap();
        assert_eq!(verify_chain(&events), VerifyResult::NotChained { events_checked: 3 });
    }

    #[test]
    fn the_lock_key_is_stable_and_tenant_specific() {
        let a = TenantId::new_v7();
        let b = TenantId::new_v7();
        assert_eq!(chain_lock_key(a), chain_lock_key(a));
        assert_ne!(chain_lock_key(a), chain_lock_key(b));
    }

    /// Needs a live database with `migrations/0001_foundations.sql` applied and the fixtures from
    /// ENC-112. Left `#[ignore]` per the M0 plan: testcontainer wiring lands with ENC-105/ENC-112,
    /// and this test is the acceptance criterion it must satisfy.
    #[tokio::test]
    #[ignore = "requires a live PostgreSQL; enable with the ENC-112 fixtures"]
    async fn pg_sink_round_trips_and_verifies() {
        // Deliberately unimplemented rather than half-written against an API that does not exist
        // yet: `PgAuditSink::new(pool, ChainMode::Enabled)`, record N events, then
        // `verify_tenant(tenant, 1_000)` must return `Valid`.
    }
}

/// Bridges a sink to the policy engine's audit port.
///
/// The engine cannot depend on this crate — `audit` depends on `core`, and the reverse would be a
/// cycle — so `core` declares a deliberately narrow `PolicyAuditSink`: record an allow, record a
/// deny, nothing else. This is the other half of that arrangement (`plans/M0-FOUNDATIONS.md` D9).
///
/// A macro rather than a blanket `impl<T: AuditSink>`, which the orphan rule forbids: both the
/// trait and `T` would be foreign. The record format, canonical serialization and hash chain all
/// stay here, where they belong.
macro_rules! policy_audit_sink {
    ($sink:ty) => {
        #[async_trait]
        impl enclave_core::PolicyAuditSink for $sink {
            async fn record_allow(
                &self,
                ctx: &enclave_core::RequestContext,
                action: Action,
                resource: &ResourceRef,
                obligations: &enclave_core::Obligations,
            ) -> enclave_core::Result<()> {
                let decision = PolicyDecision::allow(obligations.clone());
                let event = AuditEvent::allowed(ctx, action, resource, &decision);
                let _recorded = AuditSink::record(self, event).await?;
                Ok(())
            }

            async fn record_deny(
                &self,
                ctx: &enclave_core::RequestContext,
                action: Action,
                resource: &ResourceRef,
                stage: enclave_core::Stage,
                code: ReasonCode,
            ) -> enclave_core::Result<()> {
                // The stage goes in `policy_refs`, which is inside the hashed payload — so which
                // control refused is tamper-evident along with the fact of the refusal. "Denied"
                // without "by which control" is not something an investigator can work from.
                let mut event = AuditEvent::denied(ctx, action, resource, code);
                event.policy_refs.push(PolicyRef::builtin(stage.as_str()));
                let _recorded = AuditSink::record(self, event).await?;
                Ok(())
            }
        }
    };
}

policy_audit_sink!(PgAuditSink);
policy_audit_sink!(MemoryAuditSink);

/// One page of a tenant's log, newest first, for the administrative reader (`ENC-961`).
///
/// # Why a free function and not a method on the sink
///
/// [`AuditSink`] is a *write* interface, held by the policy engine as an `Arc<dyn AuditSink>` so
/// that the only way to reach the table from domain code is through the engine. A reader hung off
/// that trait would be reachable only through the write handle, and every test double would have to
/// implement a query it exists to avoid. Reading takes a `TenantScoped` transaction, exactly as
/// `enclave_db`'s queries do, so a handler reaches it the same way it reaches everything else.
///
/// # Why this is a second query and not `load_page` with a direction flag
///
/// [`PgAuditSink::load_page`] exists for **verification**: ascending by sequence, unfiltered, paged
/// so a mature chain can be walked without loading it whole. Every one of those properties is wrong
/// for a reader — an auditor wants the newest first, narrowed to what they are asking about — and
/// one statement serving both questions would make the verifier's correctness depend on a caller
/// passing the right argument.
///
/// # What it returns, and why that differs from `GET /me/activity`
///
/// **Everything, including denials and the actor's circumstances.** `crates/db/src/activity.rs`
/// excludes both and argues it at length: a `DENY` discloses that somebody tried and that the
/// resource exists, and an IP address on a screen any member can open is a disclosure with no
/// upside. Neither argument holds here. This surface *is* the compliance log, it is authorized as
/// `AdminAction::ReadAudit`, and an investigation that cannot see refusals or reconstruct a session
/// is not an investigation.
///
/// # Errors
///
/// Storage failures, and a malformed-row error if a stored row cannot be reconstructed — which is
/// itself a tamper signal, so it is surfaced rather than skipped over.
pub async fn read_page(
    tx: &mut TenantScoped,
    filter: &AuditFilter,
    limit: i64,
) -> Result<Vec<AuditEvent>> {
    let tenant = tx.tenant_id();
    let rows = sqlx::query(SELECT_ADMIN_PAGE_SQL)
        .bind(tenant.as_uuid())
        .bind(filter.before)
        .bind(filter.actor)
        .bind(filter.action.as_deref())
        .bind(filter.outcome.as_deref())
        .bind(filter.since)
        .bind(limit)
        .fetch_all(&mut **tx)
        .await?;
    rows.iter().map(event_from_row).collect()
}

/// What an administrator is asking the log.
///
/// Every field narrows and none widens, so `AuditFilter::default()` reads the whole log — which is
/// the question an auditor most often starts from.
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    /// Read rows before this sequence, for paging. `None` starts at the head.
    pub before: Option<i64>,
    /// Only this actor's events.
    pub actor: Option<Uuid>,
    /// Only this action, in the `family.verb` spelling the column stores.
    pub action: Option<String>,
    /// `ALLOW`, `DENY` or `ERROR`.
    pub outcome: Option<String>,
    /// Only events at or after this instant.
    pub since: Option<chrono::DateTime<chrono::Utc>>,
}

// `$2::bigint IS NULL OR sequence < $2` and its four siblings: one statement serves the unfiltered
// read and every combination of narrowings. The alternatives are building SQL by concatenation,
// which is how a filter becomes an injection, or a match over thirty-two shapes nobody maintains.
//
// Cursored on `sequence` rather than `occurred_at`, which is not unique: two events in the same
// microsecond would make a timestamp cursor repeat one and skip the other, and an audit reader that
// can silently drop a row is worse than no reader at all.
const SELECT_ADMIN_PAGE_SQL: &str = "SELECT id, tenant_id, sequence, occurred_at, actor_id, \
     actor_type, on_behalf_of, action, resource_type, resource_id, workspace_id, outcome, \
     reason_code, policy_refs, request_id, session_id, client_type, mcp_client_id, device_id, \
     host(ip) AS ip, country, user_agent, detail, previous_hash, event_hash \
     FROM audit_events \
     WHERE tenant_id = $1 \
       AND ($2::bigint IS NULL OR sequence < $2) \
       AND ($3::uuid IS NULL OR actor_id = $3) \
       AND ($4::text IS NULL OR action = $4) \
       AND ($5::text IS NULL OR outcome = $5) \
       AND ($6::timestamptz IS NULL OR occurred_at >= $6) \
     ORDER BY sequence DESC LIMIT $7";
