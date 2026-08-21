//! Turning a bearer token into a [`RequestContext`].
//!
//! This runs before the policy chain, not as part of it: `docs/02-HLD.md §14` puts authentication
//! second, after tenant isolation and before conditional access. What comes out is an *identity*,
//! never a permission — `PolicyEngine::enforce` decides everything else.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use enclave_core::{DevicePosture, Error, RequestContext, RequestId};

use crate::error::ApiError;
use crate::state::ApiState;

/// A verified caller.
#[derive(Debug, Clone)]
pub struct Authenticated {
    /// The context the policy chain runs against.
    pub ctx: RequestContext,
}

impl FromRequestParts<ApiState> for Authenticated {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let request_id = RequestId::new_v7();

        let token = bearer(parts).ok_or_else(|| {
            ApiError::new(Error::denied(enclave_core::ReasonCode::AccessDenied), request_id)
        })?;

        let verified = state
            .tokens
            .verify(token, chrono::Utc::now())
            .map_err(|error| ApiError::new(map_auth_error(&error), request_id))?;

        // Network origin and device posture are properties of the connection and of MDM
        // attestation. They are supplied here rather than read from the token, because a token that
        // could assert its own network origin would make every conditional-access network rule
        // self-certifying.
        //
        // The network half is now resolved from the real connection (`ENC-583`): the socket peer,
        // and a forwarded address only where a configured proxy vouched for it hop by hop
        // (`docs/06 §7.3`). Posture still awaits the device registry, and the context stays honest
        // about not knowing it — `DevicePosture::Unknown` satisfies no posture requirement.
        let network = state.edge.network_context(parts);
        let posture = DevicePosture::Unknown;

        Ok(Self { ctx: verified.to_request_context(request_id, network, posture) })
    }
}

/// Extracts the bearer token, if the header is present and well-formed.
fn bearer(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

/// Collapses every authentication failure to one client-visible outcome.
///
/// The variants stay distinct in logs so an operator can tell an expired token from a forged one.
/// The caller learns only that it was refused: distinguishing them turns the endpoint into an
/// oracle for which tokens exist and which keys are current.
fn map_auth_error(error: &enclave_auth::AuthError) -> Error {
    tracing::debug!(?error, "authentication failed");
    Error::denied(error.reason_code().unwrap_or(enclave_core::ReasonCode::AccessDenied))
}
