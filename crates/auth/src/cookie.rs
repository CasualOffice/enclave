//! The browser transport for refresh tokens (`docs/05-API.md §3`, `docs/03-LLD.md §5.3` rule 5).
//!
//! # Why these attributes are not configurable
//!
//! `HttpOnly`, `Secure` and `SameSite=Strict` are emitted unconditionally, and there is no setting
//! that turns any of them off. That is a deliberate departure from the shape of
//! `docs/08-BYO-INFRA.md §19`, which shows `same_site` as a configuration value.
//!
//! Each attribute defends against a specific attack, and each is a one-word edit away from being
//! disabled by someone debugging on a Friday:
//!
//! - **`HttpOnly`** — without it, any XSS anywhere in the SPA reads the refresh token and the
//!   attacker has a fourteen-day, silently-renewing session.
//! - **`Secure`** — without it, one downgraded request puts the token on the wire in plaintext.
//!   It works on `http://localhost`, which browsers treat as a secure context, so development does
//!   not need an exception.
//! - **`SameSite=Strict`** — without it, the refresh endpoint is reachable cross-site and the
//!   double-submit CSRF token is the only remaining layer.
//!
//! Making them constants means test K10 is not "we remembered to set these in production"; it is a
//! property of the type. Only the cookie's name and path can be configured, and the path is
//! validated because scoping the cookie to `/` would send a refresh token on every API request
//! instead of only on `/api/v1/auth`.

use chrono::Duration;
use serde::{Deserialize, Serialize};

use crate::error::AuthError;
use crate::refresh::RefreshToken;

/// Default cookie name, per `docs/08-BYO-INFRA.md §19`.
pub const DEFAULT_COOKIE_NAME: &str = "enclave_rt";

/// Default path scope, per `docs/05-API.md §3`.
pub const DEFAULT_COOKIE_PATH: &str = "/api/v1/auth";

/// The two things about the refresh cookie a deployment may choose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RefreshCookieConfig {
    /// Cookie name. Configurable so that two Enclave deployments on sibling hosts of one
    /// registrable domain do not collide.
    pub name: String,
    /// Path the cookie is scoped to. The narrower this is, the fewer requests carry the token.
    pub path: String,
}

impl Default for RefreshCookieConfig {
    fn default() -> Self {
        Self { name: DEFAULT_COOKIE_NAME.to_owned(), path: DEFAULT_COOKIE_PATH.to_owned() }
    }
}

impl RefreshCookieConfig {
    /// Rejects a configuration that would widen the cookie's reach or break the header.
    ///
    /// # Errors
    ///
    /// [`AuthError::Configuration`] naming the rule broken.
    pub fn validate(&self) -> Result<(), AuthError> {
        if self.name.is_empty()
            || !self
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            return Err(AuthError::Configuration(
                "auth.refresh_token.cookie.name must be a non-empty token of [A-Za-z0-9_.-]",
            ));
        }
        if !self.path.starts_with('/') || self.path.contains(';') {
            return Err(AuthError::Configuration(
                "auth.refresh_token.cookie.path must be an absolute path with no ';'",
            ));
        }
        // `/` would attach the refresh token to every request the SPA makes, including ones that
        // reach handlers with nothing to do with authentication. The point of a path scope is that
        // the credential is present on exactly the endpoint that consumes it.
        if self.path == "/" {
            return Err(AuthError::Configuration(
                "auth.refresh_token.cookie.path must be narrower than '/'",
            ));
        }
        Ok(())
    }

    /// Builds the `Set-Cookie` value that delivers a refresh token to a browser.
    ///
    /// `max_age` should be the sliding refresh lifetime, so the browser drops a cookie the server
    /// would refuse anyway. It is advisory — the server's copy of `expires_at` is authoritative,
    /// because a client controls its own cookie jar and nothing that lives there is trusted.
    #[must_use]
    pub fn set_cookie_header(&self, token: &RefreshToken, max_age: Duration) -> String {
        format!(
            "{}={}; Path={}; Max-Age={}; HttpOnly; Secure; SameSite=Strict",
            self.name,
            token.expose(),
            self.path,
            max_age.num_seconds().max(0),
        )
    }

    /// Builds the `Set-Cookie` value that removes the cookie on logout.
    ///
    /// Carries the same attributes as the setting header. A browser matches a deletion against
    /// name, path and domain, so a clearing cookie that differs in `Path` leaves the original in
    /// place — the user believes they logged out and the credential is still in the jar.
    #[must_use]
    pub fn clearing_header(&self) -> String {
        format!("{}=; Path={}; Max-Age=0; HttpOnly; Secure; SameSite=Strict", self.name, self.path)
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal, not a
    // production hazard. The workspace warns on these constructs for non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn k10_the_refresh_cookie_is_httponly_secure_samesite_strict_and_path_scoped() {
        let config = RefreshCookieConfig::default();
        config.validate().expect("the documented default must be valid");

        let token = RefreshToken::generate().expect("entropy");
        let header = config.set_cookie_header(&token, Duration::days(14));

        assert!(header.starts_with("enclave_rt="), "{header}");
        assert!(header.contains("; HttpOnly"), "K10: HttpOnly missing from {header}");
        assert!(header.contains("; Secure"), "K10: Secure missing from {header}");
        assert!(header.contains("; SameSite=Strict"), "K10: SameSite missing from {header}");
        assert!(header.contains("; Path=/api/v1/auth"), "K10: path scope missing from {header}");
        assert!(header.contains("; Max-Age=1209600"), "{header}");
        assert!(header.contains(token.expose()));
    }

    #[test]
    fn k10_the_clearing_cookie_carries_the_same_attributes() {
        let config = RefreshCookieConfig::default();
        let header = config.clearing_header();
        assert_eq!(
            header,
            "enclave_rt=; Path=/api/v1/auth; Max-Age=0; HttpOnly; Secure; SameSite=Strict"
        );
    }

    #[test]
    fn k10_no_configuration_can_remove_a_security_attribute() {
        // The API surface has exactly two knobs. If a future edit adds a third that can turn one of
        // these off, this test is where it should be argued about.
        let config =
            RefreshCookieConfig { name: "custom_rt".to_owned(), path: "/x/auth".to_owned() };
        config.validate().expect("valid");
        let header = config
            .set_cookie_header(&RefreshToken::generate().expect("entropy"), Duration::minutes(1));
        for required in ["HttpOnly", "Secure", "SameSite=Strict"] {
            assert!(header.contains(required), "{required} missing from {header}");
        }
    }

    #[test]
    fn a_root_scoped_or_malformed_cookie_is_refused() {
        for bad in ["/", "api/v1/auth", "/auth; Domain=evil.example.com"] {
            let config = RefreshCookieConfig { path: bad.to_owned(), ..Default::default() };
            assert!(config.validate().is_err(), "accepted path {bad:?}");
        }
        for bad in ["", "enclave rt", "enclave;rt", "enclave=rt"] {
            let config = RefreshCookieConfig { name: bad.to_owned(), ..Default::default() };
            assert!(config.validate().is_err(), "accepted name {bad:?}");
        }
    }

    #[test]
    fn a_negative_max_age_never_becomes_a_negative_header() {
        let config = RefreshCookieConfig::default();
        let header = config
            .set_cookie_header(&RefreshToken::generate().expect("entropy"), Duration::seconds(-5));
        assert!(header.contains("; Max-Age=0"), "{header}");
    }
}
