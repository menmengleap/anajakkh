//! Authorization: an audit record for granting/revoking assessment scope.
//!
//! A scope becomes *authorized* through an explicit user action. This
//! module tracks who granted it and when, and exposes a single
//! `is_authorized()` gate that every policy check must pass.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Lifecycle state of an authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorizationStatus {
    /// No authorization has been granted yet.
    Unauthorized,
    /// Explicitly granted.
    Authorized,
    /// Granted earlier, then revoked.
    Revoked,
}

/// An authorization record attached to a [`crate::security::Scope`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authorization {
    pub scope_id: String,
    pub status: AuthorizationStatus,
    pub granted_by: Option<String>,
    pub granted_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl Authorization {
    pub fn new(scope_id: impl Into<String>) -> Self {
        Self {
            scope_id: scope_id.into(),
            status: AuthorizationStatus::Unauthorized,
            granted_by: None,
            granted_at: None,
            revoked_at: None,
        }
    }

    /// Grant authorization, recording who granted it and when.
    pub fn grant(&mut self, by: impl Into<String>) {
        self.status = AuthorizationStatus::Authorized;
        self.granted_by = Some(by.into());
        self.granted_at = Some(Utc::now());
        self.revoked_at = None;
    }

    /// Revoke a previously granted authorization.
    pub fn revoke(&mut self) {
        if self.status == AuthorizationStatus::Authorized {
            self.status = AuthorizationStatus::Revoked;
            self.revoked_at = Some(Utc::now());
        }
    }

    pub fn is_authorized(&self) -> bool {
        self.status == AuthorizationStatus::Authorized
    }
}

impl Default for Authorization {
    fn default() -> Self {
        Self::new("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_revoke_lifecycle() {
        let mut auth = Authorization::new("scope-1");
        assert_eq!(auth.status, AuthorizationStatus::Unauthorized);
        assert!(!auth.is_authorized());

        auth.grant("operator");
        assert!(auth.is_authorized());
        assert_eq!(auth.granted_by.as_deref(), Some("operator"));
        assert!(auth.granted_at.is_some());

        auth.revoke();
        assert!(!auth.is_authorized());
        assert_eq!(auth.status, AuthorizationStatus::Revoked);
        assert!(auth.revoked_at.is_some());
    }

    #[test]
    fn revoking_an_unauthorized_record_is_a_noop() {
        let mut auth = Authorization::new("scope-2");
        auth.revoke();
        assert_eq!(auth.status, AuthorizationStatus::Unauthorized);
    }
}
