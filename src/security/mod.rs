//! Security boundary: scoped, authorized assessment targets.
//!
//! - `scope` — target parsing, CIDR/domain containment, exclusions.
//! - `authorization` — explicit grant/revoke of scope authorization.
//! - `policy` — risk-based rules gating tool execution.
//! - `approval` — explicit operator sign-off for dangerous operations.

pub mod approval;
pub mod authorization;
pub mod policy;
pub mod scope;

pub use approval::{ApprovalError, ApprovalRequest, ApprovalStatus, ApprovalSystem};
pub use authorization::{Authorization, AuthorizationStatus};
pub use policy::{Policy, PolicyDecision};
pub use scope::{Scope, ScopeError, Target};
