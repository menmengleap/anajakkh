//! Authorized scope management.
//!
//! Every active assessment must have an explicit scope. This module
//! implements target parsing and validation: IPs, domains, CIDR ranges,
//! exclusions, and authorization state.

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::authorization::Authorization;

/// A single assessment target.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Target {
    /// A single IPv4/IPv6 address.
    Ip(IpAddr),
    /// A fully-qualified domain name (or apex domain).
    Domain(String),
    /// An IPv4 CIDR range `a.b.c.d/prefix`.
    Cidr { network: Ipv4Addr, prefix: u8 },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScopeError {
    #[error("target is empty")]
    EmptyTarget,
    #[error("invalid target: {0}")]
    InvalidTarget(String),
    #[error("scope must contain at least one target")]
    EmptyScope,
}

impl Target {
    /// Parse a single target string (IP, CIDR, or domain).
    pub fn parse(input: &str) -> Result<Self, ScopeError> {
        let s = input.trim();
        if s.is_empty() {
            return Err(ScopeError::EmptyTarget);
        }
        if let Ok(ip) = IpAddr::from_str(s) {
            return Ok(Target::Ip(ip));
        }
        if let Some((net, prefix)) = s.split_once('/') {
            let network = Ipv4Addr::from_str(net.trim())
                .map_err(|_| ScopeError::InvalidTarget(s.to_string()))?;
            let prefix = u8::from_str(prefix.trim())
                .map_err(|_| ScopeError::InvalidTarget(s.to_string()))?;
            if prefix > 32 {
                return Err(ScopeError::InvalidTarget(s.to_string()));
            }
            return Ok(Target::Cidr { network, prefix });
        }
        if is_valid_domain(s) {
            return Ok(Target::Domain(s.to_ascii_lowercase()));
        }
        Err(ScopeError::InvalidTarget(s.to_string()))
    }

    /// Best-effort extraction of candidate targets from free-form task text.
    pub fn from_task(text: &str) -> Vec<Target> {
        let mut found = Vec::new();
        // Split on non-target characters.
        for token in text.split(|c: char| {
            !(c.is_alphanumeric() || c == '.' || c == '-' || c == '/' || c == ':' || c == '_')
        }) {
            if token.is_empty() {
                continue;
            }
            if let Ok(target) = Target::parse(token) {
                if !found.contains(&target) {
                    found.push(target);
                }
            }
        }
        found
    }

    /// Does this target contain `other`? (domain containment, CIDR containment, equality)
    pub fn contains(&self, other: &Target) -> bool {
        match (self, other) {
            (Target::Ip(a), Target::Ip(b)) => a == b,
            (Target::Ip(_), _) => false,
            (Target::Domain(a), Target::Domain(b)) => b == a || b.ends_with(&format!(".{a}")),
            (Target::Domain(_), _) => false,
            (Target::Cidr { network, prefix }, Target::Ip(ip)) => match ip {
                IpAddr::V4(v4) => cidr_contains(*network, *prefix, *v4),
                IpAddr::V6(_) => false,
            },
            (
                Target::Cidr { network, prefix },
                Target::Cidr {
                    network: other,
                    prefix: op,
                },
            ) => {
                // A CIDR contains another if its prefix is shorter/equal and networks align.
                *op >= *prefix
                    && u32::from(*other) & mask(*prefix) == u32::from(*network) & mask(*prefix)
            }
            (Target::Cidr { .. }, _) => false,
        }
    }

    pub fn display(&self) -> String {
        match self {
            Target::Ip(ip) => ip.to_string(),
            Target::Domain(d) => d.clone(),
            Target::Cidr { network, prefix } => format!("{network}/{prefix}"),
        }
    }
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn cidr_contains(network: Ipv4Addr, prefix: u8, ip: Ipv4Addr) -> bool {
    u32::from(ip) & mask(prefix) == u32::from(network) & mask(prefix)
}

fn is_valid_domain(s: &str) -> bool {
    let s = s.trim_end_matches('.');
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    if !s.contains('.') {
        return false;
    }
    // A dotted all-numeric string is an attempted IP, not a domain.
    if s.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// The authorized scope for an assessment.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Scope {
    pub scope_id: String,
    pub targets: Vec<Target>,
    pub excluded_targets: Vec<Target>,
    pub authorized: bool,
    /// Audit record of who authorized/revoked this scope.
    pub authorization: Option<Authorization>,
}

impl Scope {
    pub fn new(scope_id: impl Into<String>) -> Self {
        Self {
            scope_id: scope_id.into(),
            targets: Vec::new(),
            excluded_targets: Vec::new(),
            authorized: true,
            authorization: None,
        }
    }

    /// Parse a scope definition. Targets prefixed with `!` are exclusions.
    ///
    /// Accepts comma, semicolon, or whitespace separated lists.
    pub fn parse(scope_id: impl Into<String>, input: &str) -> Result<Self, ScopeError> {
        let mut scope = Self::new(scope_id);
        for part in input.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some(excl) = part.strip_prefix('!') {
                scope.excluded_targets.push(Target::parse(excl)?);
            } else {
                scope.targets.push(Target::parse(part)?);
            }
        }
        if scope.targets.is_empty() {
            return Err(ScopeError::EmptyScope);
        }
        Ok(scope)
    }

    /// Is `target` authorized? (in scope and not excluded)
    pub fn contains(&self, target: &Target) -> bool {
        if !self.authorized {
            return false;
        }
        let in_scope = self.targets.iter().any(|t| t.contains(target));
        let excluded = self.excluded_targets.iter().any(|t| t.contains(target));
        in_scope && !excluded
    }

    /// Return the subset of `targets` that are outside this scope.
    pub fn out_of_scope(&self, targets: &[Target]) -> Vec<Target> {
        targets
            .iter()
            .filter(|t| !self.contains(t))
            .cloned()
            .collect()
    }

    /// Explicitly authorize this scope, recording an audit entry.
    pub fn authorize(&mut self, by: impl Into<String>) {
        self.authorized = true;
        let mut record = match &self.authorization {
            Some(existing) => existing.clone(),
            None => Authorization::new(self.scope_id.clone()),
        };
        record.grant(by);
        self.authorization = Some(record);
    }

    /// Revoke authorization for this scope.
    pub fn revoke(&mut self) {
        self.authorized = false;
        if let Some(record) = self.authorization.as_mut() {
            record.revoke();
        }
    }

    /// The authorization record, if one exists.
    pub fn authorization(&self) -> Option<&Authorization> {
        self.authorization.as_ref()
    }

    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = self.targets.iter().map(|t| t.display()).collect();
        parts.sort();
        let mut s = parts.join(", ");
        if !self.excluded_targets.is_empty() {
            let excl: Vec<String> = self.excluded_targets.iter().map(|t| t.display()).collect();
            s.push_str(&format!(" (excluded: {})", excl.join(", ")));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ip_domain_cidr() {
        assert_eq!(
            Target::parse("10.0.0.1").unwrap(),
            Target::Ip(IpAddr::from([10, 0, 0, 1]))
        );
        assert_eq!(
            Target::parse("example.com").unwrap(),
            Target::Domain("example.com".to_string())
        );
        assert_eq!(
            Target::parse("10.0.0.0/8").unwrap(),
            Target::Cidr {
                network: Ipv4Addr::from([10, 0, 0, 0]),
                prefix: 8
            }
        );
    }

    #[test]
    fn rejects_invalid_targets() {
        assert!(Target::parse("").is_err());
        assert!(Target::parse("not a domain").is_err());
        assert!(Target::parse("999.1.1.1").is_err());
        assert!(Target::parse("10.0.0.0/33").is_err());
        assert!(Target::parse("10.0.0.0/abc").is_err());
    }

    #[test]
    fn cidr_containment() {
        let scope = Scope::parse("s1", "10.0.0.0/8").unwrap();
        assert!(scope.contains(&Target::parse("10.1.2.3").unwrap()));
        assert!(!scope.contains(&Target::parse("11.0.0.1").unwrap()));
    }

    #[test]
    fn domain_containment() {
        let scope = Scope::parse("s1", "example.com").unwrap();
        assert!(scope.contains(&Target::parse("example.com").unwrap()));
        assert!(scope.contains(&Target::parse("www.example.com").unwrap()));
        assert!(!scope.contains(&Target::parse("notexample.com").unwrap()));
        assert!(!scope.contains(&Target::parse("example.org").unwrap()));
    }

    #[test]
    fn exclusions_win() {
        let scope = Scope::parse("s1", "10.0.0.0/8, !10.0.0.5").unwrap();
        assert!(scope.contains(&Target::parse("10.0.0.4").unwrap()));
        assert!(!scope.contains(&Target::parse("10.0.0.5").unwrap()));
    }

    #[test]
    fn unauthorized_scope_allows_nothing() {
        let mut scope = Scope::parse("s1", "example.com").unwrap();
        scope.authorized = false;
        assert!(!scope.contains(&Target::parse("example.com").unwrap()));
    }

    #[test]
    fn empty_scope_rejected() {
        assert_eq!(
            Scope::parse("s1", "   ").unwrap_err(),
            ScopeError::EmptyScope
        );
    }

    #[test]
    fn authorize_and_revoke_scope() {
        let mut scope = Scope::parse("s1", "example.com").unwrap();
        assert!(scope.authorized);
        assert!(scope.authorization.is_none());

        scope.revoke();
        assert!(!scope.authorized);
        assert!(!scope.contains(&Target::parse("example.com").unwrap()));

        scope.authorize("operator");
        assert!(scope.authorized);
        assert!(scope.contains(&Target::parse("example.com").unwrap()));
        let record = scope.authorization().expect("record exists");
        assert!(record.is_authorized());
        assert_eq!(record.granted_by.as_deref(), Some("operator"));
    }

    #[test]
    fn extracts_targets_from_task() {
        let targets = Target::from_task("scan example.com and 10.0.0.0/24 and 192.168.1.10");
        assert_eq!(targets.len(), 3);
        assert!(targets.contains(&Target::parse("example.com").unwrap()));
        assert!(targets.contains(&Target::parse("10.0.0.0/24").unwrap()));
    }
}
