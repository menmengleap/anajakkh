//! JSON report renderer.

use anyhow::Result;

use super::Report;

/// Render `report` as pretty-printed JSON.
pub fn render(report: &Report) -> Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{Finding, Severity};
    use serde_json::Value;
    use std::path::PathBuf;

    #[test]
    fn json_is_valid_and_contains_sections() {
        let finding = Finding::observed(
            "SSH exposed",
            Severity::Low,
            "10.0.0.1",
            "port 22",
            None,
            vec!["ev-1".to_string()],
        );
        let report = Report::new(
            "s1",
            PathBuf::from("/tmp"),
            None,
            vec!["10.0.0.1".to_string()],
            None,
            vec![],
            vec![finding],
        );
        let json = render(&report).unwrap();
        let value: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["session_id"], "s1");
        assert_eq!(value["findings"][0]["severity"], "low");
        assert_eq!(value["findings"][0]["evidence_ids"][0], "ev-1");
        assert_eq!(value["evidence"].as_array().unwrap().len(), 0);
        assert!(value["generated_at"].is_string());
    }
}
