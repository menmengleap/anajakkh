//! Result parser: converts tool output into structured evidence.
//!
//! Tools that produce structured `data` (DNS, HTTP, filesystem) are
//! converted directly. Nmap's grepable output is parsed line-by-line into
//! host and service records. Anything unparseable becomes a single `Raw`
//! evidence record — raw output is never lost.

use std::collections::HashMap;

use serde_json::{json, Value};

use super::models::{Evidence, EvidenceType};

/// Convert a tool's raw output + structured data into evidence records.
///
/// `data` (from [`crate::tools::ToolResult::data`]) is preferred when
/// present; otherwise `raw_output` is parsed. If nothing can be parsed, a
/// single `Raw` record preserves the output.
pub fn parse_tool_output(
    tool: &str,
    target: &str,
    raw_output: &str,
    data: &Value,
) -> Vec<Evidence> {
    let mut items: Vec<Evidence> = match tool {
        "nmap" => parse_nmap(raw_output),
        "dns" => structured(data, tool, target, EvidenceType::DnsRecord),
        "http" => structured(data, tool, target, EvidenceType::HttpResponse),
        "filesystem" => structured(data, tool, target, EvidenceType::FileInfo),
        _ => Vec::new(),
    };

    if items.is_empty() {
        let capped = truncate(raw_output, 8192);
        items.push(Evidence::new(
            EvidenceType::Raw,
            tool,
            target,
            json!({ "raw": capped, "truncated": capped != raw_output }),
        ));
    }
    items
}

/// Convert a structured `data` payload into evidence: one record per array
/// element, or a single record for a non-array value.
fn structured(data: &Value, tool: &str, target: &str, ty: EvidenceType) -> Vec<Evidence> {
    match data {
        Value::Array(items) => items
            .iter()
            .map(|item| Evidence::new(ty, tool, target, item.clone()))
            .collect(),
        Value::Null => Vec::new(),
        _ => vec![Evidence::new(ty, tool, target, data.clone())],
    }
}

/// Parse nmap grepable (`-oG`) output into host + service evidence.
///
/// Format of relevant lines:
/// ```text
/// Host: 93.184.216.34 (example.com)  Status: Up
/// Host: 93.184.216.34 (example.com)  Ports: 22/filtered/tcp//ssh///, 80/open/tcp//http///
/// ```
pub fn parse_nmap(raw: &str) -> Vec<Evidence> {
    let mut hosts: HashMap<String, (String, String)> = HashMap::new(); // ip -> (hostname, status)
    let mut port_lines: Vec<(String, String)> = Vec::new(); // (ip, ports field)

    for line in raw.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("Host: ") else {
            continue;
        };
        let mut fields = rest.split('\t');
        let host_part = fields.next().unwrap_or_default().trim();
        let (ip, hostname) = parse_host(host_part);
        if ip.is_empty() {
            continue;
        }
        for field in fields {
            let field = field.trim();
            if let Some(status) = field.strip_prefix("Status: ") {
                hosts
                    .entry(ip.clone())
                    .or_insert_with(|| (hostname.clone(), String::new()))
                    .1 = status.to_string();
            } else if let Some(ports) = field.strip_prefix("Ports: ") {
                port_lines.push((ip.clone(), ports.to_string()));
            }
        }
    }

    let mut evidence: Vec<Evidence> = Vec::new();
    for (ip, (hostname, status)) in &hosts {
        let mut data = json!({ "ip": ip, "status": status });
        if !hostname.is_empty() {
            data["hostname"] = json!(hostname);
        }
        evidence.push(Evidence::new(EvidenceType::Host, "nmap", ip, data));
    }

    for (ip, ports) in port_lines {
        // Ensure a host record exists even if only a Ports line appeared.
        if !hosts.contains_key(&ip) {
            evidence.push(Evidence::new(
                EvidenceType::Host,
                "nmap",
                &ip,
                json!({ "ip": ip, "status": "" }),
            ));
        }
        for entry in ports.split(", ") {
            let parts: Vec<&str> = entry.split('/').collect();
            if parts.len() < 4 {
                continue;
            }
            let port = parts[0].parse::<u16>().unwrap_or(0);
            if port == 0 {
                continue;
            }
            let state = parts[1];
            let protocol = parts[2];
            let service = parts.get(4).copied().unwrap_or_default();
            let mut data = json!({
                "ip": ip,
                "port": port,
                "protocol": protocol,
                "state": state,
            });
            if !service.is_empty() {
                data["service"] = json!(service);
            }
            evidence.push(Evidence::new(EvidenceType::Service, "nmap", &ip, data));
        }
    }
    evidence
}

/// Host/service counts from nmap grepable output, for tool summaries.
pub fn nmap_counts(raw: &str) -> (usize, usize) {
    let items = parse_nmap(raw);
    let hosts = items
        .iter()
        .filter(|e| e.r#type == EvidenceType::Host)
        .count();
    let services = items
        .iter()
        .filter(|e| e.r#type == EvidenceType::Service)
        .count();
    (hosts, services)
}

/// Parse `"93.184.216.34 (example.com)"` into `(ip, hostname)`.
fn parse_host(host_part: &str) -> (String, String) {
    let host_part = host_part.trim();
    if let Some(open) = host_part.find('(') {
        let ip = host_part[..open].trim().to_string();
        let hostname = host_part[open + 1..]
            .trim_end_matches(')')
            .trim()
            .to_string();
        (ip, hostname)
    } else {
        (host_part.to_string(), String::new())
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NMAP_SAMPLE: &str = "\
# Nmap 7.80 scan initiated Mon Jan  1 00:00:00 2024 as: nmap -oG - -Pn -p 22,80 example.com
Host: 93.184.216.34 (example.com)\tStatus: Up
Host: 93.184.216.34 (example.com)\tPorts: 22/filtered/tcp//ssh///, 80/open/tcp//http///
Host: 93.184.216.35 ()\tPorts: 443/open/tcp//https///
# Nmap done at Mon Jan  1 00:00:01 2024 -- 2 IP addresses (2 hosts up) scanned in 0.41 seconds
";

    #[test]
    fn parses_nmap_hosts_and_services() {
        let items = parse_nmap(NMAP_SAMPLE);
        let hosts: Vec<&Evidence> = items
            .iter()
            .filter(|e| e.r#type == EvidenceType::Host)
            .collect();
        let services: Vec<&Evidence> = items
            .iter()
            .filter(|e| e.r#type == EvidenceType::Service)
            .collect();

        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].target, "93.184.216.34");
        assert_eq!(hosts[0].data["hostname"], "example.com");
        assert_eq!(hosts[0].data["status"], "Up");
        // Empty hostname is omitted from the data.
        assert_eq!(hosts[1].target, "93.184.216.35");
        assert!(hosts[1].data.get("hostname").is_none());

        assert_eq!(services.len(), 3);
        let ssh = services
            .iter()
            .find(|s| s.data["port"] == 22)
            .expect("ssh entry");
        assert_eq!(ssh.data["state"], "filtered");
        assert_eq!(ssh.data["service"], "ssh");
        let http = services
            .iter()
            .find(|s| s.data["port"] == 80)
            .expect("http entry");
        assert_eq!(http.data["protocol"], "tcp");
    }

    #[test]
    fn nmap_counts_are_accurate() {
        assert_eq!(nmap_counts(NMAP_SAMPLE), (2, 3));
        assert_eq!(nmap_counts(""), (0, 0));
    }

    #[test]
    fn structured_data_becomes_evidence() {
        let data = json!([
            { "name": "example.com", "addresses": ["93.184.216.34"] },
        ]);
        let items = parse_tool_output("dns", "example.com", "", &data);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].r#type, EvidenceType::DnsRecord);
        assert_eq!(items[0].source, "dns");
        assert_eq!(items[0].data["addresses"][0], "93.184.216.34");
    }

    #[test]
    fn unparseable_output_becomes_raw_evidence() {
        let items = parse_tool_output("mystery-tool", "x", "some bytes", &Value::Null);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].r#type, EvidenceType::Raw);
        assert_eq!(items[0].data["raw"], "some bytes");
    }

    #[test]
    fn empty_nmap_output_falls_back_to_raw() {
        let items = parse_tool_output("nmap", "10.0.0.1", "", &Value::Null);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].r#type, EvidenceType::Raw);
    }

    #[test]
    fn evidence_hashes_are_set() {
        for item in parse_nmap(NMAP_SAMPLE) {
            assert_eq!(item.sha256.len(), 64);
        }
    }
}
