use std::collections::HashSet;

use crate::Finding;

#[derive(Debug, Clone)]
pub struct Allowlist {
    ips: HashSet<String>,
    procs: HashSet<String>,
    descriptions: HashSet<String>,
    layers: HashSet<String>,
}

impl Allowlist {
    pub fn new() -> Self {
        Self {
            ips: HashSet::new(),
            procs: HashSet::new(),
            descriptions: HashSet::new(),
            layers: HashSet::new(),
        }
    }

    pub fn parse(content: &str) -> Self {
        let mut al = Self::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
            if parts.len() != 2 {
                continue;
            }
            match parts[0] {
                "ip" => { al.ips.insert(parts[1].trim().to_string()); }
                "proc" => { al.procs.insert(parts[1].trim().to_string()); }
                "desc" => {
                    let val = parts[1].trim();
                    // Strip surrounding quotes if present
                    let val = val.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(val);
                    al.descriptions.insert(val.to_string());
                }
                "layer" => { al.layers.insert(parts[1].trim().to_lowercase()); }
                _ => {}
            }
        }
        al
    }

    pub fn from_file(path: &str) -> Result<Self, std::io::Error> {
        let content = std::fs::read_to_string(path)?;
        Ok(Self::parse(&content))
    }

    pub fn is_ip_allowed(&self, ip: &str) -> bool {
        self.ips.contains(ip)
    }

    pub fn is_proc_allowed(&self, name: &str) -> bool {
        self.procs.contains(name)
    }

    pub fn is_description_allowed(&self, desc: &str) -> bool {
        self.descriptions.iter().any(|pattern| desc.contains(pattern.as_str()))
    }

    pub fn is_layer_allowed(&self, layer: &str) -> bool {
        self.layers.contains(&layer.to_lowercase())
    }

    /// Check if a finding should be filtered out by the allowlist.
    /// Returns true if the finding matches ANY allowlist criterion.
    pub fn should_allow(&self, finding: &Finding) -> bool {
        // Check layer
        if self.is_layer_allowed(&finding.layer) {
            return true;
        }

        // Check description pattern
        if self.is_description_allowed(&finding.description) {
            return true;
        }

        // Check if detail contains an allowlisted IP
        for ip in &self.ips {
            if finding.detail.contains(ip.as_str()) {
                return true;
            }
        }

        // Check if detail contains an allowlisted proc name (name=<procname> pattern)
        for proc_name in &self.procs {
            let pattern = format!("name={}", proc_name);
            if finding.detail.contains(&pattern) {
                return true;
            }
        }

        false
    }
}

impl Default for Allowlist {
    fn default() -> Self {
        Self::new()
    }
}
