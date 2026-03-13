use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct Allowlist {
    ips: HashSet<String>,
    procs: HashSet<String>,
}

impl Allowlist {
    pub fn new() -> Self {
        Self {
            ips: HashSet::new(),
            procs: HashSet::new(),
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
}

impl Default for Allowlist {
    fn default() -> Self {
        Self::new()
    }
}
