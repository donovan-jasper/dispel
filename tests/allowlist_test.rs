use dispel::allowlist::Allowlist;

#[test]
fn test_parse_allowlist() {
    let content = r#"
# Known infrastructure IPs
ip 10.100.100.2
ip 192.168.220.2

# Known-good processes
proc sshd
proc httpd
proc named
"#;
    let al = Allowlist::parse(content);
    assert!(al.is_ip_allowed("10.100.100.2"));
    assert!(!al.is_ip_allowed("10.0.0.1"));
    assert!(al.is_proc_allowed("sshd"));
    assert!(!al.is_proc_allowed("imix"));
}

#[test]
fn test_empty_allowlist() {
    let al = Allowlist::new();
    assert!(!al.is_ip_allowed("10.0.0.1"));
    assert!(!al.is_proc_allowed("anything"));
}

#[test]
fn test_allowlist_ignores_comments_and_blanks() {
    let content = "# comment\n\n  \nip 1.2.3.4\n";
    let al = Allowlist::parse(content);
    assert!(al.is_ip_allowed("1.2.3.4"));
}
