use dispel::scan::behavior::is_shell_binary;

// ---------------------------------------------------------------------------
// is_shell_binary — positive cases
// ---------------------------------------------------------------------------

#[test]
fn test_is_shell_binary_bash_full_path() {
    assert!(is_shell_binary("/bin/bash"));
}

#[test]
fn test_is_shell_binary_sh_full_path() {
    assert!(is_shell_binary("/bin/sh"));
}

#[test]
fn test_is_shell_binary_zsh_usr_bin() {
    assert!(is_shell_binary("/usr/bin/zsh"));
}

#[test]
fn test_is_shell_binary_dash() {
    assert!(is_shell_binary("/bin/dash"));
}

#[test]
fn test_is_shell_binary_csh() {
    assert!(is_shell_binary("/bin/csh"));
}

#[test]
fn test_is_shell_binary_tcsh() {
    assert!(is_shell_binary("/bin/tcsh"));
}

#[test]
fn test_is_shell_binary_powershell_exe() {
    assert!(is_shell_binary("powershell.exe"));
}

#[test]
fn test_is_shell_binary_pwsh_exe() {
    assert!(is_shell_binary("pwsh.exe"));
}

#[test]
fn test_is_shell_binary_cmd_exe() {
    assert!(is_shell_binary("cmd.exe"));
}

#[test]
fn test_is_shell_binary_powershell_no_ext() {
    assert!(is_shell_binary("powershell"));
}

// ---------------------------------------------------------------------------
// is_shell_binary — negative cases
// ---------------------------------------------------------------------------

#[test]
fn test_is_shell_binary_httpd_rejected() {
    assert!(!is_shell_binary("/usr/bin/httpd"));
}

#[test]
fn test_is_shell_binary_python_rejected() {
    assert!(!is_shell_binary("/usr/bin/python3"));
}

#[test]
fn test_is_shell_binary_empty_rejected() {
    assert!(!is_shell_binary(""));
}

#[test]
fn test_is_shell_binary_nginx_rejected() {
    assert!(!is_shell_binary("/usr/sbin/nginx"));
}

// ---------------------------------------------------------------------------
// check_fd_redirected_to_socket (Linux only)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_behavior {
    use dispel::scan::behavior::check_fd_redirected_to_socket;
    use dispel::Tier;

    #[test]
    fn test_shell_with_socket_fd_detected() {
        let fds = [("socket:[12345]", true), ("/dev/pts/0", false)];
        let finding = check_fd_redirected_to_socket(&fds, "bash", 1234);
        assert!(finding.is_some(), "expected finding for shell with socket fd");

        let finding = finding.unwrap();
        assert_eq!(finding.layer, "behavior");
        assert_eq!(finding.tier, Tier::Behavioral);
        assert!(finding.description.contains("reverse shell"));
        assert!(finding.detail.contains("1234"));
        assert!(finding.detail.contains("bash"));
    }

    #[test]
    fn test_shell_with_ptmx_fd_detected() {
        let fds = [("/dev/ptmx", false), ("/dev/null", false)];
        let finding = check_fd_redirected_to_socket(&fds, "sh", 5678);
        assert!(finding.is_some(), "expected finding for shell with ptmx fd");
    }

    #[test]
    fn test_shell_without_socket_not_flagged() {
        let fds = [
            ("/dev/pts/1", false),
            ("/dev/null", false),
            ("/tmp/somefile", false),
        ];
        let finding = check_fd_redirected_to_socket(&fds, "bash", 9999);
        assert!(finding.is_none(), "shell with no socket fds should not be flagged");
    }

    #[test]
    fn test_non_shell_with_socket_not_flagged() {
        let fds = [("socket:[99999]", true)];
        let finding = check_fd_redirected_to_socket(&fds, "httpd", 100);
        assert!(
            finding.is_none(),
            "non-shell process with socket should not be flagged as reverse shell"
        );
    }

    #[test]
    fn test_socket_prefix_string_detected() {
        // is_socket=false but target starts with "socket:" — should still detect
        let fds = [("socket:[77777]", false)];
        let finding = check_fd_redirected_to_socket(&fds, "zsh", 2222);
        assert!(finding.is_some());
    }
}
