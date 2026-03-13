#[cfg(target_os = "linux")]
mod linux_tests {
    use dispel::platform::linux::enumerate_processes;

    #[test]
    fn enumerate_processes_returns_non_empty() {
        let procs = enumerate_processes();
        assert!(!procs.is_empty(), "should find at least one running process");
    }

    #[test]
    fn at_least_one_process_has_exe_path() {
        let procs = enumerate_processes();
        let has_exe = procs.iter().any(|p| p.exe_path.is_some());
        assert!(has_exe, "at least one process should have a resolved exe path");
    }

    #[test]
    fn current_process_is_found_and_not_deleted() {
        let current_pid = std::process::id();
        let procs = enumerate_processes();
        let current = procs.iter().find(|p| p.pid == current_pid);
        assert!(
            current.is_some(),
            "current process (pid={}) should appear in enumeration",
            current_pid
        );
        let p = current.unwrap();
        assert!(
            !p.deleted_exe,
            "current process executable should not be marked deleted"
        );
    }

    #[test]
    fn current_process_has_thread_count_at_least_one() {
        let current_pid = std::process::id();
        let procs = enumerate_processes();
        let current = procs.iter().find(|p| p.pid == current_pid);
        if let Some(p) = current {
            assert!(
                p.thread_count >= 1,
                "thread count should be at least 1, got {}",
                p.thread_count
            );
        }
    }

    #[test]
    fn read_tcp_connections_does_not_panic() {
        // Just verify it runs without panicking; /proc/net/tcp may or may not exist
        let _conns = dispel::platform::linux::read_tcp_connections();
    }
}
