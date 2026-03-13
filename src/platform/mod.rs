#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub mod bsd;

#[cfg(windows)]
pub mod windows;

/// Portable process information struct used across scan layers.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Process ID.
    pub pid: u32,
    /// Parent process ID.
    pub ppid: u32,
    /// Process name (basename of executable).
    pub name: String,
    /// Full path to the executable, if available.
    pub exe_path: Option<String>,
    /// Command-line arguments, if available.
    pub cmdline: Option<String>,
}
