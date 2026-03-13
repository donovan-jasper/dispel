#[cfg(windows)]
use super::ProcessInfo;

#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};
#[cfg(windows)]
use windows_sys::Win32::Foundation::CloseHandle;

#[cfg(windows)]
pub fn enumerate_processes() -> Vec<ProcessInfo> {
    let mut procs = Vec::new();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return procs;
        }

        let mut entry: PROCESSENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut entry) != 0 {
            loop {
                let name = entry
                    .szExeFile
                    .iter()
                    .take_while(|&&c| c != 0)
                    .map(|&c| c as u8 as char)
                    .collect::<String>();

                let exe_path = get_process_image_path(entry.th32ProcessID);

                procs.push(ProcessInfo {
                    pid: entry.th32ProcessID,
                    name,
                    exe_path,
                    deleted_exe: false,
                    thread_count: entry.cntThreads,
                });

                if Process32Next(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
    }

    procs
}

#[cfg(windows)]
fn get_process_image_path(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }

        let mut buffer = [0u16; 1024];
        let mut size = buffer.len() as u32;

        let result = QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size);
        CloseHandle(handle);

        if result != 0 {
            Some(String::from_utf16_lossy(&buffer[..size as usize]))
        } else {
            None
        }
    }
}

#[cfg(windows)]
pub fn check_timestomp(binary_path: &str) -> bool {
    use std::fs;
    let cmd_meta = match fs::metadata(r"C:\Windows\System32\cmd.exe") {
        Ok(m) => m,
        Err(_) => return false,
    };
    let bin_meta = match fs::metadata(binary_path) {
        Ok(m) => m,
        Err(_) => return false,
    };
    match (cmd_meta.modified(), bin_meta.modified()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

#[cfg(windows)]
pub fn read_tcp_connections() -> Vec<WindowsTcpConnection> {
    use std::process::Command;

    let mut connections = Vec::new();

    let output = Command::new("netstat")
        .args(["-ano", "-p", "TCP"])
        .output();

    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines().skip(4) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 && parts[0] == "TCP" {
                if let (Some(local), Some(remote)) = (
                    parse_windows_addr(parts[1]),
                    parse_windows_addr(parts[2]),
                ) {
                    let pid: u32 = parts[4].parse().unwrap_or(0);
                    connections.push(WindowsTcpConnection {
                        local_addr: local.0,
                        local_port: local.1,
                        remote_addr: remote.0,
                        remote_port: remote.1,
                        state: parts[3].to_string(),
                        owning_pid: pid,
                    });
                }
            }
        }
    }

    connections
}

#[cfg(windows)]
#[derive(Debug, Clone)]
pub struct WindowsTcpConnection {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub owning_pid: u32,
}

#[cfg(windows)]
fn parse_windows_addr(s: &str) -> Option<(String, u16)> {
    if let Some(last_colon) = s.rfind(':') {
        let addr = &s[..last_colon];
        let port: u16 = s[last_colon + 1..].parse().ok()?;
        Some((addr.to_string(), port))
    } else {
        None
    }
}

// Windows registry check for Realm C2 persistence
#[cfg(windows)]
pub fn check_registry_imix() -> Vec<crate::Finding> {
    use crate::{Finding, Tier};
    use crate::scan::persist::is_uuid_v4;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ,
    };

    let mut findings = Vec::new();

    unsafe {
        let subkey: Vec<u16> = "SOFTWARE\\Imix\0".encode_utf16().collect();
        let mut hkey: windows_sys::Win32::System::Registry::HKEY = std::ptr::null_mut();

        let status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        );

        if status == 0 {
            findings.push(Finding::new(
                "persist",
                "Registry key HKLM\\SOFTWARE\\Imix exists",
                Tier::Tier1,
                "HKLM\\SOFTWARE\\Imix",
            ));

            let value_name: Vec<u16> = "system-id\0".encode_utf16().collect();
            let mut data = [0u8; 256];
            let mut data_size = data.len() as u32;
            let mut data_type = 0u32;

            let val_status = RegQueryValueExW(
                hkey,
                value_name.as_ptr(),
                std::ptr::null(),
                &mut data_type,
                data.as_mut_ptr(),
                &mut data_size,
            );

            if val_status == 0 && data_type == REG_SZ {
                let uuid_bytes = &data[..data_size as usize];
                let uuid_str = String::from_utf16_lossy(
                    &uuid_bytes
                        .chunks(2)
                        .filter_map(|c| {
                            if c.len() == 2 {
                                Some(u16::from_le_bytes([c[0], c[1]]))
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<u16>>(),
                );
                let trimmed = uuid_str.trim_end_matches('\0');
                if is_uuid_v4(trimmed) {
                    findings.push(Finding::new(
                        "persist",
                        "Beacon ID found in registry",
                        Tier::Tier2,
                        format!("HKLM\\SOFTWARE\\Imix\\system-id = {}", trimmed),
                    ));
                }
            }

            RegCloseKey(hkey);
        }
    }

    findings
}

// Windows service check
#[cfg(windows)]
pub fn check_windows_services() -> Vec<crate::Finding> {
    use crate::{Finding, Tier};
    use std::process::Command;

    let mut findings = Vec::new();

    for svc_name in crate::signatures::strings::TIER1_SERVICE_NAMES {
        let output = Command::new("sc.exe")
            .args(["query", svc_name])
            .output();

        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.contains("RUNNING")
                || stdout.contains("STOPPED")
                || stdout.contains("PAUSED")
            {
                findings.push(Finding::new(
                    "persist",
                    format!("Windows service '{}' exists", svc_name),
                    Tier::Tier1,
                    stdout.lines().take(5).collect::<Vec<_>>().join(" | "),
                ));
            }
        }
    }

    findings
}
