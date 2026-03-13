# Enhanced In-Memory Implant Detection

**Goal:** Detect Realm C2 imix agent running in memory even when the binary has been deleted from disk, loaded via memfd, injected into another process, or otherwise hidden from filesystem-based detection.

**Architecture:** New `src/scan/memory.rs` module with platform-specific implementations behind `#[cfg()]`. Reuses existing `BinaryScanner` for signature matching. Integrated into scan orchestration alongside existing proc/net/persist/behavior layers.

**Platforms:** Linux (primary, /proc-based), Windows (VirtualQueryEx + ReadProcessMemory)

---

## Linux Detection Techniques

### 1. Process Memory Scanning (`/proc/<pid>/mem`)
- Parse `/proc/<pid>/maps` to get readable memory regions
- Use `pread()` on `/proc/<pid>/mem` to read each region
- Run existing Aho-Corasick signatures against live memory contents
- Catches decrypted/unpacked strings that disk-only scanning misses
- Skip regions that are file-backed by known-safe paths (libc, ld-linux, etc.)

### 2. Anonymous Executable Region Detection (`/proc/<pid>/maps`)
- Parse maps for `r-xp` or `rwxp` regions with no backing file (inode=0, no pathname)
- Rust binaries should never have anonymous RWX regions
- Also detect `memfd:` backed executable regions
- Finding: Behavioral tier for anonymous exec, Tier2 for memfd exec

### 3. Process Masquerading Detection
- Compare `/proc/<pid>/exe` symlink target against `/proc/<pid>/cmdline` argv[0]
- Flag mismatches (e.g., exe=/tmp/imix but cmdline claims /usr/bin/sshd)
- Finding: Behavioral tier

### 4. memfd File Descriptor Detection
- Scan `/proc/<pid>/fd/` symlinks for `memfd:` targets
- A process with memfd FDs is suspicious (fileless execution staging)
- Finding: Behavioral tier

### 5. Suspicious Shared Library Paths
- Parse `/proc/<pid>/maps` for .so files loaded from /tmp, /dev/shm, /var/tmp, or hidden dirs
- Finding: Behavioral tier

### 6. Environment Variable Inspection
- Read `/proc/<pid>/environ` for IMIX_*, CALLBACK_*, C2_*, BEACON_* variables
- Finding: Tier2 (strong indicator if IMIX-specific vars found)

## Windows Detection Techniques

### 1. Private Executable Memory Detection
- `VirtualQueryEx` loop over target process memory
- Flag `MEM_PRIVATE` regions with `PAGE_EXECUTE*` protection
- Normal code lives in `MEM_IMAGE` regions; private executable = injected code
- Finding: Behavioral tier

### 2. Thread Start Address Validation
- Enumerate threads via `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)`
- `NtQueryInformationThread` to get each thread's start address
- Check if start address falls in `MEM_PRIVATE` vs `MEM_IMAGE` region
- Finding: Tier2 for threads from private memory

### 3. Process Memory Scanning
- `ReadProcessMemory` to read process memory contents
- Run Aho-Corasick signatures against memory
- Finding: Same tiers as binary scanning

## Integration

- New `Layer::Memory` variant (or fold into existing `Proc` layer)
- `scan::memory::scan(verbose) -> ScanResult`
- Called from CLI scan/watch orchestration
- Self-exclusion: skip own PID

## Testing

### Linux (tython - 10.100.100.201)
1. Deploy imix, scan with memory module, verify detection
2. Delete imix from disk while running, verify memory scan still detects
3. Rename binary + set misleading argv[0], verify masquerading detection
4. Baseline clean system, verify 0 false positives

### Windows (tat10ine - 10.100.100.9 or kamino - 10.100.100.11)
1. Deploy imix.exe, scan with memory module, verify detection
2. Test private executable region detection
3. Baseline clean system, verify 0 false positives
