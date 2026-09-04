//! Keeping a session's data keys out of swap and out of crash dumps
//! (plan/06-roadmap.md M11).
//!
//! A data key held for the duration of one command is unlikely to be paged out. One
//! held for an hour — which is what [`crate::session`] introduced — is a different
//! proposition, and so is a crash dump of a process that has several vaults open at
//! once. This module is the answer to both:
//!
//! - [`SecretKey`] holds 32 bytes in its own page-aligned allocation, pinned with
//!   `mlock` (`VirtualLock` on Windows) so the kernel will not write it to swap, and
//!   zeroized before the page is released.
//! - [`suppress_core_dumps`] stops the process being dumped at all.
//!
//! # What this is and is not
//!
//! This is defence in depth, not a guarantee. It does not protect against an
//! attacker who can already read this process's memory with the same privileges,
//! and it cannot pin the *decrypted payload* of a store — a directory tree can be
//! gigabytes, far beyond any `RLIMIT_MEMLOCK`. What it does buy is that the 32 bytes
//! which open a vault do not end up in a swap file or a core file, which is exactly
//! the exposure a long-lived session adds.
//!
//! Every operation here reports whether it actually worked, rather than being
//! assumed; the session prints that status at startup, because "we tried to lock
//! memory" and "memory is locked" are different claims.

use std::alloc::Layout;
use std::ops::Deref;
use std::ptr::NonNull;

use zeroize::Zeroize;

/// Whether one hardening measure is actually in force.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Support {
    /// Applied successfully.
    Enabled,
    /// The platform supports it, but the attempt failed — typically a resource
    /// limit. Carries the reason, because the fix is usually the user's to make.
    Failed(String),
    /// Not implemented on this platform, and why.
    Unsupported(&'static str),
}

impl Support {
    pub fn is_enabled(&self) -> bool {
        matches!(self, Support::Enabled)
    }
}

impl std::fmt::Display for Support {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Support::Enabled => f.write_str("enabled"),
            Support::Failed(why) => write!(f, "FAILED ({why})"),
            Support::Unsupported(why) => write!(f, "not available ({why})"),
        }
    }
}

/// What is actually in force for this process.
#[derive(Debug, Clone)]
pub struct Hardening {
    pub memory_locking: Support,
    pub core_dumps: Support,
}

impl Hardening {
    /// Apply what can be applied, and report the result.
    ///
    /// Called once, early: `prctl` and `setrlimit` affect the whole process, and
    /// doing it before any key exists means there is no window where a dump would
    /// have contained one.
    pub fn apply() -> Self {
        Hardening {
            core_dumps: suppress_core_dumps(),
            memory_locking: probe_memory_locking(),
        }
    }

    /// True when every measure is in force.
    pub fn is_complete(&self) -> bool {
        self.memory_locking.is_enabled() && self.core_dumps.is_enabled()
    }
}

/// 32 bytes of key material in its own locked page.
///
/// The allocation is page-aligned and exactly one page, which matters: `mlock` and
/// `munlock` work on whole pages, so a secret sharing a page with something else
/// would have its lock silently dropped when that other thing was unlocked. Giving
/// each key its own page costs 4 KiB and removes the interaction entirely.
///
/// The bytes never move after construction. That is the whole point — locking the
/// address of a value that Rust is free to memcpy elsewhere would pin a page that no
/// longer holds the secret.
pub struct SecretKey {
    ptr: NonNull<u8>,
    layout: Layout,
    locked: bool,
}

// SAFETY: the allocation is owned solely by this value and is never mutated after
// construction, so sending it between threads and sharing `&SecretKey` are both
// sound. Needed because a session lives behind a mutex that a watchdog thread also
// holds, and a raw pointer is otherwise neither `Send` nor `Sync`.
unsafe impl Send for SecretKey {}
unsafe impl Sync for SecretKey {}

impl SecretKey {
    /// Copy `value` into a fresh locked page.
    ///
    /// The caller's original should be a `Zeroizing` temporary: this makes a copy,
    /// and only the copy is protected.
    pub fn new(value: &[u8; 32]) -> Self {
        let page = page_size();
        let layout = Layout::from_size_align(page, page).expect("a page is a valid layout");

        // SAFETY: `layout` has a non-zero size.
        let raw = unsafe { std::alloc::alloc_zeroed(layout) };
        let Some(ptr) = NonNull::new(raw) else {
            std::alloc::handle_alloc_error(layout)
        };

        // Lock before the secret is written, so it can never have been resident in
        // an unlocked page even briefly.
        // SAFETY: `ptr` points to `layout.size()` freshly allocated bytes.
        let locked = unsafe { lock_pages(ptr.as_ptr(), layout.size()) };

        // SAFETY: source and destination are valid for 32 bytes and do not overlap.
        unsafe { std::ptr::copy_nonoverlapping(value.as_ptr(), ptr.as_ptr(), 32) };

        SecretKey {
            ptr,
            layout,
            locked,
        }
    }

    /// Whether this key's page is actually pinned. False means the allocation
    /// succeeded but the lock did not — usually `RLIMIT_MEMLOCK`.
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl Deref for SecretKey {
    type Target = [u8; 32];

    fn deref(&self) -> &[u8; 32] {
        // SAFETY: the allocation is at least one page, so the first 32 bytes are
        // valid and initialised, and are never mutated after construction.
        unsafe { &*(self.ptr.as_ptr() as *const [u8; 32]) }
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // SAFETY: `ptr` is a live allocation of `layout.size()` bytes owned by this
        // value, released exactly once here.
        unsafe {
            // Zeroize the whole page, not only the 32 bytes: `zeroize` is what
            // guarantees the write is not optimised away, which a plain loop or
            // `write_bytes` would not.
            std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.layout.size()).zeroize();
            if self.locked {
                unlock_pages(self.ptr.as_ptr(), self.layout.size());
            }
            std::alloc::dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the bytes. Same rule as everywhere else in the project: a key in a
        // log or a panic message is a key on disk.
        f.debug_struct("SecretKey")
            .field("locked", &self.locked)
            .finish_non_exhaustive()
    }
}

/// Find out whether memory locking works here, before any key depends on it.
///
/// Done by actually locking a page rather than by inspecting limits: `RLIMIT_MEMLOCK`
/// is not the only thing that can refuse, and a report that says "enabled" should
/// mean a lock succeeded.
pub fn probe_memory_locking() -> Support {
    let probe = SecretKey::new(&[0u8; 32]);
    if probe.is_locked() {
        Support::Enabled
    } else {
        Support::Failed(lock_failure_hint())
    }
}

/// Stop this process producing a core dump.
///
/// On Linux this does two things, and the second is the more valuable:
/// `RLIMIT_CORE = 0` stops a core file being written, and `PR_SET_DUMPABLE = 0`
/// stops the kernel dumping the process at all *and* makes the per-process files
/// under `/proc/<pid>` root-owned — so another process running as the same user can
/// no longer read `/proc/<pid>/mem` or attach with `ptrace`, either of which would
/// otherwise hand over every open store's data key. Verified: `/proc/<pid>/mem`
/// becomes `root:root` and reading it fails with `EACCES`.
///
/// The `/proc/<pid>` *directory* itself stays owned by the user, which matters
/// because [`crate::lock`] and [`crate::orphan`] decide whether a process is still
/// alive by looking for it. Hardening a session must not make it look dead to the
/// next one; there is a test for exactly that.
#[cfg(unix)]
pub fn suppress_core_dumps() -> Support {
    // SAFETY: `setrlimit` with a valid resource and an initialised `rlimit`.
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let core_limit = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };
    if core_limit != 0 {
        return Support::Failed(format!(
            "setrlimit(RLIMIT_CORE, 0): {}",
            std::io::Error::last_os_error()
        ));
    }

    #[cfg(target_os = "linux")]
    {
        // SAFETY: `prctl` with a valid option and argument.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
            return Support::Failed(format!(
                "prctl(PR_SET_DUMPABLE, 0): {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Support::Enabled
}

/// Windows has no process-controlled equivalent.
///
/// Crash dumps are configured by the system (Windows Error Reporting, or a debugger
/// registered as the post-mortem handler), and a process cannot opt out of them.
/// `WerRegisterExcludedMemoryBlock` can exclude specific pages from a dump, but it
/// is not present before Windows 10 1709 and would have to be resolved dynamically;
/// it is deliberately not attempted here rather than shipped untested. This is
/// reported to the user rather than passed over in silence.
#[cfg(not(unix))]
pub fn suppress_core_dumps() -> Support {
    Support::Unsupported("Windows crash dumps are configured by the system, not the process")
}

#[cfg(unix)]
fn page_size() -> usize {
    // SAFETY: `sysconf` with a valid name.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size > 0 {
        size as usize
    } else {
        4096
    }
}

#[cfg(windows)]
fn page_size() -> usize {
    let mut info = unsafe { std::mem::zeroed::<winapi::um::sysinfoapi::SYSTEM_INFO>() };
    // SAFETY: `GetSystemInfo` fills the struct it is given.
    unsafe { winapi::um::sysinfoapi::GetSystemInfo(&mut info) };
    let size = info.dwPageSize as usize;
    if size > 0 {
        size
    } else {
        4096
    }
}

#[cfg(not(any(unix, windows)))]
fn page_size() -> usize {
    4096
}

/// # Safety
/// `ptr` must point to at least `len` bytes of a live allocation.
#[cfg(unix)]
unsafe fn lock_pages(ptr: *mut u8, len: usize) -> bool {
    libc::mlock(ptr as *const libc::c_void, len) == 0
}

/// # Safety
/// As [`lock_pages`], and the range must currently be locked.
#[cfg(unix)]
unsafe fn unlock_pages(ptr: *mut u8, len: usize) {
    libc::munlock(ptr as *const libc::c_void, len);
}

/// # Safety
/// `ptr` must point to at least `len` bytes of a live allocation.
#[cfg(windows)]
unsafe fn lock_pages(ptr: *mut u8, len: usize) -> bool {
    winapi::um::memoryapi::VirtualLock(ptr as *mut winapi::ctypes::c_void, len) != 0
}

/// # Safety
/// As [`lock_pages`], and the range must currently be locked.
#[cfg(windows)]
unsafe fn unlock_pages(ptr: *mut u8, len: usize) {
    winapi::um::memoryapi::VirtualUnlock(ptr as *mut winapi::ctypes::c_void, len);
}

/// # Safety
/// Unused on platforms with no locking primitive.
#[cfg(not(any(unix, windows)))]
unsafe fn lock_pages(_ptr: *mut u8, _len: usize) -> bool {
    false
}

/// # Safety
/// Unused on platforms with no locking primitive.
#[cfg(not(any(unix, windows)))]
unsafe fn unlock_pages(_ptr: *mut u8, _len: usize) {}

fn lock_failure_hint() -> String {
    let error = std::io::Error::last_os_error();
    #[cfg(unix)]
    {
        format!(
            "{error}; RLIMIT_MEMLOCK may be too low (see `ulimit -l`, which needs at \
             least a few pages)"
        )
    }
    #[cfg(not(unix))]
    {
        format!("{error}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_reads_back_what_was_put_in_it() {
        let mut value = [0u8; 32];
        for (index, byte) in value.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let key = SecretKey::new(&value);
        assert_eq!(&*key, &value);
    }

    #[test]
    fn keys_are_independent() {
        let first = SecretKey::new(&[1u8; 32]);
        let second = SecretKey::new(&[2u8; 32]);
        assert_eq!(&*first, &[1u8; 32]);
        assert_eq!(&*second, &[2u8; 32]);
    }

    #[test]
    fn each_key_gets_its_own_page() {
        // Two secrets sharing a page would mean unlocking one silently unlocked the
        // other, since mlock/munlock work on whole pages.
        let page = page_size();
        let first = SecretKey::new(&[1u8; 32]);
        let second = SecretKey::new(&[2u8; 32]);

        let a = first.as_ptr() as usize;
        let b = second.as_ptr() as usize;
        assert_eq!(a % page, 0, "allocations must be page-aligned");
        assert_eq!(b % page, 0, "allocations must be page-aligned");
        assert_ne!(a / page, b / page, "two keys must not share a page");
    }

    #[test]
    fn dropping_many_keys_does_not_leak_locks() {
        // RLIMIT_MEMLOCK is small by default, so a leak here would show up quickly
        // as later locks failing.
        for _ in 0..64 {
            let key = SecretKey::new(&[7u8; 32]);
            assert_eq!(&*key, &[7u8; 32]);
        }
        assert!(
            SecretKey::new(&[0u8; 32]).is_locked() || !cfg!(target_os = "linux"),
            "locking stopped working, so munlock is not being called on drop"
        );
    }

    #[test]
    fn debug_never_prints_the_key() {
        let key = SecretKey::new(&[0xABu8; 32]);
        let rendered = format!("{key:?}");
        assert!(!rendered.contains("171"), "{rendered}");
        assert!(!rendered.contains("ab"), "{rendered}");
        assert!(rendered.contains("locked"), "{rendered}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_live_key_is_pinned_according_to_the_kernel() {
        // The claim being tested is the whole point of the milestone, so it is
        // checked against what the kernel reports rather than against our own
        // return value.
        let key = SecretKey::new(&[9u8; 32]);
        assert!(key.is_locked(), "mlock failed: {}", lock_failure_hint());

        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let locked_kb: u64 = status
            .lines()
            .find_map(|line| line.strip_prefix("VmLck:"))
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse().ok())
            .expect("VmLck is reported on Linux");
        assert!(
            locked_kb > 0,
            "the kernel reports no locked memory while a key is alive"
        );
    }

    #[test]
    fn probing_reports_a_usable_answer() {
        match probe_memory_locking() {
            Support::Enabled => {}
            // A machine with a tiny RLIMIT_MEMLOCK is a legitimate environment; what
            // matters is that the report says so rather than claiming success.
            Support::Failed(why) => assert!(!why.is_empty()),
            Support::Unsupported(why) => assert!(!why.is_empty()),
        }
    }

    #[test]
    fn suppressing_core_dumps_is_idempotent() {
        // Applied twice because the process running these tests may already have
        // had it applied by another test.
        let first = suppress_core_dumps();
        let second = suppress_core_dumps();
        assert_eq!(first, second);

        #[cfg(target_os = "linux")]
        if first == Support::Enabled {
            // SAFETY: `prctl` with a valid option.
            let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
            assert_eq!(dumpable, 0, "the process is still dumpable");

            let mut limit = libc::rlimit {
                rlim_cur: 1,
                rlim_max: 1,
            };
            // SAFETY: `getrlimit` with a valid resource and an out parameter.
            assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
            assert_eq!(limit.rlim_cur, 0, "RLIMIT_CORE was not set to 0");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_hardened_process_still_looks_alive_to_the_liveness_check() {
        // `PR_SET_DUMPABLE(0)` moves the per-process files under /proc/<pid> to
        // root. If it also hid the directory, every running session would look dead
        // to the next one -- which would auto-clear live vault locks and offer live
        // working directories up for recovery. Both would lose data.
        assert_eq!(suppress_core_dumps(), Support::Enabled);

        let pid = std::process::id();
        assert!(std::path::Path::new(&format!("/proc/{pid}")).exists());
        assert!(
            !crate::lock::is_definitely_gone(pid, &crate::lock::hostname()),
            "a hardened process must not be mistaken for a dead one"
        );
    }

    #[test]
    fn support_renders_for_a_status_line() {
        assert_eq!(Support::Enabled.to_string(), "enabled");
        assert!(Support::Failed("nope".into()).to_string().contains("nope"));
        assert!(Support::Unsupported("nope").to_string().contains("nope"));
    }
}
