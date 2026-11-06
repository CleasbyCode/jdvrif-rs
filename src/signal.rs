use std::sync::atomic::{AtomicI32, Ordering};

static PENDING_SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn request_cancellation(signal_number: libc::c_int) {
    let _ = PENDING_SIGNAL.compare_exchange(0, signal_number, Ordering::Relaxed, Ordering::Relaxed);
}

unsafe fn install_handler(
    signal_number: libc::c_int,
    handler: libc::sighandler_t,
) -> Result<(), String> {
    // SAFETY: sigaction is initialized before use and the handler has C ABI.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = handler;
    // Deliberately interrupt blocking syscalls.
    action.sa_flags = 0;
    // SAFETY: action owns a valid signal mask and sigaction pointer.
    if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0
        || unsafe { libc::sigaction(signal_number, &action, std::ptr::null_mut()) } != 0
    {
        return Err("Signal Error: Failed to install process signal handler.".to_string());
    }
    Ok(())
}

/// Keeps the process's memory -- the KEY, derived keys and decrypted data --
/// out of core dumps, and stops other processes running as the same user from
/// attaching with ptrace or reading /proc/<pid>/mem. Both settings are
/// per-process and end when it exits. RLIMIT_CORE alone is not enough, because
/// a core_pattern pipe handler (systemd-coredump, apport) ignores it;
/// PR_SET_DUMPABLE 0 suppresses those as well. The process can still reach its
/// own /proc/self/fd entries, which the staging files rely on.
///
/// Best effort: if either call is refused (a seccomp filter, say), a warning
/// goes to stderr and the program carries on rather than refusing to run.
/// This does not keep memory out of swap, nor out of reach of root. Mirrors
/// disableCoreDumps(), including the warning text.
pub(crate) fn disable_core_dumps() {
    let no_core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit reads a valid, initialized rlimit; prctl with
    // PR_SET_DUMPABLE takes plain integer arguments. Neither touches memory
    // we own afterwards.
    let (core_ok, dumpable_ok) = unsafe {
        (
            libc::setrlimit(libc::RLIMIT_CORE, &no_core) == 0,
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0,
        )
    };
    let refused = match (core_ok, dumpable_ok) {
        (true, true) => return,
        (false, false) => "RLIMIT_CORE 0 and PR_SET_DUMPABLE 0",
        (false, true) => "RLIMIT_CORE 0",
        (true, false) => "PR_SET_DUMPABLE 0",
    };
    eprintln!(
        "Warning: The system refused {refused}, so core dumps or other processes may \
         expose this run's memory. Continuing anyway."
    );
}

pub(crate) fn install_process_signal_handlers() -> Result<(), String> {
    // SAFETY: SIG_IGN and request_cancellation are valid sigaction handlers.
    unsafe {
        install_handler(libc::SIGPIPE, libc::SIG_IGN)?;
        // SIGTSTP is deliberately absent: it keeps its default disposition so
        // Ctrl+Z performs a genuine stop. Job-control shells save/restore termios
        // around stopped jobs, and blocked reads resume on SIGCONT.
        for signal_number in [libc::SIGHUP, libc::SIGINT, libc::SIGQUIT, libc::SIGTERM] {
            install_handler(
                signal_number,
                request_cancellation as *const () as libc::sighandler_t,
            )?;
        }
    }
    Ok(())
}

pub(crate) fn pending_signal() -> Option<libc::c_int> {
    match PENDING_SIGNAL.load(Ordering::Relaxed) {
        0 => None,
        signal_number => Some(signal_number),
    }
}

/// C callbacks query cancellation without unwinding across the FFI boundary.
#[no_mangle]
extern "C" fn jdvrif_rs_pending_signal() -> libc::c_int {
    pending_signal().unwrap_or(0)
}

pub(crate) fn check_cancellation() -> Result<(), String> {
    if pending_signal().is_some() {
        Err("Operation interrupted by signal".to_string())
    } else {
        Ok(())
    }
}

pub(crate) fn reraise_after_cleanup(signal_number: libc::c_int) -> ! {
    // SAFETY: restore the default disposition before re-raising so callers see
    // the conventional signal exit status after Rust guards have been dropped.
    unsafe {
        let _ = install_handler(signal_number, libc::SIG_DFL);
        let _ = libc::raise(signal_number);
        libc::_exit(128 + signal_number);
    }
}
