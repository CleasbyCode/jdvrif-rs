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

pub(crate) fn install_process_signal_handlers() -> Result<(), String> {
    // SAFETY: SIG_IGN and request_cancellation are valid sigaction handlers.
    unsafe {
        install_handler(libc::SIGPIPE, libc::SIG_IGN)?;
        for signal_number in [
            libc::SIGHUP,
            libc::SIGINT,
            libc::SIGQUIT,
            libc::SIGTERM,
            libc::SIGTSTP,
        ] {
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
