use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum KdfMetadataVersion {
    None,
    V2Secretstream,
    V3SecretstreamAuthenticatedMode,
    /// V3 plus an explicit record of the Argon2id cost parameters. V2/V3 left
    /// them implicit, so retuning them would have turned every existing image
    /// into an "invalid PIN" -- with V4 the image states what it was derived
    /// with and old costs stay readable.
    V4RecordedKdfParameters,
}

impl KdfMetadataVersion {
    /// True for the versions that bind the payload interpretation into every
    /// secretstream frame as associated data.
    pub(crate) fn authenticates_stream_mode(self) -> bool {
        matches!(
            self,
            KdfMetadataVersion::V3SecretstreamAuthenticatedMode
                | KdfMetadataVersion::V4RecordedKdfParameters
        )
    }

    pub(crate) fn is_supported(self) -> bool {
        self == KdfMetadataVersion::V2Secretstream || self.authenticates_stream_mode()
    }
}

/// Argon2id cost parameters used to derive a key from the recovery PIN.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct KdfParams {
    pub(crate) opslimit: usize,
    pub(crate) memlimit: usize,
}

/// Unified application error used by conceal and recover paths.
#[derive(Debug)]
pub(crate) struct JdvrifError(String);

impl JdvrifError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl From<String> for JdvrifError {
    fn from(message: String) -> Self {
        Self(message)
    }
}

impl From<&str> for JdvrifError {
    fn from(message: &str) -> Self {
        Self(message.to_string())
    }
}

impl fmt::Display for JdvrifError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct DecryptOffsets {
    pub(crate) sodium_key_index: usize,
}

pub(crate) enum DecryptStatus {
    Success {
        decrypted_filename: Vec<u8>,
        output_size: usize,
    },
    FailedPin,
}

pub(crate) struct TermiosGuard {
    old: libc::termios,
    raw: libc::termios,
    old_continue_action: libc::sigaction,
    active: bool,
    continue_hooked: bool,
}

static TERMINAL_CONTINUED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

extern "C" fn note_terminal_continue(_: libc::c_int) {
    TERMINAL_CONTINUED.store(true, std::sync::atomic::Ordering::Relaxed);
}

const TERMINAL_MODE_ERROR: &str = "Terminal Error: Unable to disable terminal echo for PIN entry. \
     Refusing to read the recovery PIN in the clear.";

impl TermiosGuard {
    pub(crate) fn new() -> Result<Self, String> {
        let mut guard = Self {
            // SAFETY: termios is a plain C struct; tcgetattr fills it before use.
            old: unsafe { std::mem::zeroed() },
            // SAFETY: assigned from the captured terminal settings before use.
            raw: unsafe { std::mem::zeroed() },
            // SAFETY: sigaction fills this plain C struct before restoration.
            old_continue_action: unsafe { std::mem::zeroed() },
            active: false,
            continue_hooked: false,
        };

        // SAFETY: libc termios calls are checked for errors and only applied to STDIN when it is a TTY.
        unsafe {
            // Piped/redirected stdin has no echo to suppress and no terminal
            // state to restore, so there is nothing to do -- and nothing to
            // fail closed on.
            if libc::isatty(libc::STDIN_FILENO) == 0 {
                return Ok(guard);
            }
            // From here stdin *is* a terminal, so a failure to establish raw
            // mode would leave ECHO on and print the PIN into the scrollback.
            // Refuse rather than silently reading the PIN in the clear.
            if libc::tcgetattr(libc::STDIN_FILENO, &mut guard.old) != 0 {
                return Err(TERMINAL_MODE_ERROR.to_string());
            }
            guard.raw = guard.old;
            guard.raw.c_lflag &= !(libc::ICANON | libc::ECHO);
            if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &guard.raw) != 0 {
                return Err(TERMINAL_MODE_ERROR.to_string());
            }
            guard.active = true;

            // Shells can restore cooked mode while a job is suspended. Flag
            // its continuation so the PIN loop disables echo again before
            // reading. Guard cleanup restores modes even if installing fails.
            TERMINAL_CONTINUED.store(false, std::sync::atomic::Ordering::Relaxed);
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = note_terminal_continue as *const () as libc::sighandler_t;
            action.sa_flags = 0;
            libc::sigemptyset(&mut action.sa_mask);
            if libc::sigaction(libc::SIGCONT, &action, &mut guard.old_continue_action) != 0 {
                return Err(TERMINAL_MODE_ERROR.to_string());
            }
            guard.continue_hooked = true;
        }

        Ok(guard)
    }

    pub(crate) fn reapply_after_continue(&self) -> Result<(), String> {
        if self.active && TERMINAL_CONTINUED.swap(false, std::sync::atomic::Ordering::Relaxed) {
            // SAFETY: raw contains the valid settings captured during creation.
            if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &self.raw) } != 0 {
                return Err(TERMINAL_MODE_ERROR.to_string());
            }
        }
        Ok(())
    }
}

impl Drop for TermiosGuard {
    fn drop(&mut self) {
        if self.continue_hooked {
            // SAFETY: the previous SIGCONT action was captured on installation.
            unsafe {
                libc::sigaction(
                    libc::SIGCONT,
                    &self.old_continue_action,
                    std::ptr::null_mut(),
                );
            }
        }
        if self.active {
            // SAFETY: original termios state captured from tcgetattr for STDIN.
            unsafe {
                libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &self.old);
            }
        }
    }
}
