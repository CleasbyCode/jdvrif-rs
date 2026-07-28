use crate::common::cleanup_path_no_throw;
use std::fmt;
use std::path::PathBuf;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum KdfMetadataVersion {
    None,
    V2Secretstream,
    V3SecretstreamAuthenticatedMode,
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

pub(crate) struct TempFileGuard {
    path: PathBuf,
    active: bool,
}

impl TempFileGuard {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path, active: true }
    }

    pub(crate) fn dismiss(&mut self) {
        self.active = false;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if self.active {
            cleanup_path_no_throw(&self.path);
        }
    }
}

pub(crate) struct TermiosGuard {
    old: libc::termios,
    active: bool,
}

impl TermiosGuard {
    pub(crate) fn new() -> Self {
        let mut guard = Self {
            old: unsafe { std::mem::zeroed() },
            active: false,
        };

        // SAFETY: libc termios calls are checked for errors and only applied to STDIN when it is a TTY.
        unsafe {
            if libc::isatty(libc::STDIN_FILENO) == 0 {
                return guard;
            }
            if libc::tcgetattr(libc::STDIN_FILENO, &mut guard.old) != 0 {
                return guard;
            }
            let mut newt = guard.old;
            newt.c_lflag &= !(libc::ICANON | libc::ECHO);
            if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &newt) == 0 {
                guard.active = true;
            }
        }

        guard
    }
}

impl Drop for TermiosGuard {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: original termios state captured from tcgetattr for STDIN.
            unsafe {
                libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &self.old);
            }
        }
    }
}
