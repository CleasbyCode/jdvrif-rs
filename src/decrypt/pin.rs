use crate::crypto::memzero;
use crate::runtime::TermiosGuard;
use crate::signal::check_cancellation;
use std::io::Write;
use zeroize::Zeroizing;

// Deliberately says nothing about which rule the input broke: the shape of a
// recovery PIN is public, but how far a given attempt got is not worth echoing.
const PIN_FORMAT_ERROR: &str = "PIN Entry Error: That is not a well-formed recovery PIN. \
A jdvrif PIN is a number of up to 20 digits, with no leading zero, \
exactly as it was printed when the file was concealed.";

// Wipe the whole allocation, not just the live length. `pop` on backspace
// lowers len() but leaves the digit in the buffer, so zeroing only the live
// prefix would release a block still holding the tail of a corrected PIN.
fn wipe_vec_capacity(buf: &mut Vec<u8>) {
    let cap = buf.capacity();
    buf.resize(cap, 0);
    memzero(buf);
    buf.clear();
}

struct WipeVecGuard(*mut Vec<u8>);

impl WipeVecGuard {
    fn new(buf: &mut Vec<u8>) -> Self {
        Self(buf as *mut Vec<u8>)
    }
}

impl Drop for WipeVecGuard {
    fn drop(&mut self) {
        // SAFETY: the Vec outlives this guard and is not moved while we wipe it.
        unsafe { wipe_vec_capacity(&mut *self.0) }
    }
}

struct WipeByteGuard(*mut u8);

impl WipeByteGuard {
    fn new(ch: &mut u8) -> Self {
        Self(ch as *mut u8)
    }
}

impl Drop for WipeByteGuard {
    fn drop(&mut self) {
        // SAFETY: the byte outlives this guard.
        unsafe { memzero(std::slice::from_mut(&mut *self.0)) }
    }
}

struct PinSignalBlock {
    previous_mask: libc::sigset_t,
}

impl PinSignalBlock {
    fn new() -> Result<Self, String> {
        // SAFETY: both masks are initialized before the checked POSIX calls.
        unsafe {
            let mut blocked: libc::sigset_t = std::mem::zeroed();
            let mut previous_mask: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut blocked);
            for signal in [
                libc::SIGHUP,
                libc::SIGINT,
                libc::SIGQUIT,
                libc::SIGTERM,
                libc::SIGCONT,
                libc::SIGTSTP,
            ] {
                libc::sigaddset(&mut blocked, signal);
            }
            if libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut previous_mask) != 0 {
                return Err("Signal Error: Failed to protect PIN input wait.".to_string());
            }
            Ok(Self { previous_mask })
        }
    }
}

impl Drop for PinSignalBlock {
    fn drop(&mut self) {
        // SAFETY: previous_mask was captured for this thread at construction.
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous_mask, std::ptr::null_mut());
        }
    }
}

struct NonblockingStdinGuard {
    previous_flags: libc::c_int,
    changed: bool,
}

impl NonblockingStdinGuard {
    fn new() -> Result<Self, String> {
        // SAFETY: F_GETFL/F_SETFL operate on stdin's open-file status flags.
        unsafe {
            let previous_flags = libc::fcntl(libc::STDIN_FILENO, libc::F_GETFL);
            if previous_flags < 0 {
                return Err("Read Error: Failed to inspect PIN input mode.".to_string());
            }
            let changed = previous_flags & libc::O_NONBLOCK == 0;
            if changed
                && libc::fcntl(
                    libc::STDIN_FILENO,
                    libc::F_SETFL,
                    previous_flags | libc::O_NONBLOCK,
                ) != 0
            {
                return Err("Read Error: Failed to prepare PIN input mode.".to_string());
            }
            Ok(Self {
                previous_flags,
                changed,
            })
        }
    }
}

impl Drop for NonblockingStdinGuard {
    fn drop(&mut self) {
        if self.changed {
            // SAFETY: restoring exactly the flags captured for stdin.
            unsafe {
                libc::fcntl(libc::STDIN_FILENO, libc::F_SETFL, self.previous_flags);
            }
        }
    }
}

fn read_single_byte(ch: &mut u8, termios_guard: &TermiosGuard) -> Result<bool, String> {
    // pselect atomically unmasks signals during the wait. SIGTSTP is deferred
    // until then, allowing SIGCONT to restore raw mode before another read.
    let signal_block = PinSignalBlock::new()?;
    loop {
        check_cancellation()?;
        termios_guard.reapply_after_continue()?;
        // SAFETY: the initialized fd set contains only the valid stdin index.
        let mut readable: libc::fd_set = unsafe { std::mem::zeroed() };
        unsafe {
            libc::FD_ZERO(&mut readable);
            libc::FD_SET(libc::STDIN_FILENO, &mut readable);
        }
        // Also bound latency when a process-directed signal is delivered to
        // another thread, where it cannot interrupt this thread's wait.
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 100_000_000,
        };
        #[cfg(test)]
        tests::before_wait();
        // SAFETY: all pointers refer to initialized objects spanning the call.
        let ready = unsafe {
            libc::pselect(
                libc::STDIN_FILENO + 1,
                &mut readable,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &timeout,
                &signal_block.previous_mask,
            )
        };
        let wait_errno = std::io::Error::last_os_error().raw_os_error();
        #[cfg(test)]
        tests::after_wait(ready);
        check_cancellation()?;
        termios_guard.reapply_after_continue()?;
        if ready < 0 {
            if wait_errno == Some(libc::EINTR) {
                continue;
            }
            return Err("Read Error: Failed to wait for PIN input.".to_string());
        }
        if ready == 0 {
            continue;
        }

        // Readiness can become stale, including when resume flushes input.
        // Never block in read while cancellation signals are masked. Restore
        // fd flags before waiting or unmasking so stopped jobs leave stdin
        // usable by the shell sharing its open-file description.
        let _nonblocking_guard = NonblockingStdinGuard::new()?;
        *ch = 0;
        // SAFETY: reading one byte from STDIN into valid writable memory.
        let bytes_read = unsafe {
            libc::read(
                libc::STDIN_FILENO,
                ch as *mut u8 as *mut libc::c_void,
                1usize,
            )
        };

        if bytes_read == 0 {
            return Ok(false);
        }
        if bytes_read < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error();
            if errno == Some(libc::EINTR)
                || errno == Some(libc::EAGAIN)
                || errno == Some(libc::EWOULDBLOCK)
            {
                continue;
            }
            return Err("Read Error: Failed to read PIN input.".to_string());
        }
        return Ok(true);
    }
}

pub(crate) fn get_pin() -> Result<Zeroizing<u64>, String> {
    const MAX_PIN_LENGTH: usize = 20;
    const MAX_U64_STR: &[u8] = b"18446744073709551615";

    check_cancellation()?;

    print!("\nPIN: ");
    let _ = std::io::stdout().flush();

    // SAFETY: querying whether STDIN is attached to a TTY.
    let is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) != 0 };
    // Install the resume hook before permitting a job-control stop.
    let setup_signal_block = PinSignalBlock::new()?;
    let termios_guard = TermiosGuard::new()?;
    drop(setup_signal_block);

    // Allocate the maximum up front so pushing a digit never reallocates. A
    // realloc would copy the digits entered so far into a new block and free the
    // old one without zeroing it, scattering PIN prefixes across the heap.
    let mut input = Vec::<u8>::with_capacity(MAX_PIN_LENGTH);
    let mut ch = 0u8;
    let _wipe_input = WipeVecGuard::new(&mut input);
    let _wipe_ch = WipeByteGuard::new(&mut ch);
    // Digits typed past MAX_PIN_LENGTH are not stored, but they are counted, so
    // that a backspace undoes the keystroke the user actually made last. Without
    // this the buffer silently stops matching what was typed: backspacing back
    // under the limit would hand out a PIN built from the first digits entered.
    let mut dropped_digits = 0usize;
    loop {
        let has_byte = read_single_byte(&mut ch, &termios_guard)?;
        // Dropping the read helper's mask delivers signals queued after its
        // readiness check. Observe them before accepting even the final byte.
        check_cancellation()?;
        if !has_byte {
            break;
        }
        if ch == b'\n' || ch == b'\r' {
            break;
        }
        if ch.is_ascii_digit() {
            if input.len() >= MAX_PIN_LENGTH {
                dropped_digits += 1; // counted, not stored, and not echoed
                continue;
            }
            input.push(ch);
            if is_tty {
                print!("*");
                let _ = std::io::stdout().flush();
            }
        } else if ch == b'\x08' || ch == 127 {
            if dropped_digits > 0 {
                // Undo an over-limit digit. Nothing was echoed for it, so
                // nothing is erased from the display either.
                dropped_digits -= 1;
            } else if !input.is_empty() {
                if is_tty {
                    print!("\x08 \x08");
                    let _ = std::io::stdout().flush();
                }
                input.pop();
            }
        }
    }

    println!();
    let _ = std::io::stdout().flush();

    // Reject overlong and leading-zero input instead of silently truncating or
    // normalizing it: generated PINs never look like that, so such input is a
    // transcription error and must not derive a key the user believes is valid.
    // dropped_digits is non-zero only if digits past the limit are still
    // outstanding -- corrected ones have already been backspaced away above.
    //
    // Return an error rather than a zero PIN. Zero is a value generate_recovery_pin
    // never mints, so it could only ever fail -- but not before paying for an
    // Argon2id derivation and, on the ICC path, staging up to two gigabytes of
    // ciphertext, and then reporting the ambiguous "invalid PIN or file is
    // corrupt". Malformed input is knowable here, so say so here.
    //
    // Any leading '0' covers both cases at once: a minted PIN is a non-zero u64
    // in decimal, so it never starts with '0'. Testing the first digit alone
    // (rather than only multi-digit input) is what rejects a lone "0", which is
    // exactly the zero PIN this check exists to refuse.
    // The termios and wipe guards above all run on the way out.
    if input.is_empty()
        || dropped_digits > 0
        || (input.len() == MAX_PIN_LENGTH && input.as_slice() > MAX_U64_STR)
        || input[0] == b'0'
    {
        return Err(PIN_FORMAT_ERROR.to_string());
    }

    match std::str::from_utf8(&input)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        Some(value) => Ok(Zeroizing::new(value)),
        None => Err(PIN_FORMAT_ERROR.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU8, Ordering};

    static WAIT_INJECTION: AtomicU8 = AtomicU8::new(0);

    pub(super) fn before_wait() {
        if WAIT_INJECTION
            .compare_exchange(1, 0, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            // SAFETY: deterministic delivery to this test thread; PIN input
            // has already blocked SIGINT until its atomic pselect wait.
            unsafe {
                libc::raise(libc::SIGINT);
            }
        }
    }

    pub(super) fn after_wait(ready: libc::c_int) {
        if ready <= 0 {
            return;
        }
        let injection = WAIT_INJECTION.swap(0, Ordering::Relaxed);
        if injection == 2 || injection == 3 {
            if injection == 3 {
                let mut byte = 0u8;
                // SAFETY: the test supplies exactly one readable pipe byte.
                assert_eq!(
                    unsafe {
                        libc::read(
                            libc::STDIN_FILENO,
                            &mut byte as *mut u8 as *mut libc::c_void,
                            1,
                        )
                    },
                    1
                );
            }
            // Queue SIGINT after readiness; the drained case must not enter a
            // blocking read while that signal remains masked.
            unsafe {
                libc::raise(libc::SIGINT);
            }
        }
    }

    // Invoked in an isolated child process by run_pin_io_tests.py: signal
    // handlers, stdin flags and terminal modes must not affect parallel tests.
    #[test]
    fn pin_process_probe() {
        let Ok(mode) = std::env::var("JDVRIF_PIN_PROBE") else {
            return;
        };
        crate::signal::install_process_signal_handlers().unwrap();
        let injection = match mode.as_str() {
            "wait-race" => 1,
            "ready-race" => 2,
            "drained-race" => 3,
            _ => 0,
        };
        WAIT_INJECTION.store(injection, Ordering::Relaxed);
        if mode == "pending" {
            unsafe {
                libc::raise(libc::SIGINT);
            }
        }
        let original_flags = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_GETFL) };
        let mut original_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut original_mask)
            },
            0
        );
        let result = get_pin();
        assert_eq!(
            unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_GETFL) },
            original_flags
        );
        let mut restored_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut restored_mask)
            },
            0
        );
        for signal in 1..=64 {
            assert_eq!(
                unsafe { libc::sigismember(&original_mask, signal) },
                unsafe { libc::sigismember(&restored_mask, signal) }
            );
        }
        match result {
            Ok(pin) => {
                assert_eq!(mode, "pin");
                println!("parsed {}", *pin);
            }
            Err(error) => {
                if crate::signal::pending_signal() == Some(libc::SIGINT) {
                    assert!(error.contains("signal"));
                    println!("cancelled SIGINT; input flags and signal mask restored");
                } else {
                    assert_eq!(mode, "pin-invalid");
                    assert!(error.contains("well-formed recovery PIN"));
                    println!("invalid PIN rejected");
                }
            }
        }
    }

    #[test]
    fn pin_io_process_regressions() {
        let output = std::process::Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/scripts/run_pin_io_tests.py"
            ))
            .arg(std::env::current_exe().unwrap())
            .output()
            .expect("run isolated PIN regression tests");
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn fail_with_guards(input: &mut Vec<u8>, ch: &mut u8) -> Result<(), &'static str> {
        let _wipe_input = WipeVecGuard::new(input);
        let _wipe_ch = WipeByteGuard::new(ch);
        Err("cancel")
    }

    #[test]
    fn pin_buffers_wipe_on_unwind() {
        let mut input = Vec::with_capacity(20);
        input.extend_from_slice(b"12345");
        input.push(b'6');
        input.pop();
        let mut ch = b'7';

        assert!(fail_with_guards(&mut input, &mut ch).is_err());
        assert!(
            input.is_empty(),
            "WipeVecGuard left PIN digits in the buffer after unwind"
        );
        assert_eq!(ch, 0, "WipeByteGuard left the last PIN byte after unwind");
    }
}
