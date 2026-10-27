use crate::pin_codec::{parse_recovery_pin_text, PinParseError, RecoveryPin};
use crate::runtime::TermiosGuard;
use crate::signal::check_cancellation;
use std::io::Write;
use zeroize::Zeroizing;

// Deliberately says nothing about which rule the input broke: the shape of a
// recovery KEY/PIN is public, but how far a given attempt got is not worth
// echoing. Each prompt describes only the forms its image can take.
fn format_error(prompt: PinPrompt) -> &'static str {
    match prompt {
        PinPrompt::Key => {
            "KEY Entry Error: That is not a well-formed recovery KEY.\n\n\
A jdvrif KEY is 24 letters and digits, printed in groups of four \
(XXXX-XXXX-XXXX-XXXX-XXXX-XXXX).\n\n\
Enter it exactly as it was printed when the file was concealed."
        }
        PinPrompt::Pin => {
            "PIN Entry Error: That is not a well-formed recovery PIN.\n\n\
This image was made before jdvrif v10 and uses a PIN of up to 20 digits.\n\n\
Enter it exactly as it was printed when the file was concealed."
        }
        PinPrompt::KeyOrPin => {
            "KEY/PIN Entry Error: That is not a well-formed recovery KEY/PIN.\n\n\
A jdvrif KEY is 24 letters and digits, printed in groups of four \
(XXXX-XXXX-XXXX-XXXX-XXXX-XXXX);\n\
Images made before jdvrif v10 use a PIN of up to 20 digits.\n\n\
Enter it exactly as it was printed when the file was concealed."
        }
    }
}

// A 24-character KEY whose check pair does not match its body: a typo the
// user can find, reported before any key derivation. An image made before v10
// takes no KEY at all, so there the entry is simply not a well-formed PIN.
fn check_error(prompt: PinPrompt) -> &'static str {
    match prompt {
        PinPrompt::Key => {
            "KEY Entry Error: That KEY has a typo: its last two characters do not \
match the rest. Check each character, including upper and lower case."
        }
        PinPrompt::Pin => format_error(prompt),
        PinPrompt::KeyOrPin => {
            "KEY/PIN Entry Error: That KEY has a typo: its last two characters do not \
match the rest. Check each character, including upper and lower case."
        }
    }
}

struct PinSignalBlock {
    previous_mask: libc::sigset_t,
}

impl PinSignalBlock {
    fn new(word: &str) -> Result<Self, String> {
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
                return Err(format!("Signal Error: Failed to protect {word} input wait."));
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
    fn new(word: &str) -> Result<Self, String> {
        // SAFETY: F_GETFL/F_SETFL operate on stdin's open-file status flags.
        unsafe {
            let previous_flags = libc::fcntl(libc::STDIN_FILENO, libc::F_GETFL);
            if previous_flags < 0 {
                return Err(format!("Read Error: Failed to inspect {word} input mode."));
            }
            let changed = previous_flags & libc::O_NONBLOCK == 0;
            if changed
                && libc::fcntl(
                    libc::STDIN_FILENO,
                    libc::F_SETFL,
                    previous_flags | libc::O_NONBLOCK,
                ) != 0
            {
                return Err(format!("Read Error: Failed to prepare {word} input mode."));
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
    let word = termios_guard.word();
    let signal_block = PinSignalBlock::new(word)?;
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
            return Err(format!("Read Error: Failed to wait for {word} input."));
        }
        if ready == 0 {
            continue;
        }

        // Readiness can become stale, including when resume flushes input.
        // Never block in read while cancellation signals are masked. Restore
        // fd flags before waiting or unmasking so stopped jobs leave stdin
        // usable by the shell sharing its open-file description.
        let _nonblocking_guard = NonblockingStdinGuard::new(word)?;
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
            return Err(format!("Read Error: Failed to read {word} input."));
        }
        return Ok(true);
    }
}

/// Which word the prompt uses (mirror of the C++ `PinPrompt`). Default and
/// Bluesky images say up front whether they were made with a 128-bit recovery
/// KEY (jdvrif v10+) or a numeric PIN (v9.x). Reddit / X-Twitter carriers
/// cannot be read until after entry -- the key locates them -- so they get a
/// prompt that names both. Errors raised while reading the entry use the
/// same word.
#[derive(Clone, Copy)]
pub(crate) enum PinPrompt {
    Key,
    Pin,
    KeyOrPin,
}

impl PinPrompt {
    pub(crate) fn word(self) -> &'static str {
        match self {
            PinPrompt::Key => "KEY",
            PinPrompt::Pin => "PIN",
            PinPrompt::KeyOrPin => "KEY/PIN",
        }
    }
}

pub(crate) fn get_pin(prompt: PinPrompt) -> Result<RecoveryPin, String> {
    // 24 characters plus 5 group dashes, with room to spare (D3).
    const MAX_PIN_KEYSTROKES: usize = 32;

    check_cancellation()?;

    print!("\n{}: ", prompt.word());
    let _ = std::io::stdout().flush();

    // SAFETY: querying whether STDIN is attached to a TTY.
    let is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) != 0 };
    // Install the resume hook before permitting a job-control stop.
    let setup_signal_block = PinSignalBlock::new(prompt.word())?;
    let termios_guard = TermiosGuard::new(prompt.word())?;
    drop(setup_signal_block);

    // A fixed stack buffer, never a heap Vec/String: nothing here can leave a
    // copy of the PIN behind in a freed allocation. Wiped on every exit path.
    let mut input = Zeroizing::new([0u8; MAX_PIN_KEYSTROKES]);
    let mut input_len = Zeroizing::new(0usize);
    let mut ch = Zeroizing::new(0u8);
    // Keystrokes typed past MAX_PIN_KEYSTROKES are not stored, but they are
    // counted, so that a backspace undoes the keystroke the user actually made
    // last. Without this the buffer silently stops matching what was typed:
    // backspacing back under the limit would hand out a PIN built from the
    // first characters entered.
    let mut dropped_keys = 0usize;
    loop {
        let has_byte = read_single_byte(&mut ch, &termios_guard)?;
        // Dropping the read helper's mask delivers signals queued after its
        // readiness check. Observe them before accepting even the final byte.
        check_cancellation()?;
        if !has_byte {
            break;
        }
        if *ch == b'\n' || *ch == b'\r' {
            break;
        }
        // Spaces and tabs are ignored, so a PIN pasted with stray whitespace
        // still works (the web variant's PIN file is trimmed the same way).
        if *ch == b' ' || *ch == b'\t' {
            continue;
        }
        if *ch == b'\x08' || *ch == 127 {
            if dropped_keys > 0 {
                // Undo an over-limit keystroke. Nothing was echoed for it, so
                // nothing is erased from the display either.
                dropped_keys -= 1;
            } else if *input_len > 0 {
                // One display cell per stored keystroke, dash or not.
                if is_tty {
                    print!("\x08 \x08");
                    let _ = std::io::stdout().flush();
                }
                *input_len -= 1;
                input[*input_len] = 0;
            }
            continue;
        }
        // Every other keystroke is kept -- including the group dash, so that
        // "XXXX-" then one backspace removes the dash the user typed, not the
        // character before it -- and so that a stray character rejects the PIN
        // below instead of being silently dropped: "12O4" is a mistyped PIN.
        if *input_len >= MAX_PIN_KEYSTROKES {
            dropped_keys += 1; // counted, not stored, and not echoed
            continue;
        }
        input[*input_len] = *ch;
        *input_len += 1;
        if is_tty {
            // Dashes are layout, not secret, and echoing them lets the user
            // keep their place in the groups.
            if *ch == b'-' {
                print!("-");
            } else {
                print!("*");
            }
            let _ = std::io::stdout().flush();
        }
    }

    println!();
    let _ = std::io::stdout().flush();

    // Reject malformed input here instead of silently truncating or
    // normalizing it: such input is a transcription error and must not derive
    // a key the user believes is valid. dropped_keys is non-zero only if
    // keystrokes past the limit are still outstanding -- corrected ones have
    // already been backspaced away above.
    //
    // Knowable mistakes are reported now rather than after an Argon2id run
    // and, on the ICC path, staging up to two gigabytes of ciphertext, only to
    // end in the ambiguous "invalid PIN or file is corrupt". The codec owns the
    // grammar (legacy decimal or 24-character Base58 with a check pair).
    // The termios guard and the Zeroizing buffers above all run on the way out.
    if dropped_keys > 0 {
        return Err(format_error(prompt).to_string());
    }
    parse_recovery_pin_text(&input[..*input_len]).map_err(|error| {
        match error {
            PinParseError::Checksum => check_error(prompt),
            PinParseError::Malformed => format_error(prompt),
        }
        .to_string()
    })
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
        let result = get_pin(PinPrompt::KeyOrPin);
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
                // Test-only probe output: the secret's hex, never its PIN text.
                match &pin {
                    RecoveryPin::Legacy(value) => println!("parsed {value}"),
                    RecoveryPin::V128(secret) => {
                        let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
                        println!("parsed v128 {hex}");
                    }
                }
            }
            Err(error) => {
                if crate::signal::pending_signal() == Some(libc::SIGINT) {
                    assert!(error.contains("signal"));
                    println!("cancelled SIGINT; input flags and signal mask restored");
                } else if mode == "pin-typo" {
                    assert_eq!(error, check_error(PinPrompt::KeyOrPin));
                    println!("typo PIN rejected");
                } else {
                    assert_eq!(mode, "pin-invalid");
                    assert_eq!(error, format_error(PinPrompt::KeyOrPin));
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
}
