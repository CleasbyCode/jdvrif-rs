use crate::crypto::memzero;
use crate::runtime::TermiosGuard;
use crate::signal::check_cancellation;
use std::io::Write;
use zeroize::Zeroizing;

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

fn read_single_byte(ch: &mut u8) -> Result<bool, String> {
    loop {
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
            if errno == Some(libc::EINTR) {
                check_cancellation()?;
                continue;
            }
            return Ok(false);
        }
        return Ok(true);
    }
}

pub(super) fn get_pin() -> Result<Zeroizing<u64>, String> {
    const MAX_PIN_LENGTH: usize = 20;
    const MAX_U64_STR: &[u8] = b"18446744073709551615";

    print!("\nPIN: ");
    let _ = std::io::stdout().flush();

    // SAFETY: querying whether STDIN is attached to a TTY.
    let is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) != 0 };
    let _termios_guard = TermiosGuard::new()?;

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
    while read_single_byte(&mut ch)? {
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
    if input.is_empty()
        || dropped_digits > 0
        || (input.len() == MAX_PIN_LENGTH && input.as_slice() > MAX_U64_STR)
        || (input.len() > 1 && input[0] == b'0')
    {
        return Ok(Zeroizing::new(0));
    }

    let parsed = Zeroizing::new(
        std::str::from_utf8(&input)
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0),
    );

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

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
