//! Recovery KEY text codec (mirror of the C++ key_codec.{h,cpp}).
//!
//! A jdvrif v10 KEY is 16 random bytes, shown as 22 Base58 body digits and a
//! 2-digit check pair in six dash-separated groups of four (D2). Nothing here
//! allocates: every temporary lives on the stack and is wiped before return.

use zeroize::{Zeroize, Zeroizing};

pub const RECOVERY_KEY_BYTES: usize = 16;
pub const RECOVERY_KEY_TEXT_CHARS: usize = 24;
pub const RECOVERY_KEY_DISPLAY_CHARS: usize = 29;

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BODY_CHARS: usize = 22;
const CHECK_MODULUS: u32 = 58 * 58;
// Part of the KEY format: every KEY's check pair is hashed under this label,
// so it keeps its original wording ("pin") byte-for-byte.
const CHECK_DOMAIN: &[u8; 19] = b"jdvrif pin check v1";

/// A recovery KEY (mirror of the C++ `RecoveryKey`). Not `Clone`
/// or `Copy`, and wiped on drop, so no stray copy outlives its holder.
pub enum RecoveryKey {
    /// v10 128-bit KEY: KDF5 envelopes, RQSTEG3 and JXSTEG4.
    V128([u8; RECOVERY_KEY_BYTES]),
}

impl Zeroize for RecoveryKey {
    fn zeroize(&mut self) {
        let RecoveryKey::V128(secret) = self;
        secret.zeroize();
    }
}

impl Drop for RecoveryKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyParseError {
    Malformed,
    Checksum,
}

pub fn is_key_separator(c: u8) -> bool {
    c == b' ' || c == b'\t' || c == b'-'
}

fn base58_digit(c: u8) -> Option<u32> {
    ALPHABET.iter().position(|&a| a == c).map(|p| p as u32)
}

fn check_value(secret: &[u8; RECOVERY_KEY_BYTES]) -> u32 {
    let mut hash = Zeroizing::new([0u8; 32]);
    let mut msg = Zeroizing::new([0u8; CHECK_DOMAIN.len() + RECOVERY_KEY_BYTES]);
    msg[..CHECK_DOMAIN.len()].copy_from_slice(CHECK_DOMAIN);
    msg[CHECK_DOMAIN.len()..].copy_from_slice(secret);
    // Unkeyed BLAKE2b-256 (crypto_generichash, 32-byte output). Only fails on
    // an invalid output length, which this fixed length is not.
    alkali::hash::generic::hash_custom(&msg[..], None, &mut hash[..])
        .expect("BLAKE2b-256 with a fixed output length");
    u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) % CHECK_MODULUS
}

/// D2 display form (`XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`), in a stack buffer that
/// is wiped when dropped. Never put it in a `String`.
pub fn encode_recovery_key_display(
    secret: &[u8; RECOVERY_KEY_BYTES],
) -> Zeroizing<[u8; RECOVERY_KEY_DISPLAY_CHARS]> {
    let mut out = Zeroizing::new([0u8; RECOVERY_KEY_DISPLAY_CHARS]);
    let mut chars = Zeroizing::new([0u8; RECOVERY_KEY_TEXT_CHARS]);
    let mut work = Zeroizing::new(*secret);

    for i in (0..BODY_CHARS).rev() {
        let mut rem: u32 = 0;
        for b in work.iter_mut() {
            let cur = (rem << 8) | u32::from(*b);
            *b = (cur / 58) as u8;
            rem = cur % 58;
        }
        chars[i] = ALPHABET[rem as usize];
    }
    let c = check_value(secret);
    chars[BODY_CHARS] = ALPHABET[(c / 58) as usize];
    chars[BODY_CHARS + 1] = ALPHABET[(c % 58) as usize];

    let mut o = 0;
    for i in 0..RECOVERY_KEY_TEXT_CHARS {
        if i != 0 && i % 4 == 0 {
            out[o] = b'-';
            o += 1;
        }
        out[o] = chars[i];
        o += 1;
    }
    out
}

/// Skips separators anywhere in `text`, then accepts a 24-character Base58 KEY
/// with a valid check pair. Never allocates; temporaries are wiped.
pub fn parse_recovery_key_text(text: &[u8]) -> Result<RecoveryKey, KeyParseError> {
    let mut sig = Zeroizing::new([0u8; RECOVERY_KEY_TEXT_CHARS]);
    let mut n = 0usize;
    for &c in text {
        if is_key_separator(c) {
            continue;
        }
        if n == sig.len() {
            return Err(KeyParseError::Malformed);
        }
        sig[n] = c;
        n += 1;
    }

    if n != RECOVERY_KEY_TEXT_CHARS {
        return Err(KeyParseError::Malformed);
    }

    let mut digits = Zeroizing::new([0u32; RECOVERY_KEY_TEXT_CHARS]);
    for i in 0..n {
        digits[i] = base58_digit(sig[i]).ok_or(KeyParseError::Malformed)?;
    }

    let mut secret = Zeroizing::new([0u8; RECOVERY_KEY_BYTES]);
    for &digit in &digits[..BODY_CHARS] {
        let mut carry = digit;
        for b in secret.iter_mut().rev() {
            let cur = u32::from(*b) * 58 + carry;
            *b = (cur & 0xff) as u8;
            carry = cur >> 8;
        }
        if carry != 0 {
            return Err(KeyParseError::Malformed);
        }
    }

    if secret.iter().all(|&b| b == 0) {
        return Err(KeyParseError::Malformed);
    }

    let expected_check = digits[BODY_CHARS] * 58 + digits[BODY_CHARS + 1];
    if check_value(&secret) != expected_check {
        return Err(KeyParseError::Checksum);
    }

    Ok(RecoveryKey::V128(*secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex16(s: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    const VECTORS: [(&str, &str); 6] = [
        (
            "00000000000000000000000000000001",
            "1111-1111-1111-1111-1111-126X",
        ),
        (
            "000102030405060708090a0b0c0d0e0f",
            "112d-rXXU-ifSr-RnXL-GbXg-8Egs",
        ),
        (
            "ffffffffffffffffffffffffffffffff",
            "YcVf-xkQb-6JRz-qk5k-F2tN-LvUM",
        ),
        (
            "8f3a1c5e9b2d4f60718293a4b5c6d7e8",
            "Jgoe-TsV4-hWLD-SMP9-PJt7-nPTd",
        ),
        // Check-value boundaries: 0 ("11") and 3363 ("zz").
        (
            "000000000000000000000000000003d3",
            "1111-1111-1111-1111-1111-Ht11",
        ),
        (
            "00000000000000000000000000000abf",
            "1111-1111-1111-1111-1111-pSzz",
        ),
    ];

    #[test]
    fn encodes_vectors() {
        for (hex, text) in VECTORS {
            let display = encode_recovery_key_display(&hex16(hex));
            assert_eq!(&display[..], text.as_bytes(), "secret {hex}");
        }
    }

    #[test]
    fn parses_vectors_with_and_without_separators() {
        for (hex, text) in VECTORS {
            let expected = hex16(hex);
            let undashed = text.replace('-', "");
            let spaced = text.replace('-', " ");
            for form in [text.to_string(), undashed, spaced, format!("\t{text} ")] {
                match parse_recovery_key_text(form.as_bytes()) {
                    Ok(RecoveryKey::V128(secret)) => assert_eq!(secret, expected, "{form}"),
                    _ => panic!("{form} did not parse as a 128-bit KEY"),
                }
            }
        }
    }

    #[test]
    fn rejects_vectors() {
        use KeyParseError::{Checksum, Malformed};
        for (text, expected) in [
            ("112d-rXXU-ifSr-RnXL-GbXg-8Egt", Checksum),
            ("112D-rXXU-ifSr-RnXL-GbXg-8Egs", Checksum),
            ("112d-rXXU-ifSr-RnXL-GbXh-8Egs", Checksum),
            ("YcVf-xkQb-6JRz-qk5k-F2tN-LwUM", Malformed),
            ("1111-1111-1111-1111-1111-11xx", Malformed),
            ("1111-1111-1111-1111-1111-1111", Malformed),
            ("112d-rXXU-ifSr-RnXL-GbXg-8Eg0", Malformed),
            ("112d-rXXU-ifSr-RnXL-GbXg-8Eg", Malformed),
            ("zzzz-zzzz-zzzz-zzzz-zzzz-zzzz", Malformed),
            ("112d-rXXU-ifSr-RnXL-GbXg-8Egs1", Malformed),
            ("", Malformed),
            ("---", Malformed),
            ("0", Malformed),
            ("0123", Malformed),
            ("1234", Malformed),
            ("15753985819510608748", Malformed),
            ("18446744073709551615", Malformed),
            ("18446744073709551616", Malformed),
            ("12O4", Malformed),
            ("***1234***", Malformed),
        ] {
            match parse_recovery_key_text(text.as_bytes()) {
                Err(e) => assert!(e == expected, "{text}: wrong error kind"),
                Ok(_) => panic!("{text} was accepted"),
            }
        }
    }

    #[test]
    fn recovery_key_zeroize_wipes_secret() {
        let mut modern = RecoveryKey::V128([0xAB; 16]);
        modern.zeroize();
        assert!(matches!(modern, RecoveryKey::V128(s) if s == [0u8; 16]));
    }
}
