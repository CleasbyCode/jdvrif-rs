use crate::cipher_source::CipherSource;
use crate::pin_codec::{legacy_decimal_text, RecoveryPin};
use crate::common::span_has_range;
use crate::constants::{CORRUPT_FILE_ERROR, KDF_METADATA_REGION_BYTES};
use crate::crypto::{argon2id13, secretbox, secretstream};
use crate::runtime::{DecryptStatus, JdvrifError, KdfMetadataVersion, KdfParams};
use crate::signal::check_cancellation;
use std::io::{self, Write};
use std::path::Path;
use zeroize::Zeroizing;

mod kdf;
mod pin;
mod stream;

use kdf::{
    derive_secretstream_key_and_header, read_kdf_params, require_coefficient_carrier_secretstream,
    require_pin_matches_kdf_version, require_supported_secretstream,
};
pub(crate) use pin::{get_pin, PinPrompt};
use stream::decrypt_ciphertext_to_stage_file;

pub(crate) use kdf::{decrypt_offsets, KDF_PARAMS_CURRENT};

pub(crate) struct PreparedDecrypt {
    key: secretstream::Key,
    header: secretstream::Header,
    metadata_version: KdfMetadataVersion,
}

impl PreparedDecrypt {
    /// True for a jdvrif v10+ image, which takes a 128-bit recovery KEY.
    pub(crate) fn takes_recovery_key(&self) -> bool {
        self.metadata_version == KdfMetadataVersion::V5Pin128
    }
}

fn prepare_decrypt_with_pin(
    metadata: &[u8],
    is_bluesky_file: bool,
    pin: &RecoveryPin,
) -> Result<PreparedDecrypt, JdvrifError> {
    let offsets = decrypt_offsets(is_bluesky_file);
    if !span_has_range(
        metadata.len(),
        offsets.sodium_key_index,
        KDF_METADATA_REGION_BYTES,
    ) {
        return Err(JdvrifError::new(CORRUPT_FILE_ERROR.to_string()));
    }

    let metadata_version = require_supported_secretstream(metadata, offsets)?;
    let params = read_kdf_params(metadata, offsets.sodium_key_index, metadata_version)?;
    require_pin_matches_kdf_version(pin, metadata_version)?;
    let (key, header) = derive_secretstream_key_and_header(metadata, offsets, params, pin)?;
    Ok(PreparedDecrypt {
        key,
        header,
        metadata_version,
    })
}

pub(crate) fn prepare_decrypt_from_metadata(
    metadata: &[u8],
    is_bluesky_file: bool,
) -> Result<PreparedDecrypt, JdvrifError> {
    // Reject unsupported metadata before asking for a PIN.
    let offsets = decrypt_offsets(is_bluesky_file);
    if !span_has_range(
        metadata.len(),
        offsets.sodium_key_index,
        KDF_METADATA_REGION_BYTES,
    ) {
        return Err(JdvrifError::new(CORRUPT_FILE_ERROR.to_string()));
    }
    let metadata_version = require_supported_secretstream(metadata, offsets)?;
    // Resolved before prompting, for the same reason the version is checked
    // first: an image declaring costs we will not run is rejected without the
    // user typing a PIN.
    read_kdf_params(metadata, offsets.sodium_key_index, metadata_version)?;

    let prompt = if metadata_version == KdfMetadataVersion::V5Pin128 {
        PinPrompt::Key
    } else {
        PinPrompt::Pin
    };
    let pin = get_pin(prompt).map_err(JdvrifError::from)?;
    // The metadata version says which kind of PIN made this image; a PIN of
    // the other kind is told so (in prepare_decrypt_with_pin) before any
    // Argon2id work.
    prepare_decrypt_with_pin(metadata, is_bluesky_file, &pin)
}

/// Takes the PIN the caller has already collected: coefficient-carrier
/// positions derive from it, so recover must obtain it before it can locate
/// anything, and must not prompt a second time here.
pub(crate) fn prepare_decrypt_from_kdf_metadata(
    metadata: &[u8],
    pin: &RecoveryPin,
) -> Result<PreparedDecrypt, JdvrifError> {
    if metadata.len() != KDF_METADATA_REGION_BYTES {
        return Err(JdvrifError::new(CORRUPT_FILE_ERROR));
    }
    let offsets = crate::runtime::DecryptOffsets {
        sodium_key_index: 0,
    };
    let metadata_version = require_coefficient_carrier_secretstream(metadata, offsets)?;
    // Reject corrupt/unsupported metadata -- and costs we will not run --
    // before consuming a PIN.
    let params = read_kdf_params(metadata, offsets.sodium_key_index, metadata_version)?;

    // Defence in depth: carrier routing already picks formats by PIN kind, so
    // a mismatched PIN should never locate an envelope. If one does, refuse
    // it before Argon2id runs.
    require_pin_matches_kdf_version(pin, metadata_version)?;

    let (key, header) = derive_secretstream_key_and_header(metadata, offsets, params, pin)?;
    Ok(PreparedDecrypt {
        key,
        header,
        metadata_version,
    })
}

fn warn_legacy_recovery(
    metadata_version: KdfMetadataVersion,
    output: &mut impl Write,
) -> io::Result<()> {
    if metadata_version == KdfMetadataVersion::V2Secretstream {
        writeln!(
            output,
            "Warning: Legacy KDF2 image: the compression flag is unauthenticated \
             and may have been altered. Verify the recovered file against a trusted original."
        )?;
        output.flush()?;
    }
    Ok(())
}

/// Decrypts `cipher` (read where it sits -- never staged) into the plaintext
/// StagingFile at `stream_stage_path`.
pub(crate) fn decrypt_prepared_cipher(
    prepared: &PreparedDecrypt,
    is_data_compressed: bool,
    cipher: &mut dyn CipherSource,
    stream_stage_path: &Path,
) -> Result<DecryptStatus, JdvrifError> {
    warn_legacy_recovery(prepared.metadata_version, &mut io::stderr().lock()).map_err(|_| {
        JdvrifError::new("Output Error: Failed to deliver legacy recovery warning.")
    })?;
    let output = decrypt_ciphertext_to_stage_file(
        cipher,
        stream_stage_path,
        &prepared.key,
        &prepared.header,
        prepared.metadata_version,
        is_data_compressed,
    )
    .map_err(JdvrifError::from)?;

    match output {
        Some(v) => Ok(DecryptStatus::Success {
            decrypted_filename: v.decrypted_filename,
            output_size: v.output_size,
        }),
        None => Ok(DecryptStatus::FailedPin),
    }
}

/// The Argon2id password (D4) is the decimal string for a legacy PIN, exactly
/// as jdvrif v9.x derived it, and the 16 secret bytes for a 128-bit PIN. Both
/// are staged in a stack buffer that is wiped on every exit path.
pub(crate) fn derive_key_from_pin(
    pin: &RecoveryPin,
    salt_bytes: &[u8],
    params: KdfParams,
) -> Result<Zeroizing<[u8; secretbox::KEYBYTES]>, String> {
    check_cancellation()?;
    let mut pin_buf = Zeroizing::new([0u8; 32]);
    let pin_len = match pin {
        RecoveryPin::Legacy(value) => {
            let (digits, len) = legacy_decimal_text(*value);
            pin_buf[..len].copy_from_slice(&digits[..len]);
            len
        }
        RecoveryPin::V128(secret) => {
            pin_buf[..secret.len()].copy_from_slice(secret);
            secret.len()
        }
    };
    let pin_bytes = &pin_buf[..pin_len];
    let salt = argon2id13::Salt::from_slice(salt_bytes)
        .ok_or_else(|| "KDF Error: Unable to derive encryption key.".to_string())?;

    let mut key_buf = Zeroizing::new([0u8; secretbox::KEYBYTES]);
    argon2id13::derive_key(
        &mut key_buf[..],
        pin_bytes,
        &salt,
        params.opslimit,
        params.memlimit,
    )
    .map_err(|_| "KDF Error: Unable to derive encryption key.".to_string())?;

    check_cancellation()?;
    Ok(key_buf)
}

#[cfg(test)]
pub(crate) fn decrypt_from_cipher_with_pin(
    metadata: &[u8],
    is_bluesky_file: bool,
    is_data_compressed: bool,
    cipher: &mut dyn CipherSource,
    stream_stage_path: &Path,
    pin: RecoveryPin,
) -> Result<DecryptStatus, JdvrifError> {
    let prepared = prepare_decrypt_with_pin(metadata, is_bluesky_file, &pin)?;
    decrypt_prepared_cipher(&prepared, is_data_compressed, cipher, stream_stage_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_warning_is_required_only_for_kdf2() {
        let mut output = Vec::new();
        warn_legacy_recovery(KdfMetadataVersion::V2Secretstream, &mut output).unwrap();
        let warning = String::from_utf8(output).unwrap();
        assert!(warning.contains("compression flag is unauthenticated"));

        let mut output = Vec::new();
        warn_legacy_recovery(
            KdfMetadataVersion::V3SecretstreamAuthenticatedMode,
            &mut output,
        )
        .unwrap();
        warn_legacy_recovery(KdfMetadataVersion::V4RecordedKdfParameters, &mut output).unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn legacy_warning_propagates_write_and_flush_errors() {
        struct BrokenOutput {
            fail_write: bool,
        }
        impl Write for BrokenOutput {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.fail_write {
                    Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed output"))
                } else {
                    Ok(bytes.len())
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "flush failed"))
            }
        }
        for fail_write in [true, false] {
            assert!(warn_legacy_recovery(
                KdfMetadataVersion::V2Secretstream,
                &mut BrokenOutput { fail_write }
            )
            .is_err());
        }
    }
}
