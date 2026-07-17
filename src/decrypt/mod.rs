use crate::common::span_has_range;
use crate::constants::{CORRUPT_FILE_ERROR, KDF_METADATA_REGION_BYTES};
use crate::crypto::{argon2id13, secretbox, secretstream};
use crate::runtime::{DecryptStatus, JdvrifError, KdfMetadataVersion};
use crate::signal::check_cancellation;
use std::path::Path;
use zeroize::Zeroizing;

mod kdf;
mod pin;
mod stream;

use kdf::{derive_secretstream_key_and_header, require_supported_secretstream};
use pin::get_pin;
use stream::decrypt_ciphertext_to_stage_file;

pub(crate) use kdf::decrypt_offsets;

pub(crate) struct PreparedDecrypt {
    key: secretstream::Key,
    header: secretstream::Header,
    metadata_version: KdfMetadataVersion,
}

fn prepare_decrypt_with_pin(
    metadata: &[u8],
    is_bluesky_file: bool,
    pin: &u64,
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
    let (key, header) = derive_secretstream_key_and_header(metadata, offsets, pin)?;
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
    require_supported_secretstream(metadata, offsets)?;

    let pin = get_pin().map_err(JdvrifError::from)?;
    prepare_decrypt_with_pin(metadata, is_bluesky_file, &pin)
}

pub(crate) fn decrypt_prepared_cipher_stage(
    prepared: &PreparedDecrypt,
    is_data_compressed: bool,
    cipher_stage_path: &Path,
    stream_stage_path: &Path,
) -> Result<DecryptStatus, JdvrifError> {
    let output = decrypt_ciphertext_to_stage_file(
        cipher_stage_path,
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

pub(crate) fn derive_key_from_pin(
    pin: &u64,
    salt_bytes: &[u8],
) -> Result<Zeroizing<[u8; secretbox::KEYBYTES]>, String> {
    check_cancellation()?;
    let pin_bytes = Zeroizing::new(pin.to_string().into_bytes());
    let salt = argon2id13::Salt::from_slice(salt_bytes)
        .ok_or_else(|| "KDF Error: Unable to derive encryption key.".to_string())?;

    let mut key_buf = Zeroizing::new([0u8; secretbox::KEYBYTES]);
    argon2id13::derive_key(
        &mut key_buf[..],
        &pin_bytes[..],
        &salt,
        argon2id13::OPSLIMIT_INTERACTIVE,
        argon2id13::MEMLIMIT_INTERACTIVE,
    )
    .map_err(|_| "KDF Error: Unable to derive encryption key.".to_string())?;

    check_cancellation()?;
    Ok(key_buf)
}

#[cfg(test)]
pub(crate) fn decrypt_from_cipher_stage_with_pin(
    metadata: &[u8],
    is_bluesky_file: bool,
    is_data_compressed: bool,
    cipher_stage_path: &Path,
    stream_stage_path: &Path,
    pin: u64,
) -> Result<DecryptStatus, JdvrifError> {
    let prepared = prepare_decrypt_with_pin(metadata, is_bluesky_file, &pin)?;
    decrypt_prepared_cipher_stage(
        &prepared,
        is_data_compressed,
        cipher_stage_path,
        stream_stage_path,
    )
}
