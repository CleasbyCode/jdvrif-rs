use std::path::Path;

use super::*;

#[path = "decrypt_kdf.rs"]
mod kdf;
#[path = "decrypt_pin.rs"]
mod pin;
#[path = "decrypt_stream.rs"]
mod stream;

use kdf::{derive_secretstream_key_and_header, require_v2_secretstream};
use pin::get_pin;
use stream::decrypt_ciphertext_to_stage_file;

pub(crate) use kdf::decrypt_offsets;

pub(crate) fn derive_key_from_pin(
    pin: u64,
    salt_bytes: &[u8],
) -> Result<[u8; secretbox::KEYBYTES], String> {
    let mut pin_bytes = pin.to_string().into_bytes();
    let salt = argon2id13::Salt::from_slice(salt_bytes)
        .ok_or_else(|| "KDF Error: Unable to derive encryption key.".to_string())?;

    let mut key_buf = [0u8; secretbox::KEYBYTES];
    argon2id13::derive_key(
        &mut key_buf,
        &pin_bytes,
        &salt,
        argon2id13::OPSLIMIT_INTERACTIVE,
        argon2id13::MEMLIMIT_INTERACTIVE,
    )
    .map_err(|_| "KDF Error: Unable to derive encryption key.".to_string())?;

    memzero(&mut pin_bytes);
    Ok(key_buf)
}

pub(crate) fn decrypt_from_cipher_stage_with_pin(
    metadata: &[u8],
    is_bluesky_file: bool,
    is_data_compressed: bool,
    cipher_stage_path: &Path,
    stream_stage_path: &Path,
    pin: u64,
) -> Result<DecryptStatus, NativeRecoverError> {
    let offsets = decrypt_offsets(is_bluesky_file);

    if !span_has_range(
        metadata.len(),
        offsets.sodium_key_index,
        KDF_METADATA_REGION_BYTES,
    ) {
        return Err(NativeRecoverError::Message(CORRUPT_FILE_ERROR.to_string()));
    }

    require_v2_secretstream(metadata, offsets)?;
    let (key, header) = derive_secretstream_key_and_header(metadata, offsets, pin)?;

    let output = decrypt_ciphertext_to_stage_file(
        cipher_stage_path,
        stream_stage_path,
        &key,
        &header,
        is_data_compressed,
    )
    .map_err(NativeRecoverError::Message)?;

    match output {
        Some(v) => Ok(DecryptStatus::Success {
            decrypted_filename: v.decrypted_filename,
            output_size: v.output_size,
        }),
        None => Ok(DecryptStatus::FailedPin),
    }
}

pub(crate) fn decrypt_from_cipher_stage(
    metadata: &[u8],
    is_bluesky_file: bool,
    is_data_compressed: bool,
    cipher_stage_path: &Path,
    stream_stage_path: &Path,
) -> Result<DecryptStatus, NativeRecoverError> {
    // Reject unsupported/legacy metadata before prompting for the PIN: there is
    // no point asking for a PIN we cannot use, and we avoid holding it across the
    // failure path. decrypt_from_cipher_stage_with_pin re-validates, so callers
    // that pass a PIN directly (e.g. tests) stay correct too.
    let offsets = decrypt_offsets(is_bluesky_file);
    if !span_has_range(
        metadata.len(),
        offsets.sodium_key_index,
        KDF_METADATA_REGION_BYTES,
    ) {
        return Err(NativeRecoverError::Message(CORRUPT_FILE_ERROR.to_string()));
    }
    require_v2_secretstream(metadata, offsets)?;

    decrypt_from_cipher_stage_with_pin(
        metadata,
        is_bluesky_file,
        is_data_compressed,
        cipher_stage_path,
        stream_stage_path,
        get_pin(),
    )
}
