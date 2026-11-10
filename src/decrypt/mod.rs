use crate::cipher_source::CipherSource;
use crate::common::span_has_range;
use crate::constants::{CORRUPT_FILE_ERROR, KDF_METADATA_REGION_BYTES};
use crate::crypto::{argon2id13, secretbox, secretstream};
use crate::key_codec::RecoveryKey;
use crate::runtime::{DecryptStatus, JdvrifError, KdfParams};
use crate::signal::check_cancellation;
use std::path::Path;
use zeroize::Zeroizing;

mod kdf;
mod key_input;
mod stream;

use kdf::{
    derive_secretstream_key_and_header, read_kdf_params, require_coefficient_carrier_secretstream,
    require_supported_secretstream,
};
pub(crate) use key_input::get_recovery_key;
use stream::decrypt_ciphertext_to_stage_file;

pub(crate) use kdf::{decrypt_offsets, KDF_PARAMS_CURRENT};

pub(crate) struct PreparedDecrypt {
    key: secretstream::Key,
    header: secretstream::Header,
}

fn prepare_decrypt_with_key(
    metadata: &[u8],
    is_bluesky_file: bool,
    recovery_key: &RecoveryKey,
) -> Result<PreparedDecrypt, JdvrifError> {
    let offsets = decrypt_offsets(is_bluesky_file);
    if !span_has_range(
        metadata.len(),
        offsets.sodium_key_index,
        KDF_METADATA_REGION_BYTES,
    ) {
        return Err(JdvrifError::new(CORRUPT_FILE_ERROR.to_string()));
    }

    require_supported_secretstream(metadata, offsets)?;
    let params = read_kdf_params(metadata, offsets.sodium_key_index)?;
    let (key, header) =
        derive_secretstream_key_and_header(metadata, offsets, params, recovery_key)?;
    Ok(PreparedDecrypt { key, header })
}

/// `on_key_entered` runs between the KEY prompt and the key derivation
/// (recover starts its progress step there).
pub(crate) fn prepare_decrypt_from_metadata(
    metadata: &[u8],
    is_bluesky_file: bool,
    on_key_entered: impl FnOnce(),
) -> Result<PreparedDecrypt, JdvrifError> {
    // Reject unsupported metadata before asking for a KEY.
    let offsets = decrypt_offsets(is_bluesky_file);
    if !span_has_range(
        metadata.len(),
        offsets.sodium_key_index,
        KDF_METADATA_REGION_BYTES,
    ) {
        return Err(JdvrifError::new(CORRUPT_FILE_ERROR.to_string()));
    }
    require_supported_secretstream(metadata, offsets)?;
    // Resolved before prompting: an image declaring costs we will not run is
    // rejected without the user typing a KEY.
    read_kdf_params(metadata, offsets.sodium_key_index)?;

    let recovery_key = get_recovery_key().map_err(JdvrifError::from)?;
    on_key_entered();
    prepare_decrypt_with_key(metadata, is_bluesky_file, &recovery_key)
}

/// Takes the KEY the caller has already collected: coefficient-carrier
/// positions derive from it, so recover must obtain it before it can locate
/// anything, and must not prompt a second time here.
pub(crate) fn prepare_decrypt_from_kdf_metadata(
    metadata: &[u8],
    recovery_key: &RecoveryKey,
) -> Result<PreparedDecrypt, JdvrifError> {
    if metadata.len() != KDF_METADATA_REGION_BYTES {
        return Err(JdvrifError::new(CORRUPT_FILE_ERROR));
    }
    let offsets = crate::runtime::DecryptOffsets {
        sodium_key_index: 0,
    };
    require_coefficient_carrier_secretstream(metadata, offsets)?;
    // Reject corrupt/unsupported metadata -- and costs we will not run --
    // before Argon2id runs.
    let params = read_kdf_params(metadata, offsets.sodium_key_index)?;
    let (key, header) =
        derive_secretstream_key_and_header(metadata, offsets, params, recovery_key)?;
    Ok(PreparedDecrypt { key, header })
}

/// Decrypts `cipher` (read where it sits -- never staged) into the plaintext
/// StagingFile at `stream_stage_path`.
pub(crate) fn decrypt_prepared_cipher(
    prepared: &PreparedDecrypt,
    is_data_compressed: bool,
    cipher: &mut dyn CipherSource,
    stream_stage_path: &Path,
) -> Result<DecryptStatus, JdvrifError> {
    let output = decrypt_ciphertext_to_stage_file(
        cipher,
        stream_stage_path,
        &prepared.key,
        &prepared.header,
        is_data_compressed,
    )
    .map_err(JdvrifError::from)?;

    match output {
        Some(v) => Ok(DecryptStatus::Success {
            decrypted_filename: v.decrypted_filename,
            output_size: v.output_size,
            stored_size: v.stored_size,
        }),
        None => Ok(DecryptStatus::FailedKey),
    }
}

/// The Argon2id password (D4) is the KEY's 16 secret bytes, staged in a stack
/// buffer that is wiped on every exit path.
pub(crate) fn derive_key_from_recovery_key(
    recovery_key: &RecoveryKey,
    salt_bytes: &[u8],
    params: KdfParams,
) -> Result<Zeroizing<[u8; secretbox::KEYBYTES]>, String> {
    check_cancellation()?;
    let RecoveryKey::V128(secret) = recovery_key;
    let recovery_key_buf = Zeroizing::new(*secret);
    let recovery_key_bytes = &recovery_key_buf[..];
    let salt = argon2id13::Salt::from_slice(salt_bytes)
        .ok_or_else(|| "KDF Error: Unable to derive encryption key.".to_string())?;

    let mut key_buf = Zeroizing::new([0u8; secretbox::KEYBYTES]);
    argon2id13::derive_key(
        &mut key_buf[..],
        recovery_key_bytes,
        &salt,
        params.opslimit,
        params.memlimit,
    )
    .map_err(|_| "KDF Error: Unable to derive encryption key.".to_string())?;

    check_cancellation()?;
    Ok(key_buf)
}

#[cfg(test)]
pub(crate) fn decrypt_from_cipher_with_key(
    metadata: &[u8],
    is_bluesky_file: bool,
    is_data_compressed: bool,
    cipher: &mut dyn CipherSource,
    stream_stage_path: &Path,
    recovery_key: RecoveryKey,
) -> Result<DecryptStatus, JdvrifError> {
    let prepared = prepare_decrypt_with_key(metadata, is_bluesky_file, &recovery_key)?;
    decrypt_prepared_cipher(&prepared, is_data_compressed, cipher, stream_stage_path)
}
