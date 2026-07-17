use crate::common::{cleanup_path_no_throw, get_value, open_binary_input_or_throw, span_has_range};
use crate::constants::{
    BASE_OFFSET_DEFAULT, CORRUPT_FILE_ERROR, MAX_DATA_SIZE_BLUESKY, MAX_SIZE_CONCEAL,
    MAX_SIZE_REDDIT, NO_ZLIB_COMPRESSION_ID, NO_ZLIB_COMPRESSION_ID_INDEX, STREAM_FRAME_LEN_BYTES,
};
use crate::crypto::secretstream;
use crate::decrypt::{decrypt_prepared_cipher_stage, prepare_decrypt_from_metadata};
use crate::extract::{
    extract_bluesky_ciphertext_to_file, extract_default_ciphertext_to_file, read_exact_at,
    validate_bluesky_exif_metadata_capacity,
};
use crate::runtime::{DecryptStatus, JdvrifError, TempFileGuard};
use std::path::Path;

use super::output::{
    commit_recovered_output, print_recovery_success, safe_recovery_path, temp_recovery_path,
};

#[derive(Clone, Copy)]
enum RecoveryFormat {
    Default,
    Reddit,
    Bluesky,
}

fn validate_declared_cipher_size(
    embedded_file_size: usize,
    format: RecoveryFormat,
) -> Result<(), JdvrifError> {
    let minimum = STREAM_FRAME_LEN_BYTES + secretstream::ABYTES;
    if embedded_file_size == 0 {
        return Err(JdvrifError::new(
            "File Extraction Error: Embedded data file is empty.",
        ));
    }
    if embedded_file_size < minimum {
        return Err(JdvrifError::new(CORRUPT_FILE_ERROR));
    }

    let maximum = match format {
        RecoveryFormat::Default => MAX_SIZE_CONCEAL + 50 * 1024 * 1024,
        RecoveryFormat::Reddit => MAX_SIZE_REDDIT + 2 * 1024 * 1024,
        RecoveryFormat::Bluesky => MAX_DATA_SIZE_BLUESKY,
    };
    if embedded_file_size > maximum {
        return Err(JdvrifError::new(
            "File Extraction Error: Embedded data size exceeds the maximum allowed for this format.",
        ));
    }
    Ok(())
}

fn failed_pin_error() -> JdvrifError {
    eprintln!("\nDecryption failed!");
    JdvrifError::new("File Decryption Error: Invalid recovery PIN or file is corrupt.")
}

pub(super) fn recover_from_icc_path(
    image_file_path: &Path,
    image_file_size: usize,
    icc_profile_sig_index: usize,
) -> Result<(), JdvrifError> {
    const INDEX_DIFF: usize = 8;
    const NO_ZLIB_COMPRESSION_ID_INDEX_DIFF: usize = 24;
    const TOTAL_PROFILE_HEADER_SEGMENTS_INDEX: usize = 0x2C8;
    const FILE_SIZE_INDEX: usize = 0x2CA;
    const ENCRYPTED_FILE_START_INDEX: usize = 0x33B;

    if icc_profile_sig_index < INDEX_DIFF {
        return Err(JdvrifError::new(
            "File Extraction Error: Corrupt ICC metadata.".to_string(),
        ));
    }

    let base_offset = icc_profile_sig_index - INDEX_DIFF;
    if base_offset > image_file_size
        || ENCRYPTED_FILE_START_INDEX > image_file_size.saturating_sub(base_offset)
    {
        return Err(JdvrifError::new(CORRUPT_FILE_ERROR.to_string()));
    }

    let mut metadata = vec![0u8; ENCRYPTED_FILE_START_INDEX];
    {
        let mut input =
            open_binary_input_or_throw(image_file_path, "Read Error: Failed to open image file.")
                .map_err(JdvrifError::from)?;
        read_exact_at(&mut input, base_offset, &mut metadata).map_err(JdvrifError::from)?;
    }

    let compression_marker_index = NO_ZLIB_COMPRESSION_ID_INDEX - NO_ZLIB_COMPRESSION_ID_INDEX_DIFF;
    if !span_has_range(metadata.len(), compression_marker_index, 1)
        || !span_has_range(metadata.len(), TOTAL_PROFILE_HEADER_SEGMENTS_INDEX, 2)
        || !span_has_range(metadata.len(), FILE_SIZE_INDEX, 4)
    {
        return Err(JdvrifError::new(
            "File Extraction Error: Corrupt metadata.".to_string(),
        ));
    }

    let is_data_compressed = metadata[compression_marker_index] != NO_ZLIB_COMPRESSION_ID;
    let total_profile_header_segments = get_value(&metadata, TOTAL_PROFILE_HEADER_SEGMENTS_INDEX, 2)
        .map_err(JdvrifError::from)? as u16;
    let embedded_file_size = get_value(&metadata, FILE_SIZE_INDEX, 4).map_err(JdvrifError::from)?;

    let format = if base_offset == BASE_OFFSET_DEFAULT {
        RecoveryFormat::Default
    } else {
        RecoveryFormat::Reddit
    };
    validate_declared_cipher_size(embedded_file_size, format)?;
    let prepared = prepare_decrypt_from_metadata(&metadata, false)?;

    let cipher_stage_path =
        temp_recovery_path(Path::new("jdvrif_cipher.bin")).map_err(JdvrifError::from)?;
    let mut cipher_guard = TempFileGuard::new(cipher_stage_path.clone());
    let stream_stage_path =
        temp_recovery_path(Path::new("jdvrif_recovered.bin")).map_err(JdvrifError::from)?;
    let mut stream_guard = TempFileGuard::new(stream_stage_path.clone());

    let extracted_cipher_size = extract_default_ciphertext_to_file(
        image_file_path,
        image_file_size,
        base_offset,
        embedded_file_size,
        total_profile_header_segments,
        &cipher_stage_path,
    )
    .map_err(JdvrifError::from)?;
    if extracted_cipher_size == 0 {
        return Err(JdvrifError::new(
            "File Extraction Error: Embedded data file is empty.".to_string(),
        ));
    }

    let decrypt_result = decrypt_prepared_cipher_stage(
        &prepared,
        is_data_compressed,
        &cipher_stage_path,
        &stream_stage_path,
    )?;

    let (decrypted_filename, output_size) = match decrypt_result {
        DecryptStatus::Success {
            decrypted_filename,
            output_size,
        } => (decrypted_filename, output_size),
        DecryptStatus::FailedPin => return Err(failed_pin_error()),
    };

    let base_output_path = safe_recovery_path(decrypted_filename).map_err(JdvrifError::from)?;
    let output_path = commit_recovered_output(&stream_stage_path, &base_output_path)
        .map_err(JdvrifError::from)?;
    stream_guard.dismiss();
    cleanup_path_no_throw(&cipher_stage_path);
    cipher_guard.dismiss();

    print_recovery_success(&output_path, output_size);
    Ok(())
}

pub(super) fn recover_from_bluesky_path(
    image_file_path: &Path,
    image_file_size: usize,
    jdvrif_sig_index: usize,
    jdvrif_sig: &[u8],
) -> Result<(), JdvrifError> {
    const FILE_SIZE_INDEX: usize = 0x1CD;
    const ENCRYPTED_FILE_START_INDEX: usize = 0x1D1;

    if ENCRYPTED_FILE_START_INDEX > image_file_size {
        return Err(JdvrifError::new(
            "Image File Error: Corrupt signature metadata.".to_string(),
        ));
    }

    let mut metadata = vec![0u8; ENCRYPTED_FILE_START_INDEX];
    {
        let mut input =
            open_binary_input_or_throw(image_file_path, "Read Error: Failed to open image file.")
                .map_err(JdvrifError::from)?;
        read_exact_at(&mut input, 0, &mut metadata).map_err(JdvrifError::from)?;
    }

    if jdvrif_sig_index > metadata.len()
        || jdvrif_sig.len() > metadata.len().saturating_sub(jdvrif_sig_index)
    {
        return Err(JdvrifError::new(
            "Image File Error: Corrupt signature metadata.".to_string(),
        ));
    }

    if &metadata[jdvrif_sig_index..jdvrif_sig_index + jdvrif_sig.len()] != jdvrif_sig {
        return Err(JdvrifError::new(
            "Image File Error: Corrupt signature metadata.".to_string(),
        ));
    }

    if !span_has_range(metadata.len(), FILE_SIZE_INDEX, 4) {
        return Err(JdvrifError::new(
            "File Extraction Error: Corrupt metadata.".to_string(),
        ));
    }

    let embedded_file_size = get_value(&metadata, FILE_SIZE_INDEX, 4).map_err(JdvrifError::from)?;

    validate_declared_cipher_size(embedded_file_size, RecoveryFormat::Bluesky)?;
    validate_bluesky_exif_metadata_capacity(&metadata, embedded_file_size)
        .map_err(JdvrifError::from)?;
    let prepared = prepare_decrypt_from_metadata(&metadata, true)?;

    let cipher_stage_path =
        temp_recovery_path(Path::new("jdvrif_cipher.bin")).map_err(JdvrifError::from)?;
    let mut cipher_guard = TempFileGuard::new(cipher_stage_path.clone());
    let stream_stage_path =
        temp_recovery_path(Path::new("jdvrif_recovered.bin")).map_err(JdvrifError::from)?;
    let mut stream_guard = TempFileGuard::new(stream_stage_path.clone());

    let extracted_cipher_size = extract_bluesky_ciphertext_to_file(
        image_file_path,
        image_file_size,
        embedded_file_size,
        &cipher_stage_path,
    )
    .map_err(JdvrifError::from)?;
    if extracted_cipher_size == 0 {
        return Err(JdvrifError::new(
            "File Extraction Error: Embedded data file is empty.".to_string(),
        ));
    }

    // The final `true` (is_data_compressed) is hardcoded for Bluesky. A payload
    // is only stored uncompressed when conceal bypasses compression (source >
    // COMPRESS_BYPASS_SIZE, 10 MB), but such a payload always exceeds the 2 MB
    // Bluesky encrypted cap (MAX_DATA_SIZE_BLUESKY) and is rejected at conceal
    // time — so a valid Bluesky image is always zlib-compressed. Revisit this
    // coupling if those limits change.
    let decrypt_result =
        decrypt_prepared_cipher_stage(&prepared, true, &cipher_stage_path, &stream_stage_path)?;

    let (decrypted_filename, output_size) = match decrypt_result {
        DecryptStatus::Success {
            decrypted_filename,
            output_size,
        } => (decrypted_filename, output_size),
        DecryptStatus::FailedPin => return Err(failed_pin_error()),
    };

    let base_output_path = safe_recovery_path(decrypted_filename).map_err(JdvrifError::from)?;
    let output_path = commit_recovered_output(&stream_stage_path, &base_output_path)
        .map_err(JdvrifError::from)?;
    stream_guard.dismiss();
    cleanup_path_no_throw(&cipher_stage_path);
    cipher_guard.dismiss();

    print_recovery_success(&output_path, output_size);
    Ok(())
}
