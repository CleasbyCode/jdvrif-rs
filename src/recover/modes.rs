use crate::cipher_source::{CipherSource, MemoryCipherSource};
use crate::common::{get_value, open_binary_input_or_throw, span_has_range, StagingFile};
use crate::constants::{
    BASE_OFFSET_DEFAULT, CORRUPT_FILE_ERROR, MAX_DATA_SIZE_BLUESKY, MAX_SIZE_CONCEAL,
    NO_ZLIB_COMPRESSION_ID, NO_ZLIB_COMPRESSION_ID_INDEX, REDDIT_UPLOAD_SIZE_LIMIT,
    STREAM_FRAME_LEN_BYTES, TWITTER_UPLOAD_SIZE_LIMIT,
};
use crate::crypto::secretstream;
use crate::decrypt::{
    decrypt_prepared_cipher, prepare_decrypt_from_kdf_metadata, prepare_decrypt_from_metadata,
    PreparedDecrypt,
};
use crate::extract::{
    open_default_ciphertext, read_bluesky_ciphertext, read_exact_at, skipped_profile_header_count,
    validate_bluesky_exif_metadata_capacity, PROFILE_HEADER_LENGTH,
};
use crate::key_codec::RecoveryKey;
use crate::reddit::RedditEncryptedEnvelope;
use crate::runtime::{DecryptStatus, JdvrifError};
use crate::twitter::TwitterEncryptedEnvelope;
use std::path::Path;

use super::output::{commit_recovered_output, print_recovery_complete, safe_recovery_path};
use crate::conceal_helpers::{begin_step, end_step, fail_step, format_size_precise};
use crate::conceal_segments::bluesky_segment_use;

const KEY_DERIVATION_RESULT: &str = "Argon2id from the 128-bit recovery KEY.";

/// Opens the "Deriving key" step once the KEY has been typed.
fn begin_key_derivation_after_prompt() {
    println!();
    begin_step("Deriving key");
}

#[derive(Clone, Copy)]
enum RecoveryFormat {
    Default,
    Bluesky,
    Reddit,
    Twitter,
}

// The embedded metadata block always sits at a fixed prefix of the image, so
// read exactly that many bytes and close the file again before any of it is
// interpreted.
fn read_embedded_metadata(
    image_file_path: &Path,
    offset: usize,
    size: usize,
) -> Result<Vec<u8>, JdvrifError> {
    let mut metadata = vec![0u8; size];
    let mut input =
        open_binary_input_or_throw(image_file_path, "Read Error: Failed to open image file.")
            .map_err(JdvrifError::from)?;
    read_exact_at(&mut input, offset, &mut metadata).map_err(JdvrifError::from)?;
    Ok(metadata)
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
        RecoveryFormat::Bluesky => MAX_DATA_SIZE_BLUESKY,
        RecoveryFormat::Reddit => REDDIT_UPLOAD_SIZE_LIMIT,
        RecoveryFormat::Twitter => TWITTER_UPLOAD_SIZE_LIMIT,
    };
    if embedded_file_size > maximum {
        return Err(JdvrifError::new(
            "File Extraction Error: Embedded data size exceeds the maximum allowed for this format.",
        ));
    }
    Ok(())
}

fn failed_key_error() -> JdvrifError {
    fail_step("authentication failed.");
    JdvrifError::new("File Decryption Error: Invalid recovery KEY or file is corrupt.")
}

/// Decryption and inflation run as one streamed pass, so the Decompressing
/// step only reports what that pass did.
fn report_decryption(stored_size: usize, output_size: usize, is_data_compressed: bool) {
    end_step("XChaCha20-Poly1305, authenticated.");
    if !is_data_compressed {
        return;
    }
    begin_step("Decompressing");
    end_step(&format!(
        "{} -> {}.",
        format_size_precise(stored_size),
        format_size_precise(output_size)
    ));
}

/// Shared tail of every recovery path, run once the KEY has produced `prepared`.
///
/// The ciphertext is read where it sits (cover image or decoded carrier) and
/// never staged: a wrong KEY fails on the first frame instead of after copying
/// up to 2 GiB. `open_cipher` runs the cheap structural checks first, so a
/// crafted image still cannot make this process do that work before a KEY.
///
/// The decrypted payload goes to a link-free StagingFile inode, so it never
/// exists on disk under a real directory entry -- visible to a backup or sync
/// client, or surviving a SIGKILL or power loss -- until it has authenticated.
/// It reaches its final name via linkat(2) on /proc/self/fd, the one name the
/// user is told about.
fn decrypt_and_publish<C, F>(
    prepared: &PreparedDecrypt,
    is_data_compressed: bool,
    open_cipher: F,
) -> Result<(), JdvrifError>
where
    C: CipherSource,
    F: FnOnce() -> Result<C, String>,
{
    let stream_stage = StagingFile::new(Path::new(""), "plain").map_err(JdvrifError::from)?;
    let mut cipher = open_cipher().map_err(JdvrifError::from)?;
    if cipher.remaining() == 0 {
        return Err(JdvrifError::new(
            "File Extraction Error: Embedded data file is empty.",
        ));
    }

    begin_step("Decrypting");
    let decrypt_result = decrypt_prepared_cipher(
        prepared,
        is_data_compressed,
        &mut cipher,
        stream_stage.path(),
    )?;

    let (decrypted_filename, output_size) = match decrypt_result {
        DecryptStatus::Success {
            decrypted_filename,
            output_size,
            stored_size,
        } => {
            report_decryption(stored_size, output_size, is_data_compressed);
            (decrypted_filename, output_size)
        }
        DecryptStatus::FailedKey => return Err(failed_key_error()),
    };

    begin_step("Writing output file");
    let base_output_path = safe_recovery_path(decrypted_filename).map_err(JdvrifError::from)?;
    let output_path =
        commit_recovered_output(&stream_stage, &base_output_path).map_err(JdvrifError::from)?;
    // Link-free inode: dropping it releases the blocks, nothing to unlink.
    drop(stream_stage);

    end_step(&format!(
        "{} ({}).",
        crate::common::display_safe_path(&output_path),
        format_size_precise(output_size)
    ));
    print_recovery_complete();
    Ok(())
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
    // conceal writes the profile at one fixed offset; an upload pipeline may
    // only push it back by the bounded run of leading segments that recover
    // walks. Anything else is unsupported.
    if base_offset < BASE_OFFSET_DEFAULT
        || base_offset - BASE_OFFSET_DEFAULT > super::MAX_LEADING_SEGMENT_BYTES
    {
        return Err(JdvrifError::new(
            "File Extraction Error: Unsupported embedded profile layout.",
        ));
    }
    if base_offset > image_file_size
        || ENCRYPTED_FILE_START_INDEX > image_file_size.saturating_sub(base_offset)
    {
        return Err(JdvrifError::new(CORRUPT_FILE_ERROR.to_string()));
    }

    let metadata =
        read_embedded_metadata(image_file_path, base_offset, ENCRYPTED_FILE_START_INDEX)?;

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

    // A payload that fits the template's own ICC segment records 0 extra ones.
    let icc_segments = usize::from(total_profile_header_segments).max(1);
    end_step(&format!(
        "Default mode, {icc_segments} ICC_PROFILE (APP2) segment{}.",
        if icc_segments == 1 { "" } else { "s" }
    ));

    validate_declared_cipher_size(embedded_file_size, RecoveryFormat::Default)?;
    let prepared =
        prepare_decrypt_from_metadata(&metadata, false, begin_key_derivation_after_prompt)?;
    end_step(KEY_DERIVATION_RESULT);

    decrypt_and_publish(&prepared, is_data_compressed, || {
        let headers =
            skipped_profile_header_count(embedded_file_size, total_profile_header_segments);
        if headers != 0 {
            begin_step("Skipping ICC_PROFILE headers");
        }
        let cipher = open_default_ciphertext(
            image_file_path,
            image_file_size,
            base_offset,
            embedded_file_size,
            total_profile_header_segments,
        )?;
        if headers != 0 {
            end_step(&format!(
                "{headers} header{} ({} bytes) left out of the ciphertext read; image unchanged.",
                if headers == 1 { "" } else { "s" },
                headers * PROFILE_HEADER_LENGTH
            ));
        }
        Ok(cipher)
    })
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

    let metadata = read_embedded_metadata(image_file_path, 0, ENCRYPTED_FILE_START_INDEX)?;

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

    let segment_use = bluesky_segment_use(embedded_file_size);
    end_step(&format!(
        "Bluesky mode, EXIF (APP1){}{} segment{}.",
        if segment_use.photoshop {
            " + Photoshop (APP13)"
        } else {
            ""
        },
        if segment_use.xmp { " + XMP (APP1)" } else { "" },
        if segment_use.photoshop || segment_use.xmp {
            "s"
        } else {
            ""
        }
    ));

    validate_declared_cipher_size(embedded_file_size, RecoveryFormat::Bluesky)?;
    validate_bluesky_exif_metadata_capacity(&metadata, embedded_file_size)
        .map_err(JdvrifError::from)?;
    let prepared =
        prepare_decrypt_from_metadata(&metadata, true, begin_key_derivation_after_prompt)?;
    end_step(KEY_DERIVATION_RESULT);

    // is_data_compressed (`true`) is hardcoded for Bluesky. A payload is only
    // stored uncompressed when conceal bypasses compression (source >
    // COMPRESS_BYPASS_SIZE, 10 MB), but such a payload always exceeds the 2 MB
    // Bluesky encrypted cap (MAX_DATA_SIZE_BLUESKY) and is rejected at conceal
    // time — so a valid Bluesky image is always zlib-compressed. Revisit this
    // coupling if those limits change.
    decrypt_and_publish(&prepared, true, || {
        read_bluesky_ciphertext(image_file_path, image_file_size, embedded_file_size)
            .map(MemoryCipherSource::new)
    })
}

fn recover_from_coefficient_carrier_path(
    kdf_metadata: Vec<u8>,
    encrypted_data: Vec<u8>,
    is_compressed: bool,
    recovery_key: &RecoveryKey,
    format: RecoveryFormat,
) -> Result<(), JdvrifError> {
    let embedded_file_size = encrypted_data.len();
    validate_declared_cipher_size(embedded_file_size, format)?;

    // Match the metadata paths' ordering: reject malformed KDF metadata and
    // derive the key from the KEY before any decryption work.
    // The KEY was entered before the carrier could be located.
    begin_step("Deriving key");
    let prepared = prepare_decrypt_from_kdf_metadata(&kdf_metadata, recovery_key)?;
    end_step(KEY_DERIVATION_RESULT);

    // Already in memory: the carrier decoder produced it.
    decrypt_and_publish(&prepared, is_compressed, || {
        Ok(MemoryCipherSource::new(encrypted_data))
    })
}

pub(super) fn recover_from_reddit_path(
    envelope: RedditEncryptedEnvelope,
    recovery_key: &RecoveryKey,
) -> Result<(), JdvrifError> {
    recover_from_coefficient_carrier_path(
        envelope.kdf_metadata,
        envelope.encrypted_data,
        envelope.is_compressed,
        recovery_key,
        RecoveryFormat::Reddit,
    )
}

pub(super) fn recover_from_twitter_path(
    envelope: TwitterEncryptedEnvelope,
    recovery_key: &RecoveryKey,
) -> Result<(), JdvrifError> {
    recover_from_coefficient_carrier_path(
        envelope.kdf_metadata,
        envelope.encrypted_data,
        envelope.is_compressed,
        recovery_key,
        RecoveryFormat::Twitter,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nondefault_icc_offset_is_rejected_before_metadata_read() {
        let shifted_signature_index = BASE_OFFSET_DEFAULT + 8 - 1;
        let err = recover_from_icc_path(
            Path::new("metadata-must-not-be-read.jpg"),
            4096,
            shifted_signature_index,
        )
        .expect_err("shifted ICC layout must be rejected");
        assert_eq!(
            err.to_string(),
            "File Extraction Error: Unsupported embedded profile layout."
        );
    }
}
