use crate::common::span_has_range;
use crate::constants::{
    BLUESKY_KDF_METADATA_INDEX, CORRUPT_FILE_ERROR, DEFAULT_DECRYPT_KDF_METADATA_INDEX,
    KDF_ALG_ARGON2ID13, KDF_ALG_OFFSET, KDF_MAGIC_OFFSET, KDF_METADATA_MAGIC_V2,
    KDF_METADATA_MAGIC_V3, KDF_METADATA_REGION_BYTES, KDF_NONCE_OFFSET, KDF_SALT_OFFSET,
    KDF_SENTINEL, KDF_SENTINEL_OFFSET,
};
use crate::crypto::{argon2id13, secretstream};
use crate::runtime::{DecryptOffsets, JdvrifError, KdfMetadataVersion};

use super::derive_key_from_pin;

const UNSUPPORTED_LEGACY_DECRYPT_ERROR: &str =
    "File Decryption Error: Unsupported legacy encrypted file format. Use an older jdvrif release to recover this file.";

fn get_kdf_metadata_version(data: &[u8], base_index: usize) -> KdfMetadataVersion {
    if !span_has_range(data.len(), base_index, KDF_METADATA_REGION_BYTES) {
        return KdfMetadataVersion::None;
    }

    let header = &data[base_index + KDF_MAGIC_OFFSET..base_index + KDF_MAGIC_OFFSET + 4];
    let has_common_fields = data[base_index + KDF_ALG_OFFSET] == KDF_ALG_ARGON2ID13
        && data[base_index + KDF_SENTINEL_OFFSET] == KDF_SENTINEL;
    if !has_common_fields {
        return KdfMetadataVersion::None;
    }
    if header == KDF_METADATA_MAGIC_V2 {
        return KdfMetadataVersion::V2Secretstream;
    }
    if header == KDF_METADATA_MAGIC_V3 {
        return KdfMetadataVersion::V3SecretstreamAuthenticatedMode;
    }
    KdfMetadataVersion::None
}

pub(crate) fn decrypt_offsets(is_bluesky_file: bool) -> DecryptOffsets {
    DecryptOffsets {
        sodium_key_index: if is_bluesky_file {
            BLUESKY_KDF_METADATA_INDEX
        } else {
            DEFAULT_DECRYPT_KDF_METADATA_INDEX
        },
    }
}

pub(super) fn derive_secretstream_key_and_header(
    metadata: &[u8],
    offsets: DecryptOffsets,
    pin: &u64,
) -> Result<(secretstream::Key, secretstream::Header), JdvrifError> {
    if !span_has_range(
        metadata.len(),
        offsets.sodium_key_index + KDF_SALT_OFFSET,
        argon2id13::SALTBYTES,
    ) || !span_has_range(
        metadata.len(),
        offsets.sodium_key_index + KDF_NONCE_OFFSET,
        secretstream::HEADERBYTES,
    ) {
        return Err(JdvrifError::new(CORRUPT_FILE_ERROR.to_string()));
    }

    let salt_begin = offsets.sodium_key_index + KDF_SALT_OFFSET;
    let salt_end = salt_begin + argon2id13::SALTBYTES;
    let key_bytes =
        derive_key_from_pin(pin, &metadata[salt_begin..salt_end]).map_err(JdvrifError::from)?;

    let key = secretstream::Key::from_slice(&key_bytes[..]).ok_or_else(|| {
        JdvrifError::new("KDF Error: Unable to derive encryption key.".to_string())
    })?;

    let hdr_begin = offsets.sodium_key_index + KDF_NONCE_OFFSET;
    let hdr_end = hdr_begin + secretstream::HEADERBYTES;
    let header = secretstream::Header::from_slice(&metadata[hdr_begin..hdr_end])
        .ok_or_else(|| JdvrifError::new(CORRUPT_FILE_ERROR.to_string()))?;

    Ok((key, header))
}

pub(super) fn require_supported_secretstream(
    metadata: &[u8],
    offsets: DecryptOffsets,
) -> Result<KdfMetadataVersion, JdvrifError> {
    let metadata_version = get_kdf_metadata_version(metadata, offsets.sodium_key_index);
    if metadata_version != KdfMetadataVersion::V2Secretstream
        && metadata_version != KdfMetadataVersion::V3SecretstreamAuthenticatedMode
    {
        return Err(JdvrifError::new(
            UNSUPPORTED_LEGACY_DECRYPT_ERROR.to_string(),
        ));
    }
    Ok(metadata_version)
}
