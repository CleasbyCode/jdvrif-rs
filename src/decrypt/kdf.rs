use crate::common::span_has_range;
use crate::constants::{
    BLUESKY_KDF_METADATA_INDEX, CORRUPT_FILE_ERROR, DEFAULT_DECRYPT_KDF_METADATA_INDEX,
    KDF_ALG_ARGON2ID13, KDF_ALG_OFFSET, KDF_COST_FIELD_BYTES, KDF_MAGIC_OFFSET,
    KDF_MEMLIMIT_MAX_ACCEPTED, KDF_MEMLIMIT_OFFSET, KDF_METADATA_MAGIC_V2, KDF_METADATA_MAGIC_V3,
    KDF_METADATA_MAGIC_V4, KDF_METADATA_REGION_BYTES, KDF_NONCE_OFFSET, KDF_OPSLIMIT_MAX_ACCEPTED,
    KDF_OPSLIMIT_OFFSET, KDF_SALT_OFFSET, KDF_SENTINEL, KDF_SENTINEL_OFFSET,
};
use crate::crypto::{argon2id13, secretstream};
use crate::runtime::{DecryptOffsets, JdvrifError, KdfMetadataVersion, KdfParams};

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
    if header == KDF_METADATA_MAGIC_V4 {
        return KdfMetadataVersion::V4RecordedKdfParameters;
    }
    KdfMetadataVersion::None
}

/// Costs jdvrif mints today. V2/V3 images carry no record and are assumed to
/// have used exactly these -- which they did, so changing them is safe now.
pub(crate) const KDF_PARAMS_CURRENT: KdfParams = KdfParams {
    opslimit: argon2id13::OPSLIMIT_INTERACTIVE,
    memlimit: argon2id13::MEMLIMIT_INTERACTIVE,
};

fn read_cost_field(data: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; KDF_COST_FIELD_BYTES];
    bytes.copy_from_slice(&data[offset..offset + KDF_COST_FIELD_BYTES]);
    u64::from(u32::from_be_bytes(bytes))
}

/// Cost parameters this image says its key was derived with. V2/V3 carry no
/// record, so they resolve to `KDF_PARAMS_CURRENT`; V4 reads the stored pair
/// and rejects anything outside the accepted range.
pub(super) fn read_kdf_params(
    data: &[u8],
    base_index: usize,
    version: KdfMetadataVersion,
) -> Result<KdfParams, JdvrifError> {
    // V2/V3 predate the recorded fields; those bytes are random filler there,
    // so the costs are the ones jdvrif always used.
    if version != KdfMetadataVersion::V4RecordedKdfParameters {
        return Ok(KDF_PARAMS_CURRENT);
    }

    if !span_has_range(
        data.len(),
        base_index + KDF_OPSLIMIT_OFFSET,
        KDF_COST_FIELD_BYTES,
    ) || !span_has_range(
        data.len(),
        base_index + KDF_MEMLIMIT_OFFSET,
        KDF_COST_FIELD_BYTES,
    ) {
        return Err(JdvrifError::new(CORRUPT_FILE_ERROR.to_string()));
    }

    let opslimit = read_cost_field(data, base_index + KDF_OPSLIMIT_OFFSET);
    let memlimit = read_cost_field(data, base_index + KDF_MEMLIMIT_OFFSET);

    // Tampering with these fields needs no separate integrity check: they feed
    // key derivation, so any change produces a different key and the very first
    // secretstream frame fails to authenticate. The range check exists for a
    // different reason -- these drive an allocation and a work loop that run
    // before the PIN can be shown to be wrong, so a hostile image does not get
    // to name them freely.
    if opslimit < argon2id13::OPSLIMIT_MIN as u64
        || opslimit > KDF_OPSLIMIT_MAX_ACCEPTED
        || memlimit < argon2id13::MEMLIMIT_MIN as u64
        || memlimit > KDF_MEMLIMIT_MAX_ACCEPTED
    {
        return Err(JdvrifError::new(
            "File Extraction Error: Encrypted file declares unsupported key-derivation parameters."
                .to_string(),
        ));
    }

    Ok(KdfParams {
        opslimit: opslimit as usize,
        memlimit: memlimit as usize,
    })
}

pub(super) fn require_coefficient_carrier_secretstream(
    metadata: &[u8],
    offsets: DecryptOffsets,
) -> Result<KdfMetadataVersion, JdvrifError> {
    let metadata_version = get_kdf_metadata_version(metadata, offsets.sodium_key_index);
    // Coefficient-carrier envelopes have only ever carried mode-authenticating
    // metadata, so V2 is not accepted even though legacy metadata paths do.
    if !metadata_version.authenticates_stream_mode() {
        return Err(JdvrifError::new(
            "File Extraction Error: Carrier encryption metadata is corrupt or unsupported.",
        ));
    }
    Ok(metadata_version)
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
    params: KdfParams,
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
    let key_bytes = derive_key_from_pin(pin, &metadata[salt_begin..salt_end], params)
        .map_err(JdvrifError::from)?;

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
    if !metadata_version.is_supported() {
        return Err(JdvrifError::new(
            UNSUPPORTED_LEGACY_DECRYPT_ERROR.to_string(),
        ));
    }
    Ok(metadata_version)
}
