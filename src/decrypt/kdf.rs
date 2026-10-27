use crate::common::span_has_range;
use crate::constants::{
    BLUESKY_KDF_METADATA_INDEX, CORRUPT_FILE_ERROR, DEFAULT_DECRYPT_KDF_METADATA_INDEX,
    KDF_ALG_ARGON2ID13, KDF_ALG_OFFSET, KDF_COST_FIELD_BYTES, KDF_MAGIC_OFFSET,
    KDF_MEMLIMIT_MAX_ACCEPTED, KDF_MEMLIMIT_OFFSET, KDF_METADATA_MAGIC_V2, KDF_METADATA_MAGIC_V3,
    KDF_METADATA_MAGIC_V4, KDF_METADATA_MAGIC_V5, KDF_METADATA_REGION_BYTES, KDF_NONCE_OFFSET, KDF_OPSLIMIT_MAX_ACCEPTED,
    KDF_OPSLIMIT_OFFSET, KDF_SALT_OFFSET, KDF_SENTINEL, KDF_SENTINEL_OFFSET,
};
use crate::crypto::{argon2id13, secretstream};
use crate::pin_codec::RecoveryPin;
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
    if header == KDF_METADATA_MAGIC_V5 {
        return KdfMetadataVersion::V5Pin128;
    }
    KdfMetadataVersion::None
}

/// Costs jdvrif mints today. Every new image is V5 and records them, so they
/// can be retuned freely: older V4 images keep the costs they recorded.
pub(crate) const KDF_PARAMS_CURRENT: KdfParams = KdfParams {
    opslimit: argon2id13::OPSLIMIT_INTERACTIVE,
    memlimit: argon2id13::MEMLIMIT_INTERACTIVE,
};

/// Costs every V2/V3 image was made with. Those formats record nothing, so
/// these are part of the formats and must never change. Written out rather
/// than taken from libsodium's INTERACTIVE preset (equal today) so neither a
/// retune of `KDF_PARAMS_CURRENT` nor a libsodium change can move them.
/// Mirrors C++ `KDF_PARAMS_V2_V3`.
const KDF_PARAMS_V2_V3: KdfParams = KdfParams {
    opslimit: 2,
    memlimit: 64 * 1024 * 1024,
};

fn read_cost_field(data: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; KDF_COST_FIELD_BYTES];
    bytes.copy_from_slice(&data[offset..offset + KDF_COST_FIELD_BYTES]);
    u64::from(u32::from_be_bytes(bytes))
}

/// Cost parameters this image says its key was derived with. V2/V3 carry no
/// record, so they resolve to `KDF_PARAMS_V2_V3`; V4/V5 read the stored pair
/// and rejects anything outside the accepted range.
pub(super) fn read_kdf_params(
    data: &[u8],
    base_index: usize,
    version: KdfMetadataVersion,
) -> Result<KdfParams, JdvrifError> {
    // V2/V3 predate the recorded fields; those bytes are random filler there,
    // so the costs are the fixed ones those formats were always made with.
    if !version.records_kdf_parameters() {
        return Ok(KDF_PARAMS_V2_V3);
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

/// Refuses, with the user-facing mismatch message, a PIN whose kind cannot
/// belong to an image with this metadata version (V2-V4 need a legacy decimal
/// PIN, V5 a 128-bit one). Call it once the PIN is in hand and before any
/// Argon2id run. Mirrors C++ `requirePinMatchesKdfVersion`.
pub(super) fn require_pin_matches_kdf_version(
    pin: &RecoveryPin,
    version: KdfMetadataVersion,
) -> Result<(), JdvrifError> {
    let image_needs_pin128 = version == KdfMetadataVersion::V5Pin128;
    match pin {
        RecoveryPin::Legacy(_) if image_needs_pin128 => Err(JdvrifError::new(
            "File Extraction Error: This image was made by jdvrif v10 or later and needs its \
             24-character recovery KEY.",
        )),
        RecoveryPin::V128(_) if !image_needs_pin128 => Err(JdvrifError::new(
            "File Extraction Error: This image was made before jdvrif v10 and needs the numeric \
             recovery PIN it was created with.",
        )),
        _ => Ok(()),
    }
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
    pin: &RecoveryPin,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_v3_costs_are_fixed_not_current() {
        // V2/V3 record nothing: whatever sits in the cost fields is ignored,
        // and the answer is the formats' fixed pair, never KDF_PARAMS_CURRENT.
        let filler = vec![0xA5u8; 256];
        for version in [
            KdfMetadataVersion::V2Secretstream,
            KdfMetadataVersion::V3SecretstreamAuthenticatedMode,
        ] {
            let params = read_kdf_params(&filler, 0, version).unwrap();
            assert!(params.opslimit == 2 && params.memlimit == 64 * 1024 * 1024);
        }
    }

    fn metadata_with_magic(magic: &[u8; 4]) -> Vec<u8> {
        let mut metadata = vec![0u8; KDF_METADATA_REGION_BYTES];
        metadata[KDF_MAGIC_OFFSET..KDF_MAGIC_OFFSET + 4].copy_from_slice(magic);
        metadata[KDF_ALG_OFFSET] = KDF_ALG_ARGON2ID13;
        metadata[KDF_SENTINEL_OFFSET] = KDF_SENTINEL;
        metadata[KDF_OPSLIMIT_OFFSET..KDF_OPSLIMIT_OFFSET + 4].copy_from_slice(&2u32.to_be_bytes());
        metadata[KDF_MEMLIMIT_OFFSET..KDF_MEMLIMIT_OFFSET + 4]
            .copy_from_slice(&(64u32 * 1024 * 1024).to_be_bytes());
        metadata
    }

    #[test]
    fn kdf5_is_recognised_and_records_costs() {
        let metadata = metadata_with_magic(b"KDF5");
        let version = get_kdf_metadata_version(&metadata, 0);
        assert!(version == KdfMetadataVersion::V5Pin128);
        assert!(version.is_supported() && version.authenticates_stream_mode());
        let params = read_kdf_params(&metadata, 0, version).unwrap();
        assert!(params.opslimit == 2 && params.memlimit == 64 * 1024 * 1024);
    }

    #[test]
    fn pin_kind_must_match_kdf_version() {
        const V10_NEEDS_PIN128: &str = "File Extraction Error: This image was made by jdvrif v10 or later and needs its 24-character recovery KEY.";
        const PRE_V10_NEEDS_DECIMAL: &str = "File Extraction Error: This image was made before jdvrif v10 and needs the numeric recovery PIN it was created with.";
        let legacy = RecoveryPin::Legacy(1234);
        let modern = RecoveryPin::V128([7u8; 16]);

        assert!(require_pin_matches_kdf_version(&modern, KdfMetadataVersion::V5Pin128).is_ok());
        let err = require_pin_matches_kdf_version(&legacy, KdfMetadataVersion::V5Pin128).unwrap_err();
        assert_eq!(err.to_string(), V10_NEEDS_PIN128);
        for version in [
            KdfMetadataVersion::V2Secretstream,
            KdfMetadataVersion::V3SecretstreamAuthenticatedMode,
            KdfMetadataVersion::V4RecordedKdfParameters,
        ] {
            assert!(require_pin_matches_kdf_version(&legacy, version).is_ok());
            let err = require_pin_matches_kdf_version(&modern, version).unwrap_err();
            assert_eq!(err.to_string(), PRE_V10_NEEDS_DECIMAL);
        }
    }
}
