use crate::common::span_has_range;
use crate::constants::{
    BLUESKY_KDF_METADATA_INDEX, CORRUPT_FILE_ERROR, DEFAULT_DECRYPT_KDF_METADATA_INDEX,
    KDF_ALG_ARGON2ID13, KDF_ALG_OFFSET, KDF_COST_FIELD_BYTES, KDF_MAGIC_OFFSET,
    KDF_MEMLIMIT_MAX_ACCEPTED, KDF_MEMLIMIT_OFFSET, KDF_METADATA_MAGIC_V5, KDF_METADATA_REGION_BYTES, KDF_NONCE_OFFSET, KDF_OPSLIMIT_MAX_ACCEPTED,
    KDF_OPSLIMIT_OFFSET, KDF_SALT_OFFSET, KDF_SENTINEL, KDF_SENTINEL_OFFSET,
};
use crate::crypto::{argon2id13, secretstream};
use crate::pin_codec::RecoveryPin;
use crate::runtime::{DecryptOffsets, JdvrifError, KdfParams};

use super::derive_key_from_pin;

const UNSUPPORTED_DECRYPT_ERROR: &str =
    "File Decryption Error: Unsupported encrypted file format. Images made before jdvrif v10 need the legacy jdvrif release.";

fn has_kdf_metadata_v5(data: &[u8], base_index: usize) -> bool {
    span_has_range(data.len(), base_index, KDF_METADATA_REGION_BYTES)
        && data[base_index + KDF_ALG_OFFSET] == KDF_ALG_ARGON2ID13
        && data[base_index + KDF_SENTINEL_OFFSET] == KDF_SENTINEL
        && data[base_index + KDF_MAGIC_OFFSET..base_index + KDF_MAGIC_OFFSET + 4] == KDF_METADATA_MAGIC_V5
}

/// Costs jdvrif mints today. Every image records them, so they can be retuned.
pub(crate) const KDF_PARAMS_CURRENT: KdfParams = KdfParams {
    opslimit: argon2id13::OPSLIMIT_INTERACTIVE,
    memlimit: argon2id13::MEMLIMIT_INTERACTIVE,
};

fn read_cost_field(data: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; KDF_COST_FIELD_BYTES];
    bytes.copy_from_slice(&data[offset..offset + KDF_COST_FIELD_BYTES]);
    u64::from(u32::from_be_bytes(bytes))
}

/// Cost parameters this image says its key was derived with; rejects anything
/// outside the accepted range.
pub(super) fn read_kdf_params(
    data: &[u8],
    base_index: usize,
) -> Result<KdfParams, JdvrifError> {
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
) -> Result<(), JdvrifError> {
    if !has_kdf_metadata_v5(metadata, offsets.sodium_key_index) {
        return Err(JdvrifError::new(
            "File Extraction Error: Carrier encryption metadata is corrupt or unsupported.",
        ));
    }
    Ok(())
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
) -> Result<(), JdvrifError> {
    if !has_kdf_metadata_v5(metadata, offsets.sodium_key_index) {
        return Err(JdvrifError::new(UNSUPPORTED_DECRYPT_ERROR.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(has_kdf_metadata_v5(&metadata, 0));
        let params = read_kdf_params(&metadata, 0).unwrap();
        assert!(params.opslimit == 2 && params.memlimit == 64 * 1024 * 1024);
    }

    #[test]
    fn pre_v10_magics_are_unsupported() {
        for magic in [b"KDF2", b"KDF3", b"KDF4"] {
            assert!(!has_kdf_metadata_v5(&metadata_with_magic(magic), 0));
        }
    }
}
