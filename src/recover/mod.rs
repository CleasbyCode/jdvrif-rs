mod modes;
mod output;

use crate::common::{open_binary_input_or_throw, read_file_bounded, validate_file_for_read};
use crate::constants::{
    BLUESKY_JDVRIF_SIG_INDEX_ABS, DEFAULT_ICC_SIG_INDEX_ABS, DEFAULT_JDVRIF_SIG_INDEX_ABS,
    ICC_PROFILE_SIG, JDVRIF_SIG, REDDIT_UPLOAD_SIZE_LIMIT, TWITTER_UPLOAD_SIZE_LIMIT,
};
use crate::extract::read_exact_at;
use crate::runtime::JdvrifError;
use std::cmp;
use std::path::Path;

/// jdvrif writes both metadata templates at file offset 0. Bluesky keeps that
/// layout, so its signature is checked in place. The default ICC template may
/// sit behind segments an upload pipeline prepended (X-Twitter adds a JFIF
/// APP0 and keeps the rest byte-for-byte), so recover walks leading APPn/COM
/// segments, within these bounds, to the first APP2, which must be jdvrif's
/// ICC profile. Every later read is relative to where it was found.
pub(crate) const MAX_LEADING_SEGMENT_BYTES: usize = 64 * 1024;
const MAX_LEADING_SEGMENTS: usize = 16;
const SIGNATURE_PREFIX_BYTES: usize =
    MAX_LEADING_SEGMENT_BYTES + DEFAULT_JDVRIF_SIG_INDEX_ABS + JDVRIF_SIG.len();
const _: () = assert!(BLUESKY_JDVRIF_SIG_INDEX_ABS + JDVRIF_SIG.len() <= SIGNATURE_PREFIX_BYTES);

/// Absolute index of the ICC profile signature of a default-mode image.
fn find_default_icc_sig_index(prefix: &[u8]) -> Option<usize> {
    if prefix.get(..2) != Some(&[0xFF, 0xD8][..]) {
        return None;
    }
    let mut pos = 2usize;
    for _ in 0..=MAX_LEADING_SEGMENTS {
        let header = prefix.get(pos..pos + 4)?;
        if header[0] != 0xFF || pos - 2 > MAX_LEADING_SEGMENT_BYTES {
            return None;
        }
        let marker = header[1];
        if marker == 0xE2 {
            let icc_index = pos - 2 + DEFAULT_ICC_SIG_INDEX_ABS;
            let jdvrif_index = icc_index + (DEFAULT_JDVRIF_SIG_INDEX_ABS - DEFAULT_ICC_SIG_INDEX_ABS);
            return (has_signature_at(prefix, icc_index, &ICC_PROFILE_SIG)
                && has_signature_at(prefix, jdvrif_index, &JDVRIF_SIG))
            .then_some(icc_index);
        }
        if !((0xE0..=0xEF).contains(&marker) || marker == 0xFE) {
            return None;
        }
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        if length < 2 {
            return None;
        }
        pos += 2 + length;
    }
    None
}

fn has_signature_at(prefix: &[u8], offset: usize, sig: &[u8]) -> bool {
    prefix.get(offset..offset + sig.len()) == Some(sig)
}

#[derive(Debug, PartialEq, Eq)]
enum MetadataLayout {
    Icc(usize),
    Bluesky,
}

fn detect_metadata_layout(
    image_file_path: &Path,
    image_file_size: usize,
) -> Result<Option<MetadataLayout>, String> {
    let mut prefix = vec![0u8; cmp::min(image_file_size, SIGNATURE_PREFIX_BYTES)];
    let mut input =
        open_binary_input_or_throw(image_file_path, "Read Error: Failed to open image file.")?;
    read_exact_at(&mut input, 0, &mut prefix)?;

    // Default: the first APP2 after any leading segments carries both
    // signatures. Bluesky: the jdvrif signature at its fixed offset in the
    // EXIF template.
    Ok(
        if let Some(icc_index) = find_default_icc_sig_index(&prefix) {
            Some(MetadataLayout::Icc(icc_index))
        } else if has_signature_at(&prefix, BLUESKY_JDVRIF_SIG_INDEX_ABS, &JDVRIF_SIG) {
            Some(MetadataLayout::Bluesky)
        } else {
            None
        },
    )
}

use self::modes::{
    recover_from_bluesky_path, recover_from_icc_path, recover_from_reddit_path,
    recover_from_twitter_path,
};

pub(crate) fn run_native_recover(image_file_path: &Path) -> Result<(), JdvrifError> {
    crate::crypto::init()
        .map_err(|_| JdvrifError::new("Libsodium initialization failed!".to_string()))?;

    let image_file_size =
        validate_file_for_read(image_file_path, true, false).map_err(JdvrifError::from)?;

    match detect_metadata_layout(image_file_path, image_file_size).map_err(JdvrifError::from)? {
        Some(MetadataLayout::Icc(icc_index)) => {
            recover_from_icc_path(image_file_path, image_file_size, icc_index)?;
            return Ok(());
        }
        Some(MetadataLayout::Bluesky) => {
            return recover_from_bluesky_path(
                image_file_path,
                image_file_size,
                BLUESKY_JDVRIF_SIG_INDEX_ABS,
                &JDVRIF_SIG,
            );
        }
        None => {}
    }

    // Reddit and X-Twitter strip APP metadata, so identify these formats from
    // keyed DCT headers and their inner encrypted-envelope markers. Keep them
    // last so ICC and Bluesky retain priority, and bound the full image read by
    // Reddit's larger upload limit.
    //
    // These formats cannot follow the "validate declared size, then PIN, then
    // extract" ordering the ICC and Bluesky paths use. Their declared payload
    // sizes live in keyed DCT coefficients. Each native carrier caps dimensions,
    // coefficient counts, and declared payload capacity; the platform upload
    // limits cap the read below. Keep those caps in mind before raising them.
    if image_file_size <= REDDIT_UPLOAD_SIZE_LIMIT {
        let image = read_file_bounded(image_file_path, REDDIT_UPLOAD_SIZE_LIMIT)
            .map_err(JdvrifError::from)?;

        // The carrier's coefficient positions derive from the recovery PIN, so
        // the PIN has to come first: without it there is nothing to locate. A
        // wrong PIN and an image with no carrier therefore share one message.
        // That hides where a payload is, not whether one exists -- see
        // reddit_steg.cpp on what statistical steganalysis can still see.
        //
        // The PIN's kind picks the formats tried (D7): a 128-bit PIN derives only
        // the RQSTEG3 / JXSTEG4 key, a numeric PIN only the pre-v10 keys. Either
        // way one Argon2id run, so testing a PIN guess against the carrier costs
        // as much as testing it against the envelope. Images written by v9.0 are
        // still read with the cheap legacy key. A PIN of the wrong kind for the
        // image cannot be told apart from a wrong PIN here, and gets the same
        // message.
        let recovery_pin = crate::decrypt::get_pin(crate::decrypt::PinPrompt::KeyOrPin).map_err(JdvrifError::from)?;
        let carrier_keys = crate::crypto::derive_carrier_keys_from_pin(&recovery_pin)
            .map_err(|_| JdvrifError::new("KDF Error: Unable to derive carrier key."))?;

        if image.len() <= TWITTER_UPLOAD_SIZE_LIMIT {
            if let Some(envelope) =
                crate::twitter::extract_envelope(&image, &carrier_keys).map_err(JdvrifError::from)?
            {
                return recover_from_twitter_path(envelope, &recovery_pin);
            }
        }

        if let Some(envelope) =
            crate::reddit::extract_envelope(&image, &carrier_keys).map_err(JdvrifError::from)?
        {
            return recover_from_reddit_path(envelope, &recovery_pin);
        }
        return Err(JdvrifError::new(
            "File Extraction Error: Invalid KEY/PIN, or this is not a valid jdvrif \"file-embedded\" image."
                .to_string(),
        ));
    }

    Err(JdvrifError::new(
        "Image File Error: Signature check failure. This is not a valid jdvrif \"file-embedded\" image."
            .to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(tag: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "jdvrif_icc_{}_{}_{}",
            tag,
            std::process::id(),
            nanos
        ))
    }

    fn image_with_signatures_at(icc_at: usize, jdvrif_at: usize) -> Vec<u8> {
        let mut data = vec![0u8; DEFAULT_JDVRIF_SIG_INDEX_ABS + JDVRIF_SIG.len() + 64];
        data[..4].copy_from_slice(&[0xFF, 0xD8, 0xFF, 0xE2]);
        data[icc_at..icc_at + ICC_PROFILE_SIG.len()].copy_from_slice(&ICC_PROFILE_SIG);
        data[jdvrif_at..jdvrif_at + JDVRIF_SIG.len()].copy_from_slice(&JDVRIF_SIG);
        data
    }

    fn with_leading_segments(image: &[u8], segments: &[u8]) -> Vec<u8> {
        let mut out = image[..2].to_vec();
        out.extend_from_slice(segments);
        out.extend_from_slice(&image[2..]);
        out
    }

    fn detect(tag: &str, data: &[u8]) -> Option<MetadataLayout> {
        let path = temp_path(tag);
        std::fs::write(&path, data).unwrap();
        let layout = detect_metadata_layout(&path, data.len()).unwrap();
        let _ = std::fs::remove_file(&path);
        layout
    }

    const JFIF_APP0: [u8; 18] = [
        0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00,
        0x01, 0x00, 0x00,
    ];

    #[test]
    fn icc_profile_accepted_at_the_fixed_offsets() {
        let data =
            image_with_signatures_at(DEFAULT_ICC_SIG_INDEX_ABS, DEFAULT_JDVRIF_SIG_INDEX_ABS);
        assert_eq!(
            detect("exact", &data),
            Some(MetadataLayout::Icc(DEFAULT_ICC_SIG_INDEX_ABS))
        );
    }

    #[test]
    fn icc_profile_found_behind_prepended_jfif_and_comment() {
        // X-Twitter prepends a JFIF APP0 and keeps the rest byte-for-byte.
        let image =
            image_with_signatures_at(DEFAULT_ICC_SIG_INDEX_ABS, DEFAULT_JDVRIF_SIG_INDEX_ABS);
        let data = with_leading_segments(&image, &JFIF_APP0);
        assert_eq!(
            detect("jfif", &data),
            Some(MetadataLayout::Icc(DEFAULT_ICC_SIG_INDEX_ABS + JFIF_APP0.len()))
        );
        let mut segments = JFIF_APP0.to_vec();
        segments.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x04, b'h', b'i']);
        let data = with_leading_segments(&image, &segments);
        assert_eq!(
            detect("jfif_com", &data),
            Some(MetadataLayout::Icc(DEFAULT_ICC_SIG_INDEX_ABS + segments.len()))
        );
    }

    #[test]
    fn shifted_icc_profile_without_a_leading_segment_is_not_recognised() {
        // Both signatures present and correctly spaced, but six bytes later
        // with no segment in front to account for the shift.
        let data = image_with_signatures_at(
            DEFAULT_ICC_SIG_INDEX_ABS + 6,
            DEFAULT_JDVRIF_SIG_INDEX_ABS + 6,
        );
        assert_eq!(detect("shifted", &data), None);
    }

    #[test]
    fn non_app_segment_or_oversized_lead_is_not_walked() {
        let image =
            image_with_signatures_at(DEFAULT_ICC_SIG_INDEX_ABS, DEFAULT_JDVRIF_SIG_INDEX_ABS);
        let dqt = [0xFF, 0xDB, 0x00, 0x04, 0x00, 0x00];
        assert_eq!(detect("dqt", &with_leading_segments(&image, &dqt)), None);

        let mut app1 = vec![0xFF, 0xE1, 0xFF, 0xFF];
        app1.resize(2 + 0xFFFF, 0);
        let segments = [app1.clone(), app1].concat();
        assert_eq!(detect("too_far", &with_leading_segments(&image, &segments)), None);
    }

    #[test]
    fn short_file_is_not_recognised() {
        let path = temp_path("short");
        std::fs::write(&path, b"tiny").unwrap();
        assert_eq!(detect_metadata_layout(&path, 4).unwrap(), None);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn bluesky_signature_accepted_only_at_its_fixed_offset() {
        for (offset, expected) in [
            (BLUESKY_JDVRIF_SIG_INDEX_ABS, Some(MetadataLayout::Bluesky)),
            (BLUESKY_JDVRIF_SIG_INDEX_ABS - 1, None),
            (BLUESKY_JDVRIF_SIG_INDEX_ABS + 1, None),
        ] {
            let path = temp_path("bluesky");
            let mut data = vec![0u8; 0x1D1];
            data[offset..offset + JDVRIF_SIG.len()].copy_from_slice(&JDVRIF_SIG);
            std::fs::write(&path, &data).unwrap();
            assert_eq!(detect_metadata_layout(&path, data.len()).unwrap(), expected);
            let _ = std::fs::remove_file(&path);
        }
    }
}
