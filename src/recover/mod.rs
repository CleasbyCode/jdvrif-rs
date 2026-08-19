mod modes;
mod output;

use crate::common::{open_binary_input_or_throw, validate_file_for_read};
use crate::constants::{
    DEFAULT_ICC_SIG_INDEX_ABS, DEFAULT_JDVRIF_SIG_INDEX_ABS, ICC_PROFILE_SIG, JDVRIF_SIG,
};
use crate::extract::{find_signature_in_file, read_exact_at};
use crate::runtime::JdvrifError;
use std::cmp;
use std::path::Path;

/// jdvrif always writes the ICC template at file offset 0, so the profile and
/// jdvrif signatures can only ever sit at two fixed absolute offsets -- which is
/// exactly what `recover_from_icc_path` re-checks before it will use the layout.
/// Verifying them in place costs one short read; scanning for them costs a pass
/// over an input that may be gigabytes and can never accept a hit anywhere else.
fn has_embedded_icc_profile(
    image_file_path: &Path,
    image_file_size: usize,
) -> Result<bool, String> {
    const PREFIX_BYTES: usize = DEFAULT_JDVRIF_SIG_INDEX_ABS + JDVRIF_SIG.len();
    const _: () = assert!(DEFAULT_ICC_SIG_INDEX_ABS + ICC_PROFILE_SIG.len() <= PREFIX_BYTES);

    if image_file_size < PREFIX_BYTES {
        return Ok(false);
    }

    let mut prefix = vec![0u8; PREFIX_BYTES];
    let mut input =
        open_binary_input_or_throw(image_file_path, "Read Error: Failed to open image file.")?;
    read_exact_at(&mut input, 0, &mut prefix)?;

    Ok(prefix[DEFAULT_ICC_SIG_INDEX_ABS..DEFAULT_ICC_SIG_INDEX_ABS + ICC_PROFILE_SIG.len()]
        == ICC_PROFILE_SIG
        && prefix[DEFAULT_JDVRIF_SIG_INDEX_ABS..DEFAULT_JDVRIF_SIG_INDEX_ABS + JDVRIF_SIG.len()]
            == JDVRIF_SIG)
}

use self::modes::{recover_from_bluesky_path, recover_from_icc_path};

pub(crate) fn run_native_recover(image_file_path: &Path) -> Result<(), JdvrifError> {
    // BLUESKY encrypted_payload_start_index: jdvrif's header signature, for a
    // Bluesky file, lives within these first bytes.
    const BLUESKY_HEADER_SEARCH_LIMIT: usize = 0x1D1;

    crate::crypto::init()
        .map_err(|_| JdvrifError::new("Libsodium initialization failed!".to_string()))?;

    let image_file_size =
        validate_file_for_read(image_file_path, true, false).map_err(JdvrifError::from)?;

    // Default: both signatures verified at their two fixed offsets.
    if has_embedded_icc_profile(image_file_path, image_file_size).map_err(JdvrifError::from)? {
        recover_from_icc_path(image_file_path, image_file_size, DEFAULT_ICC_SIG_INDEX_ABS)?;
        return Ok(());
    }

    // Bluesky: the jdvrif signature within the fixed-size header region.
    let header_search_limit = cmp::min(image_file_size, BLUESKY_HEADER_SEARCH_LIMIT);
    if let Some(jdvrif_sig_index) =
        find_signature_in_file(image_file_path, &JDVRIF_SIG, header_search_limit, 0)
            .map_err(JdvrifError::from)?
    {
        return recover_from_bluesky_path(
            image_file_path,
            image_file_size,
            jdvrif_sig_index,
            &JDVRIF_SIG,
        );
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
        std::env::temp_dir().join(format!("jdvrif_icc_{}_{}_{}", tag, std::process::id(), nanos))
    }

    fn image_with_signatures_at(icc_at: usize, jdvrif_at: usize) -> Vec<u8> {
        let mut data = vec![0u8; DEFAULT_JDVRIF_SIG_INDEX_ABS + JDVRIF_SIG.len() + 64];
        data[icc_at..icc_at + ICC_PROFILE_SIG.len()].copy_from_slice(&ICC_PROFILE_SIG);
        data[jdvrif_at..jdvrif_at + JDVRIF_SIG.len()].copy_from_slice(&JDVRIF_SIG);
        data
    }

    #[test]
    fn icc_profile_accepted_only_at_the_fixed_offsets() {
        let path = temp_path("exact");
        let data = image_with_signatures_at(DEFAULT_ICC_SIG_INDEX_ABS, DEFAULT_JDVRIF_SIG_INDEX_ABS);
        std::fs::write(&path, &data).unwrap();
        assert!(has_embedded_icc_profile(&path, data.len()).unwrap());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn shifted_icc_profile_is_not_recognised() {
        // Both signatures present and correctly spaced, but six bytes later --
        // the layout an inserted APP0 segment would produce. The scan this
        // replaced would have found it; the fixed-offset check must not.
        let path = temp_path("shifted");
        let data = image_with_signatures_at(
            DEFAULT_ICC_SIG_INDEX_ABS + 6,
            DEFAULT_JDVRIF_SIG_INDEX_ABS + 6,
        );
        std::fs::write(&path, &data).unwrap();
        assert!(!has_embedded_icc_profile(&path, data.len()).unwrap());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn short_file_is_not_recognised() {
        let path = temp_path("short");
        std::fs::write(&path, b"tiny").unwrap();
        assert!(!has_embedded_icc_profile(&path, 4).unwrap());
        let _ = std::fs::remove_file(&path);
    }
}
