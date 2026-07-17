mod modes;
mod output;

use crate::common::validate_file_for_read;
use crate::constants::{ICC_PROFILE_SIG, JDVRIF_SIG};
use crate::extract::{find_signature_in_file, find_signature_pair_in_file};
use crate::runtime::JdvrifError;
use std::cmp;
use std::path::Path;

use self::modes::{recover_from_bluesky_path, recover_from_icc_path};

pub(crate) fn run_native_recover(image_file_path: &Path) -> Result<(), JdvrifError> {
    const JDVRIF_TO_ICC_SIG_DIFF: usize = 811;
    // BLUESKY encrypted_payload_start_index: jdvrif's header signature, for a
    // Bluesky file, lives within these first bytes.
    const BLUESKY_HEADER_SEARCH_LIMIT: usize = 0x1D1;

    crate::crypto::init()
        .map_err(|_| JdvrifError::new("Libsodium initialization failed!".to_string()))?;

    let image_file_size =
        validate_file_for_read(image_file_path, true, false).map_err(JdvrifError::from)?;

    // Default / Reddit: the first ICC-profile signature that also carries the
    // jdvrif signature at +811. One linear pass verifies each candidate in place
    // (see find_signature_pair_in_file), so a file seeded with decoy ICC
    // signatures cannot force a rescan per hit.
    if let Some(icc_profile_sig_index) = find_signature_pair_in_file(
        image_file_path,
        &ICC_PROFILE_SIG,
        &JDVRIF_SIG,
        JDVRIF_TO_ICC_SIG_DIFF,
    )
    .map_err(JdvrifError::from)?
    {
        recover_from_icc_path(image_file_path, image_file_size, icc_profile_sig_index)?;
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
