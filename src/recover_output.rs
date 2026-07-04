use crate::common::{cleanup_path_no_throw, has_safe_embedded_filename};
use crate::constants::MAX_PATH_ATTEMPTS;
use crate::paths::unique_randomized_path_or_throw;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

pub(super) fn temp_recovery_path(output_path: &Path) -> Result<PathBuf, String> {
    let parent = output_path.parent().unwrap_or_else(|| Path::new(""));
    let base = output_path
        .file_name()
        .unwrap_or_else(|| OsStr::new("output"))
        .to_string_lossy();
    let prefix = format!(".{base}.jdvrif_tmp_");
    unique_randomized_path_or_throw(
        parent,
        &prefix,
        "",
        MAX_PATH_ATTEMPTS,
        "Write Error: Unable to allocate a temporary output filename.",
    )
}

pub(super) fn safe_recovery_path(decrypted_filename: Vec<u8>) -> Result<PathBuf, String> {
    // The recovered filename is handled as raw bytes so non-UTF-8 names round-trip
    // byte-for-byte (matching the C++ tool). has_safe_embedded_filename still
    // rejects path separators, control characters and reserved names.
    if decrypted_filename.is_empty() {
        return Err("File Extraction Error: Recovered filename is unsafe.".to_string());
    }

    let parsed = PathBuf::from(OsString::from_vec(decrypted_filename));
    let Some(filename) = parsed.file_name() else {
        return Err("File Extraction Error: Recovered filename is unsafe.".to_string());
    };

    if parsed.has_root()
        || parsed
            .parent()
            .is_some_and(|parent| !parent.as_os_str().is_empty())
        || parsed != *filename
        || !has_safe_embedded_filename(&parsed)
    {
        return Err("File Extraction Error: Recovered filename is unsafe.".to_string());
    }

    let candidate = PathBuf::from(filename);
    match candidate.try_exists() {
        Ok(false) => return Ok(candidate),
        Ok(true) => {}
        Err(err) => {
            return Err(format!(
                "Write Error: Failed to inspect recovery output path: {}",
                err
            ))
        }
    }

    let mut stem = candidate
        .file_stem()
        .map(|part| part.as_bytes().to_vec())
        .unwrap_or_default();
    if stem.is_empty() {
        stem = b"recovered".to_vec();
    }
    let ext = candidate.extension().map(|part| {
        let mut e = Vec::with_capacity(1 + part.len());
        e.push(b'.');
        e.extend_from_slice(part.as_bytes());
        e
    });

    let mut next_name = Vec::with_capacity(stem.len() + 1 + 20 + ext.as_ref().map_or(0, Vec::len));
    for i in 1..=10000usize {
        next_name.clear();
        next_name.extend_from_slice(&stem);
        next_name.push(b'_');
        next_name.extend_from_slice(i.to_string().as_bytes());
        if let Some(ext) = &ext {
            next_name.extend_from_slice(ext);
        }

        let next = PathBuf::from(OsStr::from_bytes(&next_name));
        match next.try_exists() {
            Ok(false) => return Ok(next),
            Ok(true) => {}
            Err(err) => {
                return Err(format!(
                    "Write Error: Failed to inspect recovery output path: {}",
                    err
                ))
            }
        }
    }

    Err("Write Error: Unable to create a unique output filename.".to_string())
}

pub(super) fn commit_recovered_output(
    staged_path: &Path,
    output_path: &Path,
) -> Result<(), String> {
    fs::hard_link(staged_path, output_path)
        .map_err(|err| format!("Write Error: Failed to commit recovered file: {}", err))?;
    cleanup_path_no_throw(staged_path);
    Ok(())
}

pub(super) fn print_recovery_success(output_path: &Path, output_size: usize) {
    println!(
        "\nExtracted hidden file: {} ({} bytes).\n\nComplete! Please check your file.\n",
        output_path.to_string_lossy(),
        output_size
    );
}
