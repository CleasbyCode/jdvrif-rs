use crate::paths::unique_randomized_path_or_throw;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use super::*;

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

pub(super) fn safe_recovery_path(decrypted_filename: String) -> Result<PathBuf, String> {
    if decrypted_filename.is_empty() {
        return Err("File Extraction Error: Recovered filename is unsafe.".to_string());
    }

    let parsed = PathBuf::from(decrypted_filename);
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
        .map(|part| part.to_string_lossy().into_owned())
        .unwrap_or_default();
    if stem.is_empty() {
        stem = "recovered".to_string();
    }
    let ext = candidate
        .extension()
        .map(|part| format!(".{}", part.to_string_lossy()))
        .unwrap_or_default();

    let mut next_name = String::with_capacity(stem.len() + 1 + 20 + ext.len());
    for i in 1..=10000usize {
        next_name.clear();
        next_name.push_str(&stem);
        next_name.push('_');
        next_name.push_str(&i.to_string());
        next_name.push_str(&ext);

        let next = PathBuf::from(&next_name);
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
