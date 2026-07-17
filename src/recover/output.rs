use crate::common::has_safe_embedded_filename;
use crate::constants::MAX_PATH_ATTEMPTS;
use crate::output_file::commit_staged_file_no_replace;
use crate::paths::unique_randomized_path_or_throw;
use std::ffi::{OsStr, OsString};
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

    Ok(PathBuf::from(filename))
}

fn recovery_candidate(base_path: &Path, attempt: usize) -> PathBuf {
    if attempt == 0 {
        return base_path.to_path_buf();
    }

    let mut stem = base_path
        .file_stem()
        .map(|part| part.as_bytes().to_vec())
        .unwrap_or_default();
    if stem.is_empty() {
        stem = b"recovered".to_vec();
    }
    let ext = base_path.extension().map(|part| {
        let mut e = Vec::with_capacity(1 + part.len());
        e.push(b'.');
        e.extend_from_slice(part.as_bytes());
        e
    });

    let mut next_name = Vec::with_capacity(stem.len() + 1 + 20 + ext.as_ref().map_or(0, Vec::len));
    next_name.extend_from_slice(&stem);
    next_name.push(b'_');
    next_name.extend_from_slice(attempt.to_string().as_bytes());
    if let Some(ext) = &ext {
        next_name.extend_from_slice(ext);
    }
    PathBuf::from(OsStr::from_bytes(&next_name))
}

pub(super) fn commit_recovered_output(
    staged_path: &Path,
    base_output_path: &Path,
) -> Result<PathBuf, String> {
    const ERR: &str = "Write Error: Failed to commit recovered file";
    for attempt in 0..=10000usize {
        let candidate = recovery_candidate(base_output_path, attempt);
        if commit_staged_file_no_replace(staged_path, &candidate, ERR)? {
            return Ok(candidate);
        }
    }
    Err("Write Error: Unable to create a unique output filename.".to_string())
}

pub(super) fn print_recovery_success(output_path: &Path, output_size: usize) {
    println!(
        "\nExtracted hidden file: {} ({} bytes).\n\nComplete! Please check your file.\n",
        output_path.to_string_lossy(),
        output_size
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    // safe_recovery_path writes relative to CWD; serialize tests that chdir.
    static CWD_LOCK: Mutex<()> = Mutex::new(());

    fn with_temp_cwd<F: FnOnce()>(f: F) {
        let _guard = CWD_LOCK.lock().expect("cwd lock");
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "jdvrif_recover_out_{}_{}",
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&dir).expect("mkdir");
        let prev = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(&dir).expect("chdir");
        f();
        let _ = std::env::set_current_dir(prev);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn safe_recovery_path_rejects_reserved_and_separators() {
        assert!(safe_recovery_path(b".".to_vec()).is_err());
        assert!(safe_recovery_path(b"..".to_vec()).is_err());
        assert!(safe_recovery_path(b"-evil".to_vec()).is_err());
        assert!(safe_recovery_path(b".hidden".to_vec()).is_err());
        assert!(safe_recovery_path(b"a/b".to_vec()).is_err());
        assert!(safe_recovery_path(b"a\\b".to_vec()).is_err());
        assert!(safe_recovery_path(Vec::new()).is_err());
    }

    #[test]
    fn safe_recovery_path_disambiguates_collisions() {
        with_temp_cwd(|| {
            fs::write("payload.bin", b"one").expect("write");
            let path = safe_recovery_path(b"payload.bin".to_vec()).expect("unique");
            assert_eq!(path.file_name().unwrap().to_string_lossy(), "payload.bin");
        });
    }

    #[test]
    fn commit_recovered_output_refuses_existing_dest() {
        with_temp_cwd(|| {
            fs::write("staged.bin", b"data").expect("stage");
            fs::write("out.bin", b"old").expect("dest");
            let output = commit_recovered_output(Path::new("staged.bin"), Path::new("out.bin"))
                .expect("collision should be disambiguated");
            assert_eq!(output, Path::new("out_1.bin"));
            assert_eq!(fs::read("out.bin").unwrap(), b"old");
            assert_eq!(fs::read("out_1.bin").unwrap(), b"data");
        });
    }

    #[test]
    fn commit_recovered_output_treats_dangling_symlink_as_collision() {
        use std::os::unix::fs::symlink;

        with_temp_cwd(|| {
            fs::write("staged.bin", b"data").expect("stage");
            symlink("missing-target", "out.bin").expect("symlink");
            let output = commit_recovered_output(Path::new("staged.bin"), Path::new("out.bin"))
                .expect("dangling symlink should be skipped");
            assert_eq!(output, Path::new("out_1.bin"));
            assert_eq!(
                fs::read_link("out.bin").unwrap(),
                Path::new("missing-target")
            );
            assert_eq!(fs::read("out_1.bin").unwrap(), b"data");
        });
    }
}
