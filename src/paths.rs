use std::path::{Path, PathBuf};

use crate::crypto::randombytes_into;

fn path_entry_exists(path: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(format!(
            "Error: Failed to inspect path \"{}\": {}",
            path.display(),
            err
        )),
    }
}

fn random_path_token(token_hex_chars: usize) -> Result<String, String> {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

    if token_hex_chars == 0 {
        return Ok(String::new());
    }

    let byte_count = token_hex_chars.div_ceil(2);
    let mut random_bytes = vec![0u8; byte_count];
    randombytes_into(&mut random_bytes)
        .map_err(|_| "CSPRNG Error: Failed to generate random path token.".to_string())?;

    let mut token = String::with_capacity(token_hex_chars);
    for value in random_bytes {
        token.push(HEX_DIGITS[(value >> 4) as usize] as char);
        if token.len() == token_hex_chars {
            break;
        }
        token.push(HEX_DIGITS[(value & 0x0F) as usize] as char);
        if token.len() == token_hex_chars {
            break;
        }
    }

    Ok(token)
}

fn make_unique_randomized_path(
    parent_dir: &Path,
    prefix: &str,
    suffix: &str,
    max_attempts: usize,
    token_hex_chars: usize,
) -> Result<Option<PathBuf>, String> {
    if max_attempts == 0 || token_hex_chars == 0 {
        return Ok(None);
    }

    for _ in 0..max_attempts {
        let token = random_path_token(token_hex_chars)?;
        let filename = format!("{prefix}{token}{suffix}");
        let candidate = if parent_dir.as_os_str().is_empty() {
            PathBuf::from(filename)
        } else {
            parent_dir.join(filename)
        };

        if !path_entry_exists(&candidate)? {
            return Ok(Some(candidate));
        }
    }

    Ok(None)
}

pub(crate) fn unique_randomized_path_or_throw_with_token_len(
    parent_dir: &Path,
    prefix: &str,
    suffix: &str,
    max_attempts: usize,
    error_message: &str,
    token_hex_chars: usize,
) -> Result<PathBuf, String> {
    make_unique_randomized_path(parent_dir, prefix, suffix, max_attempts, token_hex_chars)?
        .ok_or_else(|| error_message.to_string())
}

pub(crate) fn unique_randomized_path_or_throw(
    parent_dir: &Path,
    prefix: &str,
    suffix: &str,
    max_attempts: usize,
    error_message: &str,
) -> Result<PathBuf, String> {
    unique_randomized_path_or_throw_with_token_len(
        parent_dir,
        prefix,
        suffix,
        max_attempts,
        error_message,
        16,
    )
}
