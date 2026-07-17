use crate::common::{
    has_file_extension, has_safe_embedded_filename, open_binary_input_or_throw,
    open_binary_output_for_write_or_throw,
};
use crate::constants::{
    BLUESKY_PLATFORM_INDEX, COMPRESS_BYPASS_SIZE, DATA_FILENAME_MAX_LENGTH, LARGE_FILE_SIZE,
    MAX_DATA_SIZE_BLUESKY, MAX_PATH_ATTEMPTS, MAX_SIZE_CONCEAL, MAX_SIZE_REDDIT,
    REDDIT_PLATFORM_INDEX, WRITE_COMPLETE_ERROR,
};
use crate::crypto::randombytes_into;
use crate::paths::unique_randomized_path_or_throw;
use crate::runtime::TempFileGuard;
use crate::signal::check_cancellation;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::{BufReader, BufWriter, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

struct PlatformLimit {
    name: &'static str,
    max_image_size: usize,
    max_first_segment: usize,
    max_segments: u16,
}

const PLATFORM_LIMITS: [PlatformLimit; 8] = [
    PlatformLimit {
        name: "X-Twitter",
        max_image_size: 5 * 1024 * 1024,
        max_first_segment: 10 * 1024,
        max_segments: u16::MAX,
    },
    PlatformLimit {
        name: "Tumblr",
        max_image_size: usize::MAX,
        max_first_segment: 65534,
        max_segments: u16::MAX,
    },
    PlatformLimit {
        name: "Mastodon",
        max_image_size: 16 * 1024 * 1024,
        max_first_segment: usize::MAX,
        max_segments: 100,
    },
    PlatformLimit {
        name: "Pixelfed",
        max_image_size: 15 * 1024 * 1024,
        max_first_segment: usize::MAX,
        max_segments: u16::MAX,
    },
    PlatformLimit {
        name: "PostImage",
        max_image_size: 32 * 1024 * 1024,
        max_first_segment: usize::MAX,
        max_segments: u16::MAX,
    },
    PlatformLimit {
        name: "ImgBB",
        max_image_size: 32 * 1024 * 1024,
        max_first_segment: usize::MAX,
        max_segments: u16::MAX,
    },
    PlatformLimit {
        name: "ImgPile",
        max_image_size: 100 * 1024 * 1024,
        max_first_segment: usize::MAX,
        max_segments: u16::MAX,
    },
    PlatformLimit {
        name: "Flickr",
        max_image_size: 200 * 1024 * 1024,
        max_first_segment: usize::MAX,
        max_segments: u16::MAX,
    },
];

pub(crate) fn platform_report_template() -> Vec<String> {
    vec![
        "X-Twitter".to_string(),
        "Tumblr".to_string(),
        "Bluesky. (Only share this \"file-embedded\" JPG image on Bluesky).\n\n You must use the Python script \"bsky/bsky_post.py\" (found in the repo src folder)\n to post the image to Bluesky.".to_string(),
        "Mastodon".to_string(),
        "Pixelfed".to_string(),
        "Reddit. (Only share this \"file-embedded\" JPG image on Reddit).".to_string(),
        "PostImage".to_string(),
        "ImgBB".to_string(),
        "ImgPile".to_string(),
        "Flickr".to_string(),
    ]
}

fn filter_platforms(
    platforms: &mut Vec<String>,
    embedded_size: usize,
    first_segment_size: usize,
    total_segments: u16,
) {
    platforms.retain(|platform| {
        for limit in &PLATFORM_LIMITS {
            if platform == limit.name {
                return embedded_size <= limit.max_image_size
                    && first_segment_size <= limit.max_first_segment
                    && total_segments <= limit.max_segments;
            }
        }
        true
    });

    if platforms.is_empty() {
        platforms.push(
            "\u{8}\u{8}Unknown!\n\n Due to the large file size of the output JPG image, I'm unaware of any\n compatible platforms that this image can be posted on. Local use only?"
                .to_string(),
        );
    }
}

pub(crate) fn validate_combined_size_limits(
    encrypted_payload_size: usize,
    jpg_size: usize,
    has_reddit_option: bool,
    has_bluesky_option: bool,
) -> Result<(), String> {
    if encrypted_payload_size > usize::MAX.saturating_sub(jpg_size) {
        return Err("File Size Error: Combined file size overflow.".to_string());
    }
    let combined = encrypted_payload_size + jpg_size;

    if has_bluesky_option && encrypted_payload_size > MAX_DATA_SIZE_BLUESKY {
        return Err(
            "Data File Size Error: File exceeds maximum size limit for the Bluesky platform."
                .to_string(),
        );
    }
    if has_reddit_option && combined > MAX_SIZE_REDDIT {
        return Err("File Size Error: Combined size of image and data file exceeds maximum size limit for the Reddit platform.".to_string());
    }
    if !has_reddit_option && !has_bluesky_option && combined > MAX_SIZE_CONCEAL {
        return Err("File Size Error: Combined size of image and data file exceeds maximum default size limit for jdvrif.".to_string());
    }
    Ok(())
}

pub(crate) fn temp_compressed_path(_base_name: &[u8]) -> Result<PathBuf, String> {
    // Keep the secret filename out of directory-visible temporary paths.
    unique_randomized_path_or_throw(
        Path::new(""),
        ".jdvrif_comp_",
        ".bin",
        MAX_PATH_ATTEMPTS,
        "Write File Error: Could not create a temporary compressed filename.",
    )
}

pub(crate) fn temp_encrypted_path(_base_name: &[u8]) -> Result<PathBuf, String> {
    unique_randomized_path_or_throw(
        Path::new(""),
        ".jdvrif_enc_",
        ".bin",
        MAX_PATH_ATTEMPTS,
        "Write File Error: Could not create a temporary encrypted filename.",
    )
}

pub(crate) fn finalize_default_platform_report(
    platforms_vec: &mut Vec<String>,
    summary: crate::conceal_segments::SegmentedEmbedSummary,
) {
    platforms_vec.remove(REDDIT_PLATFORM_INDEX);
    // After removing Reddit, Bluesky index shifts down by 1 if Bluesky > Reddit.
    // BLUESKY_PLATFORM_INDEX = 2, REDDIT_PLATFORM_INDEX = 5 — Bluesky comes
    // before Reddit, so removing Reddit does NOT shift the Bluesky entry.
    // But we still need to remove Bluesky at its original index.
    platforms_vec.remove(BLUESKY_PLATFORM_INDEX);
    filter_platforms(
        platforms_vec,
        summary.embedded_image_size,
        summary.first_segment_size as usize,
        summary.total_segments,
    );
}

pub(crate) fn deliver_conceal_pin(
    platforms_vec: &[String],
    recovery_pin: u64,
) -> Result<(), String> {
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "\nPlatform compatibility for output image:-\n")
        .map_err(|_| "Output Error: Failed to deliver recovery PIN.".to_string())?;
    for s in platforms_vec {
        writeln!(output, " ✓ {s}")
            .map_err(|_| "Output Error: Failed to deliver recovery PIN.".to_string())?;
    }
    writeln!(
        output,
        "\nRecovery PIN: [***{}***]\n\nImportant: Keep your PIN safe, so that you can extract the hidden file.\n",
        recovery_pin
    )
    .map_err(|_| "Output Error: Failed to deliver recovery PIN.".to_string())?;
    output
        .flush()
        .map_err(|_| "Output Error: Failed to deliver recovery PIN.".to_string())?;
    check_cancellation()
}

pub(crate) fn print_conceal_complete(
    output_path: &Path,
    embedded_jpg_size: usize,
) -> Result<(), String> {
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    writeln!(
        output,
        "\nSaved \"file-embedded\" JPG image: {} ({} bytes).\n\nComplete!\n",
        output_path.display(),
        embedded_jpg_size
    )
    .map_err(|_| "Output Error: Failed to report committed output image.".to_string())?;
    output
        .flush()
        .map_err(|_| "Output Error: Failed to report committed output image.".to_string())
}

pub(crate) fn should_bypass_compression(data_file_path: &Path, source_data_size: usize) -> bool {
    if source_data_size <= COMPRESS_BYPASS_SIZE {
        return false;
    }

    has_file_extension(
        data_file_path,
        &[
            "zip", "jar", "rar", "7z", "bz2", "gz", "xz", "lz", "lz4", "cab", "rpm", "deb", "mp4",
            "mp3", "exe", "jpg", "jpeg", "jfif", "png", "webp", "gif", "ogg", "flac",
        ],
    )
}

fn select_compression_level(input_size: usize) -> Compression {
    if input_size > 500 * 1024 * 1024 {
        Compression::fast()
    } else if input_size > 250 * 1024 * 1024 {
        Compression::default()
    } else {
        Compression::best()
    }
}

pub(crate) fn zlib_compress_file_to_path_native(
    input_path: &Path,
    output_path: &Path,
    expected_input_size: usize,
) -> Result<(), String> {
    let mut output_guard = TempFileGuard::new(output_path.to_path_buf());
    let input_file = open_binary_input_or_throw(
        input_path,
        &format!(
            "Failed to open file for compression: {}",
            input_path.display()
        ),
    )?;
    let output_file = open_binary_output_for_write_or_throw(output_path)?;

    let mut reader = BufReader::new(input_file);
    let writer = BufWriter::new(output_file);
    let mut encoder = ZlibEncoder::new(writer, select_compression_level(expected_input_size));

    let mut in_chunk = vec![0u8; 2 * 1024 * 1024];
    let mut input_left = expected_input_size;
    while input_left > 0 {
        check_cancellation()?;
        let got = input_left.min(in_chunk.len());
        reader
            .read_exact(&mut in_chunk[..got])
            .map_err(|_| "Read Error: Input file changed while compressing.".to_string())?;
        encoder
            .write_all(&in_chunk[..got])
            .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;
        input_left -= got;
        check_cancellation()?;
    }

    let mut trailing = [0u8; 1];
    if reader
        .read(&mut trailing)
        .map_err(|_| "Read Error: Failed while compressing input file.".to_string())?
        != 0
    {
        return Err("Read Error: Input file changed while compressing.".to_string());
    }

    let mut writer = encoder
        .finish()
        .map_err(|_| "zlib: deflate finalize failed".to_string())?;
    writer
        .flush()
        .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;
    check_cancellation()?;
    output_guard.dismiss();
    Ok(())
}

pub(crate) fn generate_recovery_pin() -> Result<Zeroizing<u64>, String> {
    loop {
        let mut bytes = Zeroizing::new([0u8; 8]);
        randombytes_into(&mut bytes[..])
            .map_err(|_| "CSPRNG Error: Failed to generate recovery PIN.".to_string())?;
        let pin = Zeroizing::new(u64::from_ne_bytes(*bytes));
        if *pin != 0 {
            return Ok(pin);
        }
    }
}

pub(crate) fn maybe_print_large_file_notice(source_data_size: usize) {
    if source_data_size > LARGE_FILE_SIZE {
        println!("\nPlease wait. Larger files will take longer to complete this process.");
    }
}

pub(crate) fn validate_data_filename(data_file_path: &Path) -> Result<Vec<u8>, String> {
    // Return the raw OsStr bytes of the filename rather than a lossy String, so
    // the embedded name (and its length check) is byte-identical to the input —
    // matching the C++ tool, which stores/reads the filename as raw bytes.
    let Some(name) = data_file_path.file_name() else {
        return Err(
            "Data File Error: Embedded filename is unsafe. Filenames may not begin with '.' or '-'.".to_string(),
        );
    };
    if !has_safe_embedded_filename(Path::new(name)) {
        return Err(
            "Data File Error: Embedded filename is unsafe. Filenames may not begin with '.' or '-'.".to_string(),
        );
    }
    let name_bytes = name.as_bytes().to_vec();
    if name_bytes.len() > DATA_FILENAME_MAX_LENGTH {
        return Err(
            "Data File Error: For compatibility requirements, length of data filename must not exceed 20 characters."
                .to_string(),
        );
    }
    Ok(name_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn validate_data_filename_length_and_safety() {
        assert!(validate_data_filename(Path::new("short.txt")).is_ok());
        assert!(validate_data_filename(Path::new(".bad")).is_err());
        assert!(validate_data_filename(Path::new("-bad")).is_err());
        // 21-char name exceeds DATA_FILENAME_MAX_LENGTH (20)
        assert!(validate_data_filename(Path::new("abcdefghij1234567890x")).is_err());
    }

    #[test]
    fn should_bypass_compression_for_large_archives() {
        assert!(!should_bypass_compression(
            Path::new("big.zip"),
            COMPRESS_BYPASS_SIZE
        ));
        assert!(should_bypass_compression(
            Path::new("big.zip"),
            COMPRESS_BYPASS_SIZE + 1
        ));
        assert!(!should_bypass_compression(
            Path::new("big.txt"),
            COMPRESS_BYPASS_SIZE + 1
        ));
    }

    #[test]
    fn compression_rejects_growth_beyond_validated_size() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let input = std::env::temp_dir().join(format!(
            "jdvrif_compress_growth_{}_{}",
            std::process::id(),
            nonce
        ));
        let output = input.with_extension("zlib");
        std::fs::write(&input, b"validated-plus-growth").expect("write input");

        let err = zlib_compress_file_to_path_native(&input, &output, 9)
            .expect_err("growth must be rejected");
        assert!(err.contains("changed while compressing"));
        assert!(!output.exists());

        let _ = std::fs::remove_file(input);
    }
}
