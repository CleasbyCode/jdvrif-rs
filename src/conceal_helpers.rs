use crate::paths::unique_randomized_path_or_throw;
use std::path::{Path, PathBuf};

use super::*;

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
        "Bluesky. (Only share this \"file-embedded\" JPG image on Bluesky).\n\n You must use the Python script \"bsky_post.py\" (found in the repo src folder)\n to post the image to Bluesky.".to_string(),
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


pub(crate) fn temp_compressed_path(base_name: &str) -> Result<PathBuf, String> {
    let stem = Path::new(base_name)
        .file_stem()
        .map(|v| v.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "payload".to_string());
    let prefix = format!(".{stem}.jdvrif_comp_");
    unique_randomized_path_or_throw(
        Path::new(""),
        &prefix,
        ".bin",
        MAX_PATH_ATTEMPTS,
        "Write File Error: Could not create a temporary compressed filename.",
    )
}

pub(crate) fn temp_encrypted_path(base_name: &str) -> Result<PathBuf, String> {
    let stem = Path::new(base_name)
        .file_stem()
        .map(|v| v.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "payload".to_string());
    let prefix = format!(".{stem}.jdvrif_enc_");
    unique_randomized_path_or_throw(
        Path::new(""),
        &prefix,
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

pub(crate) fn print_conceal_summary(
    platforms_vec: &[String],
    output_path: &Path,
    embedded_jpg_size: usize,
    recovery_pin: u64,
) {
    print!("\nPlatform compatibility for output image:-\n\n");
    for s in platforms_vec {
        println!(" ✓ {}", s);
    }
    println!(
        "\nSaved \"file-embedded\" JPG image: {} ({} bytes).",
        output_path.display(),
        embedded_jpg_size
    );
    println!(
        "\nRecovery PIN: [***{}***]\n\nImportant: Keep your PIN safe, so that you can extract the hidden file.\n\nComplete!\n",
        recovery_pin
    );
}

pub(crate) fn should_bypass_compression(data_file_path: &Path, source_data_size: usize) -> bool {
    if source_data_size <= COMPRESS_BYPASS_SIZE {
        return false;
    }

    has_file_extension(
        data_file_path,
        &[
            "zip", "jar", "rar", "7z", "bz2", "gz", "xz", "lz", "lz4", "cab", "rpm", "deb",
            "mp4", "mp3", "exe", "jpg", "jpeg", "jfif", "png", "webp", "gif", "ogg", "flac",
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
) -> Result<(), String> {
    let input_file = open_binary_input_or_throw(
        input_path,
        &format!(
            "Failed to open file for compression: {}",
            input_path.display()
        ),
    )?;
    let output_file = open_binary_output_for_write_or_throw(output_path)?;

    let input_size = checked_file_size(
        input_path,
        "Read Error: Invalid compressed input file size.",
        true,
    )?;
    let mut reader = BufReader::new(input_file);
    let writer = BufWriter::new(output_file);
    let mut encoder = ZlibEncoder::new(writer, select_compression_level(input_size));

    let mut in_chunk = vec![0u8; 2 * 1024 * 1024];
    loop {
        let got = reader
            .read(&mut in_chunk)
            .map_err(|_| "Read Error: Failed while compressing input file.".to_string())?;
        if got == 0 {
            break;
        }
        encoder
            .write_all(&in_chunk[..got])
            .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;
    }

    let mut writer = encoder
        .finish()
        .map_err(|_| "zlib: deflate finalize failed".to_string())?;
    writer.flush().map_err(|_| WRITE_COMPLETE_ERROR.to_string())
}

pub(crate) fn generate_recovery_pin() -> u64 {
    loop {
        let bytes = randombytes(8);
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes);
        let pin = u64::from_ne_bytes(arr);
        if pin != 0 {
            return pin;
        }
    }
}

pub(crate) fn maybe_print_large_file_notice(source_data_size: usize) {
    if source_data_size > LARGE_FILE_SIZE {
        println!("\nPlease wait. Larger files will take longer to complete this process.");
    }
}

pub(crate) fn validate_data_filename(data_file_path: &Path) -> Result<String, String> {
    let data_filename = data_file_path
        .file_name()
        .map(|v| v.to_string_lossy().into_owned())
        .unwrap_or_default();
    if !has_safe_embedded_filename(data_file_path.file_name().map(Path::new).unwrap_or(data_file_path)) {
        return Err(
            "Data File Error: Embedded filename is unsafe. Filenames may not begin with '.' or '-'.".to_string(),
        );
    }
    if data_filename.len() > DATA_FILENAME_MAX_LENGTH {
        return Err(
            "Data File Error: For compatibility requirements, length of data filename must not exceed 20 characters."
                .to_string(),
        );
    }
    Ok(data_filename)
}
