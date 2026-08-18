use crate::common::{
    finish_buffered_file, has_file_extension, has_safe_embedded_filename,
    open_binary_input_or_throw, open_binary_output_for_staging_or_throw,
};
use crate::constants::{
    BLUESKY_PLATFORM_INDEX, COMPRESS_BYPASS_SIZE, DATA_FILENAME_MAX_LENGTH, LARGE_FILE_SIZE,
    MAX_DATA_SIZE_BLUESKY, MAX_SIZE_CONCEAL, WRITE_COMPLETE_ERROR,
};
use crate::crypto::randombytes_into;
use crate::signal::check_cancellation;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::cmp;
use std::io::{BufReader, BufWriter, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
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
        "Bluesky. (Only share this \"file-embedded\" JPG image on Bluesky).\n\n You must use the Python script \"create_bsky_post.py\" (found in the repo src/bsky folder)\n to post the image to Bluesky.".to_string(),
        "Mastodon".to_string(),
        "Pixelfed".to_string(),
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
}

pub(crate) fn validate_combined_size_limits(
    encrypted_payload_size: usize,
    jpg_size: usize,
    has_bluesky_option: bool,
) -> Result<(), String> {
    if encrypted_payload_size > usize::MAX.saturating_sub(jpg_size) {
        return Err("File Size Error: Combined file size overflow.".to_string());
    }
    let combined = encrypted_payload_size + jpg_size;

    // Check the packer's real ceiling, not just the program cap: the Bluesky
    // segments hold ~171 KB, well under MAX_DATA_SIZE_BLUESKY, and anything
    // between the two would otherwise be compressed, encrypted and half-packed
    // before failing inside the XMP overflow builder. This runs on the
    // *encrypted* size, which is derived from the compressed payload, so a large
    // but well-compressing file is still accepted on its merits.
    if has_bluesky_option {
        let max_bluesky_payload = cmp::min(
            crate::extract::max_bluesky_embedded_cipher_capacity()?,
            MAX_DATA_SIZE_BLUESKY,
        );
        if encrypted_payload_size > max_bluesky_payload {
            return Err(format!(
                "Data File Size Error: Encrypted payload is {encrypted_payload_size} bytes, above the {max_bluesky_payload}-byte limit for the Bluesky platform.\n                      Use a smaller data file, or compress it yourself first."
            ));
        }
    }
    if !has_bluesky_option && combined > MAX_SIZE_CONCEAL {
        return Err("File Size Error: Combined size of image and data file exceeds maximum default size limit for jdvrif.".to_string());
    }
    Ok(())
}

// Intermediate stages (deflated payload, encrypted payload) go to link-free
// StagingFile inodes rather than named temporaries: deflate is not encryption,
// so the compressed payload is plaintext-equivalent and must never be visible
// in a directory listing, to a backup/sync client, or survive a SIGKILL.
// See StagingFile in common.rs.

pub(crate) fn finalize_default_platform_report(
    platforms_vec: &mut Vec<String>,
    summary: crate::conceal_segments::SegmentedEmbedSummary,
) -> Result<(), String> {
    // Bounds-check rather than let Vec::remove panic, matching the C++
    // requirePlatformEntries guard: an internal inconsistency should surface as
    // a message, not an abort.
    if platforms_vec.len() <= BLUESKY_PLATFORM_INDEX {
        return Err("Internal Error: Corrupt platform compatibility list.".to_string());
    }
    platforms_vec.remove(BLUESKY_PLATFORM_INDEX);
    filter_platforms(
        platforms_vec,
        summary.embedded_image_size,
        summary.first_segment_size as usize,
        summary.total_segments,
    );
    Ok(())
}

pub(crate) fn deliver_conceal_pin(
    platforms_vec: &[String],
    recovery_pin: u64,
) -> Result<(), String> {
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "\nPlatform compatibility for output image:-\n")
        .map_err(|_| "Output Error: Failed to deliver recovery PIN.".to_string())?;
    if platforms_vec.is_empty() {
        writeln!(
            output,
            "Unknown!\n\n Due to the large file size of the output JPG image, I'm unaware of any\n compatible platforms that this image can be posted on. Local use only?"
        )
        .map_err(|_| "Output Error: Failed to deliver recovery PIN.".to_string())?;
    } else {
        for s in platforms_vec {
            writeln!(output, " ✓ {s}")
                .map_err(|_| "Output Error: Failed to deliver recovery PIN.".to_string())?;
        }
    }
    check_cancellation()?;
    writeln!(
        output,
        "\nRecovery PIN: [***{}***]\n\nImportant: Keep your PIN safe, so that you can extract the hidden file.\n",
        recovery_pin
    )
    .map_err(|_| "Output Error: Failed to deliver recovery PIN.".to_string())?;
    output
        .flush()
        .map_err(|_| "Output Error: Failed to deliver recovery PIN.".to_string())?;
    Ok(())
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
    let input_file = open_binary_input_or_throw(
        input_path,
        &format!(
            "Failed to open file for compression: {}",
            input_path.display()
        ),
    )?;
    // output_path is a StagingFile: link-free already, so a failure part way
    // through leaves nothing behind for a cleanup guard to remove.
    let output_file = open_binary_output_for_staging_or_throw(output_path)?;

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

    let writer = encoder
        .finish()
        .map_err(|_| "zlib: deflate finalize failed".to_string())?;
    // Intermediate stage file, so no fsync -- but the close is checked so a
    // deferred write error cannot pass for a complete compressed payload.
    finish_buffered_file(writer, WRITE_COMPLETE_ERROR, false)?;
    check_cancellation()?;
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
        std::fs::write(&input, b"validated-plus-growth").expect("write input");

        // Production compresses into a link-free StagingFile, so the test uses
        // one too -- the staging opener requires the inode to already exist.
        let stage = crate::common::StagingFile::new(Path::new(""), "test_comp")
            .expect("staging file");

        let err = zlib_compress_file_to_path_native(&input, stage.path(), 9)
            .expect_err("growth must be rejected");
        assert!(err.contains("changed while compressing"));

        // The partially written stage has no directory entry to leave behind:
        // the fd still resolves, but only to an unlinked inode.
        let target = std::fs::read_link(stage.path()).expect("staging fd link");
        assert!(target.to_string_lossy().ends_with("(deleted)"));

        let _ = std::fs::remove_file(input);
    }
}
