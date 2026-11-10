use crate::common::{has_safe_embedded_filename, open_binary_input_or_throw};
use crate::conceal_segments::embedded_jpg_size;
use crate::constants::{
    BLUESKY_PLATFORM_INDEX, COMPRESS_BYPASS_SIZE, DATA_FILENAME_MAX_LENGTH, LARGE_FILE_SIZE,
    MAX_DATA_SIZE_BLUESKY, MAX_SIZE_CONCEAL, WRITE_COMPLETE_ERROR,
};
use crate::crypto::randombytes_into;
use crate::key_codec::{encode_recovery_key_display, RecoveryKey};
use crate::output_file::{OutputFile, OutputFileWriter};
use crate::signal::check_cancellation;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::cmp;
use std::io::{Read, Write};
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

pub(crate) const DEFAULT_SIZE_LIMIT_ERROR: &str =
    "File Size Error: Combined size of image and data file exceeds maximum default size limit for jdvrif.";

pub(crate) fn validate_combined_size_limits(
    encrypted_payload_size: usize,
    template_size: usize,
    jpg_size: usize,
    has_bluesky_option: bool,
) -> Result<(), String> {
    // Check the packer's real ceiling, not just the program cap: the Bluesky
    // segments hold ~171 KiB, well under MAX_DATA_SIZE_BLUESKY, and anything
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
    // The cap is on the finished image, so count every byte it will hold --
    // the segment template and the per-segment ICC headers as well as the
    // payload and cover -- before anything is compressed into it.
    if !has_bluesky_option
        && embedded_jpg_size(template_size, encrypted_payload_size, jpg_size)? > MAX_SIZE_CONCEAL
    {
        return Err(DEFAULT_SIZE_LIMIT_ERROR.to_string());
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

const KEY_DELIVERY_ERROR: &str = "Output Error: Failed to deliver recovery KEY.";

/// Unbuffered write of all of `bytes` to fd 1, retrying on EINTR.
fn write_all_to_stdout_fd(mut bytes: &[u8]) -> std::io::Result<()> {
    while !bytes.is_empty() {
        // SAFETY: `bytes` is a live slice for the duration of the call.
        let written =
            unsafe { libc::write(libc::STDOUT_FILENO, bytes.as_ptr().cast(), bytes.len()) };
        if written < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if written == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

pub(crate) fn deliver_conceal_key(
    platforms_vec: &[String],
    recovery_key: &RecoveryKey,
) -> Result<(), String> {
    let RecoveryKey::V128(secret) = recovery_key;
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "\nPlatform compatibility for output image:-\n")
        .map_err(|_| "Output Error: Failed to deliver recovery KEY.".to_string())?;
    if platforms_vec.is_empty() {
        writeln!(
            output,
            "Unknown!\n\n Due to the large file size of the output JPG image, I'm unaware of any\n compatible platforms that this image can be posted on. Local use only?"
        )
        .map_err(|_| "Output Error: Failed to deliver recovery KEY.".to_string())?;
    } else {
        for s in platforms_vec {
            writeln!(output, " ✓ {s}")
                .map_err(|_| "Output Error: Failed to deliver recovery KEY.".to_string())?;
        }
    }
    check_cancellation()?;

    // `write!("{}", recovery_key)` would stage the KEY's text form in a heap buffer
    // that is freed without being zeroed, undoing the wiping the rest of the
    // KEY path is careful about. Render the display form into a 29-byte stack
    // array that is zeroed on every exit path (Zeroizing), and emit it between
    // two constant fragments instead -- straight to fd 1 after a flush, as the
    // C++ tree does, so it never sits in stdout's heap buffer either.
    let display = encode_recovery_key_display(secret);
    output
        .write_all(b"\nRecovery KEY: [***")
        .map_err(|_| KEY_DELIVERY_ERROR.to_string())?;
    output.flush().map_err(|_| KEY_DELIVERY_ERROR.to_string())?;
    write_all_to_stdout_fd(&display[..]).map_err(|_| KEY_DELIVERY_ERROR.to_string())?;
    output
        .write_all(
            b"***]\n\nImportant: Keep your KEY safe, so that you can extract the hidden file.\n\n",
        )
        .map_err(|_| KEY_DELIVERY_ERROR.to_string())?;
    output.flush().map_err(|_| KEY_DELIVERY_ERROR.to_string())?;
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
        "Saved \"file-embedded\" JPG image: {} ({} bytes).\n\nComplete!\n",
        output_path.display(),
        embedded_jpg_size
    )
    .map_err(|_| "Output Error: Failed to report committed output image.".to_string())?;
    output
        .flush()
        .map_err(|_| "Output Error: Failed to report committed output image.".to_string())
}

/// Names the format when the data file's leading bytes show one that is
/// already entropy-coded, so a zlib pass gains ~0%; `None` otherwise. The
/// header, not the extension, decides: a renamed archive is still recognized,
/// and a text file named ".zip" is still compressed. Only consulted for large
/// default/Bluesky-mode inputs (`already_compressed_format`), to save the time
/// of a pointless multi-megabyte deflate; everywhere else the payload is
/// compressed and the smaller of the two forms is kept. Executables are
/// deliberately absent: they typically deflate by 30-50%. Keep in step with
/// the C++ table.
const FORMAT_HEADER_SIZE: usize = 16;

pub(crate) fn detect_compressed_format(header: &[u8]) -> Option<&'static str> {
    let has =
        |signature: &[u8], at: usize| header.get(at..).is_some_and(|h| h.starts_with(signature));

    // Archives and compressed streams (ZIP also covers jar, apk, docx, odt, epub).
    if has(b"PK\x03\x04", 0) || has(b"PK\x05\x06", 0) || has(b"PK\x07\x08", 0) {
        return Some("ZIP");
    }
    let table: &[(&[u8], &str)] = &[
        (b"Rar!\x1a\x07", "RAR"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
        (b"\x1f\x8b", "gzip"),
    ];
    for (signature, name) in table {
        if has(signature, 0) {
            return Some(name);
        }
    }
    if has(b"BZh", 0) && header.get(3).is_some_and(|b| (b'1'..=b'9').contains(b)) {
        return Some("bzip2");
    }
    let table: &[(&[u8], &str)] = &[
        (b"\xfd7zXZ\x00", "xz"),
        (b"LZIP", "lzip"),
        (b"\x04\x22\x4d\x18", "LZ4"),
        (b"\x28\xb5\x2f\xfd", "Zstandard"),
        (b"MSCF\x00\x00\x00\x00", "CAB"),
        (b"\xed\xab\xee\xdb", "RPM"),
        (b"!<arch>\ndebian", "Debian package"),
        // Images.
        (b"\xff\xd8\xff", "JPEG"),
        (b"\x89PNG\r\n\x1a\n", "PNG"),
        (b"GIF87a", "GIF"),
        (b"GIF89a", "GIF"),
    ];
    for (signature, name) in table {
        if has(signature, 0) {
            return Some(name);
        }
    }
    if has(b"RIFF", 0) && has(b"WEBP", 8) {
        return Some("WebP");
    }
    if has(b"\xff\x0a", 0) || has(b"\x00\x00\x00\x0cJXL \r\n\x87\n", 0) {
        return Some("JPEG XL");
    }
    // Audio and video. "ftyp" at offset 4 is ISO media: MP4, MOV, M4A, HEIC, AVIF.
    if has(b"ftyp", 4) {
        return Some("MP4/ISO media");
    }
    let table: &[(&[u8], &str)] = &[
        (b"\x1a\x45\xdf\xa3", "Matroska/WebM"),
        (b"OggS", "Ogg"),
        (b"fLaC", "FLAC"),
        (b"ID3", "MP3"),
    ];
    for (signature, name) in table {
        if has(signature, 0) {
            return Some(name);
        }
    }
    // MPEG audio frame sync (MP3, ADTS AAC).
    if header.len() >= 2 && header[0] == 0xFF && header[1] & 0xE0 == 0xE0 {
        return Some("MPEG audio");
    }
    None
}

/// The detected format when a large payload should skip compression; `None`
/// when it should be compressed.
pub(crate) fn already_compressed_format(
    data_file_path: &Path,
    source_data_size: usize,
) -> Result<Option<&'static str>, String> {
    if source_data_size <= COMPRESS_BYPASS_SIZE {
        return Ok(None);
    }
    let open_error = format!(
        "Failed to open file for compression: {}",
        crate::common::display_safe_path(data_file_path)
    );
    let mut input = open_binary_input_or_throw(data_file_path, &open_error)?;
    let mut header = Zeroizing::new([0u8; FORMAT_HEADER_SIZE]);
    let mut filled = 0;
    while filled < FORMAT_HEADER_SIZE {
        match input.read(&mut header[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(open_error),
        }
    }
    Ok(detect_compressed_format(&header[..filled]))
}

/// Two tiers. The "maximum compression" tier that used to sit here is not worth
/// paying for: measured on a 150 MB mixed-binary corpus, zlib level 9 took
/// 19.4 s for 58,100,237 bytes against 6.3 s for 58,360,140 at level 6 -- 3.1x
/// the time for 0.45% smaller output. Very large inputs drop to fastest so a
/// conceal stays bounded in time.
///
/// The C++ reference additionally caps a whole-buffer libdeflate fast path at
/// 128 MiB (peak RSS and an uninterruptible window). This port has no such path:
/// `zlib_compress_file_to_path_native` always streams in 2 MiB chunks and checks
/// for cancellation every chunk, so neither bound has an analogue here.
fn select_compression_level(input_size: usize) -> Compression {
    if input_size > 500 * 1024 * 1024 {
        Compression::fast()
    } else {
        Compression::default()
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
            crate::common::display_safe_path(input_path)
        ),
    )?;
    // output_path is a StagingFile: link-free already, so a failure part way
    // through leaves nothing behind for a cleanup guard to remove.
    // The OutputFile buffer is zeroed on drop: whole deflate blocks bypass it,
    // short tails pass through it.
    let output_file = OutputFile::open_staging(output_path, 64 * 1024)?;

    // Read straight from the file: the 2 MiB chunks below would bypass a
    // BufReader's buffer anyway, and short reads would leave plaintext in it.
    let mut reader = input_file;
    let writer = OutputFileWriter::new(output_file);
    let mut encoder = ZlibEncoder::new(writer, select_compression_level(expected_input_size));

    // Deflate is not encryption, and this window holds the payload as raw
    // plaintext, so it is zeroed on every path out rather than merely dropped --
    // matching the WipeBytesGuard the C++ reference puts on its in_chunk. (The
    // compressed side: the OutputFile buffer is zeroed, and flate2's internal
    // buffers are zeroed on release by the binary's wipe_alloc allocator.)
    let mut in_chunk = Zeroizing::new(vec![0u8; 2 * 1024 * 1024]);
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
    writer.into_inner().close(WRITE_COMPLETE_ERROR, false)?;
    check_cancellation()?;
    Ok(())
}

/// A fresh 128-bit recovery KEY: 16 random bytes, never all zero (D1).
pub(crate) fn generate_recovery_key() -> Result<RecoveryKey, String> {
    let mut secret = Zeroizing::new([0u8; 16]);
    while secret.iter().all(|&b| b == 0) {
        randombytes_into(&mut secret[..])
            .map_err(|_| "CSPRNG Error: Failed to generate recovery KEY.".to_string())?;
    }
    Ok(RecoveryKey::V128(*secret))
}

// ---------------------------------------------------------------------------
// Conceal progress report (mirrors the C++ conceal.cpp helpers string for
// string). Each step prints its label on its own line
// before the work starts (flushed, so a slow step shows what it is waiting
// on), then its result on the next line, indented under a tick, when it ends.
// ---------------------------------------------------------------------------

const STEP_DONE: &str = " \u{2713}";
const STEP_FAILED: &str = " \u{2717}";
pub(crate) const ENCRYPTION_RESULT: &str =
    "XChaCha20-Poly1305, 256-bit key derived by Argon2id from the 128-bit recovery KEY.";
const KIB: usize = 1024;
const MIB: usize = KIB * KIB;

pub(crate) fn begin_step(label: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{label}...");
    let _ = out.flush();
}

pub(crate) fn end_step(result: &str) {
    if result.is_empty() {
        println!("{STEP_DONE}");
    } else {
        println!("{STEP_DONE} {result}");
    }
}

pub(crate) fn fail_step(result: &str) {
    println!("{STEP_FAILED} {result}");
    let _ = std::io::stdout().lock().flush();
}

// The compress step for a large data file shows a wait note on its result
// line, on a terminal only (a log gets just the result). When the step ends,
// the cursor goes back to the start of the note, rows included when it
// wrapped, and the note is cleared and replaced by the result.
const LARGE_FILE_WAIT: &str =
    " Please wait. Larger data files will take longer to complete this process.";

/// No note when compression is skipped: the step then ends at once.
#[must_use]
pub(crate) fn begin_compress_step(data_size: usize, bypass_compression: bool) -> bool {
    use std::io::IsTerminal;
    begin_step("Compressing data file");
    if bypass_compression || data_size <= LARGE_FILE_SIZE || !std::io::stdout().is_terminal() {
        return false;
    }
    let mut out = std::io::stdout().lock();
    let _ = write!(out, "{LARGE_FILE_WAIT}");
    let _ = out.flush();
    true
}

pub(crate) fn end_compress_step(wait_shown: bool, result: &str) {
    if wait_shown {
        let mut columns = 80usize;
        // SAFETY: TIOCGWINSZ fills a winsize owned by this frame.
        let mut window: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut window) } == 0
            && window.ws_col > 0
        {
            columns = usize::from(window.ws_col);
        }
        let rows_up = (LARGE_FILE_WAIT.len() - 1) / columns;
        if rows_up > 0 {
            print!("\x1b[{rows_up}A");
        }
        print!("\r\x1b[J");
    }
    end_step(result);
}

/// "843 bytes", "512KiB", "14.2MiB".
/// "784.4" from 7844 tenths; a zero tenth is dropped, so 6170 is "617".
fn tenths_text(tenths: usize, unit: &str) -> String {
    if tenths.is_multiple_of(10) {
        format!("{}{unit}", tenths / 10)
    } else {
        format!("{}.{}{unit}", tenths / 10, tenths % 10)
    }
}

pub(crate) fn format_size(bytes: usize) -> String {
    if bytes < KIB {
        return format!("{bytes} byte{}", if bytes == 1 { "" } else { "s" });
    }
    if bytes < MIB {
        return format!("{}KiB", bytes / KIB);
    }
    // Tenths rounded half-up in integers, matching the C++ digits exactly.
    let tenths = (bytes * 10 + MIB / 2) / MIB;
    tenths_text(tenths, "MiB")
}

/// `format_size` with one decimal for KiB too, e.g. "784.4KiB" (but "617KiB"),
/// for the output image size. A value that rounds up to 1024KiB is shown as "1MiB".
pub(crate) fn format_size_precise(bytes: usize) -> String {
    if bytes < KIB {
        return format_size(bytes);
    }
    let kib_tenths = (bytes * 10 + KIB / 2) / KIB;
    if kib_tenths < KIB * 10 {
        return tenths_text(kib_tenths, "KiB");
    }
    let tenths = (bytes * 10 + MIB / 2) / MIB;
    tenths_text(tenths, "MiB")
}

/// Whole percent, rounded down, as "37%"; a nonzero share under 1% is "<1%".
pub(crate) fn percent_text(part: usize, whole: usize) -> String {
    let percent = (part * 100).checked_div(whole).unwrap_or(0);
    if percent == 0 && part > 0 {
        "<1%".to_string()
    } else {
        format!("{percent}%")
    }
}

pub(crate) fn print_conceal_header(
    image_file_path: &Path,
    cover_size: usize,
    data_filename: &[u8],
    data_size: usize,
) {
    println!(
        "\nCover image: {} ({}).",
        crate::common::display_safe_filename(image_file_path),
        format_size(cover_size)
    );
    // validate_data_filename has already required safe UTF-8.
    println!(
        "Data file:   {} ({}).",
        String::from_utf8_lossy(data_filename),
        format_size(data_size)
    );
    println!();
}

/// "3024x4032, Progressive YCbCr 4:2:0, Source-derived Q92 quantization, EXIF orientation applied, metadata removed."
pub(crate) fn describe_optimized_cover(info: &crate::jpeg_preprocess::CoverImageInfo) -> String {
    // The default and Bluesky transforms are lossless, so the quantization
    // tables (and the quality estimated from them) are the source image's own.
    format!(
        "{}x{}, {} {}, Source-derived Q{} quantization, {}metadata removed.",
        info.width,
        info.height,
        if info.progressive {
            "Progressive"
        } else {
            "Baseline"
        },
        info.color_layout,
        info.quality,
        if info.orientation_applied {
            "EXIF orientation applied, "
        } else {
            ""
        }
    )
}

/// Result text for the "Compressing data file" step.
pub(crate) fn describe_compression(
    source_data_size: usize,
    stored_size: usize,
    is_compressed: bool,
    bypass_format: Option<&str>,
) -> String {
    if let Some(format) = bypass_format {
        return format!("skipped (file header shows {format} data, already compressed).");
    }
    if !is_compressed {
        return "no size reduction, stored uncompressed.".to_string();
    }
    if stored_size >= source_data_size {
        // Only Bluesky keeps a compressed form that did not shrink.
        return format!(
            "{} -> {} (no reduction; Bluesky stores compressed data only).",
            format_size(source_data_size),
            format_size(stored_size)
        );
    }
    format!(
        "{} -> {} ({} smaller).",
        format_size(source_data_size),
        format_size(stored_size),
        percent_text(source_data_size - stored_size, source_data_size)
    )
}

pub(crate) fn validate_data_filename(data_file_path: &Path) -> Result<Vec<u8>, String> {
    // Return the raw OsStr bytes of the filename rather than a lossy String, so
    // the embedded name (and its length check) is byte-identical to the input —
    // matching the C++ tool, which stores/reads the filename as raw bytes.
    let Some(name) = data_file_path.file_name() else {
        return Err(
            "Data File Error: Embedded filename is unsafe. Filenames may not begin with '.' or '-', and must be valid UTF-8 without control or bidirectional-formatting characters.".to_string(),
        );
    };
    if !has_safe_embedded_filename(Path::new(name)) {
        return Err(
            "Data File Error: Embedded filename is unsafe. Filenames may not begin with '.' or '-', and must be valid UTF-8 without control or bidirectional-formatting characters.".to_string(),
        );
    }
    let name_bytes = name.as_bytes().to_vec();
    if name_bytes.len() > DATA_FILENAME_MAX_LENGTH {
        return Err(
            "Data File Error: For compatibility requirements, data filename must not exceed 20 bytes (UTF-8). Non-ASCII characters use 2-4 bytes each."
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
    fn precise_size_shows_tenths_of_kib_and_mib() {
        assert_eq!(format_size_precise(843), "843 bytes");
        assert_eq!(format_size_precise(1024), "1KiB");
        assert_eq!(format_size_precise(617 * 1024), "617KiB");
        assert_eq!(format_size_precise(3 * 1024 * 1024), "3MiB");
        assert_eq!(format_size_precise(803_226), "784.4KiB");
        assert_eq!(format_size_precise(1024 * 1024 - 1), "1MiB");
        assert_eq!(format_size_precise(14_890_000), "14.2MiB");
    }

    #[test]
    fn compressed_formats_are_recognized_by_header_not_name() {
        let cases: &[(&[u8], &str)] = &[
            (b"PK\x03\x04\x14\x00", "ZIP"),
            (b"7z\xbc\xaf\x27\x1c\x00\x04", "7-Zip"),
            (b"\x1f\x8b\x08\x00", "gzip"),
            (b"BZh91AY&SY", "bzip2"),
            (b"\x28\xb5\x2f\xfd\x04", "Zstandard"),
            (b"\xff\xd8\xff\xe0\x00\x10JFIF", "JPEG"),
            (b"\x89PNG\r\n\x1a\n\x00\x00", "PNG"),
            (b"RIFF\x00\x00\x00\x00WEBPVP8 ", "WebP"),
            (b"\x00\x00\x00\x20ftypisom", "MP4/ISO media"),
            (b"\x1a\x45\xdf\xa3\x9f", "Matroska/WebM"),
            (b"ID3\x04\x00", "MP3"),
            (b"\xff\xfb\x90\x00", "MPEG audio"),
        ];
        for (header, name) in cases {
            assert_eq!(detect_compressed_format(header), Some(*name), "{name}");
        }
        // Executables, text, short and empty headers are compressed.
        for header in [
            &b"MZ\x90\x00"[..],
            b"\x7fELF\x02\x01",
            b"Hello, world",
            b"BZh",
            b"P",
            b"",
        ] {
            assert_eq!(detect_compressed_format(header), None, "{header:?}");
        }
    }

    #[test]
    fn validate_data_filename_length_and_safety() {
        assert!(validate_data_filename(Path::new("short.txt")).is_ok());
        assert!(validate_data_filename(Path::new(".bad")).is_err());
        assert!(validate_data_filename(Path::new("-bad")).is_err());
        // 21-char name exceeds DATA_FILENAME_MAX_LENGTH (20)
        assert!(validate_data_filename(Path::new("abcdefghij1234567890x")).is_err());
    }

    #[test]
    fn large_payloads_skip_compression_by_header_not_extension() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir();
        let renamed_zip = dir.join(format!("jdvrif_hdr_{nonce}_{}.txt", std::process::id()));
        let fake_zip = dir.join(format!("jdvrif_hdr_{nonce}_{}.zip", std::process::id()));
        std::fs::write(&renamed_zip, b"PK\x03\x04\x14\x00\x00\x00").expect("write");
        std::fs::write(&fake_zip, b"plain text, not an archive").expect("write");

        // Small payloads never read the header.
        assert_eq!(
            already_compressed_format(&renamed_zip, COMPRESS_BYPASS_SIZE),
            Ok(None)
        );
        assert_eq!(
            already_compressed_format(&renamed_zip, COMPRESS_BYPASS_SIZE + 1),
            Ok(Some("ZIP"))
        );
        assert_eq!(
            already_compressed_format(&fake_zip, COMPRESS_BYPASS_SIZE + 1),
            Ok(None)
        );
        let _ = std::fs::remove_file(&renamed_zip);
        let _ = std::fs::remove_file(&fake_zip);
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
        let stage =
            crate::common::StagingFile::new(Path::new(""), "test_comp").expect("staging file");

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
