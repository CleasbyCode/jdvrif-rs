use crate::common::{open_binary_input_or_throw, open_binary_output_for_write_or_throw};
use crate::constants::{
    CORRUPT_FILE_ERROR, MAX_DATA_SIZE_BLUESKY, WRITE_COMPLETE_ERROR, XMP_SEGMENT_TEMPLATE,
};
use crate::signal::check_cancellation;
use std::cmp;
use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

const BLUESKY_ENCRYPTED_FILE_START_INDEX: usize = 0x1D1;
const BLUESKY_EXIF_SEGMENT_DATA_SIZE: usize = 65027;
const BLUESKY_FIRST_DATASET_SIZE_LIMIT: usize = 32767;
const BLUESKY_LAST_DATASET_SIZE_LIMIT: usize = 32730;
const BLUESKY_XMP_SEGMENT_SIZE_LIMIT: usize = 60033;
const BLUESKY_XMP_FOOTER_SIZE: usize = 92;
const BLUESKY_XMP_BASE64_MAX_SCAN_BYTES: usize = 128 * 1024;
const BLUESKY_PHOTOSHOP_SEARCH_WINDOW: usize = BLUESKY_XMP_SEGMENT_SIZE_LIMIT + 128 * 1024;
const BLUESKY_EXIF_MARKER_SEARCH_LIMIT: usize = 100;
const BLUESKY_PHOTOSHOP_SIG_TO_APP13: usize = 9;

const JPEG_EXIF_MARKER: [u8; 2] = [0xFF, 0xE1];
const JPEG_APP13_MARKER: [u8; 2] = [0xFF, 0xED];
const BLUESKY_PHOTOSHOP_SIGNATURE: [u8; 7] = [0x73, 0x68, 0x6F, 0x70, 0x20, 0x33, 0x2E];
const BLUESKY_XMP_CREATOR_SIGNATURE: [u8; 7] = [0x3C, 0x72, 0x64, 0x66, 0x3A, 0x6C, 0x69];

fn search_sig(data: &[u8], sig: &[u8]) -> Option<usize> {
    if sig.is_empty() || data.len() < sig.len() {
        return None;
    }
    data.windows(sig.len()).position(|w| w == sig)
}

fn scan_file_windows<F>(
    path: &Path,
    overlap: usize,
    search_limit: usize,
    start_offset: usize,
    mut visitor: F,
) -> Result<(), String>
where
    F: FnMut(&[u8], usize) -> Result<bool, String>,
{
    let mut input = open_binary_input_or_throw(path, "Read Error: Failed to open image file.")?;
    if start_offset != 0 {
        input
            .seek(SeekFrom::Start(start_offset as u64))
            .map_err(|_| "Read Error: Failed to seek read position.".to_string())?;
    }

    const CHUNK_SIZE: usize = 1024 * 1024;
    let mut buffer = vec![0u8; CHUNK_SIZE + overlap];
    let mut carry = 0usize;
    let mut consumed = start_offset;

    loop {
        check_cancellation()?;
        if search_limit != 0 && consumed >= search_limit {
            break;
        }

        let mut to_read = CHUNK_SIZE;
        if search_limit != 0 {
            to_read = to_read.min(search_limit - consumed);
        }

        let got = input
            .read(&mut buffer[carry..carry + to_read])
            .map_err(|_| "Read Error: Failed while scanning image file.".to_string())?;
        if got == 0 {
            break;
        }

        let window_size = carry + got;
        let base = consumed - carry;
        if visitor(&buffer[..window_size], base)? {
            break;
        }

        if overlap > 0 {
            carry = overlap.min(window_size);
            let src_start = window_size - carry;
            buffer.copy_within(src_start..window_size, 0);
        } else {
            carry = 0;
        }

        consumed = consumed
            .checked_add(got)
            .ok_or_else(|| "File Extraction Error: Signature scan offset overflow.".to_string())?;
    }

    Ok(())
}

pub(crate) fn find_signature_in_file(
    path: &Path,
    sig: &[u8],
    search_limit: usize,
    start_offset: usize,
) -> Result<Option<usize>, String> {
    if sig.is_empty() {
        return Ok(None);
    }
    if search_limit != 0 && search_limit <= start_offset {
        return Ok(None);
    }

    let mut found = None;
    let overlap = if sig.len() > 1 { sig.len() - 1 } else { 0 };

    scan_file_windows(path, overlap, search_limit, start_offset, |window, base| {
        if let Some(pos) = search_sig(window, sig) {
            found = Some(base + pos);
            return Ok(true);
        }
        Ok(false)
    })?;

    Ok(found)
}

// Single forward scan for the first occurrence of `first_sig` that also has
// `second_sig` at `first_sig_index + second_sig_offset`. Returns first_sig's
// index. Every candidate is verified inside the buffered window; a candidate
// whose verification range crosses the window edge is re-presented at the start
// of the next window by the overlap carry, so a file full of decoy
// first-signature hits costs one scan, not one stream restart per hit.
pub(crate) fn find_signature_pair_in_file(
    path: &Path,
    first_sig: &[u8],
    second_sig: &[u8],
    second_sig_offset: usize,
) -> Result<Option<usize>, String> {
    if first_sig.is_empty() || second_sig.is_empty() || second_sig_offset < first_sig.len() {
        return Ok(None);
    }

    // Bytes needed from a candidate's start to verify both signatures.
    let verify_span = second_sig_offset
        .checked_add(second_sig.len())
        .ok_or_else(|| "File Extraction Error: Signature scan size overflow.".to_string())?;

    let mut found = None;
    scan_file_windows(path, verify_span - 1, 0, 0, |window, base| {
        let mut pos = 0usize;
        while pos < window.len() {
            let Some(rel) = search_sig(&window[pos..], first_sig) else {
                return Ok(false);
            };
            let candidate = pos + rel;
            if window.len() - candidate < verify_span {
                // Too close to the window edge to verify; the overlap carry
                // re-presents this candidate at the start of the next window.
                return Ok(false);
            }
            let sec_start = candidate + second_sig_offset;
            if &window[sec_start..sec_start + second_sig.len()] == second_sig {
                found = Some(base + candidate);
                return Ok(true);
            }
            pos = candidate + 1;
        }
        Ok(false)
    })?;

    Ok(found)
}

fn checked_add_corrupt(a: usize, b: usize) -> Result<usize, String> {
    a.checked_add(b)
        .ok_or_else(|| CORRUPT_FILE_ERROR.to_string())
}

fn require_file_range(file_size: usize, offset: usize, length: usize) -> Result<(), String> {
    if offset > file_size || length > file_size.saturating_sub(offset) {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }
    Ok(())
}

fn max_bluesky_embedded_cipher_capacity() -> Result<usize, String> {
    let xmp_overhead = XMP_SEGMENT_TEMPLATE
        .len()
        .checked_add(BLUESKY_XMP_FOOTER_SIZE)
        .ok_or_else(|| CORRUPT_FILE_ERROR.to_string())?;
    if xmp_overhead >= BLUESKY_XMP_SEGMENT_SIZE_LIMIT {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let max_xmp_base64 = BLUESKY_XMP_SEGMENT_SIZE_LIMIT - xmp_overhead;
    let max_xmp_binary = (max_xmp_base64 / 4)
        .checked_mul(3)
        .ok_or_else(|| CORRUPT_FILE_ERROR.to_string())?;

    BLUESKY_EXIF_SEGMENT_DATA_SIZE
        .checked_add(BLUESKY_FIRST_DATASET_SIZE_LIMIT)
        .and_then(|value| value.checked_add(BLUESKY_LAST_DATASET_SIZE_LIMIT))
        .and_then(|value| value.checked_add(max_xmp_binary))
        .ok_or_else(|| CORRUPT_FILE_ERROR.to_string())
}

pub(crate) fn validate_bluesky_exif_metadata_capacity(
    metadata: &[u8],
    embedded_file_size: usize,
) -> Result<(), String> {
    let header_size = cmp::min(metadata.len(), BLUESKY_EXIF_MARKER_SEARCH_LIMIT);
    let exif_sig_index = search_sig(&metadata[..header_size], &JPEG_EXIF_MARKER)
        .ok_or_else(|| CORRUPT_FILE_ERROR.to_string())?;
    if exif_sig_index > metadata.len() || metadata.len() - exif_sig_index < 4 {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let exif_segment_size =
        u16::from_be_bytes([metadata[exif_sig_index + 2], metadata[exif_sig_index + 3]]) as usize;
    if exif_segment_size < 2 {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let exif_end = checked_add_corrupt(exif_sig_index, checked_add_corrupt(2, exif_segment_size)?)?;
    if BLUESKY_ENCRYPTED_FILE_START_INDEX >= exif_end {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }
    let available_exif_payload = exif_end - BLUESKY_ENCRYPTED_FILE_START_INDEX;

    let max_capacity = cmp::min(
        max_bluesky_embedded_cipher_capacity()?,
        MAX_DATA_SIZE_BLUESKY,
    );
    if embedded_file_size > max_capacity {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    if embedded_file_size <= BLUESKY_EXIF_SEGMENT_DATA_SIZE {
        if embedded_file_size > available_exif_payload {
            return Err(CORRUPT_FILE_ERROR.to_string());
        }
    } else if available_exif_payload < BLUESKY_EXIF_SEGMENT_DATA_SIZE {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    Ok(())
}

fn validate_bluesky_exif_capacity(
    input: &mut File,
    image_size: usize,
    embedded_file_size: usize,
) -> Result<(), String> {
    let header_size = cmp::min(image_size, BLUESKY_EXIF_MARKER_SEARCH_LIMIT);
    let mut header = vec![0u8; header_size];
    read_exact_at(input, 0, &mut header).map_err(|_| CORRUPT_FILE_ERROR.to_string())?;
    validate_bluesky_exif_metadata_capacity(&header, embedded_file_size)?;

    let exif_sig_index =
        search_sig(&header, &JPEG_EXIF_MARKER).ok_or_else(|| CORRUPT_FILE_ERROR.to_string())?;
    require_file_range(image_size, exif_sig_index, 4)?;

    let exif_segment_size = read_u16_at(input, exif_sig_index + 2)
        .map_err(|_| CORRUPT_FILE_ERROR.to_string())? as usize;
    // JPEG segment length includes the two-byte length field itself.
    if exif_segment_size < 2 {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let exif_end = checked_add_corrupt(exif_sig_index, checked_add_corrupt(2, exif_segment_size)?)?;
    require_file_range(image_size, exif_sig_index, exif_end - exif_sig_index)?;

    Ok(())
}

fn find_bluesky_photoshop_signature(
    path: &Path,
    input: &mut File,
    image_size: usize,
    exif_chunk_size: usize,
) -> Result<usize, String> {
    // Do not scan EXIF ciphertext for a coincidental or injected signature.
    let search_start = checked_add_corrupt(BLUESKY_ENCRYPTED_FILE_START_INDEX, exif_chunk_size)?;
    if search_start >= image_size {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let search_end = cmp::min(
        image_size,
        checked_add_corrupt(search_start, BLUESKY_PHOTOSHOP_SEARCH_WINDOW)?,
    );
    let sig_index =
        find_signature_in_file(path, &BLUESKY_PHOTOSHOP_SIGNATURE, search_end, search_start)?
            .ok_or_else(|| CORRUPT_FILE_ERROR.to_string())?;

    if sig_index < BLUESKY_PHOTOSHOP_SIG_TO_APP13 {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }
    let app13_index = sig_index - BLUESKY_PHOTOSHOP_SIG_TO_APP13;
    require_file_range(image_size, app13_index, JPEG_APP13_MARKER.len())?;

    let mut marker = [0u8; 2];
    read_exact_at(input, app13_index, &mut marker).map_err(|_| CORRUPT_FILE_ERROR.to_string())?;
    if marker != JPEG_APP13_MARKER {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    Ok(sig_index)
}

fn find_bluesky_xmp_signature(
    path: &Path,
    search_start: usize,
    photoshop_segment_size_index: usize,
) -> Result<usize, String> {
    if search_start >= photoshop_segment_size_index {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    find_signature_in_file(
        path,
        &BLUESKY_XMP_CREATOR_SIGNATURE,
        photoshop_segment_size_index,
        search_start,
    )?
    .ok_or_else(|| CORRUPT_FILE_ERROR.to_string())
}

pub(crate) fn read_exact_at(input: &mut File, offset: usize, out: &mut [u8]) -> Result<(), String> {
    input
        .seek(SeekFrom::Start(offset as u64))
        .map_err(|_| "Read Error: Failed to seek read position.".to_string())?;
    input
        .read_exact(out)
        .map_err(|_| "Read Error: Failed to read expected bytes.".to_string())
}

fn read_u16_at(input: &mut File, offset: usize) -> Result<u16, String> {
    let mut bytes = [0u8; 2];
    read_exact_at(input, offset, &mut bytes)?;
    Ok(u16::from_be_bytes(bytes))
}

fn copy_bytes_to_output(
    input: &mut File,
    output: &mut BufWriter<File>,
    mut length: usize,
    copy_buffer: &mut [u8],
) -> Result<(), String> {
    if copy_buffer.is_empty() {
        return Err("Internal Error: Empty copy buffer.".to_string());
    }
    while length > 0 {
        check_cancellation()?;
        let chunk = cmp::min(length, copy_buffer.len());
        input
            .read_exact(&mut copy_buffer[..chunk])
            .map_err(|_| "Read Error: Failed while extracting encrypted payload.".to_string())?;
        output
            .write_all(&copy_buffer[..chunk])
            .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;
        length -= chunk;
    }

    Ok(())
}

fn copy_range_to_output(
    input: &mut File,
    output: &mut BufWriter<File>,
    offset: usize,
    length: usize,
    copy_buffer: &mut [u8],
) -> Result<(), String> {
    input
        .seek(SeekFrom::Start(offset as u64))
        .map_err(|_| "Read Error: Failed to seek payload position.".to_string())?;
    copy_bytes_to_output(input, output, length, copy_buffer)
}

fn skip_exact_bytes(input: &mut File, length: usize) -> Result<(), String> {
    input
        .seek(SeekFrom::Current(length as i64))
        .map_err(|_| "Read Error: Failed while skipping ICC profile header bytes.".to_string())?;
    Ok(())
}

fn decode_base64_char(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn stream_decode_base64_until_delimiter_to_output(
    input: &mut File,
    offset: usize,
    delimiter: u8,
    max_bytes: usize,
    expected_decoded_size: usize,
    output: &mut BufWriter<File>,
    corrupt_error: &str,
) -> Result<usize, String> {
    const READ_CHUNK_SIZE: usize = 4096;
    const WRITE_CHUNK_SIZE: usize = 4096;

    if max_bytes == 0 {
        return Err(corrupt_error.to_string());
    }

    input
        .seek(SeekFrom::Start(offset as u64))
        .map_err(|_| "Read Error: Failed to seek read position.".to_string())?;

    let mut in_chunk = [0u8; READ_CHUNK_SIZE];
    let mut out_chunk = [0u8; WRITE_CHUNK_SIZE];
    let mut quartet = [0u8; 4];

    let mut quartet_len = 0usize;
    let mut out_len = 0usize;
    let mut decoded_total = 0usize;
    let mut scanned = 0usize;
    let mut found_delimiter = false;
    let mut saw_padding = false;

    let mut emit_decoded =
        |value: u8, out_len_ref: &mut usize, decoded_total_ref: &mut usize| -> Result<(), String> {
            if *decoded_total_ref >= expected_decoded_size {
                return Err(corrupt_error.to_string());
            }

            out_chunk[*out_len_ref] = value;
            *out_len_ref += 1;
            *decoded_total_ref += 1;

            if *out_len_ref == out_chunk.len() {
                output
                    .write_all(&out_chunk[..*out_len_ref])
                    .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;
                *out_len_ref = 0;
            }

            Ok(())
        };

    while scanned < max_bytes && !found_delimiter {
        check_cancellation()?;
        let chunk = cmp::min(READ_CHUNK_SIZE, max_bytes - scanned);
        let got = input
            .read(&mut in_chunk[..chunk])
            .map_err(|_| "Read Error: Failed while scanning XMP payload.".to_string())?;
        if got == 0 {
            break;
        }
        scanned += got;

        for &c in &in_chunk[..got] {
            if c == delimiter {
                found_delimiter = true;
                break;
            }

            if saw_padding {
                return Err(corrupt_error.to_string());
            }

            quartet[quartet_len] = c;
            quartet_len += 1;
            if quartet_len != 4 {
                continue;
            }

            let p2 = quartet[2] == b'=';
            let p3 = quartet[3] == b'=';
            if p2 && !p3 {
                return Err(corrupt_error.to_string());
            }

            let v0 = decode_base64_char(quartet[0]).ok_or_else(|| corrupt_error.to_string())?;
            let v1 = decode_base64_char(quartet[1]).ok_or_else(|| corrupt_error.to_string())?;
            let v2 = if p2 {
                0
            } else {
                decode_base64_char(quartet[2]).ok_or_else(|| corrupt_error.to_string())?
            };
            let v3 = if p3 {
                0
            } else {
                decode_base64_char(quartet[3]).ok_or_else(|| corrupt_error.to_string())?
            };
            if (p2 && (v1 & 0x0F) != 0) || (!p2 && p3 && (v2 & 0x03) != 0) {
                return Err(corrupt_error.to_string());
            }

            let triple =
                ((v0 as u32) << 18) | ((v1 as u32) << 12) | ((v2 as u32) << 6) | (v3 as u32);

            emit_decoded(
                ((triple >> 16) & 0xFF) as u8,
                &mut out_len,
                &mut decoded_total,
            )?;
            if !p2 {
                emit_decoded(
                    ((triple >> 8) & 0xFF) as u8,
                    &mut out_len,
                    &mut decoded_total,
                )?;
            }
            if !p3 {
                emit_decoded((triple & 0xFF) as u8, &mut out_len, &mut decoded_total)?;
            }

            saw_padding = p2 || p3;
            quartet_len = 0;
        }
    }

    if !found_delimiter || quartet_len != 0 || decoded_total != expected_decoded_size {
        return Err(corrupt_error.to_string());
    }

    if out_len > 0 {
        output
            .write_all(&out_chunk[..out_len])
            .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;
    }

    Ok(decoded_total)
}

pub(crate) fn extract_default_ciphertext_to_file(
    image_path: &Path,
    image_size: usize,
    base_offset: usize,
    embedded_file_size: usize,
    total_profile_header_segments: u16,
    output_path: &Path,
) -> Result<usize, String> {
    const ENCRYPTED_FILE_START_INDEX: usize = 0x33B;
    const HEADER_INDEX: usize = 0xFCB0;
    const PROFILE_HEADER_LENGTH: usize = 18;
    const COMMON_DIFF_VAL: usize = 65537;

    if base_offset > image_size
        || ENCRYPTED_FILE_START_INDEX > image_size.saturating_sub(base_offset)
    {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let payload_start = base_offset + ENCRYPTED_FILE_START_INDEX;
    if embedded_file_size > image_size.saturating_sub(payload_start) {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let mut input =
        open_binary_input_or_throw(image_path, "Read Error: Failed to open image file.")?;
    let output_file = open_binary_output_for_write_or_throw(output_path)?;
    let mut output = BufWriter::new(output_file);
    let mut copy_buffer = vec![0u8; 2 * 1024 * 1024];

    if total_profile_header_segments != 0 {
        let segment_count = (total_profile_header_segments as usize).saturating_sub(1);
        let marker_offset = segment_count
            .checked_mul(COMMON_DIFF_VAL)
            .ok_or_else(|| CORRUPT_FILE_ERROR.to_string())?;
        if marker_offset < 0x16 {
            return Err(CORRUPT_FILE_ERROR.to_string());
        }

        let marker_index = marker_offset - 0x16;
        if marker_index > image_size.saturating_sub(base_offset)
            || image_size
                .saturating_sub(base_offset)
                .saturating_sub(marker_index)
                < 2
        {
            return Err(CORRUPT_FILE_ERROR.to_string());
        }

        let mut marker = [0u8; 2];
        read_exact_at(&mut input, base_offset + marker_index, &mut marker)?;
        if marker != [0xFF, 0xE2] {
            return Err(
                "File Extraction Error: Missing segments detected. Embedded data file is corrupt!"
                    .to_string(),
            );
        }
    }

    let has_profile_headers = total_profile_header_segments != 0;
    input
        .seek(SeekFrom::Start(payload_start as u64))
        .map_err(|_| "Read Error: Failed to seek payload position.".to_string())?;

    let mut cursor = 0usize;
    let mut next_header = HEADER_INDEX;
    let mut written = 0usize;

    while cursor < embedded_file_size {
        if has_profile_headers && cursor == next_header {
            let skip = cmp::min(PROFILE_HEADER_LENGTH, embedded_file_size - cursor);
            skip_exact_bytes(&mut input, skip)?;
            cursor += skip;
            if let Some(v) = next_header.checked_add(COMMON_DIFF_VAL) {
                next_header = v;
            }
            continue;
        }

        let next_cut = if has_profile_headers {
            cmp::min(embedded_file_size, next_header)
        } else {
            embedded_file_size
        };
        let run = next_cut - cursor;

        copy_bytes_to_output(&mut input, &mut output, run, &mut copy_buffer)?;
        cursor += run;
        written += run;
    }

    output
        .flush()
        .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;

    Ok(written)
}

pub(crate) fn extract_bluesky_ciphertext_to_file(
    image_path: &Path,
    image_size: usize,
    embedded_file_size: usize,
    output_path: &Path,
) -> Result<usize, String> {
    const DATASET_MAX_SIZE: usize = 32800;
    const PSHOP_SEGMENT_SIZE_DIFF: usize = 7;
    const FIRST_DATASET_SIZE_DIFF: usize = 24;
    const DATASET_FILE_INDEX_DIFF: usize = 2;
    const SECOND_DATASET_SIZE_DIFF: usize = 3;
    const BASE64_END_SIG: u8 = 0x3C;

    if embedded_file_size == 0 || BLUESKY_ENCRYPTED_FILE_START_INDEX > image_size {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let exif_chunk_size = cmp::min(embedded_file_size, BLUESKY_EXIF_SEGMENT_DATA_SIZE);
    if exif_chunk_size > image_size.saturating_sub(BLUESKY_ENCRYPTED_FILE_START_INDEX) {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let mut input =
        open_binary_input_or_throw(image_path, "Read Error: Failed to open image file.")?;
    validate_bluesky_exif_capacity(&mut input, image_size, embedded_file_size)?;

    let output_file = open_binary_output_for_write_or_throw(output_path)?;
    let mut output = BufWriter::new(output_file);
    let mut copy_buffer = vec![0u8; 2 * 1024 * 1024];

    let mut written = 0usize;
    copy_range_to_output(
        &mut input,
        &mut output,
        BLUESKY_ENCRYPTED_FILE_START_INDEX,
        exif_chunk_size,
        &mut copy_buffer,
    )?;
    written += exif_chunk_size;

    let mut remaining = embedded_file_size - exif_chunk_size;
    if remaining == 0 {
        output
            .flush()
            .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;
        return Ok(written);
    }

    let pshop_sig_index =
        find_bluesky_photoshop_signature(image_path, &mut input, image_size, exif_chunk_size)?;

    if pshop_sig_index < PSHOP_SEGMENT_SIZE_DIFF {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let pshop_segment_size_index = pshop_sig_index - PSHOP_SEGMENT_SIZE_DIFF;
    let first_dataset_size_index = checked_add_corrupt(pshop_sig_index, FIRST_DATASET_SIZE_DIFF)?;
    let first_dataset_file_index =
        checked_add_corrupt(first_dataset_size_index, DATASET_FILE_INDEX_DIFF)?;

    require_file_range(image_size, pshop_segment_size_index, 2)?;
    require_file_range(image_size, first_dataset_size_index, 2)?;

    let pshop_segment_size = read_u16_at(&mut input, pshop_segment_size_index)?;
    require_file_range(
        image_size,
        pshop_segment_size_index,
        pshop_segment_size as usize,
    )?;
    let first_dataset_size = read_u16_at(&mut input, first_dataset_size_index)? as usize;

    if first_dataset_size == 0
        || first_dataset_size > remaining
        || first_dataset_size > image_size.saturating_sub(first_dataset_file_index)
    {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    copy_range_to_output(
        &mut input,
        &mut output,
        first_dataset_file_index,
        first_dataset_size,
        &mut copy_buffer,
    )?;
    written += first_dataset_size;
    remaining -= first_dataset_size;

    if remaining == 0 {
        output
            .flush()
            .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;
        return Ok(written);
    }

    if pshop_segment_size as usize <= DATASET_MAX_SIZE {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    let second_dataset_size_index = checked_add_corrupt(
        checked_add_corrupt(first_dataset_file_index, first_dataset_size)?,
        SECOND_DATASET_SIZE_DIFF,
    )?;
    let second_dataset_file_index =
        checked_add_corrupt(second_dataset_size_index, DATASET_FILE_INDEX_DIFF)?;

    require_file_range(image_size, second_dataset_size_index, 2)?;

    let second_dataset_size = read_u16_at(&mut input, second_dataset_size_index)? as usize;
    if second_dataset_size == 0
        || second_dataset_size > remaining
        || second_dataset_size > image_size.saturating_sub(second_dataset_file_index)
    {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    copy_range_to_output(
        &mut input,
        &mut output,
        second_dataset_file_index,
        second_dataset_size,
        &mut copy_buffer,
    )?;
    written += second_dataset_size;
    remaining -= second_dataset_size;

    if remaining == 0 {
        output
            .flush()
            .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;
        return Ok(written);
    }

    let xmp_search_start =
        checked_add_corrupt(BLUESKY_ENCRYPTED_FILE_START_INDEX, exif_chunk_size)?;
    let xmp_sig_index =
        find_bluesky_xmp_signature(image_path, xmp_search_start, pshop_segment_size_index)?;
    let base64_begin_index = checked_add_corrupt(
        checked_add_corrupt(xmp_sig_index, BLUESKY_XMP_CREATOR_SIGNATURE.len())?,
        1,
    )?;
    require_file_range(image_size, base64_begin_index, 0)?;

    written += stream_decode_base64_until_delimiter_to_output(
        &mut input,
        base64_begin_index,
        BASE64_END_SIG,
        BLUESKY_XMP_BASE64_MAX_SCAN_BYTES,
        remaining,
        &mut output,
        CORRUPT_FILE_ERROR,
    )?;

    output
        .flush()
        .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;

    if written != embedded_file_size {
        return Err(CORRUPT_FILE_ERROR.to_string());
    }

    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "jdvrif_extract_{}_{}_{}",
            name,
            std::process::id(),
            nanos
        ))
    }

    fn write_fixture(name: &str, data: &[u8]) -> std::path::PathBuf {
        let path = temp_path(name);
        std::fs::write(&path, data).unwrap();
        path
    }

    fn set_exif_end(data: &mut [u8], exif_end: usize) {
        const EXIF_MARKER_INDEX: usize = 2;
        let segment_size = exif_end
            .checked_sub(EXIF_MARKER_INDEX + 2)
            .and_then(|value| u16::try_from(value).ok())
            .expect("synthetic APP1 length");
        data[EXIF_MARKER_INDEX..EXIF_MARKER_INDEX + 2].copy_from_slice(&JPEG_EXIF_MARKER);
        data[EXIF_MARKER_INDEX + 2..EXIF_MARKER_INDEX + 4]
            .copy_from_slice(&segment_size.to_be_bytes());
    }

    fn place_framed_photoshop_signature(data: &mut [u8], sig_index: usize) {
        let app13_index = sig_index - BLUESKY_PHOTOSHOP_SIG_TO_APP13;
        data[app13_index..app13_index + JPEG_APP13_MARKER.len()]
            .copy_from_slice(&JPEG_APP13_MARKER);
        data[sig_index..sig_index + BLUESKY_PHOTOSHOP_SIGNATURE.len()]
            .copy_from_slice(&BLUESKY_PHOTOSHOP_SIGNATURE);
    }

    #[test]
    fn find_signature_in_file_across_chunk_boundary() {
        let path = temp_path("sig");
        // Place signature so it straddles a potential small-window edge; scan still finds it.
        let mut data = vec![0u8; 100];
        let sig = b"JDVRSIG";
        data[40..40 + sig.len()].copy_from_slice(sig);
        std::fs::write(&path, &data).unwrap();
        let found = find_signature_in_file(&path, sig, 0, 0).unwrap();
        assert_eq!(found, Some(40));
        assert!(find_signature_in_file(&path, b"NOPE", 0, 0)
            .unwrap()
            .is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn find_signature_pair_requires_fixed_offset() {
        let path = temp_path("pair");
        let mut data = vec![0u8; 200];
        let first = b"ICCPROF";
        let second = b"JDVRIF!";
        data[10..10 + first.len()].copy_from_slice(first);
        // Offset 20 from first start => absolute 30
        data[30..30 + second.len()].copy_from_slice(second);
        std::fs::write(&path, &data).unwrap();
        assert_eq!(
            find_signature_pair_in_file(&path, first, second, 20).unwrap(),
            Some(10)
        );
        assert!(find_signature_pair_in_file(&path, first, second, 21)
            .unwrap()
            .is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn base64_stream_decode_roundtrip_size() {
        // "Man" -> "TWFu"
        let path = temp_path("b64");
        std::fs::write(&path, b"TWFu<").unwrap();
        let out = temp_path("b64out");
        let mut input = std::fs::File::open(&path).unwrap();
        let output_file = open_binary_output_for_write_or_throw(&out).unwrap();
        let mut output = BufWriter::new(output_file);
        let n = stream_decode_base64_until_delimiter_to_output(
            &mut input,
            0,
            b'<',
            64,
            3,
            &mut output,
            "corrupt",
        )
        .unwrap();
        output.flush().unwrap();
        assert_eq!(n, 3);
        assert_eq!(std::fs::read(&out).unwrap(), b"Man");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn base64_stream_decode_rejects_noncanonical_padding_bits() {
        for (index, encoded, expected_size) in [
            (0, b"TR==<".as_slice(), 1usize),
            (1, b"TWF=<".as_slice(), 2usize),
        ] {
            let path = temp_path(&format!("b64_bad_pad_{index}"));
            let out = temp_path(&format!("b64_bad_pad_out_{index}"));
            std::fs::write(&path, encoded).unwrap();
            let mut input = File::open(&path).unwrap();
            let output_file = open_binary_output_for_write_or_throw(&out).unwrap();
            let mut output = BufWriter::new(output_file);
            assert!(stream_decode_base64_until_delimiter_to_output(
                &mut input,
                0,
                b'<',
                64,
                expected_size,
                &mut output,
                "corrupt",
            )
            .is_err());
            let _ = std::fs::remove_file(path);
            let _ = std::fs::remove_file(out);
        }
    }

    #[test]
    fn bluesky_exif_capacity_checks_app1_bounds_and_transport_ceiling() {
        let valid_end = BLUESKY_ENCRYPTED_FILE_START_INDEX + BLUESKY_EXIF_SEGMENT_DATA_SIZE;
        let mut valid = vec![0u8; valid_end + 1];
        set_exif_end(&mut valid, valid_end);
        let valid_path = write_fixture("bsky_exif_valid", &valid);
        let mut valid_file = File::open(&valid_path).unwrap();
        assert!(validate_bluesky_exif_capacity(
            &mut valid_file,
            valid.len(),
            BLUESKY_EXIF_SEGMENT_DATA_SIZE + 1,
        )
        .is_ok());

        let short_end = valid_end - 1;
        let mut short = vec![0u8; valid_end + 1];
        set_exif_end(&mut short, short_end);
        let short_path = write_fixture("bsky_exif_short", &short);
        let mut short_file = File::open(&short_path).unwrap();
        assert!(validate_bluesky_exif_capacity(
            &mut short_file,
            short.len(),
            BLUESKY_EXIF_SEGMENT_DATA_SIZE + 1,
        )
        .is_err());

        let max_capacity = max_bluesky_embedded_cipher_capacity().unwrap();
        let mut oversized_file = File::open(&valid_path).unwrap();
        assert!(
            validate_bluesky_exif_capacity(&mut oversized_file, valid.len(), max_capacity + 1,)
                .is_err()
        );

        let _ = std::fs::remove_file(valid_path);
        let _ = std::fs::remove_file(short_path);
    }

    #[test]
    fn bluesky_photoshop_search_is_post_exif_bounded_and_framed() {
        let search_start = BLUESKY_ENCRYPTED_FILE_START_INDEX + BLUESKY_EXIF_SEGMENT_DATA_SIZE;
        let mut valid = vec![0u8; search_start + BLUESKY_PHOTOSHOP_SEARCH_WINDOW + 64];

        // This bare hit is inside EXIF-held ciphertext and must never be considered.
        let exif_decoy = search_start - 32;
        valid[exif_decoy..exif_decoy + BLUESKY_PHOTOSHOP_SIGNATURE.len()]
            .copy_from_slice(&BLUESKY_PHOTOSHOP_SIGNATURE);
        let real_sig = search_start + 32;
        place_framed_photoshop_signature(&mut valid, real_sig);

        let valid_path = write_fixture("bsky_pshop_valid", &valid);
        let mut valid_file = File::open(&valid_path).unwrap();
        assert_eq!(
            find_bluesky_photoshop_signature(
                &valid_path,
                &mut valid_file,
                valid.len(),
                BLUESKY_EXIF_SEGMENT_DATA_SIZE,
            )
            .unwrap(),
            real_sig,
        );

        // The first post-EXIF hit is deliberately unframed; it must be rejected
        // rather than letting a later, framed APP13 hide the malformed layout.
        let mut unframed = valid.clone();
        let bare_sig = search_start + 8;
        unframed[bare_sig..bare_sig + BLUESKY_PHOTOSHOP_SIGNATURE.len()]
            .copy_from_slice(&BLUESKY_PHOTOSHOP_SIGNATURE);
        let unframed_path = write_fixture("bsky_pshop_unframed", &unframed);
        let mut unframed_file = File::open(&unframed_path).unwrap();
        assert!(find_bluesky_photoshop_signature(
            &unframed_path,
            &mut unframed_file,
            unframed.len(),
            BLUESKY_EXIF_SEGMENT_DATA_SIZE,
        )
        .is_err());

        let mut outside = vec![0u8; search_start + BLUESKY_PHOTOSHOP_SEARCH_WINDOW + 64];
        let outside_sig = search_start + BLUESKY_PHOTOSHOP_SEARCH_WINDOW + 8;
        place_framed_photoshop_signature(&mut outside, outside_sig);
        let outside_path = write_fixture("bsky_pshop_outside", &outside);
        let mut outside_file = File::open(&outside_path).unwrap();
        assert!(find_bluesky_photoshop_signature(
            &outside_path,
            &mut outside_file,
            outside.len(),
            BLUESKY_EXIF_SEGMENT_DATA_SIZE,
        )
        .is_err());

        let _ = std::fs::remove_file(valid_path);
        let _ = std::fs::remove_file(unframed_path);
        let _ = std::fs::remove_file(outside_path);
    }

    #[test]
    fn bluesky_xmp_search_requires_signature_before_app13() {
        let search_start = 200usize;
        let photoshop_segment_size_index = 500usize;
        let expected = 300usize;

        let mut valid = vec![0u8; 800];
        valid[expected..expected + BLUESKY_XMP_CREATOR_SIGNATURE.len()]
            .copy_from_slice(&BLUESKY_XMP_CREATOR_SIGNATURE);
        valid[700..700 + BLUESKY_XMP_CREATOR_SIGNATURE.len()]
            .copy_from_slice(&BLUESKY_XMP_CREATOR_SIGNATURE);
        let valid_path = write_fixture("bsky_xmp_order", &valid);
        assert_eq!(
            find_bluesky_xmp_signature(&valid_path, search_start, photoshop_segment_size_index,)
                .unwrap(),
            expected,
        );

        let mut after_only = vec![0u8; 800];
        after_only[700..700 + BLUESKY_XMP_CREATOR_SIGNATURE.len()]
            .copy_from_slice(&BLUESKY_XMP_CREATOR_SIGNATURE);
        let after_path = write_fixture("bsky_xmp_after", &after_only);
        assert!(find_bluesky_xmp_signature(
            &after_path,
            search_start,
            photoshop_segment_size_index,
        )
        .is_err());

        let _ = std::fs::remove_file(valid_path);
        let _ = std::fs::remove_file(after_path);
    }

    #[test]
    fn bluesky_extraction_preserves_valid_single_and_split_layouts() {
        let single_payload = b"single bluesky ciphertext";
        let single_end = BLUESKY_ENCRYPTED_FILE_START_INDEX + single_payload.len();
        let mut single = vec![0u8; single_end];
        set_exif_end(&mut single, single_end);
        single[BLUESKY_ENCRYPTED_FILE_START_INDEX..single_end].copy_from_slice(single_payload);
        let single_path = write_fixture("bsky_single", &single);
        let single_out = temp_path("bsky_single_out");
        assert_eq!(
            extract_bluesky_ciphertext_to_file(
                &single_path,
                single.len(),
                single_payload.len(),
                &single_out,
            )
            .unwrap(),
            single_payload.len(),
        );
        assert_eq!(std::fs::read(&single_out).unwrap(), single_payload);

        let tail_payload = b"APP13-tail";
        let app13_index = BLUESKY_ENCRYPTED_FILE_START_INDEX + BLUESKY_EXIF_SEGMENT_DATA_SIZE;
        let photoshop_sig_index = app13_index + BLUESKY_PHOTOSHOP_SIG_TO_APP13;
        let first_dataset_size_index = photoshop_sig_index + 24;
        let first_dataset_file_index = first_dataset_size_index + 2;
        let photoshop_segment_size = 33 + tail_payload.len();
        let split_len = first_dataset_file_index + tail_payload.len();
        let mut split = vec![0u8; split_len];
        set_exif_end(&mut split, app13_index);
        split[BLUESKY_ENCRYPTED_FILE_START_INDEX..app13_index].fill(0xA5);
        place_framed_photoshop_signature(&mut split, photoshop_sig_index);
        split[app13_index + 2..app13_index + 4]
            .copy_from_slice(&(photoshop_segment_size as u16).to_be_bytes());
        split[first_dataset_size_index..first_dataset_size_index + 2]
            .copy_from_slice(&(tail_payload.len() as u16).to_be_bytes());
        split[first_dataset_file_index..first_dataset_file_index + tail_payload.len()]
            .copy_from_slice(tail_payload);

        let split_path = write_fixture("bsky_split", &split);
        let split_out = temp_path("bsky_split_out");
        let split_payload_size = BLUESKY_EXIF_SEGMENT_DATA_SIZE + tail_payload.len();
        assert_eq!(
            extract_bluesky_ciphertext_to_file(
                &split_path,
                split.len(),
                split_payload_size,
                &split_out,
            )
            .unwrap(),
            split_payload_size,
        );
        let extracted = std::fs::read(&split_out).unwrap();
        assert_eq!(
            &extracted[..BLUESKY_EXIF_SEGMENT_DATA_SIZE],
            vec![0xA5; BLUESKY_EXIF_SEGMENT_DATA_SIZE],
        );
        assert_eq!(&extracted[BLUESKY_EXIF_SEGMENT_DATA_SIZE..], tail_payload,);

        for path in [single_path, single_out, split_path, split_out] {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn bluesky_extraction_preserves_valid_xmp_overflow_layout() {
        const XMP_FOOTER: &[u8] =
            b"</rdf:li></rdf:Seq></dc:creator></rdf:Description></rdf:RDF></x:xmpmeta>\n<?xpacket end=\"w\"?>";
        const XMP_TAIL: &[u8] = b"XYZ";

        assert_eq!(XMP_FOOTER.len(), BLUESKY_XMP_FOOTER_SIZE);

        let xmp_start = BLUESKY_ENCRYPTED_FILE_START_INDEX + BLUESKY_EXIF_SEGMENT_DATA_SIZE;
        let mut image = vec![0u8; xmp_start];
        set_exif_end(&mut image, xmp_start);
        image[BLUESKY_ENCRYPTED_FILE_START_INDEX..xmp_start].fill(0xA5);

        let mut xmp = XMP_SEGMENT_TEMPLATE.to_vec();
        xmp.extend_from_slice(b"WFla");
        xmp.extend_from_slice(XMP_FOOTER);
        let xmp_segment_size = u16::try_from(xmp.len() - 2).unwrap();
        xmp[2..4].copy_from_slice(&xmp_segment_size.to_be_bytes());
        image.extend_from_slice(&xmp);

        let mut photoshop = crate::constants::PHOTOSHOP_SEGMENT_TEMPLATE.to_vec();
        photoshop.extend(std::iter::repeat_n(0xB6, BLUESKY_FIRST_DATASET_SIZE_LIMIT));
        photoshop.extend_from_slice(&[0x1C, 0x08, 0x0A]);
        photoshop.extend_from_slice(&(BLUESKY_LAST_DATASET_SIZE_LIMIT as u16).to_be_bytes());
        photoshop.extend(std::iter::repeat_n(0xC7, BLUESKY_LAST_DATASET_SIZE_LIMIT));
        image.extend_from_slice(&photoshop);

        let embedded_size = BLUESKY_EXIF_SEGMENT_DATA_SIZE
            + BLUESKY_FIRST_DATASET_SIZE_LIMIT
            + BLUESKY_LAST_DATASET_SIZE_LIMIT
            + XMP_TAIL.len();
        let image_path = write_fixture("bsky_xmp_extract", &image);
        let output_path = temp_path("bsky_xmp_extract_out");
        assert_eq!(
            extract_bluesky_ciphertext_to_file(
                &image_path,
                image.len(),
                embedded_size,
                &output_path,
            )
            .unwrap(),
            embedded_size,
        );

        let extracted = std::fs::read(&output_path).unwrap();
        let first_dataset_start = BLUESKY_EXIF_SEGMENT_DATA_SIZE;
        let second_dataset_start = first_dataset_start + BLUESKY_FIRST_DATASET_SIZE_LIMIT;
        let xmp_tail_start = second_dataset_start + BLUESKY_LAST_DATASET_SIZE_LIMIT;
        assert!(extracted[..first_dataset_start]
            .iter()
            .all(|value| *value == 0xA5));
        assert!(extracted[first_dataset_start..second_dataset_start]
            .iter()
            .all(|value| *value == 0xB6));
        assert!(extracted[second_dataset_start..xmp_tail_start]
            .iter()
            .all(|value| *value == 0xC7));
        assert_eq!(&extracted[xmp_tail_start..], XMP_TAIL);

        let _ = std::fs::remove_file(image_path);
        let _ = std::fs::remove_file(output_path);
    }
}
