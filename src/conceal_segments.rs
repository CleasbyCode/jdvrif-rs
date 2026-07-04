use crate::common::{checked_file_size, open_binary_input_or_throw, span_has_range, update_value};
use crate::constants::{
    BLUESKY_ARTIST_FIELD_SIZE_DIFF, BLUESKY_ARTIST_FIELD_SIZE_INDEX,
    BLUESKY_COMPRESSED_FILE_SIZE_INDEX, BLUESKY_EXIF_SEGMENT_DATA_INSERT_INDEX,
    BLUESKY_EXIF_SEGMENT_SIZE_INDEX, BLUESKY_EXIF_TEMPLATE, DEFAULT_ICC_SIG_INDEX_ABS,
    DEFAULT_ICC_TEMPLATE, DEFAULT_JDVRIF_SIG_INDEX_ABS, DEFAULT_METADATA_PREFIX_BYTES,
    DEFAULT_PIN_ATTEMPTS_INDEX_ABS, DEFLATED_DATA_FILE_SIZE_INDEX, ICC_PROFILE_SIG, JDVRIF_SIG,
    MAX_SIZE_REDDIT_PADDING, PADDING_RANGE, PADDING_START, PHOTOSHOP_SEGMENT_TEMPLATE,
    PIN_ATTEMPTS_RESET, PROFILE_DATA_SIZE, PROFILE_SIZE_DIFF, PROFILE_SIZE_INDEX, SEGMENT_DATA_SIZE,
    SEGMENT_HEADER_LENGTH, SEGMENT_HEADER_SIZE_INDEX, SEGMENT_SIG_LENGTH, SEGMENTS_TOTAL_VAL_INDEX,
    SOI_SIG_LENGTH, XMP_SEGMENT_TEMPLATE,
};
use crate::crypto::randombytes_uniform;
use crate::output_file::{OutputFile, PayloadSource};
use std::cmp;
use std::os::unix::io::AsRawFd;

/// Summary returned by the streaming segmenter — mirrors C++ SegmentedEmbedSummary.
#[derive(Clone, Copy, Default)]
pub(crate) struct SegmentedEmbedSummary {
    pub embedded_image_size: usize,
    pub first_segment_size: u16,
    pub total_segments: u16,
}

pub(crate) fn make_default_segment_template() -> Result<Vec<u8>, String> {
    if DEFAULT_ICC_TEMPLATE.len() != DEFAULT_METADATA_PREFIX_BYTES {
        return Err("Internal Error: Corrupt default ICC segment template.".to_string());
    }

    let mut out = DEFAULT_ICC_TEMPLATE.to_vec();
    if !span_has_range(out.len(), DEFAULT_ICC_SIG_INDEX_ABS, ICC_PROFILE_SIG.len())
        || !span_has_range(out.len(), DEFAULT_JDVRIF_SIG_INDEX_ABS, JDVRIF_SIG.len())
        || !span_has_range(out.len(), DEFAULT_PIN_ATTEMPTS_INDEX_ABS, 1)
    {
        return Err("Internal Error: Corrupt default ICC segment template.".to_string());
    }

    out[DEFAULT_ICC_SIG_INDEX_ABS..DEFAULT_ICC_SIG_INDEX_ABS + ICC_PROFILE_SIG.len()]
        .copy_from_slice(&ICC_PROFILE_SIG);
    out[DEFAULT_JDVRIF_SIG_INDEX_ABS..DEFAULT_JDVRIF_SIG_INDEX_ABS + JDVRIF_SIG.len()]
        .copy_from_slice(&JDVRIF_SIG);
    out[DEFAULT_PIN_ATTEMPTS_INDEX_ABS] = PIN_ATTEMPTS_RESET;
    Ok(out)
}

pub(crate) fn make_bluesky_segment_template() -> Result<Vec<u8>, String> {
    if BLUESKY_EXIF_TEMPLATE.len() < BLUESKY_EXIF_SEGMENT_DATA_INSERT_INDEX {
        return Err("Internal Error: Corrupt Bluesky segment template.".to_string());
    }
    Ok(BLUESKY_EXIF_TEMPLATE.to_vec())
}

fn make_icc_header(segment_length: u16, segment_index: usize) -> [u8; 18] {
    let mut header = [
        0xFF, 0xE2, 0x00, 0x00, b'I', b'C', b'C', b'_', b'P', b'R', b'O', b'F', b'I', b'L', b'E',
        0x00, 0x00, 0x01,
    ];
    header[2] = (segment_length >> 8) as u8;
    header[3] = (segment_length & 0xFF) as u8;
    header[15] = ((segment_index >> 8) & 0xFF) as u8;
    header[16] = (segment_index & 0xFF) as u8;
    header
}

/// Port of C++ writeIccDataToOutput (segmentation.cpp lines 160-249).
/// Streams segment headers + encrypted payload into `out`.
/// `segment_vec` holds the in-memory template prefix (SOI + first ICC header + KDF metadata).
pub(crate) fn write_icc_data_to_output(
    out: &mut OutputFile,
    segment_vec: &mut [u8],
    encrypted_fd: i32,
    encrypted_size: usize,
    omit_soi: bool,
) -> Result<SegmentedEmbedSummary, String> {
    let initial_header_bytes = SOI_SIG_LENGTH + SEGMENT_SIG_LENGTH + SEGMENT_HEADER_LENGTH;
    if segment_vec.len() < initial_header_bytes {
        return Err("File Extraction Error: Corrupt segment header.".to_string());
    }

    let single_segment_size = segment_vec
        .len()
        .checked_add(encrypted_size)
        .ok_or_else(|| "File Size Error: Segment output size overflow.".to_string())?;
    let max_single_segment_size =
        SEGMENT_DATA_SIZE + SOI_SIG_LENGTH + SEGMENT_SIG_LENGTH + SEGMENT_HEADER_LENGTH;

    if single_segment_size <= max_single_segment_size {
        // ── Single-segment path ──
        let segment_size = single_segment_size - (SOI_SIG_LENGTH + SEGMENT_SIG_LENGTH);
        let profile_size = segment_size - PROFILE_SIZE_DIFF;
        update_value(segment_vec, SEGMENT_HEADER_SIZE_INDEX, segment_size, 2)?;
        update_value(segment_vec, PROFILE_SIZE_INDEX, profile_size, 2)?;
        update_value(
            segment_vec,
            DEFLATED_DATA_FILE_SIZE_INDEX,
            single_segment_size - PROFILE_DATA_SIZE,
            4,
        )?;

        let write_start = if omit_soi { SOI_SIG_LENGTH } else { 0 };
        out.write(
            &segment_vec[write_start..],
            "Write File Error: Failed to write complete output file.",
        )?;

        // Stream the encrypted file
        let mut ps = PayloadSource::new(&[], encrypted_fd, encrypted_size);
        ps.copy_to(
            out,
            encrypted_size,
            "Read Error: Failed while reading encrypted payload.",
        )?;

        return Ok(SegmentedEmbedSummary {
            embedded_image_size: single_segment_size,
            first_segment_size: segment_size as u16,
            total_segments: 0,
        });
    }

    // ── Multi-segment path ──
    let payload_prefix_size = segment_vec.len() - initial_header_bytes;
    let payload_size = payload_prefix_size
        .checked_add(encrypted_size)
        .ok_or_else(|| "File Size Error: Segment output size overflow.".to_string())?;

    // requiredIccSegments logic
    if payload_size == 0 {
        return Err("File Size Error: Segment count exceeds supported limit.".to_string());
    }
    let segments_required = payload_size.div_ceil(SEGMENT_DATA_SIZE);
    if segments_required == 0 || segments_required > usize::from(u16::MAX) {
        return Err("File Size Error: Segment count exceeds supported limit.".to_string());
    }

    update_value(segment_vec, SEGMENTS_TOTAL_VAL_INDEX, segments_required, 2)?;

    let per_seg_overhead = SEGMENT_SIG_LENGTH + SEGMENT_HEADER_LENGTH;
    let total_header_bytes = segments_required
        .checked_mul(per_seg_overhead)
        .ok_or_else(|| "File Size Error: Segment output size overflow.".to_string())?;
    let icc_data_size = SOI_SIG_LENGTH
        .checked_add(payload_size)
        .and_then(|v| v.checked_add(total_header_bytes))
        .ok_or_else(|| "File Size Error: Segment output size overflow.".to_string())?;
    update_value(
        segment_vec,
        DEFLATED_DATA_FILE_SIZE_INDEX,
        icc_data_size - PROFILE_DATA_SIZE,
        4,
    )?;

    if !omit_soi {
        out.write(
            &segment_vec[..SOI_SIG_LENGTH],
            "Write File Error: Failed to write complete output file.",
        )?;
    }

    // Copy the in-memory prefix bytes (after the initial header) into a local
    // owned vec to avoid aliasing segment_vec while it's also needed for the SOI
    // write above. The prefix is small (a couple hundred bytes) so this is fine.
    let prefix_copy = segment_vec[initial_header_bytes..].to_vec();
    let mut payload_source = PayloadSource::new(&prefix_copy, encrypted_fd, encrypted_size);

    let mut payload_left = payload_size;
    for seg in 1..=segments_required {
        let data_size = payload_left.min(SEGMENT_DATA_SIZE);
        let seg_length = u16::try_from(data_size + SEGMENT_HEADER_LENGTH)
            .map_err(|_| "File Size Error: Segment size overflow.".to_string())?;
        let header = make_icc_header(seg_length, seg);
        out.write(
            &header,
            "Write File Error: Failed to write complete output file.",
        )?;
        payload_source.copy_to(
            out,
            data_size,
            "Read Error: Failed while reading encrypted payload.",
        )?;
        payload_left -= data_size;
    }

    if payload_left != 0 || !payload_source.exhausted() {
        return Err("Read Error: Encrypted payload size mismatch.".to_string());
    }

    let first_segment_data = payload_size.min(SEGMENT_DATA_SIZE);
    Ok(SegmentedEmbedSummary {
        embedded_image_size: icc_data_size,
        first_segment_size: (first_segment_data + SEGMENT_HEADER_LENGTH) as u16,
        total_segments: segments_required as u16,
    })
}

/// Port of C++ writeEmbeddedJpgFromEncryptedFile + writeRedditPaddingToOutput
/// (segmentation.cpp lines 272-310).
pub(crate) fn write_embedded_jpg_from_encrypted_file(
    out: &mut OutputFile,
    segment_vec: &mut [u8],
    encrypted_path: &std::path::Path,
    cover: &[u8],
    has_reddit_option: bool,
) -> Result<SegmentedEmbedSummary, String> {
    let encrypted_size = checked_file_size(
        encrypted_path,
        "Read Error: Invalid encrypted payload size.",
        true,
    )?;

    // Keep the File alive so the fd remains valid for the lifetime of PayloadSource
    let enc_file = open_binary_input_or_throw(
        encrypted_path,
        "Read Error: Failed to open encrypted payload.",
    )?;
    let encrypted_fd = enc_file.as_raw_fd();

    if !has_reddit_option {
        let mut summary =
            write_icc_data_to_output(out, segment_vec, encrypted_fd, encrypted_size, false)?;
        out.write(cover, "Write File Error: Output data too large to write.")?;
        summary.embedded_image_size = summary
            .embedded_image_size
            .checked_add(cover.len())
            .ok_or_else(|| "File Size Error: Embedded image size overflow.".to_string())?;
        return Ok(summary);
    }

    // ── Reddit path ──
    const EOI_SIG_LENGTH: usize = 2;
    if cover.len() < EOI_SIG_LENGTH || segment_vec.len() < SOI_SIG_LENGTH {
        return Err("File Extraction Error: Corrupt image or data segment.".to_string());
    }

    // Write SOI from segment_vec
    out.write(
        &segment_vec[..SOI_SIG_LENGTH],
        "Write File Error: Failed to write complete output file.",
    )?;
    // Write cover except the last 2 bytes (EOI)
    out.write(
        &cover[..cover.len() - EOI_SIG_LENGTH],
        "Write File Error: Output data too large to write.",
    )?;
    // Write reddit padding: 4-byte prefix + MAX_SIZE_REDDIT_PADDING random bytes
    write_reddit_padding_to_output(out)?;
    // Write ICC segments (omit_soi=true since we already wrote SOI)
    let mut summary =
        write_icc_data_to_output(out, segment_vec, encrypted_fd, encrypted_size, true)?;
    // Write cover EOI
    out.write(
        &cover[cover.len() - EOI_SIG_LENGTH..],
        "Write File Error: Output data too large to write.",
    )?;

    let reddit_padding_total = 4 + MAX_SIZE_REDDIT_PADDING;
    summary.embedded_image_size = cover
        .len()
        .checked_add(reddit_padding_total)
        .and_then(|v| v.checked_add(summary.embedded_image_size))
        .ok_or_else(|| "File Size Error: Embedded image size overflow.".to_string())?;
    Ok(summary)
}

fn write_reddit_padding_to_output(out: &mut OutputFile) -> Result<(), String> {
    const WRITE_ERR: &str = "Write File Error: Failed to write complete output file.";
    out.write(&[0xFF, 0xE2, 0x1F, 0x42], WRITE_ERR)?;
    // Generate random padding bytes in ~1 KiB chunks
    let mut remaining = MAX_SIZE_REDDIT_PADDING;
    let mut chunk = [0u8; 1024];
    while remaining > 0 {
        let batch = remaining.min(chunk.len());
        for b in chunk[..batch].iter_mut() {
            *b = PADDING_START + randombytes_uniform(PADDING_RANGE) as u8;
        }
        out.write(&chunk[..batch], WRITE_ERR)?;
        remaining -= batch;
    }
    Ok(())
}


const BSKY_FIRST_MARKER_BYTES_SIZE: usize = 4;
const BSKY_VALUE_BYTE_LENGTH: usize = 4;
const BSKY_EXIF_SEGMENT_DATA_SIZE_LIMIT: usize = 65027;
const BSKY_FIRST_DATASET_SIZE_LIMIT: usize = 32767;
const BSKY_LAST_DATASET_SIZE_LIMIT: usize = 32730;
const BSKY_FIRST_DATASET_SIZE_INDEX: usize = 0x21;
const BSKY_XMP_SEGMENT_SIZE_LIMIT: usize = 60033;
const BSKY_XMP_FOOTER: &[u8] =
    b"</rdf:li></rdf:Seq></dc:creator></rdf:Description></rdf:RDF></x:xmpmeta>\n<?xpacket end=\"w\"?>";
const BSKY_DATASET_MARKER_BASE: [u8; 3] = [0x1C, 0x08, 0x0A];
const BSKY_PSHOP_VEC_DEFAULT_SIZE: usize = 35;
const BSKY_SEGMENT_MARKER_BYTES_SIZE: usize = 2;
const BSKY_SEGMENT_SIZE_INDEX: usize = 0x2;
const BSKY_BIM_SECTION_SIZE_INDEX: usize = 0x1C;
const BSKY_BIM_SECTION_SIZE_DIFF: usize = 28;
const BASE64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

struct BlueskyLayout {
    first_exif_size: usize,
    first_dataset_size: usize,
    second_dataset_size: usize,
    xmp_raw_size: usize,
}

impl BlueskyLayout {
    fn from_encrypted_size(encrypted_size: usize) -> Self {
        let first_exif_size = cmp::min(encrypted_size, BSKY_EXIF_SEGMENT_DATA_SIZE_LIMIT);
        let remaining_after_exif = encrypted_size - first_exif_size;
        let first_dataset_size = cmp::min(BSKY_FIRST_DATASET_SIZE_LIMIT, remaining_after_exif);
        let remaining_after_first = remaining_after_exif - first_dataset_size;
        let second_dataset_size = cmp::min(BSKY_LAST_DATASET_SIZE_LIMIT, remaining_after_first);
        let xmp_raw_size = remaining_after_first - second_dataset_size;
        Self {
            first_exif_size,
            first_dataset_size,
            second_dataset_size,
            xmp_raw_size,
        }
    }

    fn has_xmp_segment(&self) -> bool {
        self.xmp_raw_size > 0
    }

    fn has_pshop_segment(&self) -> bool {
        self.first_dataset_size > 0 || self.second_dataset_size > 0
    }
}

fn encode_base64_triplet(a: u8, b: u8, c: u8, out: &mut Vec<u8>) {
    out.push(BASE64_TABLE[(a >> 2) as usize]);
    out.push(BASE64_TABLE[(((a & 0x03) << 4) | (b >> 4)) as usize]);
    out.push(BASE64_TABLE[(((b & 0x0F) << 2) | (c >> 6)) as usize]);
    out.push(BASE64_TABLE[(c & 0x3F) as usize]);
}

fn binary_to_base64_append_streaming(
    input: &[u8],
    out: &mut Vec<u8>,
    carry: &mut [u8; 3],
    carry_len: &mut usize,
) {
    let mut idx = 0usize;

    if *carry_len > 0 {
        while *carry_len < 3 && idx < input.len() {
            carry[*carry_len] = input[idx];
            *carry_len += 1;
            idx += 1;
        }
        if *carry_len == 3 {
            encode_base64_triplet(carry[0], carry[1], carry[2], out);
            *carry_len = 0;
        }
    }

    while idx + 3 <= input.len() {
        encode_base64_triplet(input[idx], input[idx + 1], input[idx + 2], out);
        idx += 3;
    }

    let rem = input.len() - idx;
    if rem > 0 {
        carry[..rem].copy_from_slice(&input[idx..]);
        *carry_len = rem;
    }
}

fn binary_to_base64_finalize(out: &mut Vec<u8>, carry: &[u8; 3], carry_len: usize) {
    if carry_len == 1 {
        let a = carry[0];
        out.push(BASE64_TABLE[(a >> 2) as usize]);
        out.push(BASE64_TABLE[((a & 0x03) << 4) as usize]);
        out.push(b'=');
        out.push(b'=');
    } else if carry_len == 2 {
        let a = carry[0];
        let b = carry[1];
        out.push(BASE64_TABLE[(a >> 2) as usize]);
        out.push(BASE64_TABLE[(((a & 0x03) << 4) | (b >> 4)) as usize]);
        out.push(BASE64_TABLE[((b & 0x0F) << 2) as usize]);
        out.push(b'=');
    }
}

pub(crate) struct BlueskySegmentStreamBuilder<'a> {
    segment_vec: &'a mut Vec<u8>,
    layout: BlueskyLayout,
    encrypted_size: usize,
    encrypted_written: usize,
    first_dataset_written: usize,
    second_dataset_written: usize,
    xmp_raw_written: usize,
    exif_insert: Vec<u8>,
    pshop_vec: Vec<u8>,
    xmp_vec: Vec<u8>,
    xmp_carry: [u8; 3],
    xmp_carry_len: usize,
    second_marker_added: bool,
}

impl<'a> BlueskySegmentStreamBuilder<'a> {
    pub(crate) fn new(segment_vec: &'a mut Vec<u8>, encrypted_size: usize) -> Result<Self, String> {
        if segment_vec.len() < BSKY_FIRST_MARKER_BYTES_SIZE
            || BLUESKY_EXIF_SEGMENT_DATA_INSERT_INDEX > segment_vec.len()
        {
            return Err("Internal Error: Corrupt Bluesky segment template.".to_string());
        }
        if !span_has_range(
            segment_vec.len(),
            BLUESKY_COMPRESSED_FILE_SIZE_INDEX,
            BSKY_VALUE_BYTE_LENGTH,
        ) || !span_has_range(segment_vec.len(), BLUESKY_EXIF_SEGMENT_SIZE_INDEX, 2)
            || !span_has_range(
                segment_vec.len(),
                BLUESKY_ARTIST_FIELD_SIZE_INDEX,
                BSKY_VALUE_BYTE_LENGTH,
            )
        {
            return Err("Internal Error: Corrupt Bluesky metadata index.".to_string());
        }

        let segment_vec_data_size = segment_vec.len() - BSKY_FIRST_MARKER_BYTES_SIZE;
        let first_exif_size = cmp::min(encrypted_size, BSKY_EXIF_SEGMENT_DATA_SIZE_LIMIT);
        let exif_segment_data_size = first_exif_size + segment_vec_data_size;
        let artist_field_size = exif_segment_data_size - BLUESKY_ARTIST_FIELD_SIZE_DIFF;

        update_value(
            segment_vec,
            BLUESKY_COMPRESSED_FILE_SIZE_INDEX,
            encrypted_size,
            BSKY_VALUE_BYTE_LENGTH,
        )?;

        if encrypted_size <= BSKY_EXIF_SEGMENT_DATA_SIZE_LIMIT {
            update_value(
                segment_vec,
                BLUESKY_ARTIST_FIELD_SIZE_INDEX,
                artist_field_size,
                BSKY_VALUE_BYTE_LENGTH,
            )?;
            update_value(
                segment_vec,
                BLUESKY_EXIF_SEGMENT_SIZE_INDEX,
                exif_segment_data_size,
                2,
            )?;
        }

        let layout = BlueskyLayout::from_encrypted_size(encrypted_size);

        let mut pshop_vec = PHOTOSHOP_SEGMENT_TEMPLATE.to_vec();
        if layout.first_dataset_size < BSKY_FIRST_DATASET_SIZE_LIMIT {
            update_value(
                &mut pshop_vec,
                BSKY_FIRST_DATASET_SIZE_INDEX,
                layout.first_dataset_size,
                2,
            )?;
        }
        let pshop_dynamic_capacity = layout.first_dataset_size
            + if layout.second_dataset_size > 0 {
                BSKY_DATASET_MARKER_BASE.len() + 2 + layout.second_dataset_size
            } else {
                0
            };
        pshop_vec.reserve(pshop_dynamic_capacity);

        let mut xmp_vec = XMP_SEGMENT_TEMPLATE.to_vec();
        if layout.has_xmp_segment() {
            let base64_size = layout.xmp_raw_size.div_ceil(3) * 4;
            let projected_xmp_len = xmp_vec
                .len()
                .checked_add(base64_size)
                .and_then(|v| v.checked_add(BSKY_XMP_FOOTER.len()))
                .ok_or_else(|| {
                    "File Size Error: Data file exceeds segment size limit for Bluesky.".to_string()
                })?;
            if projected_xmp_len > BSKY_XMP_SEGMENT_SIZE_LIMIT {
                return Err(
                    "File Size Error: Data file exceeds segment size limit for Bluesky."
                        .to_string(),
                );
            }
            xmp_vec.reserve(base64_size + BSKY_XMP_FOOTER.len());
        }

        Ok(Self {
            segment_vec,
            layout,
            encrypted_size,
            encrypted_written: 0,
            first_dataset_written: 0,
            second_dataset_written: 0,
            xmp_raw_written: 0,
            exif_insert: Vec::with_capacity(first_exif_size),
            pshop_vec,
            xmp_vec,
            xmp_carry: [0u8; 3],
            xmp_carry_len: 0,
            second_marker_added: false,
        })
    }

    fn add_second_dataset_marker_if_needed(&mut self) {
        if self.layout.second_dataset_size > 0 && !self.second_marker_added {
            self.pshop_vec.extend_from_slice(&BSKY_DATASET_MARKER_BASE);
            self.pshop_vec
                .push(((self.layout.second_dataset_size >> 8) & 0xFF) as u8);
            self.pshop_vec
                .push((self.layout.second_dataset_size & 0xFF) as u8);
            self.second_marker_added = true;
        }
    }

    pub(crate) fn push(&mut self, mut input: &[u8]) -> Result<(), String> {
        while !input.is_empty() {
            if self.encrypted_written >= self.encrypted_size {
                return Err("Internal Error: Corrupt Bluesky payload stream.".to_string());
            }

            let consumed = if self.exif_insert.len() < self.layout.first_exif_size {
                let take = cmp::min(
                    input.len(),
                    self.layout.first_exif_size - self.exif_insert.len(),
                );
                self.exif_insert.extend_from_slice(&input[..take]);
                take
            } else if self.first_dataset_written < self.layout.first_dataset_size {
                let take = cmp::min(
                    input.len(),
                    self.layout.first_dataset_size - self.first_dataset_written,
                );
                self.pshop_vec.extend_from_slice(&input[..take]);
                self.first_dataset_written += take;
                if self.first_dataset_written == self.layout.first_dataset_size {
                    self.add_second_dataset_marker_if_needed();
                }
                take
            } else if self.second_dataset_written < self.layout.second_dataset_size {
                self.add_second_dataset_marker_if_needed();
                let take = cmp::min(
                    input.len(),
                    self.layout.second_dataset_size - self.second_dataset_written,
                );
                self.pshop_vec.extend_from_slice(&input[..take]);
                self.second_dataset_written += take;
                take
            } else {
                let remaining_xmp = self
                    .layout
                    .xmp_raw_size
                    .saturating_sub(self.xmp_raw_written);
                if remaining_xmp == 0 {
                    return Err("Internal Error: Corrupt Bluesky payload stream.".to_string());
                }
                let take = cmp::min(input.len(), remaining_xmp);
                binary_to_base64_append_streaming(
                    &input[..take],
                    &mut self.xmp_vec,
                    &mut self.xmp_carry,
                    &mut self.xmp_carry_len,
                );
                self.xmp_raw_written += take;
                take
            };

            self.encrypted_written += consumed;
            input = &input[consumed..];
        }
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<(), String> {
        if self.encrypted_written != self.encrypted_size {
            return Err("Internal Error: Corrupt Bluesky payload stream.".to_string());
        }
        if self.first_dataset_written != self.layout.first_dataset_size
            || self.second_dataset_written != self.layout.second_dataset_size
            || self.xmp_raw_written != self.layout.xmp_raw_size
            || self.exif_insert.len() != self.layout.first_exif_size
        {
            return Err("Internal Error: Corrupt Bluesky payload stream.".to_string());
        }

        if self.layout.has_xmp_segment() {
            binary_to_base64_finalize(&mut self.xmp_vec, &self.xmp_carry, self.xmp_carry_len);
            self.xmp_vec.extend_from_slice(BSKY_XMP_FOOTER);

            if self.xmp_vec.len() > BSKY_XMP_SEGMENT_SIZE_LIMIT {
                return Err(
                    "File Size Error: Data file exceeds segment size limit for Bluesky."
                        .to_string(),
                );
            }

            let xmp_segment_data_size = self.xmp_vec.len() - BSKY_SEGMENT_MARKER_BYTES_SIZE;
            update_value(
                &mut self.xmp_vec,
                BSKY_SEGMENT_SIZE_INDEX,
                xmp_segment_data_size,
                2,
            )?;
            self.segment_vec.extend_from_slice(&self.xmp_vec);
        }

        if self.layout.has_pshop_segment() && self.pshop_vec.len() > BSKY_PSHOP_VEC_DEFAULT_SIZE {
            let pshop_segment_data_size = self.pshop_vec.len() - BSKY_SEGMENT_MARKER_BYTES_SIZE;
            if !self.layout.has_xmp_segment() {
                let bim_section_size = pshop_segment_data_size - BSKY_BIM_SECTION_SIZE_DIFF;
                update_value(
                    &mut self.pshop_vec,
                    BSKY_SEGMENT_SIZE_INDEX,
                    pshop_segment_data_size,
                    2,
                )?;
                update_value(
                    &mut self.pshop_vec,
                    BSKY_BIM_SECTION_SIZE_INDEX,
                    bim_section_size,
                    2,
                )?;
            }
            self.segment_vec.extend_from_slice(&self.pshop_vec);
        }

        self.segment_vec.splice(
            BLUESKY_EXIF_SEGMENT_DATA_INSERT_INDEX..BLUESKY_EXIF_SEGMENT_DATA_INSERT_INDEX,
            self.exif_insert,
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_template_uses_canonical_icc_bytes() {
        let template = make_default_segment_template().expect("default template should build");
        assert_eq!(template.len(), DEFAULT_ICC_TEMPLATE.len());
        assert_eq!(template, DEFAULT_ICC_TEMPLATE);

        // Guard against zero-filled placeholder regressions in ICC profile payload.
        assert_eq!(&template[56..60], b"acsp");
    }
}
