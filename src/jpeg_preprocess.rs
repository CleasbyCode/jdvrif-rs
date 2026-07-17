use crate::common::open_binary_input_or_throw;
use crate::signal::check_cancellation;
use libc::{self, c_void};
use std::cmp;
use std::ffi::CStr;
use std::io::Read;
use std::path::Path;

const PROGRESSIVE_SOURCE_LIMIT: usize = 2 * 1024 * 1024;
const MAX_OPTIMIZED_IMAGE_SIZE: usize = 4 * 1024 * 1024;
const MAX_OPTIMIZED_BLUESKY_IMG: usize = 805 * 1024;
const EXIF_SEARCH_LIMIT: usize = 4096;
const EXIF_HEADER_SIZE: usize = 6;
const TIFF_HEADER_SIZE: usize = 8;
const IFD_ENTRY_SIZE: usize = 12;
const DQT_SEARCH_LIMIT: usize = 32768;
const DQT_8BIT_TABLE_SIZE: usize = 64;
const DQT_16BIT_TABLE_SIZE: usize = 128;
const MIN_COVER_DIMENSION: i32 = 400;
const MAX_COVER_DIMENSION: i32 = 16_384;
const MAX_COVER_PIXELS: u64 = 40_000_000;
const MAX_ALLOWED_QUALITY: i32 = 97;
const TAG_ORIENTATION: u16 = 0x0112;
const EXIF_SIG: [u8; 6] = [b'E', b'x', b'i', b'f', 0x00, 0x00];

const STD_LUMINANCE_SUMS: [i32; 101] = [
    0, 16320, 16315, 15946, 15277, 14655, 14073, 13623, 13230, 12859, 12560, 12240, 11861, 11456,
    11081, 10714, 10360, 10027, 9679, 9368, 9056, 8680, 8331, 7995, 7668, 7376, 7084, 6823, 6562,
    6345, 6125, 5939, 5756, 5571, 5421, 5240, 5086, 4976, 4829, 4719, 4616, 4463, 4393, 4280, 4166,
    4092, 3980, 3909, 3835, 3755, 3688, 3621, 3541, 3467, 3396, 3323, 3247, 3170, 3096, 3021, 2952,
    2874, 2804, 2727, 2657, 2583, 2509, 2437, 2362, 2290, 2211, 2136, 2068, 1996, 1915, 1858, 1773,
    1692, 1620, 1552, 1477, 1398, 1326, 1251, 1179, 1109, 1031, 961, 884, 814, 736, 667, 592, 518,
    441, 369, 292, 221, 151, 86, 64,
];

const TJXOP_NONE: i32 = 0;
const TJXOP_HFLIP: i32 = 1;
const TJXOP_VFLIP: i32 = 2;
const TJXOP_TRANSPOSE: i32 = 3;
const TJXOP_TRANSVERSE: i32 = 4;
const TJXOP_ROT90: i32 = 5;
const TJXOP_ROT180: i32 = 6;
const TJXOP_ROT270: i32 = 7;
const TJXOPT_TRIM: i32 = 2;
const TJXOPT_PROGRESSIVE: i32 = 32;
const TJXOPT_COPYNONE: i32 = 64;

#[repr(C)]
#[derive(Clone, Copy)]
struct TjRegion {
    x: i32,
    y: i32,
    w: i32,
    h: i32,
}

type TjCustomFilter = Option<
    unsafe extern "C" fn(
        coeffs: *mut i16,
        array_region: TjRegion,
        plane_region: TjRegion,
        component_index: i32,
        transform_index: i32,
        transform: *mut TjTransform,
    ) -> i32,
>;

#[repr(C)]
#[derive(Clone, Copy)]
struct TjTransform {
    r: TjRegion,
    op: i32,
    options: i32,
    data: *mut c_void,
    custom_filter: TjCustomFilter,
}

#[link(name = "turbojpeg")]
unsafe extern "C" {
    fn tjInitTransform() -> *mut c_void;
    fn tjTransform(
        handle: *mut c_void,
        jpeg_buf: *const u8,
        jpeg_size: libc::c_ulong,
        n: i32,
        dst_bufs: *mut *mut u8,
        dst_sizes: *mut libc::c_ulong,
        transforms: *mut TjTransform,
        flags: i32,
    ) -> i32;
    fn tjDestroy(handle: *mut c_void) -> i32;
    fn tjFree(buffer: *mut u8);
    fn tjGetErrorStr2(handle: *mut c_void) -> *mut libc::c_char;
}

struct TurboJpegHandle {
    raw: *mut c_void,
}

impl TurboJpegHandle {
    fn new_transformer() -> Result<Self, String> {
        // SAFETY: tjInitTransform has no preconditions.
        let raw = unsafe { tjInitTransform() };
        if raw.is_null() {
            return Err("tjInitTransform() failed".to_string());
        }
        Ok(Self { raw })
    }

    fn as_ptr(&self) -> *mut c_void {
        self.raw
    }
}

impl Drop for TurboJpegHandle {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // SAFETY: handle was returned by tjInitTransform and is dropped once.
            let _ = unsafe { tjDestroy(self.raw) };
            self.raw = std::ptr::null_mut();
        }
    }
}

struct TurboJpegBuffer {
    raw: *mut u8,
}

impl Drop for TurboJpegBuffer {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // SAFETY: buffer was allocated by TurboJPEG and must be released with tjFree.
            unsafe { tjFree(self.raw) };
            self.raw = std::ptr::null_mut();
        }
    }
}

fn span_has_range(data_len: usize, index: usize, length: usize) -> bool {
    index <= data_len && length <= data_len.saturating_sub(index)
}

fn marker_has_no_length(marker: u8) -> bool {
    marker == 0x01 || marker == 0xD8 || marker == 0xD9 || (0xD0..=0xD7).contains(&marker)
}

fn is_sof_marker(marker: u8) -> bool {
    (0xC0..=0xCF).contains(&marker) && marker != 0xC4 && marker != 0xC8 && marker != 0xCC
}

fn jpeg_segment_end_from_length_offset(jpg: &[u8], length_offset: usize) -> Option<usize> {
    if !span_has_range(jpg.len(), length_offset, 2) {
        return None;
    }

    let segment_length = usize::from(u16::from_be_bytes([
        jpg[length_offset],
        jpg[length_offset + 1],
    ]));
    if segment_length < 2 || !span_has_range(jpg.len(), length_offset, segment_length) {
        return None;
    }
    Some(length_offset + segment_length)
}

fn turbojpeg_error_string(handle: *mut c_void) -> String {
    // SAFETY: returned pointer is managed by TurboJPEG and valid for immediate conversion.
    let ptr = unsafe { tjGetErrorStr2(handle) };
    if ptr.is_null() {
        return "Unknown TurboJPEG error.".to_string();
    }
    // SAFETY: TurboJPEG returns a NUL-terminated error string.
    unsafe { CStr::from_ptr(ptr.cast::<libc::c_char>()) }
        .to_string_lossy()
        .into_owned()
}

fn read_tiff_u16(tiff: &[u8], offset: usize, little_endian: bool) -> Option<u16> {
    if !span_has_range(tiff.len(), offset, 2) {
        return None;
    }
    let raw = [tiff[offset], tiff[offset + 1]];
    Some(if little_endian {
        u16::from_le_bytes(raw)
    } else {
        u16::from_be_bytes(raw)
    })
}

fn read_tiff_u32(tiff: &[u8], offset: usize, little_endian: bool) -> Option<u32> {
    if !span_has_range(tiff.len(), offset, 4) {
        return None;
    }
    let raw = [
        tiff[offset],
        tiff[offset + 1],
        tiff[offset + 2],
        tiff[offset + 3],
    ];
    Some(if little_endian {
        u32::from_le_bytes(raw)
    } else {
        u32::from_be_bytes(raw)
    })
}

fn exif_orientation_from_tiff(tiff: &[u8]) -> Option<u16> {
    if tiff.len() < TIFF_HEADER_SIZE {
        return None;
    }

    let little_endian = match (tiff[0], tiff[1]) {
        (b'I', b'I') => true,
        (b'M', b'M') => false,
        _ => return None,
    };

    let magic = read_tiff_u16(tiff, 2, little_endian)?;
    if magic != 0x002A {
        return None;
    }

    let ifd_offset = usize::try_from(read_tiff_u32(tiff, 4, little_endian)?).ok()?;
    if !span_has_range(tiff.len(), ifd_offset, 2) {
        return None;
    }

    let entry_count = read_tiff_u16(tiff, ifd_offset, little_endian)?;
    let mut entry_pos = ifd_offset + 2;
    for _ in 0..entry_count {
        if !span_has_range(tiff.len(), entry_pos, IFD_ENTRY_SIZE) {
            return None;
        }
        let tag_id = read_tiff_u16(tiff, entry_pos, little_endian)?;
        if tag_id == TAG_ORIENTATION {
            return read_tiff_u16(tiff, entry_pos + 8, little_endian);
        }
        entry_pos += IFD_ENTRY_SIZE;
    }
    None
}

#[derive(Default)]
struct JpegPrescan {
    width: i32,
    height: i32,
    components: i32,
    orientation: Option<u16>,
}

fn jpeg_prescan(jpg: &[u8]) -> Option<JpegPrescan> {
    if jpg.len() < 4 || jpg[0] != 0xFF || jpg[1] != 0xD8 {
        return None;
    }

    let mut out = JpegPrescan::default();
    let mut pos = 2usize;
    let exif_limit = cmp::min(jpg.len(), EXIF_SEARCH_LIMIT);

    while span_has_range(jpg.len(), pos, 4) {
        while pos < jpg.len() && jpg[pos] == 0xFF {
            pos += 1;
        }
        if pos >= jpg.len() {
            break;
        }

        let marker = jpg[pos];
        pos += 1;
        if marker == 0x00 || marker_has_no_length(marker) {
            continue;
        }
        if marker == 0xDA {
            break;
        }

        let end = jpeg_segment_end_from_length_offset(jpg, pos)?;
        let payload_offset = pos + 2;
        let payload_size = end - payload_offset;

        if is_sof_marker(marker) && payload_size >= 6 && out.width == 0 {
            let components = usize::from(jpg[payload_offset + 5]);
            if components == 0 || components > (payload_size - 6) / 3 {
                return None;
            }

            out.height = i32::from(u16::from_be_bytes([
                jpg[payload_offset + 1],
                jpg[payload_offset + 2],
            ]));
            out.width = i32::from(u16::from_be_bytes([
                jpg[payload_offset + 3],
                jpg[payload_offset + 4],
            ]));
            out.components = components as i32;
        } else if marker == 0xE1
            && pos <= exif_limit
            && payload_size >= EXIF_HEADER_SIZE
            && jpg[payload_offset..payload_offset + EXIF_HEADER_SIZE] == EXIF_SIG
        {
            out.orientation =
                exif_orientation_from_tiff(&jpg[payload_offset + EXIF_HEADER_SIZE..end]);
        }

        if out.width != 0 && out.orientation.is_some() {
            break;
        }
        pos = end;
    }

    Some(out)
}

fn get_transform_op(orientation: u16) -> i32 {
    match orientation {
        2 => TJXOP_HFLIP,
        3 => TJXOP_ROT180,
        4 => TJXOP_VFLIP,
        5 => TJXOP_TRANSPOSE,
        6 => TJXOP_ROT90,
        7 => TJXOP_TRANSVERSE,
        8 => TJXOP_ROT270,
        _ => TJXOP_NONE,
    }
}

fn quality_from_luminance_sum(sum: i32) -> i32 {
    if sum <= 64 {
        return 100;
    }
    if sum >= 16320 {
        return 1;
    }

    for q in 1..STD_LUMINANCE_SUMS.len() {
        if sum >= STD_LUMINANCE_SUMS[q] {
            if q > 1 {
                let diff_current = sum - STD_LUMINANCE_SUMS[q];
                let diff_prev = STD_LUMINANCE_SUMS[q - 1] - sum;
                if diff_prev < diff_current {
                    return (q - 1) as i32;
                }
            }
            return q as i32;
        }
    }
    100
}

#[derive(Default)]
struct TransformedJpegInfo {
    offset: usize,
    width: i32,
    height: i32,
    quality: Option<i32>,
}

fn inspect_transformed_jpeg(jpg: &[u8]) -> TransformedJpegInfo {
    if jpg.len() < 4 || jpg[0] != 0xFF || jpg[1] != 0xD8 {
        return TransformedJpegInfo::default();
    }

    let mut out = TransformedJpegInfo::default();
    let mut table_qualities = [None; 4];
    let mut primary_table_id = None;
    let mut pos = 2usize;

    while span_has_range(jpg.len(), pos, 2) {
        while pos < jpg.len() && jpg[pos] == 0xFF {
            pos += 1;
        }
        if pos >= jpg.len() {
            break;
        }

        let marker = jpg[pos];
        pos += 1;
        let marker_offset = pos - 2;
        if marker == 0x00 || marker_has_no_length(marker) {
            continue;
        }
        if marker == 0xDA {
            break;
        }

        let Some(end) = jpeg_segment_end_from_length_offset(jpg, pos) else {
            return TransformedJpegInfo::default();
        };
        let payload_offset = pos + 2;
        let payload_size = end - payload_offset;

        if marker == 0xDB {
            if out.offset == 0 && marker_offset <= DQT_SEARCH_LIMIT - 2 {
                out.offset = marker_offset;
            }

            let mut table_pos = payload_offset;
            while table_pos < end {
                let header = jpg[table_pos];
                table_pos += 1;
                let precision = (header >> 4) & 0x0F;
                let table_id = usize::from(header & 0x0F);
                if precision > 1 || table_id >= table_qualities.len() {
                    return TransformedJpegInfo::default();
                }

                let table_size = if precision == 0 {
                    DQT_8BIT_TABLE_SIZE
                } else {
                    DQT_16BIT_TABLE_SIZE
                };
                if !span_has_range(jpg.len(), table_pos, table_size) || table_size > end - table_pos
                {
                    return TransformedJpegInfo::default();
                }

                let sum = if precision == 0 {
                    jpg[table_pos..table_pos + DQT_8BIT_TABLE_SIZE]
                        .iter()
                        .map(|&b| i32::from(b))
                        .sum()
                } else {
                    (0..64usize)
                        .map(|i| {
                            (i32::from(jpg[table_pos + i * 2]) << 8)
                                | i32::from(jpg[table_pos + i * 2 + 1])
                        })
                        .sum()
                };
                table_qualities[table_id] = Some(quality_from_luminance_sum(sum));
                table_pos += table_size;
            }
        } else if is_sof_marker(marker) {
            if payload_size < 9 {
                return TransformedJpegInfo::default();
            }
            let components = usize::from(jpg[payload_offset + 5]);
            if components == 0 || components > (payload_size - 6) / 3 {
                return TransformedJpegInfo::default();
            }

            out.height = i32::from(u16::from_be_bytes([
                jpg[payload_offset + 1],
                jpg[payload_offset + 2],
            ]));
            out.width = i32::from(u16::from_be_bytes([
                jpg[payload_offset + 3],
                jpg[payload_offset + 4],
            ]));
            primary_table_id = Some(usize::from(jpg[payload_offset + 8]));
        }

        pos = end;
    }

    if let Some(table_id) = primary_table_id {
        if table_id < table_qualities.len() {
            out.quality = table_qualities[table_id];
        }
    }
    out
}

fn optimize_image_with_turbojpeg(
    jpg_vec: &mut Vec<u8>,
    is_progressive: bool,
) -> Result<(), String> {
    check_cancellation()?;
    if jpg_vec.is_empty() {
        return Err("JPG image is empty!".to_string());
    }

    let prescan = jpeg_prescan(jpg_vec)
        .filter(|scan| scan.width != 0 && scan.height != 0)
        .ok_or_else(|| "Image Error: Failed to parse JPEG header.".to_string())?;

    if prescan.width < MIN_COVER_DIMENSION || prescan.height < MIN_COVER_DIMENSION {
        return Err(format!(
            "Image Error: Dimensions {}x{} are too small.\nFor platform compatibility, cover image must be at least {}px for both width and height.",
            prescan.width, prescan.height, MIN_COVER_DIMENSION
        ));
    }

    let pixel_count = u64::try_from(prescan.width)
        .unwrap_or(u64::MAX)
        .saturating_mul(u64::try_from(prescan.height).unwrap_or(u64::MAX));
    if prescan.width > MAX_COVER_DIMENSION
        || prescan.height > MAX_COVER_DIMENSION
        || pixel_count > MAX_COVER_PIXELS
    {
        return Err(format!(
            "Image Error: Dimensions {}x{} exceed the safe cover-image limit ({}px per dimension and {} total pixels).",
            prescan.width,
            prescan.height,
            MAX_COVER_DIMENSION,
            MAX_COVER_PIXELS
        ));
    }

    if prescan.components != 1 && prescan.components != 3 {
        return Err(format!(
            "Image Error: Unsupported JPEG color space ({} components). CMYK/YCCK cover images must be converted to RGB before use.",
            prescan.components
        ));
    }

    let transformer = TurboJpegHandle::new_transformer()?;
    let transformer_raw = transformer.as_ptr();
    let jpeg_size = libc::c_ulong::try_from(jpg_vec.len())
        .map_err(|_| "Image Error: Input JPEG too large.".to_string())?;

    let xop = prescan
        .orientation
        .map(get_transform_op)
        .unwrap_or(TJXOP_NONE);

    let mut xform = TjTransform {
        r: TjRegion {
            x: 0,
            y: 0,
            w: 0,
            h: 0,
        },
        op: xop,
        options: TJXOPT_COPYNONE
            | TJXOPT_TRIM
            | if is_progressive {
                TJXOPT_PROGRESSIVE
            } else {
                0
            },
        data: std::ptr::null_mut(),
        custom_filter: None,
    };

    let mut dst_buf: *mut u8 = std::ptr::null_mut();
    let mut dst_size: libc::c_ulong = 0;

    // SAFETY: dst buffer pointers and transform struct are valid for the call lifetime.
    let transform_rc = unsafe {
        tjTransform(
            transformer_raw,
            jpg_vec.as_ptr(),
            jpeg_size,
            1,
            &mut dst_buf,
            &mut dst_size,
            &mut xform,
            0,
        )
    };
    let dst_guard = TurboJpegBuffer { raw: dst_buf };
    if transform_rc != 0 {
        return Err(format!(
            "tjTransform: {}",
            turbojpeg_error_string(transformer_raw)
        ));
    }
    check_cancellation()?;
    if dst_guard.raw.is_null() {
        return Err("tjTransform: produced an empty output buffer.".to_string());
    }

    let dst_len = usize::try_from(dst_size)
        .map_err(|_| "Image Error: Transformed JPEG size overflow.".to_string())?;
    // SAFETY: dst_guard owns a valid TurboJPEG-allocated buffer of dst_len bytes.
    let result = unsafe { std::slice::from_raw_parts(dst_guard.raw, dst_len) };
    let transformed = inspect_transformed_jpeg(result);
    if transformed.width == 0 || transformed.height == 0 {
        return Err("Image Error: Failed to parse transformed JPEG header.".to_string());
    }
    if transformed.width < MIN_COVER_DIMENSION || transformed.height < MIN_COVER_DIMENSION {
        return Err(format!(
            "Image Error: Lossless orientation/MCU trimming reduced dimensions to {}x{}. Cover image must remain at least {}px for both width and height.",
            transformed.width, transformed.height, MIN_COVER_DIMENSION
        ));
    }

    let estimated_quality = transformed.quality.ok_or_else(|| {
        "Image File Error: Quantization table referenced by JPEG components was not found (corrupt or unsupported JPG).".to_string()
    })?;
    if estimated_quality > MAX_ALLOWED_QUALITY {
        return Err(format!(
            "Image Error: Estimated quality {} exceeds maximum ({}).\nFor platform compatibility, cover image quality must be {} or lower.",
            estimated_quality, MAX_ALLOWED_QUALITY, MAX_ALLOWED_QUALITY
        ));
    }
    if transformed.offset == 0 || transformed.offset >= dst_len {
        return Err(
            "Image File Error: No DQT segment found (corrupt or unsupported JPG).".to_string(),
        );
    }

    jpg_vec.clear();
    jpg_vec.extend_from_slice(&result[transformed.offset..]);
    Ok(())
}

pub fn prepare_cover_image_for_conceal(
    image_file_path: &Path,
    expected_image_size: usize,
    source_data_size: usize,
    has_no_option: bool,
    has_bluesky_option: bool,
) -> Result<Vec<u8>, String> {
    let mut input = open_binary_input_or_throw(
        image_file_path,
        &format!("Failed to open file: {}", image_file_path.display()),
    )?;
    let mut jpg_vec = vec![0u8; expected_image_size];
    input
        .read_exact(&mut jpg_vec)
        .map_err(|_| "Read Error: Cover image changed while reading.".to_string())?;
    let mut trailing = [0u8; 1];
    if input
        .read(&mut trailing)
        .map_err(|_| "Read Error: Cover image changed while reading.".to_string())?
        != 0
    {
        return Err("Read Error: Cover image changed while reading.".to_string());
    }

    let is_progressive = source_data_size < PROGRESSIVE_SOURCE_LIMIT && has_no_option;
    optimize_image_with_turbojpeg(&mut jpg_vec, is_progressive)?;

    if jpg_vec.len() > MAX_OPTIMIZED_IMAGE_SIZE {
        return Err("Image File Error: Cover image file exceeds maximum size limit.".to_string());
    }

    if has_bluesky_option && jpg_vec.len() > MAX_OPTIMIZED_BLUESKY_IMG {
        return Err(
            "File Size Error: Image file exceeds maximum size limit for the Bluesky platform."
                .to_string(),
        );
    }

    Ok(jpg_vec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn append_segment(jpg: &mut Vec<u8>, marker: u8, payload: &[u8]) {
        let length = u16::try_from(payload.len() + 2).expect("test segment fits");
        jpg.extend_from_slice(&[0xFF, marker]);
        jpg.extend_from_slice(&length.to_be_bytes());
        jpg.extend_from_slice(payload);
    }

    fn sof_payload(width: u16, height: u16, first_table_id: u8) -> Vec<u8> {
        let mut payload = vec![
            8,
            (height >> 8) as u8,
            height as u8,
            (width >> 8) as u8,
            width as u8,
            3,
        ];
        payload.extend_from_slice(&[1, 0x22, first_table_id]);
        payload.extend_from_slice(&[2, 0x11, 1]);
        payload.extend_from_slice(&[3, 0x11, 1]);
        payload
    }

    #[test]
    fn prescan_walks_markers_and_finds_later_exif_segment() {
        let mut jpg = vec![0xFF, 0xD8];
        append_segment(&mut jpg, 0xE1, b"not Exif metadata");

        let mut exif = EXIF_SIG.to_vec();
        exif.extend_from_slice(&[
            b'I', b'I', 0x2A, 0x00, 0x08, 0x00, 0x00, 0x00, // TIFF header
            0x01, 0x00, // one IFD entry
            0x12, 0x01, // orientation tag
            0x03, 0x00, // SHORT
            0x01, 0x00, 0x00, 0x00, // count = 1
            0x06, 0x00, 0x00, 0x00, // orientation = 6
        ]);
        append_segment(&mut jpg, 0xE1, &exif);
        append_segment(&mut jpg, 0xC0, &sof_payload(600, 500, 0));

        let scan = jpeg_prescan(&jpg).expect("valid header walk");
        assert_eq!(scan.width, 600);
        assert_eq!(scan.height, 500);
        assert_eq!(scan.components, 3);
        assert_eq!(scan.orientation, Some(6));
    }

    #[test]
    fn transformed_inspection_uses_sof_selected_quantization_table() {
        let mut jpg = vec![0xFF, 0xD8];
        let mut app_payload = vec![0u8; 200];
        // A raw signature search would mistake this decoy for the DQT marker.
        app_payload[40..44].copy_from_slice(&[0xFF, 0xDB, 0x00, 0x43]);
        append_segment(&mut jpg, 0xE0, &app_payload);

        let expected_dqt_offset = jpg.len();
        let mut dqt_payload = vec![0];
        dqt_payload.extend_from_slice(&[1; DQT_8BIT_TABLE_SIZE]);
        dqt_payload.push(1);
        dqt_payload.extend_from_slice(&[255; DQT_8BIT_TABLE_SIZE]);
        append_segment(&mut jpg, 0xDB, &dqt_payload);
        append_segment(&mut jpg, 0xC0, &sof_payload(800, 600, 1));

        let info = inspect_transformed_jpeg(&jpg);
        assert_eq!(info.offset, expected_dqt_offset);
        assert_eq!(info.width, 800);
        assert_eq!(info.height, 600);
        assert_eq!(info.quality, Some(1));
    }

    #[test]
    fn transformed_inspection_rejects_missing_selected_table() {
        let mut jpg = vec![0xFF, 0xD8];
        let mut dqt_payload = vec![0];
        dqt_payload.extend_from_slice(&[32; DQT_8BIT_TABLE_SIZE]);
        append_segment(&mut jpg, 0xDB, &dqt_payload);
        append_segment(&mut jpg, 0xC0, &sof_payload(800, 600, 1));

        let info = inspect_transformed_jpeg(&jpg);
        assert!(info.quality.is_none());
    }

    #[test]
    fn cover_read_rejects_growth_beyond_validated_size() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "jdvrif_cover_growth_{}_{}.jpg",
            std::process::id(),
            nonce
        ));
        std::fs::write(&path, b"validated-plus-growth").expect("write cover");

        let err = prepare_cover_image_for_conceal(&path, 9, 1, true, false)
            .expect_err("growth must be rejected before JPEG parsing");
        assert!(err.contains("changed while reading"));

        let _ = std::fs::remove_file(path);
    }
}
