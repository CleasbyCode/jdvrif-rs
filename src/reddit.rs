use crate::constants::KDF_METADATA_REGION_BYTES;
use libc::{c_char, c_int, c_void};
use std::ptr;

const REDDIT_ENVELOPE_MAGIC: &[u8; 8] = b"JDVRIFR1";
const ENVELOPE_FLAG_COMPRESSED: u8 = 1;
const ENVELOPE_PREFIX_BYTES: usize = 16;
const REDDIT_ENVELOPE_HEADER_BYTES: usize = ENVELOPE_PREFIX_BYTES + KDF_METADATA_REGION_BYTES;

unsafe extern "C" {
    fn jdvrif_reddit_prepare(
        input_data: *const u8,
        input_size: usize,
        prepared_handle: *mut *mut c_void,
        width: *mut u32,
        height: *mut u32,
        luminance_blocks: *mut u64,
        payload_capacity: *mut usize,
        prepared_jpeg_size: *mut usize,
        error_data: *mut *mut c_char,
        error_size: *mut usize,
    ) -> c_int;

    fn jdvrif_reddit_prepared_free(prepared_handle: *mut c_void);

    fn jdvrif_reddit_embed(
        prepared_handle: *const c_void,
        carrier_key: u64,
        payload_data: *const u8,
        payload_size: usize,
        output_data: *mut *mut u8,
        output_size: *mut usize,
        error_data: *mut *mut c_char,
        error_size: *mut usize,
    ) -> c_int;

    fn jdvrif_reddit_extract(
        input_data: *const u8,
        input_size: usize,
        carrier_key: u64,
        kdf_data: *mut *mut u8,
        kdf_size: *mut usize,
        encrypted_data: *mut *mut u8,
        encrypted_size: *mut usize,
        is_compressed: *mut c_int,
        error_data: *mut *mut c_char,
        error_size: *mut usize,
    ) -> c_int;

    fn jdvrif_reddit_buffer_free(buffer: *mut c_void);
}

#[no_mangle]
extern "C" fn jdvrif_rs_reddit_cancellation_requested() -> c_int {
    if crate::signal::pending_signal().is_some() {
        1
    } else {
        0
    }
}

fn ffi_input_ptr(bytes: &[u8]) -> *const u8 {
    if bytes.is_empty() {
        ptr::null()
    } else {
        bytes.as_ptr()
    }
}

unsafe fn take_foreign_bytes(data: *mut u8, size: usize) -> Result<Vec<u8>, String> {
    if data.is_null() {
        if size == 0 {
            return Ok(Vec::new());
        }
        return Err("Internal Error: Reddit bridge returned an invalid buffer.".to_string());
    }

    // SAFETY: the bridge returned an allocation containing at least `size`
    // bytes, and ownership remains with it until jdvrif_reddit_buffer_free.
    let output = unsafe { std::slice::from_raw_parts(data, size) }.to_vec();
    // SAFETY: `data` was allocated by the bridge and has not been freed yet.
    unsafe { jdvrif_reddit_buffer_free(data.cast()) };
    Ok(output)
}

unsafe fn take_ffi_error(error_data: *mut c_char, error_size: usize) -> String {
    if error_data.is_null() {
        return "Reddit carrier operation failed.".to_string();
    }
    // SAFETY: error_data/error_size are produced together by the bridge.
    let bytes = unsafe { std::slice::from_raw_parts(error_data.cast::<u8>(), error_size) };
    let message = String::from_utf8_lossy(bytes).into_owned();
    // SAFETY: the error allocation uses the same bridge allocator.
    unsafe { jdvrif_reddit_buffer_free(error_data.cast()) };
    if message.is_empty() {
        "Reddit carrier operation failed.".to_string()
    } else {
        message
    }
}

pub(crate) struct PreparedRedditCover {
    handle: *mut c_void,
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) payload_capacity: usize,
    pub(crate) prepared_jpeg_size: usize,
}

impl Drop for PreparedRedditCover {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: handle came from jdvrif_reddit_prepare and is owned here.
            unsafe { jdvrif_reddit_prepared_free(self.handle) };
            self.handle = ptr::null_mut();
        }
    }
}

impl PreparedRedditCover {
    pub(crate) fn embed(&self, carrier_key: u64, payload: &[u8]) -> Result<Vec<u8>, String> {
        let mut output_data = ptr::null_mut();
        let mut output_size = 0usize;
        let mut error_data = ptr::null_mut();
        let mut error_size = 0usize;

        // SAFETY: handle is live for self's lifetime and all slices/pointers
        // remain valid for the duration of the call.
        let status = unsafe {
            jdvrif_reddit_embed(
                self.handle,
                carrier_key,
                ffi_input_ptr(payload),
                payload.len(),
                &mut output_data,
                &mut output_size,
                &mut error_data,
                &mut error_size,
            )
        };
        if status != 1 {
            // SAFETY: error pointers were initialized by the bridge.
            return Err(unsafe { take_ffi_error(error_data, error_size) });
        }
        // SAFETY: successful bridge output owns output_size readable bytes.
        unsafe { take_foreign_bytes(output_data, output_size) }
    }
}

pub(crate) fn prepare_cover(input_jpeg: &[u8]) -> Result<PreparedRedditCover, String> {
    let mut handle = ptr::null_mut();
    let mut width = 0u32;
    let mut height = 0u32;
    let mut luminance_blocks = 0u64;
    let mut payload_capacity = 0usize;
    let mut prepared_jpeg_size = 0usize;
    let mut error_data = ptr::null_mut();
    let mut error_size = 0usize;

    // SAFETY: all pointers target initialized locals and input_jpeg remains
    // valid for the duration of the call.
    let status = unsafe {
        jdvrif_reddit_prepare(
            ffi_input_ptr(input_jpeg),
            input_jpeg.len(),
            &mut handle,
            &mut width,
            &mut height,
            &mut luminance_blocks,
            &mut payload_capacity,
            &mut prepared_jpeg_size,
            &mut error_data,
            &mut error_size,
        )
    };
    if status != 1 {
        // SAFETY: error pointers were initialized by the bridge.
        return Err(unsafe { take_ffi_error(error_data, error_size) });
    }
    if handle.is_null() {
        return Err("Internal Error: Reddit bridge returned no prepared cover.".to_string());
    }

    Ok(PreparedRedditCover {
        handle,
        width,
        height,
        payload_capacity,
        prepared_jpeg_size,
    })
}

pub(crate) struct RedditEncryptedEnvelope {
    pub(crate) kdf_metadata: Vec<u8>,
    pub(crate) encrypted_data: Vec<u8>,
    pub(crate) is_compressed: bool,
}

pub(crate) fn extract_envelope(
    input_jpeg: &[u8],
    carrier_key: u64,
) -> Result<Option<RedditEncryptedEnvelope>, String> {
    let mut kdf_data = ptr::null_mut();
    let mut kdf_size = 0usize;
    let mut encrypted_data = ptr::null_mut();
    let mut encrypted_size = 0usize;
    let mut is_compressed = 0;
    let mut error_data = ptr::null_mut();
    let mut error_size = 0usize;

    // SAFETY: outputs target initialized locals and input_jpeg remains valid.
    let status = unsafe {
        jdvrif_reddit_extract(
            ffi_input_ptr(input_jpeg),
            input_jpeg.len(),
            carrier_key,
            &mut kdf_data,
            &mut kdf_size,
            &mut encrypted_data,
            &mut encrypted_size,
            &mut is_compressed,
            &mut error_data,
            &mut error_size,
        )
    };
    if status == 0 {
        return Ok(None);
    }
    if status != 1 {
        // SAFETY: error pointers were initialized by the bridge.
        return Err(unsafe { take_ffi_error(error_data, error_size) });
    }

    // SAFETY: successful bridge outputs own their indicated bytes.
    let kdf_metadata = unsafe { take_foreign_bytes(kdf_data, kdf_size) }?;
    // SAFETY: same ownership contract as kdf_data.
    let encrypted = unsafe { take_foreign_bytes(encrypted_data, encrypted_size) }?;
    Ok(Some(RedditEncryptedEnvelope {
        kdf_metadata,
        encrypted_data: encrypted,
        is_compressed: is_compressed != 0,
    }))
}

pub(crate) fn envelope_size(encrypted_size: usize) -> Result<usize, String> {
    REDDIT_ENVELOPE_HEADER_BYTES
        .checked_add(encrypted_size)
        .ok_or_else(|| "File Size Error: Reddit encrypted-envelope size overflow.".to_string())
}

pub(crate) fn make_envelope(
    kdf_metadata: &[u8],
    encrypted_data: &[u8],
    is_compressed: bool,
) -> Result<Vec<u8>, String> {
    if kdf_metadata.len() != KDF_METADATA_REGION_BYTES {
        return Err("Internal Error: Reddit KDF metadata has an invalid size.".to_string());
    }
    let encrypted_size = u32::try_from(encrypted_data.len()).map_err(|_| {
        "File Size Error: Reddit encrypted payload exceeds its format limit.".to_string()
    })?;

    let mut envelope = Vec::with_capacity(envelope_size(encrypted_data.len())?);
    envelope.extend_from_slice(REDDIT_ENVELOPE_MAGIC);
    envelope.push(if is_compressed {
        ENVELOPE_FLAG_COMPRESSED
    } else {
        0
    });
    envelope.extend_from_slice(&[0, 0, 0]);
    envelope.extend_from_slice(&encrypted_size.to_le_bytes());
    envelope.extend_from_slice(kdf_metadata);
    envelope.extend_from_slice(encrypted_data);
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_layout_matches_native_format() {
        let kdf = vec![0xA5; KDF_METADATA_REGION_BYTES];
        let encrypted = vec![1, 2, 3, 4, 5];
        let envelope = make_envelope(&kdf, &encrypted, true).unwrap();
        assert_eq!(&envelope[..8], REDDIT_ENVELOPE_MAGIC);
        assert_eq!(envelope[8], ENVELOPE_FLAG_COMPRESSED);
        assert_eq!(&envelope[9..12], &[0, 0, 0]);
        assert_eq!(&envelope[12..16], &(5u32).to_le_bytes());
        assert_eq!(&envelope[16..16 + KDF_METADATA_REGION_BYTES], &kdf);
        assert_eq!(&envelope[REDDIT_ENVELOPE_HEADER_BYTES..], &encrypted);
        assert_eq!(envelope.len(), REDDIT_ENVELOPE_HEADER_BYTES + 5);
    }
}
