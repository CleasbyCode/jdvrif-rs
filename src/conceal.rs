use crate::cli::ConcealOption;
use crate::common::{
    checked_file_size, cleanup_path_no_throw, open_binary_input_or_throw,
    open_binary_output_for_write_or_throw, span_has_range, validate_file_for_read,
};
use crate::conceal_helpers::{
    deliver_conceal_pin, finalize_default_platform_report, generate_recovery_pin,
    maybe_print_large_file_notice, platform_report_template, print_conceal_complete,
    should_bypass_compression, temp_compressed_path, temp_encrypted_path,
    validate_combined_size_limits, validate_data_filename, zlib_compress_file_to_path_native,
};
use crate::conceal_segments::{
    make_bluesky_segment_template, make_default_segment_template,
    write_embedded_jpg_from_encrypted_file, BlueskySegmentStreamBuilder, SegmentedEmbedSummary,
};
use crate::constants::{
    stream_mode_byte, BLUESKY_KDF_METADATA_INDEX, BLUESKY_PLATFORM_INDEX,
    DEFAULT_KDF_METADATA_INDEX, KDF_ALG_ARGON2ID13, KDF_ALG_OFFSET, KDF_MAGIC_OFFSET,
    KDF_METADATA_MAGIC_V3, KDF_METADATA_REGION_BYTES, KDF_NONCE_OFFSET, KDF_SALT_OFFSET,
    KDF_SENTINEL, KDF_SENTINEL_OFFSET, NO_ZLIB_COMPRESSION_ID, NO_ZLIB_COMPRESSION_ID_INDEX,
    REDDIT_PLATFORM_INDEX, STREAM_CHUNK_SIZE, STREAM_FRAME_LEN_BYTES,
};
use crate::crypto::{argon2id13, memzero, randombytes_into, secretstream};
use crate::decrypt::derive_key_from_pin;
use crate::runtime::{JdvrifError, TempFileGuard};
use crate::signal::check_cancellation;
use std::cmp;
use std::io::{BufWriter, Read};
use std::path::Path;
use zeroize::Zeroizing;

fn estimate_prefixed_stream_encrypted_size(
    input_size: usize,
    prefix_plain_len: usize,
) -> Result<usize, String> {
    if prefix_plain_len > usize::MAX - input_size {
        return Err("File Size Error: Encrypted output overflow.".to_string());
    }
    let total_plain_size = input_size + prefix_plain_len;
    if total_plain_size == 0 {
        return Ok(0);
    }

    let chunk_count = total_plain_size.div_ceil(STREAM_CHUNK_SIZE);

    let per_chunk_overhead = secretstream::ABYTES + STREAM_FRAME_LEN_BYTES;
    if chunk_count > (usize::MAX - total_plain_size) / per_chunk_overhead {
        return Err("File Size Error: Encrypted output overflow.".to_string());
    }

    Ok(total_plain_size + chunk_count * per_chunk_overhead)
}

fn encrypt_file_with_secretstream_to_sink<F>(
    data_path: &Path,
    input_size: usize,
    prefix_plaintext: &[u8],
    authenticated_mode: u8,
    key: &secretstream::Key,
    mut sink: F,
) -> Result<secretstream::Header, String>
where
    F: FnMut(&[u8]) -> Result<(), String>,
{
    if input_size == 0 {
        return Err("Data File Error: File is empty.".to_string());
    }
    if prefix_plaintext.len() > usize::MAX - input_size {
        return Err("File Size Error: Encrypted output overflow.".to_string());
    }
    let mut input =
        open_binary_input_or_throw(data_path, "Read Error: Failed to open file for encryption.")?;
    let (mut stream, header) = secretstream::Stream::init_push(key)
        .map_err(|_| "crypto_secretstream init_push failed".to_string())?;
    let associated_data = [authenticated_mode];

    let mut push_plain_chunk = |plain_chunk: &[u8], is_final: bool| -> Result<(), String> {
        check_cancellation()?;
        let tag = if is_final {
            secretstream::Tag::Final
        } else {
            secretstream::Tag::Message
        };
        let cipher = stream
            .push(plain_chunk, Some(&associated_data), tag)
            .map_err(|_| "crypto_secretstream push failed".to_string())?;

        let frame_len = u32::try_from(cipher.len())
            .map_err(|_| "File Size Error: Stream chunk exceeds size limit.".to_string())?;
        sink(&frame_len.to_be_bytes())?;
        sink(&cipher)?;
        check_cancellation()
    };

    let mut prefix_off = 0usize;
    let mut input_left = input_size;
    let mut in_chunk = Zeroizing::new(vec![0u8; STREAM_CHUNK_SIZE]);

    while prefix_off < prefix_plaintext.len() || input_left > 0 {
        check_cancellation()?;
        let mut filled = 0usize;

        if prefix_off < prefix_plaintext.len() {
            let prefix_bytes = cmp::min(STREAM_CHUNK_SIZE, prefix_plaintext.len() - prefix_off);
            in_chunk[..prefix_bytes]
                .copy_from_slice(&prefix_plaintext[prefix_off..prefix_off + prefix_bytes]);
            prefix_off += prefix_bytes;
            filled = prefix_bytes;
        }

        if filled < STREAM_CHUNK_SIZE && input_left > 0 {
            let file_bytes = cmp::min(STREAM_CHUNK_SIZE - filled, input_left);
            input
                .read_exact(&mut in_chunk[filled..filled + file_bytes])
                .map_err(|_| {
                    "Read Error: Failed to read full input while encrypting.".to_string()
                })?;
            filled += file_bytes;
            input_left -= file_bytes;
        }

        if filled == 0 {
            return Err("Internal Error: Plaintext size accounting mismatch.".to_string());
        }

        let is_final = prefix_off == prefix_plaintext.len() && input_left == 0;
        push_plain_chunk(&in_chunk[..filled], is_final)?;
        memzero(&mut in_chunk[..filled]);
    }

    if prefix_off != prefix_plaintext.len() || input_left != 0 {
        return Err("Internal Error: Plaintext size accounting mismatch.".to_string());
    }

    let mut trailing = [0u8; 1];
    if input
        .read(&mut trailing)
        .map_err(|_| "Read Error: Failed while reading input file.".to_string())?
        != 0
    {
        return Err("Read Error: Input file changed while encrypting.".to_string());
    }

    Ok(header)
}

/// Encrypt to a file on disk (for default/reddit path).
fn encrypt_file_with_secretstream_to_file(
    data_path: &Path,
    input_size: usize,
    prefix_plaintext: &[u8],
    authenticated_mode: u8,
    key: &secretstream::Key,
    out_path: &Path,
) -> Result<secretstream::Header, String> {
    let file = open_binary_output_for_write_or_throw(out_path)?;
    let mut writer = BufWriter::with_capacity(1 << 20, file);
    let header = encrypt_file_with_secretstream_to_sink(
        data_path,
        input_size,
        prefix_plaintext,
        authenticated_mode,
        key,
        |chunk| {
            std::io::Write::write_all(&mut writer, chunk)
                .map_err(|_| "Write File Error: Failed to write complete output file.".to_string())
        },
    )?;
    std::io::Write::flush(&mut writer)
        .map_err(|_| "Write File Error: Failed to write complete output file.".to_string())?;
    Ok(header)
}

/// Write the KDF metadata block into `segment_vec` at the given index.
fn write_kdf_metadata(
    segment_vec: &mut [u8],
    kdf_metadata_index: usize,
    salt: &[u8],
    stream_header: &secretstream::Header,
) -> Result<(), String> {
    let mut kdf_region = vec![0u8; KDF_METADATA_REGION_BYTES];
    randombytes_into(&mut kdf_region)
        .map_err(|_| "CSPRNG Error: Failed to fill KDF metadata region.".to_string())?;
    segment_vec[kdf_metadata_index..kdf_metadata_index + KDF_METADATA_REGION_BYTES]
        .copy_from_slice(&kdf_region);
    segment_vec[kdf_metadata_index + KDF_MAGIC_OFFSET
        ..kdf_metadata_index + KDF_MAGIC_OFFSET + KDF_METADATA_MAGIC_V3.len()]
        .copy_from_slice(&KDF_METADATA_MAGIC_V3);
    segment_vec[kdf_metadata_index + KDF_ALG_OFFSET] = KDF_ALG_ARGON2ID13;
    segment_vec[kdf_metadata_index + KDF_SENTINEL_OFFSET] = KDF_SENTINEL;
    segment_vec
        [kdf_metadata_index + KDF_SALT_OFFSET..kdf_metadata_index + KDF_SALT_OFFSET + salt.len()]
        .copy_from_slice(salt);
    segment_vec[kdf_metadata_index + KDF_NONCE_OFFSET
        ..kdf_metadata_index + KDF_NONCE_OFFSET + stream_header.0.len()]
        .copy_from_slice(&stream_header.0);
    Ok(())
}

pub(crate) fn run_native_conceal(
    option: &ConcealOption,
    image_file_path: &Path,
    data_file_path: &Path,
) -> Result<(), JdvrifError> {
    let has_no_option = matches!(option, ConcealOption::None);
    let has_bluesky_option = matches!(option, ConcealOption::Bluesky);
    let has_reddit_option = matches!(option, ConcealOption::Reddit);

    crate::crypto::init().map_err(|_| JdvrifError::new("Libsodium initialization failed!"))?;

    let source_data_size =
        validate_file_for_read(data_file_path, false, false).map_err(JdvrifError::from)?;
    let cover_size =
        validate_file_for_read(image_file_path, true, true).map_err(JdvrifError::from)?;
    let jpg_vec = crate::jpeg_preprocess::prepare_cover_image_for_conceal(
        image_file_path,
        cover_size,
        source_data_size,
        has_no_option,
        has_bluesky_option,
    )
    .map_err(JdvrifError::from)?;
    let jpg_size = jpg_vec.len();

    let data_filename = validate_data_filename(data_file_path).map_err(JdvrifError::from)?;
    let bypass_compression = should_bypass_compression(data_file_path, source_data_size);

    let mut segment_vec = if has_bluesky_option {
        make_bluesky_segment_template().map_err(JdvrifError::from)?
    } else {
        make_default_segment_template().map_err(JdvrifError::from)?
    };

    maybe_print_large_file_notice(source_data_size);

    let mut compressed_guard: Option<TempFileGuard> = None;
    let (encrypt_input_path, encrypt_input_size) = if bypass_compression {
        segment_vec[NO_ZLIB_COMPRESSION_ID_INDEX] = NO_ZLIB_COMPRESSION_ID;
        (data_file_path.to_path_buf(), source_data_size)
    } else {
        let compressed_path = temp_compressed_path(&data_filename).map_err(JdvrifError::from)?;
        zlib_compress_file_to_path_native(data_file_path, &compressed_path, source_data_size)
            .map_err(JdvrifError::from)?;
        let compressed_size = checked_file_size(
            &compressed_path,
            "Zlib Compression Error: Failed to build compressed payload.",
            true,
        )
        .map_err(JdvrifError::from)?;
        compressed_guard = Some(TempFileGuard::new(compressed_path.clone()));
        (compressed_path, compressed_size)
    };

    let filename_prefix_len = 1usize
        .checked_add(data_filename.len())
        .ok_or_else(|| JdvrifError::new("File Size Error: Encrypted output overflow."))?;
    let encrypted_payload_size =
        estimate_prefixed_stream_encrypted_size(encrypt_input_size, filename_prefix_len)
            .map_err(JdvrifError::from)?;
    validate_combined_size_limits(
        encrypted_payload_size,
        jpg_size,
        has_reddit_option,
        has_bluesky_option,
    )
    .map_err(JdvrifError::from)?;

    // Build filename prefix plaintext
    if data_filename.is_empty() || data_filename.len() >= u8::MAX as usize {
        return Err(JdvrifError::new(
            "Data File Error: Invalid data filename length.",
        ));
    }
    let filename_len = u8::try_from(data_filename.len())
        .map_err(|_| JdvrifError::new("Data File Error: Invalid data filename length."))?;
    let mut filename_prefix = Vec::with_capacity(1 + data_filename.len());
    filename_prefix.push(filename_len);
    filename_prefix.extend_from_slice(&data_filename);

    let kdf_metadata_index = if has_bluesky_option {
        BLUESKY_KDF_METADATA_INDEX
    } else {
        DEFAULT_KDF_METADATA_INDEX
    };
    if !span_has_range(
        segment_vec.len(),
        kdf_metadata_index,
        KDF_METADATA_REGION_BYTES,
    ) {
        return Err(JdvrifError::new(
            "Internal Error: Corrupt segment metadata template.",
        ));
    }

    // Generate key material
    let recovery_pin = generate_recovery_pin().map_err(JdvrifError::from)?;
    let mut salt = [0u8; argon2id13::SALTBYTES];
    randombytes_into(&mut salt)
        .map_err(|_| JdvrifError::new("CSPRNG Error: Failed to generate salt."))?;
    let key_bytes = derive_key_from_pin(&recovery_pin, &salt).map_err(JdvrifError::from)?;
    let key = secretstream::Key::from_slice(&key_bytes[..])
        .ok_or_else(|| JdvrifError::new("KDF Error: Unable to derive encryption key."))?;

    let mut platforms_vec = platform_report_template();
    let authenticated_mode = stream_mode_byte(!bypass_compression);

    // ── Bluesky path (in-memory, unchanged) ──
    if has_bluesky_option {
        let encrypted_size =
            estimate_prefixed_stream_encrypted_size(encrypt_input_size, filename_prefix.len())
                .map_err(JdvrifError::from)?;
        let mut bluesky_builder =
            BlueskySegmentStreamBuilder::new(&mut segment_vec, encrypted_size)
                .map_err(JdvrifError::from)?;
        let stream_header = encrypt_file_with_secretstream_to_sink(
            &encrypt_input_path,
            encrypt_input_size,
            &filename_prefix,
            authenticated_mode,
            &key,
            |chunk| bluesky_builder.push(chunk),
        )
        .map_err(JdvrifError::from)?;
        bluesky_builder.finish().map_err(JdvrifError::from)?;
        write_kdf_metadata(&mut segment_vec, kdf_metadata_index, &salt, &stream_header)
            .map_err(JdvrifError::from)?;

        drop(compressed_guard);

        if platforms_vec.len() <= BLUESKY_PLATFORM_INDEX {
            return Err(JdvrifError::new(
                "Internal Error: Corrupt platform compatibility list.",
            ));
        }
        platforms_vec[0] = platforms_vec[BLUESKY_PLATFORM_INDEX].clone();
        platforms_vec.truncate(1);

        let embedded_jpg_size = segment_vec.len() + jpg_vec.len();
        drop(key);
        drop(key_bytes);

        let staged_output = crate::output_file::write_to_uncommitted_staged_output(
            std::path::Path::new(""),
            "jrif_",
            ".jpg",
            9,
            1 << 20,
            |out| {
                if !segment_vec.is_empty() {
                    out.write(
                        &segment_vec,
                        "Write File Error: Output data too large to write.",
                    )?;
                }
                out.write(
                    &jpg_vec,
                    "Write File Error: Output data too large to write.",
                )?;
                Ok(())
            },
        )
        .map_err(JdvrifError::from)?;

        deliver_conceal_pin(&platforms_vec, *recovery_pin).map_err(JdvrifError::from)?;
        drop(recovery_pin);
        let output_path = staged_output.commit().map_err(JdvrifError::from)?;
        print_conceal_complete(&output_path, embedded_jpg_size).map_err(JdvrifError::from)?;
        return Ok(());
    }

    // ── Default / Reddit path: encrypt to temp file, then stream via OutputFile ──
    let enc_tmp = temp_encrypted_path(&data_filename).map_err(JdvrifError::from)?;
    let mut enc_guard = TempFileGuard::new(enc_tmp.clone());

    let stream_header = encrypt_file_with_secretstream_to_file(
        &encrypt_input_path,
        encrypt_input_size,
        &filename_prefix,
        authenticated_mode,
        &key,
        &enc_tmp,
    )
    .map_err(JdvrifError::from)?;
    drop(key);
    drop(key_bytes);
    write_kdf_metadata(&mut segment_vec, kdf_metadata_index, &salt, &stream_header)
        .map_err(JdvrifError::from)?;

    drop(compressed_guard);

    let mut summary = SegmentedEmbedSummary::default();
    let staged_output = crate::output_file::write_to_uncommitted_staged_output(
        std::path::Path::new(""),
        "jrif_",
        ".jpg",
        9,
        1 << 20,
        |out| {
            summary = write_embedded_jpg_from_encrypted_file(
                out,
                &mut segment_vec,
                &enc_tmp,
                &jpg_vec,
                has_reddit_option,
            )?;
            Ok(())
        },
    )
    .map_err(JdvrifError::from)?;

    // Dismiss the guard (suppresses auto-delete on drop) then clean up manually,
    // mirroring C++ TempFileCleanupGuard::dismiss() + explicit removal on success.
    enc_guard.dismiss();
    cleanup_path_no_throw(&enc_tmp);

    if has_reddit_option {
        if platforms_vec.len() > REDDIT_PLATFORM_INDEX {
            platforms_vec[0] = platforms_vec[REDDIT_PLATFORM_INDEX].clone();
            platforms_vec.truncate(1);
        }
    } else {
        finalize_default_platform_report(&mut platforms_vec, summary);
    }

    deliver_conceal_pin(&platforms_vec, *recovery_pin).map_err(JdvrifError::from)?;
    drop(recovery_pin);
    let output_path = staged_output.commit().map_err(JdvrifError::from)?;
    print_conceal_complete(&output_path, summary.embedded_image_size).map_err(JdvrifError::from)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn prefixed_stream_size_coalesces_exact_chunk_boundary() {
        crate::crypto::init().expect("sodium init");

        let prefix_len = 21usize;
        let input_size = STREAM_CHUNK_SIZE - prefix_len;
        let frame_overhead = secretstream::ABYTES + STREAM_FRAME_LEN_BYTES;

        assert_eq!(
            estimate_prefixed_stream_encrypted_size(input_size, prefix_len).unwrap(),
            STREAM_CHUNK_SIZE + frame_overhead,
        );
        assert_eq!(
            estimate_prefixed_stream_encrypted_size(input_size + 1, prefix_len).unwrap(),
            STREAM_CHUNK_SIZE + 1 + 2 * frame_overhead,
        );

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock drift")
            .as_nanos();
        let input_path = std::env::temp_dir().join(format!(
            "jdvrif_rs_boundary_{}_{}",
            std::process::id(),
            nonce,
        ));
        std::fs::write(&input_path, vec![0x5A; input_size]).expect("write boundary input");

        let key_bytes = [0x37; secretstream::KEYBYTES];
        let key = secretstream::Key::from_slice(&key_bytes).expect("test key");
        let prefix = vec![0xA6; prefix_len];
        let mut framed_ciphertext = Vec::new();
        encrypt_file_with_secretstream_to_sink(
            &input_path,
            input_size,
            &prefix,
            stream_mode_byte(false),
            &key,
            |bytes| {
                framed_ciphertext.extend_from_slice(bytes);
                Ok(())
            },
        )
        .expect("encrypt boundary input");
        let _ = std::fs::remove_file(&input_path);

        let only_frame_len = u32::from_be_bytes(
            framed_ciphertext[..STREAM_FRAME_LEN_BYTES]
                .try_into()
                .expect("frame length"),
        ) as usize;
        assert_eq!(only_frame_len, STREAM_CHUNK_SIZE + secretstream::ABYTES);
        assert_eq!(
            framed_ciphertext.len(),
            STREAM_FRAME_LEN_BYTES + only_frame_len,
            "the filename prefix and payload must share one exact-boundary frame",
        );
    }

    #[test]
    fn encryption_rejects_source_growth_after_expected_size() {
        crate::crypto::init().expect("sodium init");

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock drift")
            .as_nanos();
        let input_path =
            std::env::temp_dir()
                .join(format!("jdvrif_rs_growth_{}_{}", std::process::id(), nonce,));
        std::fs::write(&input_path, b"expected+grown").expect("write growing input");

        let key_bytes = [0x51; secretstream::KEYBYTES];
        let key = secretstream::Key::from_slice(&key_bytes).expect("test key");
        let err = match encrypt_file_with_secretstream_to_sink(
            &input_path,
            b"expected".len(),
            b"\x01n",
            stream_mode_byte(false),
            &key,
            |_| Ok(()),
        ) {
            Err(err) => err,
            Ok(_) => panic!("source growth must be rejected"),
        };
        let _ = std::fs::remove_file(&input_path);

        assert!(err.contains("changed while encrypting"));
    }
}
