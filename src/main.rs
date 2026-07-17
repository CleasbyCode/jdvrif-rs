// Fail fast on non-Linux toolchains.
#[cfg(not(target_os = "linux"))]
compile_error!("jdvrif-rs is Linux-only: requires sendfile(2), termios, TurboJPEG, and Unix paths");

use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

mod cli;
mod common;
mod conceal;
mod conceal_helpers;
mod conceal_segments;
mod constants;
#[allow(dead_code)]
mod crypto;
mod decrypt;
mod extract;
mod jpeg_preprocess;
#[allow(dead_code)]
mod output_file;
mod paths;
mod recover;
mod runtime;
mod signal;

use crate::cli::{parse_args, ParsedCommand};
use crate::conceal::run_native_conceal;
use crate::constants::INFO_TEXT;
use crate::recover::run_native_recover;
fn run() -> ExitCode {
    let raw_args: Vec<OsString> = env::args_os().skip(1).collect();
    let parsed = match parse_args(&raw_args) {
        Ok(cmd) => cmd,
        Err(usage) => {
            eprintln!("\n{}\n", usage);
            return ExitCode::from(1);
        }
    };

    match parsed {
        ParsedCommand::Info => {
            print!("{INFO_TEXT}");
            ExitCode::from(0)
        }
        ParsedCommand::Conceal {
            option,
            image,
            secret,
        } => {
            let image_path = PathBuf::from(image);
            let secret_path = PathBuf::from(secret);
            match run_native_conceal(&option, &image_path, &secret_path) {
                Ok(()) => ExitCode::from(0),
                Err(err) => {
                    eprintln!("\n{}\n", err);
                    ExitCode::from(1)
                }
            }
        }
        ParsedCommand::Recover { image } => {
            let image_path = PathBuf::from(image);
            match run_native_recover(&image_path) {
                Ok(()) => ExitCode::from(0),
                Err(err) => {
                    eprintln!("\n{}\n", err);
                    ExitCode::from(1)
                }
            }
        }
    }
}

fn main() -> ExitCode {
    if let Err(err) = crate::signal::install_process_signal_handlers() {
        eprintln!("\n{err}\n");
        return ExitCode::from(1);
    }

    let exit_code = run();
    if let Some(signal_number) = crate::signal::pending_signal() {
        crate::signal::reraise_after_cleanup(signal_number);
    }
    exit_code
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        stream_mode_byte, KDF_ALG_ARGON2ID13, KDF_ALG_OFFSET, KDF_MAGIC_OFFSET,
        KDF_METADATA_MAGIC_V2, KDF_METADATA_MAGIC_V3, KDF_NONCE_OFFSET, KDF_SALT_OFFSET,
        KDF_SENTINEL, KDF_SENTINEL_OFFSET, STREAM_CHUNK_SIZE,
    };
    use crate::crypto::{argon2id13, randombytes_into, secretstream};
    use crate::decrypt::{
        decrypt_from_cipher_stage_with_pin, decrypt_offsets, derive_key_from_pin,
    };
    use crate::runtime::{DecryptStatus, JdvrifError, KdfMetadataVersion};
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::cmp;
    use std::fs;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDirGuard {
        path: PathBuf,
    }

    impl TempDirGuard {
        fn new(prefix: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock drift")
                .as_nanos();
            let dir = std::env::temp_dir().join(format!(
                "jdvrif_rs_{}_{}_{}",
                prefix,
                std::process::id(),
                nanos
            ));
            fs::create_dir_all(&dir).expect("create temp dir");
            Self { path: dir }
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn compress_bytes(input: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(input).expect("compress");
        encoder.finish().expect("finish compress")
    }

    fn build_metadata_and_ciphertext(
        is_bluesky: bool,
        pin: u64,
        filename: &str,
        payload: &[u8],
        compress_payload: bool,
        metadata_version: KdfMetadataVersion,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let offsets = decrypt_offsets(is_bluesky);
        let mut metadata = vec![0u8; if is_bluesky { 0x1D1 } else { 0x33B }];
        randombytes_into(&mut metadata).expect("random metadata");

        let mut salt = [0u8; argon2id13::SALTBYTES];
        for (i, b) in salt.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(5).wrapping_add(11);
        }

        let plain_payload = if compress_payload {
            compress_bytes(payload)
        } else {
            payload.to_vec()
        };

        let mut prefixed_plain = Vec::with_capacity(1 + filename.len() + plain_payload.len());
        prefixed_plain.push(u8::try_from(filename.len()).expect("filename len"));
        prefixed_plain.extend_from_slice(filename.as_bytes());
        prefixed_plain.extend_from_slice(&plain_payload);

        let key_bytes = derive_key_from_pin(&pin, &salt).expect("derive key");
        let key = secretstream::Key::from_slice(&key_bytes[..]).expect("key from slice");
        let (mut stream, header) = secretstream::Stream::init_push(&key).expect("init push");
        let mode_data = [stream_mode_byte(compress_payload)];
        let (metadata_magic, associated_data): (&[u8; 4], Option<&[u8]>) = match metadata_version {
            KdfMetadataVersion::V2Secretstream => (&KDF_METADATA_MAGIC_V2, None),
            KdfMetadataVersion::V3SecretstreamAuthenticatedMode => {
                (&KDF_METADATA_MAGIC_V3, Some(mode_data.as_slice()))
            }
            KdfMetadataVersion::None => panic!("unsupported test metadata version"),
        };

        let mut ciphertext = Vec::new();
        let mut off = 0usize;
        while off < prefixed_plain.len() {
            let mlen = cmp::min(STREAM_CHUNK_SIZE, prefixed_plain.len() - off);
            let tag = if off + mlen == prefixed_plain.len() {
                secretstream::Tag::Final
            } else {
                secretstream::Tag::Message
            };
            let cipher = stream
                .push(&prefixed_plain[off..off + mlen], associated_data, tag)
                .expect("secretstream push");
            let frame_len = u32::try_from(cipher.len()).expect("frame len");
            ciphertext.extend_from_slice(&frame_len.to_be_bytes());
            ciphertext.extend_from_slice(&cipher);
            off += mlen;
        }
        metadata[offsets.sodium_key_index + KDF_MAGIC_OFFSET
            ..offsets.sodium_key_index + KDF_MAGIC_OFFSET + metadata_magic.len()]
            .copy_from_slice(metadata_magic);
        metadata[offsets.sodium_key_index + KDF_ALG_OFFSET] = KDF_ALG_ARGON2ID13;
        metadata[offsets.sodium_key_index + KDF_SENTINEL_OFFSET] = KDF_SENTINEL;
        metadata[offsets.sodium_key_index + KDF_SALT_OFFSET
            ..offsets.sodium_key_index + KDF_SALT_OFFSET + salt.len()]
            .copy_from_slice(&salt);
        metadata[offsets.sodium_key_index + KDF_NONCE_OFFSET
            ..offsets.sodium_key_index + KDF_NONCE_OFFSET + header.0.len()]
            .copy_from_slice(&header.0);

        (metadata, ciphertext, payload.to_vec())
    }

    fn assert_failed_pin(status: DecryptStatus) {
        match status {
            DecryptStatus::FailedPin => {}
            DecryptStatus::Success { .. } => panic!("expected authentication failure"),
        }
    }

    #[test]
    fn decrypt_v2_secretstream_compressed_roundtrip_extracts_filename() {
        crate::crypto::init().expect("sodium init");

        let pin = 4_239_884_124_001u64;
        let filename = "v2_payload.bin";
        let expected_payload = b"v2 compressed payload ".repeat(4096);
        let (metadata, ciphertext, expected_plain) = build_metadata_and_ciphertext(
            false,
            pin,
            filename,
            &expected_payload,
            true,
            KdfMetadataVersion::V2Secretstream,
        );

        let temp = TempDirGuard::new("v2_compressed");
        let cipher_path = temp.path.join("cipher.bin");
        let stage_path = temp.path.join("out.bin");
        fs::write(&cipher_path, &ciphertext).expect("write cipher");

        let status = decrypt_from_cipher_stage_with_pin(
            &metadata,
            false,
            true,
            &cipher_path,
            &stage_path,
            pin,
        )
        .expect("decrypt status");

        match status {
            DecryptStatus::Success {
                decrypted_filename,
                output_size,
            } => {
                assert_eq!(decrypted_filename, filename.as_bytes());
                assert_eq!(output_size, expected_plain.len());
            }
            DecryptStatus::FailedPin => panic!("unexpected pin failure"),
        }

        let out = fs::read(&stage_path).expect("read output");
        assert_eq!(out, expected_plain);
    }

    #[test]
    fn decrypt_v2_secretstream_wrong_pin_returns_failedpin() {
        crate::crypto::init().expect("sodium init");

        let pin = 9_876_543_210u64;
        let (metadata, ciphertext, _) = build_metadata_and_ciphertext(
            false,
            pin,
            "wrong_pin.bin",
            b"wrong pin payload",
            false,
            KdfMetadataVersion::V2Secretstream,
        );

        let temp = TempDirGuard::new("v2_wrong_pin");
        let cipher_path = temp.path.join("cipher.bin");
        let stage_path = temp.path.join("out.bin");
        fs::write(&cipher_path, &ciphertext).expect("write cipher");

        let status = decrypt_from_cipher_stage_with_pin(
            &metadata,
            false,
            false,
            &cipher_path,
            &stage_path,
            pin + 1,
        )
        .expect("decrypt status");

        assert_failed_pin(status);
    }

    #[test]
    fn decrypt_v3_secretstream_authenticated_mode_roundtrip() {
        crate::crypto::init().expect("sodium init");

        let pin = 7_003_449_238_851u64;
        let filename = "v3_payload.bin";
        let expected_payload = b"v3 authenticated compressed payload ".repeat(4096);
        let (metadata, ciphertext, expected_plain) = build_metadata_and_ciphertext(
            false,
            pin,
            filename,
            &expected_payload,
            true,
            KdfMetadataVersion::V3SecretstreamAuthenticatedMode,
        );

        let temp = TempDirGuard::new("v3_compressed");
        let cipher_path = temp.path.join("cipher.bin");
        let stage_path = temp.path.join("out.bin");
        fs::write(&cipher_path, &ciphertext).expect("write cipher");

        let status = decrypt_from_cipher_stage_with_pin(
            &metadata,
            false,
            true,
            &cipher_path,
            &stage_path,
            pin,
        )
        .expect("decrypt status");

        match status {
            DecryptStatus::Success {
                decrypted_filename,
                output_size,
            } => {
                assert_eq!(decrypted_filename, filename.as_bytes());
                assert_eq!(output_size, expected_plain.len());
            }
            DecryptStatus::FailedPin => panic!("unexpected authentication failure"),
        }
        assert_eq!(fs::read(&stage_path).expect("read output"), expected_plain);
    }

    #[test]
    fn v3_mode_tamper_and_metadata_downgrade_fail_authentication() {
        crate::crypto::init().expect("sodium init");

        let pin = 8_112_358_132_134u64;
        let (metadata, ciphertext, _) = build_metadata_and_ciphertext(
            false,
            pin,
            "mode_bound.bin",
            b"authenticated compression semantics",
            true,
            KdfMetadataVersion::V3SecretstreamAuthenticatedMode,
        );

        let temp = TempDirGuard::new("v3_tamper");
        let cipher_path = temp.path.join("cipher.bin");
        fs::write(&cipher_path, &ciphertext).expect("write cipher");

        let mode_tamper_status = decrypt_from_cipher_stage_with_pin(
            &metadata,
            false,
            false,
            &cipher_path,
            &temp.path.join("mode-tamper.bin"),
            pin,
        )
        .expect("mode tamper status");
        assert_failed_pin(mode_tamper_status);

        let offsets = decrypt_offsets(false);
        let mut downgraded_metadata = metadata;
        downgraded_metadata[offsets.sodium_key_index + KDF_MAGIC_OFFSET
            ..offsets.sodium_key_index + KDF_MAGIC_OFFSET + KDF_METADATA_MAGIC_V2.len()]
            .copy_from_slice(&KDF_METADATA_MAGIC_V2);

        let downgrade_status = decrypt_from_cipher_stage_with_pin(
            &downgraded_metadata,
            false,
            true,
            &cipher_path,
            &temp.path.join("downgrade.bin"),
            pin,
        )
        .expect("downgrade status");
        assert_failed_pin(downgrade_status);
    }

    #[test]
    fn decrypt_legacy_metadata_returns_unsupported_error() {
        crate::crypto::init().expect("sodium init");

        let pin = 42u64;
        let offsets = decrypt_offsets(false);
        let mut metadata = vec![0u8; 0x33B];
        metadata[offsets.sodium_key_index + KDF_MAGIC_OFFSET
            ..offsets.sodium_key_index + KDF_MAGIC_OFFSET + 4]
            .copy_from_slice(b"KDF1");
        metadata[offsets.sodium_key_index + KDF_ALG_OFFSET] = KDF_ALG_ARGON2ID13;
        metadata[offsets.sodium_key_index + KDF_SENTINEL_OFFSET] = KDF_SENTINEL;

        let temp = TempDirGuard::new("legacy_unsupported");
        let cipher_path = temp.path.join("cipher.bin");
        let stage_path = temp.path.join("out.bin");
        fs::write(&cipher_path, [0u8; 1]).expect("write cipher");

        let err = match decrypt_from_cipher_stage_with_pin(
            &metadata,
            false,
            false,
            &cipher_path,
            &stage_path,
            pin,
        ) {
            Ok(_) => panic!("legacy metadata should be rejected"),
            Err(e) => e,
        };

        assert_eq!(
            err.to_string(),
            "File Decryption Error: Unsupported legacy encrypted file format. Use an older jdvrif release to recover this file."
        );
        // Touch type so JdvrifError stays in scope for this test module.
        let _: JdvrifError = err;
    }
}
