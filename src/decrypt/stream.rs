use crate::common::{
    checked_file_size, open_binary_input_or_throw, open_binary_output_for_write_or_throw,
};
use crate::constants::{
    stream_mode_byte, CORRUPT_FILE_ERROR, STREAM_CHUNK_SIZE, STREAM_FRAME_LEN_BYTES,
    STREAM_INFLATE_MAX_OUTPUT, WRITE_COMPLETE_ERROR,
};
use crate::crypto::secretstream;
use crate::runtime::KdfMetadataVersion;
use crate::signal::check_cancellation;
use flate2::{Decompress, FlushDecompress, Status};
use std::cmp;
use std::io::{BufWriter, Read, Write};
use std::path::Path;
use zeroize::Zeroizing;

struct FilenamePrefixExtractor {
    has_length: bool,
    expected_len: usize,
    filename: Vec<u8>,
}

impl FilenamePrefixExtractor {
    fn new() -> Self {
        Self {
            has_length: false,
            expected_len: 0,
            filename: Vec::new(),
        }
    }

    fn consume<F>(&mut self, chunk: &[u8], mut payload_consume: F) -> Result<(), String>
    where
        F: FnMut(&[u8]) -> Result<(), String>,
    {
        let mut pos = 0usize;

        if !self.has_length {
            if chunk.is_empty() {
                return Ok(());
            }
            self.expected_len = chunk[pos] as usize;
            pos += 1;
            self.has_length = true;

            if self.expected_len == 0 {
                return Err(CORRUPT_FILE_ERROR.to_string());
            }
            self.filename.reserve(self.expected_len);
        }

        if self.filename.len() < self.expected_len {
            let need = self.expected_len - self.filename.len();
            let take = cmp::min(need, chunk.len().saturating_sub(pos));
            if take > 0 {
                self.filename.extend_from_slice(&chunk[pos..pos + take]);
                pos += take;
            }
        }

        if pos < chunk.len() {
            payload_consume(&chunk[pos..])?;
        }

        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.has_length && self.filename.len() == self.expected_len
    }

    fn into_filename(self) -> Result<Vec<u8>, String> {
        if !self.is_complete() {
            return Err(CORRUPT_FILE_ERROR.to_string());
        }
        // Keep the raw filename bytes; character-level safety is enforced later by
        // safe_recovery_path (has_safe_embedded_filename), and non-UTF-8 names must
        // round-trip byte-for-byte to match the C++ tool.
        Ok(self.filename)
    }
}

fn decrypt_with_secretstream_file_input_chunks<F>(
    encrypted_input_path: &Path,
    key: &secretstream::Key,
    header: &secretstream::Header,
    associated_data: Option<&[u8]>,
    mut consume: F,
) -> Result<bool, String>
where
    F: FnMut(&[u8]) -> Result<(), String>,
{
    const MAX_SECRETSTREAM_FRAME_BYTES: usize = STREAM_CHUNK_SIZE + secretstream::ABYTES;

    let mut input = open_binary_input_or_throw(
        encrypted_input_path,
        "Read Error: Failed to open encrypted stream input.",
    )?;

    let encrypted_input_size = checked_file_size(
        encrypted_input_path,
        "Read Error: Invalid encrypted stream input size.",
        true,
    )?;

    let mut stream = match secretstream::Stream::init_pull(header, key) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };

    let mut left = encrypted_input_size;
    let mut has_final_tag = false;
    let mut cipher_chunk = vec![0u8; MAX_SECRETSTREAM_FRAME_BYTES];

    while left > 0 {
        check_cancellation()?;
        if left < STREAM_FRAME_LEN_BYTES {
            return Ok(false);
        }

        let mut len_buf = [0u8; STREAM_FRAME_LEN_BYTES];
        if input.read_exact(&mut len_buf).is_err() {
            return Ok(false);
        }
        left -= STREAM_FRAME_LEN_BYTES;

        let frame_len = u32::from_be_bytes(len_buf) as usize;
        if frame_len < secretstream::ABYTES
            || frame_len > left
            || frame_len > MAX_SECRETSTREAM_FRAME_BYTES
        {
            return Ok(false);
        }

        if input.read_exact(&mut cipher_chunk[..frame_len]).is_err() {
            return Ok(false);
        }
        left -= frame_len;

        let (plain_chunk, tag) = match stream.pull(&cipher_chunk[..frame_len], associated_data) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        let plain_chunk = Zeroizing::new(plain_chunk);

        if !plain_chunk.is_empty() {
            consume(&plain_chunk[..])?;
        }
        check_cancellation()?;

        if tag == secretstream::Tag::Final {
            has_final_tag = true;
            break;
        }
    }

    if !has_final_tag {
        return Ok(false);
    }

    let mut extra = [0u8; 1];
    let trailing = input
        .read(&mut extra)
        .map_err(|_| "Read Error: Failed while decrypting encrypted payload stream.".to_string())?;

    Ok(trailing == 0)
}

pub(super) struct StageDecryptOutput {
    pub(super) decrypted_filename: Vec<u8>,
    pub(super) output_size: usize,
}

/// Incremental zlib inflater which requires an authenticated stream to contain
/// exactly one complete RFC 1950 stream.  `flate2::write::ZlibDecoder::finish`
/// can return successfully for a truncated checksum, so recovery must inspect
/// the low-level `StreamEnd` status and reject both truncation and trailing data.
struct StreamingInflater<W> {
    decompressor: Decompress,
    output: W,
    output_buf: Vec<u8>,
    output_size: usize,
    max_output: usize,
    stream_ended: bool,
}

impl<W: Write> StreamingInflater<W> {
    fn new(output: W, max_output: usize) -> Self {
        Self {
            decompressor: Decompress::new(true),
            output,
            output_buf: vec![0u8; 2 * 1024 * 1024],
            output_size: 0,
            max_output,
            stream_ended: false,
        }
    }

    fn consume(&mut self, mut input: &[u8]) -> Result<(), String> {
        if input.is_empty() {
            return Ok(());
        }
        if self.stream_ended {
            return Err("zlib inflate error: trailing compressed data".to_string());
        }

        loop {
            check_cancellation()?;
            let before_in = self.decompressor.total_in();
            let before_out = self.decompressor.total_out();
            let status = self
                .decompressor
                .decompress(input, &mut self.output_buf, FlushDecompress::None)
                .map_err(|_| "zlib inflate error: inflate failed".to_string())?;

            let consumed = usize::try_from(self.decompressor.total_in() - before_in)
                .map_err(|_| "zlib inflate error: input size overflow".to_string())?;
            let produced = usize::try_from(self.decompressor.total_out() - before_out)
                .map_err(|_| "zlib inflate error: output size overflow".to_string())?;

            let next_size = self
                .output_size
                .checked_add(produced)
                .ok_or_else(|| "zlib inflate error: output exceeds safe size limit".to_string())?;
            if next_size > self.max_output {
                return Err("zlib inflate error: output exceeds safe size limit".to_string());
            }
            if produced > 0 {
                self.output
                    .write_all(&self.output_buf[..produced])
                    .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;
                self.output_size = next_size;
            }

            input = &input[consumed..];
            if status == Status::StreamEnd {
                self.stream_ended = true;
                if !input.is_empty() {
                    return Err("zlib inflate error: trailing compressed data".to_string());
                }
                return Ok(());
            }

            if consumed == 0 && produced == 0 {
                if input.is_empty() {
                    return Ok(());
                }
                return Err("zlib inflate error: inflate made no progress".to_string());
            }

            // A full output buffer can mean more output is pending even after all
            // caller input was consumed. Drain that pending output with an empty
            // input slice; otherwise wait for the next authenticated frame.
            if input.is_empty() && produced < self.output_buf.len() {
                return Ok(());
            }
        }
    }

    fn finish(mut self) -> Result<(W, usize), String> {
        if !self.stream_ended {
            return Err("zlib inflate error: compressed stream is truncated".to_string());
        }
        self.output
            .flush()
            .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;
        Ok((self.output, self.output_size))
    }
}

pub(super) fn decrypt_ciphertext_to_stage_file(
    cipher_stage_path: &Path,
    stream_stage_path: &Path,
    key: &secretstream::Key,
    header: &secretstream::Header,
    metadata_version: KdfMetadataVersion,
    is_data_compressed: bool,
) -> Result<Option<StageDecryptOutput>, String> {
    let mut prefix_extractor = FilenamePrefixExtractor::new();
    let mode_data = [stream_mode_byte(is_data_compressed)];
    let associated_data = if metadata_version == KdfMetadataVersion::V3SecretstreamAuthenticatedMode
    {
        Some(mode_data.as_slice())
    } else {
        None
    };

    if is_data_compressed {
        let output_file = open_binary_output_for_write_or_throw(stream_stage_path)?;
        let mut inflater =
            StreamingInflater::new(BufWriter::new(output_file), STREAM_INFLATE_MAX_OUTPUT);

        let ok = decrypt_with_secretstream_file_input_chunks(
            cipher_stage_path,
            key,
            header,
            associated_data,
            |chunk| {
                prefix_extractor.consume(chunk, |payload_chunk| inflater.consume(payload_chunk))
            },
        )?;

        if !ok || !prefix_extractor.is_complete() {
            return Ok(None);
        }

        let (_writer, output_size) = inflater.finish()?;

        // Re-check the staged file after flushing so its physical length agrees
        // with the inflater's bounded output accounting.
        let staged_size = checked_file_size(
            stream_stage_path,
            "Zlib Compression Error: Output file is empty. Inflating file failed.",
            true,
        )?;
        if staged_size != output_size {
            return Err("zlib inflate error: output size mismatch".to_string());
        }

        return Ok(Some(StageDecryptOutput {
            decrypted_filename: prefix_extractor.into_filename()?,
            output_size,
        }));
    }

    let output_file = open_binary_output_for_write_or_throw(stream_stage_path)?;
    let mut output = BufWriter::new(output_file);
    let mut output_size = 0usize;

    let ok = decrypt_with_secretstream_file_input_chunks(
        cipher_stage_path,
        key,
        header,
        associated_data,
        |chunk| {
            prefix_extractor.consume(chunk, |payload_chunk| {
                output
                    .write_all(payload_chunk)
                    .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;
                output_size = output_size
                    .checked_add(payload_chunk.len())
                    .ok_or_else(|| {
                        "File Size Error: Decrypted output size overflow.".to_string()
                    })?;
                Ok(())
            })
        },
    )?;

    if !ok || !prefix_extractor.is_complete() {
        return Ok(None);
    }

    output
        .flush()
        .map_err(|_| WRITE_COMPLETE_ERROR.to_string())?;

    if output_size == 0 {
        return Err("File Extraction Error: Output file is empty.".to_string());
    }

    Ok(Some(StageDecryptOutput {
        decrypted_filename: prefix_extractor.into_filename()?,
        output_size,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn bounded_inflate_writer_rejects_oversize() {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;

        let mut compressed = ZlibEncoder::new(Vec::new(), Compression::default());
        compressed.write_all(b"123456789").unwrap();
        let compressed = compressed.finish().unwrap();

        let mut inflater = StreamingInflater::new(Cursor::new(Vec::new()), 8);
        let err = inflater.consume(&compressed).expect_err("over limit");
        assert!(err.contains("exceeds safe size limit"));
    }

    #[test]
    fn streaming_inflater_rejects_missing_checksum_and_trailing_data() {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(b"authenticated compressed payload")
            .unwrap();
        let compressed = encoder.finish().unwrap();

        let mut truncated = StreamingInflater::new(Cursor::new(Vec::new()), 1024);
        truncated
            .consume(&compressed[..compressed.len() - 1])
            .unwrap();
        assert!(truncated.finish().unwrap_err().contains("truncated"));

        let mut with_trailing = StreamingInflater::new(Cursor::new(Vec::new()), 1024);
        let mut bytes = compressed;
        bytes.push(0);
        assert!(with_trailing
            .consume(&bytes)
            .unwrap_err()
            .contains("trailing"));
    }

    #[test]
    fn filename_prefix_extractor_splits_name_and_payload() {
        let mut ext = FilenamePrefixExtractor::new();
        let mut payload = Vec::new();
        ext.consume(b"\x04namePAYLOAD", |p| {
            payload.extend_from_slice(p);
            Ok(())
        })
        .expect("consume");
        assert!(ext.is_complete());
        assert_eq!(ext.into_filename().unwrap(), b"name");
        assert_eq!(payload, b"PAYLOAD");
    }
}
