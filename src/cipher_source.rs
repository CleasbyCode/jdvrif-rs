//! Sequential readers over a recovery ciphertext of known length, read straight
//! from wherever it already lives (the cover image, or a decoded carrier) so it
//! is never copied to a staging file first. The decryptor pulls frames as it
//! authenticates them, so a wrong PIN is rejected after the first frame.
//! Mirrors C++ `cipher_source.h`.

use crate::signal::check_cancellation;
use std::fs::File;
use std::os::unix::fs::FileExt;

pub(crate) trait CipherSource {
    fn remaining(&self) -> usize;

    /// Fills `out` and returns `Ok(true)`, or returns `Ok(false)` (reading
    /// nothing) when fewer than `out.len()` bytes remain. I/O failures are errors.
    fn try_read(&mut self, out: &mut [u8]) -> Result<bool, String>;
}

/// A ciphertext already in memory (Reddit/X-Twitter carriers, Bluesky).
pub(crate) struct MemoryCipherSource {
    data: Vec<u8>,
    position: usize,
}

impl MemoryCipherSource {
    pub(crate) fn new(data: Vec<u8>) -> Self {
        Self { data, position: 0 }
    }
}

impl CipherSource for MemoryCipherSource {
    fn remaining(&self) -> usize {
        self.data.len() - self.position
    }

    fn try_read(&mut self, out: &mut [u8]) -> Result<bool, String> {
        if out.len() > self.remaining() {
            return Ok(false);
        }
        out.copy_from_slice(&self.data[self.position..self.position + out.len()]);
        self.position += out.len();
        Ok(true)
    }
}

/// One stretch of ciphertext in the image file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FileRun {
    pub(crate) offset: usize,
    pub(crate) length: usize,
}

/// Reads the ciphertext out of the image, run by run, with positioned reads.
pub(crate) struct FileRunsCipherSource {
    input: File,
    runs: Vec<FileRun>,
    run_index: usize,
    run_position: usize,
    remaining: usize,
}

const PAYLOAD_READ_ERROR: &str = "Read Error: Failed while extracting encrypted payload.";

impl FileRunsCipherSource {
    pub(crate) fn new(input: File, runs: Vec<FileRun>) -> Self {
        let remaining = runs.iter().map(|run| run.length).sum();
        Self {
            input,
            runs,
            run_index: 0,
            run_position: 0,
            remaining,
        }
    }
}

impl CipherSource for FileRunsCipherSource {
    fn remaining(&self) -> usize {
        self.remaining
    }

    fn try_read(&mut self, mut out: &mut [u8]) -> Result<bool, String> {
        if out.len() > self.remaining {
            return Ok(false);
        }
        self.remaining -= out.len();
        while !out.is_empty() {
            check_cancellation()?;
            let run = self.runs[self.run_index];
            let take = out.len().min(run.length - self.run_position);
            let (now, rest) = out.split_at_mut(take);
            self.input
                .read_exact_at(now, (run.offset + self.run_position) as u64)
                .map_err(|_| PAYLOAD_READ_ERROR.to_string())?;
            out = rest;
            self.run_position += take;
            if self.run_position == run.length {
                self.run_index += 1;
                self.run_position = 0;
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_source_reads_exactly_and_refuses_overreads() {
        let mut source = MemoryCipherSource::new(b"abcdef".to_vec());
        let mut two = [0u8; 2];
        assert!(source.try_read(&mut two).unwrap());
        assert_eq!(&two, b"ab");
        let mut five = [0u8; 5];
        assert!(!source.try_read(&mut five).unwrap());
        assert_eq!(source.remaining(), 4);
        let mut four = [0u8; 4];
        assert!(source.try_read(&mut four).unwrap());
        assert_eq!(&four, b"cdef");
        assert_eq!(source.remaining(), 0);
    }

    #[test]
    fn file_runs_source_skips_gaps_across_reads() {
        let path = std::env::temp_dir().join(format!(
            "jdvrif_cipher_runs_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, b"..abc###de#f").unwrap();
        let file = File::open(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let runs = vec![
            FileRun {
                offset: 2,
                length: 3,
            },
            FileRun {
                offset: 8,
                length: 2,
            },
            FileRun {
                offset: 11,
                length: 1,
            },
        ];
        let mut source = FileRunsCipherSource::new(file, runs);
        assert_eq!(source.remaining(), 6);
        let mut four = [0u8; 4];
        assert!(source.try_read(&mut four).unwrap());
        assert_eq!(&four, b"abcd");
        let mut three = [0u8; 3];
        assert!(!source.try_read(&mut three).unwrap());
        let mut two = [0u8; 2];
        assert!(source.try_read(&mut two).unwrap());
        assert_eq!(&two, b"ef");
        assert_eq!(source.remaining(), 0);
    }
}
