//! Port of the C++ streaming output sink (file_utils.cpp OutputFile) and the
//! no-replace staged-commit + sendfile-backed PayloadSource (segmentation.cpp).

use crate::paths::{
    unique_randomized_path_or_throw, unique_randomized_path_or_throw_with_token_len,
};
use crate::signal::check_cancellation;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const SENDFILE_MAX: usize = 0x7fff_f000; // Linux per-call cap (~2 GiB)

/// Buffered, fd-backed output sink. Mirrors C++ file_utils OutputFile:
/// O_EXCL | 0600 create, an internal buffer that coalesces small header writes,
/// and `send_from` that streams a region of another fd via sendfile(2) with a
/// pread/write fallback.
pub struct OutputFile {
    file: File,
    buffer: Vec<u8>,
    fill: usize,
}

impl OutputFile {
    pub fn create(path: &Path, buffer_capacity: usize) -> Result<OutputFile, String> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true) // O_CREAT | O_EXCL
            .mode(0o600)
            .open(path)
            .map_err(|_| {
                "Write Error: Unable to create output file. Make sure you have WRITE permissions for this location.".to_string()
            })?;
        Ok(OutputFile {
            file,
            buffer: vec![0u8; buffer_capacity.max(1)],
            fill: 0,
        })
    }

    fn write_raw(&mut self, mut data: &[u8], err: &str) -> Result<(), String> {
        while !data.is_empty() {
            check_cancellation()?;
            match self.file.write(data) {
                Ok(0) => return Err(err.to_string()),
                Ok(n) => data = &data[n..],
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(err.to_string()),
            }
        }
        Ok(())
    }

    fn drain(&mut self, err: &str) -> Result<(), String> {
        if self.fill == 0 {
            return Ok(());
        }
        let buf = std::mem::take(&mut self.buffer);
        let res = self.write_raw(&buf[..self.fill], err);
        self.buffer = buf;
        self.fill = 0;
        res
    }

    pub fn write(&mut self, bytes: &[u8], err: &str) -> Result<(), String> {
        if bytes.is_empty() {
            return Ok(());
        }
        check_cancellation()?;
        if bytes.len() >= self.buffer.len() {
            self.drain(err)?;
            return self.write_raw(bytes, err);
        }
        if self.fill + bytes.len() > self.buffer.len() {
            self.drain(err)?;
        }
        self.buffer[self.fill..self.fill + bytes.len()].copy_from_slice(bytes);
        self.fill += bytes.len();
        Ok(())
    }

    /// Zero-copy append of `length` bytes from `in_fd` at `in_offset`.
    pub fn send_from(
        &mut self,
        in_fd: i32,
        in_offset: usize,
        length: usize,
        err: &str,
    ) -> Result<(), String> {
        self.drain(err)?; // buffered bytes must land before the streamed region
        let out_fd = self.file.as_raw_fd();
        let mut offset = in_offset as libc::off_t;
        let mut left = length;
        while left > 0 {
            check_cancellation()?;
            let want = left.min(SENDFILE_MAX);
            // SAFETY: valid fds; offset updated by the kernel.
            let n = unsafe { libc::sendfile(out_fd, in_fd, &mut offset, want) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                let raw = e.raw_os_error().unwrap_or(0);
                if (raw == libc::EINVAL || raw == libc::ENOSYS) && left == length {
                    return self.send_from_fallback(in_fd, in_offset, length, err);
                }
                return Err(err.to_string());
            }
            if n == 0 {
                return Err(err.to_string()); // unexpected EOF
            }
            left -= n as usize;
        }
        Ok(())
    }

    fn send_from_fallback(
        &mut self,
        in_fd: i32,
        in_offset: usize,
        length: usize,
        err: &str,
    ) -> Result<(), String> {
        let mut off = in_offset as libc::off_t;
        let mut left = length;
        let mut buf = std::mem::take(&mut self.buffer);
        let cap = buf.len();
        let res = (|| {
            while left > 0 {
                check_cancellation()?;
                let want = left.min(cap);
                let mut got_total = 0usize;
                while got_total < want {
                    check_cancellation()?;
                    // SAFETY: valid fd; reading into owned buffer region.
                    let got = unsafe {
                        libc::pread(
                            in_fd,
                            buf.as_mut_ptr().add(got_total) as *mut libc::c_void,
                            want - got_total,
                            off + got_total as libc::off_t,
                        )
                    };
                    if got < 0 {
                        if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                            continue;
                        }
                        return Err(err.to_string());
                    }
                    if got == 0 {
                        return Err(err.to_string());
                    }
                    got_total += got as usize;
                }
                // can't call self.write_raw while buffer is taken; write directly
                let mut data = &buf[..want];
                while !data.is_empty() {
                    check_cancellation()?;
                    match self.file.write(data) {
                        Ok(0) => return Err(err.to_string()),
                        Ok(n) => data = &data[n..],
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => return Err(err.to_string()),
                    }
                }
                off += want as libc::off_t;
                left -= want;
            }
            Ok(())
        })();
        self.buffer = buf;
        res
    }

    pub fn close(mut self, err: &str) -> Result<(), String> {
        check_cancellation()?;
        self.drain(err)?;
        self.file.flush().map_err(|_| err.to_string())?;
        check_cancellation()
    }
}

/// No-clobber commit: hardlink staged->dest (atomic, won't replace), else fall
/// back to an O_EXCL copy. Returns Ok(false) if dest already exists.
/// Mirrors C++ tryCommitStagedFileNoReplace.
pub fn commit_staged_file_no_replace(
    staged: &Path,
    dest: &Path,
    err: &str,
) -> Result<bool, String> {
    check_cancellation()?;
    match std::fs::hard_link(staged, dest) {
        Ok(()) => {
            let _ = std::fs::remove_file(staged);
            Ok(true)
        }
        Err(e) => {
            if e.kind() == io::ErrorKind::AlreadyExists && dest.exists() {
                return Ok(false);
            }
            // cross-device or unsupported: copy with O_EXCL
            copy_file_no_replace(staged, dest, err)
        }
    }
}

fn copy_file_no_replace(source: &Path, dest: &Path, err: &str) -> Result<bool, String> {
    let mut input = File::open(source).map_err(|_| err.to_string())?;
    let mut output = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dest)
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
        Err(_) => return Err(err.to_string()),
    };
    let mut buf = vec![0u8; 2 * 1024 * 1024];
    let copy = (|| {
        loop {
            check_cancellation()?;
            let got = input.read(&mut buf).map_err(|_| err.to_string())?;
            if got == 0 {
                break;
            }
            output.write_all(&buf[..got]).map_err(|_| err.to_string())?;
        }
        output.flush().map_err(|_| err.to_string())
    })();
    if copy.is_err() {
        let _ = std::fs::remove_file(dest);
        return Err(err.to_string());
    }
    let _ = std::fs::remove_file(source);
    Ok(true)
}

/// A fully written image which is still hidden under a temporary name.  The
/// caller must deliver and flush the recovery PIN before calling `commit`.
pub struct StagedOutput {
    output_path: PathBuf,
    staged_path: PathBuf,
    active: bool,
}

impl StagedOutput {
    pub fn output_path(&self) -> &Path {
        &self.output_path
    }

    pub fn commit(mut self) -> Result<PathBuf, String> {
        check_cancellation()?;
        if !commit_staged_file_no_replace(
            &self.staged_path,
            &self.output_path,
            "Write File Error: Failed to commit output image",
        )? {
            return Err(
                "Write File Error: Failed to commit output image: output file already exists"
                    .to_string(),
            );
        }
        self.active = false;
        Ok(self.output_path.clone())
    }
}

impl Drop for StagedOutput {
    fn drop(&mut self) {
        if self.active {
            let _ = std::fs::remove_file(&self.staged_path);
        }
    }
}

/// A two-part payload source: an in-memory template prefix, then the encrypted
/// file streamed via sendfile. Mirrors C++ segmentation.cpp PayloadSource.
pub struct PayloadSource<'a> {
    template: &'a [u8],
    template_offset: usize,
    encrypted_fd: i32,
    encrypted_offset: usize,
    encrypted_left: usize,
}

impl<'a> PayloadSource<'a> {
    /// `encrypted_fd` must stay open (its File kept alive) for this struct's lifetime.
    pub fn new(template: &'a [u8], encrypted_fd: i32, encrypted_size: usize) -> PayloadSource<'a> {
        PayloadSource {
            template,
            template_offset: 0,
            encrypted_fd,
            encrypted_offset: 0,
            encrypted_left: encrypted_size,
        }
    }

    /// Append exactly `size` payload bytes to `out`: template prefix first
    /// (buffered), then the encrypted-file remainder via sendfile.
    pub fn copy_to(&mut self, out: &mut OutputFile, size: usize, err: &str) -> Result<(), String> {
        let mut left = size;
        if self.template_offset < self.template.len() {
            let take = left.min(self.template.len() - self.template_offset);
            out.write(
                &self.template[self.template_offset..self.template_offset + take],
                err,
            )?;
            self.template_offset += take;
            left -= take;
        }
        if left > 0 {
            if left > self.encrypted_left {
                return Err("Read Error: Encrypted payload is shorter than expected.".to_string());
            }
            out.send_from(self.encrypted_fd, self.encrypted_offset, left, err)?;
            self.encrypted_offset += left;
            self.encrypted_left -= left;
        }
        Ok(())
    }

    pub fn exhausted(&self) -> bool {
        self.template_offset == self.template.len() && self.encrypted_left == 0
    }
}

/// Create a unique output path, write to a hidden staged sibling via OutputFile,
/// then atomically commit no-replace. Mirrors C++ conceal.cpp writeToStagedOutput.
pub fn write_to_uncommitted_staged_output<F>(
    parent_dir: &Path,
    out_prefix: &str,
    out_suffix: &str,
    out_token_hex: usize,
    buffer_capacity: usize,
    write_fn: F,
) -> Result<StagedOutput, String>
where
    F: FnOnce(&mut OutputFile) -> Result<(), String>,
{
    const MAX_PATH_ATTEMPTS: usize = 1024;
    let output_path = unique_randomized_path_or_throw_with_token_len(
        parent_dir,
        out_prefix,
        out_suffix,
        MAX_PATH_ATTEMPTS,
        "Write File Error: Could not create a unique output filename.",
        out_token_hex,
    )?;
    let base = output_path
        .file_name()
        .map(|v| v.to_string_lossy().into_owned())
        .unwrap_or_else(|| "output".into());
    let tmp_prefix = format!(".{base}.jdvrif_tmp_");
    let staged = unique_randomized_path_or_throw(
        output_path.parent().unwrap_or(Path::new("")),
        &tmp_prefix,
        "",
        MAX_PATH_ATTEMPTS,
        "Write File Error: Could not create a temporary output filename.",
    )?;

    let run = (|| -> Result<(), String> {
        let mut out = OutputFile::create(&staged, buffer_capacity)?;
        write_fn(&mut out)?;
        out.close("Write File Error: Failed to write complete output file.")?;
        Ok(())
    })();
    if run.is_err() {
        let _ = std::fs::remove_file(&staged);
    }
    run?;
    Ok(StagedOutput {
        output_path,
        staged_path: staged,
        active: true,
    })
}

pub fn write_to_staged_output<F>(
    parent_dir: &Path,
    out_prefix: &str,
    out_suffix: &str,
    out_token_hex: usize,
    buffer_capacity: usize,
    write_fn: F,
) -> Result<PathBuf, String>
where
    F: FnOnce(&mut OutputFile) -> Result<(), String>,
{
    write_to_uncommitted_staged_output(
        parent_dir,
        out_prefix,
        out_suffix,
        out_token_hex,
        buffer_capacity,
        write_fn,
    )?
    .commit()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::randombytes;
    use std::path::PathBuf;

    fn tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("jrif_of_{}_{}", name, hex8()));
        p
    }
    fn hex8() -> String {
        randombytes(4)
            .expect("random")
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    #[test]
    fn buffered_writes_and_sendfrom_preserve_byte_order() {
        let src_path = tmp("src");
        std::fs::write(&src_path, b"PAYLOAD-BYTES-1234567890").unwrap();
        let src = File::open(&src_path).unwrap();

        let out_path = tmp("out");
        let mut out = OutputFile::create(&out_path, 8).unwrap(); // tiny buffer forces drains
        out.write(b"HEADER:", "w").unwrap();
        // stream bytes [8, 8+8) of the source via sendfile, between buffered writes
        out.send_from(src.as_raw_fd(), 8, 8, "s").unwrap();
        out.write(b":TAIL", "w").unwrap();
        out.close("c").unwrap();

        let got = std::fs::read(&out_path).unwrap();
        assert_eq!(got, b"HEADER:BYTES-12:TAIL");
        std::fs::remove_file(&src_path).ok();
        std::fs::remove_file(&out_path).ok();
    }

    #[test]
    fn create_fails_if_path_exists() {
        let p = tmp("excl");
        std::fs::write(&p, b"x").unwrap();
        assert!(OutputFile::create(&p, 1024).is_err());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn payload_source_emits_template_prefix_then_streams_encrypted() {
        let enc = tmp("enc");
        std::fs::write(&enc, b"ENCRYPTED-TAIL-BYTES").unwrap();
        let enc_f = File::open(&enc).unwrap();

        let out_path = tmp("ps_out");
        let mut out = OutputFile::create(&out_path, 4).unwrap(); // tiny buffer
        let template = b"TPL".to_vec();
        let mut ps = PayloadSource::new(
            &template,
            enc_f.as_raw_fd(),
            enc_f.metadata().unwrap().len() as usize,
        );
        ps.copy_to(&mut out, 3, "e").unwrap(); // drains template
        ps.copy_to(&mut out, 6, "e").unwrap(); // streams 6 encrypted bytes
        out.close("c").unwrap();
        assert_eq!(std::fs::read(&out_path).unwrap(), b"TPLENCRYP");
        assert!(!ps.exhausted()); // 14 encrypted bytes still unsent
        std::fs::remove_file(&enc).ok();
        std::fs::remove_file(&out_path).ok();
    }

    #[test]
    fn write_to_staged_output_creates_unique_committed_file() {
        let dir = std::env::temp_dir();
        let final_path = write_to_staged_output(&dir, "jrif_", ".jpg", 9, 1024, |f| {
            f.write(b"HELLO-STAGED", "w")
        })
        .unwrap();
        assert!(final_path.exists());
        assert_eq!(std::fs::read(&final_path).unwrap(), b"HELLO-STAGED");
        let name = final_path.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with("jrif_") && name.ends_with(".jpg"));
        std::fs::remove_file(&final_path).ok();
    }

    #[test]
    fn commit_no_replace_moves_when_absent_and_refuses_when_present() {
        let staged = tmp("staged");
        std::fs::write(&staged, b"DATA").unwrap();
        let dest = tmp("dest");

        // absent dest -> commit succeeds, staged consumed
        assert!(commit_staged_file_no_replace(&staged, &dest, "e").unwrap());
        assert_eq!(std::fs::read(&dest).unwrap(), b"DATA");
        assert!(!staged.exists());

        // present dest -> refuses (returns Ok(false)), leaves dest intact
        let staged2 = tmp("staged2");
        std::fs::write(&staged2, b"OTHER").unwrap();
        assert!(!commit_staged_file_no_replace(&staged2, &dest, "e").unwrap());
        assert_eq!(std::fs::read(&dest).unwrap(), b"DATA");
        std::fs::remove_file(&staged2).ok();
        std::fs::remove_file(&dest).ok();
    }
}
