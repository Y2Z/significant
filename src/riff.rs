//! Removes a manifest from RIFF files (WAV, AVI, WebP), using only the
//! standard library. C2PA stores it in a top-level `C2PA` chunk.

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};

const CHUNK_ID: &[u8; 4] = b"C2PA";
const COPY_CHUNK: usize = 1 << 20;

#[derive(Debug)]
pub enum RiffError {
    Io(io::Error),
    Malformed(&'static str),
    Unsupported(&'static str),
}

impl fmt::Display for RiffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Malformed(detail) => write!(f, "malformed RIFF file: {detail}"),
            Self::Unsupported(detail) => write!(f, "unsupported RIFF layout: {detail}"),
        }
    }
}

impl std::error::Error for RiffError {}

impl From<io::Error> for RiffError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Removes the `C2PA` chunk. Returns `false` if there is none.
pub fn remove_manifest(f: &mut File) -> Result<bool, RiffError> {
    let file_len = f.seek(SeekFrom::End(0))?;
    let mut head = [0; 12];
    f.seek(SeekFrom::Start(0))?;
    f.read_exact(&mut head)
        .map_err(|_| RiffError::Malformed("file is too short"))?;
    if &head[..4] != b"RIFF" {
        return Err(RiffError::Unsupported("file does not start with RIFF"));
    }
    let riff_size = u64::from(u32::from_le_bytes([head[4], head[5], head[6], head[7]]));
    let end = 8 + riff_size;
    if end > file_len {
        return Err(RiffError::Malformed(
            "RIFF size is past the end of the file",
        ));
    }

    let mut found = None;
    let mut position = 12;
    while position + 8 <= end {
        let mut header = [0; 8];
        f.seek(SeekFrom::Start(position))?;
        f.read_exact(&mut header)?;
        let size = u64::from(u32::from_le_bytes([
            header[4], header[5], header[6], header[7],
        ]));
        let mut next = position + 8 + size + (size & 1);
        if next == end + 1 {
            next = end; // the last chunk may omit its pad byte
        }
        if next > end {
            return Err(RiffError::Malformed("chunk extends past the RIFF data"));
        }
        if &header[..4] == CHUNK_ID {
            if found.is_some() {
                return Err(RiffError::Unsupported("more than one manifest chunk"));
            }
            found = Some(position..next);
        }
        position = next;
    }
    let Some(chunk) = found else {
        return Ok(false);
    };

    let removed = chunk.end - chunk.start;
    let mut buffer = vec![0; COPY_CHUNK];
    let (mut from, mut to) = (chunk.end, chunk.start);
    while from < file_len {
        f.seek(SeekFrom::Start(from))?;
        let read = f.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        f.seek(SeekFrom::Start(to))?;
        f.write_all(&buffer[..read])?;
        from += read as u64;
        to += read as u64;
    }
    f.set_len(file_len - removed)?;
    f.seek(SeekFrom::Start(4))?;
    f.write_all(&((riff_size - removed) as u32).to_le_bytes())?;
    f.flush()?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(id: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut out = id.to_vec();
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
        if data.len() % 2 == 1 {
            out.push(0);
        }
        out
    }

    fn riff(chunks: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = chunks.concat();
        let mut out = b"RIFF".to_vec();
        out.extend_from_slice(&(body.len() as u32 + 4).to_le_bytes());
        out.extend_from_slice(b"WAVE");
        out.extend(body);
        out
    }

    fn temp(bytes: &[u8], name: &str) -> (std::path::PathBuf, File) {
        let path =
            std::env::temp_dir().join(format!("significant-riff-{}-{name}", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        let file = File::options().read(true).write(true).open(&path).unwrap();
        (path, file)
    }

    #[test]
    fn removal_restores_exact_bytes_wherever_the_chunk_is() {
        let (a, b) = (chunk(b"fmt ", b"abcd"), chunk(b"data", b"odd"));
        let store = chunk(b"C2PA", b"manifest!");
        let original = riff(&[a.clone(), b.clone()]);
        for (index, signed) in [
            riff(&[a.clone(), b.clone(), store.clone()]),
            riff(&[a.clone(), store.clone(), b.clone()]),
            riff(&[store.clone(), a.clone(), b.clone()]),
        ]
        .iter()
        .enumerate()
        {
            let (path, mut file) = temp(signed, &format!("place{index}"));
            assert!(remove_manifest(&mut file).unwrap());
            drop(file);
            assert_eq!(std::fs::read(&path).unwrap(), original, "case {index}");
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn data_after_the_riff_is_kept() {
        let mut signed = riff(&[chunk(b"data", b"ab"), chunk(b"C2PA", b"store")]);
        let mut original = riff(&[chunk(b"data", b"ab")]);
        signed.extend_from_slice(b"RIFFextra");
        original.extend_from_slice(b"RIFFextra");
        let (path, mut file) = temp(&signed, "tail");
        assert!(remove_manifest(&mut file).unwrap());
        drop(file);
        assert_eq!(std::fs::read(&path).unwrap(), original);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn missing_chunk_changes_nothing() {
        let original = riff(&[chunk(b"data", b"ab")]);
        let (path, mut file) = temp(&original, "none");
        assert!(!remove_manifest(&mut file).unwrap());
        drop(file);
        assert_eq!(std::fs::read(&path).unwrap(), original);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn bad_files_are_rejected() {
        let (path, mut file) = temp(b"not riff at all", "bad");
        assert!(remove_manifest(&mut file).is_err());
        drop(file);
        std::fs::remove_file(path).unwrap();

        let mut huge = riff(&[chunk(b"data", b"ab")]);
        huge[16] = 0xFF;
        let (path, mut file) = temp(&huge, "huge");
        assert!(remove_manifest(&mut file).is_err());
        drop(file);
        std::fs::remove_file(path).unwrap();

        let original = riff(&[
            chunk(b"data", b"ab"),
            chunk(b"C2PA", b"one"),
            chunk(b"C2PA", b"two"),
        ]);
        let (path, mut file) = temp(&original, "twice");
        assert!(remove_manifest(&mut file).is_err());
        drop(file);
        std::fs::remove_file(path).unwrap();
    }
}
