//! Stores a manifest in ZIP and TAR-family archives, using only the standard
//! library.
//!
//! ZIP uses a stored `META-INF/content_credential.c2pa` entry, the location
//! C2PA defines. TAR flavors append a frame after the archive, which leaves
//! every original byte in place and needs no recompression:
//!
//! - `.tar`: an ordinary entry after the end-of-archive blocks
//! - `.tar.gz`: a gzip member holding one stored block
//! - `.tar.xz`: an xz stream holding one uncompressed LZMA2 chunk
//! - `.tar.zst`: a zstd skippable frame
//!
//! `tar` stops at the end-of-archive blocks, so it does not extract the frame.

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::Range;

pub const ZIP_MANIFEST_PATH: &str = "META-INF/content_credential.c2pa";
const FRAME_NAME: &str = "significant.c2pa";
const MAX_PAYLOAD: usize = 0xFFFF;
const MAX_CENTRAL_DIRECTORY: u64 = 256 * 1024 * 1024;
const BLOCK: usize = 512;

const EOCD_SIGNATURE: &[u8] = b"PK\x05\x06";
const EOCD_LEN: usize = 22;
const CENTRAL_SIGNATURE: &[u8] = b"PK\x01\x02";
const CENTRAL_LEN: usize = 46;
const LOCAL_SIGNATURE: &[u8] = b"PK\x03\x04";
const LOCAL_LEN: usize = 30;

const GZIP_MAGIC: &[u8] = b"\x1F\x8B";
const XZ_MAGIC: &[u8] = b"\xFD7zXZ\0";
const ZSTD_MAGIC: &[u8] = b"\x28\xB5\x2F\xFD";
const ZSTD_SKIPPABLE: u32 = 0x184D_2A5C;
const ZSTD_TAG: &[u8] = b"SIGNIFIC";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Zip,
    Tar,
    TarGz,
    TarXz,
    TarZst,
}

impl Kind {
    /// Finds the archive type from a file name, ignoring case.
    pub fn from_name(name: &str) -> Option<(Self, &'static str)> {
        const SUFFIXES: &[(&str, Kind)] = &[
            (".tar.gz", Kind::TarGz),
            (".tgz", Kind::TarGz),
            (".tar.xz", Kind::TarXz),
            (".txz", Kind::TarXz),
            (".tar.zst", Kind::TarZst),
            (".tzst", Kind::TarZst),
            (".tar", Kind::Tar),
            (".zip", Kind::Zip),
        ];
        let name = name.to_ascii_lowercase();
        SUFFIXES
            .iter()
            .find(|(suffix, _)| name.ends_with(suffix))
            .map(|(suffix, kind)| (*kind, *suffix))
    }

    pub fn media_type(self) -> &'static str {
        match self {
            Self::Zip => "application/zip",
            Self::Tar => "application/x-tar",
            Self::TarGz => "application/gzip",
            Self::TarXz => "application/x-xz",
            Self::TarZst => "application/zstd",
        }
    }

    fn magic(self) -> &'static [u8] {
        match self {
            Self::Zip | Self::Tar => b"",
            Self::TarGz => GZIP_MAGIC,
            Self::TarXz => XZ_MAGIC,
            Self::TarZst => ZSTD_MAGIC,
        }
    }
}

#[derive(Debug)]
pub enum ArchiveError {
    Io(io::Error),
    Malformed(&'static str),
    Unsupported(&'static str),
    AlreadyPresent,
    TooLarge(usize),
    PayloadSize { expected: u64, got: u64 },
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Malformed(detail) => write!(f, "malformed archive: {detail}"),
            Self::Unsupported(detail) => write!(f, "unsupported archive layout: {detail}"),
            Self::AlreadyPresent => f.write_str("archive already contains a manifest"),
            Self::TooLarge(len) => write!(f, "manifest of {len} bytes is too large"),
            Self::PayloadSize { expected, got } => {
                write!(f, "replacement payload is {got} bytes, expected {expected}")
            }
        }
    }
}

impl std::error::Error for ArchiveError {}

impl From<io::Error> for ArchiveError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

type Result<T> = std::result::Result<T, ArchiveError>;

/// Location of a manifest and of the bytes that depend on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Embedded {
    /// The manifest bytes.
    pub payload: Range<u64>,
    /// Ranges to leave out of the content hash, in file order.
    pub exclusions: Vec<Range<u64>>,
    kind: Kind,
}

/// Adds `placeholder` to the archive.
pub fn embed_placeholder<F: Read + Write + Seek>(
    kind: Kind,
    f: &mut F,
    placeholder: &[u8],
) -> Result<Embedded> {
    if placeholder.len() > MAX_PAYLOAD {
        return Err(ArchiveError::TooLarge(placeholder.len()));
    }
    if find(kind, f)?.is_some() {
        return Err(ArchiveError::AlreadyPresent);
    }
    check_magic(kind, f)?;
    match kind {
        Kind::Zip => zip_embed(f, placeholder),
        _ => trailer_embed(kind, f, placeholder),
    }
}

/// Overwrites the placeholder with a final manifest of the same size.
pub fn write_payload<F: Write + Seek>(f: &mut F, at: &Embedded, payload: &[u8]) -> Result<()> {
    let expected = at.payload.end - at.payload.start;
    if payload.len() as u64 != expected {
        return Err(ArchiveError::PayloadSize {
            expected,
            got: payload.len() as u64,
        });
    }
    if at.kind == Kind::Zip {
        f.seek(SeekFrom::Start(at.payload.start))?;
        f.write_all(payload)?;
        let crc = crc32(payload).to_le_bytes();
        for field in [&at.exclusions[0], &at.exclusions[2]] {
            f.seek(SeekFrom::Start(field.start))?;
            f.write_all(&crc)?;
        }
    } else {
        f.seek(SeekFrom::Start(at.exclusions[0].start))?;
        f.write_all(&frame(at.kind, payload))?;
    }
    f.flush()?;
    Ok(())
}

/// Returns the stored manifest and its location, if present.
pub fn read_payload<R: Read + Seek>(kind: Kind, r: &mut R) -> Result<Option<(Vec<u8>, Embedded)>> {
    let Some(at) = find(kind, r)? else {
        return Ok(None);
    };
    r.seek(SeekFrom::Start(at.payload.start))?;
    let mut payload = vec![0; (at.payload.end - at.payload.start) as usize];
    r.read_exact(&mut payload)?;
    Ok(Some((payload, at)))
}

/// Removes the manifest. Returns `false` if there is none.
pub fn remove(kind: Kind, f: &mut File) -> Result<bool> {
    let Some(at) = find(kind, f)? else {
        return Ok(false);
    };
    match kind {
        Kind::Zip => zip_remove(f)?,
        _ => f.set_len(at.exclusions[0].start)?,
    }
    f.flush()?;
    Ok(true)
}

fn find<R: Read + Seek>(kind: Kind, r: &mut R) -> Result<Option<Embedded>> {
    match kind {
        Kind::Zip => zip_find(r),
        _ => trailer_find(kind, r),
    }
}

fn check_magic<R: Read + Seek>(kind: Kind, r: &mut R) -> Result<()> {
    let magic = kind.magic();
    let mut head = vec![0; magic.len()];
    r.seek(SeekFrom::Start(0))?;
    r.read_exact(&mut head)
        .map_err(|_| ArchiveError::Malformed("file is too short"))?;
    if head != magic {
        return Err(ArchiveError::Malformed(
            "contents do not match the file name",
        ));
    }
    Ok(())
}

// Appended frames

fn trailer_embed<F: Read + Write + Seek>(
    kind: Kind,
    f: &mut F,
    placeholder: &[u8],
) -> Result<Embedded> {
    let start = f.seek(SeekFrom::End(0))?;
    if kind == Kind::Tar {
        if start < 1024 || !start.is_multiple_of(BLOCK as u64) {
            return Err(ArchiveError::Malformed("not a whole number of TAR blocks"));
        }
        let mut end = [0; 1024];
        f.seek(SeekFrom::Start(start - 1024))?;
        f.read_exact(&mut end)?;
        if end.iter().any(|byte| *byte != 0) {
            return Err(ArchiveError::Unsupported(
                "TAR has no end-of-archive blocks",
            ));
        }
    }
    let bytes = frame(kind, placeholder);
    f.seek(SeekFrom::Start(start))?;
    f.write_all(&bytes)?;
    f.flush()?;
    Ok(frame_location(kind, start, placeholder.len()))
}

fn frame_location(kind: Kind, start: u64, payload_len: usize) -> Embedded {
    let payload = start + payload_offset(kind) as u64;
    let whole_frame = start..start + frame_len(kind, payload_len) as u64;
    Embedded {
        payload: payload..payload + payload_len as u64,
        exclusions: vec![whole_frame],
        kind,
    }
}

fn trailer_find<R: Read + Seek>(kind: Kind, r: &mut R) -> Result<Option<Embedded>> {
    let file_len = r.seek(SeekFrom::End(0))?;
    let window = (frame_len(kind, MAX_PAYLOAD) as u64).min(file_len);
    let base = file_len - window;
    r.seek(SeekFrom::Start(base))?;
    let mut tail = vec![0; window as usize];
    r.read_exact(&mut tail)?;

    let marker = frame_marker(kind);
    for position in 0..tail.len().saturating_sub(marker.len() - 1) {
        if !tail[position..].starts_with(&marker) {
            continue;
        }
        let candidate = &tail[position..];
        if kind == Kind::Tar && !(base + position as u64).is_multiple_of(BLOCK as u64) {
            continue;
        }
        let Some(len) = frame_payload_len(kind, candidate) else {
            continue;
        };
        if len > MAX_PAYLOAD || frame_len(kind, len) != candidate.len() {
            continue;
        }
        let offset = payload_offset(kind);
        if candidate.len() < offset + len {
            continue;
        }
        if frame(kind, &candidate[offset..offset + len]) == candidate {
            return Ok(Some(frame_location(kind, base + position as u64, len)));
        }
    }
    Ok(None)
}

fn frame_marker(kind: Kind) -> Vec<u8> {
    match kind {
        Kind::Tar => {
            let mut name = FRAME_NAME.as_bytes().to_vec();
            name.push(0);
            name
        }
        Kind::TarGz => frame(kind, b"")[..payload_offset(kind) - 5].to_vec(),
        Kind::TarXz => frame(kind, b"")[..12].to_vec(),
        Kind::TarZst => ZSTD_SKIPPABLE.to_le_bytes().to_vec(),
        Kind::Zip => unreachable!("ZIP has no frame"),
    }
}

fn frame_payload_len(kind: Kind, frame: &[u8]) -> Option<usize> {
    match kind {
        Kind::Tar => {
            let field = std::str::from_utf8(frame.get(124..135)?).ok()?;
            usize::from_str_radix(field, 8).ok()
        }
        Kind::TarGz => {
            let at = payload_offset(kind) - 4;
            Some(u16::from_le_bytes(frame.get(at..at + 2)?.try_into().ok()?) as usize)
        }
        Kind::TarXz => {
            let at = payload_offset(kind) - 2;
            let size = u16::from_be_bytes(frame.get(at..at + 2)?.try_into().ok()?);
            Some(size as usize + 1)
        }
        Kind::TarZst => {
            let size = u32::from_le_bytes(frame.get(4..8)?.try_into().ok()?) as usize;
            size.checked_sub(ZSTD_TAG.len())
        }
        Kind::Zip => None,
    }
}

fn payload_offset(kind: Kind) -> usize {
    match kind {
        Kind::Tar => BLOCK,
        Kind::TarGz => 10 + FRAME_NAME.len() + 1 + 5,
        Kind::TarXz => 12 + 12 + 3,
        Kind::TarZst => 8 + ZSTD_TAG.len(),
        Kind::Zip => unreachable!("ZIP has no frame"),
    }
}

fn frame_len(kind: Kind, payload_len: usize) -> usize {
    frame(kind, &vec![0; payload_len]).len()
}

/// Builds the bytes appended to an archive.
fn frame(kind: Kind, payload: &[u8]) -> Vec<u8> {
    match kind {
        Kind::Tar => tar_frame(payload),
        Kind::TarGz => gzip_frame(payload),
        Kind::TarXz => xz_frame(payload),
        Kind::TarZst => {
            let mut out = ZSTD_SKIPPABLE.to_le_bytes().to_vec();
            let size = (ZSTD_TAG.len() + payload.len()) as u32;
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(ZSTD_TAG);
            out.extend_from_slice(payload);
            out
        }
        Kind::Zip => unreachable!("ZIP has no frame"),
    }
}

fn tar_frame(payload: &[u8]) -> Vec<u8> {
    let mut header = [0u8; BLOCK];
    header[..FRAME_NAME.len()].copy_from_slice(FRAME_NAME.as_bytes());
    let mut text = |at: usize, value: String| {
        header[at..at + value.len()].copy_from_slice(value.as_bytes());
    };
    text(100, "0000644\0".into());
    text(108, "0000000\0".into());
    text(116, "0000000\0".into());
    text(124, format!("{:011o}\0", payload.len()));
    text(136, "00000000000\0".into());
    text(156, "0".into());
    text(257, "ustar\0".into());
    text(263, "00".into());
    header[148..156].fill(b' ');
    let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());

    let mut out = header.to_vec();
    out.extend_from_slice(payload);
    out.resize(out.len().next_multiple_of(BLOCK) + 1024, 0);
    out
}

fn gzip_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1F, 0x8B, 8, 8, 0, 0, 0, 0, 0, 0xFF];
    out.extend_from_slice(FRAME_NAME.as_bytes());
    out.push(0);
    out.push(1);
    let len = payload.len() as u16;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&(!len).to_le_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(&crc32(payload).to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out
}

fn xz_frame(payload: &[u8]) -> Vec<u8> {
    const FLAGS: [u8; 2] = [0, 0];
    let mut block_header = vec![2, 0, 0x21, 1, 10, 0, 0, 0];
    block_header.extend_from_slice(&crc32(&block_header).to_le_bytes());

    let mut block = block_header;
    block.push(1);
    let chunk = payload.len().saturating_sub(1) as u16;
    block.extend_from_slice(&chunk.to_be_bytes());
    block.extend_from_slice(payload);
    if !payload.is_empty() {
        block.push(0);
    }
    let unpadded = block.len() as u64;
    block.resize(block.len().next_multiple_of(4), 0);

    let mut index = vec![0];
    push_vli(&mut index, 1);
    push_vli(&mut index, unpadded);
    push_vli(&mut index, payload.len() as u64);
    index.resize(index.len().next_multiple_of(4), 0);
    index.extend_from_slice(&crc32(&index).to_le_bytes());

    let backward = (index.len() as u32 / 4 - 1).to_le_bytes();
    let mut tail = backward.to_vec();
    tail.extend_from_slice(&FLAGS);

    let mut out = XZ_MAGIC.to_vec();
    out.extend_from_slice(&FLAGS);
    out.extend_from_slice(&crc32(&FLAGS).to_le_bytes());
    out.extend(block);
    out.extend(index);
    out.extend_from_slice(&crc32(&tail).to_le_bytes());
    out.extend(tail);
    out.extend_from_slice(b"YZ");
    out
}

fn push_vli(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

// ZIP

struct Eocd {
    offset: u64,
    entries: u16,
    directory: Range<u64>,
}

fn zip_eocd<R: Read + Seek>(r: &mut R) -> Result<Eocd> {
    let file_len = r.seek(SeekFrom::End(0))?;
    let window = (EOCD_LEN as u64 + 0xFFFF).min(file_len);
    r.seek(SeekFrom::Start(file_len - window))?;
    let mut tail = vec![0; window as usize];
    r.read_exact(&mut tail)?;

    let found = (0..tail.len().saturating_sub(EOCD_LEN - 1))
        .rev()
        .find(|at| {
            tail[*at..].starts_with(EOCD_SIGNATURE)
                && *at + EOCD_LEN + u16_at(&tail, *at + 20) as usize == tail.len()
        });
    let at = found.ok_or(ArchiveError::Malformed("no end of central directory"))?;
    if u16_at(&tail, at + 4) != 0 || u16_at(&tail, at + 6) != 0 {
        return Err(ArchiveError::Unsupported("multi-disk ZIP"));
    }
    let entries = u16_at(&tail, at + 10);
    let size = u32_at(&tail, at + 12);
    let start = u32_at(&tail, at + 16);
    if u16_at(&tail, at + 8) != entries {
        return Err(ArchiveError::Unsupported("multi-disk ZIP"));
    }
    if entries == 0xFFFF || size == u32::MAX || start == u32::MAX {
        return Err(ArchiveError::Unsupported("ZIP64"));
    }
    let offset = file_len - window + at as u64;
    let directory = u64::from(start)..u64::from(start) + u64::from(size);
    if directory.end != offset {
        return Err(ArchiveError::Unsupported(
            "central directory does not end at its end record",
        ));
    }
    Ok(Eocd {
        offset,
        entries,
        directory,
    })
}

fn read_range<R: Read + Seek>(r: &mut R, range: &Range<u64>) -> Result<Vec<u8>> {
    let len = range.end - range.start;
    if len > MAX_CENTRAL_DIRECTORY {
        return Err(ArchiveError::Unsupported("central directory is too large"));
    }
    r.seek(SeekFrom::Start(range.start))?;
    let mut bytes = vec![0; len as usize];
    r.read_exact(&mut bytes)?;
    Ok(bytes)
}

struct Central {
    offset: usize,
    len: usize,
    name: Vec<u8>,
    method: u16,
    crc_field: usize,
    size: u32,
    local: u64,
}

fn zip_entries(directory: &[u8], expected: u16) -> Result<Vec<Central>> {
    let mut entries = Vec::with_capacity(usize::from(expected));
    let mut at = 0;
    while at < directory.len() {
        let header = directory
            .get(at..at + CENTRAL_LEN)
            .filter(|header| header.starts_with(CENTRAL_SIGNATURE))
            .ok_or(ArchiveError::Malformed("bad central directory entry"))?;
        let name_len = u16_at(header, 28) as usize;
        let len =
            CENTRAL_LEN + name_len + u16_at(header, 30) as usize + u16_at(header, 32) as usize;
        let name = directory
            .get(at + CENTRAL_LEN..at + CENTRAL_LEN + name_len)
            .ok_or(ArchiveError::Malformed("central directory is truncated"))?;
        if at + len > directory.len() {
            return Err(ArchiveError::Malformed("central directory is truncated"));
        }
        entries.push(Central {
            offset: at,
            len,
            name: name.to_vec(),
            method: u16_at(header, 10),
            crc_field: at + 16,
            size: u32_at(header, 24),
            local: u64::from(u32_at(header, 42)),
        });
        at += len;
    }
    if entries.len() != usize::from(expected) {
        return Err(ArchiveError::Malformed("entry count does not match"));
    }
    Ok(entries)
}

fn zip_find<R: Read + Seek>(r: &mut R) -> Result<Option<Embedded>> {
    let eocd = zip_eocd(r)?;
    let directory = read_range(r, &eocd.directory)?;
    let entries = zip_entries(&directory, eocd.entries)?;
    let name = ZIP_MANIFEST_PATH.as_bytes();
    let mut matches = entries.iter().filter(|entry| entry.name == name);
    let Some(entry) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err(ArchiveError::Unsupported("more than one manifest entry"));
    }
    if entry.method != 0 {
        return Err(ArchiveError::Unsupported("manifest entry is compressed"));
    }

    let local = read_range(r, &(entry.local..entry.local + LOCAL_LEN as u64))
        .map_err(|_| ArchiveError::Malformed("bad local header"))?;
    if !local.starts_with(LOCAL_SIGNATURE) {
        return Err(ArchiveError::Malformed("bad local header"));
    }
    let start = entry.local
        + LOCAL_LEN as u64
        + u64::from(u16_at(&local, 26))
        + u64::from(u16_at(&local, 28));
    let payload = start..start + u64::from(entry.size);
    if payload.end > eocd.directory.start {
        return Err(ArchiveError::Malformed(
            "manifest entry overlaps the directory",
        ));
    }
    let local_crc = entry.local + 14;
    let central_crc = eocd.directory.start + entry.crc_field as u64;
    Ok(Some(Embedded {
        payload: payload.clone(),
        exclusions: vec![
            local_crc..local_crc + 4,
            payload,
            central_crc..central_crc + 4,
        ],
        kind: Kind::Zip,
    }))
}

fn zip_embed<F: Read + Write + Seek>(f: &mut F, placeholder: &[u8]) -> Result<Embedded> {
    let eocd = zip_eocd(f)?;
    let directory = read_range(f, &eocd.directory)?;
    zip_entries(&directory, eocd.entries)?;
    let file_len = f.seek(SeekFrom::End(0))?;
    let end = read_range(f, &(eocd.offset..file_len))?;
    if eocd.entries >= 0xFFFE {
        return Err(ArchiveError::Unsupported("ZIP has too many entries"));
    }

    let name = ZIP_MANIFEST_PATH.as_bytes();
    let crc = crc32(placeholder);
    let size = placeholder.len() as u32;
    let local_offset = eocd.directory.start;
    let local_u32 = u32::try_from(local_offset).map_err(|_| ArchiveError::Unsupported("ZIP64"))?;

    let mut fields = Vec::new();
    fields.extend_from_slice(&10u16.to_le_bytes());
    fields.extend_from_slice(&[0; 4]);
    fields.extend_from_slice(&0u16.to_le_bytes());
    fields.extend_from_slice(&0x0021u16.to_le_bytes());
    fields.extend_from_slice(&crc.to_le_bytes());
    fields.extend_from_slice(&size.to_le_bytes());
    fields.extend_from_slice(&size.to_le_bytes());
    fields.extend_from_slice(&(name.len() as u16).to_le_bytes());
    fields.extend_from_slice(&0u16.to_le_bytes());

    let mut local = LOCAL_SIGNATURE.to_vec();
    local.extend_from_slice(&fields);
    local.extend_from_slice(name);

    let mut central = CENTRAL_SIGNATURE.to_vec();
    central.extend_from_slice(&10u16.to_le_bytes());
    central.extend_from_slice(&fields);
    central.extend_from_slice(&[0; 10]);
    central.extend_from_slice(&local_u32.to_le_bytes());
    central.extend_from_slice(name);

    f.seek(SeekFrom::Start(local_offset))?;
    f.write_all(&local)?;
    f.write_all(placeholder)?;
    let directory_start = local_offset + (local.len() + placeholder.len()) as u64;
    let directory_u32 =
        u32::try_from(directory_start).map_err(|_| ArchiveError::Unsupported("ZIP64"))?;
    f.write_all(&directory)?;
    f.write_all(&central)?;

    let mut updated = end;
    let entries = (eocd.entries + 1).to_le_bytes();
    updated[8..10].copy_from_slice(&entries);
    updated[10..12].copy_from_slice(&entries);
    let directory_len = (directory.len() + central.len()) as u32;
    updated[12..16].copy_from_slice(&directory_len.to_le_bytes());
    updated[16..20].copy_from_slice(&directory_u32.to_le_bytes());
    f.write_all(&updated)?;
    f.flush()?;

    let payload = local_offset + local.len() as u64;
    let central_crc = directory_start + directory.len() as u64 + 16;
    Ok(Embedded {
        payload: payload..payload + u64::from(size),
        exclusions: vec![
            local_offset + 14..local_offset + 18,
            payload..payload + u64::from(size),
            central_crc..central_crc + 4,
        ],
        kind: Kind::Zip,
    })
}

fn zip_remove(f: &mut File) -> Result<()> {
    let eocd = zip_eocd(f)?;
    let directory = read_range(f, &eocd.directory)?;
    let entries = zip_entries(&directory, eocd.entries)?;
    let entry = entries
        .last()
        .filter(|entry| entry.name == ZIP_MANIFEST_PATH.as_bytes())
        .ok_or(ArchiveError::Unsupported(
            "manifest is not the last central entry",
        ))?;
    if entry.offset + entry.len != directory.len() {
        return Err(ArchiveError::Malformed("central directory is truncated"));
    }
    let name_len = ZIP_MANIFEST_PATH.len() as u64;
    let data_end = entry.local + LOCAL_LEN as u64 + name_len + u64::from(entry.size);
    if data_end != eocd.directory.start {
        return Err(ArchiveError::Unsupported(
            "manifest is not the last stored entry",
        ));
    }

    let kept = &directory[..entry.offset];
    let file_len = f.seek(SeekFrom::End(0))?;
    let mut end = read_range(f, &(eocd.offset..file_len))?;
    let entries_left = (eocd.entries - 1).to_le_bytes();
    end[8..10].copy_from_slice(&entries_left);
    end[10..12].copy_from_slice(&entries_left);
    end[12..16].copy_from_slice(&(kept.len() as u32).to_le_bytes());
    end[16..20].copy_from_slice(&(entry.local as u32).to_le_bytes());

    f.seek(SeekFrom::Start(entry.local))?;
    f.write_all(kept)?;
    f.write_all(&end)?;
    f.set_len(entry.local + (kept.len() + end.len()) as u64)?;
    Ok(())
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const FRAMED: [Kind; 4] = [Kind::Tar, Kind::TarGz, Kind::TarXz, Kind::TarZst];

    fn sample(kind: Kind) -> Vec<u8> {
        match kind {
            Kind::Zip => {
                let mut eocd = EOCD_SIGNATURE.to_vec();
                eocd.resize(EOCD_LEN, 0);
                eocd
            }
            Kind::Tar => vec![0; 2048],
            _ => {
                let mut bytes = kind.magic().to_vec();
                bytes.extend_from_slice(&[0x42; 700]);
                bytes
            }
        }
    }

    fn temp(bytes: &[u8], name: &str) -> (std::path::PathBuf, File) {
        let path = std::env::temp_dir().join(format!("significant-{}-{name}", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        let file = File::options().read(true).write(true).open(&path).unwrap();
        (path, file)
    }

    #[test]
    fn known_crc() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn names_pick_the_longest_suffix() {
        assert_eq!(Kind::from_name("A.TAR.GZ").unwrap().0, Kind::TarGz);
        assert_eq!(Kind::from_name("a.tzst").unwrap().0, Kind::TarZst);
        assert_eq!(Kind::from_name("a.tar").unwrap().0, Kind::Tar);
        assert!(Kind::from_name("a.gz").is_none());
    }

    #[test]
    fn every_kind_round_trips_exactly() {
        for (index, kind) in FRAMED.into_iter().chain([Kind::Zip]).enumerate() {
            let original = sample(kind);
            let (path, mut file) = temp(&original, &format!("round{index}"));
            let at = embed_placeholder(kind, &mut file, &[0; 900]).unwrap();
            let store: Vec<u8> = (0..900).map(|n| (n % 251) as u8).collect();
            write_payload(&mut file, &at, &store).unwrap();
            let (payload, found) = read_payload(kind, &mut file).unwrap().unwrap();
            assert_eq!((payload, found), (store, at), "{kind:?}");
            assert!(remove(kind, &mut file).unwrap());
            drop(file);
            assert_eq!(std::fs::read(&path).unwrap(), original, "{kind:?}");
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn exclusions_stay_inside_the_file_and_in_order() {
        for kind in FRAMED.into_iter().chain([Kind::Zip]) {
            let mut c = Cursor::new(sample(kind));
            let at = embed_placeholder(kind, &mut c, &[1; 64]).unwrap();
            let len = c.get_ref().len() as u64;
            assert!(
                at.exclusions
                    .windows(2)
                    .all(|pair| pair[0].end <= pair[1].start)
            );
            assert!(at.exclusions.last().unwrap().end <= len, "{kind:?}");
        }
    }

    #[test]
    fn second_embed_is_rejected() {
        for kind in FRAMED.into_iter().chain([Kind::Zip]) {
            let mut c = Cursor::new(sample(kind));
            embed_placeholder(kind, &mut c, b"one").unwrap();
            let error = embed_placeholder(kind, &mut c, b"two").unwrap_err();
            assert!(matches!(error, ArchiveError::AlreadyPresent), "{kind:?}");
        }
    }

    #[test]
    fn oversized_manifest_is_rejected() {
        let mut c = Cursor::new(sample(Kind::TarGz));
        let error = embed_placeholder(Kind::TarGz, &mut c, &vec![0; MAX_PAYLOAD + 1]).unwrap_err();
        assert!(matches!(error, ArchiveError::TooLarge(_)));
    }

    #[test]
    fn wrong_contents_are_rejected() {
        let mut c = Cursor::new(vec![0; 2048]);
        assert!(embed_placeholder(Kind::TarXz, &mut c, b"store").is_err());
        let mut c = Cursor::new(vec![1; 2048]);
        assert!(embed_placeholder(Kind::Tar, &mut c, b"store").is_err());
    }

    #[test]
    fn damaged_frame_is_not_treated_as_a_manifest() {
        for kind in [Kind::TarGz, Kind::TarXz] {
            let mut c = Cursor::new(sample(kind));
            embed_placeholder(kind, &mut c, &[9; 100]).unwrap();
            let last = c.get_ref().len() - 1;
            c.get_mut()[last] ^= 0xFF;
            assert!(read_payload(kind, &mut c).unwrap().is_none(), "{kind:?}");
        }
    }

    #[test]
    fn hostile_zip_inputs_return_errors() {
        let good = {
            let mut c = Cursor::new(sample(Kind::Zip));
            embed_placeholder(Kind::Zip, &mut c, &[3; 64]).unwrap();
            c.into_inner()
        };
        for len in 0..good.len() {
            let _ = read_payload(Kind::Zip, &mut Cursor::new(good[..len].to_vec()));
        }
        for at in 0..good.len() {
            let mut bad = good.clone();
            bad[at] ^= 0xFF;
            let _ = read_payload(Kind::Zip, &mut Cursor::new(bad));
        }
    }
}
