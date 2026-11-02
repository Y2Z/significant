//! Stores a C2PA manifest store inside a Matroska file as an attachment.
//!
//! This module uses only the standard library. C2PA defines no Matroska
//! embedding, so this mapping is specific to `significant`.
//!
//! Signing appends the attachment at the end of the Segment, so no existing
//! Cluster, Cues or SeekHead offset moves. Removing it restores the original
//! bytes exactly, provided the file has not otherwise changed.

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::Range;

pub const FILE_NAME: &str = "significant.c2pa";
pub const MIME_TYPE: &str = "application/c2pa";
const FILE_UID: u64 = 0x5349_474E_4946_4943; // "SIGNIFIC"
const MAX_PAYLOAD_READ: u64 = 64 * 1024 * 1024;

const ID_EBML: u32 = 0x1A45_DFA3;
const ID_SEGMENT: u32 = 0x1853_8067;
const ID_SEEK_HEAD: u32 = 0x114D_9B74;
const ID_INFO: u32 = 0x1549_A966;
const ID_TRACKS: u32 = 0x1654_AE6B;
const ID_CLUSTER: u32 = 0x1F43_B675;
const ID_CUES: u32 = 0x1C53_BB6B;
const ID_ATTACHMENTS: u32 = 0x1941_A469;
const ID_CHAPTERS: u32 = 0x1043_A770;
const ID_TAGS: u32 = 0x1254_C367;
const ID_ATTACHED_FILE: u32 = 0x61A7;
const ID_FILE_DESCRIPTION: u32 = 0x467E;
const ID_FILE_NAME: u32 = 0x466E;
const ID_FILE_MIME_TYPE: u32 = 0x4660;
const ID_FILE_DATA: u32 = 0x465C;
const ID_FILE_UID: u32 = 0x46AE;

#[derive(Debug)]
pub enum MkvError {
    Io(io::Error),
    Malformed(&'static str),
    Unsupported(&'static str),
    AlreadyPresent,
    PayloadSize { expected: u64, got: u64 },
}

impl fmt::Display for MkvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Malformed(detail) => write!(f, "malformed Matroska file: {detail}"),
            Self::Unsupported(detail) => write!(f, "unsupported Matroska layout: {detail}"),
            Self::AlreadyPresent => f.write_str("file already contains a significant attachment"),
            Self::PayloadSize { expected, got } => {
                write!(f, "replacement payload is {got} bytes, expected {expected}")
            }
        }
    }
}

impl std::error::Error for MkvError {}

impl From<io::Error> for MkvError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

type Result<T> = std::result::Result<T, MkvError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SizeField {
    offset: u64,
    width: u8,
    value: Option<u64>,
}

#[derive(Debug, Clone)]
struct ManifestFile {
    element: Range<u64>,
    payload: Range<u64>,
}

#[derive(Debug, Clone)]
struct Attachments {
    offset: u64,
    size: SizeField,
    end: u64,
    children: usize,
    manifest: Option<ManifestFile>,
}

#[derive(Debug, Clone)]
struct Layout {
    file_len: u64,
    segment_size: SizeField,
    attachments: Option<Attachments>,
}

/// Location of the manifest bytes inside the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Embedded {
    pub payload: Range<u64>,
}

impl Embedded {
    /// Byte count of the region excluded from the content hash.
    pub fn len(&self) -> u64 {
        self.payload.end - self.payload.start
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Appends `placeholder` as an attachment and updates parent sizes.
pub fn embed_placeholder<F: Read + Write + Seek>(
    f: &mut F,
    placeholder: &[u8],
) -> Result<Embedded> {
    let layout = locate(f)?;
    if layout
        .attachments
        .as_ref()
        .is_some_and(|a| a.manifest.is_some())
    {
        return Err(MkvError::AlreadyPresent);
    }

    let file = attached_file_header(placeholder.len() as u64);
    let file_total = file.len() as u64 + placeholder.len() as u64;
    let (prefix, attachments_patch) = match &layout.attachments {
        None => {
            let mut wrapper = encode_id(ID_ATTACHMENTS);
            wrapper.extend(encode_size8(file_total)?);
            (wrapper, None)
        }
        Some(a) if a.end == layout.file_len => {
            let old = a
                .size
                .value
                .ok_or(MkvError::Unsupported("Attachments has unknown size"))?;
            (Vec::new(), Some((a.size, old + file_total)))
        }
        Some(_) => {
            return Err(MkvError::Unsupported(
                "existing Attachments element is not the last element in the file",
            ));
        }
    };

    let added = prefix.len() as u64 + file_total;
    let segment_patch = layout
        .segment_size
        .value
        .map(|old| (layout.segment_size, old + added));
    for (field, value) in attachments_patch.iter().chain(segment_patch.iter()) {
        encode_size_width(*value, field.width)?;
    }

    let start = layout.file_len;
    f.seek(SeekFrom::Start(start))?;
    f.write_all(&prefix)?;
    f.write_all(&file)?;
    f.write_all(placeholder)?;
    if let Some((field, value)) = attachments_patch {
        patch_size(f, field, value)?;
    }
    if let Some((field, value)) = segment_patch {
        patch_size(f, field, value)?;
    }
    f.flush()?;

    let payload_start = start + prefix.len() as u64 + file.len() as u64;
    Ok(Embedded {
        payload: payload_start..payload_start + placeholder.len() as u64,
    })
}

/// Overwrites the placeholder with a final store of the same size.
pub fn write_payload<F: Write + Seek>(f: &mut F, at: &Embedded, payload: &[u8]) -> Result<()> {
    if payload.len() as u64 != at.len() {
        return Err(MkvError::PayloadSize {
            expected: at.len(),
            got: payload.len() as u64,
        });
    }
    f.seek(SeekFrom::Start(at.payload.start))?;
    f.write_all(payload)?;
    f.flush()?;
    Ok(())
}

/// Returns the stored manifest bytes and their location, if present.
pub fn read_payload<R: Read + Seek>(r: &mut R) -> Result<Option<(Vec<u8>, Embedded)>> {
    let layout = locate(r)?;
    let Some(manifest) = layout.attachments.and_then(|a| a.manifest) else {
        return Ok(None);
    };
    let len = manifest.payload.end - manifest.payload.start;
    if len > MAX_PAYLOAD_READ {
        return Err(MkvError::Unsupported("manifest attachment is too large"));
    }
    r.seek(SeekFrom::Start(manifest.payload.start))?;
    let mut bytes = vec![0; len as usize];
    r.read_exact(&mut bytes)?;
    Ok(Some((
        bytes,
        Embedded {
            payload: manifest.payload,
        },
    )))
}

/// Removes the manifest attachment. Returns `false` if there is none.
pub fn remove(f: &mut File) -> Result<bool> {
    let layout = locate(f)?;
    let Some(attachments) = &layout.attachments else {
        return Ok(false);
    };
    let Some(manifest) = &attachments.manifest else {
        return Ok(false);
    };
    if manifest.element.end != layout.file_len {
        return Err(MkvError::Unsupported(
            "manifest attachment is not at the end of the file",
        ));
    }

    let only_child = attachments.children == 1;
    let cut = if only_child {
        attachments.offset
    } else {
        manifest.element.start
    };
    let removed = layout.file_len - cut;
    if !only_child {
        let old = attachments
            .size
            .value
            .ok_or(MkvError::Unsupported("Attachments has unknown size"))?;
        patch_size(
            f,
            attachments.size,
            old - (manifest.element.end - manifest.element.start),
        )?;
    }
    if let Some(old) = layout.segment_size.value {
        patch_size(f, layout.segment_size, old - removed)?;
    }
    f.set_len(cut)?;
    f.flush()?;
    Ok(true)
}

fn locate<R: Read + Seek>(r: &mut R) -> Result<Layout> {
    let file_len = r.seek(SeekFrom::End(0))?;
    r.seek(SeekFrom::Start(0))?;

    let (id, size) = read_header(r, file_len)?;
    if id != ID_EBML {
        return Err(MkvError::Malformed("missing EBML header"));
    }
    let size = size
        .value
        .ok_or(MkvError::Malformed("EBML header has unknown size"))?;
    r.seek(SeekFrom::Current(
        i64::try_from(size).map_err(|_| MkvError::Malformed("size overflow"))?,
    ))?;

    let (id, segment_size) = read_header(r, file_len)?;
    if id != ID_SEGMENT {
        return Err(MkvError::Unsupported("expected Segment after EBML header"));
    }
    let segment_data = r.stream_position()?;
    let end = match segment_size.value {
        Some(size) => segment_data
            .checked_add(size)
            .ok_or(MkvError::Malformed("size overflow"))?,
        None => file_len,
    };
    if end > file_len {
        return Err(MkvError::Malformed("Segment extends past end of file"));
    }
    if end < file_len {
        return Err(MkvError::Unsupported("data follows the Segment"));
    }

    let mut attachments = None;
    let mut pos = segment_data;
    while pos < end {
        r.seek(SeekFrom::Start(pos))?;
        let (id, size) = read_header(r, end)?;
        let data = r.stream_position()?;
        let next = match size.value {
            Some(value) => element_end(data, value, end)?,
            None if id == ID_CLUSTER => skip_unknown_cluster(r, data, end)?,
            None => {
                return Err(MkvError::Unsupported(
                    "unknown-size element other than Cluster",
                ));
            }
        };
        if id == ID_ATTACHMENTS {
            if attachments.is_some() {
                return Err(MkvError::Unsupported("more than one Attachments element"));
            }
            attachments = Some(read_attachments(r, pos, size, data, next)?);
        }
        pos = next;
    }

    Ok(Layout {
        file_len,
        segment_size,
        attachments,
    })
}

fn read_attachments<R: Read + Seek>(
    r: &mut R,
    offset: u64,
    size: SizeField,
    data: u64,
    end: u64,
) -> Result<Attachments> {
    let mut pos = data;
    let mut children = 0;
    let mut manifest = None;
    while pos < end {
        r.seek(SeekFrom::Start(pos))?;
        let (id, child_size) = read_header(r, end)?;
        let child_data = r.stream_position()?;
        let value = child_size
            .value
            .ok_or(MkvError::Malformed("unknown-size attachment"))?;
        let child_end = element_end(child_data, value, end)?;
        if id == ID_ATTACHED_FILE {
            children += 1;
            if let Some(payload) = read_attached_file(r, child_data, child_end)? {
                if manifest.is_some() {
                    return Err(MkvError::Unsupported(
                        "more than one significant attachment",
                    ));
                }
                manifest = Some(ManifestFile {
                    element: pos..child_end,
                    payload,
                });
            }
        }
        pos = child_end;
    }
    Ok(Attachments {
        offset,
        size,
        end,
        children,
        manifest,
    })
}

fn read_attached_file<R: Read + Seek>(
    r: &mut R,
    start: u64,
    end: u64,
) -> Result<Option<Range<u64>>> {
    let mut pos = start;
    let (mut name, mut mime, mut payload) = (None, None, None);
    while pos < end {
        r.seek(SeekFrom::Start(pos))?;
        let (id, size) = read_header(r, end)?;
        let data = r.stream_position()?;
        let value = size
            .value
            .ok_or(MkvError::Malformed("unknown-size attachment field"))?;
        let next = element_end(data, value, end)?;
        match id {
            ID_FILE_NAME if value <= 256 => name = Some(read_bytes(r, value)?),
            ID_FILE_MIME_TYPE if value <= 256 => mime = Some(read_bytes(r, value)?),
            ID_FILE_DATA => payload = Some(data..next),
            _ => {}
        }
        pos = next;
    }
    let matches = name.as_deref() == Some(FILE_NAME.as_bytes())
        && mime.as_deref() == Some(MIME_TYPE.as_bytes());
    Ok(payload.filter(|_| matches))
}

fn read_bytes<R: Read>(r: &mut R, len: u64) -> Result<Vec<u8>> {
    let mut bytes = vec![0; len as usize];
    r.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn skip_unknown_cluster<R: Read + Seek>(r: &mut R, data: u64, end: u64) -> Result<u64> {
    let mut pos = data;
    while pos < end {
        r.seek(SeekFrom::Start(pos))?;
        let (id, size) = read_header(r, end)?;
        if is_segment_child(id) {
            return Ok(pos);
        }
        let value = size
            .value
            .ok_or(MkvError::Malformed("unknown-size element in Cluster"))?;
        pos = element_end(r.stream_position()?, value, end)?;
    }
    Ok(end)
}

fn is_segment_child(id: u32) -> bool {
    matches!(
        id,
        ID_SEEK_HEAD
            | ID_INFO
            | ID_TRACKS
            | ID_CLUSTER
            | ID_CUES
            | ID_ATTACHMENTS
            | ID_CHAPTERS
            | ID_TAGS
    )
}

fn element_end(data: u64, size: u64, limit: u64) -> Result<u64> {
    let end = data
        .checked_add(size)
        .ok_or(MkvError::Malformed("size overflow"))?;
    if end > limit {
        return Err(MkvError::Malformed("element extends past its parent"));
    }
    Ok(end)
}

fn read_header<R: Read + Seek>(r: &mut R, limit: u64) -> Result<(u32, SizeField)> {
    let id = read_id(r, limit)?;
    let size = read_size(r, limit)?;
    Ok((id, size))
}

fn read_id<R: Read + Seek>(r: &mut R, limit: u64) -> Result<u32> {
    let first = read_u8(r, limit)?;
    let width = first.leading_zeros() + 1;
    if width > 4 {
        return Err(MkvError::Malformed("invalid element ID"));
    }
    let mut id = u32::from(first);
    for _ in 1..width {
        id = (id << 8) | u32::from(read_u8(r, limit)?);
    }
    Ok(id)
}

fn read_size<R: Read + Seek>(r: &mut R, limit: u64) -> Result<SizeField> {
    let offset = r.stream_position()?;
    let first = read_u8(r, limit)?;
    let width = first.leading_zeros() as u8 + 1;
    if width > 8 {
        return Err(MkvError::Malformed("invalid element size"));
    }
    let mut value = u64::from(first) & (0xFFu64 >> width);
    for _ in 1..width {
        value = (value << 8) | u64::from(read_u8(r, limit)?);
    }
    let unknown = value == (1u64 << (7 * u32::from(width))) - 1;
    Ok(SizeField {
        offset,
        width,
        value: (!unknown).then_some(value),
    })
}

fn read_u8<R: Read + Seek>(r: &mut R, limit: u64) -> Result<u8> {
    if r.stream_position()? >= limit {
        return Err(MkvError::Malformed("unexpected end of element"));
    }
    let mut byte = [0];
    r.read_exact(&mut byte)?;
    Ok(byte[0])
}

fn patch_size<F: Write + Seek>(f: &mut F, field: SizeField, value: u64) -> Result<()> {
    let encoded = encode_size_width(value, field.width)?;
    f.seek(SeekFrom::Start(field.offset))?;
    f.write_all(&encoded)?;
    Ok(())
}

fn encode_size_width(value: u64, width: u8) -> Result<Vec<u8>> {
    let max = (1u64 << (7 * u32::from(width))) - 1;
    if value >= max {
        return Err(MkvError::Unsupported("existing size field is too narrow"));
    }
    let bytes = value.to_be_bytes();
    let mut out = bytes[8 - usize::from(width)..].to_vec();
    out[0] |= 1 << (8 - width);
    Ok(out)
}

fn encode_size8(value: u64) -> Result<Vec<u8>> {
    encode_size_width(value, 8)
}

fn encode_id(id: u32) -> Vec<u8> {
    let bytes = id.to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count();
    bytes[skip..].to_vec()
}

fn field(id: u32, data: &[u8]) -> Vec<u8> {
    let mut out = encode_id(id);
    out.extend(encode_size8(data.len() as u64).expect("short field"));
    out.extend_from_slice(data);
    out
}

/// Encodes everything in an AttachedFile up to the FileData payload.
fn attached_file_header(payload_len: u64) -> Vec<u8> {
    let mut body = field(ID_FILE_DESCRIPTION, b"C2PA manifest store");
    body.extend(field(ID_FILE_NAME, FILE_NAME.as_bytes()));
    body.extend(field(ID_FILE_MIME_TYPE, MIME_TYPE.as_bytes()));
    body.extend(field(ID_FILE_UID, &FILE_UID.to_be_bytes()));
    body.extend(encode_id(ID_FILE_DATA));
    body.extend(encode_size8(payload_len).expect("payload size"));

    let mut out = encode_id(ID_ATTACHED_FILE);
    out.extend(encode_size8(body.len() as u64 + payload_len).expect("attachment size"));
    out.extend(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn element(id: u32, data: &[u8]) -> Vec<u8> {
        field(id, data)
    }

    fn sample(with_cover: bool) -> Vec<u8> {
        let mut segment = element(ID_INFO, b"info");
        segment.extend(element(ID_CLUSTER, b"frames"));
        if with_cover {
            let cover = element(ID_ATTACHED_FILE, &element(ID_FILE_NAME, b"cover.jpg"));
            segment.extend(element(ID_ATTACHMENTS, &cover));
        }
        let mut file = element(ID_EBML, b"hdr");
        file.extend(element(ID_SEGMENT, &segment));
        file
    }

    fn temp(bytes: &[u8], name: &str) -> (std::path::PathBuf, File) {
        let path = std::env::temp_dir().join(format!("significant-{}-{name}", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        let file = File::options().read(true).write(true).open(&path).unwrap();
        (path, file)
    }

    fn roundtrip(with_cover: bool, name: &str) {
        let original = sample(with_cover);
        let (path, mut file) = temp(&original, name);
        let at = embed_placeholder(&mut file, &[0; 32]).unwrap();
        write_payload(&mut file, &at, &[7; 32]).unwrap();
        let (payload, found) = read_payload(&mut file).unwrap().unwrap();
        assert_eq!((payload, found), (vec![7; 32], at));
        assert!(remove(&mut file).unwrap());
        drop(file);
        assert_eq!(std::fs::read(&path).unwrap(), original);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn removal_restores_exact_bytes() {
        roundtrip(false, "plain");
    }

    #[test]
    fn removal_keeps_existing_attachment() {
        roundtrip(true, "cover");
    }

    #[test]
    fn second_embed_is_rejected() {
        let mut c = Cursor::new(sample(false));
        embed_placeholder(&mut c, b"one").unwrap();
        assert!(matches!(
            embed_placeholder(&mut c, b"two"),
            Err(MkvError::AlreadyPresent)
        ));
    }

    #[test]
    fn payload_size_must_match() {
        let mut c = Cursor::new(sample(false));
        let at = embed_placeholder(&mut c, b"one").unwrap();
        assert!(matches!(
            write_payload(&mut c, &at, b"longer"),
            Err(MkvError::PayloadSize { .. })
        ));
    }

    #[test]
    fn unknown_size_segment_and_cluster_are_handled() {
        let mut file = element(ID_EBML, b"hdr");
        file.extend(encode_id(ID_SEGMENT));
        file.extend([0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        file.extend(element(ID_INFO, b"info"));
        file.extend(encode_id(ID_CLUSTER));
        file.push(0xFF);
        file.extend(element(0xE7, b"\x00"));
        file.extend(element(ID_CUES, b"cues"));
        let mut c = Cursor::new(file);
        embed_placeholder(&mut c, b"store").unwrap();
        assert_eq!(read_payload(&mut c).unwrap().unwrap().0, b"store");
    }

    #[test]
    fn hostile_input_returns_errors() {
        let original = sample(false);
        assert!(locate(&mut Cursor::new(b"not matroska".to_vec())).is_err());
        for len in 0..original.len() {
            assert!(locate(&mut Cursor::new(original[..len].to_vec())).is_err());
        }
        let mut huge = element(ID_EBML, b"h");
        huge.extend(encode_id(ID_SEGMENT));
        huge.extend([0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE]);
        assert!(locate(&mut Cursor::new(huge)).is_err());
    }
}
