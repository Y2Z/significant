//! Sign and verify media files in place, using C2PA where it defines a
//! format and a `significant` attachment for Matroska.
use std::fs::{self, File};
use std::io::{self, Read, Seek as _, Write as _};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use c2pa::{Builder, CallbackSigner, Context, HashRange, Reader, Settings, SigningAlg};
use serde_json::{Value, json};

pub mod archive;
pub mod keys;
pub mod mkv;
pub mod trust;

pub use keys::{DeviceKey, FileKey};
pub use trust::{Added, Trust};

const MKV_MIME: &str = "video/x-matroska";
const RAW_STORE_MIME: &str = "application/c2pa";

// The CLI cannot know how a file was made, so it does not claim a capture.
// A camera app should use the IPTC digitalCapture value instead.
const DIGITAL_SOURCE_TYPE: &str = "http://c2pa.org/digitalsourcetype/unknown";

// Self-issued device certificates are not on a trust list, so a strict check
// straight after signing could reject them. `verify` still validates files.
const UNTRUSTED_SIGNER: &str = "signingCredential.untrusted";
const TRUSTED_SIGNER: &str = "signingCredential.trusted";
// c2pa has no handler for these containers, so it cannot locate the manifest
// and reports this failure. `verify` performs the location check itself.
const NO_HANDLER_LOCATION: &str = "data hash exclusion does not match the manifest location";

const SCAN_CHUNK: usize = 1 << 20;

const SIGNING_SETTINGS: &str = "[verify]\nverify_after_sign = false\n";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("C2PA error: {0}")]
    C2pa(#[from] c2pa::Error),
    #[error(transparent)]
    Mkv(#[from] mkv::MkvError),
    #[error(transparent)]
    Archive(#[from] archive::ArchiveError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported file type: {0}")]
    UnsupportedFormat(PathBuf),
    #[error("{0} is already signed; run unsign first")]
    AlreadySigned(PathBuf),
    #[error("manifest file {0} already exists; use --force to replace it or --discard to skip it")]
    ManifestExists(PathBuf),
    #[error("manifest does not match {path}: {problems}")]
    ManifestMismatch { path: PathBuf, problems: String },
    #[error("manifest in {0} is not stored as one contiguous block")]
    ManifestFragmented(PathBuf),
    #[error("manifest bytes appear more than once in {0}")]
    ManifestAmbiguous(PathBuf),
    #[error("no signing key in {dir}; run `significant keygen` ({source})")]
    KeyMissing { dir: PathBuf, source: io::Error },
    #[error("a signing key already exists in {0}; use --force to replace it")]
    KeyExists(PathBuf),
    #[error("key error: {0}")]
    Key(String),
    #[error("trust error: {0}")]
    Trust(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// A format `significant` embeds itself because c2pa has no handler for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Carrier {
    Mkv,
    Archive(archive::Kind),
}

/// Where a carrier put a manifest.
enum Placement {
    Mkv(mkv::Embedded),
    Archive(archive::Embedded),
}

impl Placement {
    fn payload(&self) -> Range<u64> {
        match self {
            Self::Mkv(at) => at.payload.clone(),
            Self::Archive(at) => at.payload.clone(),
        }
    }

    fn exclusions(&self) -> Vec<Range<u64>> {
        match self {
            Self::Mkv(at) => vec![at.payload.clone()],
            Self::Archive(at) => at.exclusions.clone(),
        }
    }

    fn write(&self, file: &mut File, store: &[u8]) -> Result<()> {
        match self {
            Self::Mkv(at) => mkv::write_payload(file, at, store)?,
            Self::Archive(at) => archive::write_payload(file, at, store)?,
        }
        Ok(())
    }
}

impl Carrier {
    fn embed(self, file: &mut File, bytes: &[u8]) -> Result<Placement> {
        Ok(match self {
            Self::Mkv => Placement::Mkv(mkv::embed_placeholder(file, bytes)?),
            Self::Archive(kind) => {
                Placement::Archive(archive::embed_placeholder(kind, file, bytes)?)
            }
        })
    }

    fn read(self, file: &mut File) -> Result<Option<(Vec<u8>, Placement)>> {
        Ok(match self {
            Self::Mkv => mkv::read_payload(file)?.map(|(store, at)| (store, Placement::Mkv(at))),
            Self::Archive(kind) => archive::read_payload(kind, file)?
                .map(|(store, at)| (store, Placement::Archive(at))),
        })
    }

    fn remove(self, file: &mut File) -> Result<()> {
        match self {
            Self::Mkv => {
                mkv::remove(file)?;
            }
            Self::Archive(kind) => {
                archive::remove(kind, file)?;
            }
        }
        Ok(())
    }
}

fn carrier(path: &Path) -> Option<Carrier> {
    if let Some((kind, _)) = file_name(path).and_then(archive::Kind::from_name) {
        return Some(Carrier::Archive(kind));
    }
    (media_type(path).ok() == Some(MKV_MIME)).then_some(Carrier::Mkv)
}

fn file_name(path: &Path) -> Option<&str> {
    path.file_name().and_then(|name| name.to_str())
}

/// Outcome of `verify`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    /// True when the content and signature pass validation.
    pub intact: bool,
    /// True when the signer is a trusted device or chains to a trusted
    /// authority.
    pub trusted: bool,
    /// SHA-256 of the signing certificate. Use this to identify a signer.
    pub fingerprint: Option<String>,
    /// Name in the certificate. Anyone can write any name in a certificate,
    /// so this means nothing unless `trusted` is true.
    pub claimed_name: Option<String>,
    pub problems: Vec<String>,
    pub report: String,
}

/// Signs `path` in place. The file changes only if signing succeeds.
pub fn sign(path: &Path, key: Arc<dyn DeviceKey>) -> Result<()> {
    let format = media_type(path)?;
    if is_signed(path)? {
        return Err(Error::AlreadySigned(path.to_path_buf()));
    }
    let context = signing_context(key)?;
    let mut builder =
        Builder::from_shared_context(&context).with_definition(definition(path, format))?;
    let dir = parent(path);
    let output = tempfile::NamedTempFile::new_in(dir)?;

    if let Some(carrier) = carrier(path) {
        fs::copy(path, output.path())?;
        let mut file = File::options().read(true).write(true).open(output.path())?;
        sign_custom(&mut builder, carrier, format, &mut file, hash_ranges)?;
    } else {
        let mut source = File::open(path)?;
        let mut target = File::options().read(true).write(true).open(output.path())?;
        builder.save_to_stream(format, &mut source, &mut target)?;
        target.sync_all()?;
    }
    replace(output, path)
}

fn hash_ranges(ranges: &[Range<u64>]) -> Vec<HashRange> {
    ranges
        .iter()
        .map(|range| HashRange::new(range.start, range.end - range.start))
        .collect()
}

/// Embeds a signed manifest in a format without a c2pa handler. `exclusions`
/// maps the bytes that depend on the manifest to the ranges left out of the
/// hash.
fn sign_custom(
    builder: &mut Builder,
    carrier: Carrier,
    format: &str,
    file: &mut File,
    exclusions: impl Fn(&[Range<u64>]) -> Vec<HashRange>,
) -> Result<()> {
    let placeholder = builder.placeholder(RAW_STORE_MIME)?;
    let at = carrier.embed(file, &placeholder)?;
    builder.set_data_hash_exclusions(exclusions(&at.exclusions()))?;
    file.rewind()?;
    builder.update_hash_from_stream(format, &mut *file)?;
    let store = builder.sign_embeddable(RAW_STORE_MIME)?;
    at.write(file, &store)?;
    file.sync_all()?;
    Ok(())
}

/// Checks `path` with nothing trusted. Returns `None` when it carries no
/// manifest.
pub fn verify(path: &Path) -> Result<Option<Verification>> {
    verify_with(path, &Trust::default())
}

/// Checks `path` against a trust list. Returns `None` when it carries no
/// manifest.
pub fn verify_with(path: &Path, trust: &Trust) -> Result<Option<Verification>> {
    let format = media_type(path)?;
    let context = verifying_context(trust)?;
    let reader = Reader::from_shared_context(&context);
    let mut file = File::open(path)?;
    let mut expected = None;
    let reader = if let Some(carrier) = carrier(path) {
        let Some((store, at)) = carrier.read(&mut file)? else {
            return Ok(None);
        };
        expected = Some(at.exclusions());
        file.rewind()?;
        reader.with_manifest_data_and_stream(&store, format, &mut file)?
    } else {
        match reader.with_stream(format, &mut file) {
            Ok(reader) => reader,
            Err(c2pa::Error::JumbfNotFound) => return Ok(None),
            Err(error) => return Err(error.into()),
        }
    };

    let state = format!("{:?}", reader.validation_state());
    let report = reader.json();
    let parsed: Value = serde_json::from_str(&report)?;
    let fingerprint = reader
        .active_manifest()
        .and_then(|manifest| manifest.signature_info())
        .map(|info| trust::fingerprint(info.cert_chain().as_bytes()))
        .transpose()?;
    let trusted = state == "Trusted"
        || has_success(&parsed, TRUSTED_SIGNER)
        || fingerprint
            .as_deref()
            .is_some_and(|id| trust.has_device(id));
    let mut problems = problems(&parsed);
    problems.retain(|problem| !problem.starts_with(UNTRUSTED_SIGNER));
    let intact = match &expected {
        None => state != "Invalid",
        Some(ranges) => {
            problems.retain(|problem| !problem.contains(NO_HANDLER_LOCATION));
            let detailed: Value = serde_json::from_str(&reader.detailed_json())?;
            if !exclusions_are_exactly(&detailed, ranges) {
                problems.push("hash exclusion is not exactly the manifest location".to_owned());
            }
            problems.is_empty()
        }
    };

    Ok(Some(Verification {
        intact,
        trusted,
        fingerprint,
        claimed_name: claimed_name(&parsed),
        problems,
        report,
    }))
}

/// A signed exclusion wider than the manifest would leave content unprotected.
fn exclusions_are_exactly(detailed: &Value, expected: &[Range<u64>]) -> bool {
    let Some(label) = detailed["active_manifest"].as_str() else {
        return false;
    };
    let Some(assertions) = detailed["manifests"][label]["assertion_store"].as_object() else {
        return false;
    };
    let mut hashes = assertions
        .iter()
        .filter(|(name, _)| name.starts_with("c2pa.hash.data"));
    let (Some((_, hash)), None) = (hashes.next(), hashes.next()) else {
        return false;
    };
    let Some(exclusions) = hash["exclusions"].as_array() else {
        return false;
    };
    exclusions.len() == expected.len()
        && exclusions.iter().zip(expected).all(|(exclusion, range)| {
            exclusion["start"].as_u64() == Some(range.start)
                && exclusion["length"].as_u64() == Some(range.end - range.start)
        })
}

/// Returns the byte ranges the manifest occupies, or `None` if there is none.
///
/// A hasher can skip these ranges to get a value that ignores the manifest.
/// The result is not the hash of the original unsigned file: container bytes
/// around the manifest remain, and signing may also adjust container fields.
///
/// The ranges come from the file and are not themselves proof of anything.
/// Run [`verify`] before relying on them.
pub fn manifest_ranges(path: &Path) -> Result<Option<Vec<Range<u64>>>> {
    let format = media_type(path)?;
    if !is_signed(path)? {
        return Ok(None);
    }
    let mut file = File::open(path)?;
    if let Some(carrier) = carrier(path) {
        return Ok(carrier.read(&mut file)?.map(|(_, at)| vec![at.payload()]));
    }

    let store = read_store(path, format)?;
    let found = find_occurrences(&mut file, &store, 2, SCAN_CHUNK)?;
    match found.as_slice() {
        [] => Err(Error::ManifestFragmented(path.to_path_buf())),
        [start] => Ok(Some(vec![*start..start + store.len() as u64])),
        _ => Err(Error::ManifestAmbiguous(path.to_path_buf())),
    }
}

/// Finds up to `limit` offsets of `needle` without loading the whole file.
fn find_occurrences<R: Read>(
    reader: &mut R,
    needle: &[u8],
    limit: usize,
    chunk_size: usize,
) -> io::Result<Vec<u64>> {
    let mut found = Vec::new();
    if needle.is_empty() {
        return Ok(found);
    }
    let mut chunk = vec![0; chunk_size];
    let mut window = Vec::new();
    let mut window_start = 0u64;
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            return Ok(found);
        }
        window.extend_from_slice(&chunk[..read]);
        for (position, candidate) in window.windows(needle.len()).enumerate() {
            if candidate == needle {
                found.push(window_start + position as u64);
                if found.len() == limit {
                    return Ok(found);
                }
            }
        }
        // Keep just enough to match across the next chunk boundary.
        let discard = window.len().saturating_sub(needle.len() - 1);
        window.drain(..discard);
        window_start += discard as u64;
    }
}

/// Default manifest location: `video.mp4` becomes `video.mp4.c2pa`.
pub fn sidecar_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".c2pa");
    PathBuf::from(name)
}

/// Removes the manifest. Returns `false` if the file had none.
///
/// With `manifest_out`, the manifest is saved there before the file changes,
/// so `restore` can put it back. An existing manifest file is kept unless
/// `overwrite` is set.
pub fn unsign(path: &Path, manifest_out: Option<&Path>, overwrite: bool) -> Result<bool> {
    let format = media_type(path)?;
    if !is_signed(path)? {
        return Ok(false);
    }
    if let Some(out) = manifest_out {
        if out.exists() && !overwrite {
            return Err(Error::ManifestExists(out.to_path_buf()));
        }
        let mut saved = tempfile::NamedTempFile::new_in(parent(out))?;
        saved.write_all(&read_store(path, format)?)?;
        saved.as_file().sync_all()?;
        saved.persist(out).map_err(|e| Error::Io(e.error))?;
    }

    let output = temp_beside(path)?;
    fs::copy(path, output.path())?;
    if let Some(carrier) = carrier(path) {
        let mut file = File::options().read(true).write(true).open(output.path())?;
        carrier.remove(&mut file)?;
        file.sync_all()?;
    } else {
        c2pa::jumbf_io::remove_jumbf_from_file(output.path())?;
    }
    replace(output, path)?;
    Ok(true)
}

/// Puts a saved manifest back. `path` changes only if the result verifies.
pub fn restore(path: &Path, manifest: &Path) -> Result<()> {
    let format = media_type(path)?;
    if is_signed(path)? {
        return Err(Error::AlreadySigned(path.to_path_buf()));
    }
    let store = fs::read(manifest)?;
    let output = temp_beside(path)?;
    if let Some(carrier) = carrier(path) {
        fs::copy(path, output.path())?;
        let mut file = File::options().read(true).write(true).open(output.path())?;
        carrier.embed(&mut file, &store)?;
        file.sync_all()?;
    } else {
        let mut source = File::open(path)?;
        let mut target = File::options().read(true).write(true).open(output.path())?;
        c2pa::jumbf_io::save_jumbf_to_stream(format, &mut source, &mut target, &store)?;
        target.sync_all()?;
    }

    match verify(output.path())? {
        Some(result) if result.intact => replace(output, path),
        Some(result) => Err(Error::ManifestMismatch {
            path: path.to_path_buf(),
            problems: result.problems.join("; "),
        }),
        None => Err(Error::ManifestMismatch {
            path: path.to_path_buf(),
            problems: "no manifest found after embedding".to_owned(),
        }),
    }
}

fn read_store(path: &Path, format: &str) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    if let Some(carrier) = carrier(path) {
        return Ok(carrier
            .read(&mut file)?
            .ok_or(c2pa::Error::JumbfNotFound)?
            .0);
    }
    Ok(c2pa::jumbf_io::load_jumbf_from_stream(format, &mut file)?)
}

/// c2pa picks its handler from the extension, so the copy keeps it.
fn temp_beside(path: &Path) -> Result<tempfile::NamedTempFile> {
    let suffix = match file_name(path).and_then(archive::Kind::from_name) {
        Some((_, suffix)) => suffix.to_owned(),
        None => format!(
            ".{}",
            path.extension().unwrap_or_default().to_string_lossy()
        ),
    };
    Ok(tempfile::Builder::new()
        .suffix(&suffix)
        .tempfile_in(parent(path))?)
}

fn is_signed(path: &Path) -> Result<bool> {
    let format = media_type(path)?;
    let mut file = File::open(path)?;
    if let Some(carrier) = carrier(path) {
        return Ok(carrier.read(&mut file)?.is_some());
    }
    let context = Context::new().into_shared();
    match Reader::from_shared_context(&context).with_stream(format, &mut file) {
        Ok(_) => Ok(true),
        Err(c2pa::Error::JumbfNotFound) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn verifying_context(trust: &Trust) -> Result<Arc<Context>> {
    let Some(authorities) = trust.authorities() else {
        return Ok(Context::new().into_shared());
    };
    let settings = Settings::new().with_toml(&format!(
        "[[trust.anchors]]\ntrust_kind = \"manifest\"\ntrust_anchors = \'\'\'\n{authorities}\'\'\'\n"
    ))?;
    Ok(Context::new().with_settings(settings)?.into_shared())
}

fn signing_context(key: Arc<dyn DeviceKey>) -> Result<Arc<Context>> {
    let chain = key.certificate_chain_pem().to_vec();
    let callback = move |_context: *const (), data: &[u8]| {
        key.sign_es256(data)
            .map(|signature| signature.to_vec())
            .map_err(|e| c2pa::Error::OtherError(e.to_string().into()))
    };
    let signer = CallbackSigner::new(callback, SigningAlg::Es256, chain);
    let settings = Settings::new().with_toml(SIGNING_SETTINGS)?;
    Ok(Context::new()
        .with_settings(settings)?
        .with_signer(signer)
        .into_shared())
}

fn definition(path: &Path, format: &str) -> String {
    json!({
        "title": path.file_name().map(|n| n.to_string_lossy()),
        "format": format,
        "claim_generator_info": [{
            "name": "significant",
            "version": env!("CARGO_PKG_VERSION"),
        }],
        "assertions": [{
            "label": "c2pa.actions",
            "data": { "actions": [{
                "action": "c2pa.created",
                "digitalSourceType": DIGITAL_SOURCE_TYPE,
            }] },
        }],
    })
    .to_string()
}

fn claimed_name(report: &Value) -> Option<String> {
    let label = report["active_manifest"].as_str()?;
    report["manifests"][label]["signature_info"]["common_name"]
        .as_str()
        .map(str::to_owned)
}

fn has_success(report: &Value, code: &str) -> bool {
    report["validation_results"]["activeManifest"]["success"]
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item["code"] == code))
}

fn problems(report: &Value) -> Vec<String> {
    let failures = report["validation_results"]["activeManifest"]["failure"].as_array();
    failures
        .into_iter()
        .flatten()
        .map(
            |item| match (item["code"].as_str(), item["explanation"].as_str()) {
                (Some(code), Some(text)) => format!("{code}: {text}"),
                (Some(code), None) => code.to_owned(),
                _ => item.to_string(),
            },
        )
        .collect()
}

fn media_type(path: &Path) -> Result<&'static str> {
    if let Some((kind, _)) = file_name(path).and_then(archive::Kind::from_name) {
        return Ok(kind.media_type());
    }
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    match extension.as_deref() {
        Some("mkv") => Ok(MKV_MIME),
        Some("mp4" | "m4v") => Ok("video/mp4"),
        Some("mov") => Ok("video/quicktime"),
        Some("png") => Ok("image/png"),
        Some("jpg" | "jpeg") => Ok("image/jpeg"),
        Some("mp3") => Ok("audio/mpeg"),
        Some("m4a") => Ok("audio/mp4"),
        Some("wav") => Ok("audio/wav"),
        _ => Err(Error::UnsupportedFormat(path.to_path_buf())),
    }
}

fn parent(path: &Path) -> &Path {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    }
}

fn replace(output: tempfile::NamedTempFile, path: &Path) -> Result<()> {
    let permissions = fs::metadata(path)?.permissions();
    fs::set_permissions(output.path(), permissions)?;
    output.persist(path).map_err(|e| Error::Io(e.error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn element(id: &[u8], data: &[u8]) -> Vec<u8> {
        let mut out = id.to_vec();
        out.push(0x01);
        out.extend_from_slice(&(data.len() as u64).to_be_bytes()[1..]);
        out.extend_from_slice(data);
        out
    }

    fn sample_mkv() -> Vec<u8> {
        let mut segment = element(&[0x15, 0x49, 0xA9, 0x66], b"info");
        segment.extend(element(&[0x1F, 0x43, 0xB6, 0x75], &[0x42; 4096]));
        let mut file = element(&[0x1A, 0x45, 0xDF, 0xA3], b"hdr");
        file.extend(element(&[0x18, 0x53, 0x80, 0x67], &segment));
        file
    }

    /// Signs like a dishonest key holder choosing their own exclusions.
    fn signed_with(
        exclusions: impl Fn(&Range<u64>) -> Vec<HashRange>,
    ) -> (tempfile::TempDir, PathBuf, u64) {
        let exclusions = move |ranges: &[Range<u64>]| exclusions(&ranges[0]);
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        keys::generate(&keys, false).unwrap();
        let key: Arc<dyn DeviceKey> = Arc::new(FileKey::load(&keys).unwrap());
        let path = dir.path().join("video.mkv");
        let original = sample_mkv();
        fs::write(&path, &original).unwrap();

        let context = signing_context(key).unwrap();
        let mut builder = Builder::from_shared_context(&context)
            .with_definition(definition(&path, MKV_MIME))
            .unwrap();
        let mut file = File::options().read(true).write(true).open(&path).unwrap();
        sign_custom(&mut builder, Carrier::Mkv, MKV_MIME, &mut file, exclusions).unwrap();
        (dir, path, original.len() as u64 - 100)
    }

    fn honest(range: &Range<u64>) -> Vec<HashRange> {
        vec![HashRange::new(range.start, range.end - range.start)]
    }

    fn flip(path: &Path, offset: u64) {
        let mut bytes = fs::read(path).unwrap();
        bytes[offset as usize] ^= 0xFF;
        fs::write(path, bytes).unwrap();
    }

    fn assert_bad_exclusion(path: &Path) {
        let result = verify(path).unwrap().unwrap();
        assert!(!result.intact);
        assert!(
            result.problems.iter().any(|p| p.contains("not exactly")),
            "{:?}",
            result.problems
        );
    }

    #[test]
    fn occurrences_are_found_across_chunk_boundaries() {
        let data = b"..abcd..abcd..";
        for chunk in 1..=data.len() {
            let found = find_occurrences(&mut &data[..], b"abcd", 2, chunk).unwrap();
            assert_eq!(found, [2, 8], "chunk size {chunk}");
        }
        let found = find_occurrences(&mut &data[..], b"abcd", 1, 4).unwrap();
        assert_eq!(found, [2]);
        assert!(
            find_occurrences(&mut &data[..], b"zz", 2, 4)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn mkv_manifest_range_holds_the_manifest() {
        let (_dir, path, _) = signed_with(honest);
        let ranges = manifest_ranges(&path).unwrap().unwrap();
        let [range] = ranges.as_slice() else {
            panic!("expected one range: {ranges:?}");
        };
        let bytes = fs::read(&path).unwrap();
        let slice = &bytes[range.start as usize..range.end as usize];
        assert_eq!(slice, read_store(&path, MKV_MIME).unwrap());
    }

    fn empty_zip() -> Vec<u8> {
        let mut eocd = b"PK\x05\x06".to_vec();
        eocd.resize(22, 0);
        eocd
    }

    fn signed_archive(name: &str, contents: &[u8]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        keys::generate(&keys, false).unwrap();
        let key = FileKey::load(&keys).unwrap();
        let path = dir.path().join(name);
        fs::write(&path, contents).unwrap();
        sign(&path, Arc::new(key)).unwrap();
        (dir, path)
    }

    #[test]
    fn archives_verify_and_unsign_exactly() {
        let mut gz = b"\x1F\x8B".to_vec();
        gz.extend_from_slice(&[7; 900]);
        let cases: [(&str, Vec<u8>); 3] = [
            ("a.zip", empty_zip()),
            ("a.tar", vec![0; 2048]),
            ("a.tar.gz", gz),
        ];
        for (name, original) in cases {
            let (_dir, path) = signed_archive(name, &original);
            let result = verify(&path).unwrap().unwrap();
            assert!(result.intact, "{name}: {:?}", result.problems);
            let sidecar = sidecar_path(&path);
            assert!(unsign(&path, Some(&sidecar), false).unwrap());
            assert_eq!(fs::read(&path).unwrap(), original, "{name}");
            restore(&path, &sidecar).unwrap();
            assert!(verify(&path).unwrap().unwrap().intact, "{name}");
        }
    }

    #[test]
    fn archive_change_outside_the_manifest_fails() {
        let mut gz = b"\x1F\x8B".to_vec();
        gz.extend_from_slice(&[7; 900]);
        let (_dir, path) = signed_archive("a.tar.gz", &gz);
        flip(&path, 100);
        assert!(!verify(&path).unwrap().unwrap().intact);
    }

    fn signed_mkv() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        keys::generate(&keys, false).unwrap();
        let path = dir.path().join("video.mkv");
        fs::write(&path, sample_mkv()).unwrap();
        sign(&path, Arc::new(FileKey::load(&keys).unwrap())).unwrap();
        (dir, path, keys)
    }

    #[test]
    fn fingerprint_ignores_the_certificate_name() {
        let (_one, first, _) = signed_mkv();
        let (_two, second, _) = signed_mkv();
        let first = verify(&first).unwrap().unwrap();
        let second = verify(&second).unwrap().unwrap();
        assert_eq!(first.claimed_name, second.claimed_name);
        assert_ne!(first.fingerprint, second.fingerprint);
        assert!(first.fingerprint.is_some());
    }

    #[test]
    fn unknown_signer_is_intact_but_not_trusted() {
        let (_dir, path, _) = signed_mkv();
        let result = verify(&path).unwrap().unwrap();
        assert!(result.intact && !result.trusted);
    }

    #[test]
    fn trusted_device_is_recognized_and_others_are_not() {
        let (_one, path, _) = signed_mkv();
        let (_two, other, _) = signed_mkv();
        let list = tempfile::tempdir().unwrap();
        let id = verify(&path).unwrap().unwrap().fingerprint.unwrap();
        assert_eq!(Trust::add(list.path(), &id).unwrap(), Added::Device);
        let trust = Trust::load(list.path()).unwrap();
        assert!(verify_with(&path, &trust).unwrap().unwrap().trusted);
        assert!(!verify_with(&other, &trust).unwrap().unwrap().trusted);
    }

    #[test]
    fn trusted_authority_covers_its_signers_only() {
        let (_one, path, keys) = signed_mkv();
        let (_two, other, _) = signed_mkv();
        let list = tempfile::tempdir().unwrap();
        let authority = keys.join("device-ca.pem");
        assert_eq!(
            Trust::add(list.path(), authority.to_str().unwrap()).unwrap(),
            Added::Authorities(1)
        );
        let trust = Trust::load(list.path()).unwrap();
        let result = verify_with(&path, &trust).unwrap().unwrap();
        assert!(result.intact && result.trusted, "{:?}", result.problems);
        assert!(!verify_with(&other, &trust).unwrap().unwrap().trusted);
    }

    #[test]
    fn honest_mkv_verifies_and_detects_media_change() {
        let (_dir, path, media) = signed_with(honest);
        assert!(verify(&path).unwrap().unwrap().intact);
        flip(&path, media);
        assert!(!verify(&path).unwrap().unwrap().intact);
    }

    #[test]
    fn exclusion_covering_all_media_is_rejected() {
        let (_dir, path, _) = signed_with(|range| vec![HashRange::new(0, range.end)]);
        assert_bad_exclusion(&path);
    }

    #[test]
    fn exclusion_starting_early_is_rejected() {
        let (_dir, path, _) = signed_with(|range| {
            vec![HashRange::new(
                range.start - 1024,
                range.end - range.start + 1024,
            )]
        });
        assert_bad_exclusion(&path);
    }

    #[test]
    fn extra_exclusion_range_is_rejected() {
        let (_dir, path, _) = signed_with(|range| {
            let mut ranges = vec![HashRange::new(40, 1024)];
            ranges.extend(honest(range));
            ranges
        });
        assert_bad_exclusion(&path);
    }

    #[test]
    fn manifest_location_other_than_attachment_is_rejected() {
        let (_dir, path, _) =
            signed_with(|range| vec![HashRange::new(range.start + 1, range.end - range.start - 1)]);
        assert_bad_exclusion(&path);
    }
}
