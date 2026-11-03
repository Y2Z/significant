//! Signing keys. `DeviceKey` is the seam for phone hardware.
use std::fs;
use std::path::{Path, PathBuf};

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey as _;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyIdMethod, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use time::{Duration, OffsetDateTime};

use crate::Error;

const LEAF_KEY: &str = "signing-key.pem";
const CHAIN: &str = "chain.pem";
const AUTHORITY: &str = "device-ca.pem";
const LOCK: &str = ".key.lock";
const VALIDITY_DAYS: i64 = 3650;

/// A P-256 key that can sign but need not reveal its private half.
///
/// A phone implementation would call Android Keystore or the iOS Secure
/// Enclave here. `sign` must return the 64-byte `r || s` form, not DER.
pub trait DeviceKey: Send + Sync {
    fn certificate_chain_pem(&self) -> &[u8];
    fn sign_es256(&self, message: &[u8]) -> Result<[u8; 64], Error>;
}

/// Development key stored in a file. It does not meet the hardware goal.
pub struct FileKey {
    key: SigningKey,
    chain: Vec<u8>,
}

impl FileKey {
    pub fn load(dir: &Path) -> Result<Self, Error> {
        let pem = fs::read_to_string(dir.join(LEAF_KEY)).map_err(|source| Error::KeyMissing {
            dir: dir.to_path_buf(),
            source,
        })?;
        let key = SigningKey::from_pkcs8_pem(&pem).map_err(|e| Error::Key(e.to_string()))?;
        let chain = fs::read(dir.join(CHAIN))?;
        Ok(Self { key, chain })
    }

    /// Loads the key in `dir`, creating one if there is none. Also returns the
    /// new fingerprint when a key was created.
    ///
    /// Processes starting at the same time all end up with the same key. The
    /// lock is released by the operating system, even after a crash.
    pub fn load_or_create(dir: &Path) -> Result<(Self, Option<String>), Error> {
        fs::create_dir_all(dir)?;
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join(LOCK))?;
        lock.lock()?;
        if dir.join(LEAF_KEY).exists() {
            return Ok((Self::load(dir)?, None));
        }
        let fingerprint = generate(dir, false)?;
        Ok((Self::load(dir)?, Some(fingerprint)))
    }
}

impl DeviceKey for FileKey {
    fn certificate_chain_pem(&self) -> &[u8] {
        &self.chain
    }

    fn sign_es256(&self, message: &[u8]) -> Result<[u8; 64], Error> {
        let signature: Signature = self.key.sign(message);
        Ok(signature.to_bytes().into())
    }
}

pub fn default_key_dir() -> Result<PathBuf, Error> {
    if let Some(dir) = std::env::var_os("SIGNIFICANT_HOME") {
        return Ok(dir.into());
    }
    let home = std::env::var_os("HOME").ok_or_else(|| Error::Key("HOME is not set".into()))?;
    Ok(PathBuf::from(home).join(".config/significant"))
}

/// Creates a device CA and a leaf certificate. Returns the device fingerprint.
pub fn generate(dir: &Path, force: bool) -> Result<String, Error> {
    if dir.join(LEAF_KEY).exists() && !force {
        return Err(Error::KeyExists(dir.to_path_buf()));
    }
    fs::create_dir_all(dir)?;

    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(key_error)?;
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(key_error)?;

    let mut ca = params("significant device CA")?;
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca.self_signed(&ca_key).map_err(key_error)?;

    let mut leaf = params("significant device")?;
    leaf.is_ca = IsCa::ExplicitNoCa;
    leaf.use_authority_key_identifier_extension = true;
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
    let leaf_cert = leaf
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .map_err(key_error)?;

    // The key is written last, so its presence means the set is complete.
    let chain = format!("{}{}", leaf_cert.pem(), ca_cert.pem());
    fs::write(dir.join(CHAIN), &chain)?;
    fs::write(dir.join(AUTHORITY), ca_cert.pem())?;
    write_private(&dir.join(LEAF_KEY), leaf_key.serialize_pem().as_bytes())?;
    crate::trust::fingerprint(chain.as_bytes())
}

fn params(name: &str) -> Result<CertificateParams, Error> {
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(key_error)?;
    let mut subject = DistinguishedName::new();
    subject.push(DnType::CommonName, name);
    subject.push(DnType::OrganizationName, "significant self-issued device");
    params.distinguished_name = subject;
    params.key_identifier_method = KeyIdMethod::Sha256;
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(VALIDITY_DAYS);
    Ok(params)
}

fn key_error(error: impl std::fmt::Display) -> Error {
    Error::Key(error.to_string())
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    fs::write(path, bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_use_creates_a_key_and_later_uses_load_it() {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("nested/keys");
        let (first, created) = FileKey::load_or_create(&keys).unwrap();
        assert!(created.is_some());
        let (second, created) = FileKey::load_or_create(&keys).unwrap();
        assert!(created.is_none());
        assert_eq!(
            first.certificate_chain_pem(),
            second.certificate_chain_pem()
        );
    }

    #[test]
    fn parallel_first_uses_share_one_key() {
        let dir = tempfile::tempdir().unwrap();
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let keys = dir.path().join("keys");
                std::thread::spawn(move || FileKey::load_or_create(&keys).unwrap())
            })
            .collect();
        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        let created = results.iter().filter(|(_, new)| new.is_some()).count();
        assert_eq!(created, 1);
        let chain = results[0].0.certificate_chain_pem();
        assert!(
            results
                .iter()
                .all(|(key, _)| key.certificate_chain_pem() == chain)
        );
    }
}
