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
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

use crate::Error;

const LEAF_KEY: &str = "signing-key.pem";
const CHAIN: &str = "chain.pem";
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

/// Creates a device CA and a leaf certificate. Returns the device ID.
pub fn generate(dir: &Path, force: bool) -> Result<String, Error> {
    if dir.join(LEAF_KEY).exists() && !force {
        return Err(Error::KeyExists(dir.to_path_buf()));
    }
    fs::create_dir_all(dir)?;

    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(key_error)?;
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(key_error)?;
    let device_id = hex16(&Sha256::digest(leaf_key.public_key_der()));

    let mut ca = params(&format!("significant device CA {device_id}"))?;
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca.self_signed(&ca_key).map_err(key_error)?;

    let mut leaf = params(&format!("significant device {device_id}"))?;
    leaf.is_ca = IsCa::ExplicitNoCa;
    leaf.use_authority_key_identifier_extension = true;
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
    let leaf_cert = leaf
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .map_err(key_error)?;

    write_private(&dir.join(LEAF_KEY), leaf_key.serialize_pem().as_bytes())?;
    fs::write(
        dir.join(CHAIN),
        format!("{}{}", leaf_cert.pem(), ca_cert.pem()),
    )?;
    Ok(device_id)
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

fn hex16(bytes: &[u8]) -> String {
    bytes[..8].iter().map(|b| format!("{b:02x}")).collect()
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
