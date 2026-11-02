//! Which signers to trust: individual devices, and certificate authorities.
use std::collections::BTreeSet;
use std::fs;
use std::io::Write as _;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::Error;

const DEVICES_FILE: &str = "trusted-devices.txt";
const AUTHORITIES_FILE: &str = "trusted-authorities.pem";
const FINGERPRINT_LEN: usize = 64;

/// The signers `verify` should treat as known. Empty by default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trust {
    devices: BTreeSet<String>,
    authorities: String,
}

/// What [`Trust::add`] stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Added {
    Device,
    Authorities(usize),
}

impl Trust {
    /// Loads a trust list. Missing files mean nothing is trusted.
    pub fn load(dir: &Path) -> Result<Self, Error> {
        Ok(Self {
            devices: read_optional(&dir.join(DEVICES_FILE))?
                .lines()
                .filter_map(parse_fingerprint)
                .collect(),
            authorities: read_optional(&dir.join(AUTHORITIES_FILE))?,
        })
    }

    /// Saves a device fingerprint, or the authorities in a PEM file.
    pub fn add(dir: &Path, value: &str) -> Result<Added, Error> {
        fs::create_dir_all(dir)?;
        if let Some(fingerprint) = parse_fingerprint(value) {
            if !Self::load(dir)?.devices.contains(&fingerprint) {
                append(&dir.join(DEVICES_FILE), &format!("{fingerprint}\n"))?;
            }
            return Ok(Added::Device);
        }

        let text = fs::read_to_string(value)
            .map_err(|_| Error::Trust(format!("{value} is not a fingerprint or a PEM file")))?;
        let certificates = certificates(text.as_bytes())?;
        if certificates.is_empty() {
            return Err(Error::Trust(format!("{value} has no certificates")));
        }
        append(&dir.join(AUTHORITIES_FILE), &ensure_newline(text))?;
        Ok(Added::Authorities(certificates.len()))
    }

    pub fn has_device(&self, fingerprint: &str) -> bool {
        self.devices.contains(fingerprint)
    }

    /// The authorities as a PEM bundle, if there are any.
    pub fn authorities(&self) -> Option<&str> {
        (!self.authorities.trim().is_empty()).then_some(&self.authorities)
    }
}

/// SHA-256 of the signing certificate, the first in a PEM chain.
///
/// Unlike a certificate's name, this cannot be copied: a certificate only
/// verifies a signature made by its own private key.
pub fn fingerprint(chain_pem: &[u8]) -> Result<String, Error> {
    let certificates = certificates(chain_pem)?;
    let leaf = certificates
        .first()
        .ok_or_else(|| Error::Trust("certificate chain is empty".to_owned()))?;
    Ok(Sha256::digest(leaf)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn certificates(pem_text: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let blocks = pem::parse_many(pem_text).map_err(|e| Error::Trust(e.to_string()))?;
    Ok(blocks
        .iter()
        .filter(|block| block.tag() == "CERTIFICATE")
        .map(|block| block.contents().to_vec())
        .collect())
}

/// Accepts 64 hex digits, with or without a `sha256:` prefix.
fn parse_fingerprint(value: &str) -> Option<String> {
    let value = value.trim();
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    (value.len() == FINGERPRINT_LEN && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

fn read_optional(path: &Path) -> Result<String, Error> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(error.into()),
    }
}

fn append(path: &Path, text: &str) -> Result<(), Error> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn ensure_newline(mut text: String) -> String {
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_are_normalized() {
        let hex = "AB".repeat(32);
        let expected = "ab".repeat(32);
        assert_eq!(parse_fingerprint(&hex).as_deref(), Some(expected.as_str()));
        let prefixed = format!(" sha256:{hex}\n");
        assert_eq!(
            parse_fingerprint(&prefixed).as_deref(),
            Some(expected.as_str())
        );
        assert!(parse_fingerprint("abcd").is_none());
        assert!(parse_fingerprint(&"zz".repeat(32)).is_none());
    }

    #[test]
    fn devices_are_saved_once() {
        let dir = tempfile::tempdir().unwrap();
        let value = "cd".repeat(32);
        assert_eq!(Trust::add(dir.path(), &value).unwrap(), Added::Device);
        assert_eq!(Trust::add(dir.path(), &value).unwrap(), Added::Device);
        let text = fs::read_to_string(dir.path().join(DEVICES_FILE)).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(Trust::load(dir.path()).unwrap().has_device(&value));
    }

    #[test]
    fn missing_lists_trust_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let trust = Trust::load(dir.path()).unwrap();
        assert_eq!(trust, Trust::default());
        assert!(trust.authorities().is_none());
    }

    #[test]
    fn bad_values_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Trust::add(dir.path(), "not-a-file").is_err());
        let empty = dir.path().join("empty.pem");
        fs::write(&empty, "no certificates here").unwrap();
        assert!(Trust::add(dir.path(), empty.to_str().unwrap()).is_err());
    }
}
