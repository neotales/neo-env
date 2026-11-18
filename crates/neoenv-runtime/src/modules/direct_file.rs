//! Digest-pinned single-file transport. This does not load or approve code.
//!
//! Consumers must parse the returned bytes, not reopen the cache path, and
//! must apply their own execution authorization and import containment.

use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    budget::{ResourceBudget, read_file_bytes},
    remote::RemoteError,
    transport::HttpPolicy,
};

/// A distinct single-file source; unlike a tarball, its digest is over the
/// exact document bytes. Constructing it never performs network I/O.
#[derive(Clone, Debug)]
pub struct DirectFileSource {
    url: String,
    digest: String,
    format: neoenv_config::Format,
}

impl DirectFileSource {
    pub(crate) fn is_direct(value: &str) -> bool {
        value.ends_with("&type=file")
    }

    pub(crate) fn url(&self) -> &str {
        &self.url
    }

    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }

    /// Parses an HTTPS URL with `#sha256=<64 hex digits>&type=file`.
    ///
    /// The explicit marker keeps this source distinct from the pre-existing
    /// tarball syntax, which accepts pinned URLs regardless of their suffix.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, credential-bearing or unpinned sources.
    pub fn parse(value: &str) -> Result<Self, RemoteError> {
        let (url, fragment) = value
            .split_once("#sha256=")
            .ok_or(RemoteError::InvalidSource)?;
        let digest = fragment
            .strip_suffix("&type=file")
            .ok_or(RemoteError::InvalidSource)?;
        let parsed = Url::parse(url).map_err(|_| RemoteError::InvalidSource)?;
        if !url.starts_with("https://")
            || url.contains('@')
            || url
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b' ')
            || parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || digest.len() != 64
            || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(RemoteError::InvalidSource);
        }
        let format = neoenv_config::Format::from_path(Path::new(parsed.path()))
            .map_err(|_| RemoteError::InvalidSource)?;
        if format == neoenv_config::Format::Neoenv {
            return Err(RemoteError::InvalidSource);
        }
        Ok(Self {
            url: url.into(),
            digest: digest.to_ascii_lowercase(),
            format,
        })
    }

    /// Returns the syntax selected from the source URL, not the cache path.
    #[must_use]
    pub const fn format(&self) -> neoenv_config::Format {
        self.format
    }

    pub(crate) fn path(&self, root: &Path) -> PathBuf {
        root.join(neoenv_core::names::PROJECT_MODULE_CACHE)
            .join("files")
            .join(&self.digest)
    }

    fn verify(&self, bytes: &[u8]) -> Result<(), RemoteError> {
        if format!("{:x}", Sha256::digest(bytes)) != self.digest {
            return Err(RemoteError::CacheMismatch(self.url.clone()));
        }
        Ok(())
    }
}

/// Reads and re-verifies the exact bytes on every cache access.
///
/// # Errors
///
/// Returns an error for a missing, oversized, unreadable or tampered entry.
pub fn cached_direct_file(root: &Path, source: &DirectFileSource) -> Result<Vec<u8>, RemoteError> {
    let bytes =
        read_file_bytes(&source.path(root), &ResourceBudget::default()).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                RemoteError::NotFetched(source.url.clone())
            } else {
                RemoteError::io_source("read cached direct file", error)
            }
        })?;
    source.verify(&bytes)?;
    Ok(bytes)
}

/// Explicitly downloads a pinned single file into the content-addressed cache.
/// This is not an execution approval and does not parse the downloaded bytes.
///
/// # Errors
///
/// Returns an error on transport, size, digest, or cache publication failure.
pub fn fetch_direct_file(root: &Path, source: &DirectFileSource) -> Result<Vec<u8>, RemoteError> {
    let path = source.path(root);
    if path.exists() {
        return cached_direct_file(root, source);
    }
    let limit = ResourceBudget::default().metadata_bytes;
    let policy = HttpPolicy::from_environment().map_err(RemoteError::policy_source)?;
    let response = policy
        .get(&source.url)
        .map_err(|error| RemoteError::http_source("download direct file", error))?;
    policy
        .validate_artifact_length(&source.url, &response, limit)
        .map_err(|error| RemoteError::http_source("validate direct file response", error))?;
    let mut input = policy.streaming_reader_limited(&source.url, response, limit);
    let mut bytes = Vec::new();
    input
        .read_to_end(&mut bytes)
        .map_err(|error| RemoteError::io_source("read direct file response", error))?;
    source.verify(&bytes)?;

    let parent = path.parent().ok_or(RemoteError::InvalidSource)?;
    fs::create_dir_all(parent)
        .map_err(|error| RemoteError::io_source("create direct file cache", error))?;
    let mut staging = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| RemoteError::io_source("create direct file staging", error))?;
    staging
        .write_all(&bytes)
        .and_then(|()| staging.as_file().sync_all())
        .map_err(|error| RemoteError::io_source("write direct file staging", error))?;
    match staging.persist_noclobber(&path) {
        Ok(_) => Ok(bytes),
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
            cached_direct_file(root, source)
        }
        Err(error) => Err(RemoteError::io_source(
            "publish direct file cache",
            error.error,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(bytes: &[u8]) -> DirectFileSource {
        DirectFileSource::parse(&format!(
            "https://example.test/tasks.yaml#sha256={:x}&type=file",
            Sha256::digest(bytes)
        ))
        .unwrap()
    }

    #[test]
    fn direct_file_rejects_unpinned_invalid_and_credential_urls() {
        for value in [
            "https://example.test/tasks.yaml",
            "https://example.test/tasks.yaml#sha256=bad",
            "https://example.test/tasks.yaml#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "http://example.test/tasks.yaml#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&type=file",
            "https://user@example.test/tasks.yaml#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&type=file",
            "https://example.test/tasks.yaml?token=secret#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&type=file",
        ] {
            assert!(DirectFileSource::parse(value).is_err(), "{value}");
        }
    }

    #[test]
    fn direct_file_cache_verifies_each_read_and_detects_tampering() {
        let temp = tempfile::tempdir().unwrap();
        let expected = b"tasks:\n  lint: echo ok\n";
        let source = source(expected);
        assert!(matches!(
            cached_direct_file(temp.path(), &source),
            Err(RemoteError::NotFetched(_))
        ));
        let path = source.path(temp.path());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, expected).unwrap();
        assert_eq!(cached_direct_file(temp.path(), &source).unwrap(), expected);
        fs::write(&path, b"changed").unwrap();
        assert!(matches!(
            cached_direct_file(temp.path(), &source),
            Err(RemoteError::CacheMismatch(_))
        ));
    }

    #[test]
    fn direct_file_cache_rejects_oversized_content() {
        let temp = tempfile::tempdir().unwrap();
        let source = source(b"small");
        let path = source.path(temp.path());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            path,
            vec![0; ResourceBudget::default().metadata_bytes as usize + 1],
        )
        .unwrap();
        assert!(cached_direct_file(temp.path(), &source).is_err());
    }

    #[test]
    fn direct_file_format_is_selected_from_the_source_url() {
        let digest = "a".repeat(64);
        for (name, expected) in [
            ("module.yml", neoenv_config::Format::Yaml),
            ("module.yaml", neoenv_config::Format::Yaml),
            ("module.toml", neoenv_config::Format::Toml),
        ] {
            let value = format!("https://example.test/{name}#sha256={digest}&type=file");
            assert_eq!(DirectFileSource::parse(&value).unwrap().format(), expected);
        }
        let value = format!("https://example.test/module#sha256={digest}&type=file");
        assert!(DirectFileSource::parse(&value).is_err());
    }
}
