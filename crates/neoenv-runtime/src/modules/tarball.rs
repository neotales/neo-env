//! Remote module tarballs: bounded download, cached extraction, and
//! link-aware entry copying that refuses to escape the destination.

use super::{
    Component, Digest, ExtractionBudget, GzDecoder, HttpPolicy, Path, PathBuf, Read, RemoteError,
    ResourceBudget, Sha256, Write, fs, io, module_document, read_text_file,
};

pub(crate) struct TarballModule {
    url: String,
    digest: String,
}

impl TarballModule {
    pub(crate) fn parse(value: &str) -> Result<Option<Self>, RemoteError> {
        let Some((url, digest)) = value.split_once("#sha256=") else {
            return Ok(None);
        };
        if !url.starts_with("https://")
            || url.contains('@')
            || digest.len() != 64
            || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(RemoteError::InvalidSource);
        }
        Ok(Some(Self {
            url: url.into(),
            digest: digest.to_ascii_lowercase(),
        }))
    }
}

pub(crate) struct CachedTarball {
    pub path: PathBuf,
    pub source_root: PathBuf,
    pub url: String,
    pub digest: String,
}

pub(super) fn cached_tarball(root: &Path, tarball: &TarballModule) -> Result<PathBuf, RemoteError> {
    cached_tarball_details(root, tarball).map(|cached| cached.path)
}

pub(crate) fn cached_tarball_details(
    root: &Path,
    tarball: &TarballModule,
) -> Result<CachedTarball, RemoteError> {
    let cache = root
        .join(neoenv_core::names::MODULE_TARBALLS)
        .join(&tarball.digest);
    let metadata = read_text_file(&cache.join("metadata.toml"), &ResourceBudget::default())
        .map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                RemoteError::NotFetched(tarball.url.clone())
            } else {
                RemoteError::io_source("read cached tarball metadata", error)
            }
        })?;
    let expected = format!("url = {:?}\nsha256 = {:?}\n", tarball.url, tarball.digest);
    if metadata != expected {
        return Err(RemoteError::CacheMismatch(tarball.url.clone()));
    }
    let source = fs::canonicalize(cache.join("source"))
        .map_err(|_| RemoteError::NotFetched(tarball.url.clone()))?;
    let cache =
        fs::canonicalize(cache).map_err(|_| RemoteError::CacheMismatch(tarball.url.clone()))?;
    if !source.starts_with(&cache) {
        return Err(RemoteError::CacheMismatch(tarball.url.clone()));
    }
    let document = module_document(&source)
        .map_err(|error| RemoteError::diagnostic_source("read cached module document", error))?;
    if document.starts_with(&source) {
        Ok(CachedTarball {
            path: document,
            source_root: source,
            url: tarball.url.clone(),
            digest: tarball.digest.clone(),
        })
    } else {
        Err(RemoteError::CacheMismatch(tarball.url.clone()))
    }
}

/// Explicitly downloads, verifies, and safely extracts a digest-pinned tarball.
/// Inspection never calls this function; it only reads the resulting cache.
///
/// # Errors
///
/// Returns an error for mutable or credential-bearing sources, transport and
/// digest failures, unsafe archive entries, or cache publication failures.
pub fn fetch_tarball_module(project_root: &Path, import: &str) -> Result<PathBuf, RemoteError> {
    let tarball = TarballModule::parse(import)?.ok_or(RemoteError::InvalidSource)?;
    let cache = project_root
        .join(neoenv_core::names::MODULE_TARBALLS)
        .join(&tarball.digest);
    if cache.exists() {
        return cached_tarball(project_root, &tarball);
    }
    let parent = cache
        .parent()
        .ok_or_else(|| RemoteError::Io("invalid tarball cache path".into()))?;
    fs::create_dir_all(parent)
        .map_err(|error| RemoteError::io_source("create tarball cache directory", error))?;
    let temporary = tempfile::Builder::new()
        .prefix("neoenv-tarball-")
        .tempdir_in(parent)
        .map_err(|error| RemoteError::io_source("create tarball staging directory", error))?;
    let archive = temporary.path().join("module.tar.gz");
    let limits = ResourceBudget::default();
    let policy = HttpPolicy::from_environment().map_err(RemoteError::policy_source)?;
    let response = policy
        .get(&tarball.url)
        .map_err(|error| RemoteError::http_source("download tarball", error))?;
    policy
        .validate_artifact_length(&tarball.url, &response, limits.artifact_bytes)
        .map_err(|error| RemoteError::http_source("validate tarball response", error))?;
    let mut input = policy.streaming_reader_limited(&tarball.url, response, limits.artifact_bytes);
    let mut output = fs::File::create(&archive)
        .map_err(|error| RemoteError::io_source("create tarball archive", error))?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = input
            .read(&mut buffer)
            .map_err(|error| RemoteError::io_source("read tarball response", error))?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        output
            .write_all(&buffer[..count])
            .map_err(|error| RemoteError::io_source("write tarball archive", error))?;
    }
    output
        .sync_all()
        .map_err(|error| RemoteError::io_source("sync tarball archive", error))?;
    if format!("{:x}", hash.finalize()) != tarball.digest {
        return Err(RemoteError::CacheMismatch(tarball.url));
    }
    extract_tarball(&archive, &temporary.path().join("source"))?;
    fs::write(
        temporary.path().join("metadata.toml"),
        format!("url = {:?}\nsha256 = {:?}\n", tarball.url, tarball.digest),
    )
    .map_err(|error| RemoteError::io_source("write tarball metadata", error))?;
    fs::rename(temporary.keep(), &cache)
        .map_err(|error| RemoteError::io_source("publish tarball cache", error))?;
    cached_tarball(project_root, &tarball)
}

pub(super) fn extract_tarball(archive: &Path, destination: &Path) -> Result<(), RemoteError> {
    let limits = ResourceBudget::default();
    let compressed_size = fs::metadata(archive)
        .map(|metadata| metadata.len())
        .map_err(|error| RemoteError::io_source("inspect tarball", error))?;
    if compressed_size > limits.artifact_bytes {
        return Err(RemoteError::archive_source(
            "enforce tarball size budget",
            crate::budget::ResourceLimitError::new(
                crate::budget::ResourceLimit::Artifact,
                limits.artifact_bytes,
            ),
        ));
    }
    let mut budget = ExtractionBudget::new(limits, Some(compressed_size));
    extract_tarball_with_budget(archive, destination, &mut budget)
}

fn extract_tarball_with_budget(
    archive: &Path,
    destination: &Path,
    budget: &mut ExtractionBudget,
) -> Result<(), RemoteError> {
    fs::create_dir_all(destination)
        .map_err(|error| RemoteError::io_source("create archive destination", error))?;
    let input = fs::File::open(archive)
        .map_err(|error| RemoteError::io_source("open downloaded archive", error))?;
    let mut archive = tar::Archive::new(GzDecoder::new(input));
    for entry in archive
        .entries()
        .map_err(|error| RemoteError::archive_source("read tar archive", error))?
    {
        let mut entry =
            entry.map_err(|error| RemoteError::archive_source("read tar archive entry", error))?;
        let path = entry
            .path()
            .map_err(|error| RemoteError::archive_source("read tar entry path", error))?;
        let declared_size = entry
            .header()
            .size()
            .map_err(|error| RemoteError::archive_source("read tar entry size", error))?;
        budget
            .begin_entry(path.as_ref(), Some(declared_size))
            .map_err(|error| RemoteError::archive_source("enforce tar entry budget", error))?;
        if path.as_os_str().is_empty()
            || path.is_absolute()
            || path
                .components()
                .any(|part| !matches!(part, Component::Normal(_) | Component::CurDir))
        {
            return Err(RemoteError::CacheMismatch(
                "tarball contains an escaping path".into(),
            ));
        }
        let destination_path = destination.join(path.as_ref());
        if entry.header().entry_type().is_dir() {
            fs::create_dir_all(destination_path)
                .map_err(|error| RemoteError::io_source("create archive directory", error))?;
        } else if entry.header().entry_type().is_file() {
            let parent = destination_path
                .parent()
                .ok_or_else(|| RemoteError::Io("invalid archive path".into()))?;
            fs::create_dir_all(parent)
                .map_err(|error| RemoteError::io_source("create archive entry directory", error))?;
            let mut output = fs::File::create(destination_path)
                .map_err(|error| RemoteError::io_source("create archive entry", error))?;
            copy_archive_entry(&mut entry, &mut output, budget)?;
        } else {
            return Err(RemoteError::CacheMismatch(
                "tarball contains links or special files".into(),
            ));
        }
    }
    Ok(())
}

fn copy_archive_entry(
    input: &mut impl Read,
    output: &mut impl Write,
    budget: &mut ExtractionBudget,
) -> Result<(), RemoteError> {
    let mut buffer = [0_u8; 8192];
    loop {
        let count = input
            .read(&mut buffer)
            .map_err(|error| RemoteError::archive_source("read archive entry", error))?;
        if count == 0 {
            return Ok(());
        }
        budget
            .account_entry_bytes(count)
            .map_err(|error| RemoteError::archive_source("enforce archive entry budget", error))?;
        output
            .write_all(&buffer[..count])
            .map_err(|error| RemoteError::io_source("write archive entry", error))?;
    }
}
