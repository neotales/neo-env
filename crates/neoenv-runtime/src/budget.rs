//! Shared resource budgets for filesystem, module, archive, and transport I/O.
//!
//! `nenv` treats all bytes read from configuration, metadata, downloads, and
//! archives as untrusted input.  The limits in [`ResourceBudget`] are part of
//! the runtime contract: callers must fail with the named limit rather than
//! silently truncating or accepting a partial document.

use std::{
    fmt,
    fs::File,
    io::{self, Read},
    path::Path,
};

/// The resource limits shared by `nenv` installers, module loaders, and
/// transport adapters.
///
/// The default values are deliberately conservative but large enough for the
/// supported toolchain and runtime archives.  Tests and embedders can copy a
/// budget and lower individual fields; zero is a valid limit and is not
/// treated as an omitted value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceBudget {
    /// Maximum bytes in one local configuration or metadata document.
    pub metadata_bytes: u64,
    /// Maximum bytes retained for one buffered HTTP response or archive
    /// metadata member.
    pub http_body_bytes: u64,
    /// Maximum bytes in one downloaded artifact.
    pub artifact_bytes: u64,
    /// Maximum bytes retained from Git standard output.
    pub git_stdout_bytes: u64,
    /// Maximum bytes retained from Git standard error.
    pub git_stderr_bytes: u64,
    /// Maximum number of documents on one recursive module path.
    pub module_import_depth: usize,
    /// Maximum number of documents in one module graph.
    pub module_documents: usize,
    /// Maximum number of entries in one archive, including directories.
    pub archive_entries: u64,
    /// Maximum expanded bytes in one archive entry.
    pub archive_entry_bytes: u64,
    /// Maximum expanded bytes in one archive.
    pub archive_expanded_bytes: u64,
    /// Maximum encoded byte length of an archive path.
    pub archive_path_bytes: usize,
    /// Maximum number of components in an archive path.
    pub archive_path_components: usize,
    /// Maximum expanded bytes per downloaded compressed byte.
    pub expansion_ratio: u64,
}

impl ResourceBudget {
    /// One MiB, used for local documents and Git output streams.
    pub const MEBIBYTE: u64 = 1024 * 1024;
    /// 512 MiB, used for one downloaded artifact.
    pub const ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
    /// 256 MiB, used for one expanded archive entry.
    pub const ARCHIVE_ENTRY_BYTES: u64 = 256 * 1024 * 1024;
    /// One GiB, used for one expanded archive.
    pub const ARCHIVE_EXPANDED_BYTES: u64 = 1024 * 1024 * 1024;
    /// Maximum expansion ratio for a downloaded archive.
    pub const EXPANSION_RATIO: u64 = 100;

    /// Returns the documented default budget.
    #[must_use]
    pub const fn defaults() -> Self {
        Self {
            metadata_bytes: Self::MEBIBYTE,
            http_body_bytes: 8 * Self::MEBIBYTE,
            artifact_bytes: Self::ARTIFACT_BYTES,
            git_stdout_bytes: Self::MEBIBYTE,
            git_stderr_bytes: Self::MEBIBYTE,
            module_import_depth: 16,
            module_documents: 128,
            archive_entries: 10_000,
            archive_entry_bytes: Self::ARCHIVE_ENTRY_BYTES,
            archive_expanded_bytes: Self::ARCHIVE_EXPANDED_BYTES,
            archive_path_bytes: 4_096,
            archive_path_components: 128,
            expansion_ratio: Self::EXPANSION_RATIO,
        }
    }
}

impl Default for ResourceBudget {
    fn default() -> Self {
        Self::defaults()
    }
}

/// Identifies a resource whose configured limit was exceeded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceLimit {
    /// A local configuration or metadata document.
    Metadata,
    /// A buffered HTTP response body.
    HttpBody,
    /// A buffered metadata member read from an archive.
    ArchiveMetadata,
    /// A downloaded artifact.
    Artifact,
    /// Retained Git standard output.
    GitStdout,
    /// Retained Git standard error.
    GitStderr,
    /// Recursive module import depth.
    ModuleImportDepth,
    /// Number of documents in a module graph.
    ModuleDocuments,
    /// Number of entries in an archive.
    ArchiveEntries,
    /// Expanded bytes in one archive entry.
    ArchiveEntryBytes,
    /// Expanded bytes in one archive.
    ArchiveExpandedBytes,
    /// Encoded byte length of an archive path.
    ArchivePathBytes,
    /// Number of archive path components.
    ArchivePathComponents,
    /// Archive expansion ratio.
    ExpansionRatio,
}

impl ResourceLimit {
    /// Returns the stable human-readable name used in diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Metadata => "local metadata",
            Self::HttpBody => "HTTP response body",
            Self::ArchiveMetadata => "buffered archive metadata",
            Self::Artifact => "downloaded artifact",
            Self::GitStdout => "Git stdout",
            Self::GitStderr => "Git stderr",
            Self::ModuleImportDepth => "module import depth",
            Self::ModuleDocuments => "module document count",
            Self::ArchiveEntries => "archive entry count",
            Self::ArchiveEntryBytes => "archive entry bytes",
            Self::ArchiveExpandedBytes => "archive expanded bytes",
            Self::ArchivePathBytes => "archive path bytes",
            Self::ArchivePathComponents => "archive path components",
            Self::ExpansionRatio => "archive expansion ratio",
        }
    }
}

/// A stable error raised when a configured resource limit is exceeded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceLimitError {
    /// The resource whose limit was exceeded.
    pub resource: ResourceLimit,
    /// The configured limit, in the resource's native unit.
    pub limit: u64,
}

impl ResourceLimitError {
    /// Creates a limit diagnostic.
    #[must_use]
    pub const fn new(resource: ResourceLimit, limit: u64) -> Self {
        Self { resource, limit }
    }
}

impl fmt::Display for ResourceLimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "resource budget exceeded: {} limit {}",
            self.resource.name(),
            self.limit
        )
    }
}

impl std::error::Error for ResourceLimitError {}

/// A reader that fails as soon as a configured byte limit would be crossed.
///
/// The reader never returns bytes beyond its limit.  This makes it suitable
/// for HTTP response streams, subprocess pipes, and local files without first
/// buffering the complete input in memory.
pub struct BudgetReader<R> {
    reader: R,
    resource: ResourceLimit,
    limit: u64,
    consumed: u64,
}

impl<R> BudgetReader<R> {
    /// Wraps `reader` with the supplied resource limit.
    pub fn new(reader: R, resource: ResourceLimit, limit: u64) -> Self {
        Self {
            reader,
            resource,
            limit,
            consumed: 0,
        }
    }

    /// Returns the number of bytes accepted so far.
    #[must_use]
    pub const fn consumed(&self) -> u64 {
        self.consumed
    }

    /// Returns the configured limit.
    #[must_use]
    pub const fn limit(&self) -> u64 {
        self.limit
    }

    /// Consumes an additional chunk after checking the limit.
    fn account(&mut self, count: usize) -> Result<(), ResourceLimitError> {
        let count =
            u64::try_from(count).map_err(|_| ResourceLimitError::new(self.resource, self.limit))?;
        let Some(next) = self.consumed.checked_add(count) else {
            return Err(ResourceLimitError::new(self.resource, self.limit));
        };
        if next > self.limit {
            return Err(ResourceLimitError::new(self.resource, self.limit));
        }
        self.consumed = next;
        Ok(())
    }
}

impl<R: Read> Read for BudgetReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let remaining = self.limit.saturating_sub(self.consumed);
        if remaining == 0 {
            // Probe one byte so an exactly-at-limit stream can finish with EOF,
            // while an over-limit stream fails without returning that byte.
            let mut probe = [0_u8; 1];
            return match self.reader.read(&mut probe) {
                Ok(0) => Ok(0),
                Ok(_) => Err(io::Error::other(ResourceLimitError::new(
                    self.resource,
                    self.limit,
                ))),
                Err(error) => Err(error),
            };
        }
        let allowed = usize::try_from(remaining)
            .unwrap_or(buffer.len())
            .min(buffer.len());
        let count = self.reader.read(&mut buffer[..allowed])?;
        if count == 0 {
            return Ok(0);
        }
        if count > allowed {
            return Err(io::Error::other(ResourceLimitError::new(
                self.resource,
                self.limit,
            )));
        }
        self.account(count).map_err(io::Error::other)?;
        Ok(count)
    }
}

/// Reads a local document without retaining bytes beyond the metadata limit.
///
/// # Errors
///
/// Returns the underlying file error, or a stable resource-limit error when
/// the document exceeds `budget.metadata_bytes`.
pub fn read_file_bytes(path: &Path, budget: &ResourceBudget) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut reader = BudgetReader::new(file, ResourceLimit::Metadata, budget.metadata_bytes);
    let mut bytes = Vec::with_capacity(budget.metadata_bytes.min(8192) as usize);
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(bytes);
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
}

/// Reads a local UTF-8 document without retaining bytes beyond the metadata
/// limit.
///
/// # Errors
///
/// Returns the underlying file error, a stable resource-limit error, or an
/// invalid-UTF-8 error.
pub fn read_text_file(path: &Path, budget: &ResourceBudget) -> io::Result<String> {
    String::from_utf8(read_file_bytes(path, budget)?)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "local document is not UTF-8"))
}

#[cfg(unix)]
fn archive_path_bytes(path: &Path) -> usize {
    use std::os::unix::ffi::OsStrExt as _;
    path.as_os_str().as_bytes().len()
}

#[cfg(not(unix))]
fn archive_path_bytes(path: &Path) -> usize {
    path.as_os_str().to_string_lossy().len()
}

/// Mutable accounting shared by all supported archive extractors.
#[derive(Clone, Copy, Debug)]
pub struct ExtractionBudget {
    limits: ResourceBudget,
    compressed_size: Option<u64>,
    entries: u64,
    entry_bytes: u64,
    expanded_bytes: u64,
}

impl ExtractionBudget {
    /// Creates an extraction budget for a downloaded archive.
    ///
    /// `compressed_size` is the size of the downloaded file, not the expanded
    /// stream.  Passing `None` disables only the ratio check for callers that
    /// are extracting an already-open reader whose source size is unavailable;
    /// all byte and entry limits still apply.
    #[must_use]
    pub const fn new(limits: ResourceBudget, compressed_size: Option<u64>) -> Self {
        Self {
            limits,
            compressed_size,
            entries: 0,
            entry_bytes: 0,
            expanded_bytes: 0,
        }
    }

    /// Returns the configured limits.
    #[must_use]
    pub const fn limits(&self) -> &ResourceBudget {
        &self.limits
    }

    /// Returns the number of entries admitted so far.
    #[must_use]
    pub const fn entries(&self) -> u64 {
        self.entries
    }

    /// Returns the number of expanded file bytes admitted so far.
    #[must_use]
    pub const fn expanded_bytes(&self) -> u64 {
        self.expanded_bytes
    }

    /// Checks one entry header without counting it.  Metadata scans use this
    /// before a later extraction pass so a second pass does not charge the
    /// same archive member twice.
    ///
    /// # Errors
    ///
    /// Returns a stable error when the path or declared entry size exceeds a
    /// configured archive limit.
    pub fn check_entry(
        &self,
        path: &Path,
        declared_size: Option<u64>,
    ) -> Result<(), ResourceLimitError> {
        self.check_path(path)?;
        if let Some(size) = declared_size {
            self.check_entry_size(size)?;
            self.check_expanded_size(size)?;
        }
        Ok(())
    }

    /// Admits one archive entry and its path.
    ///
    /// # Errors
    ///
    /// Returns a stable error when the path, declared size, or entry count
    /// exceeds a configured archive limit.
    pub fn begin_entry(
        &mut self,
        path: &Path,
        declared_size: Option<u64>,
    ) -> Result<(), ResourceLimitError> {
        self.check_entry(path, declared_size)?;
        self.entries = self.entries.checked_add(1).ok_or(ResourceLimitError::new(
            ResourceLimit::ArchiveEntries,
            self.limits.archive_entries,
        ))?;
        if self.entries > self.limits.archive_entries {
            return Err(ResourceLimitError::new(
                ResourceLimit::ArchiveEntries,
                self.limits.archive_entries,
            ));
        }
        self.entry_bytes = 0;
        if let Some(size) = declared_size {
            self.check_entry_size(size)?;
            self.check_expanded_size(size)?;
        }
        Ok(())
    }

    /// Accounts bytes read from one file entry.
    ///
    /// # Errors
    ///
    /// Returns a stable error when the entry, archive, or expansion-ratio
    /// limit would be crossed.
    pub fn account_entry_bytes(&mut self, count: usize) -> Result<(), ResourceLimitError> {
        let count = u64::try_from(count).map_err(|_| {
            ResourceLimitError::new(
                ResourceLimit::ArchiveEntryBytes,
                self.limits.archive_entry_bytes,
            )
        })?;
        let entry_total = self.entry_bytes.saturating_add(count);
        if entry_total > self.limits.archive_entry_bytes {
            return Err(ResourceLimitError::new(
                ResourceLimit::ArchiveEntryBytes,
                self.limits.archive_entry_bytes,
            ));
        }
        self.check_expanded_size(count)?;
        self.entry_bytes = entry_total;
        self.expanded_bytes = self.expanded_bytes.saturating_add(count);
        Ok(())
    }

    /// Checks an archive path against both path limits.
    ///
    /// # Errors
    ///
    /// Returns a stable error when the encoded path length or component count
    /// exceeds its configured limit.
    pub fn check_path(&self, path: &Path) -> Result<(), ResourceLimitError> {
        let bytes = archive_path_bytes(path);
        if bytes > self.limits.archive_path_bytes {
            return Err(ResourceLimitError::new(
                ResourceLimit::ArchivePathBytes,
                self.limits.archive_path_bytes as u64,
            ));
        }
        let components = path.components().count();
        if components > self.limits.archive_path_components {
            return Err(ResourceLimitError::new(
                ResourceLimit::ArchivePathComponents,
                self.limits.archive_path_components as u64,
            ));
        }
        Ok(())
    }

    fn check_entry_size(&self, size: u64) -> Result<(), ResourceLimitError> {
        if size > self.limits.archive_entry_bytes {
            Err(ResourceLimitError::new(
                ResourceLimit::ArchiveEntryBytes,
                self.limits.archive_entry_bytes,
            ))
        } else {
            Ok(())
        }
    }

    fn check_expanded_size(&self, additional: u64) -> Result<(), ResourceLimitError> {
        let total = self.expanded_bytes.saturating_add(additional);
        if total > self.limits.archive_expanded_bytes {
            return Err(ResourceLimitError::new(
                ResourceLimit::ArchiveExpandedBytes,
                self.limits.archive_expanded_bytes,
            ));
        }
        if let Some(compressed_size) = self.compressed_size
            && additional > 0
            && (compressed_size == 0
                || total > compressed_size.saturating_mul(self.limits.expansion_ratio))
        {
            return Err(ResourceLimitError::new(
                ResourceLimit::ExpansionRatio,
                self.limits.expansion_ratio,
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};

    use super::{BudgetReader, ExtractionBudget, ResourceBudget, ResourceLimit};

    #[test]
    fn documented_defaults_match_the_resource_contract() {
        let budget = ResourceBudget::defaults();
        assert_eq!(budget.metadata_bytes, 1024 * 1024);
        assert_eq!(budget.http_body_bytes, 8 * 1024 * 1024);
        assert_eq!(budget.artifact_bytes, 512 * 1024 * 1024);
        assert_eq!(budget.archive_entries, 10_000);
        assert_eq!(budget.module_import_depth, 16);
        assert_eq!(budget.module_documents, 128);
    }

    #[test]
    fn limited_reader_does_not_return_the_byte_after_the_limit() {
        let mut reader = BudgetReader::new(Cursor::new(b"123456789"), ResourceLimit::Metadata, 8);
        let mut output = [0_u8; 9];
        let mut count = 0;
        let error = loop {
            match reader.read(&mut output[count..]) {
                Ok(0) => panic!("the over-limit stream unexpectedly ended"),
                Ok(read) => count += read,
                Err(error) => break error,
            }
        };
        assert_eq!(count, 8);
        assert!(error.to_string().contains("local metadata limit 8"));
    }

    #[test]
    fn artifact_limit_is_checked_without_allocating_the_full_limit() {
        let mut reader =
            BudgetReader::new(Cursor::new(b"small fixture"), ResourceLimit::Artifact, 4);
        let mut output = [0_u8; 5];
        assert_eq!(reader.read(&mut output).unwrap(), 4);
        let error = reader.read(&mut output).unwrap_err();
        assert!(error.to_string().contains("downloaded artifact limit 4"));
    }

    #[test]
    fn zero_compressed_size_rejects_every_expanded_byte() {
        let limits = ResourceBudget::default();
        let mut budget = ExtractionBudget::new(limits, Some(0));
        let error = budget
            .begin_entry(std::path::Path::new("entry"), Some(1))
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("archive expansion ratio limit 100")
        );
    }

    #[test]
    fn extraction_budget_checks_ratio_before_reading_a_declared_bomb() {
        let limits = ResourceBudget {
            expansion_ratio: 2,
            ..ResourceBudget::default()
        };
        let mut budget = ExtractionBudget::new(limits, Some(2));
        let path = std::path::Path::new("entry");
        assert!(budget.begin_entry(path, Some(5)).is_err());
        assert_eq!(budget.entries(), 0);
    }
}
