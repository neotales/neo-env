//! Pure domain types shared by every `nenv` implementation layer.

use std::{error::Error, fmt, sync::Arc};

use serde::{Deserialize, Serialize};

pub mod names;
pub mod tasks;
pub mod tools;
pub mod version;

/// Stable process-exit categories emitted by the CLI layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum ExitCategory {
    Success = 0,
    Usage = 2,
    Validation = 3,
    NotFound = 4,
    Trust = 5,
    Runtime = 6,
    Internal = 70,
}

impl ExitCategory {
    #[must_use]
    pub const fn code(self) -> i32 {
        self as i32
    }
}

/// A one-based position in a configuration source.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceSpan {
    pub path: String,
    pub line: u32,
    pub column: u32,
}

impl SourceSpan {
    #[must_use]
    pub const fn new(path: String, line: u32, column: u32) -> Self {
        Self { path, line, column }
    }
}

/// A stable category for a user-visible diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCategory {
    Usage,
    Validation,
    NotFound,
    Trust,
    Runtime,
    Internal,
}

impl DiagnosticCategory {
    #[must_use]
    pub const fn exit_category(self) -> ExitCategory {
        match self {
            Self::Usage => ExitCategory::Usage,
            Self::Validation => ExitCategory::Validation,
            Self::NotFound => ExitCategory::NotFound,
            Self::Trust => ExitCategory::Trust,
            Self::Runtime => ExitCategory::Runtime,
            Self::Internal => ExitCategory::Internal,
        }
    }
}

/// A location-aware error that can be rendered as text or JSON.
#[derive(Debug, Serialize)]
pub struct Diagnostic {
    pub category: DiagnosticCategory,
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceSpan>,
    /// The originating error remains available to library callers. It is
    /// deliberately excluded from the stable diagnostic JSON contract: only
    /// the explicitly redacted `message` is rendered at the CLI boundary.
    #[serde(skip)]
    cause: Option<Arc<dyn Error + Send + Sync>>,
}

impl Clone for Diagnostic {
    fn clone(&self) -> Self {
        Self {
            category: self.category,
            code: self.code.clone(),
            message: self.message.clone(),
            source: self.source.clone(),
            cause: self.cause.clone(),
        }
    }
}

impl PartialEq for Diagnostic {
    fn eq(&self, other: &Self) -> bool {
        self.category == other.category
            && self.code == other.code
            && self.message == other.message
            && self.source == other.source
    }
}

impl Eq for Diagnostic {}

impl Diagnostic {
    #[must_use]
    pub fn new(
        category: DiagnosticCategory,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            category,
            code: code.into(),
            message: message.into(),
            source: None,
            cause: None,
        }
    }

    /// Attaches an operational error without exposing it in text or JSON
    /// diagnostics. The caller supplies a stable, credential-safe message.
    #[must_use]
    pub fn with_cause<E>(mut self, cause: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        self.cause = Some(Arc::new(cause));
        self
    }

    #[must_use]
    pub fn at(mut self, source: SourceSpan) -> Self {
        self.source = Some(source);
        self
    }

    #[must_use]
    pub const fn exit_category(&self) -> ExitCategory {
        self.category.exit_category()
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(source) = &self.source {
            write!(
                formatter,
                "{}:{}:{}: {}",
                source.path, source.line, source.column, self.message
            )
        } else {
            formatter.write_str(&self.message)
        }
    }
}

impl std::error::Error for Diagnostic {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.cause
            .as_deref()
            .map(|cause| cause as &(dyn Error + 'static))
    }
}

/// The versioned JSON envelope emitted for CLI failures.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DiagnosticDocument {
    pub schema_version: u32,
    pub diagnostic: Diagnostic,
}

impl DiagnosticDocument {
    pub const SCHEMA_VERSION: u32 = 1;

    #[must_use]
    pub fn from_diagnostic(diagnostic: &Diagnostic) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            diagnostic: diagnostic.clone(),
        }
    }
}

/// The stable JSON envelope emitted by read-only inspection commands.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InspectionDocument {
    pub schema_version: u32,
    pub format_version: u32,
    pub sources: Vec<InspectionSource>,
    pub environment: Vec<InspectionEnvironmentEntry>,
    pub path: Vec<InspectionPathOperation>,
    pub tasks: Vec<InspectionTask>,
}

impl InspectionDocument {
    pub const SCHEMA_VERSION: u32 = 2;
}

/// Resolved task metadata safe for read-only inspection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InspectionTask {
    pub key: String,
    pub id: String,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub outputs: Vec<InspectionTaskOutput>,
    pub package: Option<tasks::TaskPackageIdentity>,
    pub dependencies: Vec<tasks::TaskDependencyEdge>,
    pub before_hooks: Vec<tasks::TaskDependencyEdge>,
    pub after_hooks: Vec<tasks::TaskDependencyEdge>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InspectionTaskOutput {
    pub name: String,
    pub description: Option<String>,
    pub visibility: String,
}

/// A configuration source used to construct an inspected project.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InspectionSource {
    pub path: String,
    pub kind: String,
}

/// One inspected environment value. Sensitive values are represented by a
/// redacted marker rather than their original contents.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InspectionEnvironmentEntry {
    pub key: String,
    pub value: String,
    pub redacted: bool,
    pub source: SourceSpan,
}

/// A source-relative PATH mutation retained for inspection and activation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InspectionPathOperation {
    pub operation: String,
    pub value: String,
    pub source: SourceSpan,
}

/// The stable JSON envelope emitted by successful validation commands.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ValidationDocument {
    pub schema_version: u32,
    pub valid: bool,
    pub sources: Vec<InspectionSource>,
}

impl ValidationDocument {
    pub const SCHEMA_VERSION: u32 = 1;
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::{Diagnostic, DiagnosticCategory, DiagnosticDocument, ExitCategory, SourceSpan};

    #[test]
    fn exit_codes_are_stable() {
        assert_eq!(ExitCategory::Validation.code(), 3);
        assert_eq!(ExitCategory::Internal.code(), 70);
    }

    #[test]
    fn diagnostic_preserves_a_typed_cause_without_serializing_it() {
        let diagnostic = Diagnostic::new(DiagnosticCategory::Runtime, "NEO522", "safe message")
            .with_cause(std::io::Error::from(std::io::ErrorKind::PermissionDenied));

        let cause = diagnostic.source().expect("operational cause is retained");
        assert_eq!(
            cause
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::PermissionDenied)
        );

        let json = serde_json::to_value(DiagnosticDocument::from_diagnostic(&diagnostic))
            .expect("diagnostic document serializes");
        assert_eq!(json["diagnostic"]["message"], "safe message");
        assert!(json["diagnostic"].get("cause").is_none());
    }

    #[test]
    fn diagnostic_json_shape_is_stable_when_a_source_is_added() {
        let plain = Diagnostic::new(DiagnosticCategory::Runtime, "NEO522", "safe message");
        let sourced = plain
            .clone()
            .with_cause(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        let plain_json = serde_json::to_value(DiagnosticDocument::from_diagnostic(&plain))
            .expect("plain diagnostic serializes");
        let sourced_json = serde_json::to_value(DiagnosticDocument::from_diagnostic(&sourced))
            .expect("sourced diagnostic serializes");
        assert_eq!(plain_json, sourced_json);
        assert_eq!(
            sourced_json["diagnostic"]
                .as_object()
                .expect("diagnostic object")
                .keys()
                .collect::<Vec<_>>(),
            ["category", "code", "message"]
        );
        assert_eq!(
            sourced_json
                .as_object()
                .expect("document object")
                .keys()
                .collect::<Vec<_>>(),
            ["diagnostic", "schema_version"]
        );

        for (category, code) in [
            (DiagnosticCategory::Usage, 2),
            (DiagnosticCategory::Validation, 3),
            (DiagnosticCategory::NotFound, 4),
            (DiagnosticCategory::Trust, 5),
            (DiagnosticCategory::Runtime, 6),
            (DiagnosticCategory::Internal, 70),
        ] {
            assert_eq!(category.exit_category().code(), code);
        }
    }

    #[test]
    fn diagnostics_preserve_exit_category_and_location() {
        let diagnostic = Diagnostic::new(DiagnosticCategory::Validation, "NEO001", "invalid key")
            .at(SourceSpan::new("neoenv.toml".into(), 4, 2));

        assert_eq!(diagnostic.exit_category(), ExitCategory::Validation);
        assert_eq!(diagnostic.to_string(), "neoenv.toml:4:2: invalid key");
    }
}
