//! Reading and parsing the documents a task handoff reads: the environment
//! file, declared outputs, and their assignment syntax.

use super::{
    BTreeMap, IndexMap, Path, PathBuf, ResourceBudget, TaskOutput, TaskOutputVisibility,
    read_text_file,
};
use neoenv_core::tasks::valid_environment_key;

pub(super) struct Handoff {
    pub(super) environment: PathBuf,
    pub(super) path: PathBuf,
    pub(super) outputs: PathBuf,
}

impl Handoff {
    pub(super) fn new(directory: &Path) -> Self {
        Self {
            environment: directory.join("environment"),
            path: directory.join("path"),
            outputs: directory.join("outputs"),
        }
    }

    pub(super) fn read(
        &self,
        declared_outputs: &IndexMap<String, TaskOutput>,
    ) -> Result<HandoffValues, String> {
        let environment = read_optional_text(&self.environment)?;
        let path = read_optional_text(&self.path)?;
        let outputs = read_optional_text(&self.outputs)?;
        HandoffDocuments {
            environment: environment.as_deref(),
            path: path.as_deref(),
            outputs: outputs.as_deref(),
        }
        .parse(declared_outputs)
    }
}

/// In-memory handoff input. Parsing and validating this value is pure; the
/// scheduler is the only layer that reads the process-produced files.
pub(super) struct HandoffDocuments<'a> {
    pub(super) environment: Option<&'a str>,
    pub(super) path: Option<&'a str>,
    pub(super) outputs: Option<&'a str>,
}

impl HandoffDocuments<'_> {
    pub(super) fn parse(
        self,
        declared_outputs: &IndexMap<String, TaskOutput>,
    ) -> Result<HandoffValues, String> {
        Ok(HandoffValues {
            environment: parse_assignments(self.environment, "environment")?,
            path: parse_path_entries(self.path)?,
            outputs: parse_outputs(self.outputs, declared_outputs)?,
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct HandoffValues {
    pub(super) environment: Vec<(String, String)>,
    pub(super) path: Vec<String>,
    pub(super) outputs: Vec<(String, String)>,
}

fn read_optional_text(path: &Path) -> Result<Option<String>, String> {
    match read_text_file(path, &ResourceBudget::default()) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "failed to read task handoff {}: {error}",
            path.display()
        )),
    }
}

fn parse_assignments(input: Option<&str>, label: &str) -> Result<Vec<(String, String)>, String> {
    let mut assignments = Vec::new();
    let mut keys = std::collections::HashSet::new();
    for line in input.unwrap_or_default().lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("invalid task {label} handoff entry: {line:?}"));
        };
        if !valid_environment_key(key) {
            return Err(format!("invalid task {label} handoff key: {key}"));
        }
        if !keys.insert(key.to_owned()) {
            return Err(format!("duplicate task {label} handoff key: {key}"));
        }
        assignments.push((key.to_owned(), value.to_owned()));
    }
    Ok(assignments)
}

fn parse_outputs(
    input: Option<&str>,
    declared_outputs: &IndexMap<String, TaskOutput>,
) -> Result<Vec<(String, String)>, String> {
    let outputs = parse_assignments(input, "output")?;
    for (key, _) in &outputs {
        if !declared_outputs.contains_key(key) {
            return Err(format!("task output was not declared: {key}"));
        }
    }
    Ok(outputs
        .into_iter()
        .filter(|(key, _)| declared_outputs[key].visibility == TaskOutputVisibility::Public)
        .collect())
}

fn parse_path_entries(input: Option<&str>) -> Result<Vec<String>, String> {
    let mut entries = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for entry in input.unwrap_or_default().lines() {
        if entry.is_empty() {
            return Err("task PATH handoff entries must not be empty".to_owned());
        }
        if !seen.insert(entry.to_owned()) {
            return Err(format!("duplicate task PATH handoff entry: {entry}"));
        }
        entries.push(entry.to_owned());
    }
    Ok(entries)
}

pub(super) fn apply_handoff(environment: &mut BTreeMap<String, String>, handoff: HandoffValues) {
    for (key, value) in handoff.environment {
        environment.insert(key, value);
    }
    if !handoff.path.is_empty() {
        let separator = if cfg!(windows) { ";" } else { ":" };
        let mut paths = handoff.path;
        if let Some(existing) = environment.get("PATH") {
            paths.push(existing.clone());
        }
        environment.insert("PATH".to_owned(), paths.join(separator));
    }
    for (key, value) in handoff.outputs {
        environment.insert(format!("NEOENV_OUTPUT_{key}"), value);
    }
}
