//! Inventory document loading; no authorization or credential resolution.

use crate::budget::{ResourceBudget, read_text_file};
use indexmap::IndexMap;
use neoenv_config::Inventory;
use neoenv_core::{Diagnostic, DiagnosticCategory};
use std::{
    fs,
    path::{Component, Path, PathBuf},
};

fn invalid(message: &'static str) -> Diagnostic {
    Diagnostic::new(DiagnosticCategory::Validation, "NEO444", message)
}

/// Source declarations only. Construction/merging never reads inventory files.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct InventorySources {
    user_directory: Option<PathBuf>,
    layers: Vec<InventoryLayer>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InventoryLayer {
    document: PathBuf,
    files: Vec<String>,
    inline: IndexMap<String, Inventory>,
}

impl InventorySources {
    pub(crate) fn for_process() -> Self {
        Self {
            user_directory: crate::paths::neoenv_directory(crate::paths::UserDirectory::Config)
                .map(|directory| directory.join("inventories")),
            layers: Vec::new(),
        }
    }

    pub(crate) fn push(
        &mut self,
        document: PathBuf,
        files: Vec<String>,
        inline: IndexMap<String, Inventory>,
    ) {
        if !files.is_empty() || !inline.is_empty() {
            self.layers.push(InventoryLayer {
                document,
                files,
                inline,
            });
        }
    }

    pub(crate) fn resolve(&self) -> Result<IndexMap<String, Inventory>, Diagnostic> {
        let mut inventories = self
            .user_directory
            .as_deref()
            .map(load_user)
            .transpose()?
            .unwrap_or_default();
        for layer in &self.layers {
            inventories.extend(load_declared(&layer.document, &layer.files)?);
            inventories.extend(layer.inline.clone());
        }
        Ok(inventories)
    }
}

/// Loads the optional user inventory directory in filename order. Every entry
/// must be a regular YAML/TOML file, not a link. Later inventory names replace
/// earlier ones wholesale. No credentials or remote resources are accessed.
///
/// # Errors
/// Refuses unreadable directories, links and unsupported entries without paths.
pub(crate) fn load_user(directory: &Path) -> Result<IndexMap<String, Inventory>, Diagnostic> {
    let mut inventories = IndexMap::new();
    let metadata = match fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(inventories),
        Err(_) => return Err(invalid("cannot inspect user inventories directory")),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid(
            "user inventories directory must be a real directory, not a link",
        ));
    }
    let mut entries = fs::read_dir(directory)
        .map_err(|_| invalid("cannot list user inventories directory"))?
        .take(129)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid("cannot read user inventories directory entry"))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    if entries.len() > 128 {
        return Err(invalid("user inventories directory exceeds 128 entries"));
    }
    for entry in entries {
        if !entry
            .file_type()
            .map_err(|_| invalid("cannot inspect user inventory entry"))?
            .is_file()
        {
            return Err(invalid(
                "user inventories entries must be regular files, not links or directories",
            ));
        }
        inventories.extend(read(&entry.path())?);
    }
    Ok(inventories)
}

pub(crate) fn load_declared(
    document: &Path,
    declared: &[String],
) -> Result<IndexMap<String, Inventory>, Diagnostic> {
    if declared.is_empty() {
        return Ok(IndexMap::new());
    }
    let root = document
        .parent()
        .ok_or_else(|| invalid("inventory_files declaring document has no parent"))?
        .canonicalize()
        .map_err(|_| invalid("cannot resolve inventory_files declaring directory"))?;
    if declared.len() > 128 {
        return Err(invalid("inventory_files exceeds 128 entries"));
    }
    let mut inventories = IndexMap::new();
    for path in declared {
        let path = Path::new(path);
        if path.as_os_str().is_empty()
            || path
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(invalid(
                "inventory_files paths must be nonempty relative paths without traversal",
            ));
        }
        let file = root
            .join(path)
            .canonicalize()
            .map_err(|_| invalid("inventory_files entry is missing or unreadable"))?;
        if !file.starts_with(&root) || !file.is_file() {
            return Err(invalid(
                "inventory_files entry escapes its declaring directory or is not a file",
            ));
        }
        inventories.extend(read(&file)?);
    }
    Ok(inventories)
}

fn read(path: &Path) -> Result<IndexMap<String, Inventory>, Diagnostic> {
    let input = read_text_file(path, &ResourceBudget::default()).map_err(|_| {
        invalid("cannot read inventory file within the configuration resource budget")
    })?;
    neoenv_config::parse_inventory_file(path, &input)
}
