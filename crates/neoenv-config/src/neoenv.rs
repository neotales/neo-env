//! The line-oriented `.neoenv` document format: logical line assembly,
//! continuation handling, and key/value validation with source spans.

use super::spans::value_error;
use super::{
    Diagnostic, DiagnosticCategory, EnvironmentEntry, FORMAT_VERSION, IndexMap, Path, Project,
    SourceSpan, TaskDirectories, Workspace, document_span, reject_command_substitution,
};

pub(super) fn parse_neoenv(path: &Path, input: &str) -> Result<Project, Diagnostic> {
    let source_path = path.display().to_string();
    let mut environment = Vec::new();
    let mut inventory_files = Vec::new();
    let mut keys = std::collections::HashSet::new();
    for (line_number, line) in logical_neoenv_lines(&source_path, input)? {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(path) = line.strip_prefix("inventory ") {
            let path = parse_neoenv_value(path.trim(), &source_path, line_number)?;
            if path.is_empty() {
                return Err(value_error(
                    &source_path,
                    line_number,
                    "inventory needs a path",
                ));
            }
            inventory_files.push(path);
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO104",
                "expected KEY=VALUE assignment",
            )
            .at(SourceSpan::new(source_path.clone(), line_number, 1)));
        };
        let key = key.trim();
        validate_key(key, &source_path, line_number)?;
        if !keys.insert(key.to_owned()) {
            return Err(Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO106",
                format!("duplicate environment key: {key}"),
            )
            .at(SourceSpan::new(source_path.clone(), line_number, 1)));
        }
        environment.push(EnvironmentEntry {
            key: key.to_owned(),
            value: parse_neoenv_value(value.trim(), &source_path, line_number)?,
            source: SourceSpan::new(source_path.clone(), line_number, 1),
            // The line-oriented syntax has no secret form; redaction is by name.
            secret: false,
        });
    }
    Ok(Project {
        format_version: FORMAT_VERSION,
        source: document_span(path, input),
        vaults: IndexMap::new(),
        environment,
        dotenv: Vec::new(),
        path: Vec::new(),
        tools: Vec::new(),
        context: None,
        task_dirs: TaskDirectories::default(),
        task_packages: IndexMap::new(),
        tasks: IndexMap::new(),
        // The line-oriented `.neoenv` syntax has no job form. An empty map rather
        // than a refusal: the syntax is a strict subset by construction -- it cannot
        // express a step list at all -- so there is nothing here to reject.
        jobs: IndexMap::new(),
        // The line-oriented syntax has no inventory form; an empty map rather than a
        // refusal, for the same reason as `jobs`.
        inventories: IndexMap::new(),
        inventory_files,
        // The line-oriented syntax has no deployment form; an empty map rather than
        // a refusal, for the same reason as `jobs` and `inventories`.
        deployments: IndexMap::new(),
        imports: Vec::new(),
        workspace: Workspace::default(),
    })
}

pub(super) fn logical_neoenv_lines(
    path: &str,
    input: &str,
) -> Result<Vec<(u32, String)>, Diagnostic> {
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut start_line = None;
    for (index, raw_line) in input.lines().enumerate() {
        let line_number = u32::try_from(index + 1).map_err(|_| {
            Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO107",
                "too many input lines",
            )
        })?;
        if start_line.is_none() {
            start_line = Some(line_number);
        }
        let continued = has_continuation(raw_line);
        let segment = if continued {
            &raw_line[..raw_line.len() - 1]
        } else {
            raw_line
        };
        current.push_str(segment);
        if continued {
            continue;
        }
        lines.push((
            start_line.take().unwrap_or(line_number),
            std::mem::take(&mut current),
        ));
    }
    if start_line.is_some() {
        return Err(Diagnostic::new(
            DiagnosticCategory::Validation,
            "NEO108",
            "unterminated line continuation",
        )
        .at(SourceSpan::new(
            path.to_owned(),
            u32::try_from(input.lines().count())
                .unwrap_or(u32::MAX)
                .max(1),
            1,
        )));
    }
    Ok(lines)
}

pub(super) fn has_continuation(line: &str) -> bool {
    let trailing_backslashes = line
        .chars()
        .rev()
        .take_while(|character| *character == '\\')
        .count();
    trailing_backslashes % 2 == 1
}

pub(super) fn validate_key(key: &str, path: &str, line: u32) -> Result<(), Diagnostic> {
    let mut characters = key.chars();
    let valid = characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric());
    if valid {
        Ok(())
    } else {
        Err(Diagnostic::new(
            DiagnosticCategory::Validation,
            "NEO105",
            format!("invalid environment key: {key}"),
        )
        .at(SourceSpan::new(path.to_owned(), line, 1)))
    }
}

pub(super) fn parse_neoenv_value(value: &str, path: &str, line: u32) -> Result<String, Diagnostic> {
    if value.starts_with('\'') {
        if !value.ends_with('\'') || value.len() < 2 {
            return Err(value_error(path, line, "unterminated quoted value"));
        }
        let value = value[1..value.len() - 1].to_owned();
        reject_command_substitution(&value, path, line)?;
        return Ok(value);
    }
    if !value.starts_with('"') {
        let value = value.to_owned();
        reject_command_substitution(&value, path, line)?;
        return Ok(value);
    }
    if !value.ends_with('"') || value.len() < 2 {
        return Err(value_error(path, line, "unterminated quoted value"));
    }
    let mut output = String::new();
    let mut characters = value[1..value.len() - 1].chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            output.push(character);
            continue;
        }
        let escaped = characters
            .next()
            .ok_or_else(|| value_error(path, line, "unterminated escape sequence"))?;
        match escaped {
            '"' => output.push('"'),
            '\\' => output.push('\\'),
            'n' => output.push('\n'),
            _ => {
                return Err(value_error(
                    path,
                    line,
                    format!("unsupported escape sequence: \\{escaped}"),
                ));
            }
        }
    }
    reject_command_substitution(&output, path, line)?;
    Ok(output)
}
