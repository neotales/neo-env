//! Source-span mapping for the structured formats. Each format gets its own
//! key and header scanner so diagnostics point at real document positions.

use super::{Diagnostic, DiagnosticCategory, Format, IndexMap, SourceSpan, VecDeque};

/// Cloneable so a caller that reads both the shared sections and a Go-specific
/// one can scan the document once and reuse the result.
#[derive(Clone, Default)]
pub(super) struct StructuredSpans {
    pub(super) env: VecDeque<(u32, u32)>,
    pub(super) dotenv: VecDeque<(u32, u32)>,
    pub(super) path: VecDeque<(u32, u32)>,
    pub(super) tools: VecDeque<(u32, u32)>,
    pub(super) task_dotenv: IndexMap<String, VecDeque<(u32, u32)>>,
}

impl StructuredSpans {
    pub(super) fn source(path: &str, source: Option<(u32, u32)>) -> SourceSpan {
        let (line, column) = source.unwrap_or((1, 1));
        SourceSpan::new(path.to_owned(), line, column)
    }

    pub(super) fn next_env(&mut self, path: &str) -> SourceSpan {
        Self::source(path, self.env.pop_front())
    }

    pub(super) fn next_dotenv(&mut self, path: &str) -> SourceSpan {
        Self::source(path, self.dotenv.pop_front())
    }

    pub(super) fn next_path(&mut self, path: &str) -> SourceSpan {
        Self::source(path, self.path.pop_front())
    }

    pub(super) fn next_tool(&mut self, path: &str) -> SourceSpan {
        Self::source(path, self.tools.pop_front())
    }

    pub(super) fn next_task_dotenv(&mut self, name: &str, path: &str) -> SourceSpan {
        Self::source(
            path,
            self.task_dotenv.get_mut(name).and_then(VecDeque::pop_front),
        )
    }
}

pub(super) fn structured_spans(input: &str, format: Format) -> StructuredSpans {
    match format {
        Format::Toml => toml_spans(input),
        Format::Yaml => yaml_spans(input),
        Format::Neoenv => StructuredSpans::default(),
    }
}

pub(super) fn yaml_spans(input: &str) -> StructuredSpans {
    let mut spans = StructuredSpans::default();
    let mut root = None;
    let mut root_indent = 0;
    let mut tools_indent = None;
    let mut tasks_indent = None;
    let mut task = None;
    let mut task_body_indent = 0;
    let mut task_dotenv_indent = None;

    for (index, raw) in input.lines().enumerate() {
        let line = u32::try_from(index + 1).unwrap_or(u32::MAX);
        let content = raw.trim_start();
        if content.is_empty() || content.starts_with('#') {
            continue;
        }
        let indent = raw.len() - content.len();
        let column = u32::try_from(indent + 1).unwrap_or(u32::MAX);
        if indent == 0 {
            root = yaml_key(content);
            root_indent = 0;
            tools_indent = None;
            tasks_indent = None;
            task = None;
            task_dotenv_indent = None;
            if root.as_deref() == Some("dotenv") && !content.ends_with(':') {
                spans.dotenv.push_back((line, column));
            }
            if root.as_deref() == Some("path") && !content.ends_with(':') {
                let count = content.matches("prepend").count() + content.matches("append").count();
                spans
                    .path
                    .extend(std::iter::repeat_n((line, column), count));
            }
            continue;
        }
        match root.as_deref() {
            Some("env") if indent > root_indent => {
                // A mapping entry is `KEY: value`; a Go sequence entry is
                // `- KEY=value` or `- KEY:value`, which has no key of its own
                // when there is no colon. A mapping cannot legally contain a
                // sequence item, so accepting the `- ` form here cannot
                // misattribute a span in a native document.
                //
                // A *nested* key is not an entry. The Go detailed form
                // (`FOO: {value: v, secret: true}`) puts `value:` and `secret:`
                // one level in, and counting them as entries would hand the
                // second variable the first variable's inner line.
                let nested = content.starts_with(' ') || raw.starts_with("    ");
                if !nested && (yaml_key(content).is_some() || content.starts_with("- ")) {
                    spans.env.push_back((line, column));
                }
            }
            Some("dotenv") => {
                if content.starts_with('-') {
                    spans.dotenv.push_back((line, column));
                }
            }
            Some("path") => {
                if content.starts_with('-') {
                    spans.path.push_back((line, column));
                }
            }
            Some("tools") => {
                if content.starts_with('-') {
                    let current = tools_indent.get_or_insert(indent);
                    if *current == indent {
                        spans.tools.push_back((line, column));
                    }
                }
            }
            Some("tasks") => {
                if let Some(key) = yaml_key(content) {
                    if tasks_indent.is_none() {
                        tasks_indent = Some(indent);
                    }
                    if tasks_indent == Some(indent) {
                        task = Some(key);
                        task_body_indent = indent;
                        task_dotenv_indent = None;
                        continue;
                    }
                    if indent > task_body_indent && key == "dotenv" {
                        if content.ends_with(':') {
                            task_dotenv_indent = Some(indent);
                        } else if let Some(task) = task.as_ref() {
                            spans
                                .task_dotenv
                                .entry(task.clone())
                                .or_default()
                                .push_back((line, column));
                        }
                    }
                }
                if content.starts_with('-')
                    && task_dotenv_indent.is_some_and(|dotenv_indent| indent > dotenv_indent)
                    && task.is_some()
                {
                    spans
                        .task_dotenv
                        .entry(task.clone().unwrap_or_default())
                        .or_default()
                        .push_back((line, column));
                }
            }
            _ => {}
        }
    }
    spans
}

pub(super) fn yaml_key(content: &str) -> Option<String> {
    let content = content.strip_prefix('-').unwrap_or(content).trim_start();
    let key = if let Some(quote @ ('\'' | '"')) = content.chars().next() {
        let end = content[1..].find(quote)? + 1;
        (content.get(end + 1..)?.trim_start().starts_with(':')).then(|| &content[1..end])?
    } else {
        content.split_once(':')?.0.trim()
    };
    (!key.is_empty()).then(|| key.to_owned())
}

pub(super) fn toml_spans(input: &str) -> StructuredSpans {
    let mut spans = StructuredSpans::default();
    let mut section = Vec::new();
    let mut array_section = false;
    for (index, raw) in input.lines().enumerate() {
        let line = u32::try_from(index + 1).unwrap_or(u32::MAX);
        let content = raw.trim_start();
        if content.is_empty() || content.starts_with('#') {
            continue;
        }
        let column = u32::try_from(raw.len() - content.len() + 1).unwrap_or(u32::MAX);
        if let Some((header, is_array)) = toml_header(content) {
            section = toml_path(header);
            array_section = is_array;
            if is_array && section == ["tools"] {
                spans.tools.push_back((line, column));
            }
            continue;
        }
        let Some(key) = toml_key(content) else {
            continue;
        };
        match section.as_slice() {
            [section] if section == "env" => spans.env.push_back((line, column)),
            [] if key == "dotenv" => {
                push_toml_declarations(&mut spans.dotenv, line, column, content, &["path"]);
            }
            [] if key == "path" => {
                push_toml_declarations(
                    &mut spans.path,
                    line,
                    column,
                    content,
                    &["prepend", "append"],
                );
            }
            [tasks, task, ..] if tasks == "tasks" && key == "dotenv" => {
                let entries = spans.task_dotenv.entry(task.clone()).or_default();
                push_toml_declarations(entries, line, column, content, &["path"]);
            }
            [path]
                if array_section
                    && path == "path"
                    && matches!(key.as_str(), "prepend" | "append") =>
            {
                spans.path.push_back((line, column));
            }
            _ => {}
        }
    }
    spans
}

pub(super) fn toml_header(content: &str) -> Option<(&str, bool)> {
    let is_array = content.starts_with("[[") && content.ends_with("]]");
    let is_table = content.starts_with('[') && content.ends_with(']');
    (is_array || is_table).then(|| {
        let trim = if is_array { 2 } else { 1 };
        (&content[trim..content.len() - trim], is_array)
    })
}

pub(super) fn toml_path(header: &str) -> Vec<String> {
    let mut path = Vec::new();
    let mut part = String::new();
    let mut quoted = false;
    for character in header.chars() {
        match character {
            '"' => quoted = !quoted,
            '.' if !quoted => {
                path.push(part.trim().to_owned());
                part.clear();
            }
            _ => part.push(character),
        }
    }
    path.push(part.trim().to_owned());
    path
}

pub(super) fn toml_key(content: &str) -> Option<String> {
    content
        .split_once('=')
        .map(|(key, _)| key.trim().trim_matches('"').to_owned())
}

pub(super) fn push_toml_declarations(
    values: &mut VecDeque<(u32, u32)>,
    line: u32,
    column: u32,
    content: &str,
    keys: &[&str],
) {
    let mut declarations = Vec::new();
    for key in keys {
        let needle = format!("{key} =");
        declarations.extend(content.match_indices(&needle).map(|(index, _)| {
            (
                line,
                column.saturating_add(u32::try_from(index).unwrap_or(u32::MAX)),
            )
        }));
    }
    declarations.sort_by_key(|(_, declaration_column)| *declaration_column);
    if declarations.is_empty() {
        declarations.push((line, column));
    }
    values.extend(declarations);
}

pub(super) fn value_error(path: &str, line: u32, message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(DiagnosticCategory::Validation, "NEO109", message).at(SourceSpan::new(
        path.to_owned(),
        line,
        1,
    ))
}
