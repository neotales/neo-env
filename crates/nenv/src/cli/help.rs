//! Help rendering from the shared command tree, so `--help` output is
//! generated from the same metadata that drives parsing and completion.

use neoenv_config::FORMAT_VERSION;

use super::{CommandAction, CommandSpec};

/// Render focused help directly from a node in the authoritative command tree.
pub fn help_text_for(command: &'static CommandSpec) -> String {
    use std::fmt::Write;

    let heading = command
        .usage
        .lines()
        .next()
        .unwrap_or(command.name)
        .split_whitespace()
        .take_while(|word| {
            !word.starts_with('<') && !word.starts_with('[') && !word.starts_with('-')
        })
        .collect::<Vec<_>>()
        .join(" ");
    let mut text = format!(
        "{}\n\n{}\n\nUsage:\n  {}",
        heading, command.description, command.usage
    );
    let visible_children = command
        .children
        .iter()
        .filter(|child| child.is_public())
        .collect::<Vec<_>>();
    if !visible_children.is_empty() {
        text.push_str("\n\nCommands:\n");
        for child in &visible_children {
            let label = if child.aliases.is_empty() {
                child.name.to_owned()
            } else {
                format!("{} ({})", child.name, child.aliases.join(", "))
            };
            let _ = writeln!(text, "  {label:<10} {}", child.description);
        }
    }
    if !command.options.is_empty() {
        text.push_str(if visible_children.is_empty() {
            "\n\nOptions:\n"
        } else {
            "\nOptions:\n"
        });
        for option in command.options {
            let _ = writeln!(text, "  {:<24} {}", option.display(), option.description);
        }
    }
    if command.action == CommandAction::Root {
        let _ = write!(text, "\nConfiguration format version: {FORMAT_VERSION}");
    }
    text.trim_end().to_owned()
}
