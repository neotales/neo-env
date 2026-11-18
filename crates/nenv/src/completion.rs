use neoenv_core::{Diagnostic, DiagnosticCategory};

use crate::command_tree::{
    ArgumentCardinality, COMPLETION_SHELLS, CommandAction, CommandArgument, CommandOption,
    CommandSpec, OptionValue, ROOT,
};

pub fn generate(shell: &str) -> Result<String, Diagnostic> {
    if COMPLETION_SHELLS.contains(&shell) {
        generate_for(shell, &ROOT)
    } else {
        Err(Diagnostic::new(
            DiagnosticCategory::Usage,
            "NEO001",
            format!("unsupported completion shell: {shell}"),
        ))
    }
}

#[derive(Clone)]
struct VisiblePath {
    nodes: Vec<&'static CommandSpec>,
}

impl VisiblePath {
    fn command(&self) -> &'static CommandSpec {
        self.nodes.last().copied().unwrap_or(&ROOT)
    }

    fn invocation(&self) -> String {
        self.nodes
            .iter()
            .map(|command| command.name)
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn spellings(&self) -> Vec<&'static str> {
        self.command().command_names()
    }

    fn all_spellings(&self) -> Vec<&'static str> {
        self.nodes
            .iter()
            .flat_map(|command| command.command_names())
            .collect()
    }
}

fn visible_paths(root: &'static CommandSpec) -> Vec<VisiblePath> {
    fn append(
        root: &'static CommandSpec,
        parents: &[&'static CommandSpec],
        output: &mut Vec<VisiblePath>,
    ) {
        if !root.is_public() {
            return;
        }
        let mut nodes = parents.to_vec();
        nodes.push(root);
        output.push(VisiblePath {
            nodes: nodes.clone(),
        });
        for child in root.children {
            append(child, &nodes, output);
        }
    }

    let mut output = Vec::new();
    append(root, &[], &mut output);
    output
}

fn hidden_endpoint(root: &'static CommandSpec, action: CommandAction) -> Option<String> {
    fn find(
        command: &'static CommandSpec,
        parents: &[&'static CommandSpec],
        action: CommandAction,
    ) -> Option<String> {
        let mut nodes = parents.to_vec();
        nodes.push(command);
        if command.action == action {
            return Some(
                nodes
                    .iter()
                    .map(|command| command.name)
                    .collect::<Vec<_>>()
                    .join(" "),
            );
        }
        command
            .children
            .iter()
            .find_map(|child| find(child, &nodes, action))
    }

    find(root, &[], action)
}

fn visible_child_words(parent: &VisiblePath) -> Vec<&'static str> {
    parent
        .command()
        .children
        .iter()
        .filter(|command| command.is_public())
        .flat_map(CommandSpec::command_names)
        .collect()
}

fn option_words(command: &CommandSpec) -> Vec<&'static str> {
    command
        .options
        .iter()
        .flat_map(|option| [option.short, option.long])
        .filter(|word| !word.is_empty())
        .collect()
}

fn argument_choices(argument: &CommandArgument) -> &'static [&'static str] {
    argument.choices
}

fn completion_words(command: &CommandSpec) -> Vec<String> {
    let mut words = option_words(command)
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    words.extend(
        command
            .arguments
            .iter()
            .flat_map(argument_choices)
            .map(|choice| (*choice).to_owned()),
    );
    if command.arguments.iter().any(|argument| {
        matches!(
            argument.cardinality,
            ArgumentCardinality::OneOrMore | ArgumentCardinality::ZeroOrMore
        )
    }) {
        words.push("--".to_owned());
    }
    words
}

fn catalog_comment(paths: &[VisiblePath]) -> String {
    let mut output = String::from("# neoenv-command-tree-begin\n");
    for path in paths {
        use std::fmt::Write as _;
        let _ = writeln!(
            output,
            "# neoenv-visible {} {}",
            path.invocation(),
            path.spellings().join(" ")
        );
    }
    output.push_str("# neoenv-command-tree-end\n");
    output
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn fish_quote(value: &str) -> String {
    value.replace('\'', "\\'")
}

fn powershell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn zsh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn generate_for(shell: &str, root: &'static CommandSpec) -> Result<String, Diagnostic> {
    let paths = visible_paths(root);
    let catalog = catalog_comment(&paths);
    let endpoint = hidden_endpoint(root, CommandAction::TaskComplete).ok_or_else(|| {
        Diagnostic::new(
            DiagnosticCategory::Internal,
            "NEO701",
            "command tree is missing the completion endpoint",
        )
    })?;
    Ok(match shell {
        "bash" => format!(
            "{catalog}# nenv completion. Dynamic task candidates only read configuration.\n{}",
            render_bash(&paths, &endpoint)
        ),
        "zsh" => format!(
            "{catalog}#compdef nenv\n# nenv completion. Dynamic task candidates only read configuration.\n{}",
            render_zsh(&paths, &endpoint)
        ),
        "fish" => format!(
            "{catalog}# nenv completion. Dynamic task candidates only read configuration.\n{}",
            render_fish(&paths, &endpoint)
        ),
        "powershell" => format!(
            "{catalog}# nenv completion. Dynamic task candidates only read configuration.\n{}",
            render_powershell(&paths, &endpoint)
        ),
        "nushell" => format!(
            "{catalog}# nenv completion. Dynamic task candidates only read configuration.\n{}",
            render_nushell(root, &paths, &endpoint)
        ),
        _ => {
            return Err(Diagnostic::new(
                DiagnosticCategory::Internal,
                "NEO701",
                "completion renderer received an unsupported shell",
            ));
        }
    })
}

fn render_bash(paths: &[VisiblePath], endpoint: &str) -> String {
    use std::fmt::Write;

    let root = paths.first().map_or(&ROOT, VisiblePath::command);
    let mut root_words = paths
        .first()
        .map(|path| {
            visible_child_words(path)
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    root_words.extend(option_words(root).into_iter().map(str::to_owned));
    let mut output = String::new();
    let _ = writeln!(
        output,
        "_nenv() {{\n    local cur=\"${{COMP_WORDS[COMP_CWORD]}}\" previous=\"${{COMP_WORDS[COMP_CWORD-1]}}\"\n    local root={}\n    local tasks\n    tasks=\"$({endpoint} 2>/dev/null)\"\n    if [ \"$COMP_CWORD\" -eq 1 ]; then\n        COMPREPLY=( $(compgen -W \"$root $tasks\" -- \"$cur\") )\n        return\n    fi\n    case \"${{COMP_WORDS[1]}}\" in",
        shell_quote(&root_words.join(" "))
    );
    for path in paths.iter().skip(1).filter(|path| path.nodes.len() == 2) {
        render_bash_path(&mut output, path, 8, endpoint);
    }
    let _ = writeln!(
        output,
        "        *)\n            COMPREPLY=( $(compgen -W \"$root $tasks\" -- \"$cur\") ) ;;\n    esac\n}}\ncomplete -F _nenv nenv"
    );
    output
}

fn render_bash_path(output: &mut String, path: &VisiblePath, indent: usize, endpoint: &str) {
    render_bash_branch(output, path, indent, endpoint);
}

fn render_bash_branch(output: &mut String, path: &VisiblePath, indent: usize, endpoint: &str) {
    use std::fmt::Write;

    let padding = " ".repeat(indent);
    let _ = writeln!(output, "{padding}{}) {{", path.spellings().join("|"));
    render_bash_selected(output, path, indent + 4, endpoint);
    let _ = writeln!(output, "{padding}}} ;;");
}

fn render_bash_selected(output: &mut String, path: &VisiblePath, indent: usize, endpoint: &str) {
    use std::fmt::Write;

    let command = path.command();
    let padding = " ".repeat(indent);
    let visible_children = command
        .children
        .iter()
        .filter(|child| child.is_public())
        .collect::<Vec<_>>();
    if !visible_children.is_empty() {
        let child_words = visible_children
            .iter()
            .flat_map(|child| child.command_names())
            .collect::<Vec<_>>()
            .join(" ");
        let _ = writeln!(
            output,
            "{padding}case \"${{COMP_WORDS[{}]}}\" in",
            path.nodes.len()
        );
        let _ = writeln!(
            output,
            "{padding}    \"\") COMPREPLY=( $(compgen -W {} -- \"$cur\") ) ;;",
            shell_quote(&child_words)
        );
        for child in visible_children {
            let mut nodes = path.nodes.clone();
            nodes.push(child);
            render_bash_branch(output, &VisiblePath { nodes }, indent + 4, endpoint);
        }
        let _ = writeln!(
            output,
            "{padding}    *) COMPREPLY=( $(compgen -W {} -- \"$cur\") ) ;;",
            shell_quote(&completion_words(command).join(" "))
        );
        let _ = writeln!(output, "{padding}esac");
    } else if matches!(
        command.action,
        CommandAction::RunShortcut | CommandAction::TaskRun
    ) {
        let options = completion_words(command);
        let _ = writeln!(
            output,
            "{padding}if [ \"$COMP_CWORD\" -ge {} ]; then\n{padding}    COMPREPLY=( $(compgen -W {} \"$({endpoint} \"${{COMP_WORDS[{}]}}\" 2>/dev/null)\" -- \"$cur\") )\n{padding}else\n{padding}    COMPREPLY=( $(compgen -W \"$({endpoint} 2>/dev/null)\" -- \"$cur\") )\n{padding}fi",
            path.nodes.len() + 1,
            shell_quote(&options.join(" ")),
            path.nodes.len()
        );
    } else {
        let _ = writeln!(
            output,
            "{padding}COMPREPLY=( $(compgen -W {} -- \"$cur\") )",
            shell_quote(&completion_words(command).join(" "))
        );
    }
}

fn zsh_option(option: &CommandOption) -> Vec<String> {
    let mut output = Vec::new();
    if !option.short.is_empty() {
        output.push(zsh_quote(&format!(
            "{}[{}]",
            option.short, option.description
        )));
    }
    if !option.long.is_empty() {
        let value = if let OptionValue::Required { name, choices } = option.value {
            if choices.is_empty() {
                format!("{}[{}]:{name}:", option.long, option.description)
            } else {
                format!(
                    "{}[{}]:{name}:({})",
                    option.long,
                    option.description,
                    choices.join(" ")
                )
            }
        } else {
            format!("{}[{}]", option.long, option.description)
        };
        output.push(zsh_quote(&value));
    }
    output
}

fn zsh_arguments(command: &CommandSpec) -> Vec<String> {
    let mut output = command
        .options
        .iter()
        .flat_map(zsh_option)
        .collect::<Vec<_>>();
    if command.arguments.iter().any(|argument| {
        matches!(
            argument.cardinality,
            ArgumentCardinality::OneOrMore | ArgumentCardinality::ZeroOrMore
        )
    }) {
        output.push(zsh_quote("--[Pass literal arguments]"));
    }
    output
}

fn render_zsh(paths: &[VisiblePath], endpoint: &str) -> String {
    use std::fmt::Write;

    let root = paths.first().map_or(&ROOT, VisiblePath::command);
    let mut root_words = paths
        .first()
        .map(|path| {
            visible_child_words(path)
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    root_words.extend(option_words(root).into_iter().map(str::to_owned));
    let mut output = String::new();
    let _ = writeln!(
        output,
        "_nenv() {{\n  local -a top\n  top=({})",
        root_words.join(" ")
    );
    let _ = writeln!(output, "  case $words[2] in");
    for path in paths.iter().skip(1).filter(|path| path.nodes.len() == 2) {
        render_zsh_path(&mut output, path, 4, endpoint);
    }
    let _ = writeln!(
        output,
        "    *) _arguments {} '1:command:->command' && case $state in command) _values command $top ${{(f)\"$({endpoint} 2>/dev/null)\"}} ;; esac ;;\n  esac\n}}\n_nenv \"$@\"",
        zsh_arguments(root).join(" ")
    );
    output
}

fn render_zsh_path(output: &mut String, path: &VisiblePath, indent: usize, endpoint: &str) {
    render_zsh_branch(output, path, indent, endpoint);
}

fn render_zsh_branch(output: &mut String, path: &VisiblePath, indent: usize, endpoint: &str) {
    use std::fmt::Write;

    let padding = " ".repeat(indent);
    let _ = writeln!(output, "{padding}{}) {{", path.spellings().join("|"));
    render_zsh_selected(output, path, indent + 2, endpoint);
    let _ = writeln!(output, "{padding}}} ;;");
}

fn render_zsh_selected(output: &mut String, path: &VisiblePath, indent: usize, endpoint: &str) {
    use std::fmt::Write;

    let command = path.command();
    let padding = " ".repeat(indent);
    let visible_children = command
        .children
        .iter()
        .filter(|child| child.is_public())
        .collect::<Vec<_>>();
    if !visible_children.is_empty() {
        let child_words = visible_children
            .iter()
            .flat_map(|child| child.command_names())
            .collect::<Vec<_>>()
            .join(" ");
        let _ = writeln!(output, "{padding}case $words[{}] in", path.nodes.len() + 1);
        let _ = writeln!(
            output,
            "{padding}  '') _describe -t commands 'command' ({child_words}) ;;"
        );
        for child in visible_children {
            let mut nodes = path.nodes.clone();
            nodes.push(child);
            render_zsh_branch(output, &VisiblePath { nodes }, indent + 2, endpoint);
        }
        let _ = writeln!(
            output,
            "{padding}  *) _arguments {} ;;",
            zsh_arguments(command).join(" ")
        );
        let _ = writeln!(output, "{padding}esac");
    } else if matches!(
        command.action,
        CommandAction::RunShortcut | CommandAction::TaskRun
    ) {
        let _ = writeln!(
            output,
            "{padding}_arguments {} '1:task:->task' && case $state in task) _values task ${{(f)\"$({endpoint} 2>/dev/null)\"}} ;; esac",
            zsh_arguments(command).join(" ")
        );
    } else {
        let _ = writeln!(
            output,
            "{padding}_arguments {}",
            zsh_arguments(command).join(" ")
        );
    }
}

fn render_fish(paths: &[VisiblePath], endpoint: &str) -> String {
    use std::fmt::Write;

    let root = paths.first().map_or(&ROOT, VisiblePath::command);
    let mut root_words = paths
        .first()
        .map(|path| {
            visible_child_words(path)
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    root_words.extend(option_words(root).into_iter().map(str::to_owned));
    root_words.push(format!("({endpoint} 2>/dev/null)"));
    let mut output = String::from("complete -c nenv -f\n");
    let _ = writeln!(
        output,
        "complete -c nenv -n '__fish_use_subcommand' -a {}",
        fish_quote(&root_words.join(" "))
    );
    for path in paths.iter().skip(1) {
        let command = path.command();
        let condition = format!(
            "__fish_seen_subcommand_from {}",
            path.all_spellings().join(" ")
        );
        let children = visible_child_words(path);
        if !children.is_empty() {
            let _ = writeln!(
                output,
                "complete -c nenv -n {} -a {}",
                powershell_quote(&condition),
                fish_quote(&children.join(" "))
            );
        }
        for option in command.options {
            let mut line = format!("complete -c nenv -n {} ", powershell_quote(&condition));
            if !option.short.is_empty() {
                let _ = write!(line, "-s {} ", option.short.trim_start_matches('-'));
            }
            if !option.long.is_empty() {
                let _ = write!(line, "-l {} ", option.long.trim_start_matches('-'));
            }
            if let OptionValue::Required { choices, .. } = option.value
                && !choices.is_empty()
            {
                let _ = write!(line, "-f -a {} ", fish_quote(&choices.join(" ")));
            }
            let _ = writeln!(line, "-d {}", fish_quote(option.description));
            let _ = output.write_str(&line);
        }
        for argument in command.arguments {
            if !argument.choices.is_empty() {
                let _ = writeln!(
                    output,
                    "complete -c nenv -n {} -f -a {}",
                    powershell_quote(&condition),
                    fish_quote(&argument.choices.join(" "))
                );
            }
        }
        if matches!(
            command.action,
            CommandAction::RunShortcut | CommandAction::TaskRun
        ) {
            let _ = writeln!(
                output,
                "complete -c nenv -n {} -a '({endpoint} 2>/dev/null)'",
                powershell_quote(&condition)
            );
        }
    }
    output
}

fn render_powershell(paths: &[VisiblePath], endpoint: &str) -> String {
    use std::fmt::Write;

    let root = paths.first().map_or(&ROOT, VisiblePath::command);
    let mut root_words = paths
        .first()
        .map(|path| {
            visible_child_words(path)
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    root_words.extend(option_words(root).into_iter().map(str::to_owned));
    let root_values = root_words
        .iter()
        .map(String::as_str)
        .map(powershell_quote)
        .collect::<Vec<_>>()
        .join(",");
    let mut output = String::from(
        "Register-ArgumentCompleter -Native -CommandName nenv -ScriptBlock {\n    param($wordToComplete, $commandAst, $cursorPosition)\n    $words = @($commandAst.CommandElements | ForEach-Object { $_.Extent.Text })\n    $values = switch ($words[1]) {\n",
    );
    for path in paths.iter().skip(1).filter(|path| path.nodes.len() == 2) {
        render_powershell_path(&mut output, path, 8, endpoint);
    }
    let _ = writeln!(
        output,
        "        default {{ @({root_values}) + @({endpoint} 2>$null) }}\n    }}\n    $values | Where-Object {{ $_ -like \"$wordToComplete*\" }}\n}}"
    );
    output
}

fn powershell_words(command: &CommandSpec) -> String {
    completion_words(command)
        .iter()
        .map(String::as_str)
        .map(powershell_quote)
        .collect::<Vec<_>>()
        .join(",")
}

fn render_powershell_path(output: &mut String, path: &VisiblePath, indent: usize, endpoint: &str) {
    render_powershell_branch(output, path, indent, endpoint);
}

fn render_powershell_branch(
    output: &mut String,
    path: &VisiblePath,
    indent: usize,
    endpoint: &str,
) {
    use std::fmt::Write;

    let padding = " ".repeat(indent);
    let patterns = path
        .spellings()
        .iter()
        .copied()
        .map(powershell_quote)
        .collect::<Vec<_>>()
        .join(" | ");
    let _ = writeln!(output, "{padding}{patterns} {{");
    render_powershell_selected(output, path, indent + 4, endpoint);
    let _ = writeln!(output, "{padding}}}");
}

fn render_powershell_selected(
    output: &mut String,
    path: &VisiblePath,
    indent: usize,
    endpoint: &str,
) {
    use std::fmt::Write;

    let command = path.command();
    let padding = " ".repeat(indent);
    let visible_children = command
        .children
        .iter()
        .filter(|child| child.is_public())
        .collect::<Vec<_>>();
    if !visible_children.is_empty() {
        let child_words = visible_children
            .iter()
            .flat_map(|child| child.command_names())
            .map(powershell_quote)
            .collect::<Vec<_>>()
            .join(",");
        let _ = writeln!(
            output,
            "{padding}if ($words.Count -le {}) {{ @({child_words}) }} else {{",
            path.nodes.len() + 1
        );
        let inner_padding = " ".repeat(indent + 4);
        let _ = writeln!(
            output,
            "{inner_padding}switch ($words[{}]) {{",
            path.nodes.len()
        );
        for child in visible_children {
            let mut nodes = path.nodes.clone();
            nodes.push(child);
            render_powershell_branch(output, &VisiblePath { nodes }, indent + 8, endpoint);
        }
        let _ = writeln!(
            output,
            "{inner_padding}default {{ {} }}\n{inner_padding}}}\n{padding}}}",
            powershell_words(command)
        );
    } else if matches!(
        command.action,
        CommandAction::RunShortcut | CommandAction::TaskRun
    ) {
        let values = powershell_words(command);
        let _ = writeln!(
            output,
            "{padding}if ($words.Count -le {}) {{ @({endpoint} 2>$null) }} else {{ @({values}) + @({endpoint} $words[{}] 2>$null) }}",
            path.nodes.len() + 1,
            path.nodes.len()
        );
    } else {
        let values = powershell_words(command);
        let _ = writeln!(output, "{padding}{values}");
    }
}

fn nushell_options(command: &CommandSpec) -> Vec<String> {
    command
        .options
        .iter()
        .map(|option| {
            let name = if option.long.is_empty() {
                option.short
            } else {
                option.long
            };
            match option.value {
                OptionValue::None => name.to_owned(),
                OptionValue::Required { choices: [], .. } => {
                    format!("{name}: string")
                }
                OptionValue::Required { choices, .. } => {
                    format!("{name}: string@\"{}\"", choices.join(" "))
                }
            }
        })
        .collect()
}

fn nushell_arguments(command: &CommandSpec) -> Vec<String> {
    command
        .arguments
        .iter()
        .map(|argument| match argument.cardinality {
            ArgumentCardinality::Required => format!("{}: string", argument.name),
            ArgumentCardinality::Optional => format!("{}?: string", argument.name),
            ArgumentCardinality::OneOrMore | ArgumentCardinality::ZeroOrMore => {
                format!("...{}: string", argument.name)
            }
        })
        .collect()
}

fn render_nushell(root: &'static CommandSpec, paths: &[VisiblePath], endpoint: &str) -> String {
    use std::fmt::Write;

    let mut output = format!("def \"nu-complete nenv tasks\" [] {{ ^{endpoint} | lines }}\n");
    let mut root_params = nushell_options(root);
    root_params.push("...args: string@\"nu-complete nenv tasks\"".to_owned());
    let _ = writeln!(output, "export extern nenv [{}]", root_params.join(" "));
    for path in paths.iter().skip(1) {
        let command = path.command();
        let mut params = nushell_arguments(command);
        params.extend(nushell_options(command));
        for spelling in path.spellings() {
            let invocation = path
                .nodes
                .iter()
                .map(|node| {
                    if std::ptr::eq(*node, command) {
                        spelling
                    } else {
                        node.name
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");
            let _ = writeln!(
                output,
                "export extern {} [{}]",
                nushell_quote(&invocation),
                params.join(" ")
            );
        }
    }
    output
}

fn nushell_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use crate::command_tree::{COMPLETION_SHELLS, CommandAction, CommandOption, CommandSpec, ROOT};

    use super::{generate, generate_for, visible_paths};

    const HELP: CommandOption = CommandOption::flag("-h", "--help", "Show help.");
    const ADDED_LEAF: CommandSpec = CommandSpec {
        name: "nested",
        aliases: &["n"],
        visibility: crate::command_tree::CommandVisibility::Public,
        description: "Exercise nested generated completion.",
        usage: "nenv contract-drift nested",
        arguments: &[],
        options: &[HELP],
        output: crate::command_tree::OutputSupport::TEXT,
        action: CommandAction::Root,
        children: &[],
    };
    const ADDED: CommandSpec = CommandSpec {
        name: "contract-drift",
        aliases: &["cd"],
        visibility: crate::command_tree::CommandVisibility::Public,
        description: "Exercise generated completion.",
        usage: "nenv contract-drift <command>",
        arguments: &[],
        options: &[HELP],
        output: crate::command_tree::OutputSupport::TEXT,
        action: CommandAction::Root,
        children: &[ADDED_LEAF],
    };
    /// A synthetic root that nests the whole production tree alongside a
    /// visible `contract-drift` node, so the generator is proven to follow the
    /// tree rather than a checked-in template, including through a nested root.
    ///
    /// Built once and kept alive for the process: the generator takes a
    /// `&'static` tree, and this fixture is the only place that needs a
    /// synthetic one.
    fn catalog_with_added() -> &'static CommandSpec {
        static FIXTURE: std::sync::OnceLock<CommandSpec> = std::sync::OnceLock::new();
        FIXTURE.get_or_init(|| CommandSpec {
            children: Box::leak(vec![ROOT, ADDED].into_boxed_slice()),
            ..ADDED
        })
    }

    fn catalog(script: &str) -> &str {
        script
            .split_once("# neoenv-command-tree-begin\n")
            .and_then(|(_, script)| script.split_once("# neoenv-command-tree-end\n"))
            .map(|(catalog, _)| catalog)
            .expect("completion script has a command-tree catalog")
    }

    #[test]
    fn generates_visible_commands_and_aliases_for_every_supported_shell() {
        for shell in COMPLETION_SHELLS {
            let script = generate(shell).unwrap();
            for path in visible_paths(&ROOT) {
                for name in path.spellings() {
                    assert!(
                        catalog(&script).contains(&format!(" {name}\n"))
                            || catalog(&script).contains(&format!(" {name} ")),
                        "{shell} omits visible command or alias {name}"
                    );
                    assert!(script.contains(name), "{shell} omits {name}");
                }
            }
            for hidden in ["shell", "completion", "complete"] {
                assert!(
                    !catalog(&script)
                        .lines()
                        .any(|line| line.split_whitespace().any(|word| word == hidden)),
                    "{shell} offers hidden node {hidden}"
                );
            }
            for option in ["format", "locked", "context", "--help", "-h"] {
                assert!(script.contains(option), "{shell} omits option {option}");
            }
            assert!(script.contains("task complete"));
            assert!(!script.contains("@NEOENV_"));
        }
    }

    #[test]
    fn adding_a_visible_tree_node_updates_completion_without_a_template_edit() {
        for shell in COMPLETION_SHELLS {
            let script = generate_for(shell, catalog_with_added()).unwrap();
            assert!(script.contains("contract-drift"), "{shell}");
            assert!(script.contains(" nested"), "{shell}");
            assert!(script.contains("cd"), "{shell}");
            assert!(script.contains(" n"), "{shell}");
        }
    }

    #[test]
    fn completion_catalog_has_one_entry_for_every_visible_path() {
        let script = generate("bash").unwrap();
        assert_eq!(catalog(&script).lines().count(), visible_paths(&ROOT).len());
    }

    #[test]
    fn rejects_unsupported_shells() {
        let error = generate("sh").unwrap_err();
        assert_eq!(error.code, "NEO001");
    }
}
