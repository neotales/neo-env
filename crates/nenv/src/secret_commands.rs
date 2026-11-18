//! `nenv secret get|set`: the narrow CLI over a writable secret provider.
//!
//! `set` deliberately has no value option. A password in argv is visible in the
//! process list and in shell history, so the value is read from standard input
//! and kept in a zeroizing buffer. `get` writes the raw value to standard output
//! for a pipe; it never prints a reference path.

use std::{collections::BTreeMap, io::Read};

use neoenv_core::{Diagnostic, DiagnosticCategory};
use neoenv_installer::activation::inherited_environment;
use neoenv_runtime::vault::MAX_SECRET_BYTES;
use zeroize::Zeroizing;

use super::{OutputFormat, load_project_with_profile};
use crate::cli::SecretCommand;

pub(super) fn dispatch_secret(
    command: &SecretCommand,
    format: OutputFormat,
    profile: neoenv_config::ConfigProfile,
) -> Result<(), Diagnostic> {
    if format != OutputFormat::Text {
        return Err(Diagnostic::new(
            DiagnosticCategory::Usage,
            "NEO001",
            "secret get/set only supports text output; a secret is not put in a JSON document",
        ));
    }
    let (path, reference) = match command {
        SecretCommand::Get { path, reference } | SecretCommand::Set { path, reference } => {
            (path.as_deref(), reference)
        }
    };
    let project = load_project_with_profile(path, profile, None)?;
    let mut context: BTreeMap<String, String> = inherited_environment().into_iter().collect();
    context.extend(
        project
            .environment
            .iter()
            .map(|(key, entry)| (key.clone(), entry.value.clone())),
    );
    let vaults = neoenv_runtime::vault::VaultSet::from_project(&project);
    match command {
        SecretCommand::Get { .. } => {
            let secret = vaults
                .get(reference, &context)
                .map_err(|error| error.to_diagnostic())?;
            print!("{}", secret.expose());
            Ok(())
        }
        SecretCommand::Set { .. } => {
            let value = read_secret_input(std::io::stdin().lock())?;
            vaults
                .set_secret(reference, value.as_str(), &context)
                .map_err(|error| error.to_diagnostic())
        }
    }
}

fn read_secret_input(reader: impl Read) -> Result<Zeroizing<String>, Diagnostic> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_SECRET_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            Diagnostic::new(
                DiagnosticCategory::Runtime,
                "NEO711",
                format!("failed to read the secret from standard input: {error}"),
            )
        })?;
    if bytes.len() > MAX_SECRET_BYTES {
        return Err(Diagnostic::new(
            DiagnosticCategory::Validation,
            "NEO710",
            format!("secret input is larger than {MAX_SECRET_BYTES} bytes"),
        ));
    }
    // The pipe's bytes are the value. A newline is preserved, so a caller that
    // wants no trailing newline uses printf rather than echo.
    String::from_utf8(bytes).map(Zeroizing::new).map_err(|_| {
        Diagnostic::new(
            DiagnosticCategory::Validation,
            "NEO710",
            "secret input is not UTF-8 text",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{MAX_SECRET_BYTES, read_secret_input};

    #[test]
    fn stdin_preserves_a_trailing_newline_exactly() {
        let value = read_secret_input(&b"line one\nline two\n"[..]).unwrap();
        assert_eq!(value.as_str(), "line one\nline two\n");
    }

    #[test]
    fn stdin_rejects_oversize_before_any_write() {
        let input = vec![b'x'; MAX_SECRET_BYTES + 1];
        let error = read_secret_input(input.as_slice()).unwrap_err();
        assert_eq!(error.code, "NEO710");
    }

    #[test]
    fn stdin_rejects_non_utf8() {
        let error = read_secret_input(&[0xff_u8][..]).unwrap_err();
        assert_eq!(error.code, "NEO710");
    }
}
