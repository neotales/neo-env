//! Bounded HTTP retrieval helpers for provider metadata, sharing the
//! crate's redirect, timeout, and budget policy.

use super::{Diagnostic, http_error, http_policy, runtime_error};

pub(super) fn get_json<T: serde::de::DeserializeOwned>(url: &str) -> Result<T, Diagnostic> {
    let policy = http_policy()?;
    let response = policy
        .get(url)
        .map_err(|error| http_error(error, "failed to fetch .NET release metadata"))?;
    let bytes = policy
        .read_body(url, response)
        .map_err(|error| http_error(error, "failed to read .NET release metadata"))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| runtime_error(format!("invalid .NET release metadata: {error}")))
}

pub(super) fn get_text(url: &str) -> Result<String, Diagnostic> {
    let policy = http_policy()?;
    let response = policy
        .get(url)
        .map_err(|error| http_error(error, "failed to fetch runtime metadata"))?;
    policy
        .read_text(url, response)
        .map_err(|error| http_error(error, "failed to read runtime metadata"))
}
