//! Pure provider-backed tool planning and lockfile validation.

use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    sync::Arc,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::SourceSpan;
mod lock;
mod model;
mod planning;
#[cfg(test)]
mod tests;

pub use lock::*;
pub use model::{platform_arch_aliases, platform_os_aliases, *};
pub use planning::{
    DIGEST_ALGORITHMS, PROGRAM_EXTENSIONS, SIDECAR_EXTENSIONS, asset_matches_platform,
    canonical_http_url, cargo_toolchain_for_platform, github_declaration_fingerprint,
    is_canonical_https_url, is_cargo_toolchain_pin, is_exact_manager_version,
    is_package_not_program, is_registry_revision, is_release_artifact, is_sha256,
    named_architecture, names_a_wider_architecture, plan_aqua_registry, plan_cargo_crate,
    plan_dotnet_tool, plan_github_release, plan_go_module, plan_npm_registry, plan_ruby_gems,
    plan_tools, reject_binary_layout, select_github_asset, select_platform_override,
};

#[cfg(test)]
use lock::has_go_module_evidence;
#[cfg(test)]
use planning::canonicalize_url;
