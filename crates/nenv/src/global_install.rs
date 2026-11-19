//! Global tool installation: request parsing, key validation, config and
//! data path resolution, the bounded concurrent install supervisor, and the
//! locked config transaction. Reused by project installs only for the
//! provider primitives, never for the global storage layout.

use super::tool_dispatch::validate_tool_name;
use super::tool_lifecycle::GLOBAL_OWNERSHIP_MARKER;
use super::{
    Arc, AssertUnwindSafe, AtomicBool, BunRuntimeProgress, CommandAction, CommandSpec,
    DenoRuntimeProgress, Diagnostic, DiagnosticCategory, Digest, DotnetSdkProgress,
    DotnetToolDeclaration, Duration, GithubReleaseDeclaration, GoSdkProgress, HashSet,
    JavaRuntimeProgress, LockedStateFile, NodeRuntimeProgress, NpmDeclaration, OdinRuntimeProgress,
    OnceLock, OptionId, Ordering, Path, PathBuf, Platform, PythonRuntimeProgress, ROOT,
    ResourceBudget, RubyGemsDeclaration, RustRuntimeProgress, Sha256, SourceSpan, StateFileError,
    ToolDeclaration, ToolProvider, ToolStorage, UserDirectory, UvRuntimeProgress,
    ZigRuntimeProgress, cleanup_stale_temporaries_in, fs, install_bun_runtime_with_progress,
    install_deno_runtime_with_progress, install_dotnet_sdk_with_progress,
    install_go_sdk_with_progress, install_java_runtime_with_progress, install_locked_tools_in,
    install_node_runtime_with_progress, install_odin_runtime_with_progress,
    install_python_runtime_with_progress, install_rust_runtime_with_progress,
    install_uv_runtime_with_progress, install_zig_runtime_with_progress, mpsc, panic,
    read_lockfile, read_text_file, resolve_bun_runtime, resolve_deno_runtime, resolve_dotnet_sdk,
    resolve_go_sdk, resolve_java_runtime, resolve_node_runtime, resolve_odin_runtime,
    resolve_python_runtime, resolve_rust_runtime, resolve_tools, resolve_uv_runtime,
    resolve_zig_runtime, state_file, system_directory, thread, tool_states_in, verify_lockfile,
    write_lockfile,
};

#[derive(Debug)]
pub(super) struct GlobalUseRequest {
    pub(super) tools: Vec<GlobalToolRequest>,
    pub(super) dry_run: bool,
    pub(super) scope: GlobalScope,
}

#[derive(Clone, Debug)]
pub(super) struct GlobalToolRequest {
    /// The canonical global key.  Native aliases are normalized here; provider
    /// keys retain their spelling because it is part of their identity.
    pub(super) tool: String,
    pub(super) version: Option<String>,
    /// Provider requests carry a declaration into the shared installer.  A
    /// missing declaration means the native-runtime path.
    pub(super) declaration: Option<ToolDeclaration>,
}

/// Process state captured once at the command/effect boundary. Declaration
/// planning below consumes only this typed value and never reads the process
/// environment itself.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct GlobalProviderEnvironment {
    pub(super) github_asset: Option<String>,
    pub(super) github_checksum_asset: Option<String>,
    pub(super) github_binaries: Option<Vec<String>>,
    pub(super) github_sha256: Option<String>,
    pub(super) npm_endpoint: Option<String>,
    pub(super) nuget_endpoint: Option<String>,
    pub(super) gem_endpoint: Option<String>,
    pub(super) aqua_endpoint: Option<String>,
    pub(super) aqua_revision: Option<String>,
    pub(super) aqua_manifest_sha256: Option<String>,
}

impl GlobalProviderEnvironment {
    fn from_process() -> Self {
        Self {
            github_asset: first_environment_value(&[
                "NEOENV_GLOBAL_GH_ASSET",
                "NEOENV_GITHUB_ASSET",
                "NEOENV_GH_ASSET",
            ]),
            github_checksum_asset: first_environment_value(&[
                "NEOENV_GLOBAL_GH_CHECKSUM_ASSET",
                "NEOENV_GITHUB_CHECKSUM_ASSET",
                "NEOENV_GH_CHECKSUM_ASSET",
            ]),
            github_binaries: environment_list(&[
                "NEOENV_GLOBAL_GH_BINARIES",
                "NEOENV_GITHUB_BINARIES",
                "NEOENV_GLOBAL_GH_BINARY",
                "NEOENV_GITHUB_BINARY",
                "NEOENV_GH_BINARY",
            ]),
            github_sha256: first_environment_value(&[
                "NEOENV_GLOBAL_GH_SHA256",
                "NEOENV_GITHUB_SHA256",
                "NEOENV_GH_SHA256",
            ]),
            npm_endpoint: first_environment_value(&[
                "NEOENV_NPM_REGISTRY",
                "NEOENV_NPM_ENDPOINT",
                "NEOENV_NPM_REGISTRY_URL",
                "NEOENV_NPM_REGISTRY_ENDPOINT",
                "NPM_CONFIG_REGISTRY",
            ]),
            nuget_endpoint: first_environment_value(&[
                "NEOENV_NUGET_V3_ENDPOINT",
                "NEOENV_DOTNET_TOOL_ENDPOINT",
                "NEOENV_NUGET_SOURCE",
            ]),
            gem_endpoint: first_environment_value(&[
                "NEOENV_GEM_REGISTRY",
                "NEOENV_GEM_ENDPOINT",
                "NEOENV_GEM_SOURCE",
            ]),
            aqua_endpoint: first_environment_value(&["NEOENV_GLOBAL_AQUA_ENDPOINT"]),
            aqua_revision: first_environment_value(&["NEOENV_GLOBAL_AQUA_REVISION"]),
            aqua_manifest_sha256: first_environment_value(&["NEOENV_GLOBAL_AQUA_MANIFEST_SHA256"]),
        }
    }
}

pub(super) fn command_spec(action: CommandAction) -> Result<&'static CommandSpec, Diagnostic> {
    ROOT.find(action).ok_or_else(|| {
        Diagnostic::new(
            DiagnosticCategory::Internal,
            "NEO701",
            "command tree is missing a dispatched command endpoint",
        )
    })
}

pub(super) fn use_command_spec() -> Result<&'static CommandSpec, Diagnostic> {
    command_spec(CommandAction::UseShortcut)
}

pub(super) fn parse_global_use(arguments: &[String]) -> Result<GlobalUseRequest, Diagnostic> {
    parse_global_use_with_spec(arguments, use_command_spec()?)
}

pub(super) fn parse_global_use_with_spec(
    arguments: &[String],
    command: &CommandSpec,
) -> Result<GlobalUseRequest, Diagnostic> {
    let provider_environment = GlobalProviderEnvironment::from_process();
    let mut dry_run = false;
    let mut scope = None;
    let mut tools = Vec::new();
    for argument in arguments {
        if command.accepts_option(OptionId::User, argument) {
            if scope.replace(GlobalScope::User).is_some() {
                return Err(Diagnostic::new(
                    DiagnosticCategory::Usage,
                    "NEO001",
                    "duplicate scope option; use exactly one of --user or --global",
                ));
            }
            continue;
        }
        if command.accepts_option(OptionId::Global, argument) {
            if scope.replace(GlobalScope::System).is_some() {
                return Err(Diagnostic::new(
                    DiagnosticCategory::Usage,
                    "NEO001",
                    "duplicate scope option; use exactly one of --user or --global",
                ));
            }
            continue;
        }
        if command.accepts_option(OptionId::DryRun, argument) {
            if dry_run {
                return Err(Diagnostic::new(
                    DiagnosticCategory::Usage,
                    "NEO001",
                    "duplicate --dry-run option",
                ));
            }
            dry_run = true;
            continue;
        }
        if argument.starts_with('-') {
            return Err(Diagnostic::new(
                DiagnosticCategory::Usage,
                "NEO001",
                format!("unknown global use option: {argument}"),
            ));
        }
        let (key, version) = split_global_key_version(argument)?;
        tools.push(parse_global_tool_request_with_environment(
            key,
            version,
            &provider_environment,
        )?);
    }
    if tools.is_empty() {
        return Err(Diagnostic::new(
            DiagnosticCategory::Usage,
            "NEO001",
            "global use requires one or more tools, optionally as name@version",
        ));
    }
    let scope = scope.ok_or_else(|| {
        Diagnostic::new(
            DiagnosticCategory::Usage,
            "NEO001",
            "global tool selection requires an explicit scope: --user for per-user folders or --global for the system installation",
        )
    })?;
    Ok(GlobalUseRequest {
        tools,
        dry_run,
        scope,
    })
}

pub(super) fn split_global_key_version(argument: &str) -> Result<(&str, Option<&str>), Diagnostic> {
    let separator = if argument.starts_with("npm:") {
        argument
            .find(':')
            .and_then(|colon| argument.rfind('@').filter(|at| *at > colon + 1))
    } else {
        argument.rfind('@').filter(|at| *at > 0)
    };
    let Some(separator) = separator else {
        return Ok((argument, None));
    };
    let version = &argument[separator + 1..];
    if version.is_empty() {
        return Err(Diagnostic::new(
            DiagnosticCategory::Usage,
            "NEO001",
            "tool version cannot be empty",
        ));
    }
    Ok((&argument[..separator], Some(version)))
}

pub(super) fn parse_global_tool_request(
    key: &str,
    version: Option<&str>,
) -> Result<GlobalToolRequest, Diagnostic> {
    parse_global_tool_request_with_environment(
        key,
        version,
        &GlobalProviderEnvironment::from_process(),
    )
}

pub(super) fn parse_global_tool_request_with_environment(
    key: &str,
    version: Option<&str>,
    environment: &GlobalProviderEnvironment,
) -> Result<GlobalToolRequest, Diagnostic> {
    if version.is_some_and(|version| {
        version == "."
            || version == ".."
            || version.contains(['/', '\\'])
            || version.chars().any(char::is_control)
    }) {
        return Err(global_key_diagnostic(
            "tool versions cannot contain paths or control characters".into(),
        ));
    }
    let lower = key.to_ascii_lowercase();
    if lower.starts_with("https://") || lower.starts_with("http://") || lower.starts_with("github:")
    {
        return Err(global_key_diagnostic(format!(
            "invalid global tool key `{key}`: use gh:owner/repo for a GitHub release; github: and HTTP(S) keys are remote-module syntax, not use keys"
        )));
    }
    if let Some((provider, package)) = key.split_once(':') {
        if provider.is_empty() || package.is_empty() {
            return Err(global_key_diagnostic(format!(
                "invalid global tool key `{key}`: provider:package requires a provider and package"
            )));
        }
        if !(provider.eq_ignore_ascii_case("aqua")
            && environment.aqua_endpoint.is_some()
            && environment.aqua_revision.is_some()
            && environment.aqua_manifest_sha256.is_some())
        {
            reject_unpinnable_global_provider(provider, key)?;
        }
        if provider.eq_ignore_ascii_case("gh") {
            validate_github_global_repository(package, key)?;
        } else if !matches!(
            provider.to_ascii_lowercase().as_str(),
            "npm" | "dotnet" | "gem" | "aqua"
        ) {
            return Err(global_key_diagnostic(format!(
                "unknown global tool provider prefix `{provider}` in `{key}`; supported providers are gh, npm, dotnet, and gem"
            )));
        } else {
            validate_global_package(package, key)?;
        }
        let requested_version = version.unwrap_or("latest").to_owned();
        let declaration = global_provider_declaration(key, &requested_version, environment)?;
        return Ok(GlobalToolRequest {
            tool: key.to_owned(),
            version: version.map(str::to_owned),
            declaration: Some(declaration),
        });
    }
    validate_tool_name(key)?;
    Ok(GlobalToolRequest {
        tool: canonical_global_runtime_name(key).into(),
        version: version.map(str::to_owned),
        declaration: None,
    })
}

pub(super) fn global_key_diagnostic(message: String) -> Diagnostic {
    Diagnostic::new(DiagnosticCategory::Validation, "NEO510", message)
}

pub(super) fn reject_unpinnable_global_provider(
    provider: &str,
    key: &str,
) -> Result<(), Diagnostic> {
    let reason = match provider.to_ascii_lowercase().as_str() {
        "aqua" => "global use cannot supply the required registry revision and manifest digest",
        "go" => "global use cannot supply the required go.sum entry",
        "gl" => "global use has no GitLab release resolver",
        _ => return Ok(()),
    };
    Err(global_key_diagnostic(format!(
        "global provider `{provider}` in `{key}` requires a pinned project declaration; {reason}"
    )))
}

pub(super) fn validate_github_global_repository(
    package: &str,
    key: &str,
) -> Result<(), Diagnostic> {
    let parts = package.split('/').collect::<Vec<_>>();
    if parts.len() != 2
        || parts.iter().any(|part| {
            part.is_empty() || part.contains(['@', '\\', ':']) || *part == "." || *part == ".."
        })
    {
        return Err(global_key_diagnostic(format!(
            "invalid GitHub release key `{key}` (expected gh:owner/repo)"
        )));
    }
    Ok(())
}

pub(super) fn validate_global_package(package: &str, key: &str) -> Result<(), Diagnostic> {
    if package.is_empty()
        || package.contains(['\\', '?', '#', ' ', '\t', '\n', '\r'])
        || package
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(global_key_diagnostic(format!(
            "invalid provider package in global tool key `{key}`"
        )));
    }
    Ok(())
}

pub(super) fn global_provider_declaration(
    key: &str,
    version: &str,
    environment: &GlobalProviderEnvironment,
) -> Result<ToolDeclaration, Diagnostic> {
    let (provider, package) = key.split_once(':').ok_or_else(|| {
        global_key_diagnostic(format!("invalid provider global tool key `{key}`"))
    })?;
    let base = ToolDeclaration {
        id: key.to_owned(),
        version: version.to_owned(),
        provider: ToolProvider::ExplicitUrl,
        url: None,
        sha256: None,
        github_release: None,
        aqua: None,
        npm: None,
        dotnet_tool: None,
        go_module: None,
        ruby_gems: None,
        cargo: None,
        binaries: Vec::new(),
        platforms: Vec::new(),
        declaration_source: SourceSpan::new(format!("global:{key}"), 1, 1),

        gitlab_release: None,
        binpath: None,
        bindir: None,
    };
    let mut declaration = match provider.to_ascii_lowercase().as_str() {
        "gh" => global_github_declaration(package, base, environment),
        "npm" => global_npm_declaration(package, base, environment),
        "dotnet" => global_dotnet_declaration(package, base, environment),
        "gem" => global_ruby_declaration(package, base, environment),
        "aqua" => global_aqua_declaration(package, base, environment)?,
        _ => {
            return Err(global_key_diagnostic(format!(
                "global provider `{provider}` requires a pinned project declaration"
            )));
        }
    };
    // Keep the requested version in the declaration, not a mutable `latest`
    // sentinel in the lock. The provider resolver replaces it with an exact
    // immutable version where the provider supports a latest query.
    version.clone_into(&mut declaration.version);
    Ok(declaration)
}

fn global_aqua_declaration(
    package: &str,
    mut base: ToolDeclaration,
    environment: &GlobalProviderEnvironment,
) -> Result<ToolDeclaration, Diagnostic> {
    let endpoint = environment.aqua_endpoint.as_deref().ok_or_else(|| {
        global_key_diagnostic("Aqua global use requires NEOENV_GLOBAL_AQUA_ENDPOINT".into())
    })?;
    let revision = environment.aqua_revision.as_deref().ok_or_else(|| {
        global_key_diagnostic("Aqua global use requires NEOENV_GLOBAL_AQUA_REVISION".into())
    })?;
    let manifest_sha256 = environment.aqua_manifest_sha256.as_deref().ok_or_else(|| {
        global_key_diagnostic("Aqua global use requires NEOENV_GLOBAL_AQUA_MANIFEST_SHA256".into())
    })?;
    if !neoenv_core::tools::is_registry_revision(revision)
        || !neoenv_core::tools::is_sha256(manifest_sha256)
    {
        return Err(global_key_diagnostic(
            "Aqua global use requires an immutable registry revision and lowercase manifest SHA-256".into(),
        ));
    }
    base.provider = ToolProvider::Aqua;
    base.binaries = vec![package.rsplit('/').next().unwrap_or(package).to_owned()];
    base.aqua = Some(neoenv_core::tools::AquaDeclaration {
        endpoint: endpoint.to_owned(),
        registry_revision: revision.to_owned(),
        package: package.to_owned(),
        manifest_sha256: manifest_sha256.to_owned(),
    });
    Ok(base)
}

pub(super) fn global_github_declaration(
    package: &str,
    base: ToolDeclaration,
    environment: &GlobalProviderEnvironment,
) -> ToolDeclaration {
    let repository = package.to_owned();
    let default_name = package.rsplit('/').next().unwrap_or(package).to_owned();
    ToolDeclaration {
        provider: ToolProvider::GithubRelease,
        sha256: environment.github_sha256.clone(),
        github_release: Some(GithubReleaseDeclaration {
            repository,
            asset: environment.github_asset.clone(),
            checksum_asset: environment.github_checksum_asset.clone(),
            grep: None,
            prerelease: false,
            rename: None,
        }),
        binaries: environment
            .github_binaries
            .clone()
            .unwrap_or_else(|| vec![default_name]),
        ..base
    }
}

pub(super) fn global_npm_declaration(
    package: &str,
    base: ToolDeclaration,
    environment: &GlobalProviderEnvironment,
) -> ToolDeclaration {
    ToolDeclaration {
        provider: ToolProvider::Npm,
        npm: Some(NpmDeclaration {
            endpoint: environment
                .npm_endpoint
                .clone()
                .unwrap_or_else(|| "https://registry.npmjs.org".into()),
            package: package.to_owned(),
            manager: None,
        }),
        ..base
    }
}

pub(super) fn global_dotnet_declaration(
    package: &str,
    base: ToolDeclaration,
    environment: &GlobalProviderEnvironment,
) -> ToolDeclaration {
    ToolDeclaration {
        provider: ToolProvider::DotnetTool,
        dotnet_tool: Some(DotnetToolDeclaration {
            source: "nuget-v3".into(),
            endpoint: environment
                .nuget_endpoint
                .clone()
                .unwrap_or_else(|| "https://api.nuget.org/v3-flatcontainer".into()),
            package: package.to_owned(),
        }),
        binaries: vec![package.to_ascii_lowercase()],
        ..base
    }
}

pub(super) fn global_ruby_declaration(
    package: &str,
    base: ToolDeclaration,
    environment: &GlobalProviderEnvironment,
) -> ToolDeclaration {
    ToolDeclaration {
        provider: ToolProvider::RubyGems,
        ruby_gems: Some(RubyGemsDeclaration {
            endpoint: environment
                .gem_endpoint
                .clone()
                .unwrap_or_else(|| "https://rubygems.org".into()),
            gem: package.to_owned(),
        }),
        binaries: vec![package.to_owned()],
        ..base
    }
}

pub(super) fn first_environment_value(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        std::env::var(name)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.trim().to_owned())
    })
}

pub(super) fn environment_list(names: &[&str]) -> Option<Vec<String>> {
    first_environment_value(names).map(|value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(str::to_owned)
            .collect()
    })
}

pub(super) fn canonical_global_runtime_name(tool: &str) -> &str {
    match tool {
        "golang" => "go",
        name => name,
    }
}

/// The two install scopes.
///
/// User scope is the historical `NEOENV_CONFIG_HOME`/`NEOENV_DATA_HOME`
/// layout. System scope is machine-wide and is never selected implicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GlobalScope {
    User,
    System,
}

/// The resolved configuration file and data root for one scope.
#[derive(Clone, Debug)]
pub(super) struct GlobalLayout {
    config_path: PathBuf,
    data_root: PathBuf,
}

impl GlobalLayout {
    pub(super) fn resolve(scope: GlobalScope) -> Result<Self, Diagnostic> {
        let (config_dir, data_root) = match scope {
            GlobalScope::User => {
                let config_root = neoenv_runtime::paths::user_directory(UserDirectory::Config);
                let data_root = neoenv_runtime::paths::user_directory(UserDirectory::Data);
                // Validate the configured roots before joining the product-owned
                // directory. On Windows, metadata("file\\neoenv") reports
                // NotFound (rather than NotADirectory), which would otherwise
                // make an invalid root look like an absent optional directory.
                for root in [&config_root, &data_root].into_iter().flatten() {
                    validate_user_root_directory(root)?;
                }
                (
                    config_root.map(|root| root.join(neoenv_core::names::USER_DIRECTORY)),
                    data_root.map(|root| root.join(neoenv_core::names::USER_DIRECTORY)),
                )
            }
            GlobalScope::System => (
                system_directory(neoenv_runtime::paths::SystemDirectory::Config),
                system_directory(neoenv_runtime::paths::SystemDirectory::Install),
            ),
        };
        let config_dir = config_dir.ok_or_else(|| {
            global_scope_error(scope, "cannot determine the nenv configuration directory")
        })?;
        let data_root = data_root
            .ok_or_else(|| global_scope_error(scope, "cannot determine the nenv data directory"))?;
        if scope == GlobalScope::System {
            for path in [&config_dir, &data_root] {
                validate_system_path(path)?;
            }
            for managed in ["tools", "locks", "artifacts"] {
                validate_system_managed_child(&data_root.join(managed))?;
            }
        }
        validate_regular_directory(&config_dir)?;
        validate_regular_directory(&data_root)?;
        Ok(Self {
            config_path: config_dir.join(neoenv_core::names::GLOBAL_CONFIG_FILE),
            data_root,
        })
    }

    pub(super) fn data_directory(&self) -> PathBuf {
        self.data_root.join("tools")
    }

    pub(super) fn storage(&self) -> Result<ToolStorage, Diagnostic> {
        let storage = ToolStorage::global(&self.data_root);
        for directory in [storage.artifact_directory(), storage.install_directory()] {
            validate_regular_directory(directory)?;
        }
        Ok(storage)
    }

    pub(super) fn provider_lock_path(&self, request: &GlobalToolRequest) -> PathBuf {
        let version = request.version.as_deref().unwrap_or("latest");
        let identity = format!("{}\0{version}", request.tool);
        let digest = format!("{:x}", Sha256::digest(identity.as_bytes()));
        self.data_root.join("locks").join(format!(
            "{digest}{}",
            neoenv_core::names::LOCKFILE_LOCK_SUFFIX
        ))
    }
}

/// Rejects traversal, non-absolute paths, and symlinked ancestors for a system
/// root.
///
/// This is a fail-closed **precondition**, not a claim that a later path-based
/// rename is race-free. System mutation is disabled in this build precisely
/// because these checks cannot make `fs::rename` directory-relative; read-only
/// inspection still gets the benefit of refusing an obviously redirected root.
fn validate_system_path(path: &Path) -> Result<(), Diagnostic> {
    if !path.is_absolute() {
        return Err(Diagnostic::new(
            DiagnosticCategory::Runtime,
            "NEO522",
            format!(
                "system path {} is not absolute; set NEOENV_GLOBAL_CONFIG_DIR and NEOENV_GLOBAL_INSTALL_DIR to absolute paths",
                path.display()
            ),
        ));
    }
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(Diagnostic::new(
            DiagnosticCategory::Runtime,
            "NEO522",
            format!(
                "system path {} contains `..`; use a normalized absolute path",
                path.display()
            ),
        ));
    }
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(Diagnostic::new(
                    DiagnosticCategory::Runtime,
                    "NEO522",
                    format!(
                        "system path {} has a symlinked ancestor {}; refusing to follow it",
                        path.display(),
                        ancestor.display()
                    ),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(Diagnostic::new(
                    DiagnosticCategory::Runtime,
                    "NEO522",
                    format!(
                        "failed to inspect system path ancestor {}: {error}",
                        ancestor.display()
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn validate_system_managed_child(path: &Path) -> Result<(), Diagnostic> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(Diagnostic::new(
            DiagnosticCategory::Runtime,
            "NEO522",
            format!(
                "system managed directory {} is a symlink; refusing to follow it",
                path.display()
            ),
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Diagnostic::new(
            DiagnosticCategory::Runtime,
            "NEO522",
            format!(
                "failed to inspect system managed directory {}: {error}",
                path.display()
            ),
        )),
    }
}

fn validate_regular_directory(path: &Path) -> Result<(), Diagnostic> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            Ok(())
        }
        Ok(_) => Err(Diagnostic::new(
            DiagnosticCategory::Runtime,
            "NEO522",
            format!(
                "nenv directory is not a regular directory: {}",
                path.display()
            ),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Diagnostic::new(
            DiagnosticCategory::Runtime,
            "NEO522",
            format!(
                "failed to inspect nenv directory {}: {error}",
                path.display()
            ),
        )),
    }
}

/// Validate a user-selected XDG root while following a root symlink.
///
/// Configured roots may intentionally point through a symlink, but must resolve
/// to a directory. A missing root remains valid because read-only lookup need
/// not create the user's directory tree.
fn validate_user_root_directory(path: &Path) -> Result<(), Diagnostic> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(Diagnostic::new(
            DiagnosticCategory::Runtime,
            "NEO522",
            format!("configured user root {} is not a directory", path.display()),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Diagnostic::new(
            DiagnosticCategory::Runtime,
            "NEO522",
            format!(
                "failed to inspect configured user root {}: {error}",
                path.display()
            ),
        )),
    }
}

fn global_scope_error(scope: GlobalScope, detail: &str) -> Diagnostic {
    let override_hint = match scope {
        GlobalScope::User => {
            "set NEOENV_CONFIG_HOME and NEOENV_DATA_HOME (or XDG_CONFIG_HOME/XDG_DATA_HOME)"
        }
        GlobalScope::System => {
            "set NEOENV_GLOBAL_CONFIG_DIR and NEOENV_GLOBAL_INSTALL_DIR to writable absolute paths"
        }
    };
    Diagnostic::new(
        DiagnosticCategory::Runtime,
        "NEO522",
        format!("{detail}; {override_hint}"),
    )
}

pub(super) fn global_tool_config_path(scope: GlobalScope) -> Result<PathBuf, Diagnostic> {
    GlobalLayout::resolve(scope).map(|layout| layout.config_path)
}

pub(super) fn global_tool_data_root(scope: GlobalScope) -> Result<PathBuf, Diagnostic> {
    GlobalLayout::resolve(scope).map(|layout| layout.data_root)
}

pub(super) fn global_tool_data_directory(scope: GlobalScope) -> Result<PathBuf, Diagnostic> {
    GlobalLayout::resolve(scope).map(|layout| layout.data_directory())
}

pub(super) fn global_tool_storage(scope: GlobalScope) -> Result<ToolStorage, Diagnostic> {
    GlobalLayout::resolve(scope)?.storage()
}

pub(super) fn global_provider_lock_path(
    scope: GlobalScope,
    request: &GlobalToolRequest,
) -> Result<PathBuf, Diagnostic> {
    Ok(GlobalLayout::resolve(scope)?.provider_lock_path(request))
}

pub(super) fn safe_global_lock_name(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.ends_with(neoenv_core::names::LOCKFILE_LOCK_SUFFIX) && !name.starts_with('.')
        })
        && !path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
}

pub(super) const MAX_CONCURRENT_GLOBAL_INSTALLS: usize = 10;

#[allow(clippy::large_enum_variant)] // Completion owns the provenance-rich result.
pub(super) enum GlobalInstallEvent {
    Resolving {
        index: usize,
    },
    Progress {
        index: usize,
        progress: GlobalInstallProgress,
    },
    Finished {
        index: usize,
        result: Result<GlobalToolInstallation, Diagnostic>,
    },
}

pub(super) enum GlobalInstallProgress {
    Bun(BunRuntimeProgress),
    Deno(DenoRuntimeProgress),
    Dotnet(DotnetSdkProgress),
    Go(GoSdkProgress),
    Java(JavaRuntimeProgress),
    Node(NodeRuntimeProgress),
    Odin(OdinRuntimeProgress),
    Python(PythonRuntimeProgress),
    Rust(RustRuntimeProgress),
    Uv(UvRuntimeProgress),
    Zig(ZigRuntimeProgress),
    Provider(GlobalProviderProgress),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GlobalProviderProgress {
    Resolved,
    Installing,
    AlreadyInstalled,
}

#[derive(Clone, Debug)]
pub(super) struct GlobalProviderInstallation {
    pub(super) resolved_version: String,
    pub(super) sha256: String,
    pub(super) source: String,
    pub(super) resolver: String,
    pub(super) immutable_id: String,
    pub(super) install_path: PathBuf,
    pub(super) lock_path: PathBuf,
    pub(super) binaries: Vec<String>,
}

#[derive(Debug, Clone)]
pub(super) struct GlobalToolInstallation {
    pub(super) tool: String,
    pub(super) version: String,
    pub(super) executable: PathBuf,
    pub(super) provider: Option<GlobalProviderInstallation>,
    pub(super) new_install: bool,
}

pub(super) fn print_global_use_preview(
    tools: &[GlobalToolRequest],
    scope: GlobalScope,
) -> Result<(), Diagnostic> {
    let data_directory = global_tool_data_directory(scope)?;
    println!("Would install {} tool(s):", tools.len());
    for (index, tool) in tools.iter().enumerate() {
        let destination = if tool.declaration.is_some() {
            data_directory.join(format!(
                "{}@{}",
                tool.tool,
                tool.version.as_deref().unwrap_or("latest")
            ))
        } else {
            data_directory.join(&tool.tool)
        };
        println!(
            "[{}/{}] {}@{} -> {}",
            index + 1,
            tools.len(),
            tool.tool,
            tool.version.as_deref().unwrap_or("latest"),
            destination.display(),
        );
    }
    Ok(())
}

pub(super) struct GlobalInstallWorker {
    index: usize,
    handle: thread::JoinHandle<()>,
}

pub(crate) fn system_mutation_disabled_diagnostic() -> Diagnostic {
    Diagnostic::new(
        DiagnosticCategory::Usage,
        "NEO001",
        "system-scope mutation is disabled in this build: it cannot guarantee race-resistant directory-relative publish/remove, and a path check alone would leave a time-of-check/time-of-use gap. `--global`/`-g` remain the system scope for inspection and dry-run; use `--user` to install or remove tools",
    )
}

pub(super) fn install_global_tools(
    tools: &[GlobalToolRequest],
    scope: GlobalScope,
) -> Result<(), Diagnostic> {
    if scope == GlobalScope::System {
        return Err(system_mutation_disabled_diagnostic());
    }
    let cancellation = global_install_cancellation()?;
    install_global_tools_with_cancellation(tools, &cancellation, scope)
}

pub(super) fn install_global_tools_with_cancellation(
    tools: &[GlobalToolRequest],
    cancellation: &Arc<AtomicBool>,
    scope: GlobalScope,
) -> Result<(), Diagnostic> {
    let installations = install_global_tools_transaction(tools, cancellation, true, scope)?;
    if let Err(error) = record_global_tools(&installations, cancellation.as_ref(), scope) {
        cleanup_new_global_installations(&installations, scope);
        return Err(error);
    }
    for (index, installation) in installations.iter().enumerate() {
        println!(
            "[{}/{}] installed {}@{} -> {}",
            index + 1,
            installations.len(),
            installation.tool,
            installation.version,
            installation.executable.display(),
        );
    }
    Ok(())
}

/// Installs into the global data tree without changing the selected global
/// configuration.  Lifecycle callers use this boundary so they can publish
/// their own validated selection record only after every install succeeds.
#[allow(clippy::too_many_lines)]
pub(super) fn install_global_tools_transaction(
    tools: &[GlobalToolRequest],
    cancellation: &Arc<AtomicBool>,
    report_progress: bool,
    scope: GlobalScope,
) -> Result<Vec<GlobalToolInstallation>, Diagnostic> {
    if scope == GlobalScope::System {
        return Err(system_mutation_disabled_diagnostic());
    }
    for tool in tools {
        if tool.declaration.is_none()
            && !matches!(
                tool.tool.as_str(),
                "bun"
                    | "deno"
                    | "dotnet"
                    | "go"
                    | "golang"
                    | "java"
                    | "node"
                    | "odin"
                    | "python"
                    | "rust"
                    | "uv"
                    | "zig"
            )
        {
            return Err(Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO510",
                format!(
                    "native global installer is not available for {}; supported runtimes: bun, deno, dotnet, go, java, node, odin, python, rust, uv, zig",
                    tool.tool
                ),
            ));
        }
    }
    let total = tools.len();
    let data_directory = global_tool_data_directory(scope)?;
    cleanup_stale_temporaries_in(&global_tool_storage(scope)?)?;
    let mut existing_native = HashSet::new();
    for tool in tools {
        if tool.declaration.is_none() {
            let directory = data_directory.join(&tool.tool);
            if let Ok(entries) = fs::read_dir(directory) {
                for entry in entries.flatten() {
                    existing_native.insert((
                        tool.tool.clone(),
                        entry.file_name().to_string_lossy().into_owned(),
                    ));
                }
            }
        }
    }
    let mut progress_steps = vec![None; total];
    if report_progress {
        println!(
            "Installing {total} tool(s); up to {MAX_CONCURRENT_GLOBAL_INSTALLS} run in parallel."
        );
    }
    let results = supervise_global_installs(
        tools,
        cancellation.as_ref(),
        |index, tool, sender| {
            if report_progress {
                println!(
                    "[{}/{}] queued {}@{}",
                    index + 1,
                    total,
                    tool.tool,
                    tool.version.as_deref().unwrap_or("latest"),
                );
            }
            start_global_tool_install(
                index,
                tool.clone(),
                data_directory.clone(),
                sender,
                Arc::clone(cancellation),
                scope,
            )
        },
        |event| {
            if report_progress {
                print_global_install_event(event, tools, total, &mut progress_steps);
            }
        },
    )?;

    let mut installations = Vec::with_capacity(total);
    let mut first_error = None;
    for (index, result) in results.into_iter().enumerate() {
        match result {
            Ok(mut installation) => {
                if installation.provider.is_none()
                    && !existing_native
                        .contains(&(installation.tool.clone(), installation.version.clone()))
                {
                    installation.new_install = true;
                }
                installations.push(installation);
            }
            Err(error) => {
                if report_progress {
                    println!(
                        "[{}/{}] failed {}: {}",
                        index + 1,
                        total,
                        tool_label(&tools[index]),
                        error
                    );
                }
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
    }
    if first_error.is_some() || cancellation.load(Ordering::Acquire) {
        cleanup_new_global_installations(&installations, scope);
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    if cancellation.load(Ordering::Acquire) {
        cleanup_new_global_installations(&installations, scope);
        return Err(global_install_cancelled());
    }
    for installation in &mut installations {
        if installation.provider.is_none()
            && let Err(error) = mark_global_native_install(
                &data_directory,
                &installation.tool,
                &installation.version,
            )
        {
            cleanup_new_global_installations(&installations, scope);
            return Err(error);
        }
    }
    Ok(installations)
}

/// Supervises a bounded pool without making channel delivery a correctness
/// requirement.  A worker that exits without a `Finished` event is noticed
/// through its join handle, and a disconnected channel is harmless once the
/// handles are polled.
// Scheduling, draining, and recovery stay together.
#[allow(clippy::too_many_lines)]
pub(super) fn supervise_global_installs<F, R>(
    tools: &[GlobalToolRequest],
    cancellation: &AtomicBool,
    mut start: F,
    mut render: R,
) -> Result<Vec<Result<GlobalToolInstallation, Diagnostic>>, Diagnostic>
where
    F: FnMut(usize, &GlobalToolRequest, mpsc::Sender<GlobalInstallEvent>) -> thread::JoinHandle<()>,
    R: FnMut(&GlobalInstallEvent),
{
    let total = tools.len();
    if total == 0 {
        return Ok(Vec::new());
    }
    let (sender, receiver) = mpsc::channel();
    let mut results = (0..total).map(|_| None).collect::<Vec<_>>();
    let mut workers = Vec::with_capacity(total);
    let mut next = 0;
    let mut active = 0;

    while next < total
        && active < MAX_CONCURRENT_GLOBAL_INSTALLS
        && !cancellation.load(Ordering::Acquire)
    {
        let index = next;
        let handle = start(index, &tools[index], sender.clone());
        workers.push(GlobalInstallWorker { index, handle });
        next += 1;
        active += 1;
    }

    let mut channel_open;
    while active > 0 {
        // Drain all already-available events before inspecting finished
        // handles.  A worker queues its event before its handle becomes
        // finished, so this avoids mistaking a valid event for a lost send.
        channel_open = drain_global_install_events(
            &receiver,
            tools,
            cancellation,
            &sender,
            &mut workers,
            &mut results,
            &mut next,
            &mut active,
            &mut start,
            &mut render,
        );
        if active == 0 {
            break;
        }
        recover_finished_global_install_workers(
            &mut workers,
            &receiver,
            tools,
            cancellation,
            &sender,
            &mut results,
            &mut next,
            &mut active,
            &mut start,
            &mut render,
            &mut channel_open,
        );
        while next < tools.len()
            && active < MAX_CONCURRENT_GLOBAL_INSTALLS
            && !cancellation.load(Ordering::Acquire)
        {
            let request_index = next;
            let handle = start(request_index, &tools[request_index], sender.clone());
            workers.push(GlobalInstallWorker {
                index: request_index,
                handle,
            });
            next += 1;
            active += 1;
        }
        if active == 0 {
            break;
        }
        if channel_open {
            match receiver.recv_timeout(Duration::from_millis(10)) {
                Ok(event) => handle_global_install_event(
                    event,
                    tools,
                    cancellation,
                    &sender,
                    &mut workers,
                    &mut results,
                    &mut next,
                    &mut active,
                    &mut start,
                    &mut render,
                ),
                Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => {}
            }
        } else {
            thread::sleep(Duration::from_millis(10));
        }
    }

    // No worker is detached.  Joining every handle is also what makes a
    // cancellation/error path unable to leave an installer thread behind.
    drop(sender);
    let mut join_error = None;
    for worker in workers {
        if worker.handle.join().is_err() && join_error.is_none() {
            join_error = Some(Diagnostic::new(
                DiagnosticCategory::Internal,
                "NEO702",
                "global installer worker panicked outside its error boundary",
            ));
        }
    }
    if cancellation.load(Ordering::Acquire) {
        return Err(global_install_cancelled());
    }
    if let Some(error) = join_error {
        return Err(error);
    }

    results
        .into_iter()
        .enumerate()
        .map(|(index, result)| {
            result.ok_or_else(|| {
                Diagnostic::new(
                    DiagnosticCategory::Internal,
                    "NEO701",
                    format!(
                        "global installer completed without a result for {}",
                        tool_label(&tools[index])
                    ),
                )
            })
        })
        .collect()
}

// The event boundary passes the complete supervisor state.
#[allow(clippy::too_many_arguments)]
pub(super) fn handle_global_install_event<F, R>(
    event: GlobalInstallEvent,
    tools: &[GlobalToolRequest],
    cancellation: &AtomicBool,
    sender: &mpsc::Sender<GlobalInstallEvent>,
    workers: &mut Vec<GlobalInstallWorker>,
    results: &mut [Option<Result<GlobalToolInstallation, Diagnostic>>],
    next: &mut usize,
    active: &mut usize,
    start: &mut F,
    render: &mut R,
) where
    F: FnMut(usize, &GlobalToolRequest, mpsc::Sender<GlobalInstallEvent>) -> thread::JoinHandle<()>,
    R: FnMut(&GlobalInstallEvent),
{
    match event {
        GlobalInstallEvent::Finished { index, result } => {
            let Some(slot) = results.get_mut(index) else {
                return;
            };
            if slot.is_some() {
                return;
            }
            *slot = Some(result);
            *active = active.saturating_sub(1);
            if !cancellation.load(Ordering::Acquire) && *next < tools.len() {
                let request_index = *next;
                let handle = start(request_index, &tools[request_index], sender.clone());
                workers.push(GlobalInstallWorker {
                    index: request_index,
                    handle,
                });
                *next += 1;
                *active += 1;
            }
        }
        event => render(&event),
    }
}

// Event draining shares the complete supervisor state.
#[allow(clippy::too_many_arguments)]
pub(super) fn drain_global_install_events<F, R>(
    receiver: &mpsc::Receiver<GlobalInstallEvent>,
    tools: &[GlobalToolRequest],
    cancellation: &AtomicBool,
    sender: &mpsc::Sender<GlobalInstallEvent>,
    workers: &mut Vec<GlobalInstallWorker>,
    results: &mut [Option<Result<GlobalToolInstallation, Diagnostic>>],
    next: &mut usize,
    active: &mut usize,
    start: &mut F,
    render: &mut R,
) -> bool
where
    F: FnMut(usize, &GlobalToolRequest, mpsc::Sender<GlobalInstallEvent>) -> thread::JoinHandle<()>,
    R: FnMut(&GlobalInstallEvent),
{
    loop {
        match receiver.try_recv() {
            Ok(event) => handle_global_install_event(
                event,
                tools,
                cancellation,
                sender,
                workers,
                results,
                next,
                active,
                start,
                render,
            ),
            Err(mpsc::TryRecvError::Empty) => return true,
            Err(mpsc::TryRecvError::Disconnected) => return false,
        }
    }
}

// Recovery must drain after observing each finished handle.
#[allow(clippy::too_many_arguments)]
pub(super) fn recover_finished_global_install_workers<F, R>(
    workers: &mut Vec<GlobalInstallWorker>,
    receiver: &mpsc::Receiver<GlobalInstallEvent>,
    tools: &[GlobalToolRequest],
    cancellation: &AtomicBool,
    sender: &mpsc::Sender<GlobalInstallEvent>,
    results: &mut [Option<Result<GlobalToolInstallation, Diagnostic>>],
    next: &mut usize,
    active: &mut usize,
    start: &mut F,
    render: &mut R,
    channel_open: &mut bool,
) where
    F: FnMut(usize, &GlobalToolRequest, mpsc::Sender<GlobalInstallEvent>) -> thread::JoinHandle<()>,
    R: FnMut(&GlobalInstallEvent),
{
    let candidates = workers
        .iter()
        .filter_map(|worker| {
            (results[worker.index].is_none() && worker.handle.is_finished()).then_some(worker.index)
        })
        .collect::<Vec<_>>();
    for index in candidates {
        // Observe the handle immediately before the second drain.  The send
        // happens-before thread exit, so a successful send must be visible in
        // the channel by the time this observation returns.
        let finished = workers
            .iter()
            .find(|worker| worker.index == index)
            .is_some_and(|worker| worker.handle.is_finished());
        if !finished || results[index].is_some() {
            continue;
        }
        if !drain_global_install_events(
            receiver,
            tools,
            cancellation,
            sender,
            workers,
            results,
            next,
            active,
            start,
            render,
        ) {
            *channel_open = false;
        }
        // Only classify a lost send after the post-is_finished drain.  A
        // queued Finished event is authoritative even if the handle has
        // already exited.
        if results[index].is_some() {
            continue;
        }
        let error = if cancellation.load(Ordering::Acquire) {
            global_install_cancelled()
        } else {
            Diagnostic::new(
                DiagnosticCategory::Internal,
                "NEO701",
                format!(
                    "global installer stopped before completing: worker exited without a completion event for {}",
                    tool_label(&tools[index])
                ),
            )
        };
        results[index] = Some(Err(error));
        *active = active.saturating_sub(1);
    }
}

#[allow(clippy::too_many_lines)] // One match over every runtime's progress contract.
pub(super) fn print_global_install_event(
    event: &GlobalInstallEvent,
    tools: &[GlobalToolRequest],
    total: usize,
    progress_steps: &mut [Option<u8>],
) {
    match event {
        GlobalInstallEvent::Resolving { index } => {
            if let Some(tool) = tools.get(*index) {
                println!(
                    "[{}/{}] resolving {}@{}",
                    index + 1,
                    total,
                    tool.tool,
                    tool.version.as_deref().unwrap_or("latest"),
                );
            }
        }
        GlobalInstallEvent::Progress { index, progress } => {
            let Some(tool) = tools.get(*index) else {
                return;
            };
            match progress {
                GlobalInstallProgress::Bun(BunRuntimeProgress::Downloading {
                    received,
                    total: size,
                })
                | GlobalInstallProgress::Deno(DenoRuntimeProgress::Downloading {
                    received,
                    total: size,
                })
                | GlobalInstallProgress::Dotnet(DotnetSdkProgress::Downloading {
                    received,
                    total: size,
                })
                | GlobalInstallProgress::Go(GoSdkProgress::Downloading {
                    received,
                    total: size,
                })
                | GlobalInstallProgress::Java(JavaRuntimeProgress::Downloading {
                    received,
                    total: size,
                })
                | GlobalInstallProgress::Node(NodeRuntimeProgress::Downloading {
                    received,
                    total: size,
                })
                | GlobalInstallProgress::Odin(OdinRuntimeProgress::Downloading {
                    received,
                    total: size,
                })
                | GlobalInstallProgress::Python(PythonRuntimeProgress::Downloading {
                    received,
                    total: size,
                })
                | GlobalInstallProgress::Rust(RustRuntimeProgress::Downloading {
                    received,
                    total: size,
                })
                | GlobalInstallProgress::Uv(UvRuntimeProgress::Downloading {
                    received,
                    total: size,
                })
                | GlobalInstallProgress::Zig(ZigRuntimeProgress::Downloading {
                    received,
                    total: size,
                }) => {
                    if let Some(step) = progress_steps.get_mut(*index) {
                        print_global_download_progress(*index, total, tool, *received, *size, step);
                    }
                }
                GlobalInstallProgress::Bun(BunRuntimeProgress::Extracting)
                | GlobalInstallProgress::Deno(DenoRuntimeProgress::Extracting)
                | GlobalInstallProgress::Dotnet(DotnetSdkProgress::Extracting)
                | GlobalInstallProgress::Go(GoSdkProgress::Extracting)
                | GlobalInstallProgress::Java(JavaRuntimeProgress::Extracting)
                | GlobalInstallProgress::Node(NodeRuntimeProgress::Extracting)
                | GlobalInstallProgress::Odin(OdinRuntimeProgress::Extracting)
                | GlobalInstallProgress::Python(PythonRuntimeProgress::Extracting)
                | GlobalInstallProgress::Rust(RustRuntimeProgress::Extracting)
                | GlobalInstallProgress::Uv(UvRuntimeProgress::Extracting)
                | GlobalInstallProgress::Zig(ZigRuntimeProgress::Extracting) => println!(
                    "[{}/{}] [####################] verifying and extracting {}",
                    index + 1,
                    total,
                    tool_label(tool),
                ),
                GlobalInstallProgress::Provider(GlobalProviderProgress::Resolved) => println!(
                    "[{}/{}] resolved {}; locking provider artifact",
                    index + 1,
                    total,
                    tool_label(tool),
                ),
                GlobalInstallProgress::Provider(GlobalProviderProgress::Installing) => println!(
                    "[{}/{}] installing verified provider artifact {}",
                    index + 1,
                    total,
                    tool_label(tool),
                ),
                GlobalInstallProgress::Provider(GlobalProviderProgress::AlreadyInstalled) => {
                    println!(
                        "[{}/{}] already installed {}",
                        index + 1,
                        total,
                        tool_label(tool),
                    );
                }
            }
        }
        GlobalInstallEvent::Finished { .. } => {}
    }
}

pub(super) static CTRL_C_SIGNAL: OnceLock<Result<Arc<AtomicBool>, String>> = OnceLock::new();

pub(super) fn ctrl_c_signal() -> Result<Arc<AtomicBool>, String> {
    CTRL_C_SIGNAL
        .get_or_init(|| {
            let cancelled = Arc::new(AtomicBool::new(false));
            let signal = Arc::clone(&cancelled);
            ctrlc::set_handler(move || signal.store(true, Ordering::Release))
                .map(|()| cancelled)
                .map_err(|error| error.to_string())
        })
        .clone()
}

pub(super) fn global_install_cancellation() -> Result<Arc<AtomicBool>, Diagnostic> {
    ctrl_c_signal().map_err(|error| {
        Diagnostic::new(
            DiagnosticCategory::Runtime,
            "NEO330",
            format!("failed to install global installer cancellation handler: {error}"),
        )
    })
}

pub(super) fn global_install_cancelled() -> Diagnostic {
    Diagnostic::new(
        DiagnosticCategory::Runtime,
        "NEO330",
        "global tool installation cancelled",
    )
}

pub(super) fn start_global_tool_install(
    index: usize,
    tool: GlobalToolRequest,
    data_directory: PathBuf,
    sender: mpsc::Sender<GlobalInstallEvent>,
    cancellation: Arc<AtomicBool>,
    scope: GlobalScope,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        if !cancellation.load(Ordering::Acquire) {
            let _ = sender.send(GlobalInstallEvent::Resolving { index });
        }
        // A provider, progress callback, or filesystem adapter must not be
        // able to strand the coordinator waiting for a completion event.
        // Keep the worker supervised, but turn an unwind into the same typed
        // failure path as any other installer error.
        let result = if cancellation.load(Ordering::Acquire) {
            Err(global_install_cancelled())
        } else {
            catch_global_install_panic(&tool, || {
                if cancellation.load(Ordering::Acquire) {
                    return Err(global_install_cancelled());
                }
                install_one_global_tool(
                    index,
                    &tool,
                    &data_directory,
                    &sender,
                    &cancellation,
                    scope,
                )
            })
        };
        let _ = sender.send(GlobalInstallEvent::Finished { index, result });
    })
}

pub(super) fn catch_global_install_panic<F>(
    tool: &GlobalToolRequest,
    operation: F,
) -> Result<GlobalToolInstallation, Diagnostic>
where
    F: FnOnce() -> Result<GlobalToolInstallation, Diagnostic>,
{
    panic::catch_unwind(AssertUnwindSafe(operation)).unwrap_or_else(|_| {
        Err(Diagnostic::new(
            DiagnosticCategory::Internal,
            "NEO702",
            format!("global installer panicked for {}", tool_label(tool)),
        ))
    })
}

pub(super) fn validate_native_runtime_request(tool: &GlobalToolRequest) -> Result<(), Diagnostic> {
    if tool.version.as_deref().is_some_and(|version| {
        version.contains('/') || version.contains('\\') || version.chars().any(char::is_control)
    }) {
        return Err(global_key_diagnostic(format!(
            "invalid native runtime version for {}: versions cannot contain paths or control characters",
            tool.tool
        )));
    }
    Ok(())
}

// Provider cases remain explicit and independently auditable.
#[allow(clippy::too_many_lines)]
pub(super) fn install_one_global_tool(
    index: usize,
    tool: &GlobalToolRequest,
    data_directory: &Path,
    sender: &mpsc::Sender<GlobalInstallEvent>,
    cancellation: &AtomicBool,
    scope: GlobalScope,
) -> Result<GlobalToolInstallation, Diagnostic> {
    if let Some(declaration) = &tool.declaration {
        return install_one_global_provider(index, tool, declaration, sender, cancellation, scope);
    }
    validate_native_runtime_request(tool)?;
    match tool.tool.as_str() {
        "bun" => {
            let asset = resolve_bun_runtime(
                tool.version.as_deref().unwrap_or("latest"),
                &Platform::host(),
            )?;
            let directory = data_directory.join("bun").join(&asset.version);
            let executable = install_bun_runtime_with_progress(&directory, &asset, |progress| {
                let _ = sender.send(GlobalInstallEvent::Progress {
                    index,
                    progress: GlobalInstallProgress::Bun(progress),
                });
            })?;
            Ok(GlobalToolInstallation {
                tool: "bun".into(),
                version: asset.version,
                executable,
                provider: None,
                new_install: false,
            })
        }
        "deno" => {
            let asset = resolve_deno_runtime(
                tool.version.as_deref().unwrap_or("latest"),
                &Platform::host(),
            )?;
            let directory = data_directory.join("deno").join(&asset.version);
            let executable = install_deno_runtime_with_progress(&directory, &asset, |progress| {
                let _ = sender.send(GlobalInstallEvent::Progress {
                    index,
                    progress: GlobalInstallProgress::Deno(progress),
                });
            })?;
            Ok(GlobalToolInstallation {
                tool: "deno".into(),
                version: asset.version,
                executable,
                provider: None,
                new_install: false,
            })
        }
        "dotnet" => {
            let asset = resolve_dotnet_sdk(
                tool.version.as_deref().unwrap_or("latest"),
                &Platform::host(),
            )?;
            let directory = data_directory.join("dotnet").join(&asset.version);
            let executable = install_dotnet_sdk_with_progress(&directory, &asset, |progress| {
                let _ = sender.send(GlobalInstallEvent::Progress {
                    index,
                    progress: GlobalInstallProgress::Dotnet(progress),
                });
            })?;
            Ok(GlobalToolInstallation {
                tool: "dotnet".into(),
                version: asset.version,
                executable,
                provider: None,
                new_install: false,
            })
        }
        "go" | "golang" => {
            let asset = resolve_go_sdk(
                tool.version.as_deref().unwrap_or("latest"),
                &Platform::host(),
            )?;
            let directory = data_directory.join("go").join(&asset.version);
            let executable = install_go_sdk_with_progress(&directory, &asset, |progress| {
                let _ = sender.send(GlobalInstallEvent::Progress {
                    index,
                    progress: GlobalInstallProgress::Go(progress),
                });
            })?;
            Ok(GlobalToolInstallation {
                tool: "go".into(),
                version: asset.version,
                executable,
                provider: None,
                new_install: false,
            })
        }
        "java" => {
            let asset = resolve_java_runtime(
                tool.version.as_deref().unwrap_or("latest"),
                &Platform::host(),
            )?;
            let directory = data_directory.join("java").join(&asset.version);
            let executable = install_java_runtime_with_progress(&directory, &asset, |progress| {
                let _ = sender.send(GlobalInstallEvent::Progress {
                    index,
                    progress: GlobalInstallProgress::Java(progress),
                });
            })?;
            Ok(GlobalToolInstallation {
                tool: "java".into(),
                version: asset.version,
                executable,
                provider: None,
                new_install: false,
            })
        }
        "node" => {
            let asset = resolve_node_runtime(
                tool.version.as_deref().unwrap_or("latest"),
                &Platform::host(),
            )?;
            let directory = data_directory.join("node").join(&asset.version);
            let executable = install_node_runtime_with_progress(&directory, &asset, |progress| {
                let _ = sender.send(GlobalInstallEvent::Progress {
                    index,
                    progress: GlobalInstallProgress::Node(progress),
                });
            })?;
            Ok(GlobalToolInstallation {
                tool: "node".into(),
                version: asset.version,
                executable,
                provider: None,
                new_install: false,
            })
        }
        "odin" => {
            let asset = resolve_odin_runtime(
                tool.version.as_deref().unwrap_or("latest"),
                &Platform::host(),
            )?;
            let directory = data_directory.join("odin").join(&asset.version);
            let executable = install_odin_runtime_with_progress(&directory, &asset, |progress| {
                let _ = sender.send(GlobalInstallEvent::Progress {
                    index,
                    progress: GlobalInstallProgress::Odin(progress),
                });
            })?;
            Ok(GlobalToolInstallation {
                tool: "odin".into(),
                version: asset.version,
                executable,
                provider: None,
                new_install: false,
            })
        }
        "python" => {
            let asset = resolve_python_runtime(
                tool.version.as_deref().unwrap_or("latest"),
                &Platform::host(),
            )?;
            let directory = data_directory.join("python").join(&asset.version);
            let executable =
                install_python_runtime_with_progress(&directory, &asset, |progress| {
                    let _ = sender.send(GlobalInstallEvent::Progress {
                        index,
                        progress: GlobalInstallProgress::Python(progress),
                    });
                })?;
            Ok(GlobalToolInstallation {
                tool: "python".into(),
                version: asset.version,
                executable,
                provider: None,
                new_install: false,
            })
        }
        "rust" => {
            let asset = resolve_rust_runtime(
                tool.version.as_deref().unwrap_or("latest"),
                &Platform::host(),
            )?;
            let directory = data_directory.join("rust").join(&asset.version);
            let executable = install_rust_runtime_with_progress(&directory, &asset, |progress| {
                let _ = sender.send(GlobalInstallEvent::Progress {
                    index,
                    progress: GlobalInstallProgress::Rust(progress),
                });
            })?;
            Ok(GlobalToolInstallation {
                tool: "rust".into(),
                version: asset.version,
                executable,
                provider: None,
                new_install: false,
            })
        }
        "uv" => {
            let asset = resolve_uv_runtime(
                tool.version.as_deref().unwrap_or("latest"),
                &Platform::host(),
            )?;
            let directory = data_directory.join("uv").join(&asset.version);
            let executable = install_uv_runtime_with_progress(&directory, &asset, |progress| {
                let _ = sender.send(GlobalInstallEvent::Progress {
                    index,
                    progress: GlobalInstallProgress::Uv(progress),
                });
            })?;
            Ok(GlobalToolInstallation {
                tool: "uv".into(),
                version: asset.version,
                executable,
                provider: None,
                new_install: false,
            })
        }
        "zig" => {
            let asset = resolve_zig_runtime(
                tool.version.as_deref().unwrap_or("latest"),
                &Platform::host(),
            )?;
            let directory = data_directory.join("zig").join(&asset.version);
            let executable = install_zig_runtime_with_progress(&directory, &asset, |progress| {
                let _ = sender.send(GlobalInstallEvent::Progress {
                    index,
                    progress: GlobalInstallProgress::Zig(progress),
                });
            })?;
            Ok(GlobalToolInstallation {
                tool: "zig".into(),
                version: asset.version,
                executable,
                provider: None,
                new_install: false,
            })
        }
        _ => Err(Diagnostic::new(
            DiagnosticCategory::Internal,
            "NEO701",
            format!(
                "unsupported global installer reached worker for {}",
                tool.tool
            ),
        )),
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn install_one_global_provider(
    index: usize,
    tool: &GlobalToolRequest,
    declaration: &ToolDeclaration,
    sender: &mpsc::Sender<GlobalInstallEvent>,
    cancellation: &AtomicBool,
    scope: GlobalScope,
) -> Result<GlobalToolInstallation, Diagnostic> {
    if cancellation.load(Ordering::Acquire) {
        return Err(global_install_cancelled());
    }
    let storage = global_tool_storage(scope)?;
    let configured_document = if tool.version.is_none() {
        global_tool_config_path(scope)
            .ok()
            .and_then(|path| read_global_tool_document(&path).ok())
    } else {
        None
    };
    let effective_version = tool.version.clone().or_else(|| {
        configured_document
            .as_ref()
            .and_then(|document| configured_global_version(document, &tool.tool).ok())
    });
    let configured_lock_path = configured_document.as_ref().and_then(|document| {
        global_provider_record(document, &tool.tool)
            .and_then(|record| record.get("lock_path"))
            .and_then(toml::Value::as_str)
            .map(PathBuf::from)
    });
    let lock_identity = GlobalToolRequest {
        tool: tool.tool.clone(),
        version: effective_version.clone(),
        declaration: tool.declaration.clone(),
    };
    let lock_path = match configured_lock_path {
        Some(path) => {
            let locks_root = global_tool_data_root(scope)?.join("locks");
            if !path.starts_with(&locks_root) || !safe_global_lock_name(&path) {
                return Err(global_key_diagnostic(format!(
                    "global provider lock path is outside nenv data: {}",
                    path.display()
                )));
            }
            path
        }
        None => global_provider_lock_path(scope, &lock_identity)?,
    };
    let requested_version = effective_version.as_deref();
    let already_installed;

    // A complete global lock is an offline capability record.  Use it before
    // provider resolution so repeating an exact request cannot touch the
    // network merely to rediscover metadata.
    if requested_version.is_some() && lock_path.is_file() {
        let candidate = read_lockfile(&lock_path)?;
        neoenv_installer::tools::reject_unimplemented_cargo_install(
            std::slice::from_ref(declaration),
            &candidate,
        )?;
        if global_lock_reusable_for_request(
            declaration,
            &candidate,
            tool.tool.as_str(),
            requested_version.unwrap_or_default(),
        ) {
            let states = tool_states_in(&storage, &candidate);
            already_installed = states.first().is_some_and(|state| state.installed);
            let installed = install_locked_tools_in(&storage, &candidate)?;
            let result = provider_installation_result(
                tool,
                &candidate,
                installed,
                &lock_path,
                !already_installed,
            )?;
            if cancellation.load(Ordering::Acquire) {
                return Err(global_install_cancelled());
            }
            let _ = sender.send(GlobalInstallEvent::Progress {
                index,
                progress: GlobalInstallProgress::Provider(if already_installed {
                    GlobalProviderProgress::AlreadyInstalled
                } else {
                    GlobalProviderProgress::Installing
                }),
            });
            return Ok(result);
        }
    }

    // Keep the complete provider pipeline in the shared installer crate.  The
    // CLI only constructs the global declaration and supplies storage; it does
    // not resolve metadata, download bytes, verify digests, or extract files.
    let plan = resolve_tools(std::slice::from_ref(declaration), &Platform::host())?;
    let _ = sender.send(GlobalInstallEvent::Progress {
        index,
        progress: GlobalInstallProgress::Provider(GlobalProviderProgress::Resolved),
    });
    if cancellation.load(Ordering::Acquire) {
        return Err(global_install_cancelled());
    }
    let lock_preexisted = lock_path.is_file();
    let lock_parent = lock_path.parent().ok_or_else(|| {
        Diagnostic::new(
            DiagnosticCategory::Runtime,
            "NEO522",
            "global provider lock has no parent directory",
        )
    })?;
    fs::create_dir_all(lock_parent).map_err(|error| {
        Diagnostic::new(
            DiagnosticCategory::Runtime,
            "NEO522",
            "failed to prepare global provider lock directory",
        )
        .with_cause(error)
    })?;
    // Verify and install against a staged lock. Keep the selected lock untouched
    // until the new installation has completed successfully.
    let staged_directory = tempfile::tempdir_in(lock_parent).map_err(|error| {
        Diagnostic::new(
            DiagnosticCategory::Runtime,
            "NEO522",
            "failed to stage global provider lock",
        )
        .with_cause(error)
    })?;
    let staged_lock_path = staged_directory.path().join(neoenv_core::names::LOCKFILE);
    let previous_directory = staged_directory.path().join("previous");
    fs::create_dir(&previous_directory).map_err(|error| {
        Diagnostic::new(
            DiagnosticCategory::Runtime,
            "NEO522",
            "failed to stage previous global provider lock",
        )
        .with_cause(error)
    })?;
    let previous_lock_path = previous_directory.join(neoenv_core::names::LOCKFILE);
    if lock_preexisted {
        fs::copy(&lock_path, &previous_lock_path).map_err(|error| {
            Diagnostic::new(
                DiagnosticCategory::Runtime,
                "NEO522",
                "failed to preserve existing global provider lock while staging",
            )
            .with_cause(error)
        })?;
        fs::copy(&previous_lock_path, &staged_lock_path).map_err(|error| {
            Diagnostic::new(
                DiagnosticCategory::Runtime,
                "NEO522",
                "failed to stage existing global provider lock",
            )
            .with_cause(error)
        })?;
    }
    write_lockfile(&staged_lock_path, &plan)?;
    let verified = verify_lockfile(&staged_lock_path, &plan)?;
    let root = storage.install_directory().join(&verified.tools[0].sha256);
    let root_preexisted = root.exists();
    let _ = sender.send(GlobalInstallEvent::Progress {
        index,
        progress: GlobalInstallProgress::Provider(GlobalProviderProgress::Installing),
    });
    let was_installed = tool_states_in(&storage, &verified)
        .first()
        .is_some_and(|state| state.installed);
    let installed = match install_locked_tools_in(&storage, &verified) {
        Ok(installed) => installed,
        Err(error) => {
            if !root_preexisted {
                let _ = fs::remove_dir_all(&root);
            }
            return Err(error);
        }
    };
    if cancellation.load(Ordering::Acquire) {
        if !root_preexisted {
            let _ = fs::remove_dir_all(&root);
        }
        return Err(global_install_cancelled());
    }
    let result =
        provider_installation_result(tool, &verified, installed, &lock_path, !was_installed)?;
    if cancellation.load(Ordering::Acquire) {
        if !root_preexisted {
            let _ = fs::remove_dir_all(&root);
        }
        return Err(global_install_cancelled());
    }
    if let Err(error) = write_lockfile(&lock_path, &plan) {
        if !root_preexisted {
            let _ = fs::remove_dir_all(&root);
        }
        return Err(error);
    }
    Ok(result)
}

pub(super) fn global_lock_reusable_for_request(
    declaration: &ToolDeclaration,
    candidate: &neoenv_core::tools::ToolLockfile,
    tool_id: &str,
    requested_version: &str,
) -> bool {
    let [locked] = candidate.tools.as_slice() else {
        return false;
    };
    if locked.id != tool_id || locked.resolved_version != requested_version {
        return false;
    }
    match declaration.provider {
        ToolProvider::GithubRelease => declaration.github_release.as_ref().is_some_and(|github| {
            let override_ =
                neoenv_core::tools::select_platform_override(declaration, &locked.platform)
                    .ok()
                    .flatten();
            let expected_sha256 = override_
                .and_then(|override_| override_.sha256.as_deref())
                .or(declaration.sha256.as_deref());
            let effective_asset = override_
                .and_then(|override_| override_.asset.as_deref())
                .or(github.asset.as_deref());
            let effective_grep = override_
                .and_then(|override_| override_.grep.as_deref())
                .or(github.grep.as_deref());
            let locked_filename = locked.url.rsplit('/').next().unwrap_or_default();
            let selected_locked_asset = neoenv_core::tools::select_github_asset(
                &[neoenv_core::tools::GithubReleaseAsset {
                    id: locked.provenance.asset_id.unwrap_or_default(),
                    name: locked_filename.to_owned(),
                    url: locked.url.clone(),
                }],
                effective_asset,
                effective_grep,
                &locked.platform,
                tool_id,
            )
            .is_ok();
            locked.provenance.provider == "github-release"
                && locked.provenance.repository.as_deref() == Some(github.repository.as_str())
                && expected_sha256.is_none_or(|digest| {
                    locked.sha256 == digest && locked.verification.sha256 == digest
                })
                && (effective_asset.is_none() && effective_grep.is_none() || selected_locked_asset)
                && locked.provenance.declaration_sha256.as_deref()
                    == Some(
                        neoenv_core::tools::github_declaration_fingerprint(declaration, github)
                            .as_str(),
                    )
        }),
        ToolProvider::Aqua => declaration.aqua.as_ref().is_some_and(|aqua| {
            locked.provenance.provider == "aqua"
                && locked.provenance.registry_endpoint.as_deref()
                    == neoenv_core::tools::canonical_http_url(&aqua.endpoint)
                        .ok()
                        .as_deref()
                && locked.provenance.registry_revision.as_deref()
                    == Some(aqua.registry_revision.as_str())
                && locked.provenance.manifest_sha256.as_deref()
                    == Some(aqua.manifest_sha256.as_str())
                && locked.provenance.package.as_deref() == Some(aqua.package.as_str())
        }),
        _ => true,
    }
}

pub(super) fn provider_installation_result(
    tool: &GlobalToolRequest,
    lockfile: &neoenv_core::tools::ToolLockfile,
    installed: Vec<neoenv_installer::tools::InstalledTool>,
    lock_path: &Path,
    new_install: bool,
) -> Result<GlobalToolInstallation, Diagnostic> {
    let locked = lockfile.tools.first().ok_or_else(|| {
        Diagnostic::new(
            DiagnosticCategory::Internal,
            "NEO701",
            format!("global provider {} lock contains no tool", tool.tool),
        )
    })?;
    let installed = installed.into_iter().next().ok_or_else(|| {
        Diagnostic::new(
            DiagnosticCategory::Internal,
            "NEO701",
            format!("global provider {} was not installed", tool.tool),
        )
    })?;
    let binary = installed.bin_dir.join(
        locked
            .binaries
            .first()
            .map_or(installed.id.as_str(), String::as_str),
    );
    let install_path = installed
        .bin_dir
        .parent()
        .map_or_else(|| installed.bin_dir.clone(), Path::to_path_buf);
    Ok(GlobalToolInstallation {
        tool: tool.tool.clone(),
        version: locked.resolved_version.clone(),
        executable: binary,
        provider: Some(GlobalProviderInstallation {
            resolved_version: locked.resolved_version.clone(),
            sha256: locked.sha256.clone(),
            source: locked.url.clone(),
            resolver: locked.resolver.clone(),
            immutable_id: locked.provenance.immutable_id.clone(),
            install_path,
            lock_path: lock_path.to_owned(),
            binaries: locked.binaries.clone(),
        }),
        new_install,
    })
}

pub(super) fn tool_label(tool: &GlobalToolRequest) -> String {
    format!(
        "{}@{}",
        tool.tool,
        tool.version.as_deref().unwrap_or("latest")
    )
}

pub(super) fn print_global_download_progress(
    index: usize,
    total: usize,
    tool: &GlobalToolRequest,
    received: u64,
    size: Option<u64>,
    last_step: &mut Option<u8>,
) {
    let Some(size) = size.filter(|size| *size > 0) else {
        if last_step.is_none() {
            println!(
                "[{}/{}] [....................] downloading {}",
                index + 1,
                total,
                tool_label(tool),
            );
            *last_step = Some(0);
        }
        return;
    };
    let percentage = received.saturating_mul(100).min(size.saturating_mul(100)) / size;
    // `percentage` is bounded to 0..=100 immediately above. The fallback is
    // defensive rather than panic at the progress-reporting boundary.
    let step = u8::try_from(percentage / 5).unwrap_or(20);
    if *last_step == Some(step) {
        return;
    }
    let filled = usize::from(step);
    let bar = format!("{}{}", "#".repeat(filled), ".".repeat(20 - filled));
    println!(
        "[{}/{}] [{bar}] {:>3}% downloading {}",
        index + 1,
        total,
        percentage,
        tool_label(tool),
    );
    *last_step = Some(step);
}

pub(super) fn mark_global_native_install(
    data_directory: &Path,
    tool: &str,
    version: &str,
) -> Result<(), Diagnostic> {
    let root = data_directory.join(tool).join(version);
    let marker = root.join(GLOBAL_OWNERSHIP_MARKER);
    fs::write(&marker, format!("{tool}\n{version}\n")).map_err(|error| {
        Diagnostic::new(
            DiagnosticCategory::Runtime,
            "NEO522",
            format!(
                "failed to record nenv ownership for {}: {error}",
                root.display()
            ),
        )
    })
}

pub(super) fn cleanup_new_global_installations(
    installations: &[GlobalToolInstallation],
    scope: GlobalScope,
) {
    let Ok(data_root) = global_tool_data_root(scope) else {
        return;
    };
    let tools_root = data_root.join("tools");
    for installation in installations {
        if !installation.new_install {
            continue;
        }
        if let Some(provider) = &installation.provider {
            let path = provider.install_path.as_path();
            if path.starts_with(&tools_root) && path != tools_root {
                let _ = remove_global_path(path);
            }
        } else {
            let path = tools_root
                .join(&installation.tool)
                .join(&installation.version);
            if path.starts_with(&tools_root) {
                let _ = remove_global_path(&path);
            }
        }
    }
}

/// Publishes all selected global versions in one atomic configuration write.
/// Install roots are already staged by their providers; a failure before this
/// point therefore cannot change the active global selection.
pub(super) fn record_global_tools(
    installations: &[GlobalToolInstallation],
    cancellation: &AtomicBool,
    scope: GlobalScope,
) -> Result<(), Diagnostic> {
    if scope == GlobalScope::System {
        return Err(system_mutation_disabled_diagnostic());
    }
    let path = global_tool_config_path(scope)?;
    record_global_tools_at(&path, installations, cancellation)
}

// The locked read/modify/write transaction stays auditable.
#[allow(clippy::too_many_lines)]
fn validate_config_file_for_write(path: &Path) -> Result<(), Diagnostic> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            Ok(())
        }
        Ok(_) => Err(Diagnostic::new(
            DiagnosticCategory::Runtime,
            "NEO522",
            format!(
                "global configuration {} is not a regular file (a directory, symlink, or special file is not accepted)",
                path.display()
            ),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Diagnostic::new(
            DiagnosticCategory::Runtime,
            "NEO522",
            format!(
                "failed to inspect global configuration {}: {error}",
                path.display()
            ),
        )),
    }
}

#[allow(clippy::too_many_lines)] // The locked read/modify/write transaction stays auditable.
pub(super) fn record_global_tools_at(
    path: &Path,
    installations: &[GlobalToolInstallation],
    cancellation: &AtomicBool,
) -> Result<(), Diagnostic> {
    if cancellation.load(Ordering::Acquire) {
        return Err(global_install_cancelled());
    }
    validate_config_file_for_write(path)?;
    let parent = path.parent().ok_or_else(|| {
        Diagnostic::new(
            DiagnosticCategory::Internal,
            "NEO701",
            "global configuration path has no parent directory",
        )
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        Diagnostic::new(
            DiagnosticCategory::Runtime,
            "NEO522",
            format!("failed to create {}: {error}", parent.display()),
        )
    })?;
    let state = state_file::lock(path).map_err(|error| state_file_diagnostic(path, error))?;
    let input = match state.read_to_string() {
        Ok(input) => input,
        Err(error) if error.is_not_found() => String::new(),
        Err(error) => return Err(state_file_diagnostic(path, error)),
    };
    if cancellation.load(Ordering::Acquire) {
        return Err(global_install_cancelled());
    }
    let mut document = if input.trim().is_empty() {
        toml::Value::Table(toml::map::Map::new())
    } else {
        toml::from_str::<toml::Value>(&input).map_err(|error| {
            Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO103",
                format!(
                    "invalid nenv global configuration {}: {error}",
                    path.display()
                ),
            )
        })?
    };
    let root = document.as_table_mut().ok_or_else(|| {
        Diagnostic::new(
            DiagnosticCategory::Validation,
            "NEO103",
            "nenv global configuration must be a TOML table",
        )
    })?;
    root.insert("format_version".into(), toml::Value::Integer(1));
    let global = root
        .entry("global")
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .ok_or_else(|| {
            Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO103",
                "global must be a TOML table",
            )
        })?;
    let tools = global
        .entry("tools")
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .ok_or_else(|| {
            Diagnostic::new(
                DiagnosticCategory::Validation,
                "NEO103",
                "global.tools must be a TOML table",
            )
        })?;
    for installation in installations {
        tools.insert(
            installation.tool.clone(),
            toml::Value::String(installation.version.clone()),
        );
    }
    if installations
        .iter()
        .any(|installation| installation.provider.is_some())
    {
        let providers = global
            .entry("providers")
            .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
            .as_table_mut()
            .ok_or_else(|| {
                Diagnostic::new(
                    DiagnosticCategory::Validation,
                    "NEO103",
                    "global.providers must be a TOML table",
                )
            })?;
        for installation in installations {
            let Some(provider) = &installation.provider else {
                continue;
            };
            let mut fields = toml::map::Map::new();
            fields.insert(
                "resolved_version".into(),
                toml::Value::String(provider.resolved_version.clone()),
            );
            fields.insert(
                "version".into(),
                toml::Value::String(provider.resolved_version.clone()),
            );
            fields.insert(
                "sha256".into(),
                toml::Value::String(provider.sha256.clone()),
            );
            fields.insert(
                "digest".into(),
                toml::Value::String(provider.sha256.clone()),
            );
            fields.insert(
                "source".into(),
                toml::Value::String(provider.source.clone()),
            );
            fields.insert(
                "resolver".into(),
                toml::Value::String(provider.resolver.clone()),
            );
            fields.insert(
                "immutable_id".into(),
                toml::Value::String(provider.immutable_id.clone()),
            );
            fields.insert(
                "install_path".into(),
                toml::Value::String(provider.install_path.display().to_string()),
            );
            fields.insert(
                "lock_path".into(),
                toml::Value::String(provider.lock_path.display().to_string()),
            );
            fields.insert(
                "binaries".into(),
                toml::Value::Array(
                    provider
                        .binaries
                        .iter()
                        .cloned()
                        .map(toml::Value::String)
                        .collect(),
                ),
            );
            providers.insert(installation.tool.clone(), toml::Value::Table(fields));
        }
    }
    if cancellation.load(Ordering::Acquire) {
        return Err(global_install_cancelled());
    }
    let output = toml::to_string_pretty(&document).map_err(|error| {
        Diagnostic::new(DiagnosticCategory::Internal, "NEO701", error.to_string())
    })?;
    if output == input {
        return Ok(());
    }
    if cancellation.load(Ordering::Acquire) {
        return Err(global_install_cancelled());
    }
    state
        .write(output.as_bytes())
        .map_err(|error| state_file_diagnostic(path, error))
}

pub(super) fn global_tool_and_version(value: &str) -> Result<(&str, Option<&str>), Diagnostic> {
    let (tool, version) = split_global_key_version(value)?;
    if version.is_some_and(|version| {
        version == "."
            || version == ".."
            || version.contains(['/', '\\'])
            || version.chars().any(char::is_control)
    }) {
        return Err(global_key_diagnostic(format!(
            "invalid tool version in `{value}`: versions cannot contain paths or control characters"
        )));
    }
    if tool.contains(':') {
        // Reuse the same key grammar as `use -g`, without resolving a
        // provider or requiring endpoint environment variables for lifecycle
        // inspection/removal.
        let lower = tool.to_ascii_lowercase();
        if lower.starts_with("github:")
            || lower.starts_with("https://")
            || lower.starts_with("http://")
        {
            return Err(global_key_diagnostic(format!(
                "invalid global tool key `{tool}`: use gh:owner/repo for a GitHub release"
            )));
        }
        let (provider, package) = tool
            .split_once(':')
            .ok_or_else(|| global_key_diagnostic(format!("invalid global tool key `{tool}`")))?;
        reject_unpinnable_global_provider(provider, tool)?;
        if !matches!(
            provider.to_ascii_lowercase().as_str(),
            "gh" | "npm" | "dotnet" | "gem"
        ) {
            return Err(global_key_diagnostic(format!(
                "unknown global tool provider prefix `{provider}`"
            )));
        }
        if provider.eq_ignore_ascii_case("gh") {
            validate_github_global_repository(package, tool)?;
        } else {
            validate_global_package(package, tool)?;
        }
        Ok((tool, version))
    } else {
        validate_tool_name(tool)?;
        Ok((canonical_global_runtime_name(tool), version))
    }
}

pub(super) fn read_global_tool_document(path: &Path) -> Result<toml::Value, Diagnostic> {
    let input = read_text_file(path, &ResourceBudget::default()).map_err(|error| {
        Diagnostic::new(
            DiagnosticCategory::Runtime,
            "NEO522",
            format!("failed to read {}: {error}", path.display()),
        )
    })?;
    toml::from_str(&input).map_err(|error| {
        Diagnostic::new(
            DiagnosticCategory::Validation,
            "NEO103",
            format!(
                "invalid nenv global configuration {}: {error}",
                path.display()
            ),
        )
    })
}

pub(super) fn global_table(
    document: &toml::Value,
) -> Result<&toml::map::Map<String, toml::Value>, Diagnostic> {
    document
        .get("global")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| {
            Diagnostic::new(
                DiagnosticCategory::NotFound,
                "NEO521",
                "no global tools are configured",
            )
        })
}

pub(super) fn global_tools_table(
    document: &toml::Value,
) -> Result<&toml::map::Map<String, toml::Value>, Diagnostic> {
    global_table(document)?
        .get("tools")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| {
            Diagnostic::new(
                DiagnosticCategory::NotFound,
                "NEO521",
                "no global tools are configured",
            )
        })
}

pub(super) fn configured_global_version(
    document: &toml::Value,
    tool: &str,
) -> Result<String, Diagnostic> {
    global_tools_table(document)?
        .get(tool)
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            Diagnostic::new(
                DiagnosticCategory::NotFound,
                "NEO521",
                format!("global tool is not configured: {tool}"),
            )
        })
}

pub(super) fn global_provider_record<'a>(
    document: &'a toml::Value,
    key: &str,
) -> Option<&'a toml::map::Map<String, toml::Value>> {
    document
        .get("global")
        .and_then(toml::Value::as_table)
        .and_then(|global| global.get("providers"))
        .and_then(toml::Value::as_table)
        .and_then(|providers| providers.get(key))
        .and_then(toml::Value::as_table)
}

pub(super) fn remove_global_path(path: &Path) -> Result<(), Diagnostic> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(Diagnostic::new(
                DiagnosticCategory::Runtime,
                "NEO522",
                format!("failed to inspect {}: {error}", path.display()),
            ));
        }
    };
    if metadata.file_type().is_symlink() || metadata.file_type().is_file() {
        fs::remove_file(path).map_err(|error| {
            Diagnostic::new(
                DiagnosticCategory::Runtime,
                "NEO522",
                format!("failed to remove {}: {error}", path.display()),
            )
        })
    } else if metadata.file_type().is_dir() {
        fs::remove_dir_all(path).map_err(|error| {
            Diagnostic::new(
                DiagnosticCategory::Runtime,
                "NEO522",
                format!("failed to remove {}: {error}", path.display()),
            )
        })
    } else {
        Ok(())
    }
}

pub(super) fn write_locked_state(
    state: &LockedStateFile,
    contents: &str,
) -> Result<(), Diagnostic> {
    state
        .write(contents.as_bytes())
        .map_err(|error| state_file_diagnostic(state.path(), error))
}

pub(super) fn state_file_diagnostic(path: &Path, error: StateFileError) -> Diagnostic {
    let message = match &error {
        StateFileError::Parent { .. } => {
            format!("cannot determine parent directory for {}", path.display())
        }
        StateFileError::Inspect { source, .. } => {
            format!("cannot inspect {}: {source}", path.display())
        }
        StateFileError::UnsafePath { .. } => {
            format!(
                "refusing to replace unsafe configuration path {}",
                path.display()
            )
        }
        StateFileError::Lock { source, .. } => {
            format!(
                "failed to lock configuration path {}: {source}",
                path.display()
            )
        }
        StateFileError::CreateTemporary { source, .. } => format!(
            "failed to create temporary configuration beside {}: {source}",
            path.display()
        ),
        StateFileError::WriteTemporary { source, .. } => format!(
            "failed to write temporary configuration for {}: {source}",
            path.display()
        ),
        StateFileError::Publish { source, .. } => {
            format!("failed to publish {}: {source}", path.display())
        }
        StateFileError::Read { source, .. } => {
            format!("failed to read {}: {source}", path.display())
        }
    };
    Diagnostic::new(DiagnosticCategory::Runtime, "NEO522", message).with_cause(error)
}
