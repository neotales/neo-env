//! Provider clients that resolve a planned artifact to a real download,
//! reading credentials only from the process environment.

use super::{
    AquaRegistryAsset, AquaRegistryManifest, BudgetReader, Command, DIGEST_ALGORITHMS, Deserialize,
    Diagnostic, Digest, Engine, GithubReleaseAsset, GithubReleaseMetadata, HashSet, NpmBinary,
    NpmRegistryPackage, Ordering, Path, Platform, Read, ResourceBudget, ResourceLimit,
    RubyGemsRegistryPackage, STANDARD, Sha256, Sha512, TEMP_SEQUENCE, ToolDeclaration, ToolPlan,
    ToolPlanError, ToolProvider, Write, allows_latest_resolution, canonical_http_url, fs,
    http_error, http_policy, io, plan_aqua_registry, plan_cargo_crate, plan_dotnet_tool,
    plan_error, plan_github_release, plan_go_module, plan_npm_registry, plan_ruby_gems, plan_tools,
    preserve_budget_error, runtime_error, runtime_error_with_cause, runtime_io,
    select_github_asset, select_platform_override,
};

/// Resolves provider metadata for an unlocked plan. Tokens are read only from
/// the process environment and are intentionally absent from plans and locks.
///
/// # Errors
///
/// Returns a validation or runtime diagnostic when a provider cannot resolve
/// the exact declared artifact and checksum.
pub fn resolve_tools(
    declarations: &[ToolDeclaration],
    platform: &Platform,
) -> Result<ToolPlan, Diagnostic> {
    let mut ids = HashSet::with_capacity(declarations.len());
    let mut tools = Vec::with_capacity(declarations.len());
    for declaration in declarations {
        if !ids.insert(&declaration.id) {
            return Err(plan_error(&ToolPlanError::DuplicateToolId {
                id: declaration.id.clone(),
            }));
        }
        // Before the dispatch, so it covers every provider. The two planners that
        // checked it themselves covered only `github-release` and
        // `explicit-url`; `aqua` and the four registry providers installed
        // `declaration.binaries` at the archive root, which is exactly what
        // refusing `binpath` is for.
        neoenv_core::tools::reject_binary_layout(declaration)
            .map_err(|error| plan_error(&error))?;
        let plan = match declaration.provider {
            ToolProvider::GithubRelease => resolve_github_release(declaration, platform),
            ToolProvider::Aqua => resolve_aqua_registry(declaration, platform),
            ToolProvider::Npm => resolve_npm_registry(declaration, platform),
            ToolProvider::DotnetTool => resolve_dotnet_tool(declaration, platform),
            ToolProvider::GoModule => resolve_go_module(declaration, platform),
            ToolProvider::RubyGems => resolve_ruby_gems(declaration, platform),
            ToolProvider::Cargo => {
                plan_cargo_crate(declaration, platform).map(|tool| ToolPlan { tools: vec![tool] })
            }
            // Reported by name rather than routed to `plan_tools`, which would
            // treat the declaration as a bare URL and try to fetch `url` --
            // empty -- instead of saying the provider has no resolver.
            ToolProvider::GitlabRelease => resolve_gitlab_release(declaration, platform),
            ToolProvider::ExplicitUrl | ToolProvider::Extension(_) => {
                plan_tools(std::slice::from_ref(declaration), platform)
            }
        }
        .map_err(|error| plan_error(&error))?;
        tools.extend(plan.tools);
    }
    Ok(ToolPlan { tools })
}

#[derive(Deserialize)]
struct GitlabReleaseResponse {
    tag_name: String,
    assets: GitlabAssets,
}

#[derive(Deserialize)]
struct GitlabAssets {
    links: Vec<GitlabAsset>,
}

#[derive(Deserialize)]
struct GitlabAsset {
    name: String,
    url: String,
}

/// Resolves a pinned GitLab release through the v4 release API.
///
/// The API adapter is fixture-tested against the documented response shape;
/// live GitLab behavior is not part of the offline test suite.
pub(super) fn resolve_gitlab_release(
    declaration: &ToolDeclaration,
    platform: &Platform,
) -> Result<ToolPlan, ToolPlanError> {
    let gitlab =
        declaration
            .gitlab_release
            .as_ref()
            .ok_or_else(|| ToolPlanError::UnsupportedProvider {
                id: declaration.id.clone(),
                provider: ToolProvider::GitlabRelease.name().to_owned(),
            })?;
    let host = gitlab.host.trim_end_matches('/');
    if host.is_empty()
        || gitlab.namespace.is_empty()
        || gitlab.project.is_empty()
        || declaration.version.eq_ignore_ascii_case("latest")
        || !declaration
            .sha256
            .as_deref()
            .is_some_and(neoenv_core::tools::is_sha256)
    {
        return Err(ToolPlanError::UnpinnedRegistry {
            id: declaration.id.clone(),
        });
    }
    let base =
        std::env::var("NEOENV_GITLAB_API_URL").unwrap_or_else(|_| format!("https://{host}/api/v4"));
    resolve_gitlab_release_at(declaration, platform, &base)
}

pub(super) fn resolve_gitlab_release_at(
    declaration: &ToolDeclaration,
    platform: &Platform,
    base: &str,
) -> Result<ToolPlan, ToolPlanError> {
    let gitlab =
        declaration
            .gitlab_release
            .as_ref()
            .ok_or_else(|| ToolPlanError::UnsupportedProvider {
                id: declaration.id.clone(),
                provider: ToolProvider::GitlabRelease.name().to_owned(),
            })?;
    let project = url_encode(&format!("{}/{}", gitlab.namespace, gitlab.project));
    let tag = url_encode(&declaration.version);
    let endpoint = format!(
        "{}/projects/{project}/releases/{tag}",
        base.trim_end_matches('/')
    );
    canonical_http_url(base).map_err(|_| ToolPlanError::UnpinnedRegistry {
        id: declaration.id.clone(),
    })?;
    let body = get_metadata(&endpoint).map_err(|error| {
        preserve_budget_error(
            &declaration.id,
            error,
            ToolPlanError::MissingAsset {
                id: declaration.id.clone(),
                platform: platform.clone(),
            },
        )
    })?;
    let release: GitlabReleaseResponse =
        serde_json::from_str(&body).map_err(|_| ToolPlanError::MissingAsset {
            id: declaration.id.clone(),
            platform: platform.clone(),
        })?;
    if release.tag_name != declaration.version {
        return Err(ToolPlanError::UnpinnedRegistry {
            id: declaration.id.clone(),
        });
    }
    let mut names = HashSet::with_capacity(release.assets.links.len());
    if release
        .assets
        .links
        .iter()
        .any(|asset| asset.name.is_empty() || !names.insert(asset.name.as_str()))
    {
        return Err(ToolPlanError::AmbiguousAsset {
            id: declaration.id.clone(),
            platform: platform.clone(),
        });
    }
    let metadata = GithubReleaseMetadata {
        id: stable_numeric_id(&release.tag_name),
        tag: release.tag_name,
        assets: release
            .assets
            .links
            .into_iter()
            .enumerate()
            .map(|(index, asset)| GithubReleaseAsset {
                id: u64::try_from(index + 1).unwrap_or(u64::MAX),
                name: asset.name,
                url: asset.url,
            })
            .collect(),
    };
    let synthetic = neoenv_core::tools::GithubReleaseDeclaration {
        repository: format!("{}/{}", gitlab.namespace, gitlab.project),
        asset: Some(gitlab.asset.clone()),
        checksum_asset: None,
        grep: gitlab.grep.clone(),
        prerelease: false,
        rename: None,
    };
    let mut normalized = declaration.clone();
    normalized.provider = ToolProvider::GithubRelease;
    normalized.github_release = Some(synthetic);
    normalized.gitlab_release = None;
    let mut plan = plan_resolved_github_release(
        &normalized,
        platform,
        &metadata,
        normalized.github_release.as_ref().unwrap(),
    )?;
    let planned = plan
        .tools
        .first_mut()
        .ok_or_else(|| ToolPlanError::MissingAsset {
            id: declaration.id.clone(),
            platform: platform.clone(),
        })?;
    ToolProvider::GitlabRelease
        .name()
        .clone_into(&mut planned.provenance.provider);
    planned.provenance.authentication = ToolProvider::GitlabRelease.authentication_policy();
    Ok(plan)
}

fn stable_numeric_id(value: &str) -> u64 {
    value
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3)
        })
        .max(1)
}

#[derive(Deserialize)]
pub(super) struct GoDownload {
    #[serde(rename = "Version")]
    version: Option<String>,
    #[serde(rename = "Zip")]
    zip: String,
    #[serde(rename = "Sum")]
    sum: String,
}

pub(super) fn resolve_go_module(
    declaration: &ToolDeclaration,
    platform: &Platform,
) -> Result<ToolPlan, ToolPlanError> {
    let go = declaration
        .go_module
        .as_ref()
        .ok_or_else(|| ToolPlanError::InvalidGoModule {
            id: declaration.id.clone(),
        })?;
    let endpoint =
        canonical_http_url(&go.endpoint).map_err(|_| ToolPlanError::InvalidGoModule {
            id: declaration.id.clone(),
        })?;
    let root = std::env::temp_dir().join(format!(
        "neoenv-go-resolve-{}-{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).map_err(|_| ToolPlanError::InvalidGoModule {
        id: declaration.id.clone(),
    })?;
    let result = (|| {
        fs::write(
            root.join("go.mod"),
            format!(
                "module {}\n\ngo 1.18\n\nrequire {} {}\n",
                neoenv_core::names::GO_RESOLVE_MODULE,
                go.module,
                declaration.version
            ),
        )
        .map_err(|_| ToolPlanError::InvalidGoModule {
            id: declaration.id.clone(),
        })?;
        fs::write(
            root.join("go.sum"),
            format!("{} {}\n", go.module, go.go_sum),
        )
        .map_err(|_| ToolPlanError::InvalidGoModule {
            id: declaration.id.clone(),
        })?;
        let output = go_command(&root, &endpoint)
            .args([
                "mod",
                "download",
                "-json",
                &format!("{}@{}", go.module, declaration.version),
            ])
            .output()
            .map_err(|_| ToolPlanError::InvalidGoModule {
                id: declaration.id.clone(),
            })?;
        if !output.status.success() {
            return Err(ToolPlanError::InvalidGoChecksum {
                id: declaration.id.clone(),
            });
        }
        let download: GoDownload = serde_json::from_slice(&output.stdout).map_err(|_| {
            ToolPlanError::InvalidGoChecksum {
                id: declaration.id.clone(),
            }
        })?;
        let digest = sha256_file(
            Path::new(&download.zip),
            ResourceBudget::default().artifact_bytes,
        )
        .map_err(|error| {
            preserve_budget_error(
                &declaration.id,
                error,
                ToolPlanError::InvalidGoChecksum {
                    id: declaration.id.clone(),
                },
            )
        })?;
        let mut normalized = declaration.clone();
        if normalized.version == "latest" && allows_latest_resolution(&normalized) {
            normalized.version =
                download
                    .version
                    .clone()
                    .ok_or_else(|| ToolPlanError::InvalidGoModule {
                        id: normalized.id.clone(),
                    })?;
        }
        plan_go_module(&normalized, platform, digest, &download.sum)
    })();
    let _ = fs::remove_dir_all(&root);
    result.map(|tool| ToolPlan { tools: vec![tool] })
}

pub(super) fn go_command(root: &Path, endpoint: &str) -> Command {
    let mut command = Command::new("go");
    command
        .current_dir(root)
        .env("GOPATH", root.join("gopath"))
        .env("GOMODCACHE", root.join("modcache"))
        .env("GOPROXY", endpoint)
        .env("GONOPROXY", "")
        .env("GONOSUMDB", "*")
        .env("GOPRIVATE", "")
        .env("GOSUMDB", "off")
        .env("GOAUTH", "off");
    command
}

pub(super) fn resolve_dotnet_tool(
    declaration: &ToolDeclaration,
    platform: &Platform,
) -> Result<ToolPlan, ToolPlanError> {
    let mut normalized = declaration.clone();
    if normalized.version == "latest" && allows_latest_resolution(&normalized) {
        let endpoint = normalized
            .dotnet_tool
            .as_ref()
            .map(|tool| tool.endpoint.as_str())
            .ok_or_else(|| ToolPlanError::InvalidDotnetTool {
                id: normalized.id.clone(),
            })?;
        let endpoint =
            canonical_http_url(endpoint).map_err(|_| ToolPlanError::InvalidDotnetTool {
                id: normalized.id.clone(),
            })?;
        let package = normalized
            .dotnet_tool
            .as_ref()
            .map(|tool| tool.package.to_ascii_lowercase())
            .ok_or_else(|| ToolPlanError::InvalidDotnetTool {
                id: normalized.id.clone(),
            })?;
        let index_url = format!("{}/{}/index.json", endpoint.trim_end_matches('/'), package);
        let index: serde_json::Value =
            serde_json::from_str(&get_metadata(&index_url).map_err(|error| {
                preserve_budget_error(
                    &normalized.id,
                    error,
                    ToolPlanError::MissingAsset {
                        id: normalized.id.clone(),
                        platform: platform.clone(),
                    },
                )
            })?)
            .map_err(|_| ToolPlanError::InvalidDotnetTool {
                id: normalized.id.clone(),
            })?;
        let version = index
            .get("versions")
            .and_then(serde_json::Value::as_array)
            .and_then(|versions| versions.iter().filter_map(serde_json::Value::as_str).max())
            .ok_or_else(|| ToolPlanError::MissingAsset {
                id: normalized.id.clone(),
                platform: platform.clone(),
            })?;
        normalized.version = version.to_owned();
    }
    let dotnet =
        normalized
            .dotnet_tool
            .as_ref()
            .ok_or_else(|| ToolPlanError::InvalidDotnetTool {
                id: normalized.id.clone(),
            })?;
    let endpoint =
        canonical_http_url(&dotnet.endpoint).map_err(|_| ToolPlanError::InvalidDotnetTool {
            id: normalized.id.clone(),
        })?;
    let package = dotnet.package.to_ascii_lowercase();
    let version = normalized.version.to_ascii_lowercase();
    let package_url = format!(
        "{}/{package}/{version}/{package}.{version}.nupkg",
        endpoint.trim_end_matches('/')
    );
    let expected = get_metadata(&format!("{package_url}.sha512")).map_err(|error| {
        preserve_budget_error(
            &normalized.id,
            error,
            ToolPlanError::InvalidDotnetIntegrity {
                id: normalized.id.clone(),
            },
        )
    })?;
    let expected = format!("sha512-{}", expected.trim());
    let artifact = get_npm_bytes(&package_url).map_err(|error| {
        preserve_budget_error(
            &normalized.id,
            error,
            ToolPlanError::MissingAsset {
                id: normalized.id.clone(),
                platform: platform.clone(),
            },
        )
    })?;
    if !verify_npm_integrity(&artifact, &expected) {
        return Err(ToolPlanError::InvalidDotnetIntegrity {
            id: normalized.id.clone(),
        });
    }
    Ok(ToolPlan {
        tools: vec![plan_dotnet_tool(
            &normalized,
            platform,
            hex_digest(&artifact.sha256),
            expected,
        )?],
    })
}

pub(super) fn resolve_npm_registry(
    declaration: &ToolDeclaration,
    platform: &Platform,
) -> Result<ToolPlan, ToolPlanError> {
    let npm = declaration
        .npm
        .as_ref()
        .ok_or_else(|| ToolPlanError::InvalidNpmPackage {
            id: declaration.id.clone(),
        })?;
    if let Some(manager) = &npm.manager {
        let name = match manager.name {
            neoenv_core::tools::NpmManagerName::Bun => "bun",
            neoenv_core::tools::NpmManagerName::Pnpm => "pnpm",
        };
        return Err(ToolPlanError::UnsupportedProvider {
            id: declaration.id.clone(),
            provider: format!(
                "{name}@{} manager install is not wired; refusing direct-tarball fallback",
                manager.version
            ),
        });
    }
    let endpoint =
        canonical_http_url(&npm.endpoint).map_err(|_| ToolPlanError::InvalidNpmPackage {
            id: declaration.id.clone(),
        })?;
    let metadata_url = format!(
        "{}/{}",
        endpoint.trim_end_matches('/'),
        npm_package_path(&npm.package).ok_or_else(|| ToolPlanError::InvalidNpmPackage {
            id: declaration.id.clone()
        })?
    );
    let metadata: serde_json::Value =
        serde_json::from_str(&get_npm_metadata(&metadata_url).map_err(|error| {
            preserve_budget_error(
                &declaration.id,
                error,
                ToolPlanError::InvalidNpmPackage {
                    id: declaration.id.clone(),
                },
            )
        })?)
        .map_err(|_| ToolPlanError::InvalidNpmPackage {
            id: declaration.id.clone(),
        })?;
    let requested_version =
        if declaration.version == "latest" && allows_latest_resolution(declaration) {
            metadata
                .get("dist-tags")
                .and_then(|tags| tags.get("latest"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| ToolPlanError::MissingAsset {
                    id: declaration.id.clone(),
                    platform: platform.clone(),
                })?
        } else {
            declaration.version.as_str()
        };
    let version = metadata
        .get("versions")
        .and_then(|versions| versions.get(requested_version))
        .ok_or_else(|| ToolPlanError::MissingAsset {
            id: declaration.id.clone(),
            platform: platform.clone(),
        })?;
    let package = npm_package_from_metadata(&npm.package, version).ok_or_else(|| {
        ToolPlanError::InvalidNpmPackage {
            id: declaration.id.clone(),
        }
    })?;
    let tarball = get_npm_bytes(&package.tarball).map_err(|error| {
        preserve_budget_error(
            &declaration.id,
            error,
            ToolPlanError::MissingAsset {
                id: declaration.id.clone(),
                platform: platform.clone(),
            },
        )
    })?;
    if !verify_npm_integrity(&tarball, &package.integrity) {
        return Err(ToolPlanError::InvalidNpmIntegrity {
            id: declaration.id.clone(),
        });
    }
    let mut normalized = declaration.clone();
    normalized.version.clone_from(&package.version);
    Ok(ToolPlan {
        tools: vec![plan_npm_registry(
            &normalized,
            platform,
            &package,
            hex_digest(&tarball.sha256),
        )?],
    })
}

pub(super) fn resolve_ruby_gems(
    declaration: &ToolDeclaration,
    platform: &Platform,
) -> Result<ToolPlan, ToolPlanError> {
    let ruby = declaration
        .ruby_gems
        .as_ref()
        .ok_or_else(|| ToolPlanError::InvalidRubyGem {
            id: declaration.id.clone(),
        })?;
    let endpoint =
        canonical_http_url(&ruby.endpoint).map_err(|_| ToolPlanError::InvalidRubyGem {
            id: declaration.id.clone(),
        })?;
    let metadata_url = format!(
        "{}/api/v1/versions/{}.json",
        endpoint.trim_end_matches('/'),
        ruby.gem
    );
    let metadata: serde_json::Value =
        serde_json::from_str(&get_metadata(&metadata_url).map_err(|error| {
            preserve_budget_error(
                &declaration.id,
                error,
                ToolPlanError::InvalidRubyGem {
                    id: declaration.id.clone(),
                },
            )
        })?)
        .map_err(|_| ToolPlanError::InvalidRubyGem {
            id: declaration.id.clone(),
        })?;
    let latest = declaration.version == "latest" && allows_latest_resolution(declaration);
    let package = if latest {
        metadata.as_array().and_then(|versions| {
            versions
                .iter()
                .filter_map(|entry| {
                    let version = entry.get("number")?.as_str()?;
                    Some(RubyGemsRegistryPackage {
                        gem: entry.get("name")?.as_str()?.into(),
                        version: version.into(),
                        platform: entry.get("platform")?.as_str()?.into(),
                        sha256: entry.get("sha")?.as_str()?.into(),
                    })
                })
                // The newest gem, by version precedence. Byte order reported
                // `4.10.0` as older than `4.9.0`, so installing `latest` reached for
                // a gem from before the previous major. RubyGems versions are
                // `x.y.z` with optional pre-release suffixes, which is what the
                // comparator implements.
                .max_by(|left, right| {
                    neoenv_core::version::compare_versions(&left.version, &right.version)
                })
        })
    } else {
        // Preserve the original exact-version selection semantics: the first
        // complete registry entry wins, including its platform variant.
        metadata.as_array().and_then(|versions| {
            versions.iter().find_map(|entry| {
                let version = entry.get("number")?.as_str()?;
                if version != declaration.version {
                    return None;
                }
                Some(RubyGemsRegistryPackage {
                    gem: entry.get("name")?.as_str()?.into(),
                    version: version.into(),
                    platform: entry.get("platform")?.as_str()?.into(),
                    sha256: entry.get("sha")?.as_str()?.into(),
                })
            })
        })
    }
    .ok_or_else(|| ToolPlanError::MissingAsset {
        id: declaration.id.clone(),
        platform: platform.clone(),
    })?;
    let mut normalized = declaration.clone();
    normalized.version.clone_from(&package.version);
    let planned = plan_ruby_gems(&normalized, platform, &package)?;
    let archive = get_npm_bytes(&planned.url).map_err(|error| {
        preserve_budget_error(
            &declaration.id,
            error,
            ToolPlanError::MissingAsset {
                id: declaration.id.clone(),
                platform: platform.clone(),
            },
        )
    })?;
    if hex_digest(&archive.sha256) != package.sha256 {
        return Err(ToolPlanError::InvalidRubyGem {
            id: declaration.id.clone(),
        });
    }
    Ok(ToolPlan {
        tools: vec![planned],
    })
}

pub(super) fn npm_package_path(package: &str) -> Option<String> {
    if package.is_empty()
        || package.contains(['?', '#', '\\'])
        || package
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return None;
    }
    Some(package.replace('/', "%2f"))
}

pub(super) fn npm_package_from_metadata(
    package: &str,
    value: &serde_json::Value,
) -> Option<NpmRegistryPackage> {
    let dist = value.get("dist")?;
    let bins = match value.get("bin")? {
        serde_json::Value::String(path) => vec![NpmBinary {
            name: package.rsplit('/').next()?.into(),
            path: path.clone(),
        }],
        serde_json::Value::Object(values) => values
            .iter()
            .map(|(name, path)| {
                Some(NpmBinary {
                    name: name.clone(),
                    path: path.as_str()?.into(),
                })
            })
            .collect::<Option<Vec<_>>>()?,
        _ => return None,
    };
    Some(NpmRegistryPackage {
        package: value.get("name")?.as_str()?.into(),
        version: value.get("version")?.as_str()?.into(),
        tarball: dist.get("tarball")?.as_str()?.into(),
        integrity: dist.get("integrity")?.as_str()?.into(),
        binaries: bins,
    })
}

pub(super) fn npm_bins_from_package_json(
    package: &str,
    value: &serde_json::Value,
) -> Option<Vec<NpmBinary>> {
    match value.get("bin")? {
        serde_json::Value::String(path) => Some(vec![NpmBinary {
            name: package.rsplit('/').next()?.into(),
            path: path.clone(),
        }]),
        serde_json::Value::Object(values) => values
            .iter()
            .map(|(name, path)| {
                Some(NpmBinary {
                    name: name.clone(),
                    path: path.as_str()?.into(),
                })
            })
            .collect(),
        _ => None,
    }
}

pub(super) fn get_npm_metadata(url: &str) -> Result<String, Diagnostic> {
    get_metadata(url)
}

pub(super) struct DownloadedArtifact {
    sha256: [u8; 32],
    sha512: [u8; 64],
}

pub(super) fn get_npm_bytes(url: &str) -> Result<DownloadedArtifact, Diagnostic> {
    let policy = http_policy()?;
    let response = policy
        .get(url)
        .map_err(|error| http_error(error, "failed to download package"))?;
    policy
        .validate_artifact_length(url, &response, ResourceBudget::default().artifact_bytes)
        .map_err(|error| http_error(error, "failed to download package"))?;
    let temporary = tempfile::tempdir()
        .map_err(|error| runtime_error(format!("failed to create package buffer: {error}")))?;
    let path = temporary.path().join("package");
    let mut input =
        policy.streaming_reader_limited(url, response, ResourceBudget::default().artifact_bytes);
    let mut output = fs::File::create(&path).map_err(|error| runtime_io(&path, &error))?;
    let mut sha256 = Sha256::new();
    let mut sha512 = Sha512::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = input
            .read(&mut buffer)
            .map_err(|error| runtime_error_with_cause(error.to_string(), error))?;
        if count == 0 {
            break;
        }
        sha256.update(&buffer[..count]);
        sha512.update(&buffer[..count]);
        output
            .write_all(&buffer[..count])
            .map_err(|error| runtime_io(&path, &error))?;
    }
    output
        .sync_all()
        .map_err(|error| runtime_io(&path, &error))?;
    let sha256 = sha256.finalize();
    let sha512 = sha512.finalize();
    Ok(DownloadedArtifact {
        sha256: sha256.into(),
        sha512: sha512.into(),
    })
}

pub(super) fn verify_npm_integrity(artifact: &DownloadedArtifact, integrity: &str) -> bool {
    integrity.split_whitespace().any(|entry| {
        let Some((algorithm, encoded)) = entry.split_once('-') else {
            return false;
        };
        let Ok(expected) = STANDARD.decode(encoded) else {
            return false;
        };
        match algorithm {
            "sha512" => expected.as_slice() == artifact.sha512.as_slice(),
            "sha256" => expected.as_slice() == artifact.sha256.as_slice(),
            _ => false,
        }
    })
}

// Asset and checksum selection stay together at the provider boundary.
#[allow(clippy::too_many_lines)]
/// Fetches a GitHub release's metadata and plans the tool from it.
///
/// # Errors
///
/// Returns a `ToolPlanError` when the release cannot be fetched or no asset matches.
pub(super) fn resolve_github_release(
    declaration: &ToolDeclaration,
    platform: &Platform,
) -> Result<ToolPlan, ToolPlanError> {
    let github =
        declaration
            .github_release
            .as_ref()
            .ok_or_else(|| ToolPlanError::MissingAsset {
                id: declaration.id.clone(),
                platform: platform.clone(),
            })?;
    let metadata = github_metadata_for(&github.repository, &declaration.version, github.prerelease)
        .map_err(|error| {
            preserve_budget_error(
                &declaration.id,
                error,
                ToolPlanError::MissingAsset {
                    id: declaration.id.clone(),
                    platform: platform.clone(),
                },
            )
        })?;
    // The branch itself is [`plan_resolved_github_release`], split out so it is
    // reachable without a network fetch: `global_request` is decided by the
    // declaration's *source path*, which a test can set directly.
    let github = github.clone();
    plan_resolved_github_release(declaration, platform, &metadata, &github)
}

/// Plans a GitHub tool from release metadata that has already been fetched.
///
/// The split exists because the two branches select assets by *different* rules, and
/// an earlier version computed the ordinary path's selection unconditionally, for
/// both. The global branch never consults a platform override, so that made
/// `tool install --global` fail with `MissingAsset` -- or
/// `AmbiguousPlatformOverride` -- on a declaration `tool plan` accepts, with the
/// error coming from a value that was then discarded.
///
/// # Errors
///
/// Returns a `ToolPlanError` when no asset matches under this branch's own rule, or
/// when the checksum sidecar cannot be resolved.
#[allow(clippy::too_many_lines)]
pub(super) fn plan_resolved_github_release(
    declaration: &ToolDeclaration,
    platform: &Platform,
    metadata: &GithubReleaseMetadata,
    github: &neoenv_core::tools::GithubReleaseDeclaration,
) -> Result<ToolPlan, ToolPlanError> {
    let global_request = allows_latest_resolution(declaration);
    // The planner's own selection, resolved against the release's real assets
    // rather than a second copy of the rule.
    //
    // This used to select the asset itself from the *declaration's* keys only,
    // which is how a per-platform `asset` or `grep` -- which the planner honors --
    // became invisible: `tool plan` named the override's artifact and `tool
    // install` fetched the declaration's. The two call sites disagreed about
    // which artifact a tool was, and the disagreement was silent until download.
    // Inside the `else`, and that is load-bearing rather than tidiness: the global
    // path only ever consults the *declaration's* own asset, so computing an
    // override-aware selection for it made `tool install --global` fail with
    // `MissingAsset` or `AmbiguousPlatformOverride` on a declaration the planner
    // accepts. The error came from the discarded half.
    let asset = if global_request {
        // The global path resolves `latest` to a concrete tag first, so the
        // asset is re-selected against the release it actually found.
        select_global_github_asset(&metadata.assets, github, platform, &declaration.id)?
    } else {
        // The same shared rule the planner uses, so `tool plan` and
        // `tool install` cannot name one artifact and fetch another.
        select_github_asset(
            &metadata.assets,
            effective_asset(declaration, github, platform)?,
            effective_grep(declaration, github, platform)?,
            platform,
            &declaration.id,
        )?
    };
    let checksum = if declaration.sha256.is_none() {
        // **A documented divergence in the accepting direction: the digest asset is
        // *discovered* here, and the reference has no digest concept at all.**
        // `SelectReleaseAsset` in `neobeard/neoenv` resolves one asset and stops;
        // there is no `checksum_asset`, and a release is expected to carry a declared
        // `checksum`. On the `global:` path this model instead *infers* which of the
        // release's assets carries the digest for the one it selected, by asking
        // `is_checksum_asset_name`. That means a `gh:` key with no `sha256:` and no
        // `checksum_asset:` can install here where the reference would refuse.
        //
        // It is a real feature difference, not an accident of naming, and it was
        // undocumented until a review asked where it came from. It is also the
        // reason `is_checksum_asset_name` is a separate narrow rule rather than the
        // shared sidecar test: the reference's refusal is not available to inherit,
        // so this path has to be conservative on its own terms.
        let checksum_asset = if global_request {
            select_global_github_checksum_asset(
                &metadata.assets,
                asset,
                github,
                platform,
                &declaration.id,
            )?
        } else {
            metadata
                .assets
                .iter()
                .find(|candidate| {
                    github
                        .checksum_asset
                        .as_ref()
                        .is_some_and(|name| name == &candidate.name)
                })
                .ok_or_else(|| ToolPlanError::MissingAsset {
                    id: declaration.id.clone(),
                    platform: platform.clone(),
                })?
        };
        let checksum_body = get_github_metadata(&checksum_asset.url).map_err(|error| {
            preserve_budget_error(
                &declaration.id,
                error,
                ToolPlanError::MissingAsset {
                    id: declaration.id.clone(),
                    platform: platform.clone(),
                },
            )
        })?;
        let digest = checksum_for_asset(&checksum_body, &asset.name)
            // A sidecar is also commonly formatted as only the digest.
            .or_else(|| {
                checksum_body
                    .split_whitespace()
                    .next()
                    .map(|digest| digest.strip_prefix("sha256:").unwrap_or(digest).to_owned())
                    .filter(|digest| neoenv_core::tools::is_sha256(digest))
            })
            .ok_or_else(|| {
                github_asset_selection_error(
                    &declaration.id,
                    platform,
                    &metadata.assets,
                    &format!(
                        "checksum asset `{}` did not contain a verifiable SHA-256 for `{}`",
                        checksum_asset.name, asset.name
                    ),
                )
            })?;
        Some(digest)
    } else {
        None
    };
    let normalized = if global_request {
        let mut normalized = declaration.clone();
        if let Some(github) = normalized.github_release.as_mut() {
            github.asset = Some(asset.name.clone());
            github.checksum_asset = None;
        }
        // Every override's `asset` and `grep` are cleared, for the same reason: the
        // global selection above consulted none of them, and the planner at the
        // end of this function reads them. Left in place they defeat the name just
        // resolved -- the plan re-selects an override's asset and fails, on a
        // declaration whose global selection succeeded. Clearing *all* of them
        // rather than the matching one also keeps the branch from having to resolve
        // which one matched, which it deliberately never needed to know: an
        // ambiguous set is not this branch's error to report.
        //
        // `url`, `sha256`, and `binaries` are untouched -- the planner applies
        // those on both branches, and they are not asset selectors.
        for override_ in &mut normalized.platforms {
            override_.asset = None;
            override_.grep = None;
        }
        // `latest` is useful for a global request, but the lock must still
        // contain the immutable release tag returned by the provider.
        normalized.version.clone_from(&metadata.tag);
        normalized
    } else {
        declaration.clone()
    };
    let mut planned = plan_github_release(&normalized, platform, metadata, checksum)?;
    planned.provenance.declaration_sha256 = Some(
        neoenv_core::tools::github_declaration_fingerprint(declaration, github),
    );
    Ok(ToolPlan {
        tools: vec![planned],
    })
}

/// The asset template in force on `platform`: a matching override's, else the
/// declaration's own.
///
/// The same field-by-field overlay the planner applies. Kept here because the
/// installer has to choose the asset *before* the plan exists, and a second copy
/// of the precedence is exactly how the two drifted apart once already.
pub(super) fn effective_asset<'a>(
    declaration: &'a ToolDeclaration,
    github: &'a neoenv_core::tools::GithubReleaseDeclaration,
    platform: &Platform,
) -> Result<Option<&'a str>, ToolPlanError> {
    let declared = select_platform_override(declaration, platform)?
        .and_then(|override_| override_.asset.as_deref());
    Ok(declared.or(github.asset.as_deref()))
}

/// The `grep` pattern in force on `platform`, by the same overlay.
pub(super) fn effective_grep<'a>(
    declaration: &'a ToolDeclaration,
    github: &'a neoenv_core::tools::GithubReleaseDeclaration,
    platform: &Platform,
) -> Result<Option<&'a str>, ToolPlanError> {
    let declared = select_platform_override(declaration, platform)?
        .and_then(|override_| override_.grep.as_deref());
    Ok(declared.or(github.grep.as_deref()))
}

/// The asset a `global:` request installs.
///
/// **Stricter than [`select_github_asset`] on ambiguity, and that is a deliberate
/// policy difference rather than a shared-rule failure.** `select_github_asset`
/// takes the *first* platform match, because a project-pinned request is
/// reproducible and the lock records which asset was chosen. The global path
/// refuses when a release publishes more than one, because there is no lock yet to
/// record the choice and guessing between a `.tar.gz` and a `.deb` for a
/// machine-wide install is the outcome this profile exists to avoid.
///
/// The *predicate* -- what counts as a platform match and what counts as an
/// artifact -- is shared outright (`github_asset_matches_host` delegates to the
/// planner's own `asset_matches_platform` and `is_release_artifact`), so the two
/// can never disagree about *which* assets are candidates. On that predicate they
/// differ in nothing. The *digest* half is a genuinely separate question and a
/// separate rule: see [`is_checksum_asset_name`], whose doc records the two ways
/// it disagrees with the planner's.
pub(super) fn select_global_github_asset<'a>(
    assets: &'a [GithubReleaseAsset],
    declaration: &neoenv_core::tools::GithubReleaseDeclaration,
    platform: &Platform,
    id: &str,
) -> Result<&'a GithubReleaseAsset, ToolPlanError> {
    if declaration.asset.is_some() || declaration.grep.is_some() {
        // A declared asset or `grep:` goes through the shared rule so the
        // global path and `tool plan` cannot name one artifact and install
        // another.
        return select_github_asset(
            assets,
            declaration.asset.as_deref(),
            declaration.grep.as_deref(),
            platform,
            id,
        );
    }
    let candidates = assets
        .iter()
        .filter(|asset| github_asset_matches_host(asset, platform))
        .collect::<Vec<_>>();
    match candidates.as_slice() {
        [asset] => Ok(*asset),
        [] => Err(github_asset_selection_error(
            id,
            platform,
            assets,
            &format!(
                "no platform binary or archive matched {}/{}",
                platform.os, platform.arch
            ),
        )),
        _ => Err(github_asset_selection_error(
            id,
            platform,
            assets,
            &format!(
                "multiple platform binaries or archives matched {}/{}",
                platform.os, platform.arch
            ),
        )),
    }
}

pub(super) fn select_global_github_checksum_asset<'a>(
    assets: &'a [GithubReleaseAsset],
    selected: &GithubReleaseAsset,
    declaration: &neoenv_core::tools::GithubReleaseDeclaration,
    platform: &Platform,
    id: &str,
) -> Result<&'a GithubReleaseAsset, ToolPlanError> {
    if let Some(name) = declaration
        .checksum_asset
        .as_deref()
        .filter(|name| !name.is_empty())
    {
        return assets
            .iter()
            .find(|candidate| candidate.id != selected.id && candidate.name == name)
            .ok_or_else(|| {
                github_asset_selection_error(
                    id,
                    platform,
                    assets,
                    "the configured checksum asset name was not found",
                )
            });
    }
    let candidates = assets
        .iter()
        .filter(|candidate| candidate.id != selected.id && is_checksum_asset_name(&candidate.name))
        .collect::<Vec<_>>();
    match candidates.as_slice() {
        [asset] => Ok(*asset),
        [] => Err(github_asset_selection_error(
            id,
            platform,
            assets,
            "no checksum asset was found; declare `sha256:` or `checksum_asset:` if \
             this release publishes its digest under a name not listed above",
        )),
        _ => Err(github_asset_selection_error(
            id,
            platform,
            assets,
            "multiple checksum assets were found; declare `checksum_asset:` with the \
             one to use, or the install will not guess between them",
        )),
    }
}

/// Whether an asset is the one this platform should install.
///
/// The artifact test is the *shared* rule, not a second list. It used to be this
/// function's own nine-entry suffix table, AND-ed with a negation of the shared
/// one, which meant every suffix added to core that this table did not have was
/// **unreachable on the global path**: a release of only
/// `tool_1.2.3_linux_amd64.deb` resolved under `select_github_asset` (so `tool
/// plan` and a project `tool install` named it) and then failed under
/// `select_global_github_asset` with "no platform binary or archive matched". Same
/// release, same `gh:` key, project-pinned versus `global:` -- and the two halves
/// of one provider, which is the least defensible place for a divergence to live.
///
pub(super) fn github_asset_matches_host(asset: &GithubReleaseAsset, platform: &Platform) -> bool {
    // Case is the shared rule's business, not this function's: `is_release_artifact`
    // lowercases internally, and the deleted local did not -- which is how the
    // `SHA256SUMS` branch ended up reachable from the planner and unreachable from
    // here, two callers of one rule classifying one asset two ways.
    //
    // **Both** halves shared, not just the artifact half. This function had its own
    // nine-entry suffix table *and* its own OS and architecture alias lists, and the
    // two halves of one provider disagreed in three ways at once: every suffix core
    // knew and this list did not was unreachable here, `mac` was missing from the
    // alias list so `tool-mac-amd64.tar.gz` resolved under `tool plan` and then
    // errored under `tool install --global`, and the architecture lists treated
    // `arm` and `x86` differently. Sharing only the artifact half left the same
    // defect in the other two quarters, which is the point: a partial
    // de-duplication of a predicate is the original defect with less of it removed.
    neoenv_core::tools::is_release_artifact(&asset.name)
        && neoenv_core::tools::asset_matches_platform(&asset.name, platform)
}

pub(super) fn github_asset_selection_error(
    id: &str,
    platform: &Platform,
    assets: &[GithubReleaseAsset],
    reason: &str,
) -> ToolPlanError {
    let mut names = assets
        .iter()
        .map(|asset| asset.name.clone())
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    ToolPlanError::AssetSelection {
        id: id.to_owned(),
        platform: platform.clone(),
        reason: reason.to_owned(),
        assets: names,
    }
}

/// An asset that can *carry a digest* for the artifact.
///
/// **A third classifier, and the two questions it answers are not the same
/// question.** An earlier version of this doc claimed it "differs from
/// `is_release_artifact`'s negation only in what to do with more than one". That
/// was false, and it was false in both directions at once:
///
/// - **Too narrow.** `md5sum`, `b2sum`, and `sha3sum` name no `checksum` and no
///   `sha256`/`sha512`, so a release whose only digest sibling is an `md5sum` file
///   was refused with "no checksum asset was found" -- a *missing* sidecar, on a
///   release that published one. `sha1` and `blake3` are missing the same way.
/// - **Too broad.** The test is a substring over the whole name, so
///   `checksum_asset` in a *tool's* name -- and a release that ships both
///   `checksums.txt` and `foo_linux_amd64.tar.gz.sha256` -- yields two candidates,
///   and the caller refuses with "multiple checksum assets were found".
///
/// Widening it to the planner's own sidecar rule is the obvious fix and is wrong
/// in the other direction: this function's one caller *requires exactly one*
/// candidate, and `GoReleaser` publishes `checksums.txt` **and** `*.sig` by
/// default, so a shared "anything that is not the artifact" rule makes every
/// cosign-signed release ambiguous. It was that refactor's regression, reverted
/// once already.
///
/// So it stays a separate rule. **And it is not a third spelling of the same
/// question** -- that was the other false claim here, and the review measured
/// fifteen names where it and the planner's `is_release_artifact` disagree. They
/// answer genuinely different questions, so some disagreement is correct:
///
/// - The planner asks "is this the *program*?". A sidecar that is not a digest --
///   a `.sig`, an `.spdx.json` -- is the artifact as far as it is concerned, and
///   excluding it is its job.
/// - This asks "does this *carry a digest*?", which is narrower in one direction (a
///   signature does not) and wider in another (a tool named `blake3` does not, but
///   a digest named `checksums` does).
///
/// The two are pinned together in one direction only, and the asymmetry is the
/// design: **every name this function calls a digest, core calls a sidecar.** A
/// name core calls the artifact and this one calls a digest is the defect class
/// behind both regressions, and a test walks real names asserting it.
///
/// The two *known* divergences from the planner are pinned by tests rather than
/// papered over: a declared `checksum_asset:` is honored by name here and by name
/// in the planner, and an *undeclared* one is resolved by first match in the
/// planner and by exactly-one here. A user who names the asset gets the same answer
/// on both paths, which is the case the ambiguity rule is protecting.
///
/// **A digest sidecar is never a program or a package**, and that is the first
/// thing this function checks. The list is `neoenv_core::tools::PROGRAM_EXTENSIONS`
/// -- the shared statement of the fact. The planner keeps a copy of the constant
/// next to `SIDECAR_EXTENSIONS` and deliberately does **not** apply the guard in
/// `is_release_artifact`; a mutation showed it dead there, because no member of
/// `SIDECAR_EXTENSIONS` is a packaging extension and no packaging name ends in
/// `sum`/`sums`. Read the comment on the constant before adding the guard back
/// "for symmetry": that is the specific mistake it records.
///
/// Three successive versions of this classifier each got the trade wrong in one
/// direction, and the last got it wrong twice in the commit that claimed to fix it:
///
/// 1. Substring-anywhere (`checksum`, `sha256`) missed `md5sum`.
/// 2. Adding `md5`, `blake`, `sha1`, and `sums` fixed the miss and started matching
///    *tool names* -- `md5tool_linux_x86_64.tar.gz` became a digest candidate and
///    the caller's exactly-one rule refused the install while offering another
///    platform's archive as a checksum.
/// 3. Narrowing the substring to a *token* fixed that, missed the `GoReleaser`
///    `*_sums` and `*.sums` spellings this file cites by name, and still let
///    `blake3_linux_x86_64.tar.gz` through because a project named after an
///    algorithm splits into a bare token.
///
/// The shape that separates all of them is not the name: every offending name ends
/// in `.tar.gz`, `.deb`, or `.zip`, and every real manifest ends in `sums`, `sum`,
/// an algorithm name, or `.txt`. One test on the last extension retires the whole
/// class, including names nobody has thought of yet.
///
/// The cost is that an unusual *packaging* extension would let a tool name through,
/// which is the safe direction: an over-match here becomes a refusal naming every
/// candidate, and an under-match becomes "no checksum asset was found" on a
/// release that published one.
pub(super) fn is_checksum_asset_name(name: &str) -> bool {
    let file = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();
    // **First, and it is what makes most of the below safe.** A tool named after a
    // hash is still a tool.
    if let Some((_, extension)) = file.rsplit_once('.')
        && neoenv_core::tools::PROGRAM_EXTENSIONS.contains(&extension)
    {
        return false;
    }
    let parts: Vec<&str> = file.split(['-', '_', '.']).collect();
    let trailing = parts.last().copied().unwrap_or(&file);

    // **Any part naming a signature makes the whole name a signature, not a digest.**
    // Checked before any marker test, because `gitea-1.27.3-linux-amd64.sha256.asc`
    // contains a bare `sha256` and would otherwise read as a digest -- 729 such
    // names in one release, every one from `go-gitea/gitea`. The file is a signature
    // *of* the digest, and counting it as the digest made the classifier contradict
    // the doc above it ("narrower in one direction: a signature does not"). mise
    // reaches the same place a different way: it *penalizes* `.asc` and `.sig` by
    // −100 rather than classifying them as checksums.
    //
    // Every part, not just the last: the gitea shapes are `*.sha256.asc` **and**
    // `*.sha256.sigstore.json`, and in the second the signature kind is
    // second-to-last. A last-part-only check passes the first and misses the second,
    // which is the same "I fixed the shape I tested" trap three times running.
    if parts.iter().any(|part| is_signature_kind(part)) {
        return false;
    }

    // **The guard is on the *last* part, not on the marker's position.** Two earlier
    // versions got this wrong in opposite directions and both shipped:
    //
    // - No guard: `md5sum_linux_amd64` and `blake3_linux_amd64` are *programs*, and
    //   a release shipping one alongside its `.tar.gz` was refused with the program
    //   listed as a checksum candidate.
    // - Guard on position (skip the leading part): `sha256sums.txt` is a digest --
    //   `prometheus/prometheus`, `prometheus/node_exporter`, `prometheus/alertmanager`,
    //   `prometheus/pushgateway`, `netdata/netdata` -- and the *leading* form
    //   stopped matching, so the install was refused with the file named as missing
    //   **in the same message that listed it as available**. mise's
    //   `CHECKSUM_PATTERNS` spells it `(?i)^sha256sums?\.txt$`.
    //
    // The discriminator is neither: **a marker counts unless the name goes on to
    // name a platform or a version.** `sha256sums.txt` ends in `txt` and
    // `foo_linux_amd64.sha256sum.txt` ends in `txt`; `md5sum_linux_amd64` ends in
    // `amd64`. One predicate, both directions.
    if is_platform_or_version_token(trailing) {
        return false;
    }

    // A marker anywhere else in the name: a bare algorithm
    // (`foo_linux_amd64.sha512`), one glued to `sum`/`sums`
    // (`foo_linux_amd64.sha256sum.txt`, `sha256sums.txt`, `sha256sums`).
    //
    // **A whole name that is a *bare algorithm* is a program.** `blake3` is a
    // plausible project name and is not a manifest, while `sha256sums` and
    // `checksums` are -- and all three are a single part, so the last-part
    // coordinate test above cannot separate them. The discriminator is whether the
    // name *conveys a checksum convention*: the `sums` manifest suffix, or one of
    // the checksum words. This also subsumes the coreutils-program check, since
    // `md5sum` is neither.
    //
    // Core reaches the same verdict differently, through a *list* rather than a
    // shape, because it has a case this shape cannot decide: `md5sum` and
    // `SHA256SUMS` are identical once lowercased. See
    // `COREOUTSUM_DIGEST_PROGRAMS` there, which is private to core and has its rows
    // in core's own test file.
    if parts.len() == 1 && !file.ends_with("sums") && !is_checksum_word(&file) {
        return false;
    }
    if parts.iter().any(|part| is_digest_marker(part)) {
        return true;
    }
    // **`checksum`/`checksums` needs a stricter guard than an algorithm does.** An
    // algorithm in any part is enough, because the last-part coordinate test above
    // already separates `sha256sums.txt` from `md5sum_linux_amd64`. A `checksums`
    // part is not: `mikefarah/yq` publishes `checksums`, `checksums-bsd`,
    // `checksums_hashes_order`, `checksums.bundle`, and `checksums-bsd.bundle`, and
    // the global path requires *exactly one* digest candidate -- so matching all
    // five refused a perfectly good release and offered `yq_linux_amd64` beside the
    // rest. The last part must be the word itself or a sidecar kind, which
    // recognizes `checksums` and `checksums.txt` and leaves the other four to both
    // halves alike.
    //
    // This is an **under-match on purpose**: one recognized candidate resolves the
    // release and five do not. The alternative is a refusal the user can only fix by
    // naming the file, and the refusal now tells them how.
    if parts.iter().any(|part| is_checksum_word(part))
        && (is_checksum_word(trailing)
            || neoenv_core::tools::SIDECAR_EXTENSIONS.contains(&trailing))
    {
        return true;
    }
    // GoReleaser's `checksum.name_template: "{{ .ArtifactName }}_sums"` output, which
    // is `foo_1.0.0_linux_amd64_sums` with no algorithm anywhere in the name, and
    // the dotted `foo_linux_amd64.sums`. The same rule as the planner's shape one.
    (trailing == "sums" || trailing == "sum") && file != trailing
}

/// Name parts that belong to a *release coordinate* rather than to a digest.
///
/// The last part of `md5sum_linux_amd64` is `amd64`, so the marker there is the
/// project name and the name is a program. The last part of `sha256sums.txt` is
/// `txt`, so the marker there is a manifest and the name is a digest. Neither
/// position nor the presence of an extension separates those, and each of the two
/// rules that tried failed on a real release.
fn is_platform_or_version_token(part: &str) -> bool {
    // **Two branches, not four.** The caller splits on `-`, `_`, and `.`, so a
    // `trailing` part can never contain a `.` and a "dotted version that survived
    // the split" is unreachable; and `is_empty` is subsumed, because
    // `"".chars().all(is_ascii_digit)` is vacuously true. Both were here, both were
    // provably dead, and a mutation removing either passed every test -- which is
    // what "provably dead" means and is the only reason to delete a branch rather
    // than leave it as a safety net. A branch no input can reach is not a safety
    // net; it is a claim about the code that a reader has to check.
    part.chars().all(|c| c.is_ascii_digit()) || PLATFORM_NAME_TOKENS.contains(&part)
}

/// Every OS and architecture spelling this project recognizes in an asset name, as
/// lowercase tokens. Derived from the reference's `runtime.GOOS`/`GOARCH` sets plus
/// the aliases [`neoenv_core::tools::platform_os_aliases`] adds, because the two must
/// agree about which token is a coordinate: a token this table misses lets a program
/// name read as a digest, which is the wrong-install direction.
///
/// **No test distinguishes one member from another, and that is deliberate.** The
/// guard's two failure modes are *both* loud refusals, never a wrong install:
///
/// - a **missing** token makes a program read as a digest, so the global path finds
///   two candidates and refuses;
/// - a **spurious** token makes a digest read as not-a-digest, so the release is
///   refused with "no checksum asset was found" — and the message now names the file
///   it could not recognize.
///
/// So a wrong member costs a diagnostic, not an install, and one row per *family*
/// (an OS token, an architecture token, a version token) is the right amount of
/// coverage for a closed vocabulary. Sixty rows would read as sixty independent
/// claims and test nothing extra. What the test *does* require is that all three
/// families are load-bearing, and removing any one family fails it.
const PLATFORM_NAME_TOKENS: &[&str] = &[
    // Operating systems.
    "linux",
    "darwin",
    "macos",
    "osx",
    "mac",
    "windows",
    "win",
    "freebsd",
    "openbsd",
    "netbsd",
    "dragonfly",
    "solaris",
    "illumos",
    "aix",
    "android",
    "ios",
    "wasm",
    "wasi",
    "plan9",
    "js",
    // Architectures.
    "x86_64",
    "amd64",
    "x64",
    "arm64",
    "aarch64",
    "arm",
    "armv5",
    "armv6",
    "armv7",
    "armv7l",
    "i386",
    "i486",
    "i586",
    "i686",
    "386",
    "x86",
    "ppc64",
    "ppc64le",
    "ppc",
    "s390x",
    "sparc",
    "sparc64",
    "riscv",
    "riscv64",
    "mips",
    "mips64",
    "mips64le",
    "mipsle",
    "loong64",
    "universal",
    "unknown",
    "musl",
    "gnu",
    "msvc",
];

/// Whether a name part is a signature or a public key: the file *signs* something,
/// and this function answers "does this carry a digest for the artifact", so a
/// signature of a digest is not one.
///
/// Read from a list rather than from the planner's `SIDECAR_EXTENSIONS`, because that
/// table also holds digests and manifests, and asking "is this a sidecar?" would
/// call `checksums.txt` a signature.
fn is_signature_kind(part: &str) -> bool {
    matches!(
        part,
        "sig"
            | "asc"
            | "gpg"
            | "gpgasc"
            | "minisig"
            | "p7s"
            | "sigstore"
            | "pub"
            | "pem"
            | "cert"
            | "cer"
            | "crt"
    )
}

/// Whether a name part is the word `checksum` or `checksums`, in either spelling
/// and either case. Split out because the two places that ask have to agree, and
/// the previous version had one of them write `*part == "checksum"` and the other
/// not.
fn is_checksum_word(part: &str) -> bool {
    part == "checksum" || part == "checksums"
}

/// Whether a name part is a manifest marker: a digest algorithm, or one glued to
/// `sum` or `sums`. The "glued" half is what keeps `cksum`, `b2sum`, and `shasum`
/// out -- the algorithm is still a list, and only the *reach* of the list changed
/// when the two-step strip-then-scan replaced reading a single token.
fn is_digest_marker(part: &str) -> bool {
    DIGEST_ALGORITHMS.contains(&part)
        || ["sums", "sum"].iter().any(|suffix| {
            part.strip_suffix(suffix)
                .is_some_and(|head| DIGEST_ALGORITHMS.contains(&head))
        })
}

pub(super) fn resolve_aqua_registry(
    declaration: &ToolDeclaration,
    platform: &Platform,
) -> Result<ToolPlan, ToolPlanError> {
    let aqua = declaration
        .aqua
        .as_ref()
        .ok_or_else(|| ToolPlanError::UnpinnedRegistry {
            id: declaration.id.clone(),
        })?;
    if !neoenv_core::tools::is_registry_revision(&aqua.registry_revision)
        || !neoenv_core::tools::is_sha256(&aqua.manifest_sha256)
        || !valid_aqua_package(&aqua.package)
    {
        return Err(ToolPlanError::UnpinnedRegistry {
            id: declaration.id.clone(),
        });
    }
    let endpoint =
        canonical_http_url(&aqua.endpoint).map_err(|_| ToolPlanError::UnpinnedRegistry {
            id: declaration.id.clone(),
        })?;
    let manifest_url = format!(
        "{}/{}/pkgs/{}/registry.yaml",
        endpoint.trim_end_matches('/'),
        aqua.registry_revision,
        aqua.package
    );
    let input = get_metadata(&manifest_url).map_err(|error| {
        preserve_budget_error(
            &declaration.id,
            error,
            ToolPlanError::MissingAsset {
                id: declaration.id.clone(),
                platform: platform.clone(),
            },
        )
    })?;
    if sha256(&input) != aqua.manifest_sha256 {
        return Err(ToolPlanError::UnpinnedRegistry {
            id: declaration.id.clone(),
        });
    }
    let manifest: StructuredAquaManifest =
        serde_yaml::from_str(&input).map_err(|_| ToolPlanError::MissingAsset {
            id: declaration.id.clone(),
            platform: platform.clone(),
        })?;
    let manifest = AquaRegistryManifest {
        package: manifest.package,
        assets: manifest
            .assets
            .into_iter()
            .map(|asset| AquaRegistryAsset {
                version: asset.version,
                platform: Platform::new(asset.os, asset.arch),
                url: asset.url,
                sha256: asset.sha256,
            })
            .collect(),
    };
    let mut normalized = declaration.clone();
    if normalized.version == "latest" && allows_latest_resolution(&normalized) {
        let version = manifest
            .assets
            .iter()
            .filter(|asset| asset.platform == *platform)
            .map(|asset| asset.version.as_str())
            .max()
            .ok_or_else(|| ToolPlanError::MissingAsset {
                id: normalized.id.clone(),
                platform: platform.clone(),
            })?;
        normalized.version = version.to_owned();
    }
    Ok(ToolPlan {
        tools: vec![plan_aqua_registry(&normalized, platform, &manifest)?],
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredAquaManifest {
    package: String,
    assets: Vec<StructuredAquaAsset>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StructuredAquaAsset {
    version: String,
    os: String,
    arch: String,
    url: String,
    sha256: String,
}

pub(super) fn first_github_api_base() -> String {
    [
        "NEOENV_GITHUB_API_URL",
        "GITHUB_API_URL",
        "NEOENV_GH_API_URL",
        "NEOENV_GITHUB_API_BASE",
    ]
    .iter()
    .find_map(|name| std::env::var(name).ok())
    .filter(|value| !value.trim().is_empty())
    .unwrap_or_else(|| "https://api.github.com".into())
}

pub(super) fn github_metadata_for(
    repository: &str,
    tag: &str,
    prerelease: bool,
) -> Result<GithubReleaseMetadata, Diagnostic> {
    if repository.split('/').count() != 2 || repository.split('/').any(str::is_empty) {
        return Err(runtime_error("GitHub repository must be owner/name"));
    }
    let base = first_github_api_base();
    github_metadata_at_for(&base, repository, tag, prerelease)
}

#[cfg(test)]
pub(super) fn github_metadata_at(
    base: &str,
    repository: &str,
    tag: &str,
) -> Result<GithubReleaseMetadata, Diagnostic> {
    github_metadata_at_for(base, repository, tag, false)
}

pub(super) fn github_metadata_at_for(
    base: &str,
    repository: &str,
    tag: &str,
    prerelease: bool,
) -> Result<GithubReleaseMetadata, Diagnostic> {
    if repository.split('/').count() != 2 || repository.split('/').any(str::is_empty) {
        return Err(runtime_error("GitHub repository must be owner/name"));
    }
    let latest = tag.eq_ignore_ascii_case("latest");
    let endpoint = if latest && prerelease {
        // `/releases/latest` excludes pre-releases by definition. An explicit
        // `pre`/`prerelease` request asks for the newest non-draft release in
        // creation order, which is the only way to see one through this API.
        format!(
            "{}/repos/{repository}/releases?per_page=20",
            base.trim_end_matches('/')
        )
    } else if latest {
        format!(
            "{}/repos/{repository}/releases/latest",
            base.trim_end_matches('/')
        )
    } else {
        format!(
            "{}/repos/{repository}/releases/tags/{}",
            base.trim_end_matches('/'),
            url_encode(tag)
        )
    };
    let fetched: serde_json::Value = serde_json::from_str(
        &get_github_metadata(&endpoint)
            .map_err(|error| runtime_error_with_cause(error.message.clone(), error))?,
    )
    .map_err(|error| runtime_error(format!("invalid GitHub release metadata: {error}")))?;
    let response = if latest && prerelease {
        fetched
            .as_array()
            .and_then(|releases| {
                releases
                    .iter()
                    .find(|release| release["draft"].as_bool() != Some(true))
            })
            .ok_or_else(|| runtime_error("GitHub has no non-draft release for this repository"))?
    } else {
        &fetched
    };
    let id = response["id"]
        .as_u64()
        .ok_or_else(|| runtime_error("GitHub release metadata has no numeric ID"))?;
    let tag = response["tag_name"]
        .as_str()
        .ok_or_else(|| runtime_error("GitHub release metadata has no tag"))?
        .to_owned();
    let assets = response["assets"]
        .as_array()
        .ok_or_else(|| runtime_error("GitHub release metadata has no assets"))?
        .iter()
        .map(|asset| {
            Ok(GithubReleaseAsset {
                id: asset["id"]
                    .as_u64()
                    .ok_or_else(|| runtime_error("GitHub asset has no numeric ID"))?,
                name: asset["name"]
                    .as_str()
                    .ok_or_else(|| runtime_error("GitHub asset has no name"))?
                    .to_owned(),
                url: asset["browser_download_url"]
                    .as_str()
                    .ok_or_else(|| runtime_error("GitHub asset has no download URL"))?
                    .to_owned(),
            })
        })
        .collect::<Result<Vec<_>, Diagnostic>>()?;
    Ok(GithubReleaseMetadata { id, tag, assets })
}

pub(super) fn get_github_metadata(url: &str) -> Result<String, Diagnostic> {
    let policy = http_policy()?;
    let token = ["NEOENV_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"]
        .iter()
        .find_map(|name| std::env::var(name).ok())
        .filter(|token| !token.is_empty());
    let response = token
        .map_or_else(
            || policy.get(url),
            |token| policy.get_with_header(url, "Authorization", &format!("Bearer {token}")),
        )
        .map_err(|error| http_error(error, "failed to resolve GitHub metadata"))?;
    policy
        .read_text(url, response)
        .map_err(|error| http_error(error, "failed to read GitHub metadata"))
}

/// Registry manifests never receive ambient credentials. Aqua registry access is
/// intentionally public-only; private registries need a separately designed adapter.
pub(super) fn get_metadata(url: &str) -> Result<String, Diagnostic> {
    let policy = http_policy()?;
    let response = policy
        .get(url)
        .map_err(|error| http_error(error, "failed to resolve registry metadata"))?;
    policy
        .read_text(url, response)
        .map_err(|error| http_error(error, "failed to read registry metadata"))
}

pub(super) fn valid_aqua_package(value: &str) -> bool {
    value.split('/').count() == 2
        && value.split('/').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
}

pub(super) fn sha256(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

pub(super) fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

pub(super) fn sha256_file(path: &Path, limit: u64) -> io::Result<String> {
    let file = fs::File::open(path)?;
    let mut reader = BudgetReader::new(file, ResourceLimit::Artifact, limit);
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(hex_digest(&digest.finalize()));
        }
        digest.update(&buffer[..count]);
    }
}

pub(super) fn checksum_for_asset(input: &str, asset_name: &str) -> Option<String> {
    input.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        let digest = parts.next()?;
        let name = parts.next()?.trim_start_matches('*');
        let digest = digest.strip_prefix("sha256:").unwrap_or(digest);
        (name == asset_name && neoenv_core::tools::is_sha256(digest)).then(|| digest.to_owned())
    })
}

pub(super) fn url_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                char::from(byte).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}
