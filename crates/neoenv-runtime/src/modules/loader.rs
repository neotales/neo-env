//! Module document loading: canonical containment, cycle and depth limits,
//! postorder composition, and the per-resolution parse cache that keeps a
//! shared document from being re-read for every package graph.

use super::tarball::{CachedTarball, TarballModule, cached_tarball_details};
use super::{
    Arc, Component, ConfigSource, Diagnostic, Digest, Format, HashMap, HashSet, ModuleImport, Path,
    PathBuf, Project, RemoteModule, ResourceBudget, Sha256, SourceSpan, TaskDefinition,
    TaskDotenvImport, TaskPackage, TaskPackageIdentity, UserDirectory, fs, imported_neoenv_error,
    io, io_error, is_remote, module_document, parse_project_with_profile, read_text_file,
    remote_error, user_directory, validation,
};
use crate::remote::{CachedModule, cached_module_details};
use crate::trust::Contributor;
use neoenv_config::sources::ModuleOrigin;

/// Resolves imports before their importing document. All paths are canonical and
/// must remain below `project_root`, including after symlink resolution.
///
/// # Errors
///
/// Returns a diagnostic for unsupported import sources, unreadable documents,
/// containment failures, parser failures, or cycles.
pub fn load_local_modules(
    project_root: &Path,
    source: &Path,
) -> Result<Vec<(ConfigSource, Project)>, Diagnostic> {
    load_local_modules_with_profile(
        project_root,
        source,
        neoenv_config::ConfigProfile::process_profile(),
    )
}

/// The profile-explicit form of [`load_local_modules`].
///
/// The unqualified form follows the process-wide profile, which is right for a
/// binary that parsed its arguments and wrong for a caller that was handed a
/// profile. Resolution itself never uses it: `resolve_sources` builds a
/// `ModuleLoader::with_profile` and drives that, so a project's own document and
/// its imports are always read the same way.
pub fn load_local_modules_with_profile(
    project_root: &Path,
    source: &Path,
    profile: neoenv_config::ConfigProfile,
) -> Result<Vec<(ConfigSource, Project)>, Diagnostic> {
    let mut loader = ModuleLoader::with_profile(project_root, profile)?;
    loader.load_local_modules(source)
}

/// A resolution-scoped cache for canonical module documents.
///
/// The cache stores the parsed document and its exact input separately from
/// the order-sensitive composed views. A document can therefore be imported
/// through several package graphs without being read and parsed again, while
/// selectors and namespaces still produce a fresh view for every occurrence.
pub(crate) struct ModuleLoader {
    root: PathBuf,
    /// Configuration dialect for every document this loader parses. Threaded
    /// through so an imported module is read the same way as its importer.
    profile: neoenv_config::ConfigProfile,
    documents: HashMap<(PathBuf, ModuleOrigin), Arc<ParsedModule>>,
    /// Every parsed remote document, keyed by its canonical cache path.
    ///
    /// A task package declared *by* remote content must keep that content's
    /// repository, commit, and checkout root even when its own reference is a
    /// relative path. The map is how the package resolver learns which remote
    /// document declared it without re-deriving identity from a path that
    /// merely happens to sit under `.neoenv`.
    remote_locations: HashMap<PathBuf, RemoteLocation>,
    /// Every document whose bytes contributed to the selected graph. Recorded
    /// once per document, from the exact bytes that were parsed, so the
    /// execution gate never reopens a mutable path to compute its identity.
    contributors: Vec<Contributor>,
    contributor_keys: HashSet<String>,
    #[cfg(test)]
    parsed_documents: usize,
}

/// The repository coordinates of a remote document.
///
/// `root` is the canonical extraction root, so a nested document's repository
/// relative path is computed from the same repository checkout rather than from
/// a cache path.
#[derive(Clone, Debug)]
struct RemoteLocation {
    repository: String,
    commit: String,
    relative_path: String,
    root: PathBuf,
}

impl RemoteLocation {
    fn child(&self, path: &Path) -> Result<Self, Diagnostic> {
        Ok(Self {
            repository: self.repository.clone(),
            commit: self.commit.clone(),
            relative_path: repository_relative_path(&self.root, path)?,
            root: self.root.clone(),
        })
    }
}

#[derive(Clone)]
struct ParsedModule {
    input: String,
    project: Project,
    source: ConfigSource,
    format: Format,
}

impl ModuleLoader {
    /// A loader that parses every document in `profile`.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the project root cannot be canonicalized.
    pub(crate) fn with_profile(
        project_root: &Path,
        profile: neoenv_config::ConfigProfile,
    ) -> Result<Self, Diagnostic> {
        let root =
            fs::canonicalize(project_root).map_err(|error| io_error(project_root, &error))?;
        Ok(Self {
            root,
            profile,
            documents: HashMap::new(),
            remote_locations: HashMap::new(),
            contributors: Vec::new(),
            contributor_keys: HashSet::new(),
            #[cfg(test)]
            parsed_documents: 0,
        })
    }

    /// The remote coordinates a document was read under, when it is remote
    /// content. `None` means the document is project-local.
    fn remote_location(&self, document: &Path) -> Option<&RemoteLocation> {
        self.remote_locations.get(document)
    }

    /// Records one contributing document exactly once.
    fn record(&mut self, contributor: Contributor) {
        if self.contributor_keys.insert(contributor.identity.key()) {
            self.contributors.push(contributor);
        }
    }

    /// Takes every contributing identity recorded so far.
    pub(crate) fn take_contributors(&mut self) -> Vec<Contributor> {
        self.contributor_keys.clear();
        std::mem::take(&mut self.contributors)
    }

    pub(crate) fn load_local_modules(
        &mut self,
        source: &Path,
    ) -> Result<Vec<(ConfigSource, Project)>, Diagnostic> {
        let source = fs::canonicalize(source).map_err(|error| io_error(source, &error))?;
        let root = self.root.clone();
        let mut loaded = Vec::new();
        let mut visiting = Vec::new();
        let mut budget = ModuleVisitBudget::default();
        visit(
            self,
            &root,
            &source,
            ModuleOrigin::Local,
            None,
            &mut visiting,
            &mut loaded,
            &mut budget,
            false,
        )?;
        Ok(loaded)
    }

    pub(crate) fn load_task_package_with_identity(
        &mut self,
        importing_source: &Path,
        package: &TaskPackage,
    ) -> Result<LoadedTaskPackage, Diagnostic> {
        let importing_source = fs::canonicalize(importing_source)
            .map_err(|error| io_error(importing_source, &error))?;
        // A package declared by remote content is remote content, even when
        // its own reference is a relative path. The declaring document's
        // repository, commit, and checkout root travel with the resolution.
        let declaring_remote = self.remote_location(&importing_source).cloned();
        let TaskPackageTarget {
            root,
            path,
            origin,
            location,
        } = task_package_target(
            &self.root,
            &importing_source,
            &package.from,
            declaring_remote.as_ref(),
        )?;
        // Remote content is not part of this project even when its immutable
        // cache happens to live below the project root. `external` is what
        // makes a package task ask for its own `execute` grant, so it is
        // decided from the origin the loader resolved, not from a path shape.
        let external_origin = origin == ModuleOrigin::Remote;
        let mut loaded = Vec::new();
        let mut visiting = Vec::new();
        let mut budget = ModuleVisitBudget::default();
        let exact_input = visit(
            self,
            &root,
            &path,
            origin,
            location.as_ref(),
            &mut visiting,
            &mut loaded,
            &mut budget,
            true,
        )?;
        let (source, mut project) = loaded.pop().ok_or_else(|| {
            validation("NEO620", "task package did not contain a document".into())
        })?;
        let package_tasks = std::mem::take(&mut project.tasks);
        for (_, imported) in loaded {
            project.tasks.extend(imported.tasks);
        }
        project.tasks.extend(package_tasks);
        for task in project.tasks.values_mut() {
            resolve_package_task_paths(&root, task)?;
        }
        let canonical_document =
            fs::canonicalize(source.path()).map_err(|error| io_error(source.path(), &error))?;
        let sha256 = format!("{:x}", Sha256::digest(exact_input.as_bytes()));
        let identity = TaskPackageIdentity {
            path: canonical_document.display().to_string(),
            sha256,
            export: package.task.clone(),
            root: root.clone(),
            external: external_origin || !canonical_document.starts_with(&self.root),
        };
        Ok(LoadedTaskPackage { project, identity })
    }

    #[cfg(test)]
    pub(crate) fn parsed_document_count(&self) -> usize {
        self.parsed_documents
    }

    fn document(
        &mut self,
        path: &Path,
        origin: ModuleOrigin,
        limits: &ResourceBudget,
        imported: bool,
    ) -> Result<Arc<ParsedModule>, Diagnostic> {
        let key = (path.to_owned(), origin);
        if let Some(document) = self.documents.get(&key) {
            if imported && document.format == Format::Neoenv {
                return Err(imported_neoenv_error(path));
            }
            return Ok(Arc::clone(document));
        }
        let input = read_text_file(path, limits).map_err(|error| io_error(path, &error))?;
        let format = Format::from_path(path)?;
        if imported && format == Format::Neoenv {
            return Err(imported_neoenv_error(path));
        }
        #[cfg(test)]
        {
            self.parsed_documents += 1;
        }
        let project =
            parse_project_with_profile(path, &input, Format::from_path(path)?, self.profile)?;
        let document = Arc::new(ParsedModule {
            input,
            project,
            source: ConfigSource::module_with_origin(path.to_owned(), origin),
            format,
        });
        self.documents.insert(key, Arc::clone(&document));
        Ok(document)
    }
}

/// Loads a local structured task package without treating it as an executable
/// runner. A package can be project-relative or a bare name resolved from the
/// project `neoenv/tasks` directory before the nenv user data directory.
///
/// Package imports are composed before their package document and are confined
/// to the selected package root after canonicalization.
///
/// # Errors
///
/// Returns a diagnostic for missing, invalid, cyclic, or escaping package
/// sources, or for an unreadable package document.
pub fn load_task_package(
    project_root: &Path,
    importing_source: &Path,
    package: &TaskPackage,
) -> Result<Project, Diagnostic> {
    Ok(load_task_package_with_identity(project_root, importing_source, package)?.project)
}

/// A package snapshot together with the canonical document identity used for
/// capability policy and user-facing provenance.
#[derive(Debug)]
pub(crate) struct LoadedTaskPackage {
    pub project: Project,
    pub identity: TaskPackageIdentity,
}

/// Loads a task package and hashes the exact selected document bytes used to
/// parse it. No network operation is reachable from task-package references.
pub(crate) fn load_task_package_with_identity(
    project_root: &Path,
    importing_source: &Path,
    package: &TaskPackage,
) -> Result<LoadedTaskPackage, Diagnostic> {
    load_task_package_with_profile(
        project_root,
        importing_source,
        package,
        neoenv_config::ConfigProfile::process_profile(),
    )
}

/// The profile-explicit form of [`load_task_package_with_identity`].
pub(crate) fn load_task_package_with_profile(
    project_root: &Path,
    importing_source: &Path,
    package: &TaskPackage,
    profile: neoenv_config::ConfigProfile,
) -> Result<LoadedTaskPackage, Diagnostic> {
    let mut loader = ModuleLoader::with_profile(project_root, profile)?;
    loader.load_task_package_with_identity(importing_source, package)
}

#[derive(Clone, Copy, Debug, Default)]
struct ModuleVisitBudget {
    limits: ResourceBudget,
    documents: usize,
}

#[allow(
    clippy::too_many_arguments,
    reason = "the graph walker passes each independent traversal input explicitly"
)]
fn visit(
    module_loader: &mut ModuleLoader,
    root: &Path,
    path: &Path,
    origin: ModuleOrigin,
    location: Option<&RemoteLocation>,
    visiting: &mut Vec<PathBuf>,
    loaded: &mut Vec<(ConfigSource, Project)>,
    budget: &mut ModuleVisitBudget,
    package_imports: bool,
) -> Result<String, Diagnostic> {
    // Check cycles before applying graph limits so an actual cycle is never
    // reported as a depth or document-count failure.
    if let Some(index) = visiting.iter().position(|item| item == path) {
        let mut trace = visiting[index..]
            .iter()
            .map(|item| item.display().to_string())
            .collect::<Vec<_>>();
        trace.push(path.display().to_string());
        return Err(validation(
            "NEO610",
            format!("local module import cycle: {}", trace.join(" -> ")),
        ));
    }
    let depth = visiting.len();
    if depth > budget.limits.module_import_depth {
        return Err(validation(
            "NEO627",
            format!(
                "module import depth limit exceeded: maximum depth is {}",
                budget.limits.module_import_depth
            ),
        ));
    }
    if budget.documents >= budget.limits.module_documents {
        return Err(validation(
            "NEO628",
            format!(
                "module document count limit exceeded: maximum documents is {}",
                budget.limits.module_documents
            ),
        ));
    }
    budget.documents += 1;
    if let Some(location) = location {
        module_loader
            .remote_locations
            .insert(path.to_owned(), location.clone());
    }
    let document = module_loader.document(path, origin, &budget.limits, !visiting.is_empty())?;
    let input = document.input.clone();
    let project = document.project.clone();
    let source = document.source.clone();
    let contributor = match location {
        Some(location) => Ok(Contributor::remote(
            &location.repository,
            &location.commit,
            &location.relative_path,
            &input,
        )),
        None => Contributor::local(path, &input),
    }
    .map_err(|error| validation("NEO631", error.to_string()))?;
    module_loader.record(contributor);
    visiting.push(path.to_owned());
    for import in &project.imports {
        let (imported, import_origin, import_location) = module_path(root, path, &import.from)?;
        // A local import inside remote content is still remote content. The
        // origin is inherited, never re-derived from the imported path.
        let child_origin = if origin == ModuleOrigin::Remote {
            ModuleOrigin::Remote
        } else {
            import_origin
        };
        // A local import inside a remote checkout is identified by the same
        // repository and commit, with its path relative to that checkout.
        let child_location = match (import_location, child_origin, location) {
            (Some(location), _, _) => Some(location),
            (None, ModuleOrigin::Remote, Some(parent)) => Some(parent.child(&imported)?),
            (None, _, _) => None,
        };
        if package_imports && !imported.starts_with(root) {
            return Err(validation(
                "NEO623",
                format!(
                    "task package import escapes its package root: {}",
                    import.from
                ),
            ));
        }
        visit(
            module_loader,
            root,
            &imported,
            child_origin,
            child_location.as_ref(),
            visiting,
            loaded,
            budget,
            package_imports,
        )?;
        if let Some((_, imported)) = loaded.last_mut() {
            select_tasks(imported, import)?;
        }
    }
    visiting.pop();
    loaded.push((source, project));
    Ok(input)
}

fn resolve_package_task_paths(root: &Path, task: &mut TaskDefinition) -> Result<(), Diagnostic> {
    let Some(action) = task.action.as_mut() else {
        return Ok(());
    };
    for dotenv in &mut action.dotenv {
        dotenv.path = resolve_task_dotenv(root, dotenv)?;
    }
    if action.source.is_some() {
        resolve_render_source(root, action)?;
    }
    if !action.files.is_empty() {
        // `tmpl` file specs and their values file are resolved by the runtime
        // against the declaring document; marking them package-relative keeps a
        // package's paths inside the package root. The provenance is kept
        // separately from `source_document` so a caller override can replace it.
        action.files_from_package = true;
        action.files_document = action.source_document.clone();
    }
    if action.with.contains_key("values") {
        action.values_from_package = true;
        action.values_document = action.source_document.clone();
    }
    if action.destination.is_some() {
        resolve_render_destination(root, action)?;
    }
    if action.cwd.is_some() {
        resolve_task_working_directory(root, action)?;
    }
    Ok(())
}

fn resolve_task_dotenv(root: &Path, dotenv: &TaskDotenvImport) -> Result<String, Diagnostic> {
    let document = declaration_document(root, &dotenv.source, "dotenv")?;
    let declared = relative_declared_path(&dotenv.path, "task dotenv path")?;
    let candidate = document
        .parent()
        .unwrap_or(root)
        .join(declared)
        .canonicalize();
    match candidate {
        Ok(path) => {
            ensure_contained(root, &path, "task dotenv path")?;
            Ok(path.display().to_string())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = document
                .parent()
                .unwrap_or(root)
                .join(declared)
                .parent()
                .ok_or_else(|| {
                    validation("NEO629", "task dotenv path has no parent directory".into())
                })?
                .canonicalize()
                .map_err(|error| {
                    validation(
                        "NEO629",
                        format!(
                            "failed to resolve task dotenv path {}: {error}",
                            declared.display()
                        ),
                    )
                })?;
            ensure_contained(root, &parent, "task dotenv directory")?;
            let name = declared.file_name().ok_or_else(|| {
                validation("NEO629", "task dotenv path must name a file".to_owned())
            })?;
            Ok(parent.join(name).display().to_string())
        }
        Err(error) => Err(validation(
            "NEO629",
            format!(
                "failed to resolve task dotenv path {}: {error}",
                declared.display()
            ),
        )),
    }
}

fn resolve_render_source(
    root: &Path,
    action: &mut neoenv_core::tasks::TaskAction,
) -> Result<(), Diagnostic> {
    let source = action
        .source
        .as_deref()
        .ok_or_else(|| validation("NEO629", "render action has no source".into()))?;
    let document = declaration_document(
        root,
        action.source_document.as_ref().ok_or_else(|| {
            validation("NEO629", "render source has no declaring document".into())
        })?,
        "render source",
    )?;
    let declared = relative_declared_path(source, "render source")?;
    let resolved = document
        .parent()
        .unwrap_or(root)
        .join(declared)
        .canonicalize()
        .map_err(|error| {
            validation(
                "NEO629",
                format!(
                    "failed to resolve render source {}: {error}",
                    declared.display()
                ),
            )
        })?;
    ensure_contained(root, &resolved, "render source")?;
    if !resolved.is_file() {
        return Err(validation(
            "NEO629",
            format!("render source is not a file: {}", resolved.display()),
        ));
    }
    action.source = Some(resolved.display().to_string());
    action.source_from_package = true;
    Ok(())
}

fn resolve_render_destination(
    root: &Path,
    action: &mut neoenv_core::tasks::TaskAction,
) -> Result<(), Diagnostic> {
    let destination = action
        .destination
        .as_deref()
        .ok_or_else(|| validation("NEO629", "render action has no destination".into()))?;
    let document = declaration_document(
        root,
        action.destination_document.as_ref().ok_or_else(|| {
            validation(
                "NEO629",
                "render destination has no declaring document".into(),
            )
        })?,
        "render destination",
    )?;
    let declared = relative_declared_path(destination, "render destination")?;
    let candidate = document.parent().unwrap_or(root).join(declared);
    let parent = candidate.parent().ok_or_else(|| {
        validation(
            "NEO629",
            "render destination has no parent directory".into(),
        )
    })?;
    let parent = parent.canonicalize().map_err(|error| {
        validation(
            "NEO629",
            format!(
                "failed to resolve render destination {}: {error}",
                declared.display()
            ),
        )
    })?;
    ensure_contained(root, &parent, "render destination directory")?;
    let name = candidate
        .file_name()
        .ok_or_else(|| validation("NEO629", "render destination must name a file".to_owned()))?;
    let resolved = parent.join(name);
    ensure_contained(root, &resolved, "render destination")?;
    if fs::symlink_metadata(&resolved).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(validation(
            "NEO629",
            format!(
                "render destination must not be a symlink: {}",
                resolved.display()
            ),
        ));
    }
    action.destination = Some(resolved.display().to_string());
    action.destination_from_package = true;
    Ok(())
}

fn resolve_task_working_directory(
    root: &Path,
    action: &mut neoenv_core::tasks::TaskAction,
) -> Result<(), Diagnostic> {
    let cwd = action
        .cwd
        .as_deref()
        .ok_or_else(|| validation("NEO629", "task action has no working directory".into()))?;
    let document = declaration_document(
        root,
        action.cwd_document.as_ref().ok_or_else(|| {
            validation(
                "NEO629",
                "task working directory has no declaring document".into(),
            )
        })?,
        "task working directory",
    )?;
    let declared = relative_declared_path(cwd, "task working directory")?;
    let resolved = document
        .parent()
        .unwrap_or(root)
        .join(declared)
        .canonicalize()
        .map_err(|error| {
            validation(
                "NEO629",
                format!(
                    "failed to resolve task working directory {}: {error}",
                    declared.display()
                ),
            )
        })?;
    ensure_contained(root, &resolved, "task working directory")?;
    if !resolved.is_dir() {
        return Err(validation(
            "NEO629",
            format!(
                "task working directory is not a directory: {}",
                resolved.display()
            ),
        ));
    }
    action.cwd = Some(resolved.display().to_string());
    action.cwd_from_package = true;
    Ok(())
}

fn declaration_document(
    root: &Path,
    source: &SourceSpan,
    label: &str,
) -> Result<PathBuf, Diagnostic> {
    let document = Path::new(&source.path).canonicalize().map_err(|error| {
        validation(
            "NEO629",
            format!("failed to resolve {label} declaring document: {error}"),
        )
    })?;
    ensure_contained(root, &document, "package declaring document")?;
    if !document.is_file() {
        return Err(validation(
            "NEO629",
            format!(
                "package declaring document is not a file: {}",
                document.display()
            ),
        ));
    }
    Ok(document)
}

fn relative_declared_path<'a>(value: &'a str, label: &str) -> Result<&'a Path, Diagnostic> {
    let path = Path::new(value);
    if value.trim().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        return Err(validation(
            "NEO629",
            format!("{label} must stay within its declaring package document: {value}"),
        ));
    }
    Ok(path)
}

fn ensure_contained(root: &Path, path: &Path, label: &str) -> Result<(), Diagnostic> {
    if path.starts_with(root) {
        Ok(())
    } else {
        Err(validation(
            "NEO629",
            format!("{label} escapes its package root: {}", path.display()),
        ))
    }
}

fn module_path(
    root: &Path,
    source: &Path,
    import: &str,
) -> Result<(PathBuf, ModuleOrigin, Option<RemoteLocation>), Diagnostic> {
    if let Some(tarball) = TarballModule::parse(import).map_err(|error| remote_error(&error))? {
        let cached: CachedTarball =
            cached_tarball_details(root, &tarball).map_err(|error| remote_error(&error))?;
        let relative_path = repository_relative_path(&cached.source_root, &cached.path)?;
        return Ok((
            cached.path,
            ModuleOrigin::Remote,
            Some(RemoteLocation {
                repository: cached.url,
                // An archive has no commit; the publisher's immutable artifact
                // digest is the pinned coordinate. It is not a signature.
                commit: cached.digest,
                relative_path,
                root: cached.source_root,
            }),
        ));
    }
    if is_remote(import) {
        let module = RemoteModule::parse(import).map_err(|error| remote_error(&error))?;
        let cached: CachedModule =
            cached_module_details(root, &module).map_err(|error| remote_error(&error))?;
        let relative_path = repository_relative_path(&cached.source_root, &cached.path)?;
        return Ok((
            cached.path,
            ModuleOrigin::Remote,
            Some(RemoteLocation {
                repository: module.repository,
                commit: cached.commit,
                relative_path,
                root: cached.source_root,
            }),
        ));
    }
    if import.trim().is_empty() {
        return Err(validation(
            "NEO612",
            format!("only non-empty local module imports are supported: {import}"),
        ));
    }
    let relative = Path::new(import);
    if relative.is_absolute() {
        return Err(validation(
            "NEO613",
            format!("local module import must be relative: {import}"),
        ));
    }
    if !import.contains('/') && !import.contains('.') {
        return discover_named_module(root, import).map(|path| (path, ModuleOrigin::Local, None));
    }
    let candidate = source.parent().unwrap_or(root).join(relative);
    let canonical = fs::canonicalize(&candidate).map_err(|error| io_error(&candidate, &error))?;
    if !canonical.starts_with(root) {
        return Err(validation(
            "NEO614",
            format!("local module import escapes project root: {import}"),
        ));
    }
    Ok((canonical, ModuleOrigin::Local, None))
}

/// Normalizes a path inside a remote extraction root to a repository-relative
/// path with `/` separators. Parent components are refused rather than folded.
fn repository_relative_path(root: &Path, path: &Path) -> Result<String, Diagnostic> {
    let relative = path.strip_prefix(root).map_err(|_| {
        validation(
            "NEO630",
            format!(
                "remote document escapes its extraction root: {}",
                path.display()
            ),
        )
    })?;
    let mut normalized = String::new();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return Err(validation(
                "NEO630",
                format!(
                    "remote document path is not a normalized repository path: {}",
                    path.display()
                ),
            ));
        };
        let part = part.to_str().ok_or_else(|| {
            validation(
                "NEO630",
                format!(
                    "remote document path is not valid UTF-8: {}",
                    path.display()
                ),
            )
        })?;
        if !normalized.is_empty() {
            normalized.push('/');
        }
        normalized.push_str(part);
    }
    if normalized.is_empty() {
        return Err(validation(
            "NEO630",
            format!(
                "remote document path names the extraction root: {}",
                path.display()
            ),
        ));
    }
    Ok(normalized)
}

/// One resolved task-package document: the directory imports are confined to,
/// the document path, and the identity coordinates it was read under.
struct TaskPackageTarget {
    root: PathBuf,
    path: PathBuf,
    origin: ModuleOrigin,
    location: Option<RemoteLocation>,
}

/// Resolves a task-package reference to a document without taking any effect.
///
/// A reference is one of:
///
/// - a project-relative document path (`./tasks/lint/task.yaml`, `pkg/tool.yaml`),
///   confined to the project root and to the document's own directory after
///   symlink resolution;
/// - a bare package name discovered under the project or user task directory;
/// - a pinned GitHub source (`github:owner/repo@<commit>//tasks/lint/task.yaml`),
///   read from the already-populated immutable cache. Selecting a remote
///   document never fetches and never executes.
///
/// A relative reference is resolved against its declaring document. When that
/// document is remote content, the package stays remote content: the result
/// carries the declaring checkout's repository, commit, and root, so the
/// package document and its imports get remote execution-trust identities.
fn task_package_target(
    project_root: &Path,
    importing_source: &Path,
    reference: &str,
    declaring_remote: Option<&RemoteLocation>,
) -> Result<TaskPackageTarget, Diagnostic> {
    if reference.trim().is_empty() {
        return Err(validation(
            "NEO621",
            "task package source must not be empty".into(),
        ));
    }
    if is_remote(reference) || crate::remote::is_local_git(reference) {
        return remote_task_package_target(project_root, reference);
    }
    let reference_path = Path::new(reference);
    if reference_path.is_absolute() || reference.contains(['\\']) {
        return Err(validation(
            "NEO622",
            format!("task package source must be relative or a bare name: {reference}"),
        ));
    }
    if !reference.contains('/') && !reference.contains('.') {
        // A bare name is a discovery in the project or user task directory,
        // never content from the declaring checkout, so it stays a local
        // package and needs the ordinary local approval.
        let (root, path) = discover_named_task_package(project_root, reference)?;
        return Ok(TaskPackageTarget {
            root,
            path,
            origin: ModuleOrigin::Local,
            location: None,
        });
    }
    if let Some(declaring) = declaring_remote {
        return declaring_relative_task_package(declaring, importing_source, reference);
    }
    let (root, path) = task_package_path(project_root, importing_source, reference)?;
    Ok(TaskPackageTarget {
        root,
        path,
        origin: ModuleOrigin::Local,
        location: None,
    })
}

/// Resolves a relative package reference without letting canonicalization hide
/// a symbolic link or a parent traversal.
///
/// The walk follows the reference's actual lexical path, including `..`
/// components that move above the declaring document's directory but stay
/// inside `permitted_root`. Every component that exists is checked for a
/// symbolic link *before* canonicalization, because a same-directory link would
/// otherwise be accepted and recorded under its target's identity. A `..`
/// that would leave `permitted_root` is refused here rather than left to a
/// later containment check. A missing component is left for the canonical read
/// to report.
fn relative_task_package_path(
    base: &Path,
    permitted_root: &Path,
    reference: &str,
    escape: &str,
) -> Result<PathBuf, Diagnostic> {
    if !base.starts_with(permitted_root) {
        return Err(validation("NEO623", format!("{escape}: {reference}")));
    }
    let mut current = base.to_owned();
    for component in Path::new(reference).components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if current == permitted_root || !current.starts_with(permitted_root) {
                    return Err(validation("NEO623", format!("{escape}: {reference}")));
                }
                current.pop();
            }
            Component::Normal(part) => {
                current.push(part);
                match fs::symlink_metadata(&current) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        return Err(validation(
                            "NEO623",
                            format!(
                                "task package path must not contain a symbolic link: {reference}"
                            ),
                        ));
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(io_error(&current, &error)),
                }
            }
            Component::Prefix(_) | Component::RootDir => {
                return Err(validation(
                    "NEO622",
                    format!("task package source must be relative or a bare name: {reference}"),
                ));
            }
        }
    }
    Ok(current)
}

/// Resolves a relative package reference from inside a remote checkout.
///
/// The document must remain below that checkout after canonicalization, and its
/// imports are confined to the document's own directory exactly as for a local
/// package. The identity coordinates are the declaring checkout's, with the
/// path made repository-relative — not the cache path that happens to contain
/// `.neoenv/modules`.
fn declaring_relative_task_package(
    declaring: &RemoteLocation,
    importing_source: &Path,
    reference: &str,
) -> Result<TaskPackageTarget, Diagnostic> {
    let base = importing_source.parent().unwrap_or(&declaring.root);
    let candidate = relative_task_package_path(
        base,
        &declaring.root,
        reference,
        "task package escapes its declaring remote checkout",
    )?;
    let declared_root = candidate
        .parent()
        .ok_or_else(|| validation("NEO623", "task package has no parent directory".into()))?
        .canonicalize()
        .map_err(|error| io_error(&candidate, &error))?;
    let path = fs::canonicalize(&candidate).map_err(|error| io_error(&candidate, &error))?;
    let selected_root = path
        .parent()
        .ok_or_else(|| validation("NEO623", "task package has no parent directory".into()))?;
    if !selected_root.starts_with(&declaring.root) {
        return Err(validation(
            "NEO623",
            format!("task package escapes its declaring remote checkout: {reference}"),
        ));
    }
    if selected_root != declared_root {
        return Err(validation(
            "NEO623",
            format!("task package document escapes its package root: {reference}"),
        ));
    }
    if !path.is_file() {
        return Err(validation(
            "NEO622",
            format!("remote task package must name a document file, not a directory: {reference}"),
        ));
    }
    let relative_path = repository_relative_path(&declaring.root, &path)?;
    Ok(TaskPackageTarget {
        root: selected_root.to_owned(),
        path,
        origin: ModuleOrigin::Remote,
        location: Some(RemoteLocation {
            repository: declaring.repository.clone(),
            commit: declaring.commit.clone(),
            relative_path,
            root: declaring.root.clone(),
        }),
    })
}

/// Resolves a pinned GitHub task-package document from the immutable cache.
///
/// The repository allow-list is required, exactly as for a remote module
/// import: it authorizes reading a populated cache and never execution. The
/// returned location makes the document and every import it pulls in carry a
/// remote execution-trust identity (repository, commit, repository-relative
/// path, then the bytes).
///
/// Live fetching is not reachable here. A missing cache entry is a diagnostic,
/// not a clone.
fn remote_task_package_target(
    project_root: &Path,
    reference: &str,
) -> Result<TaskPackageTarget, Diagnostic> {
    let module =
        RemoteModule::parse(reference).map_err(|error| validation("NEO622", error.to_string()))?;
    let cached =
        cached_module_details(project_root, &module).map_err(|error| remote_error(&error))?;
    if !cached.path.is_file() {
        return Err(validation(
            "NEO622",
            format!(
                "remote task package must name a document file, not a directory: {}",
                module.canonical()
            ),
        ));
    }
    let relative_path = repository_relative_path(&cached.source_root, &cached.path)?;
    let root = cached
        .path
        .parent()
        .ok_or_else(|| validation("NEO623", "task package has no parent directory".into()))?
        .to_owned();
    Ok(TaskPackageTarget {
        root,
        path: cached.path,
        origin: ModuleOrigin::Remote,
        location: Some(RemoteLocation {
            repository: module.repository,
            commit: cached.commit,
            relative_path,
            root: cached.source_root,
        }),
    })
}

fn task_package_path(
    project_root: &Path,
    importing_source: &Path,
    reference: &str,
) -> Result<(PathBuf, PathBuf), Diagnostic> {
    let base = importing_source.parent().unwrap_or(project_root);
    let candidate = relative_task_package_path(
        base,
        project_root,
        reference,
        "task package escapes project root",
    )?;
    let declared_root = candidate
        .parent()
        .ok_or_else(|| validation("NEO623", "task package has no parent directory".into()))?
        .canonicalize()
        .map_err(|error| io_error(&candidate, &error))?;
    let path = fs::canonicalize(&candidate).map_err(|error| io_error(&candidate, &error))?;
    let selected_root = path
        .parent()
        .ok_or_else(|| validation("NEO623", "task package has no parent directory".into()))?;
    if !selected_root.starts_with(project_root) {
        return Err(validation(
            "NEO623",
            format!("task package escapes project root: {reference}"),
        ));
    }
    if selected_root != declared_root {
        return Err(validation(
            "NEO623",
            format!("task package document escapes its package root: {reference}"),
        ));
    }
    Ok((selected_root.to_owned(), path))
}

fn discover_named_task_package(root: &Path, name: &str) -> Result<(PathBuf, PathBuf), Diagnostic> {
    if name.is_empty()
        || name.contains(['/', '\\'])
        || Path::new(name)
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(validation(
            "NEO621",
            format!("invalid task package name: {name}"),
        ));
    }
    let user_root = user_directory(UserDirectory::Data)
        .map(|path| path.join(neoenv_core::names::GLOBAL_TASK_DIRECTORY));
    for directory in [
        Some(root.join(neoenv_core::names::GLOBAL_TASK_DIRECTORY)),
        user_root,
    ] {
        let Some(directory) = directory else {
            continue;
        };
        for candidate in [
            directory.join(format!("{name}.yaml")),
            directory.join(format!("{name}.yml")),
            directory.join(format!("{name}.toml")),
            directory.join(name).join("neoenv.task.yaml"),
            directory.join(name).join("neoenv.task.toml"),
        ] {
            if !candidate.is_file() {
                continue;
            }
            let canonical_directory =
                fs::canonicalize(&directory).map_err(|error| io_error(&directory, &error))?;
            let declared_root = candidate
                .parent()
                .ok_or_else(|| validation("NEO623", "task package has no parent directory".into()))?
                .canonicalize()
                .map_err(|error| io_error(&candidate, &error))?;
            let canonical =
                fs::canonicalize(&candidate).map_err(|error| io_error(&candidate, &error))?;
            let selected_root = canonical.parent().ok_or_else(|| {
                validation("NEO623", "task package has no parent directory".into())
            })?;
            if canonical.starts_with(&canonical_directory) && selected_root == declared_root {
                return Ok((selected_root.to_owned(), canonical));
            }
            return Err(validation(
                "NEO623",
                format!("task package document escapes its package root: {name}"),
            ));
        }
    }
    Err(validation(
        "NEO624",
        format!("task package was not found in project or user data: {name}"),
    ))
}

fn select_tasks(project: &mut Project, import: &ModuleImport) -> Result<(), Diagnostic> {
    if let Some(namespace) = &import.namespace
        && (namespace.is_empty() || namespace.contains(['/', '\\', ':']))
    {
        return Err(validation(
            "NEO617",
            format!("invalid module namespace: {namespace}"),
        ));
    }
    if import.tasks.iter().any(String::is_empty) {
        return Err(validation(
            "NEO618",
            "module task selectors must be non-empty".into(),
        ));
    }
    if !import.tasks.is_empty() {
        for task in &import.tasks {
            if !project.tasks.contains_key(task) {
                return Err(validation(
                    "NEO619",
                    format!("module does not declare selected task: {task}"),
                ));
            }
        }
        let selected = import.tasks.iter().collect::<HashSet<_>>();
        project.tasks.retain(|name, _| selected.contains(&name));
    }
    if let Some(namespace) = &import.namespace {
        let mut tasks = indexmap::IndexMap::new();
        for (name, mut task) in std::mem::take(&mut project.tasks) {
            task.parallel_needs = task
                .parallel_needs
                .into_iter()
                .map(|name| format!("{namespace}:{name}"))
                .collect();
            task.wait = task
                .wait
                .into_iter()
                .map(|name| {
                    if name == "all" {
                        name
                    } else {
                        format!("{namespace}:{name}")
                    }
                })
                .collect();
            task.needs = task
                .needs
                .into_iter()
                .map(|name| format!("{namespace}:{name}"))
                .collect();
            task.hooks.before = task
                .hooks
                .before
                .into_iter()
                .map(|name| format!("{namespace}:{name}"))
                .collect();
            task.hooks.after = task
                .hooks
                .after
                .into_iter()
                .map(|name| format!("{namespace}:{name}"))
                .collect();
            task.extends = task.extends.map(|name| format!("{namespace}:{name}"));
            tasks.insert(format!("{namespace}:{name}"), task);
        }
        project.tasks = tasks;
    }
    Ok(())
}

fn discover_named_module(root: &Path, name: &str) -> Result<PathBuf, Diagnostic> {
    if name.is_empty()
        || name.contains(['/', '\\'])
        || Path::new(name)
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(validation(
            "NEO612",
            format!("invalid named module: {name}"),
        ));
    }
    let user_root = user_directory(UserDirectory::Cache).map(|path| path.join("neoenv/modules"));
    discover_named_module_in(root, name, user_root.as_deref())
}

pub(super) fn discover_named_module_in(
    root: &Path,
    name: &str,
    user_root: Option<&Path>,
) -> Result<PathBuf, Diagnostic> {
    let roots = [
        Some(root.join("neoenv/modules")),
        user_root.map(Path::to_owned),
    ];
    for directory in roots.into_iter().flatten() {
        for candidate in [
            directory.join(name),
            directory.join(format!("{name}.yaml")),
            directory.join(format!("{name}.yml")),
            directory.join(name).join("neoenv.module.yaml"),
        ] {
            if candidate.is_file() {
                let canonical =
                    fs::canonicalize(&candidate).map_err(|error| io_error(&candidate, &error))?;
                let canonical_directory =
                    fs::canonicalize(&directory).map_err(|error| io_error(&directory, &error))?;
                if canonical.starts_with(&canonical_directory) {
                    let document = module_document(&canonical)?;
                    if document.starts_with(&canonical_directory) {
                        return Ok(document);
                    }
                    return Err(validation(
                        "NEO614",
                        format!("named module escapes its cache: {name}"),
                    ));
                }
                return Err(validation(
                    "NEO614",
                    format!("named module escapes its cache: {name}"),
                ));
            }
        }
    }
    Err(validation(
        "NEO615",
        format!("named module was not found in project or user cache: {name}"),
    ))
}
