use std::{
    collections::BTreeMap,
    ffi::{OsStr, c_void},
    io,
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{
        DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    },
    Globalization::{CSTR_EQUAL, CSTR_GREATER_THAN, CSTR_LESS_THAN, CompareStringOrdinal},
    System::{
        Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE},
        JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
            QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
        },
        Threading::{
            CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DETACHED_PROCESS,
            DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
            GetExitCodeProcess, InitializeProcThreadAttributeList,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION,
            ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, UpdateProcThreadAttribute,
            WaitForSingleObject,
        },
    },
};

#[path = "windows/control.rs"]
mod control;
#[path = "windows/launcher.rs"]
pub(crate) mod launcher;
#[path = "windows/output.rs"]
mod output;
pub use output::{ForwardDestination, OutputCancellation, OutputWriter, overlapped_output_pipe};
#[path = "windows/proxy.rs"]
pub(crate) mod proxy;
pub use control::{ControlClient, ControlListener, HostIdentity, VerifiedControl};
pub use launcher::{LauncherRequest, LauncherResponse};

/// Read end of an anonymous byte pipe created by this adapter.
pub struct PipeReader(std::io::PipeReader);

/// Write end of an anonymous byte pipe created by this adapter.
pub struct PipeWriter(std::io::PipeWriter);

/// Create an adapter-owned anonymous pipe. Either typed end may be offered to
/// a launcher; arbitrary handles and sockets cannot enter the transfer API.
pub fn anonymous_pipe() -> io::Result<(PipeReader, PipeWriter)> {
    let (reader, writer) = std::io::pipe()?;
    Ok((PipeReader(reader), PipeWriter(writer)))
}

impl std::io::Read for PipeReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        std::io::Read::read(&mut self.0, buffer)
    }
}

impl std::io::Write for PipeWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        std::io::Write::write(&mut self.0, buffer)
    }
    fn flush(&mut self) -> io::Result<()> {
        std::io::Write::flush(&mut self.0)
    }
}

/// Inputs for an owned process. The executable must be an absolute `.exe` or
/// `.com` path; callers resolve it against the intended child environment.
pub struct Spawn<'a> {
    pub executable: &'a Path,
    pub arguments: &'a [String],
    pub environment: &'a BTreeMap<String, String>,
    pub directory: &'a Path,
    pub inherit_stdin: bool,
}

/// Owns a running child and its non-inheritable kill-on-close job.
pub struct Child {
    job: OwnedHandle,
    process: OwnedHandle,
}

#[derive(Debug)]
struct SpawnCleanupFailure;

impl std::fmt::Display for SpawnCleanupFailure {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("worker startup cleanup failed; descendants may remain")
    }
}

impl std::error::Error for SpawnCleanupFailure {}

/// Safe operation identifiers for launcher diagnostics, without task data.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub enum LauncherStage {
    CreateJob,
    ConfigureJob,
    InspectThreads,
    OpenNull,
    DuplicateInput,
    DuplicateOutput,
    DuplicateError,
    ConfigureAttributes,
    CreateProcess,
    ResumeThread,
    ValidateExecutable,
    EncodeExecutable,
    EncodeDirectory,
    BuildEnvironment,
    EncodeArguments,
}
#[derive(Debug)]
struct StagedFailure {
    stage: LauncherStage,
    code: Option<i32>,
}
impl std::fmt::Display for StagedFailure {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            output,
            "launcher {:?} failed (Win32 code {:?})",
            self.stage, self.code
        )
    }
}
impl std::error::Error for StagedFailure {}
fn at_stage(stage: LauncherStage, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        StagedFailure {
            stage,
            code: error.raw_os_error(),
        },
    )
}

fn handle(raw: HANDLE) -> io::Result<OwnedHandle> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful Win32 handle-producing calls transfer one owned
    // handle to this function; null and INVALID_HANDLE_VALUE are rejected.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

fn raw(handle: &OwnedHandle) -> HANDLE {
    handle.as_raw_handle()
}

fn utf16(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut result: Vec<_> = value.encode_wide().collect();
    if result.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "embedded NUL"));
    }
    result.push(0);
    Ok(result)
}

// CreateProcessW's current-directory argument does not reliably accept a
// verbatim prefix. Match std::process: strip it only when GetFullPathNameW
// proves the ordinary path is unchanged; otherwise preserve the original.
fn directory_utf16(path: &Path) -> io::Result<Vec<u16>> {
    use windows_sys::Win32::Storage::FileSystem::GetFullPathNameW;
    let original = utf16(path.as_os_str())?;
    let unc: Vec<u16> = r"\\?\UNC\".encode_utf16().collect();
    let verbatim: Vec<u16> = r"\\?\".encode_utf16().collect();
    let candidate = if original.starts_with(&unc) {
        let mut value = vec![b'\\' as u16, b'\\' as u16];
        value.extend_from_slice(&original[unc.len()..]);
        Some(value)
    } else if original.starts_with(&verbatim) {
        Some(original[verbatim.len()..].to_vec())
    } else {
        None
    };
    let Some(candidate) = candidate else {
        return Ok(original);
    };
    if candidate.len() > u32::MAX as usize {
        return Ok(original);
    }
    let mut resolved = vec![0u16; candidate.len()];
    // SAFETY: candidate is NUL terminated and resolved has the advertised
    // writable capacity. Both remain live throughout the Win32 call.
    let length = unsafe {
        GetFullPathNameW(
            candidate.as_ptr(),
            resolved.len() as u32,
            resolved.as_mut_ptr(),
            null_mut(),
        )
    };
    if length != 0 && length as usize + 1 == candidate.len() && resolved == candidate {
        Ok(candidate)
    } else {
        Ok(original)
    }
}

fn quote(value: &OsStr, output: &mut Vec<u16>) -> io::Result<()> {
    let data = utf16(value)?;
    output.push(b'"' as u16);
    let mut slashes = 0;
    for &ch in &data[..data.len() - 1] {
        if ch == b'\\' as u16 {
            slashes += 1;
        } else {
            let count = if ch == b'"' as u16 {
                slashes * 2 + 1
            } else {
                slashes
            };
            output.extend(std::iter::repeat_n(b'\\' as u16, count));
            output.push(ch);
            slashes = 0;
        }
    }
    output.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
    output.push(b'"' as u16);
    Ok(())
}

fn environment_block(environment: &BTreeMap<String, String>) -> io::Result<Vec<u16>> {
    let mut entries = Vec::new();
    for (key, value) in environment {
        // GetEnvironmentStringsW includes pseudo-variables such as `=C:`
        // for per-drive current directories. Rust's Windows environment
        // iterator preserves them, so an initial '=' is legal; a later '='
        // would corrupt the name/value separator.
        let legal = !key.is_empty()
            && if let Some(rest) = key.strip_prefix('=') {
                !rest.is_empty() && !rest.contains('=')
            } else {
                !key.contains('=')
            };
        if !legal {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid environment key",
            ));
        }
        let entry = utf16(OsStr::new(&format!("{key}={value}")))?;
        entries.push((utf16(OsStr::new(key))?, entry));
    }
    let failed = std::cell::Cell::new(false);
    let compare = |a: &[u16], b: &[u16]| {
        // SAFETY: both strings are valid, NUL-terminated UTF-16 buffers, alive
        // for this call. -1 requests comparison through their terminators.
        match unsafe { CompareStringOrdinal(a.as_ptr(), -1, b.as_ptr(), -1, 1) } {
            CSTR_LESS_THAN => std::cmp::Ordering::Less,
            CSTR_EQUAL => std::cmp::Ordering::Equal,
            CSTR_GREATER_THAN => std::cmp::Ordering::Greater,
            _ => {
                failed.set(true);
                std::cmp::Ordering::Equal
            }
        }
    };
    entries.sort_by(|a, b| compare(&a.0, &b.0));
    let duplicate = entries
        .windows(2)
        .any(|w| compare(&w[0].0, &w[1].0).is_eq());
    if failed.get() {
        return Err(io::Error::other(
            "Windows environment name comparison failed",
        ));
    }
    if duplicate {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "duplicate environment key",
        ));
    }
    let mut block = Vec::new();
    for (_, entry) in entries {
        block.extend(entry);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

fn duplicate(source: HANDLE) -> io::Result<OwnedHandle> {
    let mut result = null_mut();
    // SAFETY: the current-process pseudo handle is valid; source is borrowed,
    // result points to writable handle storage, and success transfers ownership.
    let success = unsafe {
        let process = GetCurrentProcess();
        DuplicateHandle(
            process,
            source,
            process,
            &mut result,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    handle(result)
}

struct Attributes {
    storage: Vec<usize>,
}

impl Attributes {
    fn new(handles: &[HANDLE], jobs: &[HANDLE]) -> io::Result<Self> {
        let mut size = 0;
        // SAFETY: the documented sizing call accepts a null list and writes size.
        unsafe {
            InitializeProcThreadAttributeList(null_mut(), 2, 0, &mut size);
        }
        if size == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut storage = vec![0usize; size.div_ceil(size_of::<usize>())];
        let list = storage.as_mut_ptr().cast();
        // SAFETY: storage is pointer-aligned and at least size bytes; the OS
        // initializes two attributes in this allocation.
        if unsafe { InitializeProcThreadAttributeList(list, 2, 0, &mut size) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let attrs = Self { storage };
        // SAFETY: the initialized list is live; handles points to a live array
        // of inheritable handles retained through CreateProcessW.
        if unsafe {
            UpdateProcThreadAttribute(
                attrs.ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                std::mem::size_of_val(handles),
                null_mut(),
                null(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the list is initialized and jobs references live job handles
        // held open through CreateProcessW. The OS assigns them atomically.
        if unsafe {
            UpdateProcThreadAttribute(
                attrs.ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                jobs.as_ptr().cast(),
                std::mem::size_of_val(jobs),
                null_mut(),
                null(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(attrs)
    }
    fn ptr(&self) -> *mut c_void {
        self.storage.as_ptr().cast_mut().cast()
    }

    fn job_only(jobs: &[HANDLE]) -> io::Result<Self> {
        let mut size = 0;
        // SAFETY: documented sizing call; size points to writable storage.
        unsafe {
            InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut size);
        }
        if size == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut storage = vec![0usize; size.div_ceil(size_of::<usize>())];
        // SAFETY: storage is aligned and at least the requested size.
        if unsafe {
            InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), 1, 0, &mut size)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let attrs = Self { storage };
        // SAFETY: jobs is a live array of valid handles retained through
        // CreateProcessW; the initialized attribute list is uniquely owned.
        if unsafe {
            UpdateProcThreadAttribute(
                attrs.ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                jobs.as_ptr().cast(),
                std::mem::size_of_val(jobs),
                null_mut(),
                null(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(attrs)
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: the list was initialized successfully and is deleted once.
        unsafe {
            DeleteProcThreadAttributeList(self.ptr());
        }
    }
}

impl Child {
    /// Start a no-stdio launcher atomically inside a kill-on-close job.
    ///
    /// No handles are inherited and the process is detached from the console.
    /// This bootstrap primitive does not itself transfer stdio or authenticate
    /// control; callers must establish the authenticated channel separately.
    pub fn spawn_isolated_launcher(spec: &Spawn<'_>) -> io::Result<Self> {
        if spec.inherit_stdin {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "isolated launcher cannot inherit stdin",
            ));
        }
        // Resolve relative paths against the caller's working directory before
        // validating the launcher. Do not resolve against the child cwd: the
        // executable selection must not change with the spawned environment.
        let executable = std::fs::canonicalize(spec.executable)?;
        if !executable.is_absolute()
            || !executable
                .extension()
                .and_then(OsStr::to_str)
                .is_some_and(|s| s.eq_ignore_ascii_case("exe") || s.eq_ignore_ascii_case("com"))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "launcher must resolve to an absolute .exe or .com",
            ));
        }
        let app = utf16(executable.as_os_str())?;
        let cwd = directory_utf16(spec.directory)?;
        let env = environment_block(spec.environment)?;
        let mut command = Vec::new();
        quote(executable.as_os_str(), &mut command)?;
        for argument in spec.arguments {
            command.push(b' ' as u16);
            quote(OsStr::new(argument), &mut command)?;
        }
        command.push(0);
        // SAFETY: null security attributes create a non-inheritable job.
        let job = handle(unsafe { CreateJobObjectW(null(), null()) })?;
        // SAFETY: zero is valid for this Win32 POD.
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: the job is valid and limits has the documented layout and size.
        if unsafe {
            SetInformationJobObject(
                raw(&job),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let jobs = [raw(&job)];
        let attributes = Attributes::job_only(&jobs)?;
        // SAFETY: zero is valid for Win32 startup and output POD structures.
        let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.lpAttributeList = attributes.ptr();
        // SAFETY: zero is valid for this Win32 output structure.
        let mut info: PROCESS_INFORMATION = unsafe { zeroed() };
        // SAFETY: all pointers reference live, appropriately terminated buffers
        // or initialized structures. InheritHandles is FALSE, so no host
        // inheritable handle is copied. DETACHED_PROCESS prevents console
        // attachment. JOB_LIST assigns the job atomically before execution.
        if unsafe {
            CreateProcessW(
                app.as_ptr(),
                command.as_mut_ptr(),
                null(),
                null(),
                0,
                CREATE_SUSPENDED
                    | CREATE_UNICODE_ENVIRONMENT
                    | EXTENDED_STARTUPINFO_PRESENT
                    | DETACHED_PROCESS,
                env.as_ptr().cast(),
                cwd.as_ptr(),
                &startup.StartupInfo,
                &mut info,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let process = handle(info.hProcess)?;
        let thread = handle(info.hThread)?;
        // SAFETY: the thread was returned by successful CreateProcessW and is
        // suspended inside the assigned job.
        if unsafe { ResumeThread(raw(&thread)) } == u32::MAX {
            let error = io::Error::last_os_error();
            let child = Self { job, process };
            return match child.terminate() {
                Ok(()) => Err(error),
                Err(cleanup) => Err(io::Error::other(format!(
                    "launcher resume failed ({error}); cleanup failed ({cleanup})"
                ))),
            };
        }
        Ok(Self { job, process })
    }

    /// Refuses launch until inheritable stdio handles can be isolated from
    /// unrelated concurrent process creation in the host.
    pub fn spawn(spec: &Spawn<'_>) -> io::Result<Self> {
        if !stdio_isolation_available() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows owned launch disabled: inherited stdio handles cannot be isolated from concurrent host launches",
            ));
        }
        Self::spawn_unisolated(spec)
    }

    fn spawn_unisolated(spec: &Spawn<'_>) -> io::Result<Self> {
        Self::spawn_with_outputs(spec, None, None)
    }

    fn spawn_with_outputs(
        spec: &Spawn<'_>,
        outputs: Option<(&std::fs::File, &std::fs::File)>,
        pre_resume: Option<&dyn Fn() -> io::Result<bool>>,
    ) -> io::Result<Self> {
        if !spec.executable.is_absolute() {
            return Err(at_stage(
                LauncherStage::ValidateExecutable,
                io::Error::new(io::ErrorKind::InvalidInput, "executable must be absolute"),
            ));
        }
        if !spec
            .executable
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|s| s.eq_ignore_ascii_case("exe") || s.eq_ignore_ascii_case("com"))
        {
            return Err(at_stage(
                LauncherStage::ValidateExecutable,
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "only .exe and .com executables are supported",
                ),
            ));
        }
        let app = utf16(spec.executable.as_os_str())
            .map_err(|e| at_stage(LauncherStage::EncodeExecutable, e))?;
        let cwd = directory_utf16(spec.directory)
            .map_err(|e| at_stage(LauncherStage::EncodeDirectory, e))?;
        let env = environment_block(spec.environment)
            .map_err(|e| at_stage(LauncherStage::BuildEnvironment, e))?;
        let mut command = Vec::new();
        quote(spec.executable.as_os_str(), &mut command)
            .map_err(|e| at_stage(LauncherStage::EncodeExecutable, e))?;
        for argument in spec.arguments {
            command.push(b' ' as u16);
            quote(OsStr::new(argument), &mut command)
                .map_err(|e| at_stage(LauncherStage::EncodeArguments, e))?;
        }
        command.push(0);
        // SAFETY: null security attributes produce a non-inheritable unnamed job.
        let job = handle(unsafe { CreateJobObjectW(null(), null()) })
            .map_err(|e| at_stage(LauncherStage::CreateJob, e))?;
        // SAFETY: zero is a valid initial representation for this Win32 POD.
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: job is valid and limits points to the correctly sized structure.
        if unsafe {
            SetInformationJobObject(
                raw(&job),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(at_stage(
                LauncherStage::ConfigureJob,
                io::Error::last_os_error(),
            ));
        }
        // This private path is reached only in the dedicated launcher, whose
        // application code performs no other process creation concurrently.
        // The handle list constrains the worker; it does not constrain a
        // foreign CreateProcess in this process. Injection and third-party
        // concurrent process creation are outside this cooperation contract.
        let null_stdin;
        let input = if spec.inherit_stdin {
            // SAFETY: GetStdHandle returns a borrowed handle; duplication gives
            // the child its own explicitly allowlisted inheritable handle.
            duplicate(unsafe { GetStdHandle(STD_INPUT_HANDLE) })
                .map_err(|e| at_stage(LauncherStage::DuplicateInput, e))?
        } else {
            null_stdin =
                std::fs::File::open("NUL").map_err(|e| at_stage(LauncherStage::OpenNull, e))?;
            duplicate(null_stdin.as_raw_handle())
                .map_err(|e| at_stage(LauncherStage::DuplicateInput, e))?
        };
        let (output, error) = if let Some((output, error)) = outputs {
            (
                duplicate(output.as_raw_handle())
                    .map_err(|e| at_stage(LauncherStage::DuplicateOutput, e))?,
                duplicate(error.as_raw_handle())
                    .map_err(|e| at_stage(LauncherStage::DuplicateError, e))?,
            )
        } else {
            // SAFETY: standard handles are borrowed and immediately duplicated.
            let output = duplicate(unsafe { GetStdHandle(STD_OUTPUT_HANDLE) })?;
            // SAFETY: standard handles are borrowed and immediately duplicated.
            let error = duplicate(unsafe { GetStdHandle(STD_ERROR_HANDLE) })?;
            (output, error)
        };
        let handles = [raw(&input), raw(&output), raw(&error)];
        let jobs = [raw(&job)];
        let attributes = Attributes::new(&handles, &jobs)
            .map_err(|e| at_stage(LauncherStage::ConfigureAttributes, e))?;
        // SAFETY: zero is a valid initial representation for Win32 PODs.
        let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = handles[0];
        startup.StartupInfo.hStdOutput = handles[1];
        startup.StartupInfo.hStdError = handles[2];
        startup.lpAttributeList = attributes.ptr();
        // SAFETY: zero is a valid initial representation for this output POD.
        let mut info: PROCESS_INFORMATION = unsafe { zeroed() };
        // SAFETY: all pointers reference live, correctly terminated buffers;
        // startup holds the live handle allowlist, and info is writable. The
        // job list is applied atomically during creation; the child is
        // suspended before any user instruction can execute. Unsupported OS
        // versions or restrictive nested jobs fail instead of falling back.
        if unsafe {
            CreateProcessW(
                app.as_ptr(),
                command.as_mut_ptr(),
                null(),
                null(),
                1,
                CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                env.as_ptr().cast(),
                cwd.as_ptr(),
                &startup.StartupInfo,
                &mut info,
            )
        } == 0
        {
            return Err(at_stage(
                LauncherStage::CreateProcess,
                io::Error::last_os_error(),
            ));
        }
        let process = handle(info.hProcess)?;
        let thread = handle(info.hThread)?;
        // Release temporary inheritable copies immediately after creation;
        // only the new suspended child retains its allowlisted copies.
        drop(attributes);
        drop((input, output, error));
        if let Some(check) = pre_resume {
            match check() {
                Ok(true) => {}
                Ok(false) | Err(_) => {
                    let child = Self { job, process };
                    if child.terminate().is_err() {
                        return Err(io::Error::other(SpawnCleanupFailure));
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "launcher host disconnected before worker resume",
                    ));
                }
            }
        }
        // SAFETY: the suspended initial thread belongs to the assigned process.
        if unsafe { ResumeThread(raw(&thread)) } == u32::MAX {
            let error = io::Error::last_os_error();
            let child = Self { job, process };
            if child.terminate().is_err() {
                return Err(io::Error::other(SpawnCleanupFailure));
            }
            return Err(at_stage(LauncherStage::ResumeThread, error));
        }
        Ok(Self { job, process })
    }

    /// Returns the exit code when the leader has exited.
    pub fn try_wait(&self) -> io::Result<Option<u32>> {
        // SAFETY: process is a valid owned process handle.
        match unsafe { WaitForSingleObject(raw(&self.process), 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut code = 0;
                // SAFETY: process is valid and code points to writable storage.
                if unsafe { GetExitCodeProcess(raw(&self.process), &mut code) } == 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(Some(code))
                }
            }
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Stop the entire job. Dropping the job also terminates remaining members.
    pub fn terminate(&self) -> io::Result<()> {
        // SAFETY: job is a valid handle owned for the lifetime of self.
        if unsafe { TerminateJobObject(raw(&self.job), 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            // SAFETY: zero is valid for this POD and the API fills the structure.
            let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
            // SAFETY: the job is valid and accounting is writable and correctly sized.
            if unsafe {
                QueryInformationJobObject(
                    raw(&self.job),
                    JobObjectBasicAccountingInformation,
                    (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                    size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            // Job accounting reaching zero can precede the retained process
            // handle becoming signalled. Both are required for terminate()'s
            // callers to safely observe a completed direct child immediately.
            // SAFETY: process is a live retained handle; the poll is nonblocking.
            let process_state = unsafe { WaitForSingleObject(raw(&self.process), 0) };
            if process_state != WAIT_OBJECT_0 && process_state != WAIT_TIMEOUT {
                return Err(io::Error::last_os_error());
            }
            if accounting.ActiveProcesses == 0 && process_state == WAIT_OBJECT_0 {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "job members did not terminate",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

// This is deliberately not user-configurable: a safe API cannot assume that
// unrelated libraries in the host cooperate with a process-wide launch lock.
fn stdio_isolation_available() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn isolated_launcher_bootstrap_does_not_inspect_host_threads() {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        let other = std::thread::spawn(move || {
            ready_tx.send(()).unwrap();
            stop_rx.recv().unwrap();
        });
        ready_rx.recv().unwrap();
        let executable = std::env::current_exe().unwrap();
        let directory = std::env::temp_dir();
        let environment = BTreeMap::from([
            ("NEOENV_JOB_TEST_MODE".into(), "hold".into()),
            ("NEOENV_JOB_TEST_MARKER".into(), "unused".into()),
        ]);
        let arguments = vec![
            "--exact".into(),
            "windows::tests::helper".into(),
            "--nocapture".into(),
        ];
        let result = Child::spawn_isolated_launcher(&Spawn {
            executable: &executable,
            arguments: &arguments,
            environment: &environment,
            directory: &directory,
            inherit_stdin: false,
        });
        stop_tx.send(()).unwrap();
        other.join().unwrap();
        let child = result.unwrap();
        child.terminate().unwrap();
        assert!(child.try_wait().unwrap().is_some());
    }

    #[test]
    fn helper() {
        let Ok(mode) = std::env::var("NEOENV_JOB_TEST_MODE") else {
            return;
        };
        let marker = std::env::var_os("NEOENV_JOB_TEST_MARKER").unwrap();
        if mode == "worker_output" {
            use std::io::Write as _;
            std::io::stdout().write_all(b"\x1b[31mout\x1b[0m").unwrap();
            std::io::stderr().write_all(b"\x1b[32merr\x1b[0m").unwrap();
        } else if mode == "worker_flood" {
            use std::io::Write as _;
            std::fs::write(&marker, "ready").unwrap();
            std::io::stdout().write_all(&vec![b'x'; 2_000_000]).unwrap();
        } else if mode == "duplicate_attack" {
            use std::io::Write as _;
            use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_DUP_HANDLE};
            let pid: u32 = std::env::var("NEOENV_ATTACK_HOST_PID")
                .unwrap()
                .parse()
                .unwrap();
            let source: usize = std::env::var("NEOENV_ATTACK_HANDLE")
                .unwrap()
                .parse()
                .unwrap();
            // SAFETY: OpenProcess returns a new handle or null. The requested
            // access models an attacker explicitly inside the excluded scope.
            let host = handle(unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, pid) }).unwrap();
            let mut duplicated = null_mut();
            // SAFETY: host is a live process handle, source is the server
            // handle value supplied by the test, and duplicated is writable.
            let ok = unsafe {
                DuplicateHandle(
                    raw(&host),
                    source as HANDLE,
                    GetCurrentProcess(),
                    &mut duplicated,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            };
            assert_ne!(ok, 0);
            let mut stolen = std::fs::File::from(handle(duplicated).unwrap());
            stolen
                .write_all(
                    &crate::protocol::encode(crate::protocol::Kind::Request, b"injected").unwrap(),
                )
                .unwrap();
        } else if mode == "pipe_disconnect" {
            let name = std::env::var("NEOENV_JOB_TEST_PIPE").unwrap();
            let pipe = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(name)
                .unwrap();
            drop(pipe);
        } else if mode == "pipe_client"
            || mode == "pipe_frame"
            || mode == "partial_header"
            || mode == "partial_body"
            || mode == "malformed_frame"
            || mode == "pipe_transfer"
            || mode == "pipe_transfer_delayed"
            || mode == "pipe_transfer_immediate"
            || mode == "pipe_transfer_reader"
            || mode == "check_host_rights"
            || mode == "pipe_stall"
            || mode == "pipe_reject"
            || mode == "pipe_abandon"
        {
            let name = std::env::var("NEOENV_JOB_TEST_PIPE").unwrap();
            let identity = HostIdentity {
                pid: std::env::var("NEOENV_JOB_TEST_HOST_PID")
                    .unwrap()
                    .parse()
                    .unwrap(),
                creation_time: std::env::var("NEOENV_JOB_TEST_HOST_TIME")
                    .unwrap()
                    .parse()
                    .unwrap(),
            };
            let mut pipe =
                ControlClient::connect(&name, identity, Duration::from_secs(5), &|| false).unwrap();
            if mode == "pipe_transfer_reader" {
                use std::io::Read as _;
                let mut input = pipe
                    .receive_pipe(Duration::from_secs(5), &|| false)
                    .unwrap();
                let mut data = Vec::new();
                input.read_to_end(&mut data).unwrap();
                pipe.send(
                    crate::protocol::Kind::Result,
                    &data,
                    Duration::from_secs(5),
                    &|| false,
                )
                .unwrap();
                std::thread::sleep(Duration::from_secs(2));
            } else if mode == "check_host_rights" {
                let value: usize = marker.to_str().unwrap().parse().unwrap();
                let denied = pipe
                    .test_duplicate_host_handle(value)
                    .err()
                    .and_then(|error| error.raw_os_error())
                    == Some(windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED as i32);
                pipe.send(
                    crate::protocol::Kind::Result,
                    if denied { b"denied" } else { b"allowed" },
                    Duration::from_secs(5),
                    &|| false,
                )
                .unwrap();
                std::thread::sleep(Duration::from_secs(2));
            } else if mode == "pipe_stall" || mode == "pipe_reject" || mode == "pipe_abandon" {
                let (kind, body) = pipe.receive(Duration::from_secs(5), &|| false).unwrap();
                assert_eq!(kind, crate::protocol::Kind::Pipe);
                if mode == "pipe_abandon" {
                    let remote = u64::from_le_bytes(body.try_into().unwrap()) as usize as HANDLE;
                    let mut duplicate = null_mut();
                    // SAFETY: test input names the temporary handle in this
                    // process, output is writable, and success returns a new
                    // independently owned non-inheritable handle.
                    assert_ne!(
                        unsafe {
                            DuplicateHandle(
                                GetCurrentProcess(),
                                remote,
                                GetCurrentProcess(),
                                &mut duplicate,
                                0,
                                0,
                                DUPLICATE_SAME_ACCESS,
                            )
                        },
                        0
                    );
                    let duplicate = handle(duplicate).unwrap();
                    pipe.send(
                        crate::protocol::Kind::PipeAck,
                        &[],
                        Duration::from_secs(5),
                        &|| false,
                    )
                    .unwrap();
                    drop(duplicate);
                    let (kind, _) = pipe.receive(Duration::from_secs(5), &|| false).unwrap();
                    assert_eq!(kind, crate::protocol::Kind::PipeDone);
                } else if mode == "pipe_reject" {
                    pipe.send(
                        crate::protocol::Kind::PipeAck,
                        b"bad",
                        Duration::from_secs(5),
                        &|| false,
                    )
                    .unwrap();
                }
                std::fs::write(&marker, "offered").unwrap();
                std::thread::sleep(Duration::from_secs(10));
            } else if mode == "pipe_transfer"
                || mode == "pipe_transfer_delayed"
                || mode == "pipe_transfer_immediate"
            {
                use std::io::Write as _;
                if mode == "pipe_transfer_delayed" {
                    std::thread::sleep(Duration::from_millis(300));
                }
                let mut output = pipe
                    .receive_pipe(Duration::from_secs(5), &|| false)
                    .unwrap();
                let mut flags = 0;
                // SAFETY: output is live and flags is writable.
                assert_ne!(
                    unsafe {
                        windows_sys::Win32::Foundation::GetHandleInformation(
                            output.as_raw_handle(),
                            &mut flags,
                        )
                    },
                    0
                );
                assert_eq!(
                    flags & windows_sys::Win32::Foundation::HANDLE_FLAG_INHERIT,
                    0
                );
                output.write_all(b"pipe transfer").unwrap();
                drop(output);
                if mode != "pipe_transfer_immediate" {
                    std::thread::sleep(Duration::from_secs(2));
                }
            } else if mode == "malformed_frame" {
                pipe.test_send_raw(b"NWJ2\x01\0\0\0\0").unwrap();
                std::fs::write(&marker, "malformed").unwrap();
                std::thread::sleep(Duration::from_secs(10));
            } else if mode == "partial_header" || mode == "partial_body" {
                let frame =
                    crate::protocol::encode(crate::protocol::Kind::Request, b"123456").unwrap();
                let length = if mode == "partial_header" { 4 } else { 11 };
                pipe.test_send_raw(&frame[..length]).unwrap();
                std::fs::write(&marker, "partial").unwrap();
                std::thread::sleep(Duration::from_secs(10));
            } else if mode == "pipe_frame" {
                let (kind, body) = pipe.receive(Duration::from_secs(5), &|| false).unwrap();
                assert_eq!(kind, crate::protocol::Kind::Request);
                pipe.send(
                    crate::protocol::Kind::Result,
                    &body,
                    Duration::from_secs(5),
                    &|| false,
                )
                .unwrap();
                std::thread::sleep(Duration::from_secs(2));
            } else {
                std::thread::sleep(Duration::from_secs(10));
            }
        } else if mode == "hold" {
            std::thread::sleep(Duration::from_secs(10));
        } else if mode == "isolated_driver" {
            let executable = std::env::current_exe().unwrap();
            let directory = std::env::temp_dir();
            let environment = BTreeMap::from([
                ("NEOENV_JOB_TEST_MODE".into(), "isolated_leaf".into()),
                (
                    "NEOENV_JOB_TEST_MARKER".into(),
                    marker.to_str().unwrap().into(),
                ),
            ]);
            let arguments = vec![
                "--exact".into(),
                "windows::tests::helper".into(),
                "--nocapture".into(),
            ];
            let _child = Child::spawn_isolated_launcher(&Spawn {
                executable: &executable,
                arguments: &arguments,
                environment: &environment,
                directory: &directory,
                inherit_stdin: false,
            })
            .unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            while !std::path::Path::new(&marker).exists() {
                assert!(Instant::now() < deadline, "isolated child failed to start");
                std::thread::sleep(Duration::from_millis(10));
            }
            // Bypass Rust destructors to exercise kernel handle cleanup.
            std::process::exit(0);
        } else if mode == "isolated_leaf" {
            // SAFETY: GetStdHandle returns borrowed values and takes no pointers.
            let handles = unsafe {
                [
                    GetStdHandle(STD_INPUT_HANDLE),
                    GetStdHandle(STD_OUTPUT_HANDLE),
                    GetStdHandle(STD_ERROR_HANDLE),
                ]
            };
            let no_stdio = handles
                .iter()
                .all(|h| h.is_null() || *h == INVALID_HANDLE_VALUE);
            std::fs::write(
                &marker,
                if no_stdio {
                    "ready"
                } else {
                    "unexpected stdio"
                },
            )
            .unwrap();
            std::thread::sleep(Duration::from_secs(2));
            std::fs::write(&marker, "escaped").unwrap();
        } else if mode == "driver" {
            let executable = std::env::current_exe().unwrap();
            let directory = std::env::temp_dir();
            let environment = BTreeMap::from([
                ("NEOENV_JOB_TEST_MODE".into(), "roundtrip".into()),
                (
                    "NEOENV_JOB_TEST_MARKER".into(),
                    marker.to_str().unwrap().into(),
                ),
            ]);
            let arguments = vec![
                "--exact".into(),
                "windows::tests::helper".into(),
                "--nocapture".into(),
                "--skip".into(),
                "quoted space\\\"tail\\".into(),
            ];
            let child = Child::spawn_unisolated(&Spawn {
                executable: &executable,
                arguments: &arguments,
                environment: &environment,
                directory: &directory,
                inherit_stdin: false,
            })
            .unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if let Some(code) = child.try_wait().unwrap() {
                    assert_eq!(code, 0);
                    child.terminate().unwrap();
                    break;
                }
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(10));
            }
        } else if mode == "roundtrip" {
            let args: Vec<_> = std::env::args().collect();
            let argument = args.iter().position(|arg| arg == "--skip").unwrap();
            std::fs::write(&marker, &args[argument + 1]).unwrap();
            println!("NEOENV_STDOUT_ROUNDTRIP");
            eprintln!("NEOENV_STDERR_ROUNDTRIP");
        } else if mode == "leader" {
            let mut grandchild = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "windows::tests::helper", "--nocapture"])
                .env("NEOENV_JOB_TEST_MODE", "grandchild")
                .spawn()
                .unwrap();
            grandchild.wait().unwrap();
        } else if mode != "exit_early" {
            std::fs::write(&marker, "ready").unwrap();
            std::thread::sleep(Duration::from_secs(2));
            std::fs::write(&marker, "escaped").unwrap();
        }
    }

    #[test]
    fn arguments_and_stdio_round_trip_through_driver_process() {
        let directory =
            std::env::temp_dir().join(format!("neoenv-roundtrip-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let marker = directory.join("argument");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "windows::tests::helper", "--nocapture"])
            .env_clear()
            .env("NEOENV_JOB_TEST_MODE", "driver")
            .env("NEOENV_JOB_TEST_MARKER", &marker)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "driver failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            "quoted space\\\"tail\\"
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("NEOENV_STDOUT_ROUNDTRIP"));
        assert!(String::from_utf8_lossy(&output.stderr).contains("NEOENV_STDERR_ROUNDTRIP"));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn isolated_launcher_is_killed_when_host_exits_without_destructors() {
        let directory = std::env::temp_dir().join(format!("neoenv-crash-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let marker = directory.join("marker");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "windows::tests::helper", "--nocapture"])
            .env_clear()
            .env("NEOENV_JOB_TEST_MODE", "isolated_driver")
            .env("NEOENV_JOB_TEST_MARKER", &marker)
            .status()
            .unwrap();
        assert!(status.success());
        std::thread::sleep(Duration::from_millis(2200));
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "ready");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn isolated_launcher_cancellation_terminates_it() {
        let directory =
            std::env::temp_dir().join(format!("neoenv-isolated-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let marker = directory.join("marker");
        let executable = std::env::current_exe().unwrap();
        let environment = BTreeMap::from([
            ("NEOENV_JOB_TEST_MODE".into(), "isolated_leaf".into()),
            (
                "NEOENV_JOB_TEST_MARKER".into(),
                marker.to_str().unwrap().into(),
            ),
        ]);
        let arguments = vec![
            "--exact".into(),
            "windows::tests::helper".into(),
            "--nocapture".into(),
        ];
        let child = Child::spawn_isolated_launcher(&Spawn {
            executable: &executable,
            arguments: &arguments,
            environment: &environment,
            directory: &directory,
            inherit_stdin: false,
        })
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !marker.exists() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        child.terminate().unwrap();
        assert!(
            child.try_wait().unwrap().is_some(),
            "terminate returned before the process handle was signalled"
        );
        std::thread::sleep(Duration::from_millis(2200));
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "ready");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn quotes_backslashes_and_quotes() {
        let mut result = Vec::new();
        quote(OsStr::new("a b\\\"c\\"), &mut result).unwrap();
        assert_eq!(String::from_utf16(&result).unwrap(), "\"a b\\\\\\\"c\\\\\"");
    }

    #[test]
    fn environment_preserves_windows_drive_pseudo_variables() {
        let environment = BTreeMap::from([
            ("=C:".to_owned(), r"C:\work".to_owned()),
            ("NEOENV_ENV".to_owned(), "handoff".to_owned()),
        ]);
        let block = environment_block(&environment).unwrap();
        let text = String::from_utf16(&block).unwrap();
        assert!(text.contains("=C:=C:\\work\0"), "{text:?}");
        assert!(text.ends_with("\0\0"));
        assert!(environment_block(&BTreeMap::from([("BAD=NAME".into(), "x".into())])).is_err());
    }

    #[test]
    fn canonical_current_directory_is_converted_when_equivalent() {
        let canonical = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let value = directory_utf16(&canonical).unwrap();
        let result = String::from_utf16(&value[..value.len() - 1]).unwrap();
        assert!(
            !result.starts_with(r"\\?\"),
            "ordinary temporary directory should not retain verbatim prefix"
        );
        assert_eq!(std::fs::canonicalize(result).unwrap(), canonical);
    }

    #[test]
    fn rejects_duplicate_case_insensitive_environment_names() {
        let environment =
            BTreeMap::from([("Path".into(), "one".into()), ("PATH".into(), "two".into())]);
        assert!(environment_block(&environment).is_err());
    }

    #[test]
    fn cancellation_terminates_grandchild() {
        let dir = std::env::temp_dir().join(format!(
            "neoenv-job-{}-{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("marker");
        let environment = BTreeMap::from([
            ("NEOENV_JOB_TEST_MODE".into(), "leader".into()),
            (
                "NEOENV_JOB_TEST_MARKER".into(),
                marker.to_str().unwrap().into(),
            ),
        ]);
        let exe = std::env::current_exe().unwrap();
        let arguments = vec![
            "--exact".into(),
            "windows::tests::helper".into(),
            "--nocapture".into(),
        ];
        let child = Child::spawn_unisolated(&Spawn {
            executable: &exe,
            arguments: &arguments,
            environment: &environment,
            directory: &dir,
            inherit_stdin: false,
        })
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !marker.exists() {
            assert!(Instant::now() < deadline, "grandchild failed to start");
            std::thread::sleep(Duration::from_millis(10));
        }
        child.terminate().unwrap();
        std::thread::sleep(Duration::from_millis(2200));
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "ready");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_executable_fails_before_any_user_code() {
        let exe = std::env::temp_dir().join("neoenv-definitely-missing-executable.exe");
        let environment = BTreeMap::new();
        let args = Vec::new();
        assert!(
            Child::spawn_unisolated(&Spawn {
                executable: &exe,
                arguments: &args,
                environment: &environment,
                directory: &std::env::temp_dir(),
                inherit_stdin: false
            })
            .is_err()
        );
    }

    #[test]
    fn public_spawn_is_disabled_even_with_valid_executable() {
        let exe = std::env::current_exe().unwrap();
        let directory = std::env::temp_dir();
        let environment = BTreeMap::new();
        let args = Vec::new();
        let error = Child::spawn(&Spawn {
            executable: &exe,
            arguments: &args,
            environment: &environment,
            directory: &directory,
            inherit_stdin: false,
        })
        .err()
        .expect("launch must remain disabled");
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn rejects_batch_file_in_private_launcher() {
        let exe = std::env::temp_dir().join("unsafe.cmd");
        let directory = std::env::temp_dir();
        let environment = BTreeMap::new();
        let args = Vec::new();
        let error = Child::spawn_unisolated(&Spawn {
            executable: &exe,
            arguments: &args,
            environment: &environment,
            directory: &directory,
            inherit_stdin: false,
        })
        .err()
        .expect("batch file must be refused");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
