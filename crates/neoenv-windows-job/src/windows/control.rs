//! Control-channel bootstrap. Only static handshake bytes precede mutual auth.

use super::{Child, PipeReader, PipeWriter, handle, raw, utf16};
use std::{
    ffi::OsStr,
    io,
    mem::zeroed,
    os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, OwnedHandle},
    ptr::{null, null_mut},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_BROKEN_PIPE,
        ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING, FILETIME,
        GENERIC_READ, GENERIC_WRITE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_TYPE_PIPE, GetFileType, OPEN_EXISTING,
        PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
    },
    System::{
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
            GetNamedPipeServerProcessId, PIPE_NOWAIT, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
            SetNamedPipeHandleState,
        },
        Threading::{
            GetCurrentProcess, GetCurrentProcessId, GetProcessId, GetProcessTimes, OpenProcess,
            PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, WaitForSingleObject,
        },
    },
};

static NEXT_PIPE: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
thread_local! {
    static FAIL_TRANSFER_CLEANUP: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_REMOTE_CLOSE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static TRANSFER_DUP_ATTEMPTS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    // Per-thread fault injection for a deterministic partial-frame test.
    static TEST_WRITE_LIMIT: std::cell::Cell<usize> = const { std::cell::Cell::new(usize::MAX) };
    static TEST_WRITE_PROGRESS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
const CLIENT_HELLO: &[u8] =
    concat!("NWJ1 CLIENT VERIFIED ", env!("CARGO_PKG_VERSION"), "\n").as_bytes();
const SERVER_HELLO: &[u8] =
    concat!("NWJ1 SERVER VERIFIED ", env!("CARGO_PKG_VERSION"), "\n").as_bytes();

fn validate_pipe_name(name: &str) -> io::Result<()> {
    let valid = name
        .strip_prefix(r"\\.\pipe\neoenv-owned-")
        .and_then(|tail| tail.split_once('-'))
        .and_then(|(pid, seq)| Some((pid, seq, pid.parse::<u32>().ok()?, seq.parse::<u64>().ok()?)))
        .is_some_and(|(pid_text, seq_text, pid, seq)| {
            pid != 0 && pid_text == pid.to_string() && seq_text == seq.to_string()
        });
    if valid {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid local control pipe name",
        ))
    }
}

/// Host PID and process creation time, captured by the host and passed as
/// non-secret startup arguments to its freshly created launcher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostIdentity {
    pub pid: u32,
    pub creation_time: u64,
}

impl HostIdentity {
    /// Capture the identity of this process while it is alive.
    pub fn current() -> io::Result<Self> {
        // SAFETY: these functions return valid current-process identifiers.
        let (process, pid) = unsafe { (GetCurrentProcess(), GetCurrentProcessId()) };
        Ok(Self {
            pid,
            creation_time: creation_time(process)?,
        })
    }
}

fn creation_time(process: windows_sys::Win32::Foundation::HANDLE) -> io::Result<u64> {
    // SAFETY: zero is valid for FILETIME PODs; all four outputs are writable.
    let (mut created, mut exited, mut kernel, mut user): (FILETIME, FILETIME, FILETIME, FILETIME) =
        unsafe { (zeroed(), zeroed(), zeroed(), zeroed()) };
    // SAFETY: process is a live valid handle supplied by the caller.
    if unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

/// Launcher side of the experimental control connection.
///
/// This uses the same threat model as [`ControlListener`]: an attacker able
/// to duplicate handles from either peer or rewrite either process is excluded.
pub struct ControlClient {
    pipe: OwnedHandle,
    host: OwnedHandle,
    usable: bool,
}

impl ControlClient {
    #[allow(dead_code)] // Used by the isolated binary's launcher implementation.
    pub(super) fn host_running(&self) -> io::Result<bool> {
        match ensure_process_running(&self.host) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => return Ok(false),
            Err(error) => return Err(error),
        }
        let mut available = 0;
        // SAFETY: pipe is a live handle; available is writable and all other
        // optional outputs are null. This observes disconnect without reading.
        if unsafe {
            windows_sys::Win32::System::Pipes::PeekNamedPipe(
                raw(&self.pipe),
                null_mut(),
                0,
                null_mut(),
                &mut available,
                null_mut(),
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                return Ok(false);
            }
            return Err(error);
        }
        if available != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected launcher control input",
            ));
        }
        Ok(true)
    }

    #[cfg(test)]
    pub(super) fn test_duplicate_host_handle(&self, value: usize) -> io::Result<()> {
        let mut target = null_mut();
        // SAFETY: host is retained, value is interpreted in that process,
        // and target is writable. The test expects access to be denied.
        if unsafe {
            DuplicateHandle(
                raw(&self.host),
                value as _,
                GetCurrentProcess(),
                &mut target,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        drop(handle(target)?);
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn test_send_raw(&mut self, bytes: &[u8]) -> io::Result<()> {
        write_all(
            &self.pipe,
            bytes,
            deadline(Duration::from_secs(3))?,
            &|| false,
            || ensure_process_running(&self.host),
        )
    }

    /// Open the named pipe and verify its server against the host's retained
    /// process identity before sending the fixed non-secret handshake.
    ///
    /// `identity` and `name` must come from the launcher's original trusted
    /// command line, not from the pipe. This does not defend against another
    /// process that can rewrite either peer or duplicate either peer's handles;
    /// see [`ControlListener`] for the shared threat model. `CreateFileW` is
    /// synchronous, so a blocked OS or driver call cannot be interrupted by
    /// this method's deadline or cancellation callback.
    pub fn connect(
        name: &str,
        identity: HostIdentity,
        timeout: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<Self> {
        validate_pipe_name(name)?;
        let deadline = deadline(timeout)?;
        // SAFETY: OpenProcess returns a new non-inheritable handle or null.
        let host = handle(unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                identity.pid,
            )
        })?;
        ensure_process_running(&host)?;
        if creation_time(raw(&host))? != identity.creation_time {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "host identity mismatch",
            ));
        }
        let name = utf16(OsStr::new(name))?;
        let pipe = loop {
            check_deadline(deadline, cancelled)?;
            ensure_process_running(&host)?;
            // SAFETY: name is NUL-terminated; null security attributes make
            // the opened handle non-inheritable.
            let result = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    null(),
                    OPEN_EXISTING,
                    0,
                    null_mut(),
                )
            };
            match handle(result) {
                Ok(pipe) => break pipe,
                Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(error) => return Err(error),
            }
        };
        let mut server = 0;
        // SAFETY: pipe is a live connected pipe; server is writable.
        if unsafe { GetNamedPipeServerProcessId(raw(&pipe), &mut server) } == 0 {
            return Err(io::Error::last_os_error());
        }
        ensure_process_running(&host)?;
        if server != identity.pid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unexpected control server",
            ));
        }
        let mode = PIPE_NOWAIT;
        // SAFETY: mode is a live value; other optional parameters are null.
        if unsafe { SetNamedPipeHandleState(raw(&pipe), &mode, null(), null()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        write_all(&pipe, CLIENT_HELLO, deadline, cancelled, || {
            ensure_process_running(&host)
        })?;
        let mut response = [0u8; SERVER_HELLO.len()];
        read_exact(&pipe, &mut response, deadline, cancelled, || {
            ensure_process_running(&host)
        })?;
        if response != SERVER_HELLO {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid server handshake",
            ));
        }
        Ok(Self {
            pipe,
            host,
            usable: true,
        })
    }
}

/// One local, non-inheritable named-pipe instance. No secret data is written
/// to it before the client has been authenticated.
///
/// Null security attributes use Windows' default named-pipe security
/// descriptor, not an owner-only ACL. Remote clients are rejected, but a
/// permitted local process can connect first and deny service.
///
/// PID checks do not protect against an attacker able to duplicate handles
/// from either peer, or rewrite either peer. Such attackers are excluded from
/// the experimental protocol's threat model.
pub struct ControlListener {
    pipe: OwnedHandle,
    name: String,
}

/// Authenticated pipe, tied to the lifetime of the retained launcher handle.
///
/// Bounded frame send/receive and a pipe-only transfer operation are exposed
/// under the experimental threat model described by [`ControlListener`].
pub struct VerifiedControl<'a> {
    pipe: OwnedHandle,
    launcher: &'a Child,
    usable: bool,
}

impl ControlListener {
    /// Create a single local pipe instance, before starting the launcher.
    ///
    /// A predictable name is not an authentication token. A local attacker
    /// can deny service by connecting first, but receives no protocol bytes.
    pub fn new() -> io::Result<Self> {
        // SAFETY: GetCurrentProcessId has no arguments or memory effects.
        let pid = unsafe { GetCurrentProcessId() };
        let seq = NEXT_PIPE.fetch_add(1, Ordering::Relaxed);
        let name = format!(r"\\.\pipe\neoenv-owned-{pid}-{seq}");
        let wide = utf16(OsStr::new(&name))?;
        // SAFETY: name is a live NUL-terminated buffer. Null security
        // attributes make this server handle non-inheritable. FIRST_INSTANCE
        // rejects a pre-existing server; remote clients are explicitly refused.
        let pipe = handle(unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                4096,
                4096,
                0,
                null(),
            )
        })?;
        Ok(Self { pipe, name })
    }

    /// Non-secret pipe name for the launcher. Possession is not authorization.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Wait for the retained launcher's connection, bounded by timeout and
    /// cancellation. An unexpected peer is rejected without receiving data.
    /// The caller retains ownership of the launcher and must terminate it on
    /// error (dropping it closes its kill-on-close job).
    pub fn authenticate<'a>(
        self,
        launcher: &'a Child,
        timeout: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<VerifiedControl<'a>> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "timeout overflow"))?;
        // SAFETY: launcher owns this valid process handle for the borrow.
        let expected = unsafe { GetProcessId(raw(&launcher.process)) };
        if expected == 0 {
            return Err(io::Error::last_os_error());
        }
        loop {
            if cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "control startup cancelled",
                ));
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "control startup timed out",
                ));
            }
            ensure_running(launcher)?;
            // SAFETY: the server pipe is valid and configured PIPE_NOWAIT; a
            // null OVERLAPPED selects the synchronous nonblocking operation.
            let connected = unsafe { ConnectNamedPipe(raw(&self.pipe), null_mut()) };
            if connected == 0 {
                let error = io::Error::last_os_error();
                match error.raw_os_error().map(|code| code as u32) {
                    Some(ERROR_PIPE_LISTENING) => {
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Some(ERROR_PIPE_CONNECTED) => {}
                    _ => return Err(error),
                }
            }
            let mut actual = 0;
            // SAFETY: pipe is connected and actual is writable; the returned
            // PID identifies the process that established this pipe connection.
            if unsafe { GetNamedPipeClientProcessId(raw(&self.pipe), &mut actual) } == 0 {
                return Err(io::Error::last_os_error());
            }
            // The retained process must be live on both sides of the PID query;
            // this rejects PID reuse after launcher exit.
            ensure_running(launcher)?;
            if actual != expected {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unexpected control client",
                ));
            }
            let mut hello = [0u8; CLIENT_HELLO.len()];
            read_exact(&self.pipe, &mut hello, deadline, cancelled, || {
                ensure_running(launcher)
            })?;
            if hello != CLIENT_HELLO {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid client handshake",
                ));
            }
            write_all(&self.pipe, SERVER_HELLO, deadline, cancelled, || {
                ensure_running(launcher)
            })?;
            return Ok(VerifiedControl {
                pipe: self.pipe,
                launcher,
                usable: true,
            });
        }
    }
}

fn ensure_running(launcher: &Child) -> io::Result<()> {
    ensure_process_running(&launcher.process)
}

fn terminate_failed_transfer(launcher: &Child) -> io::Result<()> {
    #[cfg(test)]
    if FAIL_TRANSFER_CLEANUP.with(std::cell::Cell::get) {
        return Err(io::Error::other("injected termination failure"));
    }
    launcher.terminate()
}

fn ensure_process_running(process: &OwnedHandle) -> io::Result<()> {
    // SAFETY: launcher retains this valid process handle for the whole call.
    match unsafe { WaitForSingleObject(raw(process), 0) } {
        WAIT_TIMEOUT => Ok(()),
        WAIT_OBJECT_0 => Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "launcher exited during control startup",
        )),
        _ => Err(io::Error::last_os_error()),
    }
}

fn deadline(timeout: Duration) -> io::Result<Instant> {
    Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "timeout overflow"))
}

fn check_deadline(deadline: Instant, cancelled: &dyn Fn() -> bool) -> io::Result<()> {
    if cancelled() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "control operation cancelled",
        ));
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "control operation timed out",
        ));
    }
    Ok(())
}

fn read_exact(
    pipe: &OwnedHandle,
    data: &mut [u8],
    until: Instant,
    cancelled: &dyn Fn() -> bool,
    live: impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < data.len() {
        check_deadline(until, cancelled)?;
        live()?;
        let mut count = 0;
        // SAFETY: the pipe is nonblocking and the remaining buffer is valid
        // writable storage; count is a valid output.
        let success = unsafe {
            ReadFile(
                raw(pipe),
                data[offset..].as_mut_ptr(),
                (data.len() - offset) as u32,
                &mut count,
                null_mut(),
            )
        };
        if success == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NO_DATA as i32) {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            return Err(error);
        }
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "control peer closed",
            ));
        }
        offset += count as usize;
    }
    Ok(())
}

// Read a complete frame without a fixed wall-clock ceiling. Cancellation is
// polled between every nonblocking read, including partial progress.
fn read_exact_until_cancelled(
    pipe: &OwnedHandle,
    data: &mut [u8],
    cancelled: &dyn Fn() -> bool,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < data.len() {
        if cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "control receive cancelled",
            ));
        }
        let mut count = 0;
        // SAFETY: the pipe is nonblocking and the output buffer is live.
        let ok = unsafe {
            ReadFile(
                raw(pipe),
                data[offset..].as_mut_ptr(),
                (data.len() - offset) as u32,
                &mut count,
                null_mut(),
            )
        };
        if ok == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NO_DATA as i32) {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            return Err(error);
        }
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "control peer closed",
            ));
        }
        offset += count as usize;
    }
    Ok(())
}

fn write_all(
    pipe: &OwnedHandle,
    data: &[u8],
    until: Instant,
    cancelled: &dyn Fn() -> bool,
    live: impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < data.len() {
        check_deadline(until, cancelled)?;
        live()?;
        let mut count = 0;
        #[cfg(test)]
        let length = (data.len() - offset).min(TEST_WRITE_LIMIT.with(std::cell::Cell::get));
        #[cfg(not(test))]
        let length = data.len() - offset;
        // SAFETY: the pipe is nonblocking, input is live, and count is writable.
        let success = unsafe {
            WriteFile(
                raw(pipe),
                data[offset..].as_ptr(),
                length as u32,
                &mut count,
                null_mut(),
            )
        };
        if success == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NO_DATA as i32) {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            return Err(error);
        }
        if count == 0 {
            std::thread::sleep(Duration::from_millis(10));
        }
        offset += count as usize;
        #[cfg(test)]
        TEST_WRITE_PROGRESS.with(|progress| progress.set(progress.get() + count as usize));
    }
    Ok(())
}

fn send_frame(
    pipe: &OwnedHandle,
    kind: crate::protocol::Kind,
    body: &[u8],
    timeout: Duration,
    cancelled: &dyn Fn() -> bool,
    live: impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    let frame = crate::protocol::encode(kind, body)?;
    write_all(pipe, &frame, deadline(timeout)?, cancelled, live)
}

fn receive_frame(
    pipe: &OwnedHandle,
    timeout: Duration,
    cancelled: &dyn Fn() -> bool,
    live: impl Fn() -> io::Result<()>,
) -> io::Result<(crate::protocol::Kind, Vec<u8>)> {
    let until = deadline(timeout)?;
    let mut bytes = vec![0u8; 9];
    read_exact(pipe, &mut bytes, until, cancelled, &live)?;
    // Decode validates the header, including the body limit, before allocation.
    if let Some((kind, body, _)) = crate::protocol::decode(&bytes)? {
        return Ok((kind, body.to_vec()));
    }
    let length = u32::from_le_bytes(bytes[5..9].try_into().expect("fixed header")) as usize;
    bytes.resize(9 + length, 0);
    read_exact(pipe, &mut bytes[9..], until, cancelled, live)?;
    let (kind, body, _) = crate::protocol::decode(&bytes)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete control frame"))?;
    Ok((kind, body.to_vec()))
}

impl VerifiedControl<'_> {
    /// Duplicate an adapter-created pipe writer into the launcher and wait
    /// until it has made its own non-inheritable duplicate and the temporary
    /// launcher-side handle is closed. The source borrow remains live through
    /// acknowledgement and completion.
    ///
    /// A failure after transfer starts attempts to terminate the launcher job
    /// and reports cleanup failure; a panic triggers best-effort termination.
    /// Ownership may already have crossed the process boundary.
    ///
    /// Socket handles cannot be passed as pipe writers:
    /// ```compile_fail
    /// # use neoenv_windows_job::VerifiedControl;
    /// # use std::{net::TcpStream, time::Duration};
    /// # fn reject(control: &mut VerifiedControl<'_>, socket: &TcpStream) {
    /// control.send_pipe(socket, Duration::from_secs(1), &|| false).unwrap();
    /// # }
    /// ```
    pub fn send_pipe(
        &mut self,
        pipe: &PipeWriter,
        timeout: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<()> {
        self.send_pipe_handle(pipe.0.as_handle(), timeout, cancelled)
    }

    /// Offer the read end of an adapter-created anonymous pipe. This is for a
    /// future isolated output proxy; arbitrary handles and sockets are refused
    /// by the type signature.
    ///
    /// ```compile_fail
    /// # use neoenv_windows_job::VerifiedControl;
    /// # use std::{net::TcpStream, time::Duration};
    /// # fn reject(control: &mut VerifiedControl<'_>, socket: &TcpStream) {
    /// control.send_pipe_reader(socket, Duration::from_secs(1), &|| false).unwrap();
    /// # }
    /// ```
    pub fn send_pipe_reader(
        &mut self,
        pipe: &PipeReader,
        timeout: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<()> {
        self.send_pipe_handle(pipe.0.as_handle(), timeout, cancelled)
    }

    /// Transfer only a validated duplicate of a standard pipe or disk output
    /// to an isolated forwarding process. Never transfers the original handle.
    pub fn send_forward_destination(
        &mut self,
        destination: &super::ForwardDestination,
        timeout: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<()> {
        use std::os::windows::io::AsHandle;
        self.send_pipe_handle(destination.handle().as_handle(), timeout, cancelled)
    }

    fn send_pipe_handle(
        &mut self,
        source: BorrowedHandle<'_>,
        timeout: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<()> {
        if !self.usable {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "control connection is poisoned",
            ));
        }
        struct TransferGuard<'a> {
            launcher: &'a Child,
            armed: bool,
        }
        impl Drop for TransferGuard<'_> {
            fn drop(&mut self) {
                if self.armed {
                    let _ = self.launcher.terminate();
                }
            }
        }
        let end = deadline(timeout)?;
        check_deadline(end, cancelled)?;
        let mut guard = TransferGuard {
            launcher: self.launcher,
            armed: true,
        };
        let result = (|| {
            let mut remote = null_mut();
            #[cfg(test)]
            TRANSFER_DUP_ATTEMPTS.with(|count| count.set(count.get() + 1));
            // SAFETY: source is borrowed for this whole operation; launcher
            // is a retained process handle with duplicate rights. The new
            // launcher handle is explicitly non-inheritable.
            if unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    source.as_raw_handle(),
                    raw(&guard.launcher.process),
                    &mut remote,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            let value = (remote as usize as u64).to_le_bytes();
            self.send(
                crate::protocol::Kind::Pipe,
                &value,
                end.saturating_duration_since(Instant::now()),
                cancelled,
            )?;
            let (kind, body) =
                self.receive(end.saturating_duration_since(Instant::now()), cancelled)?;
            if kind != crate::protocol::Kind::PipeAck || !body.is_empty() {
                self.usable = false;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid pipe acknowledgement",
                ));
            }
            // The isolated launcher has acknowledged making its own duplicate
            // and must not close or reuse the original before this operation.
            let mut local = null_mut();
            // SAFETY: the source handle was created above in this retained
            // process. The authenticated launcher protocol promises not to
            // close it before ACK; this call closes it and creates a temporary
            // local duplicate that we immediately own and drop.
            #[cfg(test)]
            if FAIL_REMOTE_CLOSE.with(std::cell::Cell::get) {
                return Err(io::Error::other("injected remote-close failure"));
            }
            if unsafe {
                DuplicateHandle(
                    raw(&guard.launcher.process),
                    remote,
                    GetCurrentProcess(),
                    &mut local,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            drop(handle(local)?);
            self.send(
                crate::protocol::Kind::PipeDone,
                &[],
                end.saturating_duration_since(Instant::now()),
                cancelled,
            )?;
            let (kind, body) = self.receive_pipe_confirmation(
                end.saturating_duration_since(Instant::now()),
                cancelled,
            )?;
            if kind != crate::protocol::Kind::PipeConfirm || !body.is_empty() {
                self.usable = false;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid pipe transfer confirmation",
                ));
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                guard.armed = false;
                Ok(())
            }
            Err(primary) => {
                self.usable = false;
                match terminate_failed_transfer(guard.launcher) {
                    Ok(()) => {
                        guard.armed = false;
                        Err(primary)
                    }
                    Err(cleanup) => Err(io::Error::other(format!(
                        "pipe transfer failed ({primary}); launcher cleanup failed ({cleanup}); launcher may retain pipe authority"
                    ))),
                }
            }
        }
    }

    // A launcher may exit immediately after confirming. Drain an already
    // buffered confirmation rather than rejecting it solely because its
    // process handle is signalled. Pipe EOF and the absolute deadline still
    // bound this wait.
    fn receive_pipe_confirmation(
        &mut self,
        timeout: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<(crate::protocol::Kind, Vec<u8>)> {
        if !self.usable {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "control connection is poisoned",
            ));
        }
        self.usable = false;
        let result = receive_frame(&self.pipe, timeout, cancelled, || Ok(()));
        if result.is_ok() {
            self.usable = true;
        }
        result
    }

    /// Send a frame. On any error drop this connection; it may be partially written.
    pub fn send(
        &mut self,
        kind: crate::protocol::Kind,
        body: &[u8],
        timeout: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<()> {
        if !self.usable {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "control connection is poisoned",
            ));
        }
        self.usable = false;
        let result = send_frame(&self.pipe, kind, body, timeout, cancelled, || {
            ensure_running(self.launcher)
        });
        if result.is_ok() {
            self.usable = true;
        }
        result
    }
    /// Receive without a fixed deadline, polling caller cancellation. A partial
    /// frame poisons the channel on error, just like `receive`.
    pub fn receive_until_cancelled(
        &mut self,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<(crate::protocol::Kind, Vec<u8>)> {
        if !self.usable {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "control connection is poisoned",
            ));
        }
        self.usable = false;
        let result = (|| {
            let mut bytes = vec![0u8; 9];
            read_exact_until_cancelled(&self.pipe, &mut bytes, cancelled)?;
            if let Some((kind, body, _)) = crate::protocol::decode(&bytes)? {
                return Ok((kind, body.to_vec()));
            }
            let length = u32::from_le_bytes(bytes[5..9].try_into().expect("fixed header")) as usize;
            bytes.resize(9 + length, 0);
            read_exact_until_cancelled(&self.pipe, &mut bytes[9..], cancelled)?;
            let (kind, body, _) = crate::protocol::decode(&bytes)?.ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete control frame")
            })?;
            Ok((kind, body.to_vec()))
        })();
        if result.is_ok() {
            self.usable = true;
        }
        result
    }

    /// Receive a frame. On any error drop this connection; it may be partially read.
    pub fn receive(
        &mut self,
        timeout: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<(crate::protocol::Kind, Vec<u8>)> {
        if !self.usable {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "control connection is poisoned",
            ));
        }
        self.usable = false;
        // Drain a fully written result even when the launcher has just exited.
        // Pipe EOF and the deadline bound failures; the server handle is not
        // inherited by the launcher or its task.
        let result = receive_frame(&self.pipe, timeout, cancelled, || Ok(()));
        if result.is_ok() {
            self.usable = true;
        }
        result
    }
}

impl ControlClient {
    /// Duplicate an offered launcher-local pipe handle without inheritance.
    /// Wait for the host to close its temporary duplicate before returning.
    pub fn receive_pipe(
        &mut self,
        timeout: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<std::fs::File> {
        self.receive_handle(timeout, cancelled, false)
    }

    /// Receive a validated output handle in the isolated forwarding process.
    pub fn receive_forward_destination(
        &mut self,
        timeout: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<std::fs::File> {
        self.receive_handle(timeout, cancelled, true)
    }

    fn receive_handle(
        &mut self,
        timeout: Duration,
        cancelled: &dyn Fn() -> bool,
        allow_disk: bool,
    ) -> io::Result<std::fs::File> {
        let end = deadline(timeout)?;
        let (kind, body) =
            self.receive(end.saturating_duration_since(Instant::now()), cancelled)?;
        if kind != crate::protocol::Kind::Pipe || body.len() != 8 {
            self.usable = false;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid pipe offer",
            ));
        }
        let number = u64::from_le_bytes(body.try_into().expect("checked length"));
        let value = match usize::try_from(number) {
            Ok(value) => value,
            Err(_) => {
                self.usable = false;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid pipe value",
                ));
            }
        };
        let mut target = null_mut();
        // SAFETY: the offered value is interpreted in this process. Windows
        // validates it; a successful call returns a new independently owned,
        // explicitly non-inheritable handle. The original is not closed here.
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                value as _,
                GetCurrentProcess(),
                &mut target,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            self.usable = false;
            return Err(io::Error::last_os_error());
        }
        let target = match handle(target) {
            Ok(target) => target,
            Err(error) => {
                self.usable = false;
                return Err(error);
            }
        };
        // SAFETY: target is a newly owned valid handle.
        let kind = unsafe { GetFileType(raw(&target)) };
        if kind != FILE_TYPE_PIPE
            && !(allow_disk && kind == windows_sys::Win32::Storage::FileSystem::FILE_TYPE_DISK)
        {
            self.usable = false;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "offered handle is not a pipe",
            ));
        }
        self.send(
            crate::protocol::Kind::PipeAck,
            &[],
            end.saturating_duration_since(Instant::now()),
            cancelled,
        )?;
        let (kind, body) =
            self.receive(end.saturating_duration_since(Instant::now()), cancelled)?;
        if kind != crate::protocol::Kind::PipeDone || !body.is_empty() {
            self.usable = false;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid pipe transfer completion",
            ));
        }
        self.send(
            crate::protocol::Kind::PipeConfirm,
            &[],
            end.saturating_duration_since(Instant::now()),
            cancelled,
        )?;
        Ok(std::fs::File::from(target))
    }

    /// Send a frame. On any error drop this connection; it may be partially written.
    pub fn send(
        &mut self,
        kind: crate::protocol::Kind,
        body: &[u8],
        timeout: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<()> {
        if !self.usable {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "control connection is poisoned",
            ));
        }
        self.usable = false;
        let result = send_frame(&self.pipe, kind, body, timeout, cancelled, || {
            ensure_process_running(&self.host)
        });
        if result.is_ok() {
            self.usable = true;
        }
        result
    }
    /// Receive a frame. On any error drop this connection; it may be partially read.
    pub fn receive(
        &mut self,
        timeout: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<(crate::protocol::Kind, Vec<u8>)> {
        if !self.usable {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "control connection is poisoned",
            ));
        }
        self.usable = false;
        let result = receive_frame(&self.pipe, timeout, cancelled, || {
            ensure_process_running(&self.host)
        });
        if result.is_ok() {
            self.usable = true;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows::Spawn;
    use std::collections::BTreeMap;

    #[test]
    fn pipe_name_validation_rejects_remote_and_noncanonical_paths() {
        assert!(validate_pipe_name(r"\\.\pipe\neoenv-owned-1-0").is_ok());
        for bad in [
            r"\\remote\pipe\neoenv-owned-1-0",
            r"\\localhost\pipe\neoenv-owned-1-0",
            r"\\.\pipe\other",
            r"\\.\pipe\neoenv-owned-1-0\extra",
            r"\\.\pipe\neoenv-owned-01-0",
            r"\\.\pipe\neoenv-owned-0-0",
            r"\\.\pipe\neoenv-owned-1-18446744073709551616",
        ] {
            assert!(validate_pipe_name(bad).is_err(), "{bad}");
        }
    }

    fn launcher(mode: &str, pipe: &str) -> Child {
        launcher_with_marker(mode, pipe, "unused")
    }

    fn launcher_with_marker(mode: &str, pipe: &str, marker: &str) -> Child {
        let exe = std::env::current_exe().unwrap();
        let cwd = std::env::temp_dir();
        let arguments = vec![
            "--exact".into(),
            "windows::tests::helper".into(),
            "--nocapture".into(),
        ];
        let host = HostIdentity::current().unwrap();
        let environment = BTreeMap::from([
            ("NEOENV_JOB_TEST_MODE".into(), mode.into()),
            ("NEOENV_JOB_TEST_PIPE".into(), pipe.into()),
            ("NEOENV_JOB_TEST_MARKER".into(), marker.into()),
            ("NEOENV_JOB_TEST_HOST_PID".into(), host.pid.to_string()),
            (
                "NEOENV_JOB_TEST_HOST_TIME".into(),
                host.creation_time.to_string(),
            ),
        ]);
        Child::spawn_isolated_launcher(&Spawn {
            executable: &exe,
            arguments: &arguments,
            environment: &environment,
            directory: &cwd,
            inherit_stdin: false,
        })
        .unwrap()
    }

    #[test]
    fn accepts_only_retained_live_launcher() {
        let listener = ControlListener::new().unwrap();
        let child = launcher("pipe_client", listener.name());
        let verified = listener
            .authenticate(&child, Duration::from_secs(10), &|| false)
            .unwrap();
        drop(verified);
        child.terminate().unwrap();
    }

    #[test]
    fn mutual_authentication_allows_bounded_frame_round_trip() {
        let listener = ControlListener::new().unwrap();
        let child = launcher("pipe_frame", listener.name());
        let mut verified = listener
            .authenticate(&child, Duration::from_secs(10), &|| false)
            .unwrap();
        verified
            .send(
                crate::protocol::Kind::Request,
                b"roundtrip",
                Duration::from_secs(5),
                &|| false,
            )
            .unwrap();
        let (kind, body) = verified.receive(Duration::from_secs(5), &|| false).unwrap();
        assert_eq!(kind, crate::protocol::Kind::Result);
        assert_eq!(body, b"roundtrip");
        drop(verified);
        child.terminate().unwrap();
    }

    #[test]
    fn transfers_noninheritable_pipe_and_preserves_eof() {
        use std::io::Read as _;
        let listener = ControlListener::new().unwrap();
        let child = launcher("pipe_transfer", listener.name());
        let mut verified = listener
            .authenticate(&child, Duration::from_secs(10), &|| false)
            .unwrap();
        let (mut reader, writer) = crate::windows::anonymous_pipe().unwrap();
        verified
            .send_pipe(&writer, Duration::from_secs(5), &|| false)
            .unwrap();
        drop(writer);
        let (tx, rx) = std::sync::mpsc::channel();
        let reader_thread = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = reader.read_to_end(&mut bytes).map(|_| bytes);
            let _ = tx.send(result);
        });
        let result = rx.recv_timeout(Duration::from_secs(3));
        drop(verified);
        child.terminate().unwrap();
        if result.is_err() {
            let _ = rx.recv_timeout(Duration::from_secs(3));
        }
        let bytes = result
            .expect("pipe EOF timed out after supervised cleanup")
            .unwrap();
        reader_thread.join().unwrap();
        assert_eq!(bytes, b"pipe transfer");
    }

    #[test]
    fn delayed_ack_keeps_source_owned_through_transfer() {
        let listener = ControlListener::new().unwrap();
        let child = launcher("pipe_transfer_delayed", listener.name());
        let mut verified = listener
            .authenticate(&child, Duration::from_secs(10), &|| false)
            .unwrap();
        let (_reader, writer) = crate::windows::anonymous_pipe().unwrap();
        let start = Instant::now();
        verified
            .send_pipe(&writer, Duration::from_secs(5), &|| false)
            .unwrap();
        assert!(start.elapsed() >= Duration::from_millis(200));
        drop(writer);
        drop(verified);
        child.terminate().unwrap();
    }

    #[test]
    fn transferred_reader_receives_bytes_and_eof() {
        use std::io::Write as _;
        let listener = ControlListener::new().unwrap();
        let child = launcher("pipe_transfer_reader", listener.name());
        let mut verified = listener
            .authenticate(&child, Duration::from_secs(10), &|| false)
            .unwrap();
        let (reader, mut writer) = crate::windows::anonymous_pipe().unwrap();
        verified
            .send_pipe_reader(&reader, Duration::from_secs(5), &|| false)
            .unwrap();
        drop(reader);
        writer.write_all(b"\x1b[32mbytes\x1b[0m").unwrap();
        drop(writer);
        let (kind, body) = verified.receive(Duration::from_secs(5), &|| false).unwrap();
        assert_eq!(kind, crate::protocol::Kind::Result);
        assert_eq!(body, b"\x1b[32mbytes\x1b[0m");
        drop(verified);
        child.terminate().unwrap();
    }

    #[test]
    fn receiver_can_exit_immediately_after_completion() {
        use std::io::Read as _;
        let listener = ControlListener::new().unwrap();
        let child = launcher("pipe_transfer_immediate", listener.name());
        let mut verified = listener
            .authenticate(&child, Duration::from_secs(10), &|| false)
            .unwrap();
        let (mut reader, writer) = crate::windows::anonymous_pipe().unwrap();
        verified
            .send_pipe(&writer, Duration::from_secs(5), &|| false)
            .unwrap();
        drop(writer);
        drop(verified);
        let (tx, rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = reader.read_to_end(&mut bytes).map(|_| bytes);
            let _ = tx.send(result);
        });
        let result = rx.recv_timeout(Duration::from_secs(3));
        if result.is_err() {
            let _ = child.terminate();
            let _ = rx.recv_timeout(Duration::from_secs(3));
        }
        let bytes = result
            .expect("EOF timed out; launcher cleanup attempted")
            .unwrap();
        thread.join().unwrap();
        assert_eq!(bytes, b"pipe transfer");
    }

    #[test]
    fn cancellation_and_expired_deadline_before_offer_have_no_side_effect() {
        let listener = ControlListener::new().unwrap();
        let child = launcher("pipe_transfer", listener.name());
        let mut verified = listener
            .authenticate(&child, Duration::from_secs(10), &|| false)
            .unwrap();
        let (_reader, writer) = crate::windows::anonymous_pipe().unwrap();
        let error = verified
            .send_pipe(&writer, Duration::from_secs(5), &|| true)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(child.try_wait().unwrap().is_none());
        let error = verified
            .send_pipe(&writer, Duration::ZERO, &|| false)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(child.try_wait().unwrap().is_none());
        verified
            .send_pipe(&writer, Duration::from_secs(5), &|| false)
            .unwrap();
        drop(verified);
        child.terminate().unwrap();
    }

    #[test]
    fn failed_remote_close_poisons_channel_and_terminates_launcher() {
        let listener = ControlListener::new().unwrap();
        let child = launcher("pipe_transfer", listener.name());
        let mut verified = listener
            .authenticate(&child, Duration::from_secs(10), &|| false)
            .unwrap();
        let (_reader, writer) = crate::windows::anonymous_pipe().unwrap();
        FAIL_REMOTE_CLOSE.with(|flag| flag.set(true));
        let error = verified
            .send_pipe(&writer, Duration::from_secs(5), &|| false)
            .unwrap_err();
        FAIL_REMOTE_CLOSE.with(|flag| flag.set(false));
        assert!(error.to_string().contains("injected remote-close failure"));
        assert_eq!(
            verified
                .receive(Duration::from_secs(1), &|| false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        assert!(child.try_wait().unwrap().is_some());
    }

    #[test]
    fn live_receiver_abandoning_pipe_after_ack_cannot_report_success() {
        let marker = std::env::temp_dir().join(format!("neoenv-abandon-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let listener = ControlListener::new().unwrap();
        let child = launcher_with_marker("pipe_abandon", listener.name(), marker.to_str().unwrap());
        let mut verified = listener
            .authenticate(&child, Duration::from_secs(10), &|| false)
            .unwrap();
        let (_reader, writer) = crate::windows::anonymous_pipe().unwrap();
        let error = verified
            .send_pipe(&writer, Duration::from_millis(700), &|| false)
            .unwrap_err();
        match error.kind() {
            io::ErrorKind::TimedOut => {}
            // A failed cleanup is a different, stronger refusal: the caller
            // is warned that the peer may retain authority, never success.
            io::ErrorKind::Other => assert!(
                error.to_string().contains("launcher cleanup failed")
                    && error
                        .to_string()
                        .contains("launcher may retain pipe authority"),
                "unexpected refusal: {error}"
            ),
            other => panic!("unexpected refusal kind {other:?}: {error}"),
        }
        assert!(
            marker.exists(),
            "receiver did not observe completion while alive"
        );
        assert!(
            child.try_wait().unwrap().is_some(),
            "abandoning launcher was not terminated"
        );
        std::fs::remove_file(marker).unwrap();
    }

    #[test]
    fn poisoned_channel_rejects_transfer_before_duplicate_or_callback() {
        let listener = ControlListener::new().unwrap();
        let child = launcher("pipe_client", listener.name());
        let mut verified = listener
            .authenticate(&child, Duration::from_secs(10), &|| false)
            .unwrap();
        assert_eq!(
            verified
                .receive(Duration::from_millis(80), &|| false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        let (_reader, writer) = crate::windows::anonymous_pipe().unwrap();
        let before = TRANSFER_DUP_ATTEMPTS.with(std::cell::Cell::get);
        let callbacks = std::cell::Cell::new(0);
        let error = verified
            .send_pipe(&writer, Duration::from_secs(1), &|| {
                callbacks.set(callbacks.get() + 1);
                false
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(TRANSFER_DUP_ATTEMPTS.with(std::cell::Cell::get), before);
        assert_eq!(callbacks.get(), 0);
        assert!(child.try_wait().unwrap().is_none());
        drop(verified);
        child.terminate().unwrap();
    }

    #[test]
    fn retained_host_handle_lacks_duplicate_right() {
        let (_reader, writer) = crate::windows::anonymous_pipe().unwrap();
        let value = (writer.0.as_handle().as_raw_handle() as usize).to_string();
        let listener = ControlListener::new().unwrap();
        let child = launcher_with_marker("check_host_rights", listener.name(), &value);
        let mut verified = listener
            .authenticate(&child, Duration::from_secs(10), &|| false)
            .unwrap();
        let (kind, body) = verified.receive(Duration::from_secs(5), &|| false).unwrap();
        assert_eq!(kind, crate::protocol::Kind::Result);
        assert_eq!(body, b"denied");
        drop(verified);
        child.terminate().unwrap();
    }

    #[test]
    fn rejected_pipe_ack_terminates_launcher() {
        let marker = std::env::temp_dir().join(format!("neoenv-reject-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let listener = ControlListener::new().unwrap();
        let child = launcher_with_marker("pipe_reject", listener.name(), marker.to_str().unwrap());
        let mut verified = listener
            .authenticate(&child, Duration::from_secs(10), &|| false)
            .unwrap();
        let (_reader, writer) = crate::windows::anonymous_pipe().unwrap();
        let error = verified
            .send_pipe(&writer, Duration::from_secs(5), &|| false)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(child.try_wait().unwrap().is_some());
        let _ = std::fs::remove_file(marker);
    }

    #[test]
    fn failed_cleanup_reports_outstanding_launcher_authority() {
        let marker =
            std::env::temp_dir().join(format!("neoenv-cleanup-fail-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let listener = ControlListener::new().unwrap();
        let child = launcher_with_marker("pipe_reject", listener.name(), marker.to_str().unwrap());
        let mut verified = listener
            .authenticate(&child, Duration::from_secs(10), &|| false)
            .unwrap();
        let (_reader, writer) = crate::windows::anonymous_pipe().unwrap();
        FAIL_TRANSFER_CLEANUP.with(|flag| flag.set(true));
        let error = verified
            .send_pipe(&writer, Duration::from_secs(5), &|| false)
            .unwrap_err();
        FAIL_TRANSFER_CLEANUP.with(|flag| flag.set(false));
        assert!(
            error
                .to_string()
                .contains("launcher may retain pipe authority")
        );
        assert_eq!(
            verified
                .receive(Duration::from_secs(1), &|| false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        drop(verified);
        child.terminate().unwrap();
        let _ = std::fs::remove_file(marker);
    }

    #[test]
    fn pipe_transfer_panic_terminates_launcher() {
        let marker =
            std::env::temp_dir().join(format!("neoenv-transfer-panic-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let listener = ControlListener::new().unwrap();
        let child = launcher_with_marker("pipe_stall", listener.name(), marker.to_str().unwrap());
        let mut verified = listener
            .authenticate(&child, Duration::from_secs(10), &|| false)
            .unwrap();
        let (_reader, writer) = crate::windows::anonymous_pipe().unwrap();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verified.send_pipe(&writer, Duration::from_secs(5), &|| {
                assert!(!marker.exists(), "injected transfer panic");
                false
            })
        }));
        assert!(outcome.is_err());
        assert!(child.try_wait().unwrap().is_some());
        std::fs::remove_file(marker).unwrap();
    }

    #[test]
    fn stalled_frame_read_times_out_and_poisons_connection() {
        let listener = ControlListener::new().unwrap();
        let child = launcher("pipe_client", listener.name());
        let mut verified = listener
            .authenticate(&child, Duration::from_secs(10), &|| false)
            .unwrap();
        let error = verified
            .receive(Duration::from_millis(100), &|| false)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let error = verified
            .send(
                crate::protocol::Kind::Request,
                b"never sent",
                Duration::from_secs(1),
                &|| false,
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        drop(verified);
        child.terminate().unwrap();
    }

    #[test]
    fn panic_during_partial_header_and_body_read_poisons_connection() {
        for mode in ["partial_header", "partial_body"] {
            let marker = std::env::temp_dir()
                .join(format!("neoenv-panic-read-{}-{mode}", std::process::id()));
            let _ = std::fs::remove_file(&marker);
            let listener = ControlListener::new().unwrap();
            let child = launcher_with_marker(mode, listener.name(), marker.to_str().unwrap());
            let mut verified = listener
                .authenticate(&child, Duration::from_secs(10), &|| false)
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !marker.exists() {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(10));
            }
            let calls = std::cell::Cell::new(0);
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                verified.receive(Duration::from_secs(5), &|| {
                    calls.set(calls.get() + 1);
                    assert!(calls.get() < 10, "injected cancellation panic");
                    false
                })
            }));
            assert!(outcome.is_err());
            let error = verified
                .receive(Duration::from_secs(1), &|| false)
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
            drop(verified);
            child.terminate().unwrap();
            std::fs::remove_file(marker).unwrap();
        }
    }

    #[test]
    fn panic_during_partial_write_poisons_connection() {
        let listener = ControlListener::new().unwrap();
        let child = launcher("pipe_client", listener.name());
        let mut verified = listener
            .authenticate(&child, Duration::from_secs(10), &|| false)
            .unwrap();
        // Named-pipe capacity and peer scheduling vary: constrain only this
        // test's first write and inject the panic after actual byte progress.
        // No sleep, marker file, or assumption about pipe buffer size is used.
        TEST_WRITE_LIMIT.with(|limit| limit.set(1024));
        TEST_WRITE_PROGRESS.with(|progress| progress.set(0));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verified.send(
                crate::protocol::Kind::Request,
                &vec![0; crate::protocol::MAX_BODY],
                Duration::from_secs(5),
                &|| {
                    assert_eq!(
                        TEST_WRITE_PROGRESS.with(std::cell::Cell::get),
                        0,
                        "injected panic after partial write"
                    );
                    false
                },
            )
        }));
        let written = TEST_WRITE_PROGRESS.with(std::cell::Cell::get);
        TEST_WRITE_LIMIT.with(|limit| limit.set(usize::MAX));
        assert!(
            outcome.is_err(),
            "write did not reach the injected partial state"
        );
        assert!(
            written > 0 && written < crate::protocol::MAX_BODY,
            "unexpected partial progress: {written}"
        );
        let error = verified
            .send(
                crate::protocol::Kind::Request,
                b"must not send",
                Duration::from_secs(1),
                &|| false,
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        drop(verified);
        child.terminate().unwrap();
    }

    #[test]
    fn malformed_frame_and_cancelled_partial_body_poison_connection() {
        for mode in ["malformed_frame", "partial_body"] {
            let marker =
                std::env::temp_dir().join(format!("neoenv-control-{}-{mode}", std::process::id()));
            let _ = std::fs::remove_file(&marker);
            let listener = ControlListener::new().unwrap();
            let child = launcher_with_marker(mode, listener.name(), marker.to_str().unwrap());
            let mut verified = listener
                .authenticate(&child, Duration::from_secs(10), &|| false)
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !marker.exists() {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(10));
            }
            let started = Instant::now();
            let error = verified
                .receive(Duration::from_secs(5), &|| {
                    mode == "partial_body" && started.elapsed() >= Duration::from_millis(100)
                })
                .unwrap_err();
            assert_eq!(
                error.kind(),
                if mode == "partial_body" {
                    io::ErrorKind::Interrupted
                } else {
                    io::ErrorKind::InvalidData
                }
            );
            assert_eq!(
                verified
                    .receive(Duration::from_secs(1), &|| false)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::BrokenPipe
            );
            drop(verified);
            child.terminate().unwrap();
            std::fs::remove_file(marker).unwrap();
        }
    }

    #[test]
    fn client_rejects_wrong_creation_time_before_connecting() {
        let listener = ControlListener::new().unwrap();
        let mut identity = HostIdentity::current().unwrap();
        identity.creation_time ^= 1;
        let error =
            ControlClient::connect(listener.name(), identity, Duration::from_secs(5), &|| false)
                .err()
                .expect("replayed PID with different creation time must fail");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn client_rejects_pipe_server_other_than_expected_process() {
        let listener = ControlListener::new().unwrap();
        let child = launcher("hold", listener.name());
        // SAFETY: child owns a valid process handle through this scope.
        let pid = unsafe { GetProcessId(raw(&child.process)) };
        let identity = HostIdentity {
            pid,
            creation_time: creation_time(raw(&child.process)).unwrap(),
        };
        let error =
            ControlClient::connect(listener.name(), identity, Duration::from_secs(5), &|| false)
                .err()
                .expect("unexpected server must fail");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        child.terminate().unwrap();
    }

    #[test]
    fn process_with_dup_handle_can_inject_after_authentication() {
        let listener = ControlListener::new().unwrap();
        let child = launcher("pipe_frame", listener.name());
        let mut verified = listener
            .authenticate(&child, Duration::from_secs(10), &|| false)
            .unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "windows::tests::helper", "--nocapture"])
            .env_clear()
            .env("NEOENV_JOB_TEST_MODE", "duplicate_attack")
            .env("NEOENV_JOB_TEST_MARKER", "unused")
            .env("NEOENV_ATTACK_HOST_PID", std::process::id().to_string())
            .env(
                "NEOENV_ATTACK_HANDLE",
                (raw(&verified.pipe) as usize).to_string(),
            )
            .status()
            .unwrap();
        assert!(status.success(), "attacker could not exercise DUP_HANDLE");
        let (kind, body) = verified.receive(Duration::from_secs(5), &|| false).unwrap();
        assert_eq!(kind, crate::protocol::Kind::Result);
        assert_eq!(body, b"injected");
        drop(verified);
        child.terminate().unwrap();
    }

    #[test]
    fn rejects_a_different_local_client() {
        let listener = ControlListener::new().unwrap();
        let child = launcher("hold", listener.name());
        let _impostor = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(listener.name())
            .unwrap();
        let error = listener
            .authenticate(&child, Duration::from_secs(5), &|| false)
            .err()
            .expect("unexpected peer must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        child.terminate().unwrap();
    }

    #[test]
    fn wait_honors_timeout_and_cancellation() {
        let listener = ControlListener::new().unwrap();
        let child = launcher("hold", listener.name());
        let error = listener
            .authenticate(&child, Duration::from_millis(50), &|| false)
            .err()
            .expect("missing client must time out");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let listener = ControlListener::new().unwrap();
        let error = listener
            .authenticate(&child, Duration::from_secs(5), &|| true)
            .err()
            .expect("cancelled wait must stop");
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        child.terminate().unwrap();
    }

    #[test]
    fn cancellation_is_observed_during_polling() {
        let listener = ControlListener::new().unwrap();
        let child = launcher("hold", listener.name());
        let start = Instant::now();
        let error = listener
            .authenticate(&child, Duration::from_secs(5), &|| {
                start.elapsed() >= Duration::from_millis(80)
            })
            .err()
            .expect("polling must observe cancellation");
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(start.elapsed() < Duration::from_secs(2));
        child.terminate().unwrap();
    }

    #[test]
    fn launcher_exit_during_connect_is_reported() {
        let listener = ControlListener::new().unwrap();
        let child = launcher("exit_early", listener.name());
        let error = listener
            .authenticate(&child, Duration::from_secs(5), &|| false)
            .err()
            .expect("exited launcher must not authenticate");
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        child.terminate().unwrap();
    }

    #[test]
    fn disconnected_client_never_authenticates() {
        let listener = ControlListener::new().unwrap();
        let child = launcher("pipe_disconnect", listener.name());
        let deadline = Instant::now() + Duration::from_secs(5);
        while child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            listener
                .authenticate(&child, Duration::from_secs(5), &|| false)
                .is_err()
        );
        child.terminate().unwrap();
    }

    #[test]
    fn dropped_listener_releases_pipe_name() {
        let listener = ControlListener::new().unwrap();
        let name = utf16(OsStr::new(listener.name())).unwrap();
        drop(listener);
        // SAFETY: the name is a live NUL-terminated string; null security
        // attributes make the new handle non-inheritable. FIRST_INSTANCE
        // succeeds only if the previous server instance has been released.
        let replacement = handle(unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                4096,
                4096,
                0,
                null(),
            )
        });
        assert!(replacement.is_ok(), "pipe instance was not released");
    }
}
