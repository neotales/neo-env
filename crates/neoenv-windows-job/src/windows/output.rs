//! Output writes to overlapped pipes and chunked synchronous character handles.
//!
//! A duplicated handle retains the original file object's synchronous mode;
//! supplying OVERLAPPED to a synchronous handle does not make it asynchronous.
//! Inspect pipe mode before issuing a write; synchronous pipes are forwarded by
//! a separate job-owned process. Character calls use the chunk-boundary contract.

use super::{handle, raw};
use std::{
    io,
    mem::{size_of, zeroed},
    os::windows::io::{AsRawHandle, BorrowedHandle, OwnedHandle},
    ptr::{null, null_mut},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use windows_sys::Win32::{
    Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_IO_PENDING, WAIT_OBJECT_0},
    Storage::FileSystem::{FILE_TYPE_CHAR, FILE_TYPE_PIPE, GetFileType, WriteFile},
    System::{
        Console::{GetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE},
        IO::{CancelIoEx, GetOverlappedResult, IO_STATUS_BLOCK, OVERLAPPED},
        Threading::{
            CreateEventW, GetCurrentProcess, INFINITE, SetEvent, WaitForMultipleObjects,
            WaitForSingleObject,
        },
    },
};

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryInformationFile(
        file: *mut core::ffi::c_void,
        status: *mut IO_STATUS_BLOCK,
        information: *mut core::ffi::c_void,
        length: u32,
        class: i32,
    ) -> i32;
}

fn duplicate(source: *mut core::ffi::c_void) -> io::Result<OwnedHandle> {
    let mut result = null_mut();
    // SAFETY: source is a borrowed live handle, process pseudohandles are valid,
    // and result receives a new non-inheritable handle, never the original.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            source,
            GetCurrentProcess(),
            &mut result,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    handle(result)
}

fn event() -> io::Result<OwnedHandle> {
    // SAFETY: null security/name create a private manual-reset event.
    handle(unsafe { CreateEventW(null(), 1, 0, null()) })
}

/// Shared cancellation request and manual-reset I/O event.
///
/// Signalling the event waits for any admitted synchronous character call to
/// return. `request_cancel` is nonblocking and immediately prevents admission
/// of another call, even while the event signal is waiting on that call.
#[derive(Clone)]
pub struct OutputCancellation(Arc<CancellationState>);
struct CancellationState {
    event: OwnedHandle,
    requested: AtomicBool,
    console_gate: Mutex<()>,
}
impl OutputCancellation {
    pub fn new() -> io::Result<Self> {
        Ok(Self(Arc::new(CancellationState {
            event: event()?,
            requested: AtomicBool::new(false),
            console_gate: Mutex::new(()),
        })))
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.requested.load(Ordering::Acquire)
    }
    /// Prevent new console call admissions without waiting for an active call.
    pub fn request_cancel(&self) {
        self.0.requested.store(true, Ordering::Release);
    }
    /// Signal the I/O event after any admitted character call has returned.
    /// This may wait indefinitely if that call never returns.
    pub fn cancel(&self) -> io::Result<()> {
        self.request_cancel();
        let _gate = self
            .0
            .console_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: event remains owned by the Arc, and the gate serializes
        // signalling with the complete synchronous character call.
        if unsafe { SetEvent(raw(&self.0.event)) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

// Hold the gate through the call: releasing it between the check and WriteFile
// would allow cancellation to signal before the actual call starts.
fn console_call<T>(
    cancel: &OutputCancellation,
    call: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    let _gate = cancel
        .0
        .console_gate
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if cancel.is_cancelled() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "output cancelled",
        ));
    }
    call()
}

/// A duplicated stdout/stderr destination for an isolated forwarding process.
/// Synchronous pipes and disk files can block, so they may only be written by
/// a separately job-owned helper. Character handles instead use the host-side
/// chunked `OutputWriter` because they cannot be forwarded by this mechanism.
pub struct ForwardDestination(OwnedHandle);
impl ForwardDestination {
    pub fn stdout() -> io::Result<Self> {
        Self::new(unsafe { GetStdHandle(STD_OUTPUT_HANDLE) })
    }
    pub fn stderr() -> io::Result<Self> {
        Self::new(unsafe { GetStdHandle(STD_ERROR_HANDLE) })
    }
    /// Duplicate a borrowed pipe or disk output for isolated forwarding.
    pub fn from_handle(source: BorrowedHandle<'_>) -> io::Result<Self> {
        Self::new(source.as_raw_handle())
    }
    fn new(source: *mut core::ffi::c_void) -> io::Result<Self> {
        use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_DISK, FILE_TYPE_PIPE};
        let owned = duplicate(source)?;
        let kind = unsafe { GetFileType(raw(&owned)) };
        if kind != FILE_TYPE_DISK && kind != FILE_TYPE_PIPE {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "output destination cannot be forwarded: only pipe and disk handles are supported",
            ));
        }
        let mut status: IO_STATUS_BLOCK = unsafe { zeroed() };
        let mut mode: u32 = 0;
        // SAFETY: the owned handle and both output structures remain live.
        let result = unsafe {
            NtQueryInformationFile(
                raw(&owned),
                &mut status,
                (&mut mode as *mut u32).cast(),
                size_of::<u32>() as u32,
                16,
            )
        };
        if result != 0 || mode & (0x10 | 0x20) == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "output destination is not a verified synchronous pipe or disk file",
            ));
        }
        Ok(Self(owned))
    }
    pub(crate) fn handle(&self) -> &OwnedHandle {
        &self.0
    }
}

/// Owns a duplicate of an asynchronous pipe or character destination.
///
/// Character writes are synchronous and cancellation takes effect only before
/// the next 4 KiB write. Windows cannot interrupt a call already in progress;
/// a stalled call can exceed the task cleanup deadline.
pub struct OutputWriter {
    destination: OwnedHandle,
    cancel: OutputCancellation,
    character: bool,
}

impl OutputWriter {
    pub fn stdout(cancel: OutputCancellation) -> io::Result<Self> {
        // SAFETY: GetStdHandle returns a borrowed process handle, never owned.
        Self::from_raw(unsafe { GetStdHandle(STD_OUTPUT_HANDLE) }, cancel)
    }
    pub fn stderr(cancel: OutputCancellation) -> io::Result<Self> {
        // SAFETY: GetStdHandle returns a borrowed process handle, never owned.
        Self::from_raw(unsafe { GetStdHandle(STD_ERROR_HANDLE) }, cancel)
    }
    pub fn from_handle(source: BorrowedHandle<'_>, cancel: OutputCancellation) -> io::Result<Self> {
        Self::from_raw(source.as_raw_handle(), cancel)
    }
    fn from_raw(source: *mut core::ffi::c_void, cancel: OutputCancellation) -> io::Result<Self> {
        let destination = duplicate(source).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("output destination duplication failed: {e}"),
            )
        })?;
        // SAFETY: destination is a valid duplicate held by this function.
        let kind = unsafe { GetFileType(raw(&destination)) };
        if kind == FILE_TYPE_CHAR {
            return Ok(Self {
                destination,
                cancel,
                character: true,
            });
        }
        if kind != FILE_TYPE_PIPE {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "output destination is not a character handle or asynchronous pipe",
            ));
        }
        let mut status: IO_STATUS_BLOCK = unsafe { zeroed() };
        let mut mode: u32 = 0;
        // SAFETY: destination is live; both outputs are writable POD values.
        // FileModeInformation reports the file object's actual I/O mode.
        let result = unsafe {
            NtQueryInformationFile(
                raw(&destination),
                &mut status,
                (&mut mode as *mut u32).cast(),
                size_of::<u32>() as u32,
                16,
            )
        };
        if result != 0 || mode & (0x10 | 0x20) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "output destination does not support verified overlapped I/O",
            ));
        }
        Ok(Self {
            destination,
            cancel,
            character: false,
        })
    }

    /// Write all bytes. Character calls can block indefinitely; cancellation
    /// stops the next chunk, not an already-running synchronous console call.
    pub fn write_all(&self, bytes: &[u8]) -> io::Result<()> {
        let chunk = if self.character { 4096 } else { 16 * 1024 };
        write_chunks(bytes, chunk, &self.cancel, |part| {
            if self.character {
                self.write_character(part)
            } else {
                self.write_one(part)
            }
        })
    }

    fn write_character(&self, bytes: &[u8]) -> io::Result<usize> {
        console_call(&self.cancel, || {
            let mut written = 0;
            // SAFETY: destination is an owned duplicate, bytes is live for this
            // synchronous call, and written is writable. No original is closed.
            if unsafe {
                WriteFile(
                    raw(&self.destination),
                    bytes.as_ptr(),
                    bytes.len() as u32,
                    &mut written,
                    null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(written as usize)
        })
    }

    fn write_one(&self, bytes: &[u8]) -> io::Result<usize> {
        struct Operation {
            handle: OwnedHandle,
            event: OwnedHandle,
            overlapped: OVERLAPPED,
            data: Vec<u8>,
        }
        let mut op = Box::new(Operation {
            handle: duplicate(raw(&self.destination))?,
            event: event()?,
            overlapped: unsafe { zeroed() },
            data: bytes.to_vec(),
        });
        op.overlapped.hEvent = raw(&op.event);
        // SAFETY: event is live and the zero-time wait does not block.
        if unsafe { WaitForSingleObject(raw(&self.cancel.0.event), 0) } == WAIT_OBJECT_0 {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "output cancelled",
            ));
        }
        let mut written = 0;
        // SAFETY: handle is verified overlapped; op and its buffer remain pinned
        // on the heap until completion (or are deliberately leaked on timeout).
        let ok = unsafe {
            WriteFile(
                raw(&op.handle),
                op.data.as_ptr(),
                op.data.len() as u32,
                &mut written,
                &mut op.overlapped,
            )
        };
        if ok != 0 {
            return Ok(written as usize);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
            return Err(io::Error::new(
                error.kind(),
                format!("overlapped output destination failed: {error}"),
            ));
        }
        let events = [raw(&self.cancel.0.event), raw(&op.event)];
        // SAFETY: both event handles and the operation are live.
        let wait = unsafe { WaitForMultipleObjects(2, events.as_ptr(), 0, INFINITE) };
        if wait != WAIT_OBJECT_0 + 1 {
            // SAFETY: op is the exact outstanding operation on this handle.
            unsafe {
                CancelIoEx(raw(&op.handle), &op.overlapped);
            }
            // A driver can ignore cancellation. Retain the operation and its
            // handle in that case; freeing the kernel's buffer would be unsound.
            if unsafe { WaitForSingleObject(raw(&op.event), 3000) } != WAIT_OBJECT_0 {
                std::mem::forget(op);
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "output cancellation completion deadline exceeded",
                ));
            }
            return Err(if wait == WAIT_OBJECT_0 {
                io::Error::new(io::ErrorKind::Interrupted, "output cancelled")
            } else {
                io::Error::other("output wait failed")
            });
        }
        // SAFETY: completion event is signalled and storage remains live.
        if unsafe { GetOverlappedResult(raw(&op.handle), &op.overlapped, &mut written, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(written as usize)
    }
}

// Check before *every* call, including after a partial synchronous write.
fn write_chunks(
    mut bytes: &[u8],
    limit: usize,
    cancel: &OutputCancellation,
    mut write: impl FnMut(&[u8]) -> io::Result<usize>,
) -> io::Result<()> {
    while !bytes.is_empty() {
        if cancel.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "output cancelled",
            ));
        }
        let part = &bytes[..bytes.len().min(limit)];
        let written = write(part)?;
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "output destination wrote zero bytes",
            ));
        }
        if written > part.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "output destination reported an invalid byte count",
            ));
        }
        bytes = &bytes[written..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        ffi::OsStr,
        io::Read,
        os::windows::{
            ffi::OsStrExt,
            io::{AsHandle, FromRawHandle},
        },
        sync::atomic::{AtomicU32, Ordering},
        time::{Duration, Instant},
    };
    use windows_sys::Win32::{
        Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, PIPE_ACCESS_OUTBOUND,
        },
        System::{
            Pipes::{CreateNamedPipeW, PIPE_TYPE_BYTE},
            Threading::GetCurrentProcessId,
        },
    };

    fn pipe() -> (std::fs::File, OwnedHandle) {
        static SEQUENCE: AtomicU32 = AtomicU32::new(0);
        let name: Vec<u16> = OsStr::new(&format!(
            r"\\.\pipe\neoenv-output-test-{}-{}",
            unsafe { GetCurrentProcessId() },
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
        .encode_wide()
        .chain([0])
        .collect();
        // SAFETY: the name is terminated; both calls return owned handles.
        let server = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE,
                1,
                4096,
                4096,
                0,
                null(),
            )
        };
        assert_ne!(server, INVALID_HANDLE_VALUE);
        let client = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ,
                0,
                null(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        assert_ne!(client, INVALID_HANDLE_VALUE);
        (
            unsafe { std::fs::File::from_raw_handle(client) },
            handle(server).unwrap(),
        )
    }

    #[test]
    fn cancelled_between_precheck_and_admission_starts_no_console_call() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let cancel = OutputCancellation::new().unwrap();
        let worker_cancel = cancel.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            write_chunks(&[7; 8192], 4096, &worker_cancel, |part| {
                // Pause after the outer check but before the admission gate.
                entered_tx.send(()).unwrap();
                resume_rx.recv().unwrap();
                console_call(&worker_cancel, || {
                    observed.fetch_add(1, Ordering::SeqCst);
                    Ok(part.len())
                })
            })
        });
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        cancel.cancel().unwrap();
        resume_tx.send(()).unwrap();
        assert_eq!(
            worker.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn signal_waits_for_an_already_admitted_console_call() {
        let cancel = OutputCancellation::new().unwrap();
        let worker_cancel = cancel.clone();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            console_call(&worker_cancel, || {
                entered_tx.send(()).unwrap();
                resume_rx.recv().unwrap();
                Ok(())
            })
        });
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let signal_cancel = cancel.clone();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let signal = std::thread::spawn(move || {
            let _ = done_tx.send(signal_cancel.cancel());
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while !cancel.is_cancelled() && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(cancel.is_cancelled());
        // SAFETY: the event is held alive by cancel and a zero-time wait is nonblocking.
        assert_eq!(
            unsafe { WaitForSingleObject(raw(&cancel.0.event), 0) },
            windows_sys::Win32::Foundation::WAIT_TIMEOUT
        );
        assert!(done_rx.try_recv().is_err());
        resume_tx.send(()).unwrap();
        worker.join().unwrap().unwrap();
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        signal.join().unwrap();
        let result = console_call(&cancel, || Ok(()));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
    }

    #[test]
    fn character_handle_is_accepted_without_closing_original() {
        use std::io::Write as _;
        let mut original = std::fs::OpenOptions::new().write(true).open("NUL").unwrap();
        let cancel = OutputCancellation::new().unwrap();
        let writer = OutputWriter::from_handle(original.as_handle(), cancel).unwrap();
        writer.write_all(b"console\0bytes").unwrap();
        drop(writer);
        original.write_all(b"original still open").unwrap();
    }

    // This fixture is started as a separately job-owned task by the test below.
    #[test]
    fn console_task_fixture() {
        if let Some(marker) = std::env::var_os("NEOENV_CONSOLE_TASK_FIXTURE") {
            std::fs::write(marker, b"started").unwrap();
            std::thread::sleep(Duration::from_secs(30));
        }
    }

    #[test]
    fn cancel_at_character_chunk_boundary_stops_output_and_task_job() {
        use super::super::{Child, Spawn};
        use std::collections::BTreeMap;
        let executable = std::env::current_exe().unwrap();
        let directory = std::env::temp_dir();
        let marker = directory.join(format!(
            "neoenv-console-task-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&marker);
        let env = BTreeMap::from([(
            "NEOENV_CONSOLE_TASK_FIXTURE".to_owned(),
            marker.to_string_lossy().into_owned(),
        )]);
        let args = vec![
            "--exact".to_owned(),
            "windows::output::tests::console_task_fixture".to_owned(),
        ];
        let child = Child::spawn_isolated_launcher(&Spawn {
            executable: &executable,
            arguments: &args,
            environment: &env,
            directory: &directory,
            inherit_stdin: false,
        })
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !marker.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(marker.exists(), "job-owned fixture did not start");
        let cancel = OutputCancellation::new().unwrap();
        let mut calls = 0;
        let result = write_chunks(&[1; 8192], 4096, &cancel, |part| {
            calls += 1;
            assert_eq!(part.len(), 4096);
            cancel.cancel()?;
            // The runtime terminates its task job after observing cancellation.
            child.terminate()?;
            Ok(part.len())
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert_eq!(calls, 1, "no second console call may start");
        assert!(
            child.try_wait().unwrap().is_some(),
            "task process survived job termination"
        );
        let _ = std::fs::remove_file(marker);
    }

    #[test]
    fn preserves_nul_and_ansi() {
        let (mut reader, pipe) = pipe();
        let writer =
            OutputWriter::from_handle(pipe.as_handle(), OutputCancellation::new().unwrap())
                .unwrap();
        let data = b"\x1b[31mhello\0world\x1b[0m";
        writer.write_all(data).unwrap();
        let mut result = vec![0; data.len()];
        reader.read_exact(&mut result).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn cancel_blocked_pipe_within_deadline() {
        let (_reader, pipe) = pipe();
        let cancel = OutputCancellation::new().unwrap();
        let writer = OutputWriter::from_handle(pipe.as_handle(), cancel.clone()).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            tx.send(writer.write_all(&vec![7; 2_000_000])).unwrap();
        });
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
        let started = Instant::now();
        cancel.cancel().unwrap();
        let result = rx
            .recv_timeout(Duration::from_secs(4))
            .expect("cancelled write did not finish");
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(4));
        worker.join().unwrap();
    }

    #[test]
    fn refuses_non_pipe_explicitly() {
        let event = event().unwrap();
        let error = match OutputWriter::from_handle(
            event.as_handle(),
            OutputCancellation::new().unwrap(),
        ) {
            Ok(_) => panic!("event accepted as output"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("output destination"));
    }
}

/// Create an overlapped outbound pipe and its synchronous read end. The writer
/// may be installed as stdout/stderr of a child without changing its file mode.
pub fn overlapped_output_pipe() -> io::Result<(std::fs::File, std::fs::File)> {
    use std::{
        ffi::OsStr,
        os::windows::ffi::OsStrExt,
        sync::atomic::{AtomicU64, Ordering},
    };
    use windows_sys::Win32::{
        Foundation::GENERIC_READ,
        Storage::FileSystem::{
            CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
            PIPE_ACCESS_OUTBOUND,
        },
        System::{
            Pipes::{CreateNamedPipeW, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE},
            Threading::GetCurrentProcessId,
        },
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    // SAFETY: no arguments or memory access.
    let pid = unsafe { GetCurrentProcessId() };
    let name = format!(
        r"\\.\pipe\neoenv-output-{pid}-{}",
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let name: Vec<u16> = OsStr::new(&name).encode_wide().chain([0]).collect();
    // SAFETY: name is NUL terminated; result is transferred to OwnedHandle.
    let writer = handle(unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            65536,
            65536,
            0,
            null(),
        )
    })?;
    // SAFETY: same name is live, and a successful result is a new owned handle.
    let reader = handle(unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ,
            0,
            null(),
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    })?;
    // Convert ownership without closing either live handle.
    Ok((std::fs::File::from(reader), std::fs::File::from(writer)))
}
