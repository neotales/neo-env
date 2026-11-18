//! Experimental isolated pipe-to-pipe output proxy.

use super::{ControlClient, HostIdentity};
use crate::protocol::Kind;
use std::{
    io::{self, Read, Write},
    time::Duration,
};

/// Run only in the dedicated launcher binary. The parent owns its job and
/// must terminate that job if this process is blocked or the control channel
/// is lost. A blocked synchronous I/O call is not cancellable in-process.
#[allow(dead_code)] // Used by the separately compiled private binary.
pub(crate) fn run_proxy(name: &str, host: HostIdentity) -> io::Result<()> {
    let mut control = ControlClient::connect(name, host, Duration::from_secs(10), &|| false)?;
    let mut source = control.receive_pipe(Duration::from_secs(10), &|| false)?;
    let mut destination = control.receive_pipe(Duration::from_secs(10), &|| false)?;
    let mut buffer = [0u8; 8192];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        destination.write_all(&buffer[..count])?;
    }
    drop(destination);
    control.send(Kind::Result, b"ok", Duration::from_secs(3), &|| false)
}

/// A synchronous output destination is confined to this job-owned process.
/// Its caller must terminate and verify the job on cancellation or error.
#[allow(dead_code)] // Used by the private launcher binary.
pub(crate) fn run_forward_proxy(name: &str, host: HostIdentity) -> io::Result<()> {
    let mut control = ControlClient::connect(name, host, Duration::from_secs(10), &|| false)?;
    let mut source = control.receive_pipe(Duration::from_secs(10), &|| false)?;
    let mut destination =
        control.receive_forward_destination(Duration::from_secs(10), &|| false)?;
    drop(control);
    io::copy(&mut source, &mut destination)?;
    Ok(())
}
