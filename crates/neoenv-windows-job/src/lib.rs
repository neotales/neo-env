//! Windows process creation and job ownership boundary.
//!
//! This is not a sandbox: work requested from an external broker is not a
//! descendant and is not contained by a job.

pub mod protocol;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::{
    Child, ControlClient, ControlListener, ForwardDestination, HostIdentity, LauncherRequest,
    LauncherResponse, LauncherStage, OutputCancellation, OutputWriter, PipeReader, PipeWriter,
    Spawn, VerifiedControl, anonymous_pipe, overlapped_output_pipe,
};
