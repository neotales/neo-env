//! Task execution, including explicitly authorized inventory-backed SSH scripts.

use std::{
    collections::{BTreeMap, HashSet},
    fmt, fs,
    io::{self, Write as _},
    path::{Component, Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use indexmap::IndexMap;
use neoenv_config::{EnvironmentEntry, PathOperation, PathOperationKind};
use neoenv_core::tasks::{
    PredicateContext, TaskAction, TaskDefinition, TaskEdgeOrigin, TaskError, TaskInputValues,
    TaskOutcome, TaskOutput, TaskOutputVisibility, TaskPackageIdentity, TaskParameterDefault,
    evaluate_predicate_with_context, normalize_input_value, plan_task, task_dependency_edges,
};
use neoenv_policy::{Capability, CapabilityGrants};
use neotales_gotmpl::{Template, Value};
use neotales_process::{Error as ProcessError, ExecutionOptions, parse};
use neotales_process::{execute_argv, execute_chain};
use serde::Serialize;
use tempfile::TempDir;

use crate::{
    budget::{ResourceBudget, read_text_file},
    resolved_config::apply_task_dotenv,
};
mod handoff;
mod model;
#[cfg(not(windows))]
mod owned_process;
#[cfg(windows)]
#[path = "tasks/owned_process_windows.rs"]
mod owned_process;
mod process;
mod runners;
mod scheduler;
mod ssh_runner;
mod template;
#[cfg(test)]
mod tests;

pub use model::*;
pub use scheduler::{run_tasks, run_tasks_with_cancellation};

#[cfg(test)]
use handoff::{Handoff, HandoffDocuments, HandoffValues};
#[cfg(test)]
use process::{interpolate_portable_environment, render_file, resolve_fallback_runner};
