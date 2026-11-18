//! Pure task declarations, resolution, and dependency planning.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    fmt::Write,
    path::PathBuf,
};

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::SourceSpan;
mod context;
mod help;
mod model;
mod planning;
mod predicate;
mod runners;
#[cfg(test)]
mod tests;

pub use context::{known_contexts, validate_context};
pub use help::{resolve_hook_name, resolve_task_name, task_help};
pub use model::*;
pub use planning::{
    LoweredJob, bind_task_inputs, lower_job, lower_jobs, normalize_input_value, plan_task,
    resolve_inheritance, resolve_inheritance_for, select_context, task_dependency_edges,
    valid_environment_key,
};
pub use predicate::{
    evaluate_predicate, evaluate_predicate_with_context, predicate_environment_dependencies,
    predicate_outcome_dependencies, predicate_reads_uncertain_aggregate,
};
pub use runners::{
    SCRIPT_RUNNERS, UvRunner, is_builtin_runner, is_exact_version, is_script_runner,
    is_template_runner, is_wsl_runner, parse_uv_runner,
};
