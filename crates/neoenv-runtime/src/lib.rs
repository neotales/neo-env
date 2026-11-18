//! Filesystem, process, and network adapters for `nenv` application services.

pub mod budget;
pub mod discovery;
pub mod inventory;
mod inventory_files;
mod local_repository;
pub mod modules;
pub mod paths;
pub mod policy;
pub mod remote;
pub mod resolved_config;
pub mod ssh;
pub mod ssh_output;
pub mod state_file;
pub mod tasks;
pub mod transport;
pub mod trust;
pub mod vault;

/// Runtime features are introduced behind explicit application-service APIs.
pub const LAYER: &str = "runtime";

#[cfg(test)]
mod tests {
    use super::LAYER;

    #[test]
    fn identifies_the_effect_boundary() {
        assert_eq!(LAYER, "runtime");
    }
}
