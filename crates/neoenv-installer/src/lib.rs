//! Verified tool installation and activation planning for `nenv` projects.

pub mod activation;
pub mod tools;

/// Installer features are introduced behind explicit application-service APIs.
pub const LAYER: &str = "installer";

#[cfg(test)]
mod tests {
    use super::LAYER;

    #[test]
    fn identifies_the_installation_boundary() {
        assert_eq!(LAYER, "installer");
    }
}
