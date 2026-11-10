//! Device management: manager HTTP API and high level operations.

#[cfg(feature = "manager-api")]
pub mod api;

#[cfg(all(feature = "manager-api", feature = "hsm"))]
pub mod ops;

#[cfg(feature = "manager-api")]
pub use api::{Application, ManagerApi};

#[cfg(all(feature = "manager-api", feature = "hsm"))]
pub use ops::Manager;
