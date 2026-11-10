//! App clients: talk to the coin apps running on the device.
//!
//! Transactions are generated with the [`outscript`] crate; these modules
//! handle the device side (address derivation, signing).

#[cfg(feature = "btc")]
pub mod btc;
#[cfg(feature = "eth")]
pub mod eth;
#[cfg(feature = "sol")]
pub mod sol;
