//! # lsdk
//!
//! A Rust SDK to talk to hardware wallets that run the BOLOS operating system
//! (Nano S, Nano S Plus, Nano X, Stax, Flex, Nano Gen5) over USB HID, from
//! native code or from the browser through WebHID.
//!
//! The crate is split in layers, each behind a cargo feature so you only pay
//! for what you use:
//!
//! | Layer | Feature | Content |
//! |-------|---------|---------|
//! | core | *(always)* | APDU encoding, status words, HID framing, device models, [`Transport`](transport::Transport) trait, dashboard commands ([`Device`]) |
//! | native HID | `hid` | [`transport::hid::HidTransport`] built on `hidapi` |
//! | WebHID | `webhid` | [`transport::webhid::WebHidTransport`] for `wasm32` |
//! | manager API | `manager-api` | [`manager::api::ManagerApi`]: app catalog, firmware metadata |
//! | HSM channel | `hsm` | [`hsm`]: the websocket secure channel used for genuine check, install, update |
//! | manager | `manager` | [`manager::ops`]: genuine check, install / uninstall apps, firmware update |
//! | apps | `eth`, `btc`, `sol` | app clients ([`apps`]) to derive addresses, build and sign transactions |
//!
//! ```no_run
//! # #[cfg(feature = "hid")]
//! # async fn demo() -> Result<(), lsdk::Error> {
//! use lsdk::{Device, transport::hid::HidTransport};
//!
//! let transport = HidTransport::open_first()?;
//! let device = Device::new(transport);
//! let version = device.get_version().await?;
//! println!("{} running {}", version.model().map(|m| m.name()).unwrap_or("?"), version.se_version);
//! # Ok(()) }
//! ```

#![allow(async_fn_in_trait)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod apdu;
pub mod device;
pub mod error;
pub mod framing;
pub mod model;
pub mod os;
pub mod path;
pub mod transport;

#[cfg(any(feature = "manager-api", feature = "hsm"))]
pub mod manager;

#[cfg(feature = "hsm")]
pub mod hsm;

#[cfg(feature = "attestation")]
pub mod attestation;

#[cfg(any(feature = "eth", feature = "btc", feature = "sol"))]
pub mod apps;

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub mod wasm;

pub use apdu::{Apdu, Response, StatusWord};
pub use device::Device;
pub use error::{Error, Result};
pub use model::DeviceModel;
pub use transport::Transport;

/// USB vendor id used by all devices.
pub const VENDOR_ID: u16 = 0x2c97;
