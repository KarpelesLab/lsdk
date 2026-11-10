//! Transports carry raw APDUs to a device and bring back raw responses.

use crate::error::Result;

#[cfg(all(feature = "hid", not(target_arch = "wasm32")))]
pub mod hid;
#[cfg(all(feature = "hid", target_os = "linux"))]
mod usbfs;

#[cfg(all(feature = "webhid", target_arch = "wasm32"))]
pub mod webhid;

pub mod mock;

/// A channel to a device able to exchange APDUs.
///
/// `exchange` sends a fully encoded APDU (`CLA INS P1 P2 Lc data`) and returns
/// the raw response including the trailing status word. Implementations must
/// serialize concurrent calls.
pub trait Transport {
    async fn exchange(&self, apdu: &[u8]) -> Result<Vec<u8>>;
}

impl<T: Transport + ?Sized> Transport for &T {
    async fn exchange(&self, apdu: &[u8]) -> Result<Vec<u8>> {
        (**self).exchange(apdu).await
    }
}

impl<T: Transport + ?Sized> Transport for std::rc::Rc<T> {
    async fn exchange(&self, apdu: &[u8]) -> Result<Vec<u8>> {
        (**self).exchange(apdu).await
    }
}

impl<T: Transport + ?Sized> Transport for std::sync::Arc<T> {
    async fn exchange(&self, apdu: &[u8]) -> Result<Vec<u8>> {
        (**self).exchange(apdu).await
    }
}

impl<T: Transport + ?Sized> Transport for Box<T> {
    async fn exchange(&self, apdu: &[u8]) -> Result<Vec<u8>> {
        (**self).exchange(apdu).await
    }
}
