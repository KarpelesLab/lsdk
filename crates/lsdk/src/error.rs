//! Error type used across the crate.

use crate::apdu::StatusWord;

/// Result alias using [`Error`].
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Every error the SDK can produce.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The device answered with a non-success status word.
    #[error("device returned status {0}")]
    Status(StatusWord),

    /// No device could be found.
    #[error("no device found")]
    NoDevice,

    /// The device was disconnected during an operation.
    #[error("device disconnected")]
    Disconnected,

    /// Transport level failure (HID I/O, WebHID promise rejected...).
    #[error("transport error: {0}")]
    Transport(String),

    /// The device did not answer in time.
    #[error("timeout waiting for device")]
    Timeout,

    /// HID framing error (bad channel, tag or sequence).
    #[error("framing error: {0}")]
    Framing(String),

    /// A response could not be parsed.
    #[error("invalid response: {0}")]
    InvalidResponse(String),

    /// Caller supplied invalid input.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// The device must be on the dashboard (no app open) for this operation.
    #[error("device must be on the dashboard (close any open app)")]
    DashboardExpected,

    /// The user refused the action on the device.
    #[error("action refused on device")]
    UserRefused,

    /// The device is locked (PIN not entered).
    #[error("device is locked")]
    Locked,

    /// HTTP error when talking to the manager API.
    #[error("http error: {0}")]
    Http(String),

    /// Websocket error when talking to the HSM.
    #[error("websocket error: {0}")]
    WebSocket(String),

    /// The HSM reported an error.
    #[error("hsm error: {0}")]
    Hsm(String),

    /// Requested item was not found (app, firmware...).
    #[error("not found: {0}")]
    NotFound(String),

    /// Operation was cancelled.
    #[error("cancelled")]
    Cancelled,

    /// App specific error.
    #[error("{0}")]
    App(String),
}

impl Error {
    /// Status word carried by this error, if any.
    pub fn status(&self) -> Option<StatusWord> {
        match self {
            Error::Status(sw) => Some(*sw),
            _ => None,
        }
    }
}

impl From<StatusWord> for Error {
    fn from(sw: StatusWord) -> Self {
        match sw {
            StatusWord::LOCKED_DEVICE => Error::Locked,
            sw => Error::Status(sw),
        }
    }
}

#[cfg(any(feature = "manager-api", feature = "hsm"))]
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::InvalidResponse(e.to_string())
    }
}
