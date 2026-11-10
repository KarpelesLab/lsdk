//! Native USB HID transport based on `hidapi`.
//!
//! On Linux, when the hidraw node can't be opened (no udev rules), the
//! transport falls back to raw USB through usbfs (`rawusb`), which works when
//! `/dev/bus/usb` is accessible. [`HidTransport::backend`] tells which is used.
//!
//! The I/O is blocking: [`Transport::exchange`] performs the HID reads and
//! writes on the calling thread. That's fine for CLIs and current-thread
//! runtimes; in a multi-threaded async server, wrap calls in `spawn_blocking`.

use std::ffi::CString;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use hidapi::{HidApi, HidDevice};

use crate::VENDOR_ID;
use crate::error::{Error, Result};
use crate::framing::{self, DEFAULT_CHANNEL, PACKET_SIZE};
use crate::model::DeviceModel;
use crate::transport::Transport;

/// HID usage page exposed by the devices for APDU exchange.
pub const USAGE_PAGE: u16 = 0xffa0;

fn api() -> Result<&'static Mutex<HidApi>> {
    static API: OnceLock<std::result::Result<Mutex<HidApi>, String>> = OnceLock::new();
    API.get_or_init(|| HidApi::new().map(Mutex::new).map_err(|e| e.to_string()))
        .as_ref()
        .map_err(|e| Error::Transport(e.clone()))
}

/// A device found while enumerating.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct HidDeviceInfo {
    /// Platform specific path, pass it to [`HidTransport::open`].
    pub path: String,
    pub product_id: u16,
    pub model: Option<DeviceModel>,
    pub product: Option<String>,
    pub serial: Option<String>,
    /// Device is in bootloader mode.
    pub bootloader: bool,
}

enum Backend {
    Hid(HidDevice),
    #[cfg(target_os = "linux")]
    Usb(super::usbfs::UsbHid),
}

impl Backend {
    /// Send one report (without report id).
    fn write(&self, packet: &[u8]) -> Result<()> {
        match self {
            Backend::Hid(d) => {
                let mut report = Vec::with_capacity(packet.len() + 1);
                report.push(0x00); // report id
                report.extend_from_slice(packet);
                d.write(&report).map(|_| ()).map_err(map_hid_err)
            }
            #[cfg(target_os = "linux")]
            Backend::Usb(d) => d.write(packet),
        }
    }

    /// Read one report, `Ok(0)` on timeout.
    fn read_timeout(&self, buf: &mut [u8], timeout_ms: i32) -> Result<usize> {
        match self {
            Backend::Hid(d) => d.read_timeout(buf, timeout_ms).map_err(map_hid_err),
            #[cfg(target_os = "linux")]
            Backend::Usb(d) => d.read_timeout(buf, timeout_ms as u64),
        }
    }
}

/// USB HID transport.
pub struct HidTransport {
    device: Mutex<Backend>,
    info: HidDeviceInfo,
    channel: u16,
    timeout: Option<Duration>,
}

impl HidTransport {
    /// List connected devices.
    pub fn list() -> Result<Vec<HidDeviceInfo>> {
        let mut api = api()?
            .lock()
            .map_err(|_| Error::Transport("hidapi poisoned".into()))?;
        api.refresh_devices()
            .map_err(|e| Error::Transport(e.to_string()))?;
        let mut out: Vec<HidDeviceInfo> = Vec::new();
        for d in api.device_list() {
            if d.vendor_id() != VENDOR_ID {
                continue;
            }
            // Devices expose several interfaces (U2F, ...). Keep the APDU one.
            if !(d.usage_page() == USAGE_PAGE || d.interface_number() == 0) {
                continue;
            }
            let path = d.path().to_string_lossy().into_owned();
            if out.iter().any(|o| o.path == path) {
                continue;
            }
            let pid = d.product_id();
            out.push(HidDeviceInfo {
                path,
                product_id: pid,
                model: DeviceModel::from_product_id(pid),
                product: d.product_string().map(str::to_owned),
                serial: d.serial_number().map(str::to_owned),
                bootloader: DeviceModel::is_bootloader_product_id(pid),
            });
        }
        Ok(out)
    }

    /// Open a device by path.
    pub fn open(info: &HidDeviceInfo) -> Result<Self> {
        let api = api()?
            .lock()
            .map_err(|_| Error::Transport("hidapi poisoned".into()))?;
        let path =
            CString::new(info.path.clone()).map_err(|e| Error::InvalidInput(e.to_string()))?;
        let device = match api.open_path(&path) {
            Ok(d) => Backend::Hid(d),
            Err(e) => {
                let m = e.to_string();
                #[cfg(target_os = "linux")]
                if m.contains("ermission") || m.contains("Failed to open") {
                    drop(api);
                    return Self::open_usbfs(info).map_err(|u| {
                        Error::Transport(format!(
                            "{m}: no access to {} (raw USB fallback: {u}); install udev rules for USB vendor 2c97 (see the README)",
                            info.path
                        ))
                    });
                }
                return Err(Error::Transport(m));
            }
        };
        Ok(Self {
            device: Mutex::new(device),
            info: info.clone(),
            channel: DEFAULT_CHANNEL,
            timeout: None,
        })
    }

    /// Open a device over raw USB (usbfs) instead of hidraw. [`Self::open`]
    /// does this by itself when hidraw access is denied. The kernel HID
    /// driver is detached from the interface until the transport is dropped.
    #[cfg(target_os = "linux")]
    pub fn open_usbfs(info: &HidDeviceInfo) -> Result<Self> {
        Ok(Self {
            device: Mutex::new(Backend::Usb(super::usbfs::UsbHid::open(
                &info.path,
                info.product_id,
            )?)),
            info: info.clone(),
            channel: DEFAULT_CHANNEL,
            timeout: None,
        })
    }

    /// Open the first device found.
    pub fn open_first() -> Result<Self> {
        let list = Self::list()?;
        let first = list.first().ok_or(Error::NoDevice)?;
        Self::open(first)
    }

    /// Wait (polling) until a device shows up, then open it.
    pub fn wait_and_open(timeout: Duration) -> Result<Self> {
        let start = Instant::now();
        loop {
            if let Some(first) = Self::list()?.first()
                && let Ok(t) = Self::open(first)
            {
                return Ok(t);
            }
            if start.elapsed() > timeout {
                return Err(Error::NoDevice);
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// Set a timeout for each exchange. `None` (default) waits forever, which
    /// is needed for actions requiring user confirmation.
    pub fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout;
    }

    /// How the device is reached: `"hidraw"` (hidapi), or `"usbfs"` for the
    /// Linux raw USB fallback.
    pub fn backend(&self) -> &'static str {
        match &*self.device.lock().unwrap_or_else(|e| e.into_inner()) {
            Backend::Hid(_) => "hidraw",
            #[cfg(target_os = "linux")]
            Backend::Usb(_) => "usbfs",
        }
    }

    /// Information about the opened device.
    pub fn info(&self) -> &HidDeviceInfo {
        &self.info
    }

    /// Read a response without sending anything, waiting up to `timeout`.
    ///
    /// Used after a mid-command re-enumeration (e.g. host onboarding): once
    /// the device is reopened, the host polls it again and the response it
    /// was trying to send is delivered here.
    pub fn read_pending_response(&self, timeout: Duration) -> Result<Vec<u8>> {
        let dev = self
            .device
            .lock()
            .map_err(|_| Error::Transport("device mutex poisoned".into()))?;
        let mut decoder = framing::Decoder::new(self.channel);
        let start = Instant::now();
        let mut buf = [0u8; PACKET_SIZE + 1];
        loop {
            let n = dev.read_timeout(&mut buf, 500)?;
            if n == 0 {
                if start.elapsed() > timeout {
                    return Err(Error::Timeout);
                }
                continue;
            }
            if let Some(resp) = decoder.push(&buf[..n])? {
                return Ok(resp);
            }
        }
    }

    fn exchange_blocking(&self, apdu: &[u8]) -> Result<Vec<u8>> {
        let dev = self
            .device
            .lock()
            .map_err(|_| Error::Transport("device mutex poisoned".into()))?;
        for packet in framing::encode(self.channel, apdu, PACKET_SIZE) {
            dev.write(&packet)?;
        }
        let mut decoder = framing::Decoder::new(self.channel);
        let start = Instant::now();
        let mut buf = [0u8; PACKET_SIZE + 1];
        loop {
            let n = dev.read_timeout(&mut buf, 500)?;
            if n == 0 {
                if let Some(t) = self.timeout
                    && start.elapsed() > t
                {
                    return Err(Error::Timeout);
                }
                continue;
            }
            if let Some(resp) = decoder.push(&buf[..n])? {
                return Ok(resp);
            }
        }
    }
}

fn map_hid_err(e: hidapi::HidError) -> Error {
    let s = e.to_string();
    if s.contains("No such device")
        || s.contains("disconnected")
        || s.contains("Input/output error")
    {
        Error::Disconnected
    } else {
        Error::Transport(s)
    }
}

impl Transport for HidTransport {
    async fn exchange(&self, apdu: &[u8]) -> Result<Vec<u8>> {
        self.exchange_blocking(apdu)
    }
}
