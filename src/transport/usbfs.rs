//! Linux fallback for [`super::hid::HidTransport`]: talk to the HID interface
//! over usbfs (`/dev/bus/usb/BBB/DDD`) with `rawusb` when the hidraw node is
//! not accessible.
//!
//! The kernel `usbhid` driver is detached from the interface while it is in
//! use (its hidraw node disappears meanwhile) and re-attached on drop.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rawusb::{Context, DeviceHandle, ErrorKind};

use crate::VENDOR_ID;
use crate::error::{Error, Result};

pub(crate) struct UsbHid {
    handle: DeviceHandle,
    /// Drives transfer completion: must outlive the handle's transfers.
    _ctx: Context,
    interface: u8,
    ep_in: u8,
    /// IN endpoint packet size: reads must not ask for more, or a full
    /// packet doesn't end the transfer and it waits for a next one.
    in_size: usize,
    ep_out: Option<u8>,
}

fn usb_err(e: rawusb::Error) -> Error {
    match e.kind() {
        ErrorKind::NoDevice => Error::Disconnected,
        ErrorKind::Timeout => Error::Timeout,
        _ => Error::Transport(e.to_string()),
    }
}

fn read_sysfs(dir: &Path, name: &str) -> Option<String> {
    std::fs::read_to_string(dir.join(name))
        .ok()
        .map(|s| s.trim().to_owned())
}

/// USB bus, address and interface number of a hidraw node, from sysfs:
/// `/sys/class/hidraw/hidrawN/device` is the HID device, its parent the USB
/// interface, and the interface's parent the USB device.
fn locate(hidraw: &str) -> Option<(u8, u8, u8)> {
    let name = Path::new(hidraw).file_name()?;
    let hid: PathBuf =
        std::fs::canonicalize(Path::new("/sys/class/hidraw").join(name).join("device")).ok()?;
    let iface = hid.parent()?;
    let dev = iface.parent()?;
    let interface = u8::from_str_radix(&read_sysfs(iface, "bInterfaceNumber")?, 16).ok()?;
    let bus = read_sysfs(dev, "busnum")?.parse().ok()?;
    let addr = read_sysfs(dev, "devnum")?.parse().ok()?;
    Some((bus, addr, interface))
}

impl UsbHid {
    /// Open the USB device behind `hidraw` (falling back to the first device
    /// with this product id when sysfs can't tell).
    pub fn open(hidraw: &str, product_id: u16) -> Result<Self> {
        let ctx = Context::new().map_err(usb_err)?;
        let devices = ctx.devices().map_err(usb_err)?;
        let located = locate(hidraw);
        let dev = devices
            .into_iter()
            .find(|d| match located {
                Some((bus, addr, _)) => d.bus_number() == bus && d.address() == addr,
                None => d.vendor_id() == VENDOR_ID && d.product_id() == product_id,
            })
            .ok_or(Error::NoDevice)?;
        let cfg = dev.active_config_descriptor().map_err(usb_err)?;
        // The APDU interface: the one behind the hidraw node, else the first
        // HID interface.
        let alt = cfg
            .interfaces
            .iter()
            .filter_map(|i| i.alt_setting(0))
            .find(|a| match located {
                Some((_, _, n)) => a.number == n,
                None => a.class == 3,
            })
            .ok_or_else(|| Error::Transport("no HID interface".into()))?;
        let (ep_in, in_size) = alt
            .endpoints
            .iter()
            .find(|e| e.address & 0x80 != 0)
            .map(|e| (e.address, usize::from(e.max_packet_size & 0x7ff).max(1)))
            .ok_or_else(|| Error::Transport("no IN endpoint".into()))?;
        let ep_out = alt
            .endpoints
            .iter()
            .map(|e| e.address)
            .find(|a| a & 0x80 == 0);
        let interface = alt.number;
        let handle = dev.open().map_err(usb_err)?;
        handle.set_auto_detach_kernel_driver(true);
        handle.claim_interface(interface).map_err(usb_err)?;
        Ok(Self {
            handle,
            _ctx: ctx,
            interface,
            ep_in,
            in_size,
            ep_out,
        })
    }

    /// Send one HID report (no report id).
    pub fn write(&self, report: &[u8]) -> Result<()> {
        let timeout = Duration::from_secs(5);
        match self.ep_out {
            Some(ep) => self.handle.interrupt_write(ep, report, timeout),
            // SET_REPORT(output) on the control pipe.
            None => self.handle.control_write(
                0x21,
                0x09,
                0x0200,
                self.interface.into(),
                report,
                timeout,
            ),
        }
        .map(|_| ())
        .map_err(usb_err)
    }

    /// Read one HID report, `Ok(0)` after `timeout_ms` without data.
    pub fn read_timeout(&self, buf: &mut [u8], timeout_ms: u64) -> Result<usize> {
        let len = buf.len().min(self.in_size);
        match self.handle.interrupt_read(
            self.ep_in,
            &mut buf[..len],
            Duration::from_millis(timeout_ms),
        ) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == ErrorKind::Timeout => Ok(0),
            Err(e) => Err(usb_err(e)),
        }
    }
}
