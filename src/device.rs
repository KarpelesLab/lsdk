//! High level device handle with the dashboard commands.

use crate::apdu::{Apdu, Response, StatusWord};
use crate::error::{Error, Result};
use crate::os::{
    self, AppAndVersion, BatteryStatus, BatteryStatusKind, InstalledApp, OsVersion, ScreenSaver,
    ScreenSaverAnimation, ScreenSaverSpeed,
};
use crate::transport::Transport;

/// A device reachable through a [`Transport`].
pub struct Device<T: Transport> {
    transport: T,
}

impl<T: Transport> Device<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn into_inner(self) -> T {
        self.transport
    }

    /// Send raw bytes and get the raw answer (data + SW).
    pub async fn exchange_raw(&self, apdu: &[u8]) -> Result<Vec<u8>> {
        self.transport.exchange(apdu).await
    }

    /// Send an APDU and get the parsed response (whatever the status).
    pub async fn exchange(&self, apdu: &Apdu) -> Result<Response> {
        let raw = self.transport.exchange(&apdu.encode()?).await?;
        Response::from_raw(raw)
    }

    /// Send an APDU and return its data, failing on a non `0x9000` status.
    pub async fn send(&self, apdu: &Apdu) -> Result<Vec<u8>> {
        self.exchange(apdu).await?.ok()
    }

    /// Firmware / hardware information (`GET_VERSION`). Must be on the dashboard.
    pub async fn get_version(&self) -> Result<OsVersion> {
        let r = self.exchange(&os::GET_VERSION).await?;
        match r.sw {
            StatusWord::DEVICE_NOT_ONBOARDED | StatusWord::DEVICE_NOT_ONBOARDED_2 => {
                Err(Error::App("device is not onboarded".into()))
            }
            StatusWord::CLA_NOT_SUPPORTED | StatusWord::INS_NOT_SUPPORTED => {
                Err(Error::DashboardExpected)
            }
            _ => OsVersion::parse(&r.ok()?),
        }
    }

    /// Currently running app name and version (works in any app).
    pub async fn get_app_and_version(&self) -> Result<AppAndVersion> {
        AppAndVersion::parse(&self.send(&os::GET_APP_AND_VERSION).await?)
    }

    /// Whether the device is on the dashboard (or in bootloader).
    pub async fn is_on_dashboard(&self) -> Result<bool> {
        let r = self.exchange(&os::GET_APP_AND_VERSION).await?;
        match r.sw {
            StatusWord::OK => Ok(AppAndVersion::parse(&r.data)?.is_dashboard()),
            StatusWord::CLA_NOT_SUPPORTED | StatusWord::CLA_NOT_SUPPORTED_BOOTLOADER => Ok(true),
            StatusWord::INS_NOT_SUPPORTED => Ok(false),
            sw => Err(sw.into()),
        }
    }

    /// Ask the running app to exit back to the dashboard.
    ///
    /// Note: on most models the USB device re-enumerates when switching apps,
    /// so the transport may need to be reopened afterwards.
    pub async fn quit_app(&self) -> Result<()> {
        self.send(&os::QUIT_APP).await.map(|_| ())
    }

    /// Open an app by name (from the dashboard). Requires user confirmation on
    /// some firmwares. See [`Device::quit_app`] about re-enumeration.
    pub async fn open_app(&self, name: &str) -> Result<()> {
        let r = self.exchange(&os::open_app(name)).await?;
        match r.sw {
            StatusWord::OK => Ok(()),
            StatusWord::APP_NOT_FOUND | StatusWord(0x6984) => {
                Err(Error::NotFound(format!("app {name:?} is not installed")))
            }
            sw if sw.is_refused() => Err(Error::UserRefused),
            sw => Err(sw.into()),
        }
    }

    /// List installed apps (requires user consent on the device unless the
    /// secure channel was already allowed).
    pub async fn list_apps(&self) -> Result<Vec<InstalledApp>> {
        let mut apps = Vec::new();
        let mut r = self.exchange(&os::LIST_APPS).await?;
        loop {
            match r.sw {
                StatusWord::OK => {}
                sw if sw.is_refused() => return Err(Error::UserRefused),
                sw => return Err(sw.into()),
            }
            if r.data.is_empty() {
                break;
            }
            apps.extend(os::parse_list_apps(&r.data)?);
            r = self.exchange(&os::LIST_APPS_CONTINUE).await?;
        }
        Ok(apps)
    }

    /// Device name (as shown over Bluetooth). The device asks the user to
    /// allow it, so avoid calling this implicitly.
    pub async fn get_device_name(&self) -> Result<String> {
        let data = self.send(&os::GET_DEVICE_NAME).await?;
        Ok(String::from_utf8_lossy(&data).into_owned())
    }

    /// Rename the device (requires user confirmation).
    pub async fn set_device_name(&self, name: &str) -> Result<()> {
        if name.is_empty() || name.len() > 32 {
            return Err(Error::InvalidInput("name must be 1..=32 bytes".into()));
        }
        match self.exchange(&os::set_device_name(name)).await?.sw {
            StatusWord::OK => Ok(()),
            sw if sw.is_refused() => Err(Error::UserRefused),
            sw => Err(sw.into()),
        }
    }

    fn screen_saver_err(sw: StatusWord) -> Error {
        match sw {
            sw if sw.is_refused() => Error::UserRefused,
            // The dashboard answers 0x6d02 outside recovery mode and for a
            // malformed request (verified on a Nano S Plus).
            StatusWord(0x6d00..=0x6dff) => Error::App(
                "screensaver command rejected: only accepted in recovery mode (Nano X / Nano S Plus), with a valid request"
                    .into(),
            ),
            sw => sw.into(),
        }
    }

    /// Current custom screensaver, `None` for the default one. Recovery mode only.
    pub async fn get_screen_saver(&self) -> Result<Option<ScreenSaver>> {
        let r = self.exchange(&os::get_screen_saver()).await?;
        if !r.sw.is_ok() {
            return Err(Self::screen_saver_err(r.sw));
        }
        ScreenSaver::parse(&r.data)
    }

    /// Set a custom scrolling-text screensaver (user confirmation required).
    /// Recovery mode only.
    pub async fn set_screen_saver(
        &self,
        text: &str,
        animation: ScreenSaverAnimation,
        speed: ScreenSaverSpeed,
    ) -> Result<()> {
        let r = self
            .exchange(&os::set_screen_saver(text, animation, speed)?)
            .await?;
        if r.sw.is_ok() {
            Ok(())
        } else {
            Err(Self::screen_saver_err(r.sw))
        }
    }

    /// Restore the default screensaver (user confirmation required). Recovery mode only.
    pub async fn reset_screen_saver(&self) -> Result<()> {
        let r = self.exchange(&os::reset_screen_saver()).await?;
        if r.sw.is_ok() {
            Ok(())
        } else {
            Err(Self::screen_saver_err(r.sw))
        }
    }

    /// Query one battery metric (raw payload).
    pub async fn get_battery_raw(&self, kind: BatteryStatusKind) -> Result<Vec<u8>> {
        self.send(&os::get_battery_status(kind)).await
    }

    /// Battery summary (models with a battery only).
    pub async fn get_battery_status(&self) -> Result<BatteryStatus> {
        let mut st = BatteryStatus::default();
        let p = self.get_battery_raw(BatteryStatusKind::Percentage).await?;
        st.percentage = p.first().copied().filter(|v| *v <= 100);
        if let Ok(v) = self.get_battery_raw(BatteryStatusKind::Voltage).await
            && v.len() >= 2
        {
            st.voltage_mv = Some(u16::from_be_bytes([v[0], v[1]]));
        }
        if let Ok(v) = self.get_battery_raw(BatteryStatusKind::Temperature).await {
            st.temperature_c = v.first().map(|b| *b as i8);
        }
        if let Ok(v) = self.get_battery_raw(BatteryStatusKind::Current).await {
            st.current_ma = v.first().map(|b| *b as i8);
        }
        if let Ok(v) = self.get_battery_raw(BatteryStatusKind::Flags).await
            && v.len() >= 4
        {
            let f = u32::from_be_bytes([v[0], v[1], v[2], v[3]]);
            st.raw_flags = Some(f);
            st.charging = f & 0x1 != 0;
            st.usb_connected = f & 0x2 != 0;
            st.ble_connected = f & 0x4 != 0;
        }
        Ok(st)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mock::MockTransport;

    fn block_on<F: core::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn list_apps_paging() {
        let mut page = String::from("01");
        page += &format!("{:02x}", 70 + 3);
        page += "00100000";
        page += &"aa".repeat(32);
        page += &"bb".repeat(32);
        page += "03657468";
        let t = MockTransport::new()
            .expect("e0de000000", &format!("{page}9000"))
            .expect("e0df000000", "9000");
        let d = Device::new(t);
        let apps = block_on(d.list_apps()).unwrap();
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].name, "eth");
        assert!(d.transport().is_done());
    }

    #[test]
    fn dashboard_detection() {
        let t = MockTransport::new().expect("b001000000", "6e01");
        assert!(block_on(Device::new(t).is_on_dashboard()).unwrap());
    }
}
