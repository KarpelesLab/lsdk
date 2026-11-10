//! High level device management: genuine check, apps, firmware update.
//!
//! These operations combine dashboard APDUs, the manager HTTP API and the HSM
//! secure channel. The device must be on the dashboard (no app open).

use serde::Serialize;

use crate::device::Device;
use crate::error::{Error, Result};
use crate::hsm::{self, HsmEvent};
use crate::manager::api::{
    self, Application, DeviceVersion, FinalFirmware, LanguagePackage, ManagerApi, McuVersion,
    OsuFirmware,
};
use crate::os::{InstalledApp, OsVersion};
use crate::transport::Transport;

/// Statuses returned when installing an app that is already installed.
fn is_already_installed(sw: crate::apdu::StatusWord) -> bool {
    matches!(sw.0, 0x6a80 | 0x6a81 | 0x6a8e | 0x6a8f)
}

/// Expected HSM result for a genuine device.
pub const GENUINE_RESULT: &str = "0000";

/// Manager API + HSM endpoints.
#[derive(Clone, Debug)]
pub struct Manager {
    pub api: ManagerApi,
    pub hsm_url: String,
}

impl Default for Manager {
    fn default() -> Self {
        Self {
            api: ManagerApi::default(),
            hsm_url: hsm::DEFAULT_BASE_URL.into(),
        }
    }
}

/// Firmware context of a device, as known by the manager API.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirmwareContext {
    pub os: OsVersion,
    pub device_version: DeviceVersion,
    /// Current final firmware (absent while in OSU / bootloader).
    pub firmware: Option<FinalFirmware>,
}

/// An available firmware update.
#[derive(Clone, Debug, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirmwareUpdate {
    pub osu: OsuFirmware,
    #[serde(rename = "final")]
    pub final_firmware: FinalFirmware,
    /// The MCU must be flashed after the OSU (older models only).
    pub should_flash_mcu: bool,
}

/// Outcome of one MCU / bootloader flash step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FlashKind {
    Mcu,
    Bootloader,
}

/// An installed app with its catalog entry (if found).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledAppInfo {
    pub installed: InstalledApp,
    pub catalog: Option<Application>,
}

/// Result of the HSM based app listing.
#[derive(Clone, Debug, Serialize, serde::Deserialize)]
pub struct HsmListedApp {
    pub name: String,
    pub hash: String,
    #[serde(default)]
    pub hash_code_data: Option<String>,
}

impl Manager {
    pub fn new(api_base: impl Into<String>, hsm_base: impl Into<String>) -> Self {
        Self {
            api: ManagerApi::new(api_base),
            hsm_url: hsm_base.into(),
        }
    }

    async fn ensure_dashboard<T: Transport>(&self, device: &Device<T>) -> Result<()> {
        if device.is_on_dashboard().await? {
            Ok(())
        } else {
            Err(Error::DashboardExpected)
        }
    }

    /// Read the device version and resolve it against the manager API.
    pub async fn firmware_context<T: Transport>(
        &self,
        device: &Device<T>,
    ) -> Result<FirmwareContext> {
        let os = device.get_version().await?;
        self.firmware_context_for(os).await
    }

    /// Resolve an already read [`OsVersion`] against the manager API.
    pub async fn firmware_context_for(&self, os: OsVersion) -> Result<FirmwareContext> {
        let provider = os.provider_id();
        let device_version = self.api.get_device_version(os.target_id, provider).await?;
        let firmware = if os.is_osu || os.is_bootloader {
            None
        } else {
            Some(
                self.api
                    .get_firmware_version(device_version.id, &os.version(), provider)
                    .await?,
            )
        };
        Ok(FirmwareContext {
            os,
            device_version,
            firmware,
        })
    }

    /// Run the genuine check.
    ///
    /// It proves the secure element is authentic and its firmware unmodified,
    /// not that the rest of the device is free of added hardware (spy
    /// implants...): only buying directly from the manufacturer guarantees that.
    ///
    /// Returns `true` if the HSM vouches for the device. The user has to
    /// allow the secure channel on the device.
    pub async fn genuine_check<T: Transport>(
        &self,
        device: &Device<T>,
        on_event: &mut dyn FnMut(HsmEvent),
    ) -> Result<bool> {
        self.ensure_dashboard(device).await?;
        let ctx = self.firmware_context(device).await?;
        let fw = ctx
            .firmware
            .ok_or_else(|| Error::App("device is updating its firmware".into()))?;
        let target = ctx.os.target_id.to_string();
        let url = hsm::build_url(
            &self.hsm_url,
            "/genuine",
            &[("targetId", &target), ("perso", &fw.perso)],
        );
        let out = hsm::run(device.transport(), &url, on_event).await?;
        Ok(out.result.as_ref().and_then(|v| v.as_str()) == Some(GENUINE_RESULT))
    }

    /// List installed apps through the HSM (alternative to [`Device::list_apps`]).
    pub async fn list_installed_apps_hsm<T: Transport>(
        &self,
        device: &Device<T>,
        on_event: &mut dyn FnMut(HsmEvent),
    ) -> Result<Vec<HsmListedApp>> {
        self.ensure_dashboard(device).await?;
        let ctx = self.firmware_context(device).await?;
        let fw = ctx
            .firmware
            .ok_or_else(|| Error::App("device is updating its firmware".into()))?;
        let target = ctx.os.target_id.to_string();
        let url = hsm::build_url(
            &self.hsm_url,
            "/apps/list",
            &[("targetId", &target), ("perso", &fw.perso)],
        );
        let out = hsm::run(device.transport(), &url, on_event).await?;
        match out.result {
            Some(v) => Ok(serde_json::from_value(v)?),
            None => Ok(Vec::new()),
        }
    }

    /// App catalog available for this device and firmware.
    pub async fn catalog(&self, os: &OsVersion) -> Result<Vec<Application>> {
        self.api
            .get_apps_by_target(os.target_id, &os.version(), os.provider_id())
            .await
    }

    /// Installed apps (via `LIST_APPS`) with their catalog metadata.
    pub async fn installed_apps<T: Transport>(
        &self,
        device: &Device<T>,
    ) -> Result<Vec<InstalledAppInfo>> {
        let installed = device.list_apps().await?;
        if installed.is_empty() {
            return Ok(Vec::new());
        }
        let hashes: Vec<String> = installed.iter().map(|a| a.hash.clone()).collect();
        let meta = self.api.get_apps_by_hash(&hashes).await.unwrap_or_default();
        Ok(installed
            .into_iter()
            .enumerate()
            .map(|(i, installed)| InstalledAppInfo {
                installed,
                catalog: meta.get(i).cloned().flatten(),
            })
            .collect())
    }

    /// Install one app (no dependency resolution, see [`Manager::install_app_with_deps`]).
    pub async fn install_app<T: Transport>(
        &self,
        device: &Device<T>,
        os: &OsVersion,
        app: &Application,
        on_event: &mut dyn FnMut(HsmEvent),
    ) -> Result<()> {
        let target = os.target_id.to_string();
        let url = hsm::build_url(
            &self.hsm_url,
            "/install",
            &[
                ("targetId", &target),
                ("perso", &app.perso),
                ("deleteKey", &app.delete_key),
                ("firmware", &app.firmware),
                ("firmwareKey", &app.firmware_key),
                ("hash", &app.hash),
            ],
        );
        match hsm::run(device.transport(), &url, on_event).await {
            Ok(_) => Ok(()),
            Err(Error::Status(sw)) if sw.0 == 0x6a83 || sw.0 == 0x6811 => Err(Error::App(format!(
                "{} requires {} to be installed first",
                app.version_name,
                app.parent_name.as_deref().unwrap_or("another app")
            ))),
            Err(Error::Status(sw)) if sw.0 == 0x6a84 || sw.0 == 0x5102 => {
                Err(Error::App("not enough space on the device".into()))
            }
            Err(e) => Err(e),
        }
    }

    /// Install an app by name, with its parent app (e.g. Ethereum for its
    /// plugins) when needed.
    ///
    /// `installed`: names of the apps known to be installed (from a previous
    /// [`Device::list_apps`]); listing apps requires the user's approval, so
    /// this method never lists them itself. With `None`, the parent is
    /// installed unconditionally and "already installed" is not an error.
    pub async fn install_app_with_deps<T: Transport>(
        &self,
        device: &Device<T>,
        name: &str,
        installed: Option<&[String]>,
        on_event: &mut dyn FnMut(&str, HsmEvent),
    ) -> Result<()> {
        self.ensure_dashboard(device).await?;
        let os = device.get_version().await?;
        let catalog = self.catalog(&os).await?;
        let find = |n: &str| {
            catalog
                .iter()
                .find(|a| a.version_name.eq_ignore_ascii_case(n))
                .cloned()
                .ok_or_else(|| {
                    Error::NotFound(format!("app {n:?} is not available for this device"))
                })
        };
        let app = find(name)?;
        if let Some(parent) = app.parent_name.as_deref() {
            let known = installed.map(|list| list.iter().any(|a| a.eq_ignore_ascii_case(parent)));
            if known != Some(true) {
                let parent_app = find(parent)?;
                let label = parent_app.version_name.clone();
                match self
                    .install_app(device, &os, &parent_app, &mut |ev| on_event(&label, ev))
                    .await
                {
                    Ok(()) => {}
                    Err(Error::Status(sw)) if known.is_none() && is_already_installed(sw) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        let label = app.version_name.clone();
        self.install_app(device, &os, &app, &mut |ev| on_event(&label, ev))
            .await
    }

    /// Uninstall one app.
    pub async fn uninstall_app<T: Transport>(
        &self,
        device: &Device<T>,
        os: &OsVersion,
        app: &Application,
        on_event: &mut dyn FnMut(HsmEvent),
    ) -> Result<()> {
        let target = os.target_id.to_string();
        let url = hsm::build_url(
            &self.hsm_url,
            "/install",
            &[
                ("targetId", &target),
                ("perso", &app.perso),
                ("deleteKey", &app.delete_key),
                ("firmware", &app.delete),
                ("firmwareKey", &app.delete_key),
                ("hash", &app.hash),
            ],
        );
        match hsm::run(device.transport(), &url, on_event).await {
            Ok(_) => Ok(()),
            Err(Error::Status(sw)) if sw.0 == 0x6a83 => Err(Error::App(format!(
                "other apps depend on {}, uninstall them first",
                app.version_name
            ))),
            Err(e) => Err(e),
        }
    }

    /// Uninstall an app by name. Uses the catalog entry of that name (no app
    /// listing, which would require the user's approval).
    pub async fn uninstall_app_by_name<T: Transport>(
        &self,
        device: &Device<T>,
        name: &str,
        on_event: &mut dyn FnMut(HsmEvent),
    ) -> Result<()> {
        self.ensure_dashboard(device).await?;
        let os = device.get_version().await?;
        let app = self
            .catalog(&os)
            .await?
            .into_iter()
            .find(|a| a.version_name.eq_ignore_ascii_case(name))
            .ok_or_else(|| Error::NotFound(format!("no catalog entry for {name:?}")))?;
        self.uninstall_app(device, &os, &app, on_event).await
    }

    /// Check whether a firmware update is available.
    pub async fn check_firmware_update(&self, os: &OsVersion) -> Result<Option<FirmwareUpdate>> {
        if os.is_bootloader {
            return Err(Error::App(
                "device is in bootloader mode: finish the update with repair_mcu (flash the MCU) first".into(),
            ));
        }
        let provider = os.provider_id();
        let dv = self.api.get_device_version(os.target_id, provider).await?;
        let osu = if os.is_osu {
            Some(
                self.api
                    .get_osu_version(dv.id, &os.raw_version, provider)
                    .await?,
            )
        } else {
            let current = self
                .api
                .get_firmware_version(dv.id, &os.version(), provider)
                .await?;
            self.api
                .get_latest_firmware(current.id, dv.id, provider)
                .await?
        };
        let Some(osu) = osu else { return Ok(None) };
        let final_firmware = self
            .api
            .get_final_firmware_by_id(osu.next_se_firmware_final_version)
            .await?;
        let mcus = self.api.get_mcu_versions().await?;
        let should_flash_mcu = match mcus.iter().find(|m| m.name == os.mcu_version()) {
            Some(current) => !final_firmware.mcu_versions.contains(&current.id),
            None if os.mcu_version().is_empty() => false,
            None => {
                return Err(Error::NotFound(format!(
                    "unknown MCU version {:?}",
                    os.mcu_version()
                )));
            }
        };
        Ok(Some(FirmwareUpdate {
            osu,
            final_firmware,
            should_flash_mcu,
        }))
    }

    /// Step 1 of a firmware update: install the OS updater. The user confirms
    /// on the device; it then reboots (the transport must be reopened).
    pub async fn install_osu<T: Transport>(
        &self,
        device: &Device<T>,
        update: &FirmwareUpdate,
        on_event: &mut dyn FnMut(HsmEvent),
    ) -> Result<()> {
        let os = device.get_version().await?;
        if os.is_bootloader {
            return Err(Error::App(
                "device is in bootloader mode, flash the MCU instead".into(),
            ));
        }
        let target = os.target_id.to_string();
        let url = hsm::build_url(
            &self.hsm_url,
            "/install",
            &[
                ("targetId", &target),
                ("perso", &update.osu.perso),
                ("firmware", &update.osu.firmware),
                ("firmwareKey", &update.osu.firmware_key),
            ],
        );
        match hsm::run(device.transport(), &url, on_event).await {
            // The device reboots at the end of the bulk phase, losing the link is expected.
            Ok(_) | Err(Error::Disconnected) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Step 2 (only when [`FirmwareUpdate::should_flash_mcu`]): with the device in
    /// bootloader mode, flash the MCU or the bootloader. Repeat (reopening the
    /// transport each time) while the device stays in bootloader mode.
    pub async fn flash_mcu<T: Transport>(
        &self,
        device: &Device<T>,
        update: &FirmwareUpdate,
        on_event: &mut dyn FnMut(HsmEvent),
    ) -> Result<FlashKind> {
        let os = device.get_version().await?;
        if !os.is_bootloader {
            return Err(Error::App("device is not in bootloader mode".into()));
        }
        self.flash_mcu_for(device, &os, &update.final_firmware, on_event)
            .await
    }

    /// Recovery from bootloader mode without an update context (page reloaded,
    /// update interrupted...): the bootloader reports the installed SE firmware,
    /// from which the required MCU is derived. Returns `None` when the device
    /// is not in bootloader mode.
    pub async fn repair_mcu<T: Transport>(
        &self,
        device: &Device<T>,
        on_event: &mut dyn FnMut(HsmEvent),
    ) -> Result<Option<FlashKind>> {
        let os = device.get_version().await?;
        if !os.is_bootloader {
            return Ok(None);
        }
        let (Some(se_target), false) = (os.se_target_id, os.se_version.is_empty()) else {
            return Err(Error::App(
                "the bootloader does not report the installed firmware; cannot pick an MCU version"
                    .into(),
            ));
        };
        let provider = os.provider_id();
        let dv = self.api.get_device_version(se_target, provider).await?;
        let final_firmware = self
            .api
            .get_firmware_version(dv.id, &os.se_version, provider)
            .await?;
        self.flash_mcu_for(device, &os, &final_firmware, on_event)
            .await
            .map(Some)
    }

    async fn flash_mcu_for<T: Transport>(
        &self,
        device: &Device<T>,
        os: &OsVersion,
        final_firmware: &FinalFirmware,
        on_event: &mut dyn FnMut(HsmEvent),
    ) -> Result<FlashKind> {
        let mcus = self.api.get_mcu_versions().await?;
        let provider = os.provider_id();
        let candidates: Vec<McuVersion> = mcus
            .into_iter()
            .filter(|m| {
                m.providers.contains(&provider)
                    && m.from_bootloader_version != "none"
                    && final_firmware.mcu_versions.contains(&m.id)
            })
            .collect();
        let mcu = api::find_best_mcu(&candidates)
            .ok_or_else(|| Error::NotFound("no suitable MCU version".into()))?;
        let bootloader_version: String = mcu
            .from_bootloader_version
            .split('.')
            .take(3)
            .collect::<Vec<_>>()
            .join(".");
        let is_mcu = os.maj_min() == bootloader_version;
        let version = if is_mcu {
            mcu.name.clone()
        } else {
            bootloader_version
        };
        let target = os.target_id.to_string();
        let url = hsm::build_url(
            &self.hsm_url,
            "/mcu",
            &[("targetId", &target), ("version", &version)],
        );
        match hsm::run(device.transport(), &url, on_event).await {
            Ok(_) | Err(Error::Disconnected) => Ok(if is_mcu {
                FlashKind::Mcu
            } else {
                FlashKind::Bootloader
            }),
            Err(e) => Err(e),
        }
    }

    /// Language packs available for the device's firmware.
    pub async fn language_packs(&self, os: &OsVersion) -> Result<Vec<LanguagePackage>> {
        let provider = os.provider_id();
        let dv = self.api.get_device_version(os.target_id, provider).await?;
        let fw = self
            .api
            .get_firmware_version(dv.id, &os.version(), provider)
            .await?;
        self.api.get_language_packages(dv.id, fw.id).await
    }

    /// Install a language pack: removes the installed packs (one at a time
    /// is supported), then replays the signed install script.
    /// `on_progress(sent, total)` counts APDUs.
    pub async fn install_language_pack<T: Transport>(
        &self,
        device: &Device<T>,
        pack: &LanguagePackage,
        on_progress: &mut dyn FnMut(usize, usize),
    ) -> Result<()> {
        self.ensure_dashboard(device).await?;
        let script = self.api.fetch_text(&pack.apdu_install_url).await?;
        device.install_language_script(&script, on_progress).await
    }

    /// Remove every language pack (back to English).
    pub async fn remove_language_packs<T: Transport>(&self, device: &Device<T>) -> Result<()> {
        self.ensure_dashboard(device).await?;
        for installed in device.list_language_packs().await? {
            device.delete_language_pack(installed.id as u8).await?;
        }
        Ok(())
    }
}
