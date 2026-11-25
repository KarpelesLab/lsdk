//! High level device management: genuine check, apps, firmware update.
//!
//! These operations combine dashboard APDUs, the manager HTTP API and the HSM
//! secure channel. The device must be on the dashboard (no app open).

use serde::Serialize;

use crate::device::Device;
use crate::error::{Error, Result};
use crate::hsm::{self, HsmEvent};
use crate::manager::api::{
    self, Application, CatalogFinal, CatalogOsu, DeviceVersion, FinalFirmware, LanguagePackage,
    ManagerApi, McuVersion, OsuFirmware,
};
use crate::os::{InstalledApp, OsVersion};
use crate::transport::Transport;

/// Statuses returned when installing an app that is already installed.
fn is_already_installed(sw: crate::apdu::StatusWord) -> bool {
    matches!(sw.0, 0x6a80 | 0x6a81 | 0x6a8e | 0x6a8f)
}

/// Expected HSM result for a genuine device.
pub const GENUINE_RESULT: &str = "0000";

/// Vendor endorsement owner key reference used by [`Manager::vendor_endorse`].
pub const VENDOR_ENDORSEMENT_KEY: &str = "attest_1";

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
    /// OSU hash the device should display once received (to compare on
    /// screen). Differs from `osu.hash` when the API value is known wrong.
    #[serde(default)]
    pub expected_hash: Option<String>,
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

/// One OS updater reachable from a final firmware, and what follows it.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirmwarePath {
    pub osu: CatalogOsu,
    /// The final firmware the OSU installs.
    pub target: CatalogFinal,
    /// Names of the MCU versions the target accepts (same order as
    /// `target.mcu_versions`).
    pub target_mcu_names: Vec<String>,
    /// Whether the OSU is distributed to the device's provider (otherwise the
    /// API won't hand it out).
    pub available: bool,
    pub next: Vec<FirmwarePath>,
}

/// Update paths from the device's current firmware.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirmwarePaths {
    pub current: CatalogFinal,
    pub device_version: u32,
    pub provider: u32,
    pub paths: Vec<FirmwarePath>,
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

    /// Vendor endorsement: the HSM opens a secure channel, has the device
    /// generate the endorsement key of `slot` and stores a certificate signed
    /// by the vendor's own endorsement owner key (`endorse`, default
    /// [`VENDOR_ENDORSEMENT_KEY`]). Apps can then prove to third parties that
    /// they run on a genuine device. This replaces any key already in the slot.
    pub async fn vendor_endorse<T: Transport>(
        &self,
        device: &Device<T>,
        slot: crate::os::EndorsementSlot,
        endorse: Option<&str>,
        on_event: &mut dyn FnMut(HsmEvent),
    ) -> Result<Option<serde_json::Value>> {
        self.ensure_dashboard(device).await?;
        let ctx = self.firmware_context(device).await?;
        let fw = ctx
            .firmware
            .ok_or_else(|| Error::App("device is updating its firmware".into()))?;
        let target = ctx.os.target_id.to_string();
        let scheme = (slot as u8).to_string();
        let url = hsm::build_url(
            &self.hsm_url,
            "/endorse",
            &[
                ("targetId", &target),
                ("perso", &fw.perso),
                ("endorse", endorse.unwrap_or(VENDOR_ENDORSEMENT_KEY)),
                ("endorseScheme", &scheme),
            ],
        );
        Ok(hsm::run_legacy(device.transport(), &url, on_event)
            .await?
            .result)
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
        on_event(HsmEvent::Installing {
            name: app.firmware.clone(),
        });
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
        self.firmware_update_via(os, None).await
    }

    /// Like [`Self::check_firmware_update`], with the OS updater chosen by
    /// name (e.g. `1.4.2-osu-hidden`) instead of the latest one. The OSU must
    /// update from the device's current final firmware. Ignored when the
    /// device already runs an OS updater.
    pub async fn firmware_update_via(
        &self,
        os: &OsVersion,
        osu_name: Option<&str>,
    ) -> Result<Option<FirmwareUpdate>> {
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
            match osu_name {
                Some(name) => {
                    let osu = self.api.get_osu_version(dv.id, name, provider).await?;
                    if !osu
                        .previous_se_firmware_final_versions
                        .contains(&current.id)
                    {
                        return Err(Error::InvalidInput(format!(
                            "{name} (id {}) does not update from {} (final firmware id {}; it updates from ids {:?})",
                            osu.id,
                            current.name,
                            current.id,
                            osu.previous_se_firmware_final_versions
                        )));
                    }
                    Some(osu)
                }
                None => {
                    self.api
                        .get_latest_firmware(current.id, dv.id, provider)
                        .await?
                }
            }
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
            expected_hash: osu.expected_hash().map(str::to_owned),
            osu,
            final_firmware,
            should_flash_mcu,
        }))
    }

    /// Update paths from the device's current final firmware, `depth` OSUs
    /// deep, from the full catalog. With `all_providers`, OSUs not
    /// distributed to the device's provider are listed too (marked
    /// unavailable, and not followed further).
    pub async fn firmware_paths(
        &self,
        os: &OsVersion,
        depth: usize,
        all_providers: bool,
    ) -> Result<FirmwarePaths> {
        if os.is_bootloader || os.is_osu {
            return Err(Error::App(
                "a firmware update is in progress: finish it first".into(),
            ));
        }
        let provider = os.provider_id();
        let dv = self.api.get_device_version(os.target_id, provider).await?;
        let current_id = self
            .api
            .get_firmware_version(dv.id, &os.version(), provider)
            .await?
            .id;
        let catalog = self.api.get_firmware_catalog().await?;
        let mcus = self.api.get_mcu_versions().await?;
        let current = catalog
            .iter()
            .find(|f| f.id == current_id)
            .cloned()
            .ok_or_else(|| {
                Error::NotFound(format!("final firmware {current_id} not in catalog"))
            })?;
        struct Ctx<'a> {
            catalog: &'a [CatalogFinal],
            mcus: &'a [McuVersion],
            provider: u32,
            all: bool,
        }
        fn walk(
            cx: &Ctx,
            from: u32,
            dvs: &[u32],
            depth: usize,
            seen: &mut Vec<u32>,
        ) -> Vec<FirmwarePath> {
            let mut out = Vec::new();
            if depth == 0 {
                return out;
            }
            for f in cx.catalog {
                for o in &f.osu_versions {
                    if !o.previous_se_firmware_final_versions.contains(&from)
                        || !o.device_versions.iter().any(|d| dvs.contains(d))
                    {
                        continue;
                    }
                    let available = o.providers.contains(&cx.provider);
                    if !available && !cx.all {
                        continue;
                    }
                    let next = if available && !seen.contains(&f.id) {
                        seen.push(f.id);
                        let n = walk(cx, f.id, &f.device_versions, depth - 1, seen);
                        seen.pop();
                        n
                    } else {
                        Vec::new()
                    };
                    let mut target = f.clone();
                    target.osu_versions.clear();
                    out.push(FirmwarePath {
                        osu: o.clone(),
                        target_mcu_names: f
                            .mcu_versions
                            .iter()
                            .map(|id| {
                                cx.mcus
                                    .iter()
                                    .find(|m| m.id == *id)
                                    .map(|m| m.name.clone())
                                    .unwrap_or_else(|| "?".into())
                            })
                            .collect(),
                        target,
                        available,
                        next,
                    });
                }
            }
            out.sort_by_key(|p| (!p.available, p.target.id, p.osu.id));
            out
        }
        let cx = Ctx {
            catalog: &catalog,
            mcus: &mcus,
            provider,
            all: all_providers,
        };
        let paths = walk(&cx, current_id, &[dv.id], depth, &mut vec![current_id]);
        let mut current = current;
        current.osu_versions.clear();
        Ok(FirmwarePaths {
            current,
            device_version: dv.id,
            provider,
            paths,
        })
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
        on_event(HsmEvent::Installing {
            name: update.osu.firmware.clone(),
        });
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

    /// Run a vendor `/install` session for an explicit firmware component
    /// (`perso` / `firmware` / `firmwareKey` from the catalog) and relay it to
    /// `device`, without any device-state precondition. The firmware is
    /// streamed from the HSM, so with APDU logging (or an emulated device)
    /// this captures ("downloads") the firmware without flashing real
    /// hardware. The device reboot at the end (lost link) is treated as
    /// success.
    pub async fn install_component<T: Transport>(
        &self,
        device: &Device<T>,
        target_id: u32,
        perso: &str,
        firmware: &str,
        firmware_key: &str,
        on_event: &mut dyn FnMut(HsmEvent),
    ) -> Result<()> {
        on_event(HsmEvent::Installing {
            name: firmware.to_string(),
        });
        let target = target_id.to_string();
        let url = hsm::build_url(
            &self.hsm_url,
            "/install",
            &[
                ("targetId", &target),
                ("perso", perso),
                ("firmware", firmware),
                ("firmwareKey", firmware_key),
            ],
        );
        match hsm::run(device.transport(), &url, on_event).await {
            Ok(_) | Err(Error::Disconnected) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Whether [`Self::install_final_firmware`] is needed after the OS updater
    /// (and MCU): devices whose final firmware has its own image (Nano S).
    pub fn needs_final_install(update: &FirmwareUpdate) -> bool {
        update.final_firmware.firmware.is_some()
    }

    /// Last step on devices where [`Self::needs_final_install`]: with the device
    /// running the OS updater (it shows "Update"), install the final firmware.
    pub async fn install_final_firmware<T: Transport>(
        &self,
        device: &Device<T>,
        update: &FirmwareUpdate,
        on_event: &mut dyn FnMut(HsmEvent),
    ) -> Result<()> {
        let os = device.get_version().await?;
        if !os.is_osu {
            return Err(Error::App(
                "the device is not running the OS updater (it should show \"Update\")".into(),
            ));
        }
        let f = &update.final_firmware;
        let (firmware, key) = match (&f.firmware, &f.firmware_key) {
            (Some(fw), Some(k)) => (fw, k),
            _ => {
                return Err(Error::App(
                    "this final firmware has no separate image to install".into(),
                ));
            }
        };
        on_event(HsmEvent::Installing {
            name: firmware.clone(),
        });
        let target = os.target_id.to_string();
        let url = hsm::build_url(
            &self.hsm_url,
            "/install",
            &[
                ("targetId", &target),
                ("perso", &f.perso),
                ("firmware", firmware),
                ("firmwareKey", key),
            ],
        );
        match hsm::run(device.transport(), &url, on_event).await {
            // The device reboots at the end, losing the link is expected.
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
            return self.repair_legacy(device, os, on_event).await.map(Some);
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
        // Compare numerically: bootloaders report "0.6" for "0.6.0".
        let have = crate::model::parse_version(&os.maj_min());
        let need = crate::model::parse_version(&bootloader_version);
        if have > need {
            // Bootloaders do not roll back: flashing the older one is a no-op
            // and the update would loop on it.
            return Err(Error::App(format!(
                "firmware {} needs MCU {} (from bootloader {bootloader_version}), but this device has bootloader {}, which cannot be downgraded: install a firmware that supports the current MCU instead",
                final_firmware.name,
                mcu.name,
                os.maj_min()
            )));
        }
        let is_mcu = have == need;
        let version = if is_mcu {
            mcu.name.clone()
        } else {
            bootloader_version
        };
        let kind = if is_mcu {
            FlashKind::Mcu
        } else {
            FlashKind::Bootloader
        };
        self.install_mcu(device, os, &version, kind, on_event).await
    }

    /// Old bootloaders (Nano S, before the SE firmware was reported in
    /// bootloader mode) only give their own version: the next step is fixed
    /// per bootloader version, as in the vendor's repair flow.
    async fn repair_legacy<T: Transport>(
        &self,
        device: &Device<T>,
        os: OsVersion,
        on_event: &mut dyn FnMut(HsmEvent),
    ) -> Result<FlashKind> {
        let full = os.maj_min();
        let mm: String = full.split('.').take(2).collect::<Vec<_>>().join(".");
        let (version, kind) = match mm.as_str() {
            // A bootloader reporting no version at all: install bootloader
            // 0.6 first, the next pass then flashes the MCU.
            "0.0" => ("0.6".to_string(), FlashKind::Bootloader),
            "0.6" => ("1.5".to_string(), FlashKind::Mcu),
            "0.7" => ("1.6".to_string(), FlashKind::Mcu),
            "0.9" => ("1.7".to_string(), FlashKind::Mcu),
            _ => {
                let provider = os.provider_id();
                let mcus = self.api.get_mcu_versions().await?;
                let candidates: Vec<McuVersion> = mcus
                    .into_iter()
                    .filter(|m| {
                        m.providers.contains(&provider)
                            && (m.from_bootloader_version == mm
                                || m.from_bootloader_version == full)
                    })
                    .collect();
                let mcu = api::find_best_mcu(&candidates).ok_or_else(|| {
                    Error::NotFound(format!(
                        "no MCU version known for bootloader {full} (the bootloader does not report the installed firmware)"
                    ))
                })?;
                (mcu.name.clone(), FlashKind::Mcu)
            }
        };
        self.install_mcu(device, &os, &version, kind, on_event)
            .await
    }

    /// Flash a given MCU or bootloader `version` from bootloader mode, with
    /// no compatibility check (unlike [`Self::flash_mcu`]): for recovery and
    /// experiments. A wrong bootloader can leave the device unrecoverable.
    pub async fn flash_mcu_version<T: Transport>(
        &self,
        device: &Device<T>,
        version: &str,
        kind: FlashKind,
        on_event: &mut dyn FnMut(HsmEvent),
    ) -> Result<FlashKind> {
        let os = device.get_version().await?;
        if !os.is_bootloader {
            return Err(Error::App("device is not in bootloader mode".into()));
        }
        self.install_mcu(device, &os, version, kind, on_event).await
    }

    /// Flash an MCU or bootloader `version` through the vendor HSM.
    async fn install_mcu<T: Transport>(
        &self,
        device: &Device<T>,
        os: &OsVersion,
        version: &str,
        kind: FlashKind,
        on_event: &mut dyn FnMut(HsmEvent),
    ) -> Result<FlashKind> {
        let what = match kind {
            FlashKind::Mcu => "mcu",
            FlashKind::Bootloader => "bootloader",
        };
        on_event(HsmEvent::Installing {
            name: format!("{what} {version}"),
        });
        let target = os.target_id.to_string();
        let url = hsm::build_url(
            &self.hsm_url,
            "/mcu",
            &[("targetId", &target), ("version", version)],
        );
        match hsm::run(device.transport(), &url, on_event).await {
            // The device reboots at the end, losing the link is expected.
            Ok(_) | Err(Error::Disconnected) => Ok(kind),
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
