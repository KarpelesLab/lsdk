//! JavaScript API (wasm-bindgen) used by the web UI.
//!
//! ```js
//! import init, { HwDevice } from "lsdk";
//! await init();
//! const dev = await HwDevice.request(); // device picker (user gesture)
//! console.log(await dev.info());
//! ```

use std::cell::RefCell;

use js_sys::Function;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::apps::{btc, eth, sol};
use crate::hsm::HsmEvent;
use crate::manager::Manager;
use crate::manager::ops::FirmwareUpdate;
use crate::path::DerivationPath;
use crate::transport::webhid::{self, WebHidTransport};
use crate::{Device, Error, Result};

type JsResult<T> = core::result::Result<T, JsValue>;

fn js_err(e: Error) -> JsValue {
    let err = js_sys::Error::new(&e.to_string());
    let code = match &e {
        Error::Status(sw) => Some(format!("0x{:04x}", sw.0)),
        _ => None,
    };
    let kind = match &e {
        Error::UserRefused => "UserRefused",
        Error::Locked => "Locked",
        Error::Disconnected => "Disconnected",
        Error::DashboardExpected => "DashboardExpected",
        Error::NoDevice => "NoDevice",
        Error::NotFound(_) => "NotFound",
        Error::Status(_) => "Status",
        _ => "Error",
    };
    let _ = js_sys::Reflect::set(&err, &"kind".into(), &kind.into());
    if let Some(code) = code {
        let _ = js_sys::Reflect::set(&err, &"statusCode".into(), &code.into());
    }
    err.into()
}

fn to_js<T: Serialize + ?Sized>(v: &T) -> JsResult<JsValue> {
    v.serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|e| js_sys::Error::new(&e.to_string()).into())
}

fn from_js<T: for<'de> Deserialize<'de>>(v: JsValue) -> JsResult<T> {
    serde_wasm_bindgen::from_value(v)
        .map_err(|e| js_sys::Error::new(&format!("invalid argument: {e}")).into())
}

fn path(s: &str) -> JsResult<DerivationPath> {
    s.parse().map_err(js_err)
}

fn endorsement_slot(n: u8) -> JsResult<crate::os::EndorsementSlot> {
    match n {
        1 => Ok(crate::os::EndorsementSlot::Slot1),
        2 => Ok(crate::os::EndorsementSlot::Slot2),
        _ => Err(js_err(Error::InvalidInput("slot must be 1 or 2".into()))),
    }
}

fn scp_emitter(cb: &Option<Function>) -> impl FnMut(crate::scp::ScpEvent) + '_ {
    move |ev| {
        if let (Some(cb), Ok(v)) = (cb, to_js(&ev)) {
            let _ = cb.call1(&JsValue::NULL, &v);
        }
    }
}

fn emitter(cb: Option<Function>) -> impl FnMut(HsmEvent) {
    move |ev: HsmEvent| {
        if let Some(cb) = &cb
            && let Ok(v) = to_js(&ev)
        {
            let _ = cb.call1(&JsValue::NULL, &v);
        }
    }
}

/// Whether the browser supports WebHID.
#[wasm_bindgen(js_name = isSupported)]
pub fn is_supported() -> bool {
    js_sys::Reflect::get(&js_sys::global(), &"navigator".into())
        .and_then(|n| js_sys::Reflect::get(&n, &"hid".into()))
        .map(|h| !h.is_undefined())
        .unwrap_or(false)
}

/// Derive single-sig addresses locally from an account xpub.
#[wasm_bindgen(js_name = btcDeriveAddresses)]
pub fn btc_derive_addresses(
    xpub: &str,
    kind: &str,
    testnet: bool,
    change: u32,
    start: u32,
    count: u32,
) -> JsResult<JsValue> {
    let kind = btc::AddressType::parse(kind).map_err(js_err)?;
    let x = btc::Xpub::parse(xpub).map_err(js_err)?;
    let mut out = Vec::new();
    for i in start..start + count {
        let (_, addr, _) =
            btc::psbt::derive_script(&x, kind, testnet, change, i).map_err(js_err)?;
        out.push(addr);
    }
    to_js(&out)
}

/// Generate a CA / root key. Returns `{ privateKey, publicKey }` (hex).
#[wasm_bindgen(js_name = generateRootKey)]
pub fn generate_root_key() -> JsResult<JsValue> {
    let k = crate::scp::RootKey::generate().map_err(js_err)?;
    to_js(
        &serde_json::json!({ "privateKey": hex::encode(k.to_bytes()), "publicKey": hex::encode(k.public_key()) }),
    )
}

/// Public key (hex) of a private key (hex).
#[wasm_bindgen(js_name = rootPublicKey)]
pub fn root_public_key(private_key: &str) -> JsResult<String> {
    Ok(hex::encode(
        crate::scp::RootKey::from_hex(private_key)
            .map_err(js_err)?
            .public_key(),
    ))
}

/// Metadata of an app ELF (name, version, flags, API level, target id...).
#[wasm_bindgen(js_name = appImageInfo)]
pub fn app_image_info(elf: &[u8]) -> JsResult<JsValue> {
    let img = crate::loader::AppImage::from_elf(elf).map_err(js_err)?;
    let mut v = serde_json::to_value(&img).map_err(|e| js_err(Error::App(e.to_string())))?;
    v["imageSize"] = img.image_size().into();
    to_js(&v)
}

fn root_or_random(key: Option<String>) -> Result<crate::scp::RootKey> {
    match key.filter(|k| !k.trim().is_empty()) {
        Some(k) => crate::scp::RootKey::from_hex(&k),
        None => crate::scp::RootKey::generate(),
    }
}

/// Estimated virtual size of a single-sig transaction.
#[wasm_bindgen(js_name = btcEstimateVsize)]
pub fn btc_estimate_vsize(kind: &str, inputs: usize, outputs: usize) -> JsResult<f64> {
    Ok(btc::psbt::estimate_vsize(
        btc::AddressType::parse(kind).map_err(js_err)?,
        inputs,
        outputs,
    ) as f64)
}

/// Parse a decimal amount into base units (string).
#[wasm_bindgen(js_name = parseUnits)]
pub fn parse_units(amount: &str, decimals: u32) -> JsResult<String> {
    eth::parse_units(amount, decimals)
        .map(|v| v.to_string())
        .map_err(js_err)
}

/// Firmware / app catalog lookups that don't need a device.
#[wasm_bindgen(js_name = catalogFor)]
pub async fn catalog_for(
    target_id: u32,
    version: String,
    provider: Option<u32>,
) -> JsResult<JsValue> {
    let m = Manager::default();
    to_js(
        &m.api
            .get_apps_by_target(target_id, &version, provider.unwrap_or(1))
            .await
            .map_err(js_err)?,
    )
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InfoOut {
    model: Option<&'static str>,
    product_name: String,
    product_id: u16,
    app: Option<crate::os::AppAndVersion>,
    version: Option<crate::os::OsVersion>,
    /// The device is locked (PIN / screensaver): unlock it to continue.
    locked: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EthTxIn {
    chain_id: u64,
    nonce: u64,
    to: String,
    #[serde(default)]
    value: Option<String>,
    gas: u64,
    #[serde(default)]
    max_fee: Option<String>,
    #[serde(default)]
    priority_fee: Option<String>,
    #[serde(default)]
    gas_price: Option<String>,
    #[serde(default)]
    data: Option<String>,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    decimals: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EthTxOut {
    unsigned: String,
    raw: String,
    hash: String,
    from: String,
    signature: eth::EthSignature,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BtcSendIn {
    kind: String,
    #[serde(default)]
    account: u32,
    #[serde(default)]
    testnet: bool,
    utxos: Vec<btc::Utxo>,
    payments: Vec<btc::Payment>,
    #[serde(default)]
    change_index: Option<u32>,
    #[serde(default)]
    change_amount: Option<u64>,
    #[serde(default = "yes")]
    rbf: bool,
}

fn yes() -> bool {
    true
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BtcSendOut {
    unsigned_psbt: String,
    signed_psbt: String,
    tx: String,
    txid: String,
    signatures: Vec<btc::PartialSignature>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BtcAccountOut {
    key: String,
    xpub: String,
    fingerprint: String,
    path: String,
    descriptor: String,
    change_descriptor: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SolTxOut {
    from: String,
    base64: String,
    base58: String,
    signature: String,
}

/// A device connected over WebHID.
#[wasm_bindgen]
pub struct HwDevice {
    device: Device<WebHidTransport>,
    manager: RefCell<Manager>,
}

impl HwDevice {
    fn manager(&self) -> Manager {
        self.manager.borrow().clone()
    }
}

#[wasm_bindgen]
impl HwDevice {
    /// Open the browser device picker and connect. Must run in a user gesture.
    pub async fn request() -> JsResult<HwDevice> {
        let t = WebHidTransport::request().await.map_err(js_err)?;
        Ok(Self::from_transport(t))
    }

    /// Reconnect to an already authorized device (no picker), e.g. after the
    /// device re-enumerated (app opened / closed, firmware reboot).
    pub async fn reconnect() -> JsResult<HwDevice> {
        let t = WebHidTransport::open_granted().await.map_err(js_err)?;
        Ok(Self::from_transport(t))
    }

    /// Number of authorized devices currently plugged.
    #[wasm_bindgen(js_name = grantedCount)]
    pub async fn granted_count() -> JsResult<u32> {
        Ok(webhid::granted_devices().await.map_err(js_err)?.len() as u32)
    }

    fn from_transport(t: WebHidTransport) -> Self {
        Self {
            device: Device::new(t),
            manager: RefCell::new(Manager::default()),
        }
    }

    /// Override the manager API / HSM endpoints.
    #[wasm_bindgen(js_name = setEndpoints)]
    pub fn set_endpoints(&self, api: String, hsm: String) {
        *self.manager.borrow_mut() = Manager::new(api, hsm);
    }

    #[wasm_bindgen(getter, js_name = productName)]
    pub fn product_name(&self) -> String {
        self.device.transport().device().product_name()
    }

    #[wasm_bindgen(getter, js_name = productId)]
    pub fn product_id(&self) -> u16 {
        self.device.transport().product_id()
    }

    #[wasm_bindgen(getter)]
    pub fn model(&self) -> Option<String> {
        self.device
            .transport()
            .model()
            .map(|m| m.name().to_string())
    }

    /// The underlying browser `HIDDevice` (to match `navigator.hid` events).
    #[wasm_bindgen(getter, js_name = hidDevice)]
    pub fn hid_device(&self) -> JsValue {
        self.device.transport().device().clone().into()
    }

    #[wasm_bindgen(getter)]
    pub fn disconnected(&self) -> bool {
        self.device.transport().is_disconnected()
    }

    pub async fn close(&self) -> JsResult<()> {
        self.device.transport().close().await.map_err(js_err)
    }

    /// App + firmware information.
    pub async fn info(&self) -> JsResult<JsValue> {
        let (app, locked) = match self.device.get_app_and_version().await {
            Ok(a) => (Some(a), false),
            Err(Error::Locked) => (None, true),
            Err(_) => (None, false),
        };
        let on_dashboard = !locked && app.as_ref().map(|a| a.is_dashboard()).unwrap_or(true);
        // No device name here: reading it asks the user for consent on the
        // device. Use `getName()` explicitly.
        let version = if on_dashboard {
            self.device.get_version().await.ok()
        } else {
            None
        };
        let t = self.device.transport();
        to_js(&InfoOut {
            model: version
                .as_ref()
                .and_then(|v| v.model())
                .or(t.model())
                .map(|m| m.name()),
            product_name: t.device().product_name(),
            product_id: t.product_id(),
            app,
            version,
            locked,
        })
    }

    #[wasm_bindgen(js_name = appAndVersion)]
    pub async fn app_and_version(&self) -> JsResult<JsValue> {
        to_js(&self.device.get_app_and_version().await.map_err(js_err)?)
    }

    #[wasm_bindgen(js_name = openApp)]
    pub async fn open_app(&self, name: String) -> JsResult<()> {
        self.device.open_app(&name).await.map_err(js_err)
    }

    #[wasm_bindgen(js_name = quitApp)]
    pub async fn quit_app(&self) -> JsResult<()> {
        self.device.quit_app().await.map_err(js_err)
    }

    /// Installed apps with catalog metadata (consent required on device).
    #[wasm_bindgen(js_name = listApps)]
    pub async fn list_apps(&self) -> JsResult<JsValue> {
        to_js(
            &self
                .manager()
                .installed_apps(&self.device)
                .await
                .map_err(js_err)?,
        )
    }

    /// Device name. Asks the user for consent on the device.
    #[wasm_bindgen(js_name = getName)]
    pub async fn get_name(&self) -> JsResult<String> {
        self.device.get_device_name().await.map_err(js_err)
    }

    #[wasm_bindgen(js_name = setName)]
    pub async fn set_name(&self, name: String) -> JsResult<()> {
        self.device.set_device_name(&name).await.map_err(js_err)
    }

    /// Custom screensaver (`null` = default). Recovery mode only.
    #[wasm_bindgen(js_name = getScreenSaver)]
    pub async fn get_screen_saver(&self) -> JsResult<JsValue> {
        to_js(&self.device.get_screen_saver().await.map_err(js_err)?)
    }

    /// Set a custom screensaver. `animation`: classic | circle-rl | circle-lr;
    /// `speed`: fast | normal | slow. Recovery mode only, confirmed on device.
    #[wasm_bindgen(js_name = setScreenSaver)]
    pub async fn set_screen_saver(
        &self,
        text: String,
        animation: String,
        speed: String,
    ) -> JsResult<()> {
        let a = crate::os::ScreenSaverAnimation::parse(&animation).map_err(js_err)?;
        let sp = crate::os::ScreenSaverSpeed::parse(&speed).map_err(js_err)?;
        self.device
            .set_screen_saver(&text, a, sp)
            .await
            .map_err(js_err)
    }

    /// Restore the default screensaver. Recovery mode only, confirmed on device.
    #[wasm_bindgen(js_name = resetScreenSaver)]
    pub async fn reset_screen_saver(&self) -> JsResult<()> {
        self.device.reset_screen_saver().await.map_err(js_err)
    }

    pub async fn battery(&self) -> JsResult<JsValue> {
        to_js(&self.device.get_battery_status().await.map_err(js_err)?)
    }

    /// Raw APDU exchange (hex in, hex out including the status word).
    pub async fn apdu(&self, hex_apdu: String) -> JsResult<String> {
        let raw = hex::decode(hex_apdu.replace([' ', '\n'], ""))
            .map_err(|e| js_err(Error::InvalidInput(e.to_string())))?;
        Ok(hex::encode(
            self.device.exchange_raw(&raw).await.map_err(js_err)?,
        ))
    }

    #[wasm_bindgen(js_name = genuineCheck)]
    pub async fn genuine_check(&self, on_event: Option<Function>) -> JsResult<bool> {
        self.manager()
            .genuine_check(&self.device, &mut emitter(on_event))
            .await
            .map_err(js_err)
    }

    /// Offline genuine check: verify the device attestation locally (no
    /// network). The device asks to allow an insecure manager connection.
    /// `extraIssuerKeys`: optional array of hex issuer public keys to trust.
    #[wasm_bindgen(js_name = offlineGenuineCheck)]
    pub async fn offline_genuine_check(
        &self,
        on_event: Option<Function>,
        extra_issuer_keys: Option<Vec<String>>,
    ) -> JsResult<JsValue> {
        let extra = extra_issuer_keys
            .unwrap_or_default()
            .iter()
            .enumerate()
            .map(|(i, k)| {
                hex::decode(k.trim().trim_start_matches("0x"))
                    .map(|b| (format!("custom issuer key #{}", i + 1), b))
                    .map_err(|e| js_err(Error::InvalidInput(format!("issuer key: {e}"))))
            })
            .collect::<JsResult<Vec<_>>>()?;
        let mut cb = |ev: crate::attestation::AttestationEvent| {
            if let (Some(cb), Ok(v)) = (&on_event, to_js(&ev)) {
                let _ = cb.call1(&JsValue::NULL, &v);
            }
        };
        let att = crate::attestation::offline_genuine_check(&self.device, &extra, &mut cb)
            .await
            .map_err(js_err)?;
        to_js(&att)
    }

    /// App catalog for this device.
    pub async fn catalog(&self) -> JsResult<JsValue> {
        let os = self.device.get_version().await.map_err(js_err)?;
        to_js(&self.manager().catalog(&os).await.map_err(js_err)?)
    }

    /// Install an app by name (and its parent if missing). Events: `{app, ...}`.
    /// `installed`: names of the installed apps if already known (avoids a
    /// second listing approval on the device).
    #[wasm_bindgen(js_name = installApp)]
    pub async fn install_app(
        &self,
        name: String,
        on_event: Option<Function>,
        installed: Option<Vec<String>>,
    ) -> JsResult<()> {
        let mut cb = |app: &str, ev: HsmEvent| {
            if let (Some(cb), Ok(v)) = (&on_event, to_js(&ev)) {
                let _ = js_sys::Reflect::set(&v, &"app".into(), &app.into());
                let _ = cb.call1(&JsValue::NULL, &v);
            }
        };
        self.manager()
            .install_app_with_deps(&self.device, &name, installed.as_deref(), &mut cb)
            .await
            .map_err(js_err)
    }

    #[wasm_bindgen(js_name = uninstallApp)]
    pub async fn uninstall_app(&self, name: String, on_event: Option<Function>) -> JsResult<()> {
        self.manager()
            .uninstall_app_by_name(&self.device, &name, &mut emitter(on_event))
            .await
            .map_err(js_err)
    }

    /// Firmware update available? Returns the update descriptor or `null`.
    #[wasm_bindgen(js_name = checkFirmware)]
    pub async fn check_firmware(&self) -> JsResult<JsValue> {
        let os = self.device.get_version().await.map_err(js_err)?;
        let u = self
            .manager()
            .check_firmware_update(&os)
            .await
            .map_err(js_err)?;
        to_js(&u)
    }

    /// Install the OS updater (step 1). The device reboots afterwards.
    #[wasm_bindgen(js_name = installOsu)]
    pub async fn install_osu(&self, update: JsValue, on_event: Option<Function>) -> JsResult<()> {
        let u: FirmwareUpdate = from_js(update)?;
        self.manager()
            .install_osu(&self.device, &u, &mut emitter(on_event))
            .await
            .map_err(js_err)
    }

    /// Flash MCU / bootloader (step 2, bootloader mode only). Returns "mcu" or "bootloader".
    #[wasm_bindgen(js_name = flashMcu)]
    pub async fn flash_mcu(
        &self,
        update: JsValue,
        on_event: Option<Function>,
    ) -> JsResult<JsValue> {
        let u: FirmwareUpdate = from_js(update)?;
        to_js(
            &self
                .manager()
                .flash_mcu(&self.device, &u, &mut emitter(on_event))
                .await
                .map_err(js_err)?,
        )
    }

    /// Bootloader mode recovery: flash the MCU required by the installed
    /// firmware. Returns "mcu", "bootloader" or `null` if not in bootloader.
    #[wasm_bindgen(js_name = repairMcu)]
    pub async fn repair_mcu(&self, on_event: Option<Function>) -> JsResult<JsValue> {
        to_js(
            &self
                .manager()
                .repair_mcu(&self.device, &mut emitter(on_event))
                .await
                .map_err(js_err)?,
        )
    }

    // ---- Device settings ----

    /// Restart the dashboard.
    pub async fn reset(&self) -> JsResult<()> {
        self.device.reset().await.map_err(js_err)
    }

    /// Bluetooth MAC address (BLE models).
    #[wasm_bindgen(js_name = getMac)]
    pub async fn get_mac(&self) -> JsResult<String> {
        self.device.get_device_mac().await.map_err(js_err)
    }

    /// Battery charge limit (percent).
    #[wasm_bindgen(js_name = setChargeLimit)]
    pub async fn set_charge_limit(&self, percent: u8) -> JsResult<()> {
        self.device
            .set_battery_charge_limit(percent)
            .await
            .map_err(js_err)
    }

    // ---- Language packs ----

    /// Installed language packs `[{id, size}]`.
    #[wasm_bindgen(js_name = listLanguagePacks)]
    pub async fn list_language_packs(&self) -> JsResult<JsValue> {
        to_js(&self.device.list_language_packs().await.map_err(js_err)?)
    }

    /// Language packs available for this firmware.
    #[wasm_bindgen(js_name = availableLanguagePacks)]
    pub async fn available_language_packs(&self) -> JsResult<JsValue> {
        let os = self.device.get_version().await.map_err(js_err)?;
        to_js(&self.manager().language_packs(&os).await.map_err(js_err)?)
    }

    /// Install a language pack by name (`french`...). Progress: `(sent, total)`.
    #[wasm_bindgen(js_name = installLanguagePack)]
    pub async fn install_language_pack(
        &self,
        language: String,
        on_progress: Option<Function>,
    ) -> JsResult<()> {
        let os = self.device.get_version().await.map_err(js_err)?;
        let m = self.manager();
        let pack = m
            .language_packs(&os)
            .await
            .map_err(js_err)?
            .into_iter()
            .find(|p| p.language.eq_ignore_ascii_case(&language))
            .ok_or_else(|| {
                js_err(Error::NotFound(format!(
                    "no {language} pack for this firmware"
                )))
            })?;
        let mut cb = |i: usize, n: usize| {
            if let Some(f) = &on_progress {
                let _ = f.call2(&JsValue::NULL, &(i as u32).into(), &(n as u32).into());
            }
        };
        m.install_language_pack(&self.device, &pack, &mut cb)
            .await
            .map_err(js_err)
    }

    /// Remove every language pack (back to English).
    #[wasm_bindgen(js_name = removeLanguagePacks)]
    pub async fn remove_language_packs(&self) -> JsResult<()> {
        self.manager()
            .remove_language_packs(&self.device)
            .await
            .map_err(js_err)
    }

    // ---- Endorsement ----

    /// Endorsement key and certificate of slot 1 or 2.
    #[wasm_bindgen(js_name = endorsementInfo)]
    pub async fn endorsement_info(&self, slot: u8) -> JsResult<JsValue> {
        to_js(
            &self
                .device
                .endorsement_info(endorsement_slot(slot)?)
                .await
                .map_err(js_err)?,
        )
    }

    /// Create the slot key and certify it with `ownerKey` (hex private key).
    /// Returns `{ publicKey, certificate }`.
    #[wasm_bindgen(js_name = endorseSetup)]
    pub async fn endorse_setup(&self, slot: u8, owner_key: String) -> JsResult<JsValue> {
        let owner = crate::scp::RootKey::from_hex(&owner_key).map_err(js_err)?;
        let (public, _) = self
            .device
            .endorse_start(endorsement_slot(slot)?)
            .await
            .map_err(js_err)?;
        let cert = crate::scp::endorsement_certificate(&owner, &public).map_err(js_err)?;
        self.device.endorse_commit(&cert).await.map_err(js_err)?;
        to_js(
            &serde_json::json!({ "publicKey": hex::encode(&public), "certificate": hex::encode(&cert) }),
        )
    }

    // ---- Secure channel (custom CA, sideloading) ----

    /// Install a custom CA (recovery mode). `recover` uses the Recover channel.
    #[wasm_bindgen(js_name = caInstall)]
    pub async fn ca_install(
        &self,
        name: String,
        public_key: String,
        recover: bool,
        on_event: Option<Function>,
    ) -> JsResult<()> {
        let pk = hex::decode(public_key.trim().trim_start_matches("0x"))
            .map_err(|e| js_err(Error::InvalidInput(e.to_string())))?;
        let root = crate::scp::RootKey::generate().map_err(js_err)?;
        let mode = if recover {
            crate::scp::ScpMode::Recover
        } else {
            crate::scp::ScpMode::Default
        };
        let mut chan = crate::scp::SecureChannel::open_mode(
            &self.device,
            &root,
            mode,
            &mut scp_emitter(&on_event),
        )
        .await
        .map_err(js_err)?;
        if recover {
            chan.recover_set_ca(&name, &pk).await
        } else {
            chan.setup_custom_ca(&name, &pk).await
        }
        .map_err(js_err)
    }

    /// Remove the custom CA (recovery mode). The Recover channel needs the
    /// CA name and public key.
    #[wasm_bindgen(js_name = caRemove)]
    pub async fn ca_remove(
        &self,
        recover: bool,
        name: Option<String>,
        public_key: Option<String>,
        on_event: Option<Function>,
    ) -> JsResult<()> {
        let root = crate::scp::RootKey::generate().map_err(js_err)?;
        if recover {
            let pk = hex::decode(
                public_key
                    .unwrap_or_default()
                    .trim()
                    .trim_start_matches("0x"),
            )
            .map_err(|e| js_err(Error::InvalidInput(e.to_string())))?;
            let mut chan = crate::scp::SecureChannel::open_mode(
                &self.device,
                &root,
                crate::scp::ScpMode::Recover,
                &mut scp_emitter(&on_event),
            )
            .await
            .map_err(js_err)?;
            chan.recover_delete_ca(&name.unwrap_or_default(), &pk)
                .await
                .map_err(js_err)
        } else {
            let mut chan =
                crate::scp::SecureChannel::open(&self.device, &root, &mut scp_emitter(&on_event))
                    .await
                    .map_err(js_err)?;
            chan.reset_custom_ca().await.map_err(js_err)
        }
    }

    /// Run a secure command set with `rootKey` (hex; empty = random key, the
    /// device then asks to allow an unknown manager). `op`: `memoryInfo`,
    /// `listApps`, `hashFirmware`, `deleteAllApps`, `resetEndorsement`,
    /// `deleteApp` (arg: name), `deleteAppByHash` (arg: hex hash).
    pub async fn secure(
        &self,
        op: String,
        root_key: Option<String>,
        arg: Option<String>,
        on_event: Option<Function>,
    ) -> JsResult<JsValue> {
        let root = root_or_random(root_key).map_err(js_err)?;
        let mut chan =
            crate::scp::SecureChannel::open(&self.device, &root, &mut scp_emitter(&on_event))
                .await
                .map_err(js_err)?;
        let arg = arg.unwrap_or_default();
        let r: Result<JsValue> = match op.as_str() {
            "memoryInfo" => chan
                .get_memory_info()
                .await
                .and_then(|v| to_js(&v).map_err(|_| Error::App("js".into()))),
            "listApps" => chan
                .list_apps()
                .await
                .and_then(|v| to_js(&v).map_err(|_| Error::App("js".into()))),
            "hashFirmware" => chan.hash_firmware().await.map(|h| hex::encode(h).into()),
            "deleteAllApps" => chan.delete_all_apps().await.map(|_| JsValue::UNDEFINED),
            "resetEndorsement" => chan.reset_endorsement().await.map(|_| JsValue::UNDEFINED),
            "deleteApp" => chan.delete_app(&arg).await.map(|_| JsValue::UNDEFINED),
            "deleteAppByHash" => {
                let h: [u8; 32] = hex::decode(arg.trim())
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| {
                        js_err(Error::InvalidInput("hash must be 32 bytes hex".into()))
                    })?;
                chan.delete_app_by_hash(&h)
                    .await
                    .map(|_| JsValue::UNDEFINED)
            }
            other => Err(Error::InvalidInput(format!(
                "unknown secure operation {other:?}"
            ))),
        };
        r.map_err(js_err)
    }

    /// Sideload an app ELF with the custom CA private key (hex).
    /// Events: handshake events, then `{type: "loading", sent, total}`.
    #[wasm_bindgen(js_name = sideload)]
    pub async fn sideload(
        &self,
        elf: Vec<u8>,
        ca_key: String,
        replace: bool,
        on_event: Option<Function>,
    ) -> JsResult<()> {
        let img = crate::loader::AppImage::from_elf(&elf).map_err(js_err)?;
        let root = crate::scp::RootKey::from_hex(&ca_key).map_err(js_err)?;
        let mut chan =
            crate::scp::SecureChannel::open(&self.device, &root, &mut scp_emitter(&on_event))
                .await
                .map_err(js_err)?;
        let mut progress = |sent: usize, total: usize| {
            if let Some(f) = &on_event {
                let v = serde_json::json!({ "type": "loading", "sent": sent, "total": total });
                if let Ok(v) = to_js(&v) {
                    let _ = f.call1(&JsValue::NULL, &v);
                }
            }
        };
        crate::loader::install_app(&mut chan, &img, replace, &mut progress)
            .await
            .map_err(js_err)
    }

    // ---- Factory (devices not yet personalized) ----

    /// `FACTORY_TEST` raw (hex data), returns hex.
    #[wasm_bindgen(js_name = factoryTest)]
    pub async fn factory_test(&self, p1: u8, p2: u8, data: String) -> JsResult<String> {
        let d = hex::decode(data.trim()).map_err(|e| js_err(Error::InvalidInput(e.to_string())))?;
        Ok(hex::encode(
            self.device.factory_test(p1, p2, &d).await.map_err(js_err)?,
        ))
    }

    /// `GET_DEVICE_PUBLIC_KEY` (personalization), hex.
    #[wasm_bindgen(js_name = factoryPublicKey)]
    pub async fn factory_public_key(&self) -> JsResult<String> {
        Ok(hex::encode(
            self.device
                .factory_get_device_public_key()
                .await
                .map_err(js_err)?,
        ))
    }

    /// `GET_CXPORT`, hex.
    #[wasm_bindgen(js_name = factoryCxport)]
    pub async fn factory_cxport(&self) -> JsResult<String> {
        Ok(hex::encode(
            self.device.factory_get_cxport().await.map_err(js_err)?,
        ))
    }

    // ---- Ethereum ----

    #[wasm_bindgen(js_name = ethConfig)]
    pub async fn eth_config(&self) -> JsResult<JsValue> {
        to_js(
            &eth::EthApp::new(&self.device)
                .get_configuration()
                .await
                .map_err(js_err)?,
        )
    }

    #[wasm_bindgen(js_name = ethAddress)]
    pub async fn eth_address(&self, path_str: String, display: bool) -> JsResult<JsValue> {
        let a = eth::EthApp::new(&self.device)
            .get_address(&path(&path_str)?, display, false)
            .await
            .map_err(js_err)?;
        to_js(&a)
    }

    /// Build (with outscript) and sign a transaction.
    #[wasm_bindgen(js_name = ethSignTx)]
    pub async fn eth_sign_tx(&self, path_str: String, tx: JsValue) -> JsResult<JsValue> {
        let p = path(&path_str)?;
        let input: EthTxIn = from_js(tx)?;
        let app = eth::EthApp::new(&self.device);
        let from = app
            .get_address(&p, false, false)
            .await
            .map_err(js_err)?
            .address;
        let mut tx = build_eth_tx(&input).map_err(js_err)?;
        let unsigned = tx
            .sign_bytes()
            .map_err(|e| js_err(Error::InvalidInput(format!("{e:?}"))))?;
        let signature = app.sign_tx(&p, &mut tx).await.map_err(js_err)?;
        let raw = tx
            .to_bytes()
            .map_err(|e| js_err(Error::App(format!("{e:?}"))))?;
        let hash = tx
            .hash()
            .map_err(|e| js_err(Error::App(format!("{e:?}"))))?;
        to_js(&EthTxOut {
            unsigned: format!("0x{}", hex::encode(unsigned)),
            raw: format!("0x{}", hex::encode(raw)),
            hash: format!("0x{}", hex::encode(hash)),
            from,
            signature,
        })
    }

    #[wasm_bindgen(js_name = ethSignMessage)]
    pub async fn eth_sign_message(&self, path_str: String, message: String) -> JsResult<String> {
        let s = eth::EthApp::new(&self.device)
            .sign_personal_message(&path(&path_str)?, message.as_bytes())
            .await
            .map_err(js_err)?;
        Ok(format!("0x{}", hex::encode(s.to_rsv())))
    }

    #[wasm_bindgen(js_name = ethSignTypedHashes)]
    pub async fn eth_sign_typed_hashes(
        &self,
        path_str: String,
        domain: String,
        message: String,
    ) -> JsResult<String> {
        let h = |s: &str| -> JsResult<[u8; 32]> {
            hex::decode(s.trim_start_matches("0x"))
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| js_err(Error::InvalidInput("expected a 32-byte hex hash".into())))
        };
        let s = eth::EthApp::new(&self.device)
            .sign_eip712_hashed(&path(&path_str)?, &h(&domain)?, &h(&message)?)
            .await
            .map_err(js_err)?;
        Ok(format!("0x{}", hex::encode(s.to_rsv())))
    }

    // ---- Bitcoin ----

    /// Account key information for a default single-sig account.
    #[wasm_bindgen(js_name = btcAccount)]
    pub async fn btc_account(
        &self,
        kind: String,
        account: u32,
        testnet: bool,
    ) -> JsResult<JsValue> {
        let kind = btc::AddressType::parse(&kind).map_err(js_err)?;
        let key = btc::BtcApp::new(&self.device)
            .get_account_key(kind, testnet, account)
            .await
            .map_err(js_err)?;
        let policy = btc::WalletPolicy::default_single_sig(kind, key.clone());
        to_js(&BtcAccountOut {
            key: key.to_string(),
            xpub: key.xpub.clone(),
            fingerprint: hex::encode(key.fingerprint.unwrap_or_default()),
            path: key.path.to_string(),
            descriptor: policy.descriptor(false),
            change_descriptor: policy.descriptor(true),
        })
    }

    #[wasm_bindgen(js_name = btcXpub)]
    pub async fn btc_xpub(&self, path_str: String, display: bool) -> JsResult<String> {
        btc::BtcApp::new(&self.device)
            .get_extended_pubkey(&path(&path_str)?, display)
            .await
            .map_err(js_err)
    }

    /// Address from the device, checked against local derivation.
    #[wasm_bindgen(js_name = btcAddress)]
    pub async fn btc_address(
        &self,
        kind: String,
        account: u32,
        testnet: bool,
        change: bool,
        index: u32,
        display: bool,
    ) -> JsResult<String> {
        let kind = btc::AddressType::parse(&kind).map_err(js_err)?;
        let app = btc::BtcApp::new(&self.device);
        let key = app
            .get_account_key(kind, testnet, account)
            .await
            .map_err(js_err)?;
        app.get_wallet_address_checked(kind, testnet, &key, change, index, display)
            .await
            .map_err(js_err)
    }

    /// Sign a message, returns the base64 signature.
    #[wasm_bindgen(js_name = btcSignMessage)]
    pub async fn btc_sign_message(&self, path_str: String, message: String) -> JsResult<String> {
        let sig = btc::BtcApp::new(&self.device)
            .sign_message(&path(&path_str)?, message.as_bytes())
            .await
            .map_err(js_err)?;
        Ok(outscript::base64::encode(&sig))
    }

    /// Sign a PSBT (base64) with a default account. Returns `{signedPsbt, tx?}`.
    #[wasm_bindgen(js_name = btcSignPsbt)]
    pub async fn btc_sign_psbt(
        &self,
        kind: String,
        account: u32,
        testnet: bool,
        psbt_b64: String,
    ) -> JsResult<JsValue> {
        let kind = btc::AddressType::parse(&kind).map_err(js_err)?;
        let bytes = outscript::psbt::Psbt::decode_base64(psbt_b64.trim())
            .map_err(|e| js_err(Error::InvalidInput(format!("{e:?}"))))?;
        let app = btc::BtcApp::new(&self.device);
        let policy = app
            .default_policy(kind, testnet, account)
            .await
            .map_err(js_err)?;
        let signed = app
            .sign_psbt_into(&bytes, &policy, None)
            .await
            .map_err(js_err)?;
        let tx = btc::psbt::finalize_and_extract(&signed)
            .ok()
            .map(hex::encode);
        let out = serde_json::json!({ "signedPsbt": outscript::base64::encode(&signed), "tx": tx });
        to_js(&out)
    }

    /// Build a PSBT with outscript from UTXOs, sign it and finalize it.
    #[wasm_bindgen(js_name = btcSend)]
    pub async fn btc_send(&self, request: JsValue) -> JsResult<JsValue> {
        let req: BtcSendIn = from_js(request)?;
        let kind = btc::AddressType::parse(&req.kind).map_err(js_err)?;
        let app = btc::BtcApp::new(&self.device);
        let key = app
            .get_account_key(kind, req.testnet, req.account)
            .await
            .map_err(js_err)?;
        let xpub = btc::Xpub::parse(&key.xpub).map_err(js_err)?;
        let change = match (req.change_index, req.change_amount) {
            (Some(i), Some(a)) if a > 0 => Some((i, a)),
            _ => None,
        };
        let spend = btc::psbt::SpendRequest {
            kind,
            testnet: req.testnet,
            master_fingerprint: key.fingerprint.unwrap_or_default(),
            account_path: key.path.components(),
            account_xpub: &xpub,
            utxos: &req.utxos,
            payments: &req.payments,
            change,
            rbf: req.rbf,
        };
        let unsigned = btc::psbt::build_psbt(&spend).map_err(js_err)?;
        let policy = btc::WalletPolicy::default_single_sig(kind, key);
        let signatures = app
            .sign_psbt(&unsigned, &policy, None)
            .await
            .map_err(js_err)?;
        let signed = btc::psbt::insert_signatures(&unsigned, &signatures).map_err(js_err)?;
        let tx = btc::psbt::finalize_and_extract(&signed).map_err(js_err)?;
        let txid = outscript::btctx::BtcTx::from_bytes(&tx)
            .map(|t| hex::encode(t.hash()))
            .unwrap_or_default();
        to_js(&BtcSendOut {
            unsigned_psbt: outscript::base64::encode(&unsigned),
            signed_psbt: outscript::base64::encode(&signed),
            tx: hex::encode(tx),
            txid,
            signatures,
        })
    }

    // ---- Solana ----

    #[wasm_bindgen(js_name = solConfig)]
    pub async fn sol_config(&self) -> JsResult<JsValue> {
        to_js(
            &sol::SolApp::new(&self.device)
                .get_configuration()
                .await
                .map_err(js_err)?,
        )
    }

    #[wasm_bindgen(js_name = solAddress)]
    pub async fn sol_address(&self, path_str: String, display: bool) -> JsResult<String> {
        sol::SolApp::new(&self.device)
            .get_address(&path(&path_str)?, display)
            .await
            .map_err(js_err)
    }

    /// Build (with outscript) and sign a SOL transfer. `amount` in SOL.
    #[wasm_bindgen(js_name = solTransfer)]
    pub async fn sol_transfer(
        &self,
        path_str: String,
        to: String,
        amount: String,
        blockhash: String,
    ) -> JsResult<JsValue> {
        let p = path(&path_str)?;
        let app = sol::SolApp::new(&self.device);
        let from = app.get_address(&p, false).await.map_err(js_err)?;
        let lamports: u64 = eth::parse_units(&amount, 9)
            .map_err(js_err)?
            .try_into()
            .map_err(|_| js_err(Error::InvalidInput("amount too large".into())))?;
        let mut tx = sol::build_transfer(&from, &to, lamports, &blockhash).map_err(js_err)?;
        let sig = app.sign_tx(&p, &mut tx).await.map_err(js_err)?;
        let raw = tx
            .to_bytes()
            .map_err(|e| js_err(Error::App(format!("{e:?}"))))?;
        to_js(&SolTxOut {
            from,
            base64: outscript::base64::encode(&raw),
            base58: outscript::base58::encode(&raw),
            signature: outscript::base58::encode(&sig),
        })
    }
}

fn build_eth_tx(i: &EthTxIn) -> Result<eth::EvmTx> {
    let mut tx = eth::EvmTx::default();
    tx.chain_id = i.chain_id;
    tx.nonce = i.nonce;
    tx.gas = i.gas;
    let value = i
        .value
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or("0");
    match i.token.as_deref().filter(|t| !t.is_empty()) {
        Some(token) => {
            tx.to = token.to_string();
            tx.data = eth::erc20_transfer_data(
                &i.to,
                &eth::parse_units(value, i.decimals.unwrap_or(18))?,
            )?;
        }
        None => {
            tx.to = i.to.clone();
            tx.value = eth::parse_units(value, 18)?;
            if let Some(d) = i.data.as_deref().filter(|d| !d.is_empty() && *d != "0x") {
                tx.data = hex::decode(d.trim_start_matches("0x"))
                    .map_err(|e| Error::InvalidInput(e.to_string()))?;
            }
        }
    }
    let gwei = |s: &str| eth::parse_units(s, 9);
    match i.gas_price.as_deref().filter(|g| !g.is_empty()) {
        Some(gp) => {
            tx.tx_type = eth::EvmTxType::Legacy;
            tx.gas_fee_cap = gwei(gp)?;
        }
        None => {
            tx.tx_type = eth::EvmTxType::Eip1559;
            tx.gas_tip_cap = gwei(i.priority_fee.as_deref().unwrap_or("1"))?;
            tx.gas_fee_cap = gwei(i.max_fee.as_deref().ok_or_else(|| {
                Error::InvalidInput("maxFee (gwei) or gasPrice is required".into())
            })?)?;
        }
    }
    Ok(tx)
}
