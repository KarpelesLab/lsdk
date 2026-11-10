//! Dashboard (BOLOS) commands: version, apps, device name, battery...

use crate::apdu::{Apdu, Reader};
use crate::error::{Error, Result};
use crate::model::{DeviceModel, version_gte};

/// `GET_VERSION` (`E0 01 00 00`).
pub const GET_VERSION: Apdu = Apdu::new(0xe0, 0x01, 0x00, 0x00);
/// `GET_APP_AND_VERSION` (`B0 01 00 00`), works in any app.
pub const GET_APP_AND_VERSION: Apdu = Apdu::new(0xb0, 0x01, 0x00, 0x00);
/// `QUIT_APP` (`B0 A7 00 00`), works in any app.
pub const QUIT_APP: Apdu = Apdu::new(0xb0, 0xa7, 0x00, 0x00);
/// `LIST_APPS` first page (`E0 DE 00 00`).
pub const LIST_APPS: Apdu = Apdu::new(0xe0, 0xde, 0x00, 0x00);
/// `LIST_APPS` next page (`E0 DF 00 00`).
pub const LIST_APPS_CONTINUE: Apdu = Apdu::new(0xe0, 0xdf, 0x00, 0x00);
/// `GET_DEVICE_NAME` (`E0 D2 00 00`).
pub const GET_DEVICE_NAME: Apdu = Apdu::new(0xe0, 0xd2, 0x00, 0x00);

/// Build `OPEN_APP` (`E0 D8 00 00 <name>`).
pub fn open_app(name: &str) -> Apdu {
    Apdu::with_data(0xe0, 0xd8, 0x00, 0x00, name.as_bytes().to_vec())
}

/// Build `SET_DEVICE_NAME` (`E0 D4 00 00 <name>`).
pub fn set_device_name(name: &str) -> Apdu {
    Apdu::with_data(0xe0, 0xd4, 0x00, 0x00, name.as_bytes().to_vec())
}

/// Build `GET_BATTERY_STATUS` (`E0 10 00 <kind>`).
pub fn get_battery_status(kind: BatteryStatusKind) -> Apdu {
    Apdu::new(0xe0, 0x10, 0x00, kind as u8)
}

/// `SET_SCREEN_SAVER` instruction (recovery mode only).
pub const INS_SET_SCREEN_SAVER: u8 = 0xd6;
const SCREEN_SAVER_MAGIC: &[u8] = b"Screensaver Perso";

fn screen_saver_magic() -> Vec<u8> {
    let mut v = vec![0x01, SCREEN_SAVER_MAGIC.len() as u8];
    v.extend_from_slice(SCREEN_SAVER_MAGIC);
    v
}

/// Build `SET_SCREEN_SAVER` (custom scrolling text).
pub fn set_screen_saver(
    text: &str,
    animation: ScreenSaverAnimation,
    speed: ScreenSaverSpeed,
) -> Result<Apdu> {
    if text.is_empty() || text.len() > 52 || !text.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return Err(Error::InvalidInput(
            "screensaver text must be 1 to 52 printable ASCII characters".into(),
        ));
    }
    let mut data = screen_saver_magic();
    data.push(0x02);
    data.push(text.len() as u8);
    data.extend_from_slice(text.as_bytes());
    Ok(Apdu::with_data(
        0xe0,
        INS_SET_SCREEN_SAVER,
        0x00,
        ((animation as u8) << 4) | speed as u8,
        data,
    ))
}

/// Build `SET_SCREEN_SAVER` (reset to the default screensaver).
pub fn reset_screen_saver() -> Apdu {
    Apdu::with_data(0xe0, INS_SET_SCREEN_SAVER, 0x80, 0x00, screen_saver_magic())
}

/// Build `SET_SCREEN_SAVER` (read the current setting).
pub fn get_screen_saver() -> Apdu {
    Apdu::with_data(0xe0, INS_SET_SCREEN_SAVER, 0x40, 0x00, screen_saver_magic())
}

/// Screensaver text scrolling animation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[repr(u8)]
pub enum ScreenSaverAnimation {
    /// Scrolls back and forth.
    Classic = 0,
    /// Loops right to left.
    CircleRightToLeft = 1,
    /// Loops left to right.
    CircleLeftToRight = 2,
}

/// Screensaver animation speed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[repr(u8)]
pub enum ScreenSaverSpeed {
    Fast = 0,
    Normal = 1,
    Slow = 2,
}

impl ScreenSaverAnimation {
    pub fn from_u8(v: u8) -> Option<Self> {
        [
            Self::Classic,
            Self::CircleRightToLeft,
            Self::CircleLeftToRight,
        ]
        .into_iter()
        .find(|x| *x as u8 == v)
    }
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "classic" | "0" => Self::Classic,
            "circle-rl" | "circlerighttoleft" | "rl" | "1" => Self::CircleRightToLeft,
            "circle-lr" | "circlelefttoright" | "lr" | "2" => Self::CircleLeftToRight,
            _ => {
                return Err(Error::InvalidInput(format!(
                    "unknown animation {s:?} (classic, circle-rl, circle-lr)"
                )));
            }
        })
    }
}

impl ScreenSaverSpeed {
    pub fn from_u8(v: u8) -> Option<Self> {
        [Self::Fast, Self::Normal, Self::Slow]
            .into_iter()
            .find(|x| *x as u8 == v)
    }
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "fast" | "0" => Self::Fast,
            "normal" | "1" => Self::Normal,
            "slow" | "2" => Self::Slow,
            _ => {
                return Err(Error::InvalidInput(format!(
                    "unknown speed {s:?} (fast, normal, slow)"
                )));
            }
        })
    }
}

/// A custom screensaver.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ScreenSaver {
    pub text: String,
    pub animation: Option<ScreenSaverAnimation>,
    pub speed: Option<ScreenSaverSpeed>,
}

impl ScreenSaver {
    /// Parse a status response: empty for the default screensaver, else
    /// `type(1) speed(1) len(1) text [0]`.
    pub fn parse(data: &[u8]) -> Result<Option<Self>> {
        if data.len() < 3 {
            return Ok(None);
        }
        let len = (data[2] as usize).min(data.len() - 3);
        let text = String::from_utf8_lossy(&data[3..3 + len])
            .trim_end_matches('\0')
            .to_string();
        if text.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self {
            text,
            animation: ScreenSaverAnimation::from_u8(data[0]),
            speed: ScreenSaverSpeed::from_u8(data[1]),
        }))
    }
}

/// `RESET` (`E0 02`): puts the dashboard / secure element in reset state.
pub const RESET: Apdu = Apdu::new(0xe0, 0x02, 0x00, 0x00);
/// `GET_DEVICE_MAC` (`E0 D5`): Bluetooth MAC address (BLE models).
pub const GET_DEVICE_MAC: Apdu = Apdu::new(0xe0, 0xd5, 0x00, 0x00);
/// `GET_DEVICE_PUBLIC_KEY` (`E0 40`): factory personalization only.
pub const GET_DEVICE_PUBLIC_KEY: Apdu = Apdu::new(0xe0, 0x40, 0x00, 0x00);
/// `GET_CXPORT` (`E0 C5`): factory.
pub const GET_CXPORT: Apdu = Apdu::new(0xe0, 0xc5, 0x00, 0x00);

/// Build `SET_MAX_BATT_PERC` (`E0 19`): battery charge limit (0-100).
pub fn set_battery_charge_limit(percent: u8) -> Result<Apdu> {
    if percent > 100 {
        return Err(Error::InvalidInput("percentage must be 0..=100".into()));
    }
    Ok(Apdu::with_data(0xe0, 0x19, 0x00, 0x00, vec![percent]))
}

/// Build `LIST_LANGUAGE_PACKS` (`E0 34`), first page or continuation.
pub fn list_language_packs(first: bool) -> Apdu {
    Apdu::new(0xe0, 0x34, if first { 0x00 } else { 0x01 }, 0x00)
}

/// Build `DEL_LANGUAGE_PACK` (`E0 33`).
pub fn delete_language_pack(language: u8) -> Apdu {
    Apdu::new(0xe0, 0x33, language, 0x00)
}

/// Build `CREATE_LANGUAGE_PACK` (`E0 30`): reserve `size` bytes for a pack.
pub fn create_language_pack(language: u8, size: u32) -> Apdu {
    Apdu::with_data(0xe0, 0x30, language, 0x00, size.to_be_bytes().to_vec())
}

/// Build `LOAD_LANGUAGE_PACK` (`E0 31`): chunk at `offset`.
pub fn load_language_pack(language: u8, offset: u32, chunk: &[u8]) -> Apdu {
    let mut d = offset.to_be_bytes().to_vec();
    d.extend_from_slice(chunk);
    Apdu::with_data(0xe0, 0x31, language, 0x00, d)
}

/// Build `COMMIT_LANGUAGE_PACK` (`E0 32`) with the vendor signature (mandatory).
pub fn commit_language_pack(language: u8, signature: &[u8]) -> Apdu {
    let mut d = vec![signature.len() as u8];
    d.extend_from_slice(signature);
    Apdu::with_data(0xe0, 0x32, language, 0x00, d)
}

/// An installed language pack.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct LanguagePack {
    /// Language id (0 English, 1 French, 2 Spanish, 3 Portuguese, 4 German, 5 Russian, 6 Turkish...).
    pub id: u32,
    pub size: u32,
}

/// Human name of a language id.
pub fn language_name(id: u32) -> &'static str {
    match id {
        0 => "English",
        1 => "French",
        2 => "Spanish",
        3 => "Portuguese",
        4 => "German",
        5 => "Russian",
        6 => "Turkish",
        _ => "unknown",
    }
}

/// Parse one `LIST_LANGUAGE_PACKS` response (`None` when the list is over).
pub fn parse_language_pack(data: &[u8]) -> Result<Option<LanguagePack>> {
    if data.is_empty() {
        return Ok(None);
    }
    let int_of = |b: &[u8]| b.iter().fold(0u32, |acc, x| (acc << 8) | *x as u32);
    let mut r = Reader::new(data);
    let _version = r.u8()?;
    let _len = r.u8()?;
    let id = int_of(r.lv()?);
    let size = int_of(r.lv()?);
    Ok(Some(LanguagePack { id, size }))
}

/// Endorsement slot (user attestation keys).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum EndorsementSlot {
    Slot1 = 1,
    Slot2 = 2,
}

/// Build `ENDORSE_SET_START` (`E0 C0`): generate the slot key.
pub fn endorse_set_start(slot: EndorsementSlot) -> Apdu {
    Apdu::new(0xe0, 0xc0, slot as u8, 0x00)
}

/// Build `ENDORSE_SET_COMMIT` (`E0 C2`): store the owner certificate.
pub fn endorse_set_commit(certificate: &[u8]) -> Apdu {
    Apdu::with_data(0xe0, 0xc2, 0x00, 0x00, certificate.to_vec())
}

/// Build `ENDORSEMENT_INFO_RETRIEVAL` (`E0 C6`).
pub fn endorsement_info(slot: EndorsementSlot) -> Apdu {
    Apdu::new(0xe0, 0xc6, slot as u8, 0x00)
}

/// Endorsement key of a slot and its certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct EndorsementInfo {
    pub role: u8,
    /// Endorsement public key (hex).
    pub public_key: String,
    /// Owner certificate (hex DER signature over `sha256(0xFE || public_key)`).
    pub certificate: String,
}

impl EndorsementInfo {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let role = r.u8()?;
        let public_key = hex::encode(r.lv()?);
        let certificate = hex::encode(r.lv()?);
        Ok(Self {
            role,
            public_key,
            certificate,
        })
    }
}

/// Onboarding identity (`E0 D0` P1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[repr(u8)]
pub enum OnboardIdentity {
    /// Main identity (PIN + recovery phrase), only on a non-onboarded device.
    Main = 0,
    /// Alternate identity (second PIN, e.g. passphrase wallet).
    Alternate = 1,
    /// Temporary identity (no PIN, until reboot).
    Temporary = 2,
}

/// Build `ONBOARD` (`E0 D0`). **The PIN and recovery phrase travel in clear
/// over USB**: only for test devices.
pub fn onboard(
    identity: OnboardIdentity,
    pin: &str,
    prefix: &str,
    passphrase: &str,
    words: &str,
) -> Result<Apdu> {
    let mut d = Vec::new();
    for f in [pin, prefix, passphrase, words] {
        if f.len() > 255 {
            return Err(Error::InvalidInput("onboard field too long".into()));
        }
        d.push(f.len() as u8);
        d.extend_from_slice(f.as_bytes());
    }
    if d.len() > 255 {
        return Err(Error::InvalidInput("onboard data too long".into()));
    }
    Ok(Apdu::with_data(0xe0, 0xd0, identity as u8, 0x00, d))
}

/// Build `FACTORY_TEST` (`E0 44`) — devices without a serial number only.
pub fn factory_test(p1: u8, p2: u8, data: &[u8]) -> Apdu {
    Apdu::with_data(0xe0, 0x44, p1, p2, data.to_vec())
}

/// `FACTORY_TEST` P1 values.
pub mod factory {
    pub const START_STOP: u8 = 0x00;
    pub const SCREEN: u8 = 0x10;
    pub const BUTTON: u8 = 0x20;
    pub const BATTERY: u8 = 0x30;
    pub const GET_SE_SERIAL: u8 = 0xd0;
    pub const RESET: u8 = 0xe0;
    pub const SERIAL_NUMBER: u8 = 0xf0;
    pub const BACKUP_SERIAL_NUMBER: u8 = 0xf1;
    pub const MCU_SERIAL_NUMBER: u8 = 0xf2;
}

/// Names reported by `GET_APP_AND_VERSION` while on the dashboard.
pub fn is_dashboard_name(name: &str) -> bool {
    name == "BOLOS" || name == "OLOS\0"
}

/// Known manager API providers, keyed by the firmware version suffix.
pub fn provider_id_from_name(name: Option<&str>) -> u32 {
    match name {
        Some("das") => 2,
        Some("club") => 3,
        Some("shitcoins") => 4,
        Some("ee") => 5,
        _ => 1,
    }
}

/// Parsed `GET_VERSION` response.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct OsVersion {
    /// Device is in bootloader mode (firmware update in progress).
    pub is_bootloader: bool,
    /// Device runs the OS updater (firmware update in progress).
    pub is_osu: bool,
    /// Target id (identifies the model / hardware).
    pub target_id: u32,
    /// Target id of the secure element.
    pub se_target_id: Option<u32>,
    /// Target id of the MCU (bootloader mode only).
    pub mcu_target_id: Option<u32>,
    /// Raw firmware version string as returned by the device (e.g. `1.4.1`, `2.2.3-osu`).
    pub raw_version: String,
    /// Secure element version.
    pub se_version: String,
    /// Raw secure element flags.
    #[cfg_attr(feature = "serde", serde(serialize_with = "ser_hex"))]
    pub se_flags: Vec<u8>,
    /// MCU SEPH version.
    pub mcu_seph_version: String,
    /// MCU bootloader version.
    pub mcu_bootloader_version: String,
    /// Hardware revision (hex).
    pub hw_version: String,
    /// Installed language pack id.
    pub language_id: Option<u32>,
    /// Seed recovery service state.
    pub recover_state: Option<u32>,
    /// Parsed flags.
    pub flags: SeFlags,
}

#[cfg(feature = "serde")]
fn ser_hex<S: serde::Serializer>(v: &[u8], s: S) -> core::result::Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(v))
}

impl OsVersion {
    /// Parse a `GET_VERSION` response payload.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let target_id = r.u32()?;
        let mut raw_version = String::from_utf8_lossy(r.opt_lv()?.unwrap_or_default()).into_owned();
        let mut se_flags = r.opt_lv()?.unwrap_or_default().to_vec();
        if raw_version.is_empty() {
            raw_version = "0.0.0".into();
            se_flags.clear();
        }
        let is_bootloader = target_id & 0xf000_0000 != 0x3000_0000;
        let is_osu = raw_version.contains("-osu");
        let model = DeviceModel::from_target_id(target_id);

        let mut v = OsVersion {
            is_bootloader,
            is_osu,
            target_id,
            se_target_id: None,
            mcu_target_id: None,
            raw_version: raw_version.clone(),
            se_version: String::new(),
            flags: SeFlags::parse(&se_flags),
            se_flags,
            mcu_seph_version: String::new(),
            mcu_bootloader_version: String::new(),
            hw_version: String::new(),
            language_id: None,
            recover_state: None,
        };

        let str_of = |b: &[u8]| {
            String::from_utf8_lossy(b)
                .trim_end_matches('\0')
                .to_string()
        };
        let int_of = |b: &[u8]| b.iter().fold(0u32, |acc, x| (acc << 8) | *x as u32);

        if is_bootloader {
            v.mcu_bootloader_version = raw_version;
            v.mcu_target_id = Some(target_id);
            if let Some(se) = r.opt_lv()? {
                if se.len() >= 5 {
                    v.se_version = str_of(se);
                    v.se_target_id = r.opt_lv()?.map(int_of);
                } else {
                    v.se_target_id = Some(int_of(se));
                }
            }
        } else {
            v.se_version = raw_version;
            v.se_target_id = Some(target_id);
            v.mcu_seph_version = r.opt_lv()?.map(str_of).unwrap_or_default();
            let se = v.se_version.as_str();
            let bl_supported = match model {
                Some(DeviceModel::NanoS | DeviceModel::NanoX) => version_gte(se, (2, 0, 0)),
                _ => true,
            };
            if bl_supported {
                v.mcu_bootloader_version = r.opt_lv()?.map(str_of).unwrap_or_default();
            }
            let hw_supported =
                matches!(model, Some(DeviceModel::NanoX)) && version_gte(se, (2, 0, 0));
            v.hw_version = if hw_supported {
                r.opt_lv()?.map(hex::encode).unwrap_or_default()
            } else {
                "00".into()
            };
            let lang_supported = match model {
                Some(DeviceModel::NanoS) => false,
                Some(DeviceModel::NanoSPlus) => version_gte(se, (1, 1, 0)),
                Some(DeviceModel::NanoX) => version_gte(se, (2, 1, 0)),
                _ => true,
            };
            if lang_supported {
                v.language_id = r.opt_lv()?.map(int_of);
            }
            let recover_supported = match model {
                Some(DeviceModel::NanoS) => false,
                Some(DeviceModel::NanoSPlus) => version_gte(se, (1, 1, 2)),
                Some(DeviceModel::NanoX) => version_gte(se, (2, 2, 3)),
                Some(DeviceModel::Stax) => version_gte(se, (1, 4, 0)),
                Some(DeviceModel::Flex) => version_gte(se, (1, 0, 1)),
                _ => true,
            };
            if recover_supported {
                v.recover_state = r.opt_lv()?.map(int_of);
            }
        }
        Ok(v)
    }

    /// Device model, deduced from the target id.
    pub fn model(&self) -> Option<DeviceModel> {
        DeviceModel::from_target_id(self.target_id)
            .or_else(|| self.se_target_id.and_then(DeviceModel::from_target_id))
    }

    /// Firmware version without the `-osu` suffix.
    pub fn version(&self) -> String {
        self.raw_version.replace("-osu", "")
    }

    /// `major.minor[.patch]` part of the version.
    pub fn maj_min(&self) -> String {
        self.raw_version
            .split('-')
            .next()
            .unwrap_or_default()
            .to_string()
    }

    /// Provider name (suffix after `-` that is not `osu`), if any.
    pub fn provider_name(&self) -> Option<String> {
        let suffix = self.raw_version.split_once('-')?.1;
        match suffix {
            "das" | "club" | "shitcoins" | "ee" => Some(suffix.to_string()),
            _ => None,
        }
    }

    /// Manager API provider id for this device.
    pub fn provider_id(&self) -> u32 {
        provider_id_from_name(self.provider_name().as_deref())
    }

    /// MCU version to match against the manager API `mcu_versions` list.
    pub fn mcu_version(&self) -> &str {
        &self.mcu_seph_version
    }
}

/// Parsed secure element flags.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct SeFlags {
    pub is_pin_validated: bool,
    pub has_mcu_serial_number: bool,
    pub has_valid_certificate: bool,
    pub is_custom_authority_connection_allowed: bool,
    /// The user already allowed the secure channel ("allow manager") since boot.
    pub is_secure_connection_allowed: bool,
    pub is_onboarded: bool,
    pub is_mcu_code_signed: bool,
    pub is_in_recovery_mode: bool,
    pub has_endorsement_slot1: bool,
    pub has_endorsement_slot2: bool,
    /// Number of seed words (12/18/24), when known.
    pub seed_word_count: Option<u8>,
    pub current_word_index: u8,
    /// Raw onboarding state byte.
    pub onboarding_state: u8,
}

impl SeFlags {
    pub fn parse(flags: &[u8]) -> Self {
        let mut f = [0u8; 4];
        let n = flags.len().min(4);
        f[..n].copy_from_slice(&flags[..n]);
        let bit = |b: u8, n: u8| (b >> (8 - n)) & 1 == 1;
        let words = (f[2] >> 5) & 0x03;
        SeFlags {
            is_pin_validated: bit(f[0], 1),
            has_mcu_serial_number: bit(f[0], 2),
            has_valid_certificate: bit(f[0], 3),
            is_custom_authority_connection_allowed: bit(f[0], 4),
            is_secure_connection_allowed: bit(f[0], 5),
            is_onboarded: bit(f[0], 6),
            is_mcu_code_signed: bit(f[0], 7),
            is_in_recovery_mode: bit(f[0], 8),
            has_endorsement_slot1: f[1] & 1 != 0,
            has_endorsement_slot2: f[1] & 2 != 0,
            seed_word_count: [Some(24), Some(18), Some(12), None][words as usize],
            current_word_index: f[2] & 0x1f,
            onboarding_state: f[3],
        }
    }
}

/// Parsed `GET_APP_AND_VERSION` response.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct AppAndVersion {
    pub name: String,
    pub version: String,
    pub flags: Option<u32>,
}

impl AppAndVersion {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        if r.u8()? != 1 {
            return Err(Error::InvalidResponse(
                "unknown GET_APP_AND_VERSION format".into(),
            ));
        }
        let name = r.lv_string()?;
        let version = r.lv_string()?;
        let flags = r
            .opt_lv()?
            .map(|b| b.iter().fold(0u32, |acc, x| (acc << 8) | *x as u32));
        Ok(Self {
            name,
            version,
            flags,
        })
    }

    /// Whether this is the dashboard rather than an app.
    pub fn is_dashboard(&self) -> bool {
        is_dashboard_name(&self.name)
    }
}

/// An app installed on the device, as returned by `LIST_APPS`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct InstalledApp {
    pub name: String,
    /// Size in flash blocks.
    pub blocks: u16,
    pub flags: u16,
    /// Hash of code + data (hex).
    pub hash_code_data: String,
    /// Full app hash (hex), matches the manager API `hash`.
    pub hash: String,
}

/// Parse one `LIST_APPS` page.
pub fn parse_list_apps(data: &[u8]) -> Result<Vec<InstalledApp>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let mut r = Reader::new(data);
    if r.u8()? != 1 {
        return Err(Error::InvalidResponse("unknown LIST_APPS format".into()));
    }
    let mut apps = Vec::new();
    while !r.is_empty() {
        let _entry_len = r.u8()?;
        let blocks = r.u16()?;
        let flags = r.u16()?;
        let hash_code_data = hex::encode(r.bytes(32)?);
        let hash = hex::encode(r.bytes(32)?);
        let name = r.lv_string()?;
        apps.push(InstalledApp {
            name,
            blocks,
            flags,
            hash_code_data,
            hash,
        });
    }
    Ok(apps)
}

/// Battery information that can be queried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BatteryStatusKind {
    Percentage = 0,
    Voltage = 1,
    Temperature = 2,
    Current = 3,
    Flags = 4,
}

/// Battery status summary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct BatteryStatus {
    pub percentage: Option<u8>,
    pub voltage_mv: Option<u16>,
    pub temperature_c: Option<i8>,
    pub current_ma: Option<i8>,
    pub charging: bool,
    pub usb_connected: bool,
    pub ble_connected: bool,
    pub raw_flags: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_version_nanosp() {
        // target 33100004, "1.1.1", flags, mcu "5.24", bl "0.11", lang 00, recover? (absent)
        let mut d = vec![0x33, 0x10, 0x00, 0x04];
        d.push(5);
        d.extend_from_slice(b"1.1.1");
        d.extend_from_slice(&[4, 0xae, 0, 0, 0x0b]);
        d.push(4);
        d.extend_from_slice(b"5.24");
        d.push(4);
        d.extend_from_slice(b"0.11");
        d.extend_from_slice(&[1, 0]);
        let v = OsVersion::parse(&d).unwrap();
        assert_eq!(v.model(), Some(DeviceModel::NanoSPlus));
        assert_eq!(v.se_version, "1.1.1");
        assert_eq!(v.mcu_seph_version, "5.24");
        assert_eq!(v.mcu_bootloader_version, "0.11");
        assert_eq!(v.language_id, Some(0));
        assert!(v.flags.is_pin_validated);
        assert!(v.flags.is_secure_connection_allowed);
        assert!(!v.is_bootloader);
        assert_eq!(v.recover_state, None);
    }

    #[test]
    fn parse_app_version() {
        let d = [
            1, 5, b'B', b'O', b'L', b'O', b'S', 5, b'1', b'.', b'4', b'.', b'1',
        ];
        let a = AppAndVersion::parse(&d).unwrap();
        assert!(a.is_dashboard());
        assert_eq!(a.version, "1.4.1");
    }

    #[test]
    fn screen_saver() {
        let a = set_screen_saver(
            "Hello",
            ScreenSaverAnimation::CircleRightToLeft,
            ScreenSaverSpeed::Slow,
        )
        .unwrap();
        assert_eq!(a.p2, 0x12);
        assert_eq!(&a.data[..19], b"\x01\x11Screensaver Perso");
        assert_eq!(&a.data[19..], b"\x02\x05Hello");
        assert!(
            set_screen_saver("", ScreenSaverAnimation::Classic, ScreenSaverSpeed::Fast).is_err()
        );
        assert!(
            set_screen_saver("é", ScreenSaverAnimation::Classic, ScreenSaverSpeed::Fast).is_err()
        );
        assert_eq!(reset_screen_saver().encode().unwrap().len(), 5 + 19);
        let s = ScreenSaver::parse(b"\x01\x02\x05Hello\x00")
            .unwrap()
            .unwrap();
        assert_eq!(s.text, "Hello");
        assert_eq!(s.animation, Some(ScreenSaverAnimation::CircleRightToLeft));
        assert_eq!(s.speed, Some(ScreenSaverSpeed::Slow));
        assert_eq!(ScreenSaver::parse(b"").unwrap(), None);
    }

    #[test]
    fn misc_commands() {
        assert!(set_battery_charge_limit(101).is_err());
        assert_eq!(set_battery_charge_limit(80).unwrap().data, vec![80]);
        let o = onboard(OnboardIdentity::Main, "1234", "", "", "abandon about").unwrap();
        assert_eq!(o.p1, 0);
        assert_eq!(o.data, b"\x041234\x00\x00\x0dabandon about".to_vec());
        let lp = parse_language_pack(&[1, 9, 1, 2, 4, 0, 1, 0, 0])
            .unwrap()
            .unwrap();
        assert_eq!(lp, LanguagePack { id: 2, size: 65536 });
        assert_eq!(parse_language_pack(&[]).unwrap(), None);
        let e = EndorsementInfo::parse(&[0xff, 1, 0xaa, 2, 0x30, 0x00]).unwrap();
        assert_eq!(e.public_key, "aa");
        assert_eq!(e.certificate, "3000");
    }

    #[test]
    fn parse_apps() {
        let mut d = vec![1u8];
        let name = b"Bitcoin";
        d.push(70 + name.len() as u8);
        d.extend_from_slice(&[0x00, 0x20, 0x00, 0x08]);
        d.extend_from_slice(&[0xaa; 32]);
        d.extend_from_slice(&[0xbb; 32]);
        d.push(name.len() as u8);
        d.extend_from_slice(name);
        let apps = parse_list_apps(&d).unwrap();
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].name, "Bitcoin");
        assert_eq!(apps[0].blocks, 0x20);
        assert_eq!(apps[0].hash, "bb".repeat(32));
    }
}
