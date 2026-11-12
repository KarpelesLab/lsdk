//! Firmware update of the legacy BTChip family (HW.1, original Nano), a
//! port of the Ledger Wallet Chrome app's updater (`app/src/fup`).
//!
//! The firmware images are Ledger-signed APDU scripts published in that
//! app's repository; they are fetched from [`FIRMWARE_BASE_URL`] (pinned
//! commit) and checked against [`file_sha256`] before use.
//!
//! An update goes through the dongle's bootloader, across several reboots:
//!
//! 1. OS mode (`GET FIRMWARE VERSION`): a dongle set up on a firmware older
//!    than 1.1.0 must be **erased** first (wrong PINs); otherwise the init
//!    script of the current version, then the reloader that reboots into the
//!    bootloader ([`plan_os`]).
//! 2. Bootloader mode ([`bootloader_info`]: customer id and version): load the
//!    bootloader reloader, the bootloader, or (bootloader up to date) the OS,
//!    each followed by a reboot ([`plan_bootloader`]).
//! 3. OS mode again, on the new version: the init script.
//!
//! The caller drives the reboots (wait for the dongle to come back, detect
//! its mode, plan the next step) and runs each step with [`run_script`].

use purecrypto::hash::sha256;

use crate::apdu::{Response, StatusWord};
use crate::device::Device;
use crate::error::{Error, Result};
use crate::transport::Transport;

/// Commit of `LedgerHQ/ledger-wallet-chrome` holding the firmware files
/// ("Add HW.1/Nano update 1.0.4", August 2017).
pub const FIRMWARE_COMMIT: &str = "32e419d22e9b92b764866d7562708ad9af45514a";

/// Where the firmware files are fetched from (followed by the file name).
pub const FIRMWARE_BASE_URL: &str = "https://raw.githubusercontent.com/LedgerHQ/ledger-wallet-chrome/32e419d22e9b92b764866d7562708ad9af45514a/app/firmwares/";

/// `major.minor.patch` packed as `(major << 16) | (minor << 8) | patch`.
pub const fn v(major: u32, minor: u32, patch: u32) -> u32 {
    (major << 16) | (minor << 8) | patch
}

/// Latest OS: architecture 0x20, 1.0.4.
pub const LATEST_OS: (u8, u32) = (0x20, v(1, 0, 4));
/// Latest bootloader.
pub const LATEST_BOOTLOADER: u32 = v(1, 3, 16);
/// Bootloader reloader version.
pub const RELOADER: u32 = v(1, 33, 0);
/// Bootloaders older than this need a delay between APDUs.
const SLOW_BOOTLOADER_BELOW: u32 = v(1, 3, 11);
/// Firmware versions from which the PIN unlocks instead of erasing.
const SUB_FIRMWARE_FROM: (u8, u32) = (0x20, v(1, 1, 0));

/// Bootloader customer ids, in the order of the customer-specific files.
const CUSTOMER_IDS: [u16; 11] = [
    0x0143, 0x0144, 0x0146, 0x0147, 0x0148, 0x0149, 0x014a, 0x014b, 0x014c, 0x014d, 0x014e,
];

/// Suffixes of the customer-specific files (`loader-*`,
/// `loader-from-loader-*`, `reloader-from-loader-*`), in the app's order.
const CUSTOMER_FILES: [&str; 16] = [
    "0143", "0144", "0146", "0147", "0148", "0149", "01410", "01411", "01412", "01413", "01414",
    "1100", "1101", "1102", "1103", "1104",
];

/// OS reloaders (reboot from this OS version into the bootloader).
const OS_RELOADERS: [((u8, u32), &str); 17] = [
    ((0x00, v(1, 4, 3)), "reloader-0143"),
    ((0x00, v(1, 4, 4)), "reloader-0144"),
    ((0x00, v(1, 4, 5)), "reloader-0145"),
    ((0x00, v(1, 4, 6)), "reloader-0146"),
    ((0x00, v(1, 4, 7)), "reloader-0147"),
    ((0x00, v(1, 4, 8)), "reloader-0148"),
    ((0x00, v(1, 4, 9)), "reloader-0149"),
    ((0x00, v(1, 4, 10)), "reloader-01410"),
    ((0x00, v(1, 4, 11)), "reloader-01411"),
    ((0x00, v(1, 4, 12)), "reloader-01412"),
    ((0x00, v(1, 4, 13)), "reloader-01413"),
    ((0x00, v(1, 4, 14)), "reloader-01414"),
    ((0x20, v(1, 0, 0)), "reloader-1100"),
    ((0x20, v(1, 0, 1)), "reloader-1101"),
    ((0x20, v(1, 0, 2)), "reloader-1102"),
    ((0x20, v(1, 0, 3)), "reloader-1103"),
    ((0x20, v(1, 0, 4)), "reloader-1104"),
];

/// OS init scripts.
const OS_INITS: [((u8, u32), &str); 10] = [
    ((0x00, v(1, 4, 10)), "init-01410"),
    ((0x00, v(1, 4, 11)), "init-01411"),
    ((0x00, v(1, 4, 12)), "init-01412"),
    ((0x00, v(1, 4, 13)), "init-01413"),
    ((0x00, v(1, 4, 14)), "init-01414"),
    ((0x20, v(1, 0, 0)), "init-1100"),
    ((0x20, v(1, 0, 1)), "init-1101"),
    ((0x20, v(1, 0, 2)), "init-1102"),
    ((0x20, v(1, 0, 3)), "init-1103"),
    ((0x20, v(1, 0, 4)), "init-1104"),
];

/// SHA-256 of each firmware file (as published at [`FIRMWARE_COMMIT`]).
const FILE_HASHES: [(&str, &str); 75] = [
    (
        "reloader-01410",
        "e9a96f94cccd1ab3367e9dcdb02bf32478ab3fcbcc61bff69cb7469a0d2bbab6",
    ),
    (
        "reloader-01411",
        "814dacf2b0af4f4c1d4e75e43cbe2482e0f373505fc6832b0e2d5a8807533711",
    ),
    (
        "reloader-01412",
        "fdb5e404bcd73271f2cea235153d59f55f31cd800654ed20b548589a7ce8c2e5",
    ),
    (
        "reloader-01413",
        "9123dee12528a59e911dff078484df2c61de28737200b7f8ba9b8783fe0e706f",
    ),
    (
        "reloader-01414",
        "31dbd90eadc3c83750c595278c7c3718b63e09ed25115b62a5a8f4c6451812f5",
    ),
    (
        "reloader-0143",
        "4f74bb2f1ab8089989ef88601ccbaf55b8b846d0eb6b54e9f2fcf529d47a38f8",
    ),
    (
        "reloader-0144",
        "ffcfa5d0cfd5a6bc1f032030816d1662b1883e1fcccfd602dd725c700465b142",
    ),
    (
        "reloader-0145",
        "e929ecc8a3e594cf4ab37a3e6280e860232d52a77988450d6ecb1ec6a6a4bc9d",
    ),
    (
        "reloader-0146",
        "96deb754b3917f8e08bfdd528a7780227f7e519377d29ec4bf83b458e81e7a38",
    ),
    (
        "reloader-0147",
        "d52d045d8c80866407322f3e09b8139d894f1100f59cb207c0cbc419597ec1c0",
    ),
    (
        "reloader-0148",
        "c872466bfa1039949891aed01b4fed2b01806364b38d19d7d908248e43342720",
    ),
    (
        "reloader-0149",
        "cd75899670cedf44791e0dba08970e7dd8d03a91ec7be439c5d376721df0403d",
    ),
    (
        "reloader-1100",
        "31033ce574601ea0dd724a4909c50a05156aec5cb8868c3ca13dbc699d748625",
    ),
    (
        "reloader-1101",
        "4a81a376b664653202840b2fd7605c3da825e10108c4d51acc576b0e74df9471",
    ),
    (
        "reloader-1102",
        "50493020eebffeae35e5b90ebd7bb1a60c9eb1d922e82b1fc8320536d13ea0c0",
    ),
    (
        "reloader-1103",
        "3a40a79d7e7a290937d36753dc8a9aff7be50775ec99ba3b7054b9e20dfa0ee9",
    ),
    (
        "reloader-1104",
        "05614233a6463049ef60f6c7c66befcc395cd6a6a0195f573831a42246c7bbff",
    ),
    (
        "reloader-from-loader-01410",
        "18c1cab9a30da11be2cc0f90ea1a787c7721bc6a405a54ee3c6048f112b4f4a7",
    ),
    (
        "reloader-from-loader-01411",
        "b6828ab44d3296f97ab2985583f928e47240525ae090716b91c5ef5b647d2c7d",
    ),
    (
        "reloader-from-loader-01412",
        "589557cc5b8a86a51de330116bc80aafecf10fddd2e74dd3c30a014324563326",
    ),
    (
        "reloader-from-loader-01413",
        "966196c393bd2826678338aa39ead736a66913f6ecc717f353389c378f9611ca",
    ),
    (
        "reloader-from-loader-01414",
        "d403301232eeddfdb4d892c3c64ee17a4da19193539d474cf3c7566dc85319ff",
    ),
    (
        "reloader-from-loader-0143",
        "c87d4a189128222b5a6edf6d21e90be49e7e60aa992124b5679baa1054db653e",
    ),
    (
        "reloader-from-loader-0144",
        "3bd354b88b0d4df870a8762df148af2a3348f3ccbd2fd36357d3a6302a863485",
    ),
    (
        "reloader-from-loader-0146",
        "cfc8723c03b87d4e85fe596a5956853c2ff42836c324c4c492a5088de95e8608",
    ),
    (
        "reloader-from-loader-0147",
        "c9f7eed91ae44cc2cd1333bdb5e3809b0dbb6cf4a55078943d43cfe611ec5330",
    ),
    (
        "reloader-from-loader-0148",
        "79167994dea054ac7124e4efbfb736305a02b532213d7153eb0edc9b5b578b8f",
    ),
    (
        "reloader-from-loader-0149",
        "b8e41481776d2df3d7e11b249ec30f41fac80361ddbdcd0ca8c0110af63b6478",
    ),
    (
        "reloader-from-loader-1100",
        "246e701a60d929f2d618488d7608b1ad5bfbc481e2899f0fc221fe96fa284566",
    ),
    (
        "reloader-from-loader-1101",
        "69a35c1c6fe010503797afd4621e18b72fb5f4f3f5bd5c0ef44eb254bff76a46",
    ),
    (
        "reloader-from-loader-1102",
        "586be7d44cade2fe7d8fc377fcd96860f6bd04a9059e60ff6cdbf6bafd68347d",
    ),
    (
        "reloader-from-loader-1103",
        "2ec881fbfee89385eba50bd91fff4cf1b62de1ffebc94c266316041903525091",
    ),
    (
        "reloader-from-loader-1104",
        "936da2c88d9d36ff6002e101682e5b6b593a71e163921b2030c15b1127bd7cb4",
    ),
    (
        "init-01410",
        "fdb68b2068ea13f0b75e69f216c44e83f1375419b3f73f92e91586227b1a7402",
    ),
    (
        "init-01411",
        "a5fad57d875517cdf90324d7f2f6f3fff00517dab9cb699184e235d1629b6368",
    ),
    (
        "init-01412",
        "76d06d0da19c417ee1134dcc589b75eeb1ca8853b28b636d84f9e14a0c7bb140",
    ),
    (
        "init-01413",
        "00e3854eb5179aa6a160aa95344b63f4c5d63c4c2d8dfe7ec1ed58ea51969950",
    ),
    (
        "init-01414",
        "8d79045e0e29857e14888971b7a9956ab2f8b6175386150e6a93455fe4dc1aa7",
    ),
    (
        "init-1100",
        "628897917bfd52669be8c324f4cf167e6ca95a90ab15cca235911025aaf63dc1",
    ),
    (
        "init-1101",
        "7d5fda35a975d1aca7c5664a67ebacc86582fe533763a04ff800a00d061ad226",
    ),
    (
        "init-1102",
        "543f1c7909873e67e8fac2d2e1243ee50f1239f87f283cf4e56a22a83bbcd3a9",
    ),
    (
        "init-1103",
        "c4c0417c6b1586cf84b1a8461ea11586e945cdefd3cc409d7af10b0a773876b1",
    ),
    (
        "init-1104",
        "e8a5305a26d111e60d2a145936a3b2e0dfa943e4c99feaf89e7b7ff11d2c512f",
    ),
    (
        "loader-01410",
        "c9120b744fb0698aa7bd0dbe2717c698290664d2d50b65f648ccaf59fe4614d1",
    ),
    (
        "loader-01411",
        "8720194d92c1355e280a8c8bdb250826a571a8d5573f43845ac8c5259b569eef",
    ),
    (
        "loader-01412",
        "70130a404794fdd8974c5a7dc03dfac199a6cae34d22d3a2349ad3967f99223c",
    ),
    (
        "loader-01413",
        "51fc0892c3b038dd3b603f5be9e64351258538782e0c69fbeaa410f080d0ac06",
    ),
    (
        "loader-01414",
        "d2c9f4e3b81f7bed18201267454a549fa0f55079c90dda20405eeece61e9a4eb",
    ),
    (
        "loader-0143",
        "bb7a6c845694f7a225b22b06053f2ac9f3f4de13c83cda8e49d5646987de5553",
    ),
    (
        "loader-0144",
        "cf9c013b9629879cadabdce0b7dbb0bfdc6ba138e9faf6765af254381818b3ce",
    ),
    (
        "loader-0146",
        "9f8483d00ece47bf1587ede6d59e6b6460b9aa2e38b44f8c4f2f1bb715ada894",
    ),
    (
        "loader-0147",
        "e4f08a194ee6dc407f6601a4fd0636e9a7d35f5cd71455e1e0c7926de361e228",
    ),
    (
        "loader-0148",
        "7a12d6332172c81cbd76992ce37b937117a72d3163110cc992d68b7cb2b0664d",
    ),
    (
        "loader-0149",
        "803d377987307b4d691a68bc922710f898195e191fa5cf661d543564608317e9",
    ),
    (
        "loader-1100",
        "00d607b019ca9ae81b45c3b2e06503cfd49bfe7b6c60b971d558f122f37672a6",
    ),
    (
        "loader-1101",
        "c36429dc6b6c933ba78ec0bd55dc3f1d18a9906bd8b5556618fd8a30b2343091",
    ),
    (
        "loader-1102",
        "73e03d27a039ca1d3fdc735aaa21047eb8e93a99cda48304aef1b21ed950e629",
    ),
    (
        "loader-1103",
        "9621fae7b8944252760c69ab3735b60c7b2d85f8f3b7aefc1e39fb7b3ab3724f",
    ),
    (
        "loader-1104",
        "4e9d5920c07f13702f7b50df76af9342dc24bde68c76bd86f5bb415e330b05a4",
    ),
    (
        "loader-from-loader-01410",
        "ecdfcb56a935821095ea8ef41941c1efb5f54981b56204763a9776fe1a87a055",
    ),
    (
        "loader-from-loader-01411",
        "9755580a6dfa333366891035bfc0f3b649546d203f04f92adea87a31cc5f21af",
    ),
    (
        "loader-from-loader-01412",
        "3a27922817d812aaccd405657746e74f1719634503d90b3403beff3d53f9c0bb",
    ),
    (
        "loader-from-loader-01413",
        "99f1e3d7783b27ec6691ecd700694c6d7271730ce2e331a6e69d10da9e724168",
    ),
    (
        "loader-from-loader-01414",
        "b8271049155b501f9b16fc4a5f1d37fd039f28d0faf81a6773ebad3caf30ef25",
    ),
    (
        "loader-from-loader-0143",
        "5e42ee7d47df7b772f3d00a3090c6825fa7f120a3783cdcd462f45a071e1f9d2",
    ),
    (
        "loader-from-loader-0144",
        "6587b0f2025218ffff5ad645a790f61f14be98431b0aa608446d94b9bae404ea",
    ),
    (
        "loader-from-loader-0146",
        "59155768f51813240d79c5803220ddbda0050252dc88738ac316d73186f43bf6",
    ),
    (
        "loader-from-loader-0147",
        "c2f1d9352fcf6b96da15735479b303c8952e077d8fe1604199319032d794d980",
    ),
    (
        "loader-from-loader-0148",
        "05c34cf1e7ec5e53231b574183cc27df51c88ee6649bcf8321b52d52f9802b21",
    ),
    (
        "loader-from-loader-0149",
        "1a32410ac281753ad07594cf9a1e1cbdf756228cb656fb2e2ea309b1412b606c",
    ),
    (
        "loader-from-loader-1100",
        "b5406749f9ce52668c720b73d455aff1cabc7dd94d0656b72b21f976608466c9",
    ),
    (
        "loader-from-loader-1101",
        "ddf5c5d91bddfe102516b26bf71f0eab4466eec179088cf7b6c24f47891ca968",
    ),
    (
        "loader-from-loader-1102",
        "f3b0bf02febfc2b15a7b944fb25f992683c808676ec22162cd2fa74f199e55fd",
    ),
    (
        "loader-from-loader-1103",
        "12584b45aa12ca6bba860daeec765e08d920836d47fa78155b0b3cdf1acd72a8",
    ),
    (
        "loader-from-loader-1104",
        "118ae0f34bdf9627789a7ec25cf403e55ee8de66d3f81d8f3f1eafad206c4b1c",
    ),
];

/// Pinned SHA-256 (hex) of a firmware file, by name (`reloader-1101`...).
pub fn file_sha256(name: &str) -> Option<&'static str> {
    FILE_HASHES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, h)| *h)
}

/// URL of a firmware file.
pub fn file_url(name: &str) -> String {
    format!("{FIRMWARE_BASE_URL}btchipfirmware-{name}.js")
}

/// Check a downloaded file against its pinned hash and extract its APDUs
/// (the quoted hex strings of the `var X = [...]` script).
pub fn load_script(name: &str, contents: &str) -> Result<Vec<Vec<u8>>> {
    let want = file_sha256(name)
        .ok_or_else(|| Error::InvalidInput(format!("unknown firmware file {name}")))?;
    if hex::encode(sha256(contents.as_bytes())) != want {
        return Err(Error::App(format!(
            "firmware file {name} does not match its pinned hash"
        )));
    }
    let mut out = Vec::new();
    for (i, part) in contents.split('"').enumerate() {
        if i % 2 == 1 {
            out.push(
                hex::decode(part)
                    .map_err(|e| Error::InvalidInput(format!("{name}: bad hex: {e}")))?,
            );
        }
    }
    if out.is_empty() {
        return Err(Error::InvalidInput(format!("{name}: no APDU")));
    }
    Ok(out)
}

/// Download, check and parse a firmware file.
#[cfg(feature = "manager-api")]
pub async fn fetch_script(name: &str) -> Result<Vec<Vec<u8>>> {
    let text = crate::manager::api::get_text(&file_url(name)).await?;
    load_script(name, &text)
}

/// Version as packed in [`v`], shown as `x.y.z`.
pub fn version_string(version: u32) -> String {
    format!(
        "{}.{}.{}",
        version >> 16,
        (version >> 8) & 0xff,
        version & 0xff
    )
}

/// Bootloader state.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct BootloaderInfo {
    pub customer_id: u16,
    /// Position of the customer id in the app's list, `None` if unknown.
    pub customer_index: Option<usize>,
    /// Packed version ([`v`]).
    pub version: u32,
}

/// Probe a dongle opened with the bootloader (plain) framing: `Ok(true)` if a
/// bootloader answers; an OS in channel framing replies with a frame starting
/// with 0xF0.
pub async fn is_bootloader<T: Transport>(device: &Device<T>) -> Result<bool> {
    let raw = device.exchange_raw(&[0xf0, 0x01, 0x00, 0x00, 0x00]).await?;
    Ok(raw.first() != Some(&0xf0))
}

fn ok(raw: Vec<u8>) -> Result<Vec<u8>> {
    let r = Response::from_raw(raw)?;
    match r.sw {
        StatusWord::OK => Ok(r.data),
        sw => Err(sw.into()),
    }
}

/// Customer id and version of the bootloader. Afterwards the bootloader only
/// accepts the `E0` load commands until it is power cycled: read this once,
/// then load in the same session.
pub async fn bootloader_info<T: Transport>(device: &Device<T>) -> Result<BootloaderInfo> {
    let id = ok(device.exchange_raw(&[0xf0, 0x01, 0x01, 0x00, 0x00]).await?)?;
    if id.len() < 2 {
        return Err(Error::InvalidResponse("short customer id".into()));
    }
    let customer_id = u16::from_be_bytes([id[0], id[1]]);
    let mut version = ok(device.exchange_raw(&[0xf0, 0x01, 0x00, 0x00, 0x00]).await?)?;
    // A loaded reloader answers this one instead.
    if let Ok(r) = ok(device.exchange_raw(&[0xe0, 0x01, 0x00, 0x00, 0x00]).await?) {
        version = r;
    }
    if version.len() < 8 {
        return Err(Error::InvalidResponse("short bootloader version".into()));
    }
    Ok(BootloaderInfo {
        customer_id,
        customer_index: CUSTOMER_IDS.iter().position(|c| *c == customer_id),
        version: (u32::from(version[5]) << 16)
            | (u32::from(version[6]) << 8)
            | u32::from(version[7]),
    })
}

/// One update step.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "camelCase", tag = "step", content = "file")
)]
pub enum Step {
    /// Nothing to do.
    UpToDate,
    /// Set up on a firmware older than 1.1.0: erase it first (3 wrong PINs,
    /// replugging after each).
    Erase,
    /// Init script of the current OS (status words ignored).
    OsInit(String),
    /// Reboot from the OS into the bootloader (the dongle reboots by itself).
    ReloadBootloaderFromOs(String),
    /// Bootloader: load the reloader (then reboot).
    LoadBootloaderReloader(String),
    /// Reloader: load the latest bootloader (then reboot).
    LoadBootloader(String),
    /// Bootloader up to date: load the latest OS (then reboot).
    LoadOs(String),
    /// New OS loaded: its init script; the update is then done.
    InitOs(String),
}

impl Step {
    /// Firmware file of the step, if any.
    pub fn file(&self) -> Option<&str> {
        match self {
            Step::UpToDate | Step::Erase => None,
            Step::OsInit(f)
            | Step::ReloadBootloaderFromOs(f)
            | Step::LoadBootloaderReloader(f)
            | Step::LoadBootloader(f)
            | Step::LoadOs(f)
            | Step::InitOs(f) => Some(f),
        }
    }

    /// How [`run_script`] must send this step's file.
    pub fn options(&self, slow: bool) -> ScriptOptions {
        match self {
            Step::OsInit(_) | Step::InitOs(_) => ScriptOptions {
                ignore_sw: true,
                ..Default::default()
            },
            Step::ReloadBootloaderFromOs(_) => ScriptOptions {
                fire_last: true,
                ..Default::default()
            },
            _ => ScriptOptions {
                slow,
                ..Default::default()
            },
        }
    }

    /// Whether the dongle reboots after this step.
    pub fn reboots(&self) -> bool {
        matches!(
            self,
            Step::ReloadBootloaderFromOs(_)
                | Step::LoadBootloaderReloader(_)
                | Step::LoadBootloader(_)
                | Step::LoadOs(_)
        )
    }
}

fn newer(a: (u8, u32), b: (u8, u32)) -> bool {
    a.0 > b.0 || (a.0 == b.0 && a.1 > b.1)
}

/// Steps from OS mode: `os` is `(architecture, version)` from `GET FIRMWARE
/// VERSION`, `set_up` whether the dongle is set up, `os_loaded` whether the
/// latest OS was just loaded by this update.
pub fn plan_os(os: (u8, u32), set_up: bool, os_loaded: bool) -> Result<Vec<Step>> {
    if os == LATEST_OS {
        return Ok(if os_loaded {
            vec![Step::InitOs(init_file(os)?)]
        } else {
            vec![Step::UpToDate]
        });
    }
    if newer(os, LATEST_OS) {
        return Err(Error::App(format!(
            "firmware {} is newer than the latest known ({})",
            version_string(os.1),
            version_string(LATEST_OS.1)
        )));
    }
    if set_up && newer(SUB_FIRMWARE_FROM, os) {
        return Ok(vec![Step::Erase]);
    }
    let reloader = OS_RELOADERS
        .iter()
        .find(|(k, _)| *k == os)
        .map(|(_, f)| f.to_string())
        .ok_or_else(|| {
            Error::App(format!(
                "no update path from firmware {} (architecture 0x{:02x})",
                version_string(os.1),
                os.0
            ))
        })?;
    let mut steps = Vec::new();
    if let Some((_, f)) = OS_INITS.iter().find(|(k, _)| *k == os) {
        steps.push(Step::OsInit(f.to_string()));
    }
    steps.push(Step::ReloadBootloaderFromOs(reloader));
    Ok(steps)
}

fn init_file(os: (u8, u32)) -> Result<String> {
    OS_INITS
        .iter()
        .find(|(k, _)| *k == os)
        .map(|(_, f)| f.to_string())
        .ok_or_else(|| Error::App("no init script for this version".into()))
}

/// Step from bootloader mode.
pub fn plan_bootloader(info: &BootloaderInfo) -> Result<Step> {
    let i = info.customer_index.ok_or_else(|| {
        Error::App(format!(
            "unknown bootloader customer id {:04x}: no matching firmware",
            info.customer_id
        ))
    })?;
    let suffix = CUSTOMER_FILES[i];
    Ok(if info.version == LATEST_BOOTLOADER {
        Step::LoadOs(format!("loader-{suffix}"))
    } else if info.version == RELOADER {
        Step::LoadBootloader(format!("loader-from-loader-{suffix}"))
    } else {
        Step::LoadBootloaderReloader(format!("reloader-from-loader-{suffix}"))
    })
}

/// Whether a bootloader needs a delay between APDUs.
pub fn is_slow_bootloader(info: &BootloaderInfo) -> bool {
    info.version < SLOW_BOOTLOADER_BELOW
}

/// How [`run_script`] treats replies.
#[derive(Clone, Copy, Debug, Default)]
pub struct ScriptOptions {
    /// Don't check status words (init scripts).
    pub ignore_sw: bool,
    /// Send the last APDU without waiting for a reply (the dongle reboots).
    pub fire_last: bool,
    /// Wait 200 ms between APDUs (old bootloaders).
    pub slow: bool,
}

/// Send a firmware script, APDU by APDU. A non-`9000` reply is retried once
/// after a pause, as the app did; the last APDU may fail (the dongle is
/// rebooting). `progress(sent, total)` is called after each APDU.
pub async fn run_script<T: Transport>(
    device: &Device<T>,
    apdus: &[Vec<u8>],
    opts: ScriptOptions,
    progress: &mut dyn FnMut(usize, usize),
) -> Result<()> {
    let total = apdus.len();
    for (i, apdu) in apdus.iter().enumerate() {
        let last = i + 1 == total;
        if last && opts.fire_last {
            // The dongle may reboot before (or instead of) answering.
            let _ = device.exchange_raw(apdu).await;
            progress(total, total);
            return Ok(());
        }
        let mut retried = false;
        loop {
            match device.exchange_raw(apdu).await.and_then(Response::from_raw) {
                Ok(r) if opts.ignore_sw || r.sw == StatusWord::OK => break,
                _ if last => break,
                Err(Error::Disconnected) => return Err(Error::Disconnected),
                Ok(_) | Err(_) if !retried => retried = true,
                Ok(r) => {
                    return Err(Error::App(format!(
                        "APDU {}/{total} refused: {}",
                        i + 1,
                        r.sw
                    )));
                }
                Err(e) => return Err(e),
            }
            pause(200).await;
        }
        if opts.slow {
            pause(200).await;
        }
        progress(i + 1, total);
    }
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
async fn pause(ms: u64) {
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

#[cfg(target_arch = "wasm32")]
async fn pause(ms: u64) {
    let p = js_sys::Promise::new(&mut |resolve, _| {
        if let Some(w) = web_sys::window() {
            let _ = w.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms as i32);
        }
    });
    let _ = wasm_bindgen_futures::JsFuture::from(p).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans() {
        // Blank 1.0.1 dongle: init of 1.0.1, then reboot into the bootloader.
        assert_eq!(
            plan_os((0x20, v(1, 0, 1)), false, false).unwrap(),
            vec![
                Step::OsInit("init-1101".into()),
                Step::ReloadBootloaderFromOs("reloader-1101".into())
            ]
        );
        assert_eq!(
            plan_os((0x20, v(1, 0, 1)), true, false).unwrap(),
            vec![Step::Erase]
        );
        assert_eq!(
            plan_os(LATEST_OS, false, false).unwrap(),
            vec![Step::UpToDate]
        );
        assert_eq!(
            plan_os(LATEST_OS, false, true).unwrap(),
            vec![Step::InitOs("init-1104".into())]
        );
        let bl = |version, customer_id| BootloaderInfo {
            customer_id,
            customer_index: CUSTOMER_IDS.iter().position(|c| *c == customer_id),
            version,
        };
        assert_eq!(
            plan_bootloader(&bl(LATEST_BOOTLOADER, 0x014a)).unwrap(),
            Step::LoadOs("loader-01410".into())
        );
        assert_eq!(
            plan_bootloader(&bl(RELOADER, 0x0143)).unwrap(),
            Step::LoadBootloader("loader-from-loader-0143".into())
        );
        assert_eq!(
            plan_bootloader(&bl(v(1, 3, 10), 0x0149)).unwrap(),
            Step::LoadBootloaderReloader("reloader-from-loader-0149".into())
        );
        assert!(plan_bootloader(&bl(LATEST_BOOTLOADER, 0x9999)).is_err());
        // Every file a plan can name has a pinned hash.
        for (_, f) in OS_RELOADERS.iter().chain(OS_INITS.iter()) {
            assert!(file_sha256(f).is_some(), "{f}");
        }
        for s in CUSTOMER_FILES {
            for p in ["loader-", "loader-from-loader-", "reloader-from-loader-"] {
                assert!(file_sha256(&format!("{p}{s}")).is_some(), "{p}{s}");
            }
        }
    }

    #[test]
    fn load_script_checks_hash() {
        assert!(load_script("reloader-1101", "var RELOADER_1101 = [\"00\"];").is_err());
        assert!(load_script("nope", "").is_err());
    }
}
