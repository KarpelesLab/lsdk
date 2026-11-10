//! Client for the manager HTTP API (app catalog, firmware metadata).

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Default manager API base URL.
pub const DEFAULT_BASE_URL: &str = "https://manager.api.live.ledger.com/api";

/// A device version (hardware family) as known by the API.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceVersion {
    pub id: u32,
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub target_id: Option<String>,
    #[serde(default)]
    pub providers: Vec<u32>,
    #[serde(default)]
    pub mcu_versions: Vec<u32>,
    #[serde(default)]
    pub se_firmware_final_versions: Vec<u32>,
}

/// A final (installed) secure element firmware.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalFirmware {
    pub id: u32,
    pub name: String,
    pub version: String,
    pub perso: String,
    #[serde(default)]
    pub firmware: Option<String>,
    #[serde(default)]
    pub firmware_key: Option<String>,
    #[serde(default)]
    pub hash: Option<String>,
    #[serde(default)]
    pub bytes: Option<u64>,
    #[serde(default)]
    pub mcu_versions: Vec<u32>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
}

/// An OS updater: the package that moves a device to a new final firmware.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OsuFirmware {
    pub id: u32,
    pub name: String,
    pub perso: String,
    pub firmware: String,
    pub firmware_key: String,
    #[serde(default)]
    pub hash: Option<String>,
    pub next_se_firmware_final_version: u32,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
}

/// An MCU firmware version.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McuVersion {
    pub id: u32,
    pub name: String,
    #[serde(default)]
    pub mcu: Option<u32>,
    #[serde(default)]
    pub providers: Vec<u32>,
    #[serde(default)]
    pub from_bootloader_version: String,
    #[serde(default)]
    pub device_versions: Vec<u32>,
    #[serde(default)]
    pub se_firmware_final_versions: Vec<u32>,
}

/// An app in the catalog (v2 API).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Application {
    pub version_id: u64,
    /// App name, as reported by `LIST_APPS` once installed.
    pub version_name: String,
    #[serde(default)]
    pub version_display_name: Option<String>,
    pub version: String,
    #[serde(default)]
    pub currency_id: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub application_type: Option<String>,
    #[serde(default)]
    pub date_modified: Option<String>,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub author_name: Option<String>,
    #[serde(default, rename = "supportURL")]
    pub support_url: Option<String>,
    #[serde(default, rename = "sourceURL")]
    pub source_url: Option<String>,
    /// Full app hash, matches [`crate::os::InstalledApp::hash`].
    pub hash: String,
    pub perso: String,
    pub firmware: String,
    pub firmware_key: String,
    pub delete: String,
    pub delete_key: String,
    #[serde(default)]
    pub bytes: Option<u64>,
    #[serde(default)]
    pub warning: Option<String>,
    #[serde(default)]
    pub is_dev_tools: bool,
    #[serde(default)]
    pub category: Option<u32>,
    #[serde(default)]
    pub parent: Option<u64>,
    /// Name of the app this one depends on (e.g. Ethereum for plugins).
    #[serde(default)]
    pub parent_name: Option<String>,
}

/// A language pack from the catalog.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LanguagePackage {
    /// Language name (`french`, `spanish`...).
    pub language: String,
    #[serde(rename = "languagePackageVersionId")]
    pub language_package_version_id: u64,
    pub version: String,
    #[serde(default)]
    pub language_package_id: Option<u64>,
    /// URL of the install APDU script (one hex APDU per line).
    pub apdu_install_url: String,
    /// URL of the uninstall APDU script.
    #[serde(default)]
    pub apdu_uninstall_url: Option<String>,
    #[serde(default)]
    pub bytes: Option<u64>,
}

impl LanguagePackage {
    /// Device language id of this pack.
    pub fn language_id(&self) -> Option<u8> {
        Some(match self.language.as_str() {
            "english" => 0,
            "french" => 1,
            "spanish" => 2,
            "portuguese" => 3,
            "german" => 4,
            "russian" => 5,
            "turkish" => 6,
            _ => return None,
        })
    }
}

#[derive(Deserialize)]
struct LatestFirmwareResponse {
    result: String,
    se_firmware_osu_version: Option<OsuFirmware>,
}

/// Manager API client.
#[derive(Clone, Debug)]
pub struct ManagerApi {
    base_url: String,
    client: reqwest::Client,
    /// Firmware distribution salt (staged rollouts). `"0"` by default.
    pub salt: String,
}

impl Default for ManagerApi {
    fn default() -> Self {
        Self::new(DEFAULT_BASE_URL)
    }
}

fn http_err(e: reqwest::Error) -> Error {
    Error::Http(e.to_string())
}

impl ManagerApi {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            client: reqwest::Client::new(),
            salt: "0".into(),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    async fn get<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .get(&url)
            .query(query)
            .send()
            .await
            .map_err(http_err)?;
        let status = resp.status();
        if status.as_u16() == 404 {
            return Err(Error::NotFound(format!("{path} {query:?}")));
        }
        if !status.is_success() {
            return Err(Error::Http(format!("{url}: HTTP {status}")));
        }
        resp.json().await.map_err(http_err)
    }

    /// Device version from a target id.
    pub async fn get_device_version(&self, target_id: u32, provider: u32) -> Result<DeviceVersion> {
        self.get(
            "/get_device_version",
            &[
                ("target_id", target_id.to_string()),
                ("provider", provider.to_string()),
            ],
        )
        .await
    }

    /// Final firmware from its version name (e.g. `1.4.1`).
    pub async fn get_firmware_version(
        &self,
        device_version: u32,
        version_name: &str,
        provider: u32,
    ) -> Result<FinalFirmware> {
        self.get(
            "/get_firmware_version",
            &[
                ("device_version", device_version.to_string()),
                ("version_name", version_name.to_string()),
                ("provider", provider.to_string()),
            ],
        )
        .await
    }

    /// OSU from its version name (e.g. `1.4.1-osu`).
    pub async fn get_osu_version(
        &self,
        device_version: u32,
        version_name: &str,
        provider: u32,
    ) -> Result<OsuFirmware> {
        self.get(
            "/get_osu_version",
            &[
                ("device_version", device_version.to_string()),
                ("version_name", version_name.to_string()),
                ("provider", provider.to_string()),
            ],
        )
        .await
    }

    /// Final firmware by id.
    pub async fn get_final_firmware_by_id(&self, id: u32) -> Result<FinalFirmware> {
        self.get(&format!("/firmware_final_versions/{id}"), &[])
            .await
    }

    /// Latest available OSU for a device, `None` when up to date.
    pub async fn get_latest_firmware(
        &self,
        current_final_id: u32,
        device_version: u32,
        provider: u32,
    ) -> Result<Option<OsuFirmware>> {
        let r: LatestFirmwareResponse = self
            .get(
                "/get_latest_firmware",
                &[
                    (
                        "current_se_firmware_final_version",
                        current_final_id.to_string(),
                    ),
                    ("device_version", device_version.to_string()),
                    ("provider", provider.to_string()),
                    ("salt", self.salt.clone()),
                ],
            )
            .await?;
        match r.result.as_str() {
            "null" => Ok(None),
            "success" => Ok(r.se_firmware_osu_version),
            other => Err(Error::Http(format!("get_latest_firmware: {other}"))),
        }
    }

    /// All MCU versions.
    pub async fn get_mcu_versions(&self) -> Result<Vec<McuVersion>> {
        self.get("/mcu_versions", &[]).await
    }

    /// App catalog for a device / firmware.
    pub async fn get_apps_by_target(
        &self,
        target_id: u32,
        firmware_version_name: &str,
        provider: u32,
    ) -> Result<Vec<Application>> {
        self.get(
            "/v2/apps/by-target",
            &[
                ("target_id", target_id.to_string()),
                ("provider", provider.to_string()),
                ("firmware_version_name", firmware_version_name.to_string()),
            ],
        )
        .await
    }

    /// Language packs available for a device version and final firmware.
    pub async fn get_language_packages(
        &self,
        device_version: u32,
        final_firmware_id: u32,
    ) -> Result<Vec<LanguagePackage>> {
        self.get(
            "/language-packages",
            &[
                ("device_version", device_version.to_string()),
                (
                    "current_se_firmware_final_version",
                    final_firmware_id.to_string(),
                ),
            ],
        )
        .await
    }

    /// Download a text resource (APDU scripts).
    pub async fn fetch_text(&self, url: &str) -> Result<String> {
        let resp = self.client.get(url).send().await.map_err(http_err)?;
        if !resp.status().is_success() {
            return Err(Error::Http(format!("{url}: HTTP {}", resp.status())));
        }
        resp.text().await.map_err(http_err)
    }

    /// Resolve installed app hashes to catalog entries.
    pub async fn get_apps_by_hash(&self, hashes: &[String]) -> Result<Vec<Option<Application>>> {
        let url = format!("{}/v2/apps/hash", self.base_url);
        let resp = self
            .client
            .post(&url)
            .json(hashes)
            .send()
            .await
            .map_err(http_err)?;
        if !resp.status().is_success() {
            return Err(Error::Http(format!("{url}: HTTP {}", resp.status())));
        }
        resp.json().await.map_err(http_err)
    }
}

/// Pick the highest MCU version from a list (semver-ish comparison on `name`).
pub fn find_best_mcu(mcus: &[McuVersion]) -> Option<&McuVersion> {
    mcus.iter()
        .max_by_key(|m| crate::model::parse_version(&m.name))
}
