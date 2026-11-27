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
    /// Final firmware ids this OSU updates from.
    #[serde(default)]
    pub previous_se_firmware_final_versions: Vec<u32>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
}

/// A final firmware from the full catalog (`/firmware_final_versions`),
/// with the OS updaters leading to it. Release notes are left out.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CatalogFinal {
    pub id: u32,
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub perso: Option<String>,
    #[serde(default)]
    pub firmware: Option<String>,
    #[serde(default)]
    pub firmware_key: Option<String>,
    #[serde(default)]
    pub hash: Option<String>,
    /// OS size, as used by Ledger Live to compute the space left for apps.
    #[serde(default)]
    pub bytes: Option<u64>,
    #[serde(default)]
    pub mcu_versions: Vec<u32>,
    #[serde(default)]
    pub device_versions: Vec<u32>,
    #[serde(default)]
    pub providers: Vec<u32>,
    #[serde(default)]
    pub date_creation: Option<String>,
    #[serde(default)]
    pub date_last_modified: Option<String>,
    #[serde(default)]
    pub osu_versions: Vec<CatalogOsu>,
}

/// An OS updater from the full catalog. Release notes are left out.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CatalogOsu {
    pub id: u32,
    pub name: String,
    #[serde(default)]
    pub perso: Option<String>,
    #[serde(default)]
    pub firmware: Option<String>,
    #[serde(default)]
    pub firmware_key: Option<String>,
    #[serde(default)]
    pub hash: Option<String>,
    pub next_se_firmware_final_version: u32,
    #[serde(default)]
    pub previous_se_firmware_final_versions: Vec<u32>,
    #[serde(default)]
    pub device_versions: Vec<u32>,
    #[serde(default)]
    pub providers: Vec<u32>,
    #[serde(default)]
    pub date_creation: Option<String>,
    #[serde(default)]
    pub date_last_modified: Option<String>,
}

/// OSU hashes the API is known to get wrong, by OSU id: `(id, correct hash)`.
///
/// - 56 (`1.6.0-osu-hidden`, Nano S from 1.3.1): the API value keeps the real
///   first/last 4 characters but its middle is copied from the 1.3.1 OSU hash.
const OSU_HASH_OVERRIDES: &[(u32, &str)] = &[(
    56,
    "9e54738f0235898098a1dbcefd9399380508d8e152d16652ccddf59bf317a009",
)];

/// Corrected hash for an OSU id whose API hash is known to be wrong.
pub fn osu_hash_override(osu_id: u32) -> Option<&'static str> {
    OSU_HASH_OVERRIDES
        .iter()
        .find(|(id, _)| *id == osu_id)
        .map(|(_, h)| *h)
}

impl OsuFirmware {
    /// Hash the device should display after receiving this OSU: the known
    /// correction if any, else the API value as returned.
    pub fn expected_hash(&self) -> Option<&str> {
        osu_hash_override(self.id).or(self.hash.as_deref())
    }
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
            "portuguese" | "brazilian" => 3,
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
    /// Firmware distribution salt (staged rollouts). `"0"` by default.
    pub salt: String,
}

impl Default for ManagerApi {
    fn default() -> Self {
        Self::new(DEFAULT_BASE_URL)
    }
}

fn http_err(e: rsurl::Error) -> Error {
    Error::Http(e.to_string())
}

/// Percent-encode a query component (RFC 3986 unreserved characters kept).
fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

async fn send(req: rsurl::aio::Request) -> Result<rsurl::aio::Response> {
    #[cfg(not(target_arch = "wasm32"))]
    let resp = rsurl::aio::request(&rsurl::aio::TokioRuntime, &req).await;
    #[cfg(target_arch = "wasm32")]
    let resp = rsurl::aio::request(&req).await;
    resp.map_err(http_err)
}

fn check(url: &str, resp: &rsurl::aio::Response) -> Result<()> {
    if resp.is_success() {
        Ok(())
    } else {
        Err(Error::Http(format!(
            "{url}: HTTP {} {}",
            resp.status, resp.reason
        )))
    }
}

/// GET a text resource (any URL).
pub async fn get_text(url: &str) -> Result<String> {
    let resp = send(request("GET", url)).await?;
    check(url, &resp)?;
    resp.text().map_err(http_err)
}

fn request(method: &str, url: &str) -> rsurl::aio::Request {
    rsurl::aio::Request::new(method, url)
        .follow_redirects(true)
        .timeout(std::time::Duration::from_secs(60))
}

impl ManagerApi {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
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
        let mut url = format!("{}{}", self.base_url, path);
        for (i, (k, v)) in query.iter().enumerate() {
            url.push(if i == 0 { '?' } else { '&' });
            url.push_str(&encode(k));
            url.push('=');
            url.push_str(&encode(v));
        }
        let resp = send(request("GET", &url)).await?;
        if resp.status == 404 {
            return Err(Error::NotFound(format!("{path} {query:?}")));
        }
        check(&url, &resp)?;
        resp.json().map_err(http_err)
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

    /// Every final firmware with its OS updaters (all devices).
    pub async fn get_firmware_catalog(&self) -> Result<Vec<CatalogFinal>> {
        self.get("/firmware_final_versions", &[]).await
    }

    /// All device versions (hardware families and revisions).
    pub async fn get_device_versions(&self) -> Result<Vec<DeviceVersion>> {
        self.get("/device_versions", &[]).await
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
        let resp = send(request("GET", url)).await?;
        check(url, &resp)?;
        resp.text().map_err(http_err)
    }

    /// Resolve installed app hashes to catalog entries.
    pub async fn get_apps_by_hash(&self, hashes: &[String]) -> Result<Vec<Option<Application>>> {
        let url = format!("{}/v2/apps/hash", self.base_url);
        let body = serde_json::to_vec(hashes).map_err(|e| Error::Http(e.to_string()))?;
        let req = request("POST", &url)
            .header("Content-Type", "application/json")
            .body(body);
        let resp = send(req).await?;
        check(&url, &resp)?;
        resp.json().map_err(http_err)
    }
}

/// Pick the highest MCU version from a list (semver-ish comparison on `name`).
pub fn find_best_mcu(mcus: &[McuVersion]) -> Option<&McuVersion> {
    mcus.iter()
        .max_by_key(|m| crate::model::parse_version(&m.name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn osu(id: u32, hash: Option<&str>) -> OsuFirmware {
        OsuFirmware {
            id,
            name: "x-osu".into(),
            perso: "perso_11".into(),
            firmware: "f".into(),
            firmware_key: "k".into(),
            hash: hash.map(str::to_owned),
            next_se_firmware_final_version: 0,
            previous_se_firmware_final_versions: vec![],
            notes: None,
            description: None,
            display_name: None,
        }
    }

    #[test]
    fn osu_hash_override() {
        // API value kept verbatim (case included) when not overridden.
        assert_eq!(osu(16, Some("AbCd")).expected_hash(), Some("AbCd"));
        assert_eq!(osu(16, None).expected_hash(), None);
        let api = "9E544503452b5810b42e6e715d4fe8ff3765f06758c78eefe3977e1949a1A009";
        assert_eq!(
            osu(56, Some(api)).expected_hash(),
            Some("9e54738f0235898098a1dbcefd9399380508d8e152d16652ccddf59bf317a009")
        );
    }
}
