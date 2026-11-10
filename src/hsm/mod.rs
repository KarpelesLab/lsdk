//! Secure channel with the HSM ("scriptrunner") over a websocket.
//!
//! Genuine check, app install / uninstall and firmware updates are all driven
//! by the HSM: it opens a secure channel with the device and streams the APDUs
//! to run. The client only relays them:
//!
//! * `{"query":"exchange","nonce":n,"data":"<apdu hex>"}`: send the APDU,
//!   reply `{"nonce":n,"response":"success"|"error","data":"<resp hex>"}`
//! * `{"query":"bulk","data":["<apdu hex>",...]}`: close the socket and
//!   send every APDU to the device
//! * `{"query":"success","result":...}`: done, with an optional result
//! * `{"query":"error","data":"..."}` / `{"query":"warning","data":"..."}`

use serde::Deserialize;
use serde_json::Value;

use crate::apdu::{Response, StatusWord};
use crate::error::{Error, Result};
use crate::transport::Transport;

#[cfg(not(target_arch = "wasm32"))]
mod ws_native;
#[cfg(not(target_arch = "wasm32"))]
use ws_native::WsConn;

#[cfg(target_arch = "wasm32")]
mod ws_wasm;
#[cfg(target_arch = "wasm32")]
use ws_wasm::WsConn;

/// Default HSM websocket base URL.
pub const DEFAULT_BASE_URL: &str = "wss://scriptrunner.api.live.ledger.com/update";

/// Events reported while a secure channel session runs.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", rename_all = "camelCase"))]
pub enum HsmEvent {
    /// Websocket connected.
    Opened,
    /// The device is asking the user to allow the secure channel ("allow manager").
    PermissionRequested,
    /// The user allowed the secure channel.
    PermissionGranted,
    /// One APDU exchanged with the device on behalf of the HSM.
    Exchange {
        #[cfg_attr(feature = "serde", serde(serialize_with = "ser_hex"))]
        apdu: Vec<u8>,
        status: u16,
    },
    /// Bulk phase progress (`index` APDUs out of `total` sent).
    Progress { index: usize, total: usize },
    /// Warning from the HSM.
    Warning { message: String },
}

#[cfg(feature = "serde")]
fn ser_hex<S: serde::Serializer>(v: &[u8], s: S) -> core::result::Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(v))
}

impl HsmEvent {
    /// Progress in `0.0..=1.0`, for progress events.
    pub fn progress(&self) -> Option<f64> {
        match self {
            HsmEvent::Progress { index, total } if *total > 0 => {
                Some(*index as f64 / *total as f64)
            }
            _ => None,
        }
    }
}

#[derive(Deserialize)]
struct InMessage {
    query: String,
    #[serde(default)]
    nonce: Option<Value>,
    #[serde(default)]
    data: Option<Value>,
    #[serde(default)]
    result: Option<Value>,
}

/// Turn a device status met during a secure channel session into an error.
fn map_device_error(sw: StatusWord) -> Error {
    match sw.0 {
        _ if sw.is_refused() => Error::UserRefused,
        0x5515 => Error::Locked,
        0x6615 | 0x6616 => Error::App(format!(
            "the device refused a secure command ({sw}): make sure it is set up, unlocked \
             (PIN entered) and on the dashboard, then retry"
        )),
        0x6a84 | 0x5102 => Error::App("not enough space on the device".into()),
        _ => Error::Status(sw),
    }
}

/// Build an HSM URL: `base + path + ?k=v&...` (values percent-encoded).
pub fn build_url(base: &str, path: &str, params: &[(&str, &str)]) -> String {
    let mut url = format!("{}{}", base.trim_end_matches('/'), path);
    for (i, (k, v)) in params.iter().enumerate() {
        url.push(if i == 0 { '?' } else { '&' });
        url.push_str(&percent_encode(k));
        url.push('=');
        url.push_str(&percent_encode(v));
    }
    url
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Result of a secure channel session.
#[derive(Clone, Debug, Default)]
pub struct HsmOutcome {
    /// Payload of the final `success` message, if any.
    pub result: Option<Value>,
    /// Whether the session ended with a bulk phase.
    pub bulk: bool,
}

/// Run a secure channel session at `url`, relaying APDUs to `transport`.
pub async fn run<T: Transport + ?Sized>(
    transport: &T,
    url: &str,
    on_event: &mut dyn FnMut(HsmEvent),
) -> Result<HsmOutcome> {
    let mut ws = WsConn::connect(url).await?;
    on_event(HsmEvent::Opened);
    // An error from the device is only fatal if the HSM hangs up right after.
    let mut device_error: Option<Error> = None;

    loop {
        let Some(text) = ws.recv().await? else {
            return Err(device_error
                .unwrap_or_else(|| Error::WebSocket("connection closed unexpectedly".into())));
        };
        device_error = None;
        let msg: InMessage = serde_json::from_str(&text)
            .map_err(|e| Error::Hsm(format!("invalid message from HSM: {e}: {text}")))?;

        match msg.query.as_str() {
            "exchange" => {
                let data = msg
                    .data
                    .as_ref()
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let apdu =
                    hex::decode(data).map_err(|e| Error::Hsm(format!("bad APDU hex: {e}")))?;
                if apdu.len() < 5 {
                    return Err(Error::Hsm(format!("invalid APDU from HSM: {data}")));
                }
                let asks_permission = apdu[0] == 0xe0 && apdu[1] == 0x51;
                if asks_permission {
                    on_event(HsmEvent::PermissionRequested);
                }
                let resp = Response::from_raw(transport.exchange(&apdu).await?)?;
                on_event(HsmEvent::Exchange {
                    apdu,
                    status: resp.sw.0,
                });
                let response = match resp.sw {
                    StatusWord::OK => "success",
                    StatusWord::LOCKED_DEVICE => return Err(Error::Locked),
                    sw if asks_permission && sw.is_refused() => return Err(Error::UserRefused),
                    sw => {
                        device_error = Some(map_device_error(sw));
                        "error"
                    }
                };
                if asks_permission && resp.sw.is_ok() {
                    on_event(HsmEvent::PermissionGranted);
                }
                let reply = serde_json::json!({
                    "nonce": msg.nonce.unwrap_or(Value::Null),
                    "response": response,
                    "data": hex::encode(&resp.data),
                });
                ws.send(reply.to_string()).await?;
            }
            "bulk" => {
                ws.close().await;
                let list: Vec<Vec<u8>> = msg
                    .data
                    .as_ref()
                    .and_then(Value::as_array)
                    .ok_or_else(|| Error::Hsm("invalid bulk payload".into()))?
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(hex::decode)
                    .collect::<core::result::Result<_, _>>()
                    .map_err(|e| Error::Hsm(format!("bad bulk APDU hex: {e}")))?;
                let total = list.len();
                on_event(HsmEvent::Progress { index: 0, total });
                for (i, apdu) in list.iter().enumerate() {
                    let resp = Response::from_raw(transport.exchange(apdu).await?)?;
                    if !resp.sw.is_ok() {
                        return Err(map_device_error(resp.sw));
                    }
                    on_event(HsmEvent::Progress {
                        index: i + 1,
                        total,
                    });
                }
                return Ok(HsmOutcome {
                    result: None,
                    bulk: true,
                });
            }
            "success" => {
                let result = msg.result.or(msg.data).filter(|v| !v.is_null());
                ws.close().await;
                return Ok(HsmOutcome {
                    result,
                    bulk: false,
                });
            }
            "error" => {
                ws.close().await;
                let data = msg.data.map(|v| match v {
                    Value::String(s) => s,
                    v => v.to_string(),
                });
                return Err(Error::Hsm(data.unwrap_or_else(|| "unknown error".into())));
            }
            "warning" => {
                let message = msg.data.map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| v.to_string())
                });
                on_event(HsmEvent::Warning {
                    message: message.unwrap_or_default(),
                });
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url() {
        let u = build_url(
            DEFAULT_BASE_URL,
            "/install",
            &[
                ("targetId", "856686596"),
                ("firmware", "nanos+/1.4.1/app 1"),
            ],
        );
        assert_eq!(
            u,
            "wss://scriptrunner.api.live.ledger.com/update/install?targetId=856686596&firmware=nanos%2B%2F1.4.1%2Fapp%201"
        );
    }
}
