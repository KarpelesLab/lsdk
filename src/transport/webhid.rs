//! WebHID transport for `wasm32` targets running in a browser.
//!
//! WebHID is only available in secure contexts (https or localhost) of
//! Chromium based browsers. [`WebHidTransport::request`] must be called from
//! a user gesture (click handler) as it opens the browser device picker.

use std::cell::Cell;
use std::rc::Rc;

use futures_channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use futures_util::StreamExt;
use futures_util::lock::Mutex;
use js_sys::{Array, Object, Promise, Reflect, Uint8Array};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::VENDOR_ID;
use crate::error::{Error, Result};
use crate::framing::{self, DEFAULT_CHANNEL, PACKET_SIZE};
use crate::model::DeviceModel;
use crate::transport::Transport;

#[wasm_bindgen]
extern "C" {
    /// The browser `HIDDevice` object.
    #[wasm_bindgen(js_name = HIDDevice)]
    #[derive(Clone, Debug)]
    pub type HidDevice;

    #[wasm_bindgen(method, getter)]
    pub fn opened(this: &HidDevice) -> bool;
    #[wasm_bindgen(method, getter, js_name = productId)]
    pub fn product_id(this: &HidDevice) -> u16;
    #[wasm_bindgen(method, getter, js_name = vendorId)]
    pub fn vendor_id(this: &HidDevice) -> u16;
    #[wasm_bindgen(method, getter, js_name = productName)]
    pub fn product_name(this: &HidDevice) -> String;
    #[wasm_bindgen(method)]
    fn open(this: &HidDevice) -> Promise;
    #[wasm_bindgen(method)]
    fn close(this: &HidDevice) -> Promise;
    #[wasm_bindgen(method, js_name = sendReport)]
    fn send_report(this: &HidDevice, report_id: u8, data: &Uint8Array) -> Promise;
    #[wasm_bindgen(method, js_name = addEventListener)]
    fn add_event_listener(this: &HidDevice, kind: &str, cb: &js_sys::Function);
    #[wasm_bindgen(method, js_name = removeEventListener)]
    fn remove_event_listener(this: &HidDevice, kind: &str, cb: &js_sys::Function);
}

fn js_err(e: JsValue) -> Error {
    let msg = e
        .dyn_ref::<js_sys::Error>()
        .map(|e| String::from(e.message()))
        .or_else(|| e.as_string())
        .unwrap_or_else(|| format!("{e:?}"));
    Error::Transport(msg)
}

fn hid_object() -> Result<JsValue> {
    let global = js_sys::global();
    let navigator = Reflect::get(&global, &"navigator".into()).map_err(js_err)?;
    let hid = Reflect::get(&navigator, &"hid".into()).map_err(js_err)?;
    if hid.is_undefined() || hid.is_null() {
        return Err(Error::Transport(
            "WebHID is not supported by this browser (use Chrome/Edge over https)".into(),
        ));
    }
    Ok(hid)
}

async fn call_hid(method: &str, args: &Array) -> Result<Vec<HidDevice>> {
    let hid = hid_object()?;
    let f: js_sys::Function = Reflect::get(&hid, &method.into())
        .map_err(js_err)?
        .dyn_into()
        .map_err(js_err)?;
    let p: Promise = f
        .apply(&hid, args)
        .map_err(js_err)?
        .dyn_into()
        .map_err(js_err)?;
    let list: Array = JsFuture::from(p)
        .await
        .map_err(js_err)?
        .dyn_into()
        .map_err(js_err)?;
    Ok(list
        .iter()
        .map(|d| d.unchecked_into::<HidDevice>())
        .collect())
}

/// Open the browser picker filtered on our vendor id. Requires a user gesture.
pub async fn request_devices() -> Result<Vec<HidDevice>> {
    let filter = Object::new();
    Reflect::set(&filter, &"vendorId".into(), &JsValue::from(VENDOR_ID)).map_err(js_err)?;
    let opts = Object::new();
    Reflect::set(&opts, &"filters".into(), &Array::of1(&filter)).map_err(js_err)?;
    call_hid("requestDevice", &Array::of1(&opts)).await
}

/// Devices the user already granted access to.
pub async fn granted_devices() -> Result<Vec<HidDevice>> {
    Ok(call_hid("getDevices", &Array::new())
        .await?
        .into_iter()
        .filter(|d| d.vendor_id() == VENDOR_ID)
        .collect())
}

type Packet = Result<Vec<u8>>;

/// WebHID transport.
pub struct WebHidTransport {
    device: HidDevice,
    rx: Mutex<UnboundedReceiver<Packet>>,
    on_report: Closure<dyn FnMut(JsValue)>,
    on_disconnect: Closure<dyn FnMut(JsValue)>,
    disconnected: Rc<Cell<bool>>,
    channel: u16,
}

impl WebHidTransport {
    /// Ask the user to pick a device, then open it.
    pub async fn request() -> Result<Self> {
        let dev = request_devices()
            .await?
            .into_iter()
            .next()
            .ok_or(Error::NoDevice)?;
        Self::open_device(dev).await
    }

    /// Open the first already-granted device (no picker), if any.
    pub async fn open_granted() -> Result<Self> {
        let dev = granted_devices()
            .await?
            .into_iter()
            .next()
            .ok_or(Error::NoDevice)?;
        Self::open_device(dev).await
    }

    /// Open a specific `HIDDevice`.
    pub async fn open_device(device: HidDevice) -> Result<Self> {
        if !device.opened() {
            JsFuture::from(device.open()).await.map_err(|e| match js_err(e) {
                Error::Transport(m) if m.contains("Failed to open") => Error::Transport(format!(
                    "{m} The OS denied access: close other wallet software using the device; on Linux, \
                     install udev rules granting access to USB vendor 2c97 (see the README), then replug it."
                )),
                e => e,
            })?;
        }
        let (tx, rx): (UnboundedSender<Packet>, _) = unbounded();
        let tx2 = tx.clone();
        let on_report = Closure::<dyn FnMut(JsValue)>::new(move |ev: JsValue| {
            let Ok(data) = Reflect::get(&ev, &"data".into()) else {
                return;
            };
            let Ok(view) = data.dyn_into::<js_sys::DataView>() else {
                return;
            };
            let bytes = Uint8Array::new_with_byte_offset_and_length(
                &view.buffer(),
                view.byte_offset() as u32,
                view.byte_length() as u32,
            )
            .to_vec();
            let _ = tx.unbounded_send(Ok(bytes));
        });
        device.add_event_listener("inputreport", on_report.as_ref().unchecked_ref());

        let disconnected = Rc::new(Cell::new(false));
        let flag = disconnected.clone();
        let me = device.clone();
        let on_disconnect = Closure::<dyn FnMut(JsValue)>::new(move |ev: JsValue| {
            let dev = Reflect::get(&ev, &"device".into()).unwrap_or(JsValue::UNDEFINED);
            if Object::is(&dev, &me) {
                flag.set(true);
                let _ = tx2.unbounded_send(Err(Error::Disconnected));
            }
        });
        if let Ok(hid) = hid_object()
            && let Ok(f) = Reflect::get(&hid, &"addEventListener".into())
            && let Ok(f) = f.dyn_into::<js_sys::Function>()
        {
            let _ = f.call2(&hid, &"disconnect".into(), on_disconnect.as_ref());
        }

        Ok(Self {
            device,
            rx: Mutex::new(rx),
            on_report,
            on_disconnect,
            disconnected,
            channel: DEFAULT_CHANNEL,
        })
    }

    /// Underlying `HIDDevice`.
    pub fn device(&self) -> &HidDevice {
        &self.device
    }

    /// USB product id.
    pub fn product_id(&self) -> u16 {
        self.device.product_id()
    }

    /// Device model deduced from the USB product id.
    pub fn model(&self) -> Option<DeviceModel> {
        DeviceModel::from_product_id(self.product_id())
    }

    /// Whether the device has been unplugged (or re-enumerated).
    pub fn is_disconnected(&self) -> bool {
        self.disconnected.get()
    }

    /// Close the device.
    pub async fn close(&self) -> Result<()> {
        if self.device.opened() {
            JsFuture::from(self.device.close()).await.map_err(js_err)?;
        }
        Ok(())
    }
}

impl Drop for WebHidTransport {
    fn drop(&mut self) {
        self.device
            .remove_event_listener("inputreport", self.on_report.as_ref().unchecked_ref());
        if let Ok(hid) = hid_object()
            && let Ok(f) = Reflect::get(&hid, &"removeEventListener".into())
            && let Ok(f) = f.dyn_into::<js_sys::Function>()
        {
            let _ = f.call2(&hid, &"disconnect".into(), self.on_disconnect.as_ref());
        }
        if self.device.opened() {
            let _ = self.device.close();
        }
    }
}

impl Transport for WebHidTransport {
    async fn exchange(&self, apdu: &[u8]) -> Result<Vec<u8>> {
        let mut rx = self.rx.lock().await;
        if self.disconnected.get() {
            return Err(Error::Disconnected);
        }
        // Drop anything stale.
        while let Ok(p) = rx.try_recv() {
            p?;
        }
        for packet in framing::encode(self.channel, apdu, PACKET_SIZE) {
            let arr = Uint8Array::from(packet.as_slice());
            JsFuture::from(self.device.send_report(0, &arr))
                .await
                .map_err(|e| {
                    if self.disconnected.get() {
                        Error::Disconnected
                    } else {
                        js_err(e)
                    }
                })?;
        }
        let mut decoder = framing::Decoder::new(self.channel);
        loop {
            let packet = rx.next().await.ok_or(Error::Disconnected)??;
            if let Some(resp) = decoder.push(&packet)? {
                return Ok(resp);
            }
        }
    }
}
