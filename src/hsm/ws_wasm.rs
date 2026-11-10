//! Browser websocket backend (`web_sys::WebSocket`).

use futures_channel::mpsc::{UnboundedReceiver, unbounded};
use futures_util::StreamExt;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use web_sys::{CloseEvent, MessageEvent, WebSocket};

use crate::error::{Error, Result};

enum WsEvent {
    Open,
    Message(String),
    Error,
    Close(String),
}

pub(crate) struct WsConn {
    ws: WebSocket,
    rx: UnboundedReceiver<WsEvent>,
    _handlers: [Closure<dyn FnMut(JsValue)>; 4],
    closed: bool,
}

impl WsConn {
    pub async fn connect(url: &str) -> Result<Self> {
        let ws = WebSocket::new(url).map_err(|e| Error::WebSocket(format!("{e:?}")))?;
        let (tx, rx) = unbounded();
        let t = tx.clone();
        let on_open = Closure::<dyn FnMut(JsValue)>::new(move |_| {
            let _ = t.unbounded_send(WsEvent::Open);
        });
        let t = tx.clone();
        let on_message = Closure::<dyn FnMut(JsValue)>::new(move |ev: JsValue| {
            if let Some(s) = ev.unchecked_into::<MessageEvent>().data().as_string() {
                let _ = t.unbounded_send(WsEvent::Message(s));
            }
        });
        let t = tx.clone();
        let on_error = Closure::<dyn FnMut(JsValue)>::new(move |_| {
            let _ = t.unbounded_send(WsEvent::Error);
        });
        let t = tx;
        let on_close = Closure::<dyn FnMut(JsValue)>::new(move |ev: JsValue| {
            let ev = ev.unchecked_into::<CloseEvent>();
            let _ = t.unbounded_send(WsEvent::Close(format!("code {} {}", ev.code(), ev.reason())));
        });
        ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));
        ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
        ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));
        ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));

        let mut conn = Self { ws, rx, _handlers: [on_open, on_message, on_error, on_close], closed: false };
        match conn.rx.next().await {
            Some(WsEvent::Open) => Ok(conn),
            Some(WsEvent::Close(r)) => Err(Error::WebSocket(format!("connection failed: {r}"))),
            _ => Err(Error::WebSocket(format!("connection to {url} failed"))),
        }
    }

    pub async fn recv(&mut self) -> Result<Option<String>> {
        if self.closed {
            return Ok(None);
        }
        loop {
            match self.rx.next().await {
                Some(WsEvent::Message(s)) => return Ok(Some(s)),
                Some(WsEvent::Open) => continue,
                Some(WsEvent::Error) => continue, // a close event follows
                Some(WsEvent::Close(_)) | None => {
                    self.closed = true;
                    return Ok(None);
                }
            }
        }
    }

    pub async fn send(&mut self, text: String) -> Result<()> {
        self.ws.send_with_str(&text).map_err(|e| Error::WebSocket(format!("{e:?}")))
    }

    pub async fn close(&mut self) {
        self.closed = true;
        let _ = self.ws.close();
    }
}

impl Drop for WsConn {
    fn drop(&mut self) {
        self.ws.set_onopen(None);
        self.ws.set_onmessage(None);
        self.ws.set_onerror(None);
        self.ws.set_onclose(None);
        let _ = self.ws.close();
    }
}
