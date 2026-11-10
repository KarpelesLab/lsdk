//! Websocket to the HSM, over rsurl (native sockets, or the browser's WebSocket).

use rsurl::aio::WsMessage;

use crate::error::{Error, Result};

#[cfg(not(target_arch = "wasm32"))]
type Sock = rsurl::aio::TokioWebSocket;
#[cfg(target_arch = "wasm32")]
type Sock = rsurl::aio::WebSocket;

pub(crate) struct WsConn {
    ws: Option<Sock>,
}

fn ws_err(e: impl core::fmt::Display) -> Error {
    Error::WebSocket(e.to_string())
}

impl WsConn {
    pub async fn connect(url: &str) -> Result<Self> {
        #[cfg(not(target_arch = "wasm32"))]
        let ws = Sock::connect(&rsurl::aio::TokioRuntime, url).await;
        #[cfg(target_arch = "wasm32")]
        let ws = Sock::connect(url).await;
        Ok(Self {
            ws: Some(ws.map_err(ws_err)?),
        })
    }

    /// Next text message, `None` when the connection is closed.
    pub async fn recv(&mut self) -> Result<Option<String>> {
        let Some(ws) = self.ws.as_mut() else {
            return Ok(None);
        };
        match ws.recv().await {
            Some(Ok(WsMessage::Text(t))) => Ok(Some(t)),
            Some(Ok(WsMessage::Binary(b))) => Ok(Some(String::from_utf8_lossy(&b).into_owned())),
            // The HSM may drop the socket without a closing handshake.
            Some(Err(_)) if ws.is_closed() => Ok(None),
            Some(Err(e)) => Err(ws_err(e)),
            None => Ok(None),
        }
    }

    pub async fn send(&mut self, text: String) -> Result<()> {
        let ws = self
            .ws
            .as_mut()
            .ok_or_else(|| Error::WebSocket("closed".into()))?;
        ws.send_text(&text).await.map_err(ws_err)
    }

    pub async fn close(&mut self) {
        if let Some(mut ws) = self.ws.take() {
            let _ = ws.close().await;
        }
    }
}
