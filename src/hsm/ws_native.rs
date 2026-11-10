//! Native websocket backend (tokio-tungstenite). Requires a tokio runtime.

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

use crate::error::{Error, Result};

pub(crate) struct WsConn {
    ws: Option<WebSocketStream<MaybeTlsStream<TcpStream>>>,
}

fn ws_err(e: impl core::fmt::Display) -> Error {
    Error::WebSocket(e.to_string())
}

impl WsConn {
    pub async fn connect(url: &str) -> Result<Self> {
        let (ws, _) = connect_async(url).await.map_err(ws_err)?;
        Ok(Self { ws: Some(ws) })
    }

    /// Next text message, `None` when the connection is closed.
    pub async fn recv(&mut self) -> Result<Option<String>> {
        let Some(ws) = self.ws.as_mut() else { return Ok(None) };
        while let Some(msg) = ws.next().await {
            match msg {
                Ok(Message::Text(t)) => return Ok(Some(t.to_string())),
                Ok(Message::Binary(b)) => return Ok(Some(String::from_utf8_lossy(&b).into_owned())),
                Ok(Message::Close(_)) => return Ok(None),
                Ok(_) => continue,
                Err(
                    tokio_tungstenite::tungstenite::Error::ConnectionClosed
                    | tokio_tungstenite::tungstenite::Error::AlreadyClosed
                    | tokio_tungstenite::tungstenite::Error::Protocol(
                        tokio_tungstenite::tungstenite::error::ProtocolError::ResetWithoutClosingHandshake,
                    ),
                ) => return Ok(None),
                Err(e) => return Err(ws_err(e)),
            }
        }
        Ok(None)
    }

    pub async fn send(&mut self, text: String) -> Result<()> {
        let ws = self.ws.as_mut().ok_or_else(|| Error::WebSocket("closed".into()))?;
        ws.send(Message::text(text)).await.map_err(ws_err)
    }

    pub async fn close(&mut self) {
        if let Some(mut ws) = self.ws.take() {
            let _ = ws.close(None).await;
        }
    }
}
