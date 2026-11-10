//! Scripted transport for tests and examples.

use std::cell::RefCell;
use std::collections::VecDeque;

use crate::error::{Error, Result};
use crate::transport::Transport;

/// A transport replaying a fixed list of `(expected_apdu, response)` pairs.
///
/// An empty expected APDU matches anything.
#[derive(Default)]
pub struct MockTransport {
    script: RefCell<VecDeque<(Vec<u8>, Vec<u8>)>>,
    log: RefCell<Vec<Vec<u8>>>,
}

impl MockTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue an expected APDU and its response (hex strings, response must include SW).
    pub fn expect(self, apdu_hex: &str, response_hex: &str) -> Self {
        self.script.borrow_mut().push_back((
            hex::decode(apdu_hex.replace(' ', "")).expect("bad apdu hex"),
            hex::decode(response_hex.replace(' ', "")).expect("bad response hex"),
        ));
        self
    }

    /// All APDUs sent so far.
    pub fn sent(&self) -> Vec<Vec<u8>> {
        self.log.borrow().clone()
    }

    /// Whether every scripted exchange was consumed.
    pub fn is_done(&self) -> bool {
        self.script.borrow().is_empty()
    }
}

impl Transport for MockTransport {
    async fn exchange(&self, apdu: &[u8]) -> Result<Vec<u8>> {
        self.log.borrow_mut().push(apdu.to_vec());
        let (expected, response) = self
            .script
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| Error::Transport(format!("unexpected APDU {}", hex::encode(apdu))))?;
        if !expected.is_empty() && expected != apdu {
            return Err(Error::Transport(format!(
                "APDU mismatch: expected {} got {}",
                hex::encode(expected),
                hex::encode(apdu)
            )));
        }
        Ok(response)
    }
}
