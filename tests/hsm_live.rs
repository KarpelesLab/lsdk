//! Live check of the HSM websocket (network required): `cargo test --features full -- --ignored`.
#![cfg(all(feature = "hsm", not(target_arch = "wasm32")))]

use lsdk::hsm::{self, HsmEvent};
use lsdk::{Error, Transport};

struct Refuser(std::cell::RefCell<Vec<Vec<u8>>>);

impl Transport for Refuser {
    async fn exchange(&self, apdu: &[u8]) -> lsdk::Result<Vec<u8>> {
        self.0.borrow_mut().push(apdu.to_vec());
        Ok(vec![0x6d, 0x00])
    }
}

#[tokio::test]
#[ignore]
async fn genuine_handshake() {
    let url = hsm::build_url(
        hsm::DEFAULT_BASE_URL,
        "/genuine",
        &[("targetId", "856686596"), ("perso", "perso_11")],
    );
    let t = Refuser(Default::default());
    let mut events = Vec::new();
    let r = hsm::run(&t, &url, &mut |e: HsmEvent| events.push(format!("{e:?}"))).await;
    eprintln!(
        "result: {r:?}\nevents: {events:?}\napdus: {:?}",
        t.0.borrow().iter().map(hex::encode).collect::<Vec<_>>()
    );
    assert!(matches!(events.first().map(String::as_str), Some("Opened")));
    assert!(
        !t.0.borrow().is_empty(),
        "the HSM should have sent at least one APDU"
    );
    assert!(matches!(
        r,
        Err(Error::Status(_)) | Err(Error::Hsm(_)) | Err(Error::WebSocket(_))
    ));
}
