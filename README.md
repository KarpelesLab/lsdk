# lsdk

[![CI](https://github.com/KarpelesLab/lsdk/actions/workflows/ci.yml/badge.svg)](https://github.com/KarpelesLab/lsdk/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/lsdk.svg)](https://crates.io/crates/lsdk)
[![docs.rs](https://img.shields.io/docsrs/lsdk)](https://docs.rs/lsdk)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Web console](https://img.shields.io/badge/web%20console-GitHub%20Pages-0f766e.svg)](https://karpeleslab.github.io/lsdk/)

**Web console: <https://karpeleslab.github.io/lsdk/>** (Chrome / Edge, WebHID)

A Rust SDK and browser console for hardware wallets running the BOLOS
operating system (Nano S, Nano S Plus, Nano X, Stax, Flex, Nano Gen5), over
USB HID natively or through WebHID in the browser.

* **Detect** devices, read firmware / hardware / onboarding state
* **Genuine check**, **install / uninstall / update apps**, **firmware updates**
  (through the vendor HSM secure channel, over websocket)
* **List apps**, open / quit apps, rename, battery status, raw APDUs
* **App clients** to derive addresses, **generate transactions**
  (with [outscript](https://crates.io/crates/outscript)) and sign them on the
  device: Ethereum / EVM, Bitcoin (PSBT, wallet policies), Solana

This project is not affiliated with or endorsed by the device manufacturer.

## Web console

Live at **<https://karpeleslab.github.io/lsdk/>**.

The [`web/`](web) directory is a Vue app built on the wasm build of the crate.
It is deployed to GitHub Pages by [`.github/workflows/pages.yml`](.github/workflows/pages.yml).
It needs a Chromium based browser (WebHID).

Tabs: **Device** (info, genuine check, rename, battery), **Apps** (installed
apps, catalog, install / update / uninstall), **Firmware** (check and update),
**Advanced** (EVM, Bitcoin and Solana: addresses, build + sign + broadcast
transactions, message signing, PSBT signing; raw APDU console).

```sh
cd web
npm ci
npm run wasm    # wasm-pack build of the crate into web/src/pkg
npm run dev
```

## Rust crate

Everything is behind cargo features:

| Feature | Content |
|---|---|
| *(none)* | APDU types, HID framing, device models, `Transport` trait, dashboard commands (`Device`) |
| `hid` *(default)* | native USB transport (`hidapi`) |
| `webhid` | WebHID transport (`wasm32`) |
| `manager-api` | app catalog / firmware metadata HTTP client |
| `hsm` | HSM secure channel (websocket; tokio-tungstenite natively, `WebSocket` in the browser) |
| `manager` | genuine check, app install / uninstall, firmware update (`manager-api` + `hsm`) |
| `eth`, `btc`, `sol`, `apps` | app clients; transactions generated with outscript |
| `serde` | serde derives on public types |
| `full` | `hid` + `manager` + `apps` |
| `wasm` | JS bindings used by the web console |
| `cli` | the `lsdk` command line tool |

```rust
use lsdk::{Device, transport::hid::HidTransport, manager::Manager};

# async fn demo() -> lsdk::Result<()> {
let device = Device::new(HidTransport::open_first()?);
let version = device.get_version().await?;
println!("{:?} {}", version.model(), version.se_version);

let manager = Manager::default();
let genuine = manager.genuine_check(&device, &mut |ev| println!("{ev:?}")).await?;
manager.install_app_with_deps(&device, "Bitcoin", &mut |_, ev| println!("{ev:?}")).await?;
# Ok(()) }
```

The transport is a small trait, so other transports (BLE, emulator TCP...) can
be plugged in:

```rust
pub trait Transport {
    async fn exchange(&self, apdu: &[u8]) -> lsdk::Result<Vec<u8>>;
}
```

### Signing

```rust
use lsdk::apps::eth::{EthApp, EvmTx, EvmTxType, parse_units};

# async fn demo<T: lsdk::Transport>(device: &lsdk::Device<T>) -> lsdk::Result<()> {
let mut tx = EvmTx {
    tx_type: EvmTxType::Eip1559,
    chain_id: 1,
    nonce: 0,
    to: "0x...".into(),
    value: parse_units("0.01", 18)?,
    gas: 21_000,
    gas_tip_cap: parse_units("1", 9)?,
    gas_fee_cap: parse_units("30", 9)?,
    ..Default::default()
};
EthApp::new(device).sign_tx(&"m/44'/60'/0'/0/0".parse()?, &mut tx).await?;
let raw = tx.to_bytes(); // ready to broadcast
# Ok(()) }
```

Bitcoin: `BtcApp` handles the app's merkleized client-command protocol,
default and registered wallet policies, message signing and PSBT signing;
`apps::btc::psbt::build_psbt` builds a PSBT from UTXOs with outscript and
`finalize_and_extract` produces the network transaction. Addresses returned
by the device for default policies are checked against a local BIP-32
derivation.

## CLI

```sh
cargo install --path . --features cli
lsdk list
lsdk info
lsdk genuine
lsdk apps
lsdk install Bitcoin
lsdk firmware check
lsdk eth address --display
lsdk eth sign-tx --nonce 0 --to 0x... --value 0.01 --max-fee 30
lsdk btc address --kind taproot --display
lsdk sol transfer --to ... --amount 0.1 --blockhash ...
```

On Linux, access to the device needs udev rules granting access to USB
vendor `2c97`.

## Requirements

Rust 1.95+ (edition 2024). Native HID on Linux needs `libudev`.

## License

MIT, see [LICENSE](LICENSE). The Bitcoin client-command interpreter
(`src/apps/btc/merkle.rs`) is a port of the vendor's Apache-2.0 reference
client.
