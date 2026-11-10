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
* **Genuine check**, online (vendor HSM) or **offline** (local attestation check), **install / uninstall / update apps**, **firmware updates**
  (through the vendor HSM secure channel, over websocket)
* **List apps**, open / quit apps, rename, battery status and charge limit,
  Bluetooth MAC, language packs, screensaver, raw APDUs
* **Dashboard secure channel**: custom CA (regular and Recover channels),
  **sideloading apps from their ELF**, memory info, delete apps, firmware hash;
  endorsement keys, host onboarding (test devices) and factory commands
* **App clients** to derive addresses, **generate transactions**
  (with [outscript](https://crates.io/crates/outscript)) and sign them on the
  device: Ethereum / EVM, Bitcoin (PSBT, wallet policies), Solana

> **About genuine checks:** a successful genuine check (online or offline)
> proves the secure element is authentic and its firmware unmodified. It does
> not prove the rest of the device is clean: extra hardware (a spy implant, a
> modified screen, USB or Bluetooth chip...) can sit next to a genuine secure
> element. Only a device bought directly from the manufacturer guarantees
> nothing was added.

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
| `attestation` | offline genuine check: device attestation verified locally against pinned issuer keys |
| `scp` | dashboard secure channel: secure commands, custom CA management |
| `loader` | app images from ELF / Intel HEX, sideloading through the secure channel |
| `recover` | self-hosted seed backup through the Recover protocol (3 shares, your CA as backup service) |
| `eth`, `btc`, `sol`, `apps` | app clients; transactions generated with outscript |
| `serde` | serde derives on public types |
| `full` | `hid` + `manager` + `apps` + `attestation` + `scp` + `loader` + `recover` |
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
lsdk genuine --offline        # no network: local attestation check
lsdk apps
lsdk install Bitcoin
lsdk firmware check
lsdk lang available | lsdk lang install french
lsdk endorse info 1 | lsdk endorse setup 1
lsdk firmware hash | lsdk app delete-all
lsdk eth address --display
lsdk eth sign-tx --nonce 0 --to 0x... --value 0.01 --max-fee 30
lsdk btc address --kind taproot --display
lsdk sol transfer --to ... --amount 0.1 --blockhash ...
```

### Sideloading apps (app development)

The device only installs apps from its vendor, or from a **custom CA** you
install once. With `lsdk`:

```sh
lsdk ca keygen                           # once: CA key in ~/.config/lsdk/ca.key (0600)
lsdk ca install --name "dev"             # once, with the device in recovery mode
lsdk app load build/nanos2/bin/app.elf   # after every build (replaces the previous one)
lsdk app list | lsdk app delete "My App" | lsdk meminfo
```

`app load` reads everything from the ELF built by the C or Rust SDK (name,
version, flags, API level, target id, NVRAM and install parameters sizes): no
manifest, no Python. The app's API level must match the firmware's (e.g.
API level 27 for Nano S Plus 1.7.0); `--dry-run` shows what would be sent.
Intel HEX files work too, with `--name`, `--flags`, `--api-level`,
`--data-size` and `--install-params-size`.

Recovery mode: hold the right button while plugging in (Nano S Plus) or
powering on (Nano X). `lsdk ca remove` deletes the CA.

### Self-hosted seed backup (Recover protocol)

The dashboard can split the seed into 3 encrypted shares (any 2 restore it)
for backup providers certified by a CA. With your own CA, you are the backup
service:

```sh
lsdk ca install --recover --name "backup CA"   # recovery mode; CA through the Recover channel
lsdk recover init --first-name John --last-name Doe --birth "1 January 1980"   # conf.json
lsdk recover backup -c conf.json -o shares/    # Backup_N.json + DeleteBackup_N.json
lsdk recover restore -c conf.json shares/Backup_1.json shares/Backup_2.json   # device: restore from backup
lsdk recover delete -c conf.json shares/DeleteBackup_*.json
lsdk ca remove --recover --name "backup CA"    # vendor app installs fail while a CA is set
```

Files use the formats of the vendor's legacy tooling. Shares are secrets:
store them encrypted and apart.

### Linux: udev rules

On Linux the device node is root-only by default; both the CLI and the
browser (WebHID) need a udev rule:

As root:

```sh
cat > /etc/udev/rules.d/20-hw1.rules <<'EOF'
SUBSYSTEMS=="usb", ATTRS{idVendor}=="2c97", MODE="0660", TAG+="uaccess", TAG+="udev-acl"
KERNEL=="hidraw*", ATTRS{idVendor}=="2c97", MODE="0660", TAG+="uaccess", TAG+="udev-acl"
EOF
udevadm control --reload-rules && udevadm trigger
```

Then replug the device. Without (e)logind seat management, use `MODE="0666"`.

## Requirements

Rust 1.95+ (edition 2024). Native HID on Linux needs `libudev`.

## License

MIT, see [LICENSE](LICENSE). The Bitcoin client-command interpreter
(`src/apps/btc/merkle.rs`) is a port of the vendor's Apache-2.0 reference
client.
