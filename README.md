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
  endorsement keys (your owner key, or vendor endorsement through the HSM),
  host onboarding (test devices) and factory commands
* **Legacy HW.1 / original Nano** (BTChip firmware): setup, PIN, addresses,
  message and P2PKH transaction signing with the keyboard confirmation
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
transactions, message signing, PSBT signing; raw APDU console; host onboarding
with known test phrases, for test devices only).

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
| `manager-api` | app catalog / firmware metadata HTTP client (rsurl) |
| `hsm` | HSM secure channel (websocket over [rsurl](https://crates.io/crates/rsurl): its own sockets and TLS natively, `WebSocket` in the browser) |
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
lsdk endorse info 1 | lsdk endorse setup 1   # or --vendor (see below)
lsdk firmware hash | lsdk app delete-all
lsdk eth address --display
lsdk eth sign-tx --nonce 0 --to 0x... --value 0.01 --max-fee 30
lsdk btc address --kind taproot --display
lsdk sol transfer --to ... --amount 0.1 --blockhash ...
```

> **Vendor endorsement (`endorse setup --vendor`)** runs the vendor HSM's
> `/endorse` script (as `endorsementSetupLedger2.py` does). It did not work
> as of 2026-11. On a Stax (SE 1.6.2, `perso_11`, `attest_1`) the HSM
> opened the secure channel and had the device create the slot key, but then
> sent a commit **without a certificate**. A Nano S Plus (SE 1.7.0) and a
> Nano X (SE 2.8.0), both on their latest firmware, got the same empty commit,
> on both slots (in recovery mode the HSM hung up earlier, right after the
> secure channel was allowed). lsdk refuses
> to forward an empty commit, because the device
> would store the empty certificate and keep the slot unusable until
> `lsdk endorse reset`. The `attest_1` owner key was reportedly removed at
> some point, which would explain the empty certificate. On devices whose vendor certificate is checked against the root
> CA (seen on a Stax), vendor HSM sessions are refused while a custom CA is
> installed.

### Sideloading apps (app development)

The device only installs apps from its vendor, or from a **custom CA** you
install once. With `lsdk`:

```sh
lsdk ca keygen                           # once: CA key in ~/.config/lsdk/ca.key (0600)
lsdk ca install --name "dev"             # once, with the device in recovery mode (Recover channel)
lsdk ca install --name "dev" --regular   # firmware older than Ledger Recover (answers 0x650e)
lsdk app load build/nanos2/bin/app.elf   # after every build (replaces the previous one)
lsdk app list | lsdk app delete "My App" | lsdk meminfo
```

`app load` reads everything from the ELF built by the C or Rust SDK (name,
version, flags, API level, target id, NVRAM and install parameters sizes): no
manifest, no Python. The app's API level must match the firmware's (e.g.
API level 27 for Nano S Plus 1.7.0); `--dry-run` shows what would be sent.
Intel HEX files work too, with `--name`, `--flags`, `--api-level`,
`--data-size` and `--install-params-size`. Firmware older than API levels (e.g.
Nano S Plus 1.0.x, which answers 0x6512) needs `--legacy-layout`: CREATE APP
without the API level byte.

Recovery mode: hold the right button while plugging in (Nano S Plus) or
powering on (Nano X). `lsdk ca remove --recover --name "dev"` deletes the CA
(name and key must match the installed CA).

### Self-hosted seed backup (Recover protocol)

The dashboard can split the seed into 3 encrypted shares (any 2 restore it)
for backup providers certified by a CA. With your own CA, you are the backup
service:

```sh
lsdk ca install --name "backup CA"             # recovery mode
lsdk recover init --first-name John --last-name Doe --birth "1 January 1980"   # conf.json
lsdk recover backup -c conf.json -o shares/    # Backup_N.json + DeleteBackup_N.json
lsdk recover restore -c conf.json shares/Backup_1.json shares/Backup_2.json   # device: restore from backup
lsdk recover delete -c conf.json shares/DeleteBackup_*.json
lsdk ca remove --recover --name "backup CA"    # vendor app installs fail while a CA is set
```

Files use the formats of the vendor's legacy tooling. The device encrypts the
seed with a key common to all devices before splitting it, so shares can only
be restored through a device; still keep them private and apart.

**Restoring:** setting the PIN during onboarding erases the custom CA, so:
wipe the device, onboard it (PIN, then "restore from a backup"), reboot into
recovery mode, `lsdk ca install`, then `lsdk recover restore` while still in
recovery mode (the restore step survives the reboot), and `lsdk ca remove
--recover` afterwards. The PIN may differ from the one used at backup time.

### HW.1 / original Nano (BTChip)

The 2014-2015 dongles (USB vendor `2581`) run the BTChip firmware: no screen,
no apps, legacy Base58 (P2PKH) addresses only. The PIN is typed on the
computer, and operations are confirmed by unplugging the dongle: plugged into a
computer with a text editor focused, it **types** a summary and a one-time
code, then goes back and the code is entered. **3 wrong PINs erase it.**

```sh
lsdk hw1 info                                    # firmware, setup state, PIN attempts, attestation
lsdk hw1 setup --pin 1234                        # new / wiped dongle: it generates and types its seed
lsdk hw1 setup --pin 1111 --words "..." --i-understand-the-seed-travels-over-usb   # test devices
lsdk hw1 address --pin 1234 --path "44'/0'/0'/0/0"
lsdk hw1 sign-message --pin 1234 "message"       # asks for the typed code
lsdk hw1 sign-tx --pin 1234 --input PREV_TX_HEX_OR_FILE:VOUT:PATH --to 1... --amount 50000 --fee 1000
```

`sign-tx` prints the signed transaction; nothing is broadcast. The web console
shows a dedicated HW.1 view when one is connected.

```sh
lsdk hw1 update --dry-run          # read the dongle, fetch and check the files
lsdk hw1 update --erase            # update to OS 1.0.4 (erases a set-up dongle first)
```

The update replays Ledger's signed images from its Chrome wallet repository
(pinned commit, each file checked against a pinned SHA-256) through the
dongle's bootloader, rebooting a few times. A dongle set up on a firmware
older than 1.1.0 is erased first with wrong PINs: replug it when asked. After a
dry run in bootloader mode, replug the dongle before updating (reading the
bootloader version leaves it accepting only the load commands).

### Linux: udev rules

On Linux the device node is root-only by default; both the CLI and the
browser (WebHID) need a udev rule:

As root:

```sh
cat > /etc/udev/rules.d/20-hw1.rules <<'EOF'
SUBSYSTEMS=="usb", ATTRS{idVendor}=="2c97", MODE="0660", TAG+="uaccess", TAG+="udev-acl"
KERNEL=="hidraw*", ATTRS{idVendor}=="2c97", MODE="0660", TAG+="uaccess", TAG+="udev-acl"
SUBSYSTEMS=="usb", ATTRS{idVendor}=="2581", MODE="0660", TAG+="uaccess", TAG+="udev-acl"
KERNEL=="hidraw*", ATTRS{idVendor}=="2581", MODE="0660", TAG+="uaccess", TAG+="udev-acl"
EOF
udevadm control --reload-rules && udevadm trigger
```

Then replug the device. Without (e)logind seat management, use `MODE="0666"`.

When the hidraw node isn't accessible but the USB device node is (for
instance, you are in a group that owns `/dev/bus/usb`), the native transport
falls back to raw USB through usbfs, using [rawusb](https://crates.io/crates/rawusb).
It detaches the kernel HID driver from the interface while in use and re-attaches
it when the transport is dropped. `lsdk --usbfs …` (or `HidTransport::open_usbfs`)
forces this path. The browser always needs the hidraw rule.

## Requirements

Rust 1.95+ (edition 2024). Native HID on Linux needs `libudev`.

## License

MIT, see [LICENSE](LICENSE). The Bitcoin client-command interpreter
(`src/apps/btc/merkle.rs`) is a port of the vendor's Apache-2.0 reference
client.
