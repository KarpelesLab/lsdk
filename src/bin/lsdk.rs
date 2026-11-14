//! `lsdk` command line tool.

use std::io::Write;
use std::time::Duration;

use clap::{Parser, Subcommand};
use lsdk::apps::{btc, eth, sol};
use lsdk::btchip;
use lsdk::hsm::HsmEvent;
use lsdk::manager::Manager;
use lsdk::path::DerivationPath;
use lsdk::transport::hid::HidTransport;
use lsdk::transport::tcp::TcpTransport;
use lsdk::{Device, Error, Result};
use serde::Serialize;

#[derive(Parser)]
#[command(
    name = "lsdk",
    version,
    about = "Manage and use hardware wallets over USB HID"
)]
struct Cli {
    /// Device path (from `lsdk list`); defaults to the first device.
    #[arg(long, global = true)]
    device: Option<String>,
    /// Linux: talk to the device over raw USB (usbfs) instead of hidraw. Used
    /// automatically when hidraw access is denied.
    #[cfg(target_os = "linux")]
    #[arg(long, global = true)]
    usbfs: bool,
    /// Talk to a device over TCP (Speculos's APDU protocol, e.g. Speculos or
    /// ledger_console) at host:port instead of USB.
    #[arg(long, global = true)]
    tcp: Option<String>,
    /// Manager API base URL.
    #[arg(long, global = true, default_value = lsdk::manager::api::DEFAULT_BASE_URL)]
    api: String,
    /// HSM websocket base URL.
    #[arg(long, global = true, default_value = lsdk::hsm::DEFAULT_BASE_URL)]
    hsm: String,
    #[command(subcommand)]
    cmd: Cmd,
}

impl Cli {
    /// The usbfs note is only worth printing when the fallback kicked in.
    fn usbfs_quiet(&self) -> bool {
        #[cfg(target_os = "linux")]
        return self.usbfs;
        #[cfg(not(target_os = "linux"))]
        false
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// List connected devices.
    List,
    /// Firmware, app and device information.
    Info,
    /// Installed apps (asks for consent on the device).
    Apps,
    /// App catalog for the connected device (or a given target id / version).
    Catalog {
        #[arg(long)]
        target_id: Option<String>,
        #[arg(long)]
        version: Option<String>,
    },
    /// Genuine check (through the vendor HSM, or --offline).
    Genuine {
        /// Verify the device attestation locally against pinned issuer keys,
        /// without contacting the vendor (the device asks to allow an
        /// insecure manager connection).
        #[arg(long)]
        offline: bool,
        /// Extra trusted issuer public key (hex, uncompressed), repeatable.
        #[arg(long = "issuer-key")]
        issuer_keys: Vec<String>,
    },
    /// Install an app (and its parent app if needed).
    Install { name: String },
    /// Uninstall an app.
    Uninstall { name: String },
    /// Open an app.
    Open { name: String },
    /// Quit the running app.
    Quit,
    /// Device name (asks for consent on the device).
    Name,
    /// Rename the device.
    Rename { name: String },
    /// Battery status.
    Battery,
    /// Restart the dashboard.
    Reset,
    /// Bluetooth MAC address.
    Mac,
    /// Set the battery charge limit (percent).
    ChargeLimit { percent: u8 },
    /// Language packs.
    Lang {
        #[command(subcommand)]
        cmd: LangCmd,
    },
    /// Endorsement (user attestation keys).
    Endorse {
        #[command(subcommand)]
        cmd: EndorseCmd,
    },
    /// Onboard from the host (test devices: the seed travels over USB).
    Onboard {
        /// main, alternate or temporary
        #[arg(long, default_value = "main")]
        identity: String,
        #[arg(long, default_value = "")]
        pin: String,
        /// Recovery phrase (empty to reuse the main one for alternate identities).
        #[arg(long, default_value = "")]
        words: String,
        #[arg(long, default_value = "")]
        passphrase: String,
        /// Seed derivation prefix (empty = BIP-39 "mnemonic").
        #[arg(long, default_value = "")]
        prefix: String,
        /// Required: acknowledges the PIN and phrase are sent in clear over USB.
        #[arg(long)]
        i_understand_the_seed_travels_over_usb: bool,
    },
    /// Self-hosted seed backup through the Recover protocol (your CA as backup service).
    Recover {
        #[command(subcommand)]
        cmd: RecoverCmd,
    },
    /// Factory commands (devices not yet personalized only).
    Factory {
        #[command(subcommand)]
        cmd: FactoryCmd,
    },
    /// Custom certificate authority (needed to sideload apps).
    Ca {
        #[command(subcommand)]
        cmd: CaCmd,
    },
    /// Sideload / manage apps through the secure channel.
    App {
        #[command(subcommand)]
        cmd: AppCmd,
    },
    /// Memory usage (secure channel).
    Meminfo {
        /// Root key file (defaults to the CA key if present, else a random key).
        #[arg(long)]
        key: Option<std::path::PathBuf>,
    },
    /// Custom screensaver (Nano X / Nano S Plus, recovery mode only).
    Screensaver {
        #[command(subcommand)]
        cmd: ScreensaverCmd,
    },
    /// Firmware update.
    Firmware {
        #[command(subcommand)]
        cmd: FirmwareCmd,
    },
    /// Send a raw APDU (hex).
    Apdu { hex: String },
    /// Ethereum app.
    Eth {
        #[command(subcommand)]
        cmd: EthCmd,
    },
    /// Bitcoin app.
    Btc {
        #[command(subcommand)]
        cmd: BtcCmd,
    },
    /// Solana app.
    Sol {
        #[command(subcommand)]
        cmd: SolCmd,
    },
    /// Legacy HW.1 / original Nano (BTChip firmware, USB vendor 0x2581).
    Hw1 {
        #[command(subcommand)]
        cmd: Hw1Cmd,
    },
}

#[derive(Subcommand)]
enum Hw1Cmd {
    /// Firmware, setup state, PIN attempts and attestation.
    Info,
    /// First setup of a new or wiped dongle. Without --words the dongle
    /// generates a seed and types it (as a keyboard) on later power-ups
    /// until the PIN is entered: have a text editor focused.
    Setup {
        /// PIN, 4 to 32 characters (sent in clear: that's how this device works).
        #[arg(long)]
        pin: String,
        /// Restore this BIP-39 phrase instead (test devices: it travels in clear).
        #[arg(long)]
        words: Option<String>,
        /// BIP-39 passphrase for --words.
        #[arg(long, default_value = "")]
        passphrase: String,
        /// Secondary PIN (up to 4 characters) opening a random decoy wallet.
        #[arg(long)]
        secondary_pin: Option<String>,
        /// Bitcoin testnet address versions.
        #[arg(long)]
        testnet: bool,
        /// Required with --words: acknowledges the phrase is sent in clear over USB.
        #[arg(long)]
        i_understand_the_seed_travels_over_usb: bool,
    },
    /// Public key and Base58 address of a path.
    Address {
        #[arg(long, default_value = "44'/0'/0'/0/0")]
        path: String,
        #[arg(long)]
        pin: String,
    },
    /// Sign a message (ASCII, up to 140 characters; keyboard confirmation).
    SignMessage {
        #[arg(long, default_value = "44'/0'/0'/0/0")]
        path: String,
        #[arg(long)]
        pin: String,
        message: String,
    },
    /// Update the firmware (to OS 1.0.4) through the bootloader, with Ledger's
    /// signed images from its Chrome app repository (checked against pinned
    /// hashes). A set-up dongle on firmware < 1.1.0 is erased first.
    Update {
        /// Only read the dongle and fetch the files: show what would be sent.
        #[arg(long)]
        dry_run: bool,
        /// Allow erasing a set-up dongle (its seed and PIN): have its recovery phrase.
        #[arg(long)]
        erase: bool,
        /// Read the firmware files from this directory (`app/firmwares` of
        /// ledger-wallet-chrome) instead of downloading them.
        #[arg(long)]
        firmware_dir: Option<std::path::PathBuf>,
    },
    /// Sign a P2PKH transaction to one address, change back to --change-path.
    /// Prints the signed transaction (hex); nothing is broadcast.
    SignTx {
        #[arg(long)]
        pin: String,
        /// Input to spend: RAW_TX_HEX_OR_FILE:VOUT:PATH (repeat for more).
        #[arg(long = "input", required = true)]
        inputs: Vec<String>,
        /// Destination (Base58 address).
        #[arg(long)]
        to: String,
        /// Amount in satoshis.
        #[arg(long)]
        amount: u64,
        /// Fee in satoshis.
        #[arg(long)]
        fee: u64,
        #[arg(long, default_value = "44'/0'/0'/1/0")]
        change_path: String,
    },
}

#[derive(Subcommand)]
enum LangCmd {
    /// Packs available for this firmware.
    Available,
    /// Installed packs.
    List,
    /// Install a pack (e.g. french); replaces the installed one.
    Install { language: String },
    /// Remove the installed packs (back to English).
    Remove,
    /// Install a pack from its signed APDU script file.
    InstallFile { file: std::path::PathBuf },
}

#[derive(Subcommand)]
enum EndorseCmd {
    /// Show the endorsement key of a slot (1 or 2).
    Info { slot: u8 },
    /// Create the slot key and certify it (your owner key, or --vendor).
    Setup {
        slot: u8,
        /// Owner private key file (default: the lsdk CA key).
        #[arg(long)]
        owner_key: Option<std::path::PathBuf>,
        /// Use this DER certificate (hex) instead of signing with the owner key.
        #[arg(long)]
        certificate: Option<String>,
        /// Have the vendor HSM certify the key instead (vendor endorsement).
        #[arg(long, conflicts_with_all = ["owner_key", "certificate"])]
        vendor: bool,
        /// Vendor endorsement owner key reference (with --vendor).
        #[arg(long, requires = "vendor", default_value = "attest_1")]
        vendor_key: String,
    },
    /// Erase the endorsement keys (secure channel, confirmed on device).
    Reset {
        #[arg(long)]
        key: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
enum RecoverCmd {
    /// Create a configuration (identity + fresh orchestrator / provider keys).
    Init {
        #[arg(long)]
        first_name: String,
        #[arg(long)]
        last_name: String,
        /// Date of birth, as it should appear on the device.
        #[arg(long)]
        birth: String,
        #[arg(long, default_value = "")]
        city: String,
        #[arg(long, default_value = "lsdk backup")]
        name: String,
        #[arg(short, long, default_value = "conf.json")]
        output: std::path::PathBuf,
    },
    /// Back up the seed into 3 shares (Backup_N.json + DeleteBackup_N.json).
    Backup {
        #[arg(short, long, default_value = "conf.json")]
        config: std::path::PathBuf,
        /// CA private key file (default: the lsdk CA key).
        #[arg(long)]
        ca: Option<std::path::PathBuf>,
        /// Output directory.
        #[arg(short, long, default_value = ".")]
        output: std::path::PathBuf,
    },
    /// Restore the seed from 2 or 3 Backup_N.json files (device onboarding: restore from backup).
    Restore {
        #[arg(short, long, default_value = "conf.json")]
        config: std::path::PathBuf,
        #[arg(long)]
        ca: Option<std::path::PathBuf>,
        backups: Vec<std::path::PathBuf>,
    },
    /// Delete backups (DeleteBackup_N.json files).
    Delete {
        #[arg(short, long, default_value = "conf.json")]
        config: std::path::PathBuf,
        #[arg(long)]
        ca: Option<std::path::PathBuf>,
        files: Vec<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
enum FactoryCmd {
    /// FACTORY_TEST with raw P1, P2 and data (hex).
    Test {
        p1: String,
        #[arg(default_value = "0")]
        p2: String,
        #[arg(default_value = "")]
        data: String,
    },
    /// GET_DEVICE_PUBLIC_KEY (personalization).
    PublicKey,
    /// GET_CXPORT.
    Cxport,
}

#[derive(Subcommand)]
enum CaCmd {
    /// Generate the CA key (stored in the lsdk config directory).
    Keygen {
        /// Overwrite an existing key.
        #[arg(long)]
        force: bool,
        #[arg(long)]
        key: Option<std::path::PathBuf>,
    },
    /// Show the CA public key.
    Show {
        #[arg(long)]
        key: Option<std::path::PathBuf>,
    },
    /// Install the CA on the device (recovery mode, confirmed on device).
    Install {
        /// Name shown by the device when the CA connects.
        #[arg(long, default_value = "lsdk dev")]
        name: String,
        /// CA key file (default: the lsdk CA key).
        #[arg(long)]
        key: Option<std::path::PathBuf>,
        /// Install this public key (hex) instead of the key file's.
        #[arg(long)]
        public: Option<String>,
        /// Use the regular secure channel instead of the Recover one: firmware
        /// older than Ledger Recover (e.g. Nano S Plus 1.0.x answers 0x650e).
        #[arg(long)]
        regular: bool,
    },
    /// Remove the custom CA from the device (recovery mode, confirmed on device).
    Remove {
        /// Use the Recover secure channel (needs the installed CA name and key).
        #[arg(long)]
        recover: bool,
        #[arg(long, default_value = "lsdk dev")]
        name: String,
        #[arg(long)]
        key: Option<std::path::PathBuf>,
        #[arg(long)]
        public: Option<String>,
    },
}

#[derive(Subcommand)]
enum AppCmd {
    /// Install an app from its ELF (or Intel HEX with --name and friends).
    Load {
        file: std::path::PathBuf,
        /// CA key file (default: the lsdk CA key).
        #[arg(long)]
        key: Option<std::path::PathBuf>,
        /// Keep an installed app with the same name (fails if present).
        #[arg(long)]
        no_replace: bool,
        /// Only print what would be installed.
        #[arg(long)]
        dry_run: bool,
        /// Sign the app hash with the CA key (or --sign-key) at commit.
        #[arg(long)]
        sign: bool,
        /// Key file to sign the app with (implies --sign).
        #[arg(long)]
        sign_key: Option<std::path::PathBuf>,
        /// HEX input: app name.
        #[arg(long)]
        name: Option<String>,
        /// HEX input: app flags (e.g. 0x200).
        #[arg(long)]
        flags: Option<String>,
        /// HEX input: API level.
        #[arg(long)]
        api_level: Option<u8>,
        /// HEX input: NVRAM data size.
        #[arg(long)]
        data_size: Option<u32>,
        /// HEX input: install parameters size.
        #[arg(long)]
        install_params_size: Option<u32>,
        /// Old CREATE APP layout, without the API level byte: firmware older
        /// than API levels (e.g. Nano S Plus 1.0.x, which answers 0x6512).
        #[arg(long)]
        legacy_layout: bool,
        /// Firmware before 1.4 (e.g. Nano S 1.3.x): dashboard icon, hex
        /// (`icon.py <gif> hexbitmaponly`). Defaults to the icon of the
        /// install parameters, if any.
        #[arg(long)]
        icon: Option<String>,
    },
    /// Delete an app by name (or --hash).
    Delete {
        name: String,
        /// Treat NAME as the app's full hash (hex).
        #[arg(long)]
        hash: bool,
        #[arg(long)]
        key: Option<std::path::PathBuf>,
    },
    /// Delete every app (confirmed on device).
    DeleteAll {
        #[arg(long)]
        key: Option<std::path::PathBuf>,
    },
    /// List apps through the secure channel.
    List {
        #[arg(long)]
        key: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
enum ScreensaverCmd {
    /// Show the current setting.
    Get,
    /// Set a custom scrolling text (1-52 printable ASCII characters).
    Set {
        text: String,
        /// classic, circle-rl, circle-lr
        #[arg(long, default_value = "classic")]
        animation: String,
        /// fast, normal, slow
        #[arg(long, default_value = "normal")]
        speed: String,
    },
    /// Restore the default screensaver.
    Reset,
}

#[derive(Subcommand)]
enum FirmwareCmd {
    /// Check whether an update is available.
    Check,
    /// Install the latest firmware (OSU, then MCU if needed).
    Update,
    /// Device stuck in bootloader mode: flash the MCU its firmware needs.
    Repair,
    /// Firmware integrity hash (vendor HSM sessions only: refused with a custom CA).
    Hash {
        #[arg(long)]
        key: Option<std::path::PathBuf>,
        /// Start address (hex).
        #[arg(long, default_value = "0")]
        address: String,
        /// Length (hex).
        #[arg(long, default_value = "0")]
        length: String,
    },
}

#[derive(Subcommand)]
enum EthCmd {
    /// Show an address.
    Address {
        #[arg(long, default_value = eth::DEFAULT_PATH)]
        path: String,
        #[arg(long)]
        display: bool,
    },
    /// Build and sign a transaction (EIP-1559 unless --gas-price is given).
    SignTx {
        #[arg(long, default_value = eth::DEFAULT_PATH)]
        path: String,
        #[arg(long, default_value_t = 1)]
        chain_id: u64,
        #[arg(long)]
        nonce: u64,
        #[arg(long)]
        to: String,
        /// Amount in ETH (or in token units with --token).
        #[arg(long, default_value = "0")]
        value: String,
        #[arg(long, default_value_t = 21000)]
        gas: u64,
        /// Max fee per gas, in gwei.
        #[arg(long)]
        max_fee: Option<String>,
        /// Priority fee per gas, in gwei.
        #[arg(long, default_value = "1")]
        priority_fee: String,
        /// Legacy gas price in gwei (legacy transaction).
        #[arg(long)]
        gas_price: Option<String>,
        /// Calldata hex.
        #[arg(long)]
        data: Option<String>,
        /// ERC-20 token contract: send `value` tokens to `to`.
        #[arg(long)]
        token: Option<String>,
        #[arg(long, default_value_t = 18)]
        decimals: u32,
    },
    /// Sign an unsigned raw transaction (hex).
    SignRaw {
        #[arg(long, default_value = eth::DEFAULT_PATH)]
        path: String,
        hex: String,
    },
    /// personal_sign a message.
    SignMessage {
        #[arg(long, default_value = eth::DEFAULT_PATH)]
        path: String,
        message: String,
    },
}

#[derive(Subcommand)]
enum BtcCmd {
    /// Account xpub.
    Xpub {
        #[arg(long, default_value = "segwit")]
        kind: String,
        #[arg(long, default_value_t = 0)]
        account: u32,
        #[arg(long)]
        testnet: bool,
        #[arg(long)]
        display: bool,
    },
    /// Receive / change address.
    Address {
        #[arg(long, default_value = "segwit")]
        kind: String,
        #[arg(long, default_value_t = 0)]
        account: u32,
        #[arg(long, default_value_t = 0)]
        index: u32,
        #[arg(long)]
        change: bool,
        #[arg(long)]
        testnet: bool,
        #[arg(long)]
        display: bool,
    },
    /// Sign a message.
    SignMessage {
        #[arg(long, default_value = "m/84'/0'/0'/0/0")]
        path: String,
        message: String,
    },
    /// Sign a PSBT (base64) with a default single-sig account.
    SignPsbt {
        #[arg(long, default_value = "segwit")]
        kind: String,
        #[arg(long, default_value_t = 0)]
        account: u32,
        #[arg(long)]
        testnet: bool,
        /// Output the signed PSBT instead of the finalized transaction.
        #[arg(long)]
        no_finalize: bool,
        psbt: String,
    },
}

#[derive(Subcommand)]
enum SolCmd {
    /// Show an address.
    Address {
        #[arg(long, default_value = sol::DEFAULT_PATH)]
        path: String,
        #[arg(long)]
        display: bool,
    },
    /// Build and sign a SOL transfer.
    Transfer {
        #[arg(long, default_value = sol::DEFAULT_PATH)]
        path: String,
        #[arg(long)]
        to: String,
        /// Amount in SOL.
        #[arg(long)]
        amount: String,
        #[arg(long)]
        blockhash: String,
    },
}

const GENUINE_NOTE: &str = "A successful genuine check proves the secure element is authentic and its firmware unmodified. It does not prove the rest of the device is clean: extra hardware (a spy implant, a modified screen, USB or Bluetooth chip...) can sit next to a genuine secure element. Only a device bought directly from the manufacturer guarantees nothing was added.";

fn print<T: Serialize>(v: &T) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}

fn progress(ev: HsmEvent) {
    match ev {
        HsmEvent::PermissionRequested => eprintln!("> allow the secure connection on the device"),
        HsmEvent::PermissionGranted => eprintln!("> secure connection allowed"),
        HsmEvent::Progress { index, total } => {
            eprint!("\r> {index}/{total}");
            if index == total {
                eprintln!();
            }
            let _ = std::io::stderr().flush();
        }
        HsmEvent::Warning { message } => eprintln!("> warning: {message}"),
        // LSDK_DEBUG=1: log the APDUs the HSM sends through us.
        HsmEvent::Exchange { apdu, status } if std::env::var_os("LSDK_DEBUG").is_some() => {
            eprintln!("> hsm apdu {} -> {status:04x}", hex::encode(&apdu));
        }
        _ => {}
    }
}

/// The transport `open` picked: USB HID, or TCP with `--tcp`.
enum Link {
    Hid(HidTransport),
    Tcp(TcpTransport),
}

impl Link {
    fn product(&self) -> Option<String> {
        match self {
            Link::Hid(t) => t.info().product.clone(),
            Link::Tcp(_) => None,
        }
    }

    /// Legacy HW.1 / original Nano (never over TCP).
    fn legacy(&self) -> bool {
        matches!(self, Link::Hid(t) if t.info().legacy)
    }
}

impl lsdk::Transport for Link {
    async fn exchange(&self, apdu: &[u8]) -> Result<Vec<u8>> {
        match self {
            Link::Hid(t) => t.exchange(apdu).await,
            Link::Tcp(t) => t.exchange(apdu).await,
        }
    }
}

fn open(cli: &Cli) -> Result<Device<Link>> {
    if let Some(addr) = &cli.tcp {
        return Ok(Device::new(Link::Tcp(TcpTransport::connect(
            addr.as_str(),
        )?)));
    }
    let list = HidTransport::list()?;
    let info = match &cli.device {
        Some(path) => list.into_iter().find(|d| &d.path == path),
        None => list.into_iter().next(),
    }
    .ok_or(Error::NoDevice)?;
    #[cfg(target_os = "linux")]
    let t = if cli.usbfs {
        HidTransport::open_usbfs(&info)?
    } else {
        HidTransport::open(&info)?
    };
    #[cfg(not(target_os = "linux"))]
    let t = HidTransport::open(&info)?;
    if t.backend() == "usbfs" && !cli.usbfs_quiet() {
        eprintln!("note: {} is not accessible, using raw USB", info.path);
    }
    Ok(Device::new(Link::Hid(t)))
}

/// Unlock a HW.1 with --pin, refusing to burn the last attempt blindly.
async fn hw1_unlock<T: lsdk::Transport>(w: &btchip::BtchipWallet<'_, T>, pin: &str) -> Result<()> {
    match w.pin_attempts().await? {
        None => {
            return Err(Error::App(
                "the dongle is not set up: run `lsdk hw1 setup` first".into(),
            ));
        }
        Some(n) if n < 3 => {
            eprintln!("> warning: {n} PIN attempt(s) left before the dongle erases itself")
        }
        _ => {}
    }
    w.verify_pin(pin).await.map(|_| ())
}

/// Keyboard confirmation: the user power cycles the dongle, which types a
/// summary and a code, then plugs it back. Returns the code and the reopened
/// device.
fn hw1_confirm(cli: &Cli, c: &btchip::Confirmation) -> Result<(String, Device<Link>)> {
    if c.kind != 0x01 {
        return Err(Error::App(format!(
            "confirmation type 0x{:02x} (security card / secure screen) is not supported, only keyboard confirmation",
            c.kind
        )));
    }
    eprintln!("> confirmation needed:");
    eprintln!(
        "  1. unplug the dongle and open a text editor (ideally on another computer), cursor in it"
    );
    eprintln!(
        "  2. plug the dongle in: it types a summary of the operation and a 4-digit code - check the summary"
    );
    eprintln!("  3. plug the dongle back into this computer, then type the code here");
    eprint!("code: ");
    let _ = std::io::stderr().flush();
    let mut code = String::new();
    std::io::stdin()
        .read_line(&mut code)
        .map_err(|e| Error::InvalidInput(e.to_string()))?;
    let code = code.trim().to_string();
    if code.is_empty() {
        return Err(Error::UserRefused);
    }
    // Wait for the dongle to be back.
    let start = std::time::Instant::now();
    loop {
        if let Ok(d) = open(cli) {
            return Ok((code, d));
        }
        if start.elapsed() > Duration::from_secs(60) {
            return Err(Error::NoDevice);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Wait for a legacy dongle (any mode) and open it. Returns the device and
/// whether it is in bootloader mode.
async fn hw1_open_any(cli: &Cli, wait: Duration) -> Result<(Device<HidTransport>, bool)> {
    use lsdk::framing::{LegacyFraming, legacy_framing};
    let start = std::time::Instant::now();
    let info = loop {
        let found = HidTransport::list()?
            .into_iter()
            .find(|d| match &cli.device {
                Some(p) => &d.path == p,
                None => d.legacy,
            });
        if let Some(i) = found {
            break i;
        }
        if start.elapsed() > wait {
            return Err(Error::NoDevice);
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    // Give a freshly enumerated dongle a moment.
    std::thread::sleep(Duration::from_millis(300));
    let open = |plain: bool, timeout: u64| -> Result<Device<HidTransport>> {
        let mut t = HidTransport::open(&info)?;
        t.set_plain(plain);
        t.set_timeout(Some(Duration::from_secs(timeout)));
        Ok(Device::new(t))
    };
    match legacy_framing(info.product_id) {
        Some(LegacyFraming::Plain) if info.product_id == 0x1807 => Ok((open(true, 10)?, true)),
        Some(LegacyFraming::Plain) => Ok((open(true, 10)?, false)),
        _ => {
            // 0x3b7c: the OS (channel framing) or a bootloader (plain framing).
            // Retried: a dongle that just enumerated may not answer yet.
            let mut last = String::new();
            for _ in 0..4 {
                let os = {
                    let d = open(false, 2)?;
                    // Any status (even 0x6faa, halted) means the OS framing works.
                    match btchip::BtchipWallet::new(&d).firmware().await {
                        Ok(_) | Err(Error::Status(_)) => {
                            drop(d);
                            return Ok((open(false, 10)?, false));
                        }
                        Err(e) => e,
                    }
                };
                let d = open(true, 2)?;
                match lsdk::btchip_update::is_bootloader(&d).await {
                    Ok(true) => {
                        drop(d);
                        return Ok((open(true, 10)?, true));
                    }
                    Ok(false) => last = format!("OS probe: {os}; bootloader probe: OS reply"),
                    Err(e) => last = format!("OS probe: {os}; bootloader probe: {e}"),
                }
                drop(d);
                std::thread::sleep(Duration::from_millis(700));
            }
            Err(Error::App(format!(
                "the dongle answers neither as an OS nor as a bootloader ({last})"
            )))
        }
    }
}

/// Wait for the dongle to go away (reboot or unplug).
fn hw1_wait_gone(cli: &Cli, wait: Duration) -> Result<()> {
    let start = std::time::Instant::now();
    while HidTransport::list()?
        .iter()
        .any(|d| cli.device.as_ref().map_or(d.legacy, |p| &d.path == p))
    {
        if start.elapsed() > wait {
            return Err(Error::Timeout);
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    Ok(())
}

async fn hw1_script(dir: &Option<std::path::PathBuf>, name: &str) -> Result<Vec<Vec<u8>>> {
    use lsdk::btchip_update::{fetch_script, load_script};
    match dir {
        Some(d) => {
            let p = d.join(format!("btchipfirmware-{name}.js"));
            let text = std::fs::read_to_string(&p)
                .map_err(|e| Error::InvalidInput(format!("{}: {e}", p.display())))?;
            load_script(name, &text)
        }
        None => fetch_script(name).await,
    }
}

/// Erase a set-up dongle with wrong PINs (it erases itself after 3). After
/// each wrong PIN the dongle answers 0x6faa (halted) until it is replugged.
async fn hw1_erase(cli: &Cli) -> Result<()> {
    let mut asked = false;
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() > Duration::from_secs(30 * 60) {
            return Err(Error::Timeout);
        }
        let (d, bootloader) = match hw1_open_any(cli, Duration::from_secs(5)).await {
            Ok(x) => x,
            Err(Error::NoDevice) => continue,
            Err(e) => return Err(e),
        };
        if bootloader {
            return Ok(());
        }
        let w = btchip::BtchipWallet::new(&d);
        let left = match w.pin_attempts().await {
            Err(Error::Timeout) | Err(Error::Status(lsdk::StatusWord(0x6faa))) => {
                if !asked {
                    eprintln!("> unplug the dongle and plug it back");
                    asked = true;
                }
                drop(d);
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
            r => r?,
        };
        let Some(left) = left else {
            eprintln!("> the dongle is erased");
            return Ok(());
        };
        // Two digits: never a valid PIN (4 to 32 characters).
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.subsec_nanos())
            .unwrap_or(0)
            % 100;
        let _ = w.verify_pin(&format!("{n:02}")).await;
        eprintln!("> wrong PIN sent ({left} attempt(s) were left)");
        asked = false;
    }
}

async fn hw1_update(
    cli: &Cli,
    dry_run: bool,
    erase: bool,
    dir: &Option<std::path::PathBuf>,
) -> Result<()> {
    use lsdk::btchip_update::{
        Step, bootloader_info, is_slow_bootloader, plan_bootloader, plan_os, run_script,
        version_string,
    };
    let mut os_loaded = false;
    for _ in 0..12 {
        let (d, bootloader) = hw1_open_any(cli, Duration::from_secs(90)).await?;
        let (steps, slow) = if bootloader {
            let info = bootloader_info(&d).await?;
            eprintln!(
                "> bootloader {}, customer id {:04x}",
                version_string(info.version),
                info.customer_id
            );
            (vec![plan_bootloader(&info)?], is_slow_bootloader(&info))
        } else {
            let w = btchip::BtchipWallet::new(&d);
            let halted = |e: &Error| matches!(e, Error::Status(sw) if sw.0 == 0x6faa);
            let (fw, set_up) = match async {
                let fw = w.firmware().await?;
                let set_up = w.operation_mode().await?.is_some();
                Ok::<_, Error>((fw, set_up))
            }
            .await
            {
                // Halted after a wrong PIN: an erase in progress.
                Err(e) if halted(&e) && erase && !dry_run => {
                    drop(d);
                    hw1_erase(cli).await?;
                    continue;
                }
                Err(e) if halted(&e) => {
                    return Err(Error::App(
                        "the dongle is halted after a wrong PIN: unplug it and plug it back".into(),
                    ));
                }
                r => r?,
            };
            let (a, b, c) = lsdk::model::parse_version(&fw.version);
            eprintln!(
                "> OS {} (architecture 0x{:02x}), {}",
                fw.version,
                fw.architecture,
                if set_up { "set up" } else { "not set up" }
            );
            let steps = plan_os(
                (fw.architecture, lsdk::btchip_update::v(a, b, c)),
                set_up,
                os_loaded,
            )?;
            (steps, false)
        };
        if dry_run {
            for s in &steps {
                match s.file() {
                    Some(f) => {
                        let apdus = hw1_script(dir, f).await?;
                        eprintln!("> would send {f} ({} APDUs, hash checked)", apdus.len());
                    }
                    None => eprintln!("> {s:?}"),
                }
            }
            if bootloader {
                eprintln!(
                    "> note: the bootloader now only accepts the load commands; replug the dongle before running the update"
                );
            } else if steps.iter().any(Step::reboots) {
                eprintln!(
                    "> then, after the reboot into the bootloader: the bootloader reloader, bootloader or OS image matching its customer id"
                );
            }
            println!("dry run: nothing was written");
            return Ok(());
        }
        for step in steps {
            match &step {
                Step::UpToDate => {
                    println!(
                        "firmware {} is up to date",
                        version_string(lsdk::btchip_update::LATEST_OS.1)
                    );
                    return Ok(());
                }
                Step::Erase => {
                    if !erase {
                        return Err(Error::App(
                            "the dongle is set up: updating erases its seed and PIN first; pass --erase (keep its recovery phrase)"
                                .into(),
                        ));
                    }
                    drop(d);
                    hw1_erase(cli).await?;
                    break;
                }
                _ => {
                    let name = step.file().unwrap_or_default().to_string();
                    let apdus = hw1_script(dir, &name).await?;
                    let mut progress = |i: usize, n: usize| {
                        eprint!("\r> {name}: {i}/{n}");
                        if i == n {
                            eprintln!();
                        }
                        let _ = std::io::stderr().flush();
                    };
                    run_script(&d, &apdus, step.options(slow), &mut progress).await?;
                    if matches!(step, Step::LoadOs(_)) {
                        os_loaded = true;
                    }
                    if matches!(step, Step::InitOs(_)) {
                        println!(
                            "updated to {}: set it up again (lsdk hw1 setup)",
                            version_string(lsdk::btchip_update::LATEST_OS.1)
                        );
                        return Ok(());
                    }
                    if step.reboots() {
                        eprintln!("> the dongle reboots...");
                        drop(d);
                        // It may re-enumerate faster than we poll.
                        let _ = hw1_wait_gone(cli, Duration::from_secs(10));
                        break;
                    }
                }
            }
        }
    }
    Err(Error::App(
        "the update did not finish after 12 steps".into(),
    ))
}

/// `RAW_TX_HEX_OR_FILE:VOUT:PATH`.
fn hw1_input(s: &str) -> Result<btchip::SpendInput> {
    let mut it = s.rsplitn(3, ':');
    let (path_s, vout, tx_s) = match (it.next(), it.next(), it.next()) {
        (Some(p), Some(v), Some(t)) => (p, v, t),
        _ => {
            return Err(Error::InvalidInput(format!(
                "input \"{s}\": expected RAW_TX_HEX_OR_FILE:VOUT:PATH"
            )));
        }
    };
    let raw = match std::fs::read_to_string(tx_s) {
        Ok(t) => t,
        Err(_) => tx_s.to_string(),
    };
    let raw = hex::decode(raw.trim())
        .map_err(|e| Error::InvalidInput(format!("input transaction hex: {e}")))?;
    Ok(btchip::SpendInput {
        prev_tx: btchip::Tx::parse(&raw)?,
        vout: vout
            .parse()
            .map_err(|_| Error::InvalidInput(format!("bad output index {vout}")))?,
        path: path(path_s)?,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Hw1Info {
    family: &'static str,
    product: Option<String>,
    firmware: btchip::FirmwareInfo,
    set_up: bool,
    operation_mode: Option<u8>,
    pin_attempts: Option<u8>,
    attestation: Option<btchip::Attestation>,
}

async fn hw1_info(d: &Device<Link>) -> Result<Hw1Info> {
    let w = btchip::BtchipWallet::new(d);
    let firmware = w.firmware().await?;
    let operation_mode = w.operation_mode().await?;
    let pin_attempts = w.pin_attempts().await?;
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_nanos())
        .unwrap_or(0)
        ^ u128::from(std::process::id());
    let mut blob = [0u8; 8];
    blob.copy_from_slice(&seed.to_le_bytes()[..8]);
    Ok(Hw1Info {
        family: "BTChip (HW.1 / Nano 2014)",
        product: d.transport().product(),
        set_up: operation_mode.is_some(),
        firmware,
        operation_mode,
        pin_attempts,
        attestation: w.attestation(blob).await.ok(),
    })
}

fn path(s: &str) -> Result<DerivationPath> {
    s.parse()
}

fn wei(gwei: &str) -> Result<num_bigint::BigInt> {
    eth::parse_units(gwei, 9)
}

#[derive(Serialize)]
struct Info {
    version: lsdk::os::OsVersion,
    model: Option<&'static str>,
    app: Option<lsdk::os::AppAndVersion>,
}

async fn run(cli: Cli) -> Result<()> {
    let manager = Manager::new(cli.api.clone(), cli.hsm.clone());
    match &cli.cmd {
        Cmd::List => print(&HidTransport::list()?),
        Cmd::Info => {
            let d = open(&cli)?;
            if d.transport().legacy() {
                print(&hw1_info(&d).await?);
                return Ok(());
            }
            let app = d.get_app_and_version().await.ok();
            if let Some(a) = app.as_ref().filter(|a| !a.is_dashboard()) {
                print(a);
                eprintln!("(app {} is open: quit it to see firmware details)", a.name);
                return Ok(());
            }
            let version = d.get_version().await?;
            print(&Info {
                model: version.model().map(|m| m.name()),
                version,
                app,
            });
        }
        Cmd::Apps => print(&manager.installed_apps(&open(&cli)?).await?),
        Cmd::Catalog { target_id, version } => {
            let apps = match (target_id, version) {
                (Some(t), Some(v)) => {
                    let t = if let Some(h) = t.strip_prefix("0x") {
                        u32::from_str_radix(h, 16)
                    } else {
                        t.parse()
                    }
                    .map_err(|_| Error::InvalidInput("bad target id".into()))?;
                    manager.api.get_apps_by_target(t, v, 1).await?
                }
                _ => manager.catalog(&open(&cli)?.get_version().await?).await?,
            };
            let mut out = std::io::stdout().lock();
            for a in apps {
                let line = format!(
                    "{:<32} {:<10} {:>8} {}",
                    a.version_name,
                    a.version,
                    a.bytes.unwrap_or(0),
                    a.hash
                );
                if writeln!(out, "{line}").is_err() {
                    break;
                }
            }
        }
        Cmd::Genuine {
            offline: true,
            issuer_keys,
        } => {
            let extra = issuer_keys
                .iter()
                .enumerate()
                .map(|(i, k)| {
                    hex::decode(k.trim_start_matches("0x"))
                        .map(|b| (format!("--issuer-key #{}", i + 1), b))
                        .map_err(|e| Error::InvalidInput(format!("issuer key: {e}")))
                })
                .collect::<Result<Vec<_>>>()?;
            let att = lsdk::attestation::offline_genuine_check(&open(&cli)?, &extra, &mut |ev| {
                use lsdk::attestation::AttestationEvent::*;
                match ev {
                    PermissionRequested { host_public_key } => eprintln!(
                        "> the device shows this manager key, check it matches, then allow:\n  {host_public_key}"
                    ),
                    PermissionGranted => eprintln!("> allowed"),
                    Attesting => eprintln!("> device is signing its attestation..."),
                }
            })
            .await?;
            print(&att);
            println!(
                "{}",
                if att.genuine {
                    "genuine (offline attestation)"
                } else {
                    "NOT VERIFIED"
                }
            );
            if att.genuine {
                eprintln!("note: {GENUINE_NOTE}");
            }
            if !att.genuine {
                std::process::exit(2);
            }
        }
        Cmd::Genuine { .. } => {
            let ok = manager.genuine_check(&open(&cli)?, &mut progress).await?;
            println!("{}", if ok { "genuine" } else { "NOT GENUINE" });
            if ok {
                eprintln!("note: {GENUINE_NOTE}");
            }
            if !ok {
                std::process::exit(2);
            }
        }
        Cmd::Install { name } => {
            manager
                .install_app_with_deps(&open(&cli)?, name, None, &mut |app, ev| {
                    if matches!(ev, HsmEvent::Opened) {
                        eprintln!("installing {app}");
                    }
                    progress(ev)
                })
                .await?;
            println!("installed {name}");
        }
        Cmd::Uninstall { name } => {
            manager
                .uninstall_app_by_name(&open(&cli)?, name, &mut progress)
                .await?;
            println!("uninstalled {name}");
        }
        Cmd::Open { name } => open(&cli)?.open_app(name).await?,
        Cmd::Quit => open(&cli)?.quit_app().await?,
        Cmd::Name => println!("{}", open(&cli)?.get_device_name().await?),
        Cmd::Rename { name } => open(&cli)?.set_device_name(name).await?,
        Cmd::Reset => {
            open(&cli)?.reset().await?;
            println!("dashboard reset");
        }
        Cmd::Mac => println!("{}", open(&cli)?.get_device_mac().await?),
        Cmd::ChargeLimit { percent } => {
            open(&cli)?.set_battery_charge_limit(*percent).await?;
            println!("charge limit set to {percent}%");
        }
        Cmd::Lang { cmd } => {
            let d = open(&cli)?;
            match cmd {
                LangCmd::Available => {
                    let os = d.get_version().await?;
                    for p in manager.language_packs(&os).await? {
                        println!(
                            "{:<12} {:<8} {:>6} bytes",
                            p.language,
                            p.version,
                            p.bytes.unwrap_or(0)
                        );
                    }
                }
                LangCmd::List => {
                    for p in d.list_language_packs().await? {
                        println!(
                            "{} ({}) {} bytes",
                            lsdk::os::language_name(p.id),
                            p.id,
                            p.size
                        );
                    }
                }
                LangCmd::Install { language } => {
                    let os = d.get_version().await?;
                    let pack = manager
                        .language_packs(&os)
                        .await?
                        .into_iter()
                        .find(|p| p.language.eq_ignore_ascii_case(language))
                        .ok_or_else(|| {
                            Error::NotFound(format!("no {language} pack for this firmware"))
                        })?;
                    eprintln!("> confirm on the device if asked");
                    manager
                        .install_language_pack(&d, &pack, &mut |i, n| {
                            eprint!("\r> {i}/{n}");
                            if i == n {
                                eprintln!();
                            }
                        })
                        .await?;
                    println!("{} {} installed", pack.language, pack.version);
                }
                LangCmd::InstallFile { file } => {
                    let script = std::fs::read_to_string(file)
                        .map_err(|e| Error::InvalidInput(format!("{}: {e}", file.display())))?;
                    eprintln!("> confirm on the device if asked");
                    d.install_language_script(&script, &mut |i, n| {
                        eprint!("\r> {i}/{n}");
                        if i == n {
                            eprintln!();
                        }
                    })
                    .await?;
                    println!("language pack installed");
                }
                LangCmd::Remove => {
                    manager.remove_language_packs(&d).await?;
                    println!("language packs removed");
                }
            }
        }
        Cmd::Endorse { cmd } => {
            use lsdk::os::EndorsementSlot;
            let slot = |n: u8| match n {
                1 => Ok(EndorsementSlot::Slot1),
                2 => Ok(EndorsementSlot::Slot2),
                _ => Err(Error::InvalidInput("slot must be 1 or 2".into())),
            };
            let d = open(&cli)?;
            match cmd {
                EndorseCmd::Reset { key } => {
                    let root = root_key(key.as_ref())?;
                    let mut chan =
                        lsdk::scp::SecureChannel::open(&d, &root, &mut scp_progress).await?;
                    eprintln!("> confirm on the device");
                    chan.reset_endorsement().await?;
                    println!("endorsement reset");
                }
                EndorseCmd::Info { slot: n } => print(&d.endorsement_info(slot(*n)?).await?),
                EndorseCmd::Setup {
                    slot: n,
                    vendor: true,
                    vendor_key,
                    ..
                } => {
                    let result = manager
                        .vendor_endorse(&d, slot(*n)?, Some(vendor_key), &mut progress)
                        .await?;
                    if let Some(r) = result.filter(|r| !r.is_null()) {
                        eprintln!("HSM result: {r}");
                    }
                    print(&d.endorsement_info(slot(*n)?).await?);
                    println!("slot {n} endorsed by the vendor");
                }
                EndorseCmd::Setup {
                    slot: n,
                    owner_key,
                    certificate,
                    ..
                } => {
                    let (public, _device_sig) = d.endorse_start(slot(*n)?).await?;
                    eprintln!("endorsement key: {}", hex::encode(&public));
                    let cert = match certificate {
                        Some(c) => hex::decode(c.trim_start_matches("0x"))
                            .map_err(|e| Error::InvalidInput(e.to_string()))?,
                        None => {
                            let owner =
                                read_key(&owner_key.clone().unwrap_or_else(default_ca_path))?;
                            lsdk::scp::endorsement_certificate(&owner, &public)?
                        }
                    };
                    d.endorse_commit(&cert).await?;
                    println!("slot {n} endorsed, certificate {}", hex::encode(&cert));
                }
            }
        }
        Cmd::Onboard {
            identity,
            pin,
            words,
            passphrase,
            prefix,
            i_understand_the_seed_travels_over_usb,
        } => {
            use lsdk::os::OnboardIdentity;
            if !i_understand_the_seed_travels_over_usb {
                return Err(Error::InvalidInput(
                    "host onboarding sends the PIN and recovery phrase in clear over USB; \
                     pass --i-understand-the-seed-travels-over-usb (test devices only)"
                        .into(),
                ));
            }
            let id = match identity.as_str() {
                "main" => OnboardIdentity::Main,
                "alternate" => OnboardIdentity::Alternate,
                "temporary" => OnboardIdentity::Temporary,
                _ => {
                    return Err(Error::InvalidInput(
                        "identity: main, alternate or temporary".into(),
                    ));
                }
            };
            eprintln!(
                "> onboarding (no confirmation on a wiped device); it can take a few minutes: keep it plugged in"
            );
            match open(&cli)?
                .onboard(id, pin, prefix, passphrase, words)
                .await
            {
                Ok(()) => {}
                // The device re-enumerates once the PIN is entered, while it
                // derives the seed: reopen it and collect its answer.
                Err(Error::Disconnected | Error::Transport(_)) => {
                    eprintln!("> device re-enumerated, waiting for it to finish processing...");
                    std::thread::sleep(Duration::from_secs(1));
                    let t = HidTransport::wait_and_open(Duration::from_secs(120))?;
                    let raw = t.read_pending_response(Duration::from_secs(180))?;
                    let r = lsdk::Response::from_raw(raw)?;
                    match r.sw {
                        lsdk::StatusWord::OK => {}
                        sw if sw.is_refused() => return Err(Error::UserRefused),
                        sw => return Err(sw.into()),
                    }
                }
                Err(e) => return Err(e),
            }
            println!("onboarded ({identity})");
        }
        Cmd::Recover { cmd } => {
            use lsdk::recover::{self, RecoverConfig, RecoverEvent, UserInfo};
            let read_json = |p: &std::path::Path| -> Result<serde_json::Value> {
                let s = std::fs::read_to_string(p)
                    .map_err(|e| Error::InvalidInput(format!("{}: {e}", p.display())))?;
                serde_json::from_str(&s)
                    .map_err(|e| Error::InvalidInput(format!("{}: {e}", p.display())))
            };
            let load_conf = |p: &std::path::Path| -> Result<RecoverConfig> {
                serde_json::from_value(read_json(p)?)
                    .map_err(|e| Error::InvalidInput(format!("{}: {e}", p.display())))
            };
            let mut events = |ev: RecoverEvent| match ev {
                RecoverEvent::Channel { event } => scp_progress(event),
                RecoverEvent::Provider { name } => eprintln!("> provider {name}"),
                RecoverEvent::ConfirmOnDevice => {
                    eprintln!("> check the identity shown on the device and confirm")
                }
                RecoverEvent::ShareVerified { name } => eprintln!("> {name}: done"),
            };
            let hint = |e: Error| match e {
                Error::Status(sw) if (sw.0 >> 8) == 0x55 || sw.0 == 0x6982 => Error::App(format!(
                    "{e}: is the CA installed? (lsdk ca install, in recovery mode)"
                )),
                e => e,
            };
            match cmd {
                RecoverCmd::Init {
                    first_name,
                    last_name,
                    birth,
                    city,
                    name,
                    output,
                } => {
                    let conf = RecoverConfig::generate(
                        UserInfo {
                            first_name: first_name.clone(),
                            last_name: last_name.clone(),
                            birth: birth.clone(),
                            city: city.clone(),
                        },
                        name,
                    )?;
                    std::fs::write(
                        output,
                        serde_json::to_string_pretty(&conf).unwrap_or_default(),
                    )
                    .map_err(|e| Error::App(format!("{}: {e}", output.display())))?;
                    println!(
                        "configuration written to {} (keep it secret: it holds the provider keys)",
                        output.display()
                    );
                }
                RecoverCmd::Backup { config, ca, output } => {
                    let conf = load_conf(config)?;
                    let ca = read_key(&ca.clone().unwrap_or_else(default_ca_path))?;
                    let d = open(&cli)?;
                    let backups = recover::backup(&d, &ca, &conf, &mut events)
                        .await
                        .map_err(hint)?;
                    std::fs::create_dir_all(output).map_err(|e| Error::App(e.to_string()))?;
                    for b in &backups {
                        let write = |file: String, v: serde_json::Value| {
                            let p = output.join(file);
                            std::fs::write(&p, serde_json::to_string_pretty(&v).unwrap_or_default())
                                .map_err(|e| Error::App(format!("{}: {e}", p.display())))
                        };
                        write(format!("{}.json", b.provider), b.backup_json())?;
                        write(format!("Delete{}.json", b.provider), b.delete_json())?;
                    }
                    println!(
                        "{} shares written to {} (encrypt them before storing them)",
                        backups.len(),
                        output.display()
                    );
                }
                RecoverCmd::Restore {
                    config,
                    ca,
                    backups,
                } => {
                    let conf = load_conf(config)?;
                    let ca = read_key(&ca.clone().unwrap_or_else(default_ca_path))?;
                    let mut shares = std::collections::BTreeMap::new();
                    for p in backups {
                        let v: std::collections::BTreeMap<String, recover::ShareBackup> =
                            serde_json::from_value(read_json(p)?)
                                .map_err(|e| Error::InvalidInput(e.to_string()))?;
                        shares.extend(v);
                    }
                    let d = open(&cli)?;
                    recover::restore(&d, &ca, &conf, &shares, &mut events)
                        .await
                        .map_err(hint)?;
                    println!("seed restored from {} shares", shares.len());
                }
                RecoverCmd::Delete { config, ca, files } => {
                    let conf = load_conf(config)?;
                    let ca = read_key(&ca.clone().unwrap_or_else(default_ca_path))?;
                    let mut keys = std::collections::BTreeMap::new();
                    for p in files {
                        let v: std::collections::BTreeMap<String, serde_json::Value> =
                            serde_json::from_value(read_json(p)?)
                                .map_err(|e| Error::InvalidInput(e.to_string()))?;
                        for (name, entry) in v {
                            let pk = entry["public_key"].as_str().unwrap_or_default().to_string();
                            keys.insert(name, pk);
                        }
                    }
                    let d = open(&cli)?;
                    recover::delete(&d, &ca, &conf, &keys, &mut events)
                        .await
                        .map_err(hint)?;
                    println!("{} backups deleted", keys.len());
                }
            }
        }
        Cmd::Factory { cmd } => {
            let d = open(&cli)?;
            let num = |s: &str| {
                u8::from_str_radix(s.trim_start_matches("0x"), 16)
                    .map_err(|e| Error::InvalidInput(e.to_string()))
            };
            let out = match cmd {
                FactoryCmd::Test { p1, p2, data } => {
                    let data = hex::decode(data).map_err(|e| Error::InvalidInput(e.to_string()))?;
                    d.factory_test(num(p1)?, num(p2)?, &data).await?
                }
                FactoryCmd::PublicKey => d.factory_get_device_public_key().await?,
                FactoryCmd::Cxport => d.factory_get_cxport().await?,
            };
            println!("{}", hex::encode(out));
        }
        Cmd::Ca { cmd } => {
            match cmd {
                CaCmd::Keygen { force, key } => {
                    let path = key.clone().unwrap_or_else(default_ca_path);
                    if path.exists() && !force {
                        return Err(Error::InvalidInput(format!(
                            "{} exists (use --force to replace it)",
                            path.display()
                        )));
                    }
                    let k = lsdk::scp::RootKey::generate()?;
                    write_key(&path, &k)?;
                    println!("CA key written to {}", path.display());
                    println!("public key: {}", hex::encode(k.public_key()));
                }
                CaCmd::Show { key } => {
                    let k = read_key(&key.clone().unwrap_or_else(default_ca_path))?;
                    println!("{}", hex::encode(k.public_key()));
                }
                CaCmd::Install {
                    name,
                    key,
                    public,
                    regular,
                } => {
                    let public = match public {
                        Some(p) => hex::decode(p.trim_start_matches("0x"))
                            .map_err(|e| Error::InvalidInput(e.to_string()))?,
                        None => read_key(&key.clone().unwrap_or_else(default_ca_path))?
                            .public_key()
                            .to_vec(),
                    };
                    let d = open(&cli)?;
                    // Any root key works here: the device asks to allow it. The
                    // Recover channel by default: recent firmware no longer has the
                    // regular CA command (0x6d01), old firmware has no Recover one.
                    let root = lsdk::scp::RootKey::generate()?;
                    let mode = if *regular {
                        lsdk::scp::ScpMode::Default
                    } else {
                        lsdk::scp::ScpMode::Recover
                    };
                    let mut chan =
                    lsdk::scp::SecureChannel::open_mode(&d, &root, mode, &mut scp_progress)
                        .await
                        .map_err(|e| match e {
                            Error::Status(sw) if sw.0 == 0x650e && !*regular => Error::App(format!(
                                "{e}: this firmware has no Recover channel, use `lsdk ca install --regular`"
                            )),
                            e => e,
                        })?;
                    eprintln!("> confirm installing the CA \"{name}\" on the device");
                    if *regular {
                        chan.setup_custom_ca(name, &public).await.map_err(ca_hint)?;
                    } else {
                        chan.recover_set_ca(name, &public).await.map_err(ca_hint)?;
                    }
                    println!("custom CA \"{name}\" installed: {}", hex::encode(&public));
                }
                CaCmd::Remove {
                    recover,
                    name,
                    key,
                    public,
                } => {
                    let d = open(&cli)?;
                    let root = lsdk::scp::RootKey::generate()?;
                    if *recover {
                        let public = match public {
                            Some(p) => hex::decode(p.trim_start_matches("0x"))
                                .map_err(|e| Error::InvalidInput(e.to_string()))?,
                            None => read_key(&key.clone().unwrap_or_else(default_ca_path))?
                                .public_key()
                                .to_vec(),
                        };
                        let mut chan = lsdk::scp::SecureChannel::open_mode(
                            &d,
                            &root,
                            lsdk::scp::ScpMode::Recover,
                            &mut scp_progress,
                        )
                        .await?;
                        eprintln!("> confirm removing the custom CA on the device");
                        chan.recover_delete_ca(name, &public)
                            .await
                            .map_err(ca_hint)?;
                    } else {
                        let mut chan =
                            lsdk::scp::SecureChannel::open(&d, &root, &mut scp_progress).await?;
                        eprintln!("> confirm removing the custom CA on the device");
                        chan.reset_custom_ca().await.map_err(ca_hint)?;
                    }
                    println!("custom CA removed");
                }
            }
        }
        Cmd::App { cmd } => match cmd {
            AppCmd::Load {
                file,
                key,
                no_replace,
                dry_run,
                sign,
                sign_key,
                name,
                flags,
                api_level,
                data_size,
                install_params_size,
                legacy_layout,
                icon,
            } => {
                let icon = icon
                    .as_deref()
                    .map(hex::decode)
                    .transpose()
                    .map_err(|e| Error::InvalidInput(format!("--icon: {e}")))?;
                let raw = std::fs::read(file)
                    .map_err(|e| Error::InvalidInput(format!("{}: {e}", file.display())))?;
                let mut img = if raw.starts_with(b"\x7fELF") {
                    lsdk::loader::AppImage::from_elf(&raw)?
                } else {
                    let name = name.clone().ok_or_else(|| {
                        Error::InvalidInput("--name is required for HEX files".into())
                    })?;
                    lsdk::loader::AppImage::from_ihex(&String::from_utf8_lossy(&raw), &name)?
                };
                if let Some(f) = flags {
                    img.flags = u32::from_str_radix(f.trim_start_matches("0x"), 16)
                        .map_err(|e| Error::InvalidInput(format!("--flags: {e}")))?;
                }
                if api_level.is_some() {
                    img.api_level = *api_level;
                }
                if let Some(v) = data_size {
                    img.data_size = *v;
                }
                if let Some(v) = install_params_size {
                    img.install_params_size = *v;
                }
                if *legacy_layout {
                    img.api_level = None;
                }
                eprintln!(
                    "{} {} (flags 0x{:x}, api {:?}, {} bytes, target {})",
                    img.name,
                    img.version.as_deref().unwrap_or(""),
                    img.flags,
                    img.api_level,
                    img.image_size(),
                    img.target_id
                        .map(|t| format!("0x{t:08x}"))
                        .unwrap_or_else(|| "?".into())
                );
                if *dry_run {
                    println!("create_app {}", hex::encode(img.create_app_params()?));
                    if let Some(t) = img.target_id {
                        println!("app hash {}", hex::encode(img.app_hash(t)?));
                    }
                    return Ok(());
                }
                let root = read_key(&key.clone().unwrap_or_else(default_ca_path)).map_err(|e| {
                    Error::InvalidInput(format!(
                        "{e}\nSideloading needs the custom CA key: run `lsdk ca keygen`, then `lsdk ca install` with the device in recovery mode"
                    ))
                })?;
                let d = open(&cli)?;
                let mut chan = lsdk::scp::SecureChannel::open(&d, &root, &mut scp_progress).await?;
                let signer = match (sign_key, sign) {
                    (Some(p), _) => Some(read_key(p)?),
                    (None, true) => Some(root.clone()),
                    (None, false) => None,
                };
                let opts = lsdk::loader::InstallOptions {
                    replace: !no_replace,
                    signer: signer.as_ref(),
                    icon: icon.as_deref(),
                };
                lsdk::loader::install_app_with(&mut chan, &img, &opts, &mut |sent, total| {
                    eprint!("\r> loading {sent}/{total}");
                    if sent == total {
                        eprintln!();
                    }
                })
                .await
                .map_err(|e| match e {
                    Error::Status(sw) if sw.0 == 0x6512 && !*legacy_layout => Error::App(format!(
                        "{e}: CREATE APP has the wrong layout for this firmware; if it predates API levels (e.g. Nano S Plus 1.0.x), retry with --legacy-layout"
                    )),
                    e => e,
                })?;
                println!("installed {}", img.name);
            }
            AppCmd::Delete { name, hash, key } => {
                let d = open(&cli)?;
                let root = root_key(key.as_ref())?;
                let mut chan = lsdk::scp::SecureChannel::open(&d, &root, &mut scp_progress).await?;
                if *hash {
                    let h: [u8; 32] = hex::decode(name)
                        .ok()
                        .and_then(|v| v.try_into().ok())
                        .ok_or_else(|| Error::InvalidInput("hash must be 32 bytes hex".into()))?;
                    chan.delete_app_by_hash(&h).await?;
                } else {
                    chan.delete_app(name).await?;
                }
                println!("deleted {name}");
            }
            AppCmd::DeleteAll { key } => {
                let d = open(&cli)?;
                let root = root_key(key.as_ref())?;
                let mut chan = lsdk::scp::SecureChannel::open(&d, &root, &mut scp_progress).await?;
                eprintln!("> confirm deleting all apps on the device");
                chan.delete_all_apps().await?;
                println!("all apps deleted");
            }
            AppCmd::List { key } => {
                let d = open(&cli)?;
                let root = root_key(key.as_ref())?;
                let mut chan = lsdk::scp::SecureChannel::open(&d, &root, &mut scp_progress).await?;
                print(&chan.list_apps().await?);
            }
        },
        Cmd::Meminfo { key } => {
            let d = open(&cli)?;
            let root = root_key(key.as_ref())?;
            let mut chan = lsdk::scp::SecureChannel::open(&d, &root, &mut scp_progress).await?;
            print(&chan.get_memory_info().await?);
        }
        Cmd::Screensaver { cmd } => {
            use lsdk::os::{ScreenSaverAnimation, ScreenSaverSpeed};
            let d = open(&cli)?;
            match cmd {
                ScreensaverCmd::Get => match d.get_screen_saver().await? {
                    Some(s) => print(&s),
                    None => println!("default screensaver"),
                },
                ScreensaverCmd::Set {
                    text,
                    animation,
                    speed,
                } => {
                    eprintln!("> confirm on the device");
                    d.set_screen_saver(
                        text,
                        ScreenSaverAnimation::parse(animation)?,
                        ScreenSaverSpeed::parse(speed)?,
                    )
                    .await?;
                    println!("screensaver set");
                }
                ScreensaverCmd::Reset => {
                    eprintln!("> confirm on the device");
                    d.reset_screen_saver().await?;
                    println!("default screensaver restored");
                }
            }
        }
        Cmd::Battery => print(&open(&cli)?.get_battery_status().await?),
        Cmd::Firmware {
            cmd:
                FirmwareCmd::Hash {
                    key,
                    address,
                    length,
                },
        } => {
            let hexnum = |s: &str| {
                u32::from_str_radix(s.trim_start_matches("0x"), 16)
                    .map_err(|e| Error::InvalidInput(e.to_string()))
            };
            let (address, length) = (hexnum(address)?, hexnum(length)?);
            let d = open(&cli)?;
            let root = root_key(key.as_ref())?;
            let mut chan = lsdk::scp::SecureChannel::open(&d, &root, &mut scp_progress).await?;
            println!(
                "{}",
                hex::encode(chan.hash_firmware(address, length).await?)
            );
        }
        Cmd::Firmware { cmd } => {
            let d = open(&cli)?;
            let os = d.get_version().await?;
            // An update interrupted in bootloader mode resumes from its saved
            // plan: old bootloaders don't report the target firmware.
            let pending_path = config_dir().join("pending-update.json");
            let pending: Option<lsdk::manager::ops::FirmwareUpdate> =
                std::fs::read_to_string(&pending_path)
                    .ok()
                    .and_then(|t| serde_json::from_str(&t).ok());
            let update = if os.is_bootloader
                && matches!(cmd, FirmwareCmd::Update)
                && let Some(p) = pending
            {
                eprintln!(
                    "> resuming the update to {} (saved in {})",
                    p.final_firmware.name,
                    pending_path.display()
                );
                Some(p)
            } else if os.is_bootloader || matches!(cmd, FirmwareCmd::Repair) {
                drop(d);
                repair_loop(&manager).await?;
                return Ok(());
            } else {
                manager.check_firmware_update(&os).await?
            };
            match (cmd, update) {
                (FirmwareCmd::Repair | FirmwareCmd::Hash { .. }, _) => unreachable!(),
                (_, None) => println!("firmware {} is up to date", os.se_version),
                (FirmwareCmd::Check, Some(u)) => print(&u),
                (FirmwareCmd::Update, Some(u)) => {
                    eprintln!("updating {} -> {}", os.se_version, u.final_firmware.name);
                    if let Some(dir) = pending_path.parent() {
                        let _ = std::fs::create_dir_all(dir);
                    }
                    let _ = std::fs::write(
                        &pending_path,
                        serde_json::to_string(&u).unwrap_or_default(),
                    );
                    if !os.is_osu && !os.is_bootloader {
                        eprintln!("> installing the OS updater: confirm on the device");
                        manager.install_osu(&d, &u, &mut progress).await?;
                    }
                    drop(d);
                    // Reopen the device (it reboots between steps) and read its state.
                    async fn state(
                        wait: Duration,
                    ) -> Result<(Device<HidTransport>, lsdk::os::OsVersion)> {
                        let d = Device::new(HidTransport::wait_and_open(wait)?);
                        let os = d.get_version().await?;
                        Ok((d, os))
                    }
                    if u.should_flash_mcu {
                        // The device must be put in bootloader mode by hand.
                        let start = std::time::Instant::now();
                        let mut asked = false;
                        let mut flashed = 0;
                        loop {
                            if start.elapsed() > Duration::from_secs(15 * 60) {
                                return Err(Error::App(
                                    "the device never entered bootloader mode".into(),
                                ));
                            }
                            let (d, os) = match state(Duration::from_secs(60)).await {
                                Ok(x) => x,
                                Err(Error::NoDevice) => continue,
                                Err(e) => return Err(e),
                            };
                            if os.is_bootloader {
                                let kind = manager.flash_mcu(&d, &u, &mut progress).await?;
                                eprintln!("> flashed {kind:?}");
                                flashed += 1;
                                if flashed > 6 {
                                    return Err(Error::App(
                                        "still in bootloader mode after 6 flashes".into(),
                                    ));
                                }
                                drop(d);
                                std::thread::sleep(Duration::from_secs(3));
                                continue;
                            }
                            if flashed > 0 {
                                break;
                            }
                            if !asked {
                                eprintln!(
                                    "> the MCU must be updated from bootloader mode: unplug the device, then hold its left button while plugging it back in, until it shows \"Bootloader\""
                                );
                                asked = true;
                            }
                            drop(d);
                            std::thread::sleep(Duration::from_secs(2));
                        }
                    }
                    if lsdk::manager::Manager::needs_final_install(&u) {
                        // Back in the OS updater ("Update"): send the final firmware.
                        let start = std::time::Instant::now();
                        let d = loop {
                            if start.elapsed() > Duration::from_secs(5 * 60) {
                                return Err(Error::App(
                                    "the device did not come back to the OS updater (\"Update\")"
                                        .into(),
                                ));
                            }
                            match state(Duration::from_secs(60)).await {
                                Ok((d, os)) if os.is_osu => break d,
                                Ok((_, os)) if os.is_bootloader => {
                                    return Err(Error::App(
                                        "the device is still in bootloader mode: run the update again".into(),
                                    ));
                                }
                                Ok((_, os)) => {
                                    let _ = std::fs::remove_file(&pending_path);
                                    println!(
                                        "the device runs {}: nothing left to do",
                                        os.se_version
                                    );
                                    return Ok(());
                                }
                                Err(Error::NoDevice) => continue,
                                Err(e) => return Err(e),
                            }
                        };
                        eprintln!("> installing the final firmware {}", u.final_firmware.name);
                        manager
                            .install_final_firmware(&d, &u, &mut progress)
                            .await?;
                        let _ = std::fs::remove_file(&pending_path);
                        println!(
                            "firmware {} installed: the device restarts; follow its instructions",
                            u.final_firmware.name
                        );
                    } else {
                        let _ = std::fs::remove_file(&pending_path);
                        println!("update sent, follow the instructions on the device");
                    }
                }
            }
        }
        Cmd::Apdu { hex } => {
            let raw = hex::decode(hex.replace(' ', ""))
                .map_err(|e| Error::InvalidInput(e.to_string()))?;
            println!("{}", hex::encode(open(&cli)?.exchange_raw(&raw).await?));
        }
        Cmd::Eth { cmd } => {
            let d = open(&cli)?;
            let app = eth::EthApp::new(&d);
            match cmd {
                EthCmd::Address { path: p, display } => {
                    print(&app.get_address(&path(p)?, *display, false).await?)
                }
                EthCmd::SignTx {
                    path: p,
                    chain_id,
                    nonce,
                    to,
                    value,
                    gas,
                    max_fee,
                    priority_fee,
                    gas_price,
                    data,
                    token,
                    decimals,
                } => {
                    let mut tx = eth::EvmTx::default();
                    tx.chain_id = *chain_id;
                    tx.nonce = *nonce;
                    tx.gas = *gas;
                    match token {
                        Some(token) => {
                            tx.to = token.clone();
                            tx.data =
                                eth::erc20_transfer_data(to, &eth::parse_units(value, *decimals)?)?;
                        }
                        None => {
                            tx.to = to.clone();
                            tx.value = eth::parse_units(value, 18)?;
                            if let Some(h) = data {
                                tx.data = hex::decode(h.trim_start_matches("0x"))
                                    .map_err(|e| Error::InvalidInput(e.to_string()))?;
                            }
                        }
                    }
                    if let Some(gp) = gas_price {
                        tx.tx_type = eth::EvmTxType::Legacy;
                        tx.gas_fee_cap = wei(gp)?;
                    } else {
                        tx.tx_type = eth::EvmTxType::Eip1559;
                        tx.gas_tip_cap = wei(priority_fee)?;
                        tx.gas_fee_cap = wei(max_fee.as_deref().ok_or_else(|| {
                            Error::InvalidInput(
                                "--max-fee (gwei) or --gas-price is required".into(),
                            )
                        })?)?;
                    }
                    app.sign_tx(&path(p)?, &mut tx).await?;
                    let raw = tx.to_bytes().map_err(|e| Error::App(format!("{e:?}")))?;
                    println!("0x{}", hex::encode(raw));
                }
                EthCmd::SignRaw { path: p, hex } => {
                    let raw = hex::decode(hex.trim_start_matches("0x"))
                        .map_err(|e| Error::InvalidInput(e.to_string()))?;
                    let sig = app.sign_transaction(&path(p)?, &raw).await?;
                    println!("0x{}", hex::encode(eth::assemble_signed(&raw, &sig)?));
                }
                EthCmd::SignMessage { path: p, message } => {
                    let sig = app
                        .sign_personal_message(&path(p)?, message.as_bytes())
                        .await?;
                    println!("0x{}", hex::encode(sig.to_rsv()));
                }
            }
        }
        Cmd::Btc { cmd } => {
            let d = open(&cli)?;
            let app = btc::BtcApp::new(&d);
            match cmd {
                BtcCmd::Xpub {
                    kind,
                    account,
                    testnet,
                    display,
                } => {
                    let kind = btc::AddressType::parse(kind)?;
                    let p = kind.account_path(*testnet, *account);
                    let xpub = app.get_extended_pubkey(&p, *display).await?;
                    let fpr = app.get_master_fingerprint().await?;
                    println!("{}", btc::KeyInfo::new(fpr, p, xpub));
                }
                BtcCmd::Address {
                    kind,
                    account,
                    index,
                    change,
                    testnet,
                    display,
                } => {
                    let kind = btc::AddressType::parse(kind)?;
                    let key = app.get_account_key(kind, *testnet, *account).await?;
                    println!(
                        "{}",
                        app.get_wallet_address_checked(
                            kind, *testnet, &key, *change, *index, *display
                        )
                        .await?
                    );
                }
                BtcCmd::SignMessage { path: p, message } => {
                    let sig = app.sign_message(&path(p)?, message.as_bytes()).await?;
                    println!("{}", outscript::base64::encode(&sig));
                }
                BtcCmd::SignPsbt {
                    kind,
                    account,
                    testnet,
                    no_finalize,
                    psbt,
                } => {
                    let kind = btc::AddressType::parse(kind)?;
                    let bytes = outscript::psbt::Psbt::decode_base64(psbt.trim())
                        .map_err(|e| Error::InvalidInput(format!("{e:?}")))?;
                    let policy = app.default_policy(kind, *testnet, *account).await?;
                    let signed = app.sign_psbt_into(&bytes, &policy, None).await?;
                    if *no_finalize {
                        println!("{}", outscript::base64::encode(&signed));
                    } else {
                        println!("{}", hex::encode(btc::psbt::finalize_and_extract(&signed)?));
                    }
                }
            }
        }
        Cmd::Hw1 {
            cmd:
                Hw1Cmd::Update {
                    dry_run,
                    erase,
                    firmware_dir,
                },
        } => hw1_update(&cli, *dry_run, *erase, firmware_dir).await?,
        Cmd::Hw1 { cmd } => {
            let d = open(&cli)?;
            if !d.transport().legacy() {
                return Err(Error::InvalidInput(
                    "not a HW.1 / original Nano (BTChip, USB vendor 0x2581)".into(),
                ));
            }
            let w = btchip::BtchipWallet::new(&d);
            match cmd {
                Hw1Cmd::Info => print(&hw1_info(&d).await?),
                Hw1Cmd::Update { .. } => unreachable!(),
                Hw1Cmd::Setup {
                    pin,
                    words,
                    passphrase,
                    secondary_pin,
                    testnet,
                    i_understand_the_seed_travels_over_usb,
                } => {
                    if w.operation_mode().await?.is_some() {
                        return Err(Error::App(
                            "the dongle is already set up (3 wrong PINs wipe it)".into(),
                        ));
                    }
                    let seed = match words {
                        Some(phrase) => {
                            if !i_understand_the_seed_travels_over_usb {
                                return Err(Error::InvalidInput(
                                    "--words sends the recovery phrase's seed in clear over USB; pass --i-understand-the-seed-travels-over-usb (test devices only)"
                                        .into(),
                                ));
                            }
                            Some(btchip::bip39_seed(phrase, passphrase)?.to_vec())
                        }
                        None => None,
                    };
                    let mut s = btchip::Setup::new(pin.clone(), seed);
                    s.secondary_pin = secondary_pin.clone();
                    if *testnet {
                        s.key_version = 111;
                        s.p2sh_version = 196;
                    }
                    let typed = w.setup(&s).await?;
                    println!("set up");
                    if typed || words.is_none() {
                        eprintln!(
                            "> the dongle generated a seed: on the next power-ups it types it (as a keyboard) until the PIN is entered; open a text editor before replugging and back it up"
                        );
                    }
                }
                Hw1Cmd::Address { path: p, pin } => {
                    hw1_unlock(&w, pin).await?;
                    print(&w.wallet_public_key(&path(p)?).await?);
                }
                Hw1Cmd::SignMessage {
                    path: p,
                    pin,
                    message,
                } => {
                    hw1_unlock(&w, pin).await?;
                    let compressed = w.firmware().await?.compressed_keys;
                    let path = path(p)?;
                    let address = w.wallet_public_key(&path).await?.address;
                    let der = match w.sign_message_prepare(&path, message.as_bytes()).await? {
                        None => w.sign_message_finish("").await?,
                        Some(c) => {
                            let (code, d2) = hw1_confirm(&cli, &c)?;
                            btchip::BtchipWallet::new(&d2)
                                .sign_message_finish(&code)
                                .await?
                        }
                    };
                    print(&serde_json::json!({
                        "address": address,
                        "message": message,
                        "signature": btchip::message_signature_base64(&der, compressed)?,
                    }));
                }
                Hw1Cmd::SignTx {
                    pin,
                    inputs,
                    to,
                    amount,
                    fee,
                    change_path,
                } => {
                    let inputs = inputs
                        .iter()
                        .map(|s| hw1_input(s))
                        .collect::<Result<Vec<_>>>()?;
                    let mut signer = btchip::TxSigner::new(
                        inputs,
                        btchip::Payment {
                            to: to.clone(),
                            amount: *amount,
                            fee: *fee,
                            change_path: path(change_path)?,
                        },
                    )?;
                    let (change, total) = signer.summary();
                    eprintln!(
                        "> spending {total} sat: {amount} to {to}, {fee} fee, {change} change to {change_path}"
                    );
                    hw1_unlock(&w, pin).await?;
                    let mut step = signer.step(&w).await?;
                    let mut reopened;
                    loop {
                        match step {
                            btchip::TxStep::Done(tx) => {
                                println!("{}", hex::encode(tx));
                                break;
                            }
                            btchip::TxStep::NeedsConfirmation(c) => {
                                let (code, d2) = hw1_confirm(&cli, &c)?;
                                reopened = d2;
                                signer.set_code(code);
                                let w2 = btchip::BtchipWallet::new(&reopened);
                                step = match signer.step(&w2).await {
                                    Err(Error::Status(sw)) if sw.0 == 0x6982 => {
                                        w2.verify_pin(pin).await?;
                                        signer.step(&w2).await?
                                    }
                                    r => r?,
                                };
                            }
                        }
                    }
                }
            }
        }
        Cmd::Sol { cmd } => {
            let d = open(&cli)?;
            let app = sol::SolApp::new(&d);
            match cmd {
                SolCmd::Address { path: p, display } => {
                    println!("{}", app.get_address(&path(p)?, *display).await?)
                }
                SolCmd::Transfer {
                    path: p,
                    to,
                    amount,
                    blockhash,
                } => {
                    let p = path(p)?;
                    let from = app.get_address(&p, false).await?;
                    let lamports: u64 = eth::parse_units(amount, 9)?
                        .try_into()
                        .map_err(|_| Error::InvalidInput("amount too large".into()))?;
                    let mut tx = sol::build_transfer(&from, to, lamports, blockhash)?;
                    app.sign_tx(&p, &mut tx).await?;
                    let raw = tx.to_bytes().map_err(|e| Error::App(format!("{e:?}")))?;
                    println!("{}", outscript::base64::encode(&raw));
                }
            }
        }
    }
    Ok(())
}

/// Flash MCU / bootloader while the device stays in bootloader mode.
async fn repair_loop(manager: &Manager) -> Result<()> {
    for _ in 0..6 {
        let d = Device::new(HidTransport::wait_and_open(Duration::from_secs(300))?);
        let os = d.get_version().await?;
        if !os.is_bootloader {
            println!(
                "device is out of bootloader mode (firmware {})",
                os.se_version
            );
            return Ok(());
        }
        eprintln!(
            "bootloader {}, installed firmware {}",
            os.maj_min(),
            os.se_version
        );
        let kind = manager.repair_mcu(&d, &mut progress).await?;
        eprintln!("flashed {kind:?}, waiting for the device to restart...");
        drop(d);
        std::thread::sleep(Duration::from_secs(5));
    }
    Err(Error::App(
        "device still in bootloader mode after several flashes".into(),
    ))
}

fn config_dir() -> std::path::PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| ".".into())
        .join("lsdk")
}

fn default_ca_path() -> std::path::PathBuf {
    config_dir().join("ca.key")
}

fn write_key(path: &std::path::Path, key: &lsdk::scp::RootKey) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| Error::App(format!("{}: {e}", dir.display())))?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| Error::App(format!("{}: {e}", path.display())))?;
    writeln!(f, "{}", hex::encode(key.to_bytes())).map_err(|e| Error::App(e.to_string()))
}

fn read_key(path: &std::path::Path) -> Result<lsdk::scp::RootKey> {
    let s = std::fs::read_to_string(path)
        .map_err(|e| Error::InvalidInput(format!("{}: {e}", path.display())))?;
    lsdk::scp::RootKey::from_hex(&s)
}

/// The CA key when present (no foreign-key prompt), else a random key.
fn root_key(key: Option<&std::path::PathBuf>) -> Result<lsdk::scp::RootKey> {
    match key {
        Some(p) => read_key(p),
        None if default_ca_path().exists() => read_key(&default_ca_path()),
        None => lsdk::scp::RootKey::generate(),
    }
}

fn scp_progress(ev: lsdk::scp::ScpEvent) {
    match ev {
        lsdk::scp::ScpEvent::PermissionRequested { host_public_key } => {
            eprintln!("> allow the manager on the device; it shows this key:\n  {host_public_key}")
        }
        lsdk::scp::ScpEvent::PermissionGranted => eprintln!("> allowed"),
        lsdk::scp::ScpEvent::Opened => {}
    }
}

fn ca_hint(e: Error) -> Error {
    match e {
        Error::Status(sw) if sw.0 == 0x661e => {
            Error::App("the device must be in recovery mode".into())
        }
        Error::Status(sw) if sw.0 == 0x6982 => {
            Error::App("a custom CA is already installed: remove it first (lsdk ca remove)".into())
        }
        Error::Status(sw) if sw.0 == 0x6a84 => Error::App("no custom CA is installed".into()),
        e => e,
    }
}

fn main() {
    let cli = Cli::parse();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(e) = rt.block_on(run(cli)) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
