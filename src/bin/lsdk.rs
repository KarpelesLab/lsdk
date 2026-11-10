//! `lsdk` command line tool.

use std::io::Write;
use std::time::Duration;

use clap::{Parser, Subcommand};
use lsdk::apps::{btc, eth, sol};
use lsdk::hsm::HsmEvent;
use lsdk::manager::Manager;
use lsdk::path::DerivationPath;
use lsdk::transport::hid::HidTransport;
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
    /// Manager API base URL.
    #[arg(long, global = true, default_value = lsdk::manager::api::DEFAULT_BASE_URL)]
    api: String,
    /// HSM websocket base URL.
    #[arg(long, global = true, default_value = lsdk::hsm::DEFAULT_BASE_URL)]
    hsm: String,
    #[command(subcommand)]
    cmd: Cmd,
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
    /// Create the slot key and certify it with your owner key.
    Setup {
        slot: u8,
        /// Owner private key file (default: the lsdk CA key).
        #[arg(long)]
        owner_key: Option<std::path::PathBuf>,
        /// Use this DER certificate (hex) instead of signing with the owner key.
        #[arg(long)]
        certificate: Option<String>,
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
        /// Use the Recover secure channel (for firmware without the regular command).
        #[arg(long)]
        recover: bool,
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
        _ => {}
    }
}

fn open(cli: &Cli) -> Result<Device<HidTransport>> {
    let t = match &cli.device {
        Some(path) => {
            let info = HidTransport::list()?
                .into_iter()
                .find(|d| &d.path == path)
                .ok_or(Error::NoDevice)?;
            HidTransport::open(&info)?
        }
        None => HidTransport::open_first()?,
    };
    Ok(Device::new(t))
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
            if !att.genuine {
                std::process::exit(2);
            }
        }
        Cmd::Genuine { .. } => {
            let ok = manager.genuine_check(&open(&cli)?, &mut progress).await?;
            println!("{}", if ok { "genuine" } else { "NOT GENUINE" });
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
                    owner_key,
                    certificate,
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
                "> confirm on the device, then enter your PIN; keep it plugged in while it processes"
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
                    "{e}: is the CA installed through the Recover channel? (lsdk ca install --recover, in recovery mode)"
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
        Cmd::Ca { cmd } => match cmd {
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
                recover,
            } => {
                let public = match public {
                    Some(p) => hex::decode(p.trim_start_matches("0x"))
                        .map_err(|e| Error::InvalidInput(e.to_string()))?,
                    None => read_key(&key.clone().unwrap_or_else(default_ca_path))?
                        .public_key()
                        .to_vec(),
                };
                let d = open(&cli)?;
                // Any root key works here: the device asks to allow it.
                let root = lsdk::scp::RootKey::generate()?;
                let mode = if *recover {
                    lsdk::scp::ScpMode::Recover
                } else {
                    lsdk::scp::ScpMode::Default
                };
                let mut chan =
                    lsdk::scp::SecureChannel::open_mode(&d, &root, mode, &mut scp_progress).await?;
                eprintln!("> confirm installing the CA \"{name}\" on the device");
                if *recover {
                    chan.recover_set_ca(name, &public).await.map_err(ca_hint)?;
                } else {
                    chan.setup_custom_ca(name, &public).await.map_err(ca_hint)?;
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
        },
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
            } => {
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
                };
                lsdk::loader::install_app_with(&mut chan, &img, &opts, &mut |sent, total| {
                    eprint!("\r> loading {sent}/{total}");
                    if sent == total {
                        eprintln!();
                    }
                })
                .await
                .map_err(|e| match e {
                    Error::Status(sw) if sw.0 == 0x6a80 || sw.0 == 0x6a81 => {
                        Error::App(format!("{e}: an app with this name is already installed"))
                    }
                    Error::Status(sw) if sw.0 == 0x6a84 || sw.0 == 0x6a85 => {
                        Error::App(format!("{e}: not enough space"))
                    }
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
            if os.is_bootloader || matches!(cmd, FirmwareCmd::Repair) {
                drop(d);
                repair_loop(&manager).await?;
                return Ok(());
            }
            let update = manager.check_firmware_update(&os).await?;
            match (cmd, update) {
                (FirmwareCmd::Repair | FirmwareCmd::Hash { .. }, _) => unreachable!(),
                (_, None) => println!("firmware {} is up to date", os.se_version),
                (FirmwareCmd::Check, Some(u)) => print(&u),
                (FirmwareCmd::Update, Some(u)) => {
                    eprintln!(
                        "installing OS updater {} -> {}",
                        os.se_version, u.final_firmware.name
                    );
                    if !os.is_osu && !os.is_bootloader {
                        manager.install_osu(&d, &u, &mut progress).await?;
                    }
                    drop(d);
                    if u.should_flash_mcu {
                        for _ in 0..6 {
                            eprintln!("waiting for the device (bootloader)...");
                            let d =
                                Device::new(HidTransport::wait_and_open(Duration::from_secs(300))?);
                            let os = d.get_version().await?;
                            if !os.is_bootloader {
                                break;
                            }
                            let kind = manager.flash_mcu(&d, &u, &mut progress).await?;
                            eprintln!("flashed {kind:?}");
                            std::thread::sleep(Duration::from_secs(3));
                        }
                    }
                    println!("update sent, follow the instructions on the device");
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
