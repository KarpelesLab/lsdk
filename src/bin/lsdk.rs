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
    /// Genuine check through the HSM.
    Genuine,
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
enum FirmwareCmd {
    /// Check whether an update is available.
    Check,
    /// Install the latest firmware (OSU, then MCU if needed).
    Update,
    /// Device stuck in bootloader mode: flash the MCU its firmware needs.
    Repair,
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
        Cmd::Genuine => {
            let ok = manager.genuine_check(&open(&cli)?, &mut progress).await?;
            println!("{}", if ok { "genuine" } else { "NOT GENUINE" });
            if !ok {
                std::process::exit(2);
            }
        }
        Cmd::Install { name } => {
            manager
                .install_app_with_deps(&open(&cli)?, name, &mut |app, ev| {
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
        Cmd::Battery => print(&open(&cli)?.get_battery_status().await?),
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
                (FirmwareCmd::Repair, _) => unreachable!(),
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
