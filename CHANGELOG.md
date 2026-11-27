# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0](https://github.com/KarpelesLab/lsdk/compare/v0.3.0...v0.4.0) - 2026-11-27

### Other

- firmware table: CSV of device/version/MCU/bootloader relations from the manager API
- one subcommand per FACTORY_TEST sub-test, guard backup-serial read
- small change in onboard_dev.sh
- add set-cxport and set-certificate, named FACTORY_TEST sub-tests
- firmware mcu <version> [--bootloader]: flash a given MCU or bootloader from bootloader mode
- device found in bootloader mode restarts into its OS before anything is flashed
- firmware update --skip-mcu: install the final firmware without flashing the MCU
- compare bootloader versions numerically, refuse a bootloader downgrade
- expose a device over TCP in Speculos's APDU protocol
- firmware from-log: rebuild a .fw command stream from a decrypted session log
- firmware download: write the stream to .fw~, rename to .fw only on success
- firmware download: write the secure command stream (.fw) instead of Intel HEX

## [0.3.0](https://github.com/KarpelesLab/lsdk/compare/v0.2.0...v0.3.0) - 2026-11-24

### Fixed

- *(wasm)* gate device_session to non-wasm (dead code under --features wasm)

### Other

- rustfmt the firmware-download logging/keyfile code
- firmware download: emit a decrypted session log with the ephemeral key
- firmware download --step final: treat empty catalog firmware as "no separate image"
- firmware download: offset-aware reconstruction, Intel HEX output, and the final (post-OSU) step
- firmware download: reconstruct and decrypt the firmware image from the emulated device
- firmware download --device-key: capture vendor firmware via the emulated device (reaches the HSM load phase)
- genuine --device-key: also run the online (vendor HSM) check against the emulated device
- genuine --offline --device-key <file>: run the check against a dumped SE attestation key (emulated virtual device)
- firmware update/repair --log: note when the HSM bulk phase starts (APDU count, data bytes) and when it ends
- app load --no-flush / --no-crc: skip FLUSH and/or the per-window CRC check (experimental)
- sign the app hash without the target id on 1.4.x (target 0x…3)
- firmware update/repair --log <file>: append every APDU exchanged with the device (timestamped, with response times and errors, across reconnects) plus devices opened, states seen, the plan, steps, HSM events and the outcome
- pre-1.4 CREATE_APP sends the app version after the derivation path, as ledgerblue's --appVersion (console create-app: --app-version)
- pre-1.4 app list reads until the used-slot count (skipping erased slots, capped at the slot count) instead of stopping at the first erased slot; without the counts the first erased slot still ends it
- pre-1.4 app list stops at the used-slot count from the memory info, so it never asks past the last app
- pre-1.4 app list reports the real flags (low half of the registry word, high half is its complement) and also ends on a word failing that check
- pre-1.4 app list stops at the first erased slot (1.3.1 has no end marker and crashes when asked past it)

## [0.2.0](https://github.com/KarpelesLab/lsdk/compare/v0.1.1...v0.2.0) - 2026-11-21

### Other

- offline genuine check authenticates with a caller root key (CLI uses the CA key when present, --key; web uses the saved CA key) and checks against a caller issuer list (known_issuers(); --no-default-issuer to trust only --issuer-key, which also takes a file); RootKey moves to attestation, re-exported from scp
- show the expected OSU hash to compare with the device screen
- console create-app takes named fields (1.4+: --code-len, --data-size, --params-size, --flags, --entry, --api-level / --legacy-layout; pre-1.4: --length, --name, --icon, --derivation), layout from the device, --raw for a hand-built payload
- console gets install (app load options, shared), load primitives (create-app, set-load-offset, load-chunk, flush, crc, commit), mcu-bootloader, send; clap-parsed lines with quoting
- lsdk console, interactive secure channel console (named commands, raw INS hex, plain apdu; --recover, --key; scriptable from stdin)
- --reserve on modern models, aligned on the device's flash page (Nano S 64, Nano X 256, others 512)
- 1.4+ builds the install parameters TLV (name, version, icon, path ff) for images without them (HEX); --app-version; signed reserve hash zero-fills like hashApp
- --reserve on firmware 1.4+ (data length += reserve, install params moved after it; pad / bare SET_LOAD_OFFSET at its end)
- firmware update: already in the OS updater with no MCU flash, install the final firmware on the open connection
- firmware update/repair: reopen the device between steps the same way as open() (honours --tcp, --device, --usbfs)
- firmware update: print the plan and each device state seen while waiting between steps
- firmware paths: list the update paths from the installed firmware (OSU/final script names, hashes, sizes, MCUs; --depth, --all-providers, --json)
- --osu <name> picks the OS updater (check/update), refused unless it updates from the current firmware
- log the internal name of what is installed (app/OSU/final firmware path, MCU/bootloader version)
- report bulk data bytes in progress (CLI and web log)
- --reserve-pad-pattern fills the reserve pad with a repeating hex pattern
- --reserve-pad loads N zero bytes at the end of the reserved area (pre-1.4)
- with --reserve, SET_LOAD_OFFSET to the reserved area's last byte (no LOAD)
- --reserve declares extra (unloaded) bytes in pre-1.4 CREATE_APP
- finish Nano S firmware updates (MCU from bootloader, final firmware)
- firmware repair: old bootloaders that don't report the SE firmware
- drop --commit-format; pre-1.4 signed COMMIT is bootadr || len || DER
- CA-signed installs on pre-1.4 (image-only app hash, bootadr+len+DER commit; sign_digest_raw; --commit-format)
- Signed sideload on firmware before 1.4 (Nano S 1.3.x)
- Sideload on firmware before 1.4 (Nano S 1.3.x)
- TCP (Speculos APDU protocol) and lsdk --tcp host:port
- firmware update: finish Nano S updates (MCU from bootloader, final firmware)
- app load: --legacy-layout for firmware older than API levels
- ca install: explicit --regular channel for firmware older than Ledger Recover
- Add onboard_dev.sh: host-onboard a test device with the zero seed and PIN 1111
- HW.1 / original Nano firmware update
- HW.1 update: fixes from a real update to 1.0.4
- HW.1 / original Nano firmware update (CLI)
- HW.1 / original Nano in the web console, README
- Support the legacy HW.1 / original Nano (BTChip firmware)
- neutral wording for the attest_1 report
- vendor endorsement fails because attest_1 was reportedly removed
- host onboarding panel for test devices
- Document the self-hosted Recover restore procedure
- Revert offline Recover combine: the shared secret is the encrypted seed
- Rebuild the recovery phrase offline from Recover share files
- Install the custom CA through the Recover channel only
- open the app automatically before app commands
- vendor endorsement fails the same way on a Nano X (SE 2.8.0)
- Nano S Plus gets the same empty endorsement commit in normal mode
- vendor endorsement also fails on a Nano S Plus with the latest firmware
- Vendor endorsement: guard against empty HSM commits, ledgerblue replies
- Name the onboarding step in seFlags and document each bit
- Vendor endorsement through the HSM (lsdk endorse setup --vendor)

## [0.1.1](https://github.com/KarpelesLab/lsdk/compare/v0.1.0...v0.1.1) - 2026-11-10

### Other

- fall back to raw USB (rawusb) when hidraw is not accessible
- Use rsurl for HTTP and the HSM websocket

## [0.0.3](https://github.com/KarpelesLab/lsdk/compare/v0.0.2...v0.0.3) - 2026-11-10

### Other

- Explain 0x6804 during vendor operations (custom CA installed)
- Self-hosted seed backup through the Recover protocol

## [0.0.2](https://github.com/KarpelesLab/lsdk/compare/v0.0.1...v0.0.2) - 2026-11-10

### Other

- survive the mid-command re-enumeration and collect the device answer
- firmware hash: takes address/length, documented as vendor-HSM-only
- Language id for the Brazilian pack, clearer error for empty endorsement slots
- wording
- Expose the remaining dashboard commands, in the library, CLI and web page
- sideloading workflow (custom CA + lsdk app load), verified on a Nano S Plus
- Secure channel (SCP), custom CA and app sideloading

## [0.0.1](https://github.com/KarpelesLab/lsdk/compare/v0.0.0...v0.0.1) - 2026-11-10

### Other

- clearer rejection message (0x6d02 covers wrong mode and bad request)
- Custom screensaver (Nano X / Nano S Plus, recovery mode)
- Offline genuine check: show the manager public key to compare with the device
- fix the firmware restart race (stale handle taken as reconnected)
- Report a locked device instead of 'running: unknown'
- offer to install a missing app (then open it) from the advanced tab
- no implicit network requests in the advanced tab
- Don't list apps during install/uninstall (it asks for approval again)
- Offline genuine check (feature 'attestation')
- Explain 0x6615/0x6616 (secure command refused: device locked / not set up)
- Don't read the device name implicitly (it prompts for consent)
- offer to finish the update in a modal when a device in bootloader mode connects
- Firmware update: recover from bootloader mode, fix reconnect and disconnect detection
- render firmware release notes as sanitized markdown (marked + DOMPurify)
- udev rules as root commands
- explain permission failures on Linux; README udev rules
- Explain device open failures (udev rules on Linux), document the rules
- MIT only
- Build EvmTx via Default (non-exhaustive since outscript 0.2.8)
