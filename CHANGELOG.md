# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/KarpelesLab/lsdk/compare/v0.1.1...v0.2.0) - 2026-11-14

### Other

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
