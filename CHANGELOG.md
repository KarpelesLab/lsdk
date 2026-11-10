# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.2](https://github.com/KarpelesLab/lsdk/compare/v0.0.1...v0.0.2) - 2026-11-10

### Other

- Signed app commit, endorsement reset, language packs and APDU scripts from files
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
